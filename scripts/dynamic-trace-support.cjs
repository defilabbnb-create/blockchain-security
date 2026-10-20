const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const {effectSiteId} = require('./evm-source-map.cjs');

const TRACE_EFFECT_KINDS = new Map([
  ['SSTORE', 'state_write'], ['TSTORE', 'state_write'],
  ['CALL', 'external_call'], ['CALLCODE', 'external_call'],
  ['DELEGATECALL', 'external_call'], ['STATICCALL', 'external_call'],
  ['CREATE', 'contract_creation'], ['CREATE2', 'contract_creation'],
  ['SELFDESTRUCT', 'selfdestruct'], ['REVERT', null],
]);
const MAX_REPORTED_TRACE_EFFECTS = 160;
const MAX_TRACE_STEPS = 250_000;
const EVM_OPCODE_PATTERN = /^[A-Z][A-Z0-9]*$/;
const EVM_OPCODE_NAMES = new Set(`
  STOP ADD MUL SUB DIV SDIV MOD SMOD ADDMOD MULMOD EXP SIGNEXTEND
  LT GT SLT SGT EQ ISZERO AND OR XOR NOT BYTE SHL SHR SAR KECCAK256 SHA3
  ADDRESS BALANCE ORIGIN CALLER CALLVALUE CALLDATALOAD CALLDATASIZE CALLDATACOPY
  CODESIZE CODECOPY GASPRICE EXTCODESIZE EXTCODECOPY RETURNDATASIZE RETURNDATACOPY
  EXTCODEHASH BLOCKHASH COINBASE TIMESTAMP NUMBER PREVRANDAO DIFFICULTY GASLIMIT
  CHAINID SELFBALANCE BASEFEE BLOBHASH BLOBBASEFEE
  POP MLOAD MSTORE MSTORE8 SLOAD SSTORE TLOAD TSTORE JUMP JUMPI PC MSIZE GAS
  JUMPDEST MCOPY PUSH0 CREATE CALL CALLCODE RETURN DELEGATECALL CREATE2 STATICCALL REVERT
  INVALID SELFDESTRUCT SUICIDE DATALOAD DATALOADN DATASIZE DATACOPY RJUMP RJUMPI
  RJUMPV CALLF RETF JUMPF DUPN SWAPN EXCHANGE EOFCREATE RETURNCONTRACT EXTCALL
  EXTDELEGATECALL EXTSTATICCALL RETURNDATALOAD
`.trim().split(/\s+/));
for (let opcode = 1; opcode <= 32; opcode++) EVM_OPCODE_NAMES.add(`PUSH${opcode}`);
for (let opcode = 1; opcode <= 16; opcode++) {
  EVM_OPCODE_NAMES.add(`DUP${opcode}`);
  EVM_OPCODE_NAMES.add(`SWAP${opcode}`);
}
for (let opcode = 0; opcode <= 4; opcode++) EVM_OPCODE_NAMES.add(`LOG${opcode}`);

function hasValidTraceStep(step) {
  return Boolean(step && typeof step.op === 'string' && EVM_OPCODE_PATTERN.test(step.op) &&
    Number.isSafeInteger(step.pc) && step.pc >= 0 &&
    Number.isSafeInteger(step.depth) && step.depth >= 1);
}

function sampleKey(target, selector) {
  return JSON.stringify([target, selector]);
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  }
  return value;
}

function stableHash(value) {
  const encoded = typeof value === 'string' ? value : JSON.stringify(canonical(value));
  return crypto.createHash('sha256').update(encoded, 'utf8').digest('hex');
}

function createTraceSampler() {
  const attempts = new Map();
  return {
    has(target, selector, failed) {
      return attempts.get(sampleKey(target, selector))?.has(failed ? 'reverted' : 'committed') || false;
    },
    markAttempted(target, selector, failed) {
      const key = sampleKey(target, selector);
      let outcomes = attempts.get(key);
      if (!outcomes) attempts.set(key, outcomes = new Set());
      outcomes.add(failed ? 'reverted' : 'committed');
    },
  };
}

// Sampling state is evidence state: a structurally valid, summarized result
// may consume the one-sample-per-outcome budget even when it is partial. A
// partial trace is still a real sample; retrying it cannot remove a fixed
// step/effect cap and would repeatedly pay the debug-trace cost. Callers can
// retry only unavailable or structurally invalid responses.
function markTraceSampleComplete(sampler, target, selector, failed, result) {
  if (!sampler || typeof sampler.markAttempted !== 'function' ||
      !result || !['available', 'partial'].includes(result.state) || result.traceValid !== true) return false;
  sampler.markAttempted(target, selector, failed);
  return true;
}

function traceSummaryEvidenceState(summary) {
  if (!summary || typeof summary !== 'object') return 'unavailable';
  return summary.stepsTruncated === true || summary.effectsTruncated === true ||
    summary.effectCountComplete === false ||
    (Number.isSafeInteger(summary.unknownOpcodeCount) && summary.unknownOpcodeCount > 0)
    ? 'partial' : 'available';
}

function traceSourceAttributionState(summary) {
  if (!summary || typeof summary !== 'object' ||
      !Number.isSafeInteger(summary.targetEffectCount) || summary.targetEffectCount < 0 ||
      !Number.isSafeInteger(summary.unmappedTargetEffects) || summary.unmappedTargetEffects < 0 ||
      summary.unmappedTargetEffects > summary.targetEffectCount) return 'unavailable';
  if (summary.frameIdentityState === 'not_applicable') return 'not_applicable';
  if (summary.frameIdentityState === 'unavailable' ||
      !Number.isSafeInteger(summary.targetCodeStepCount) || summary.targetCodeStepCount === 0) return 'unavailable';
  if (summary.frameIdentityState === 'partial' || summary.targetFrameDepthMismatchCount > 0) return 'partial';
  if (summary.stepsTruncated === true || summary.unmappedTargetEffects > 0) return 'partial';
  return summary.targetEffectCount === 0 ? 'not_applicable' : 'available';
}

function traceSourceAttributionEvidenceState(stats) {
  const count = (name) => Number.isSafeInteger(stats?.[name]) && stats[name] >= 0 ? stats[name] : null;
  const valid = count('valid');
  const requested = count('requested');
  const invalid = count('invalid');
  const stepLimited = count('stepLimited');
  const unknownOpcodeCount = count('unknownOpcodeCount');
  const targetEffects = count('targetEffects');
  const unmappedTargetEffects = count('unmappedTargetEffects');
  const frameIdentityAvailable = count('frameIdentityAvailable');
  const frameIdentityPartial = count('frameIdentityPartial');
  const frameIdentityUnavailable = count('frameIdentityUnavailable');
  const targetCodeStepCount = count('targetCodeStepCount');
  const targetFrameDepthMismatchCount = count('targetFrameDepthMismatchCount');
  if ([valid, requested, invalid, stepLimited, unknownOpcodeCount, targetEffects, unmappedTargetEffects,
    frameIdentityAvailable, frameIdentityPartial, frameIdentityUnavailable, targetCodeStepCount,
    targetFrameDepthMismatchCount].includes(null) ||
      unmappedTargetEffects > targetEffects) return 'unavailable';
  if (valid === 0) return requested > 0 || invalid > 0
    ? 'unavailable' : 'not_performed';
  if (invalid > 0 || stepLimited > 0 || unknownOpcodeCount > 0) return 'partial';
  if (frameIdentityAvailable + frameIdentityPartial === 0) return 'unavailable';
  if (frameIdentityPartial > 0 || frameIdentityUnavailable > 0 || targetFrameDepthMismatchCount > 0) return 'partial';
  if (targetCodeStepCount === 0) return 'unavailable';
  if (targetEffects === 0) return 'not_applicable';
  return unmappedTargetEffects > 0 ? 'partial' : 'available';
}

function normalizeFrameAddress(value) {
  if (typeof value !== 'string') {
    if (value && typeof value.toString === 'function') value = value.toString();
    else return null;
  }
  return /^0x[0-9a-fA-F]{40}$/.test(value) ? value.toLowerCase() : null;
}

function findHardhatEvmEvents(provider) {
  const queue = [provider];
  const visited = new Set();
  while (queue.length > 0) {
    const value = queue.shift();
    if (!value || (typeof value !== 'object' && typeof value !== 'function') || visited.has(value)) continue;
    visited.add(value);
    const events = value._node?._vm?.evm?.events;
    if (events && typeof events.on === 'function' && typeof events.off === 'function') return events;
    for (const key of ['provider', '_wrapped', '_provider', '_wrappedProvider']) {
      try { queue.push(value[key]); } catch {}
    }
  }
  return null;
}

function createFrameStepCapture(maxSteps) {
  let capacity = Math.min(maxSteps, 1024);
  let stepCount = 0;
  let programCounters = new Float64Array(capacity);
  let depths = new Uint32Array(capacity);
  let opcodeIds = new Uint32Array(capacity);
  let codeAddressIds = new Uint32Array(capacity);
  const opcodes = [''];
  const opcodeIdByName = new Map();
  const frameAddresses = [null];
  const frameAddressIdByValue = new Map();

  function intern(value, values, ids) {
    let id = ids.get(value);
    if (id === undefined) {
      id = values.length;
      if (id > 0xffffffff) return null;
      values.push(value);
      ids.set(value, id);
    }
    return id;
  }

  function grow() {
    const nextCapacity = Math.min(maxSteps, Math.max(1, capacity * 2));
    if (nextCapacity <= capacity) return false;
    const nextProgramCounters = new Float64Array(nextCapacity);
    const nextDepths = new Uint32Array(nextCapacity);
    const nextOpcodeIds = new Uint32Array(nextCapacity);
    const nextCodeAddressIds = new Uint32Array(nextCapacity);
    nextProgramCounters.set(programCounters);
    nextDepths.set(depths);
    nextOpcodeIds.set(opcodeIds);
    nextCodeAddressIds.set(codeAddressIds);
    programCounters = nextProgramCounters;
    depths = nextDepths;
    opcodeIds = nextOpcodeIds;
    codeAddressIds = nextCodeAddressIds;
    capacity = nextCapacity;
    return true;
  }

  function append(step, codeAddress) {
    if (stepCount >= maxSteps) return false;
    if (stepCount >= capacity && !grow()) return false;
    const opcodeId = intern(step.op, opcodes, opcodeIdByName);
    const codeAddressId = codeAddress === null
      ? 0
      : intern(codeAddress, frameAddresses, frameAddressIdByValue);
    if (opcodeId === null || codeAddressId === null) return false;
    programCounters[stepCount] = step.pc;
    depths[stepCount] = step.depth;
    opcodeIds[stepCount] = opcodeId;
    codeAddressIds[stepCount] = codeAddressId;
    stepCount++;
    return true;
  }

  return {
    get stepCount() { return stepCount; },
    get programCounters() { return programCounters; },
    get depths() { return depths; },
    get opcodeIds() { return opcodeIds; },
    get codeAddressIds() { return codeAddressIds; },
    opcodes,
    frameAddresses,
    frames:[],
    invalid:false,
    initialStepSeen:false,
    append,
  };
}

// This depends on Hardhat 2.22.19's private provider._node._vm.evm.events path
// and the locked EDR 0.8.0 transaction-time event behavior. Keep this listener
// scoped to selected target transactions so calls and gas estimates stay cheap;
// trace alignment fails closed if a dependency change alters the event stream.
function installHardhatFrameIdentityCapture(provider, shouldCaptureTransaction,
  maxCapturedSteps = MAX_TRACE_STEPS) {
  if (!Number.isSafeInteger(maxCapturedSteps) || maxCapturedSteps < 0) {
    throw new RangeError('maxCapturedSteps must be a non-negative safe integer');
  }
  const events = findHardhatEvmEvents(provider);
  if (!events || !provider || typeof provider.request !== 'function') {
    return {supported:false, take:()=>null, discard:()=>false, dispose:()=>{}};
  }
  const captures = new Map();
  const originalDescriptor = Object.getOwnPropertyDescriptor(provider, 'request');
  const originalRequest = provider.request.bind(provider);
  let active = null;
  let disposed = false;

  const onBeforeMessage = (message) => {
    if (!active || active.invalid || disposed) return;
    const address = normalizeFrameAddress(message?.codeAddress) || normalizeFrameAddress(message?.to);
    active.frames.push(address);
  };
  const onAfterMessage = () => {
    if (!active || active.invalid || disposed) return;
    if (active.frames.length === 0) active.invalid = true;
    else active.frames.pop();
  };
  const onStep = (step) => {
    if (!active || active.invalid || disposed) return;
    const row = {pc:Number(step.pc),depth:step.depth,op:step.opcode?.name};
    if (!Number.isSafeInteger(row.pc) || !Number.isSafeInteger(row.depth) || row.depth < 1 || row.depth > 0xffffffff ||
        typeof row.op !== 'string') {
      active.invalid = true;
      return;
    }
    // Hardhat removes one leading REVM STOP from debug_traceTransaction output.
    if (!active.initialStepSeen) {
      active.initialStepSeen = true;
      if (row.op === 'STOP') return;
    }
    if (!active.append(row, active.frames.at(-1) || null)) {
      active.invalid = true;
      return;
    }
  };

  const detachListeners = () => {
    events.off('beforeMessage', onBeforeMessage);
    events.off('afterMessage', onAfterMessage);
    events.off('step', onStep);
  };

  provider.request = async function(args) {
    if (disposed) return originalRequest(args);
    let selected = false;
    try {
      selected = args?.method === 'eth_sendTransaction' &&
        typeof shouldCaptureTransaction === 'function' && shouldCaptureTransaction(args.params?.[0]);
    } catch {}
    if (!selected) return originalRequest(args);
    if (active) {
      active.invalid = true;
      return originalRequest(args);
    }

    const capture = createFrameStepCapture(maxCapturedSteps);
    active = capture;
    events.on('beforeMessage', onBeforeMessage);
    events.on('afterMessage', onAfterMessage);
    events.on('step', onStep);
    try {
      const hash = await originalRequest(args);
      if (!disposed && typeof hash === 'string' && /^0x[0-9a-fA-F]{64}$/.test(hash)) {
        captures.set(hash.toLowerCase(),capture);
      }
      return hash;
    } finally {
      detachListeners();
      if (active === capture) active = null;
    }
  };

  const take = (transactionHash) => {
    if (typeof transactionHash !== 'string') return null;
    const key = transactionHash.toLowerCase();
    const capture = captures.get(key) || null;
    captures.delete(key);
    return capture;
  };
  const discard = (transactionHash) => {
    if (typeof transactionHash !== 'string') return false;
    return captures.delete(transactionHash.toLowerCase());
  };
  const dispose = () => {
    if (disposed) return;
    disposed = true;
    if (active) active.invalid=true;
    detachListeners();
    active = null;
    if (originalDescriptor) Object.defineProperty(provider, 'request', originalDescriptor);
    else delete provider.request;
    captures.clear();
  };
  return {supported:true,take,discard,dispose};
}

function alignTraceFrameIdentities(trace, capture) {
  const compactCapture = capture && Number.isSafeInteger(capture.stepCount) &&
    capture.programCounters instanceof Float64Array && capture.depths instanceof Uint32Array &&
    capture.opcodeIds instanceof Uint32Array && capture.codeAddressIds instanceof Uint32Array &&
    Array.isArray(capture.opcodes) && Array.isArray(capture.frameAddresses);
  const legacySteps = !compactCapture && Array.isArray(capture?.steps) ? capture.steps : null;
  const captureLength = compactCapture ? capture.stepCount : legacySteps?.length;
  if (!trace || !Array.isArray(trace.structLogs) || !capture || capture.invalid ||
      captureLength !== trace.structLogs.length || (compactCapture && capture.frameAddresses[0] !== null)) {
    return {state:'unavailable',codeAddresses:[]};
  }
  const validatedAddressIds = compactCapture
    ? new Uint8Array(Math.min(capture.frameAddresses.length, capture.stepCount + 1))
    : null;
  if (compactCapture && validatedAddressIds.length > 0) validatedAddressIds[0] = 1;
  const codeAddresses = [];
  for (let index=0; index<trace.structLogs.length; index++) {
    const expected = trace.structLogs[index];
    const observed = compactCapture ? null : legacySteps[index];
    const observedPc = compactCapture ? capture.programCounters[index] : observed?.pc;
    const observedDepth = compactCapture ? capture.depths[index] : observed?.depth;
    const observedOp = compactCapture ? capture.opcodes[capture.opcodeIds[index]] : observed?.op;
    const addressId = compactCapture ? capture.codeAddressIds[index] : null;
    const codeAddress = compactCapture
      ? addressId === 0 ? null : capture.frameAddresses[addressId]
      : observed?.codeAddress;
    let invalidCodeAddress=false;
    if (compactCapture) {
      if (addressId >= capture.frameAddresses.length || addressId >= validatedAddressIds.length) {
        invalidCodeAddress=true;
      } else if (addressId > 0 && validatedAddressIds[addressId] === 0) {
        invalidCodeAddress=normalizeFrameAddress(codeAddress) !== codeAddress;
        if (!invalidCodeAddress) validatedAddressIds[addressId] = 1;
      }
    }
    if (!hasValidTraceStep(expected) || (!compactCapture && !observed) ||
        expected.pc !== observedPc || expected.depth !== observedDepth || expected.op !== observedOp || invalidCodeAddress) {
      return {state:'unavailable',codeAddresses:[]};
    }
    codeAddresses.push(codeAddress);
  }
  return {state:codeAddresses.every(Boolean)?'available':'partial',codeAddresses};
}

function hasValidTraceSteps(trace) {
  return Boolean(trace && typeof trace.failed === 'boolean' && Array.isArray(trace.structLogs) &&
    trace.structLogs.length > 0 && trace.structLogs.every(hasValidTraceStep));
}

function summarizeTraceSteps(trace, targetDepth, sourceLocations, sourceCoverage,
  effectLimit = MAX_REPORTED_TRACE_EFFECTS, stepLimit = MAX_TRACE_STEPS, frameIdentity = null) {
  if (!trace || typeof trace.failed !== 'boolean' || !Array.isArray(trace.structLogs) ||
      trace.structLogs.length === 0) {
    throw new Error('trace response missing valid failed, structLogs, pc, op, or depth fields');
  }
  // debug_traceTransaction depths are one-based (the top-level frame is 1).
  // null explicitly disables source attribution for non-target traces;
  // accepting zero would otherwise silently classify every real step as a
  // nested call and could produce an apparently complete but empty sample.
  if (targetDepth !== null && (!Number.isSafeInteger(targetDepth) || targetDepth < 1)) {
    throw new RangeError('targetDepth must be a positive safe integer or null');
  }
  if (!Number.isSafeInteger(effectLimit) || effectLimit < 0) {
    throw new RangeError('effectLimit must be a non-negative safe integer');
  }
  if (!Number.isSafeInteger(stepLimit) || stepLimit < 0) {
    throw new RangeError('stepLimit must be a non-negative safe integer');
  }
  const targetCodeAddress = normalizeFrameAddress(frameIdentity?.targetCodeAddress);
  const normalizedAddressCache = new Map();
  const normalizeKnownFrameAddress = (address) => {
    if (!normalizedAddressCache.has(address)) normalizedAddressCache.set(address, normalizeFrameAddress(address));
    return normalizedAddressCache.get(address);
  };
  let frameIdentityValid = targetDepth === null || Boolean(frameIdentity &&
    ['available','partial'].includes(frameIdentity.state) &&
    Array.isArray(frameIdentity.codeAddresses) && frameIdentity.codeAddresses.length === trace.structLogs.length &&
    targetCodeAddress);
  let hasMissingFrameAddress = false;
  let frameAddressesRequireNormalization = false;
  if (frameIdentityValid && targetDepth !== null) {
    for (let index = 0; index < frameIdentity.codeAddresses.length; index++) {
      const address = frameIdentity.codeAddresses[index];
      if (address === null) {
        hasMissingFrameAddress = true;
        continue;
      }
      const normalizedAddress = normalizeKnownFrameAddress(address);
      if (!normalizedAddress) {
        frameIdentityValid = false;
        break;
      }
      if (normalizedAddress !== address) frameAddressesRequireNormalization = true;
    }
  }
  const frameIdentityState = targetDepth === null ? 'not_applicable' :
    !frameIdentityValid ? 'unavailable' : frameIdentity.state === 'partial' || hasMissingFrameAddress ? 'partial' : 'available';

  const opcodeCounts = {};
  let effects = [];
  const effectTargetFlags = [];
  let mappedTargetEffects = null;
  let unmappedTargetEffectsList = null;
  const pendingCoverage = new Map();
  const processedSteps = Math.min(trace.structLogs.length, stepLimit);
  const stepsTruncated = processedSteps < trace.structLogs.length;
  let effectCount = 0;
  let targetEffectCount = 0;
  let unmappedTargetEffects = 0;
  let nonTargetEffects = 0;
  let mappedEffects = 0;
  let unmappedEffects = 0;
  let targetCodeStepCount = 0;
  let targetFrameDepthMismatchCount = 0;
  const unknownOpcodes = new Set();
  for (let index = 0; index < processedSteps; index++) {
    const step = trace.structLogs[index];
    if (!hasValidTraceStep(step)) {
      throw new Error('trace response missing valid failed, structLogs, pc, op, or depth fields');
    }
    opcodeCounts[step.op] = (opcodeCounts[step.op] || 0) + 1;
    if (!EVM_OPCODE_NAMES.has(step.op)) unknownOpcodes.add(step.op);
    const codeAddress = frameIdentityValid && targetDepth !== null
      ? frameAddressesRequireNormalization
        ? normalizeKnownFrameAddress(frameIdentity.codeAddresses[index])
        : frameIdentity.codeAddresses[index]
      : null;
    const targetCodeStep = targetDepth !== null && frameIdentityValid && codeAddress === targetCodeAddress;
    if (targetCodeStep) {
      targetCodeStepCount++;
      if (step.depth !== targetDepth) targetFrameDepthMismatchCount++;
    }
    const targetStep = targetCodeStep && step.depth === targetDepth;
    const sourceLocation = targetStep ? (sourceLocations.get(step.pc) || null) : null;
    if (sourceLocation) {
      // Keep the digest in the key: a caller may reuse a coverage map across
      // source bundles, and file names can legally contain ':' characters.
      // JSON tuple encoding avoids ambiguous string concatenation collisions.
      const key = JSON.stringify([
        sourceLocation.file,
        sourceLocation.start,
        sourceLocation.length,
        sourceLocation.sourceSha256 || null,
      ]);
      if (!pendingCoverage.has(key) && !sourceCoverage.has(key)) pendingCoverage.set(key, sourceLocation);
    }
    if (!TRACE_EFFECT_KINDS.has(step.op)) continue;

    effectCount++;
    if (targetStep) {
      targetEffectCount++;
      if (sourceLocation) mappedEffects++;
      else unmappedTargetEffects++;
    } else {
      nonTargetEffects++;
    }
    if (!sourceLocation) unmappedEffects++;
    const overflowed = effectCount > effectLimit;
    if (overflowed && effectLimit > 0 && mappedTargetEffects === null) {
      mappedTargetEffects = [];
      unmappedTargetEffectsList = [];
      for (let index = 0; index < effects.length; index++) {
        const effect = effects[index];
        if (!effectTargetFlags[index]) continue;
        const bucket = effect.sourceLocation ? mappedTargetEffects : unmappedTargetEffectsList;
        bucket.push({ index, effect });
      }
    }
    const kind = !overflowed || (targetStep && effectLimit > 0)
      ? TRACE_EFFECT_KINDS.get(step.op)
      : null;
    const priorityBucket = overflowed && targetStep && TRACE_EFFECT_KINDS.has(step.op) && effectLimit > 0
      ? sourceLocation ? mappedTargetEffects : unmappedTargetEffectsList
      : null;
    const keepInTracePrefix = effects.length < effectLimit;
    const keepByTargetPriority = priorityBucket !== null && priorityBucket.length < effectLimit;
    if (!keepInTracePrefix && !keepByTargetPriority) continue;
    const effect = {
      pc: step.pc,
      op: step.op,
      depth: step.depth,
      sourceLocation,
      effectSiteId: kind && sourceLocation ? effectSiteId(sourceLocation, kind) : null,
    };
    if (keepInTracePrefix) {
      effects.push(effect);
      effectTargetFlags.push(targetStep);
    }
    if (keepByTargetPriority) priorityBucket.push({ index: effectCount - 1, effect });
  }
  for (const [key, sourceLocation] of pendingCoverage) sourceCoverage.set(key, sourceLocation);

  let effectRetentionPolicy = 'trace_order';
  if (effectCount > effectLimit) {
    const prioritized = [];
    const selectedIndices = new Set();
    const tracePrefix = effects.map((effect, index) => ({ index, effect }));
    for (const record of [...(mappedTargetEffects || []), ...(unmappedTargetEffectsList || []), ...tracePrefix]) {
      if (prioritized.length >= effectLimit) break;
      if (selectedIndices.has(record.index)) continue;
      selectedIndices.add(record.index);
      prioritized.push(record);
    }
    prioritized.sort((left, right) => left.index - right.index);
    if (prioritized.some((record, index) => record.effect !== effects[index])) {
      effects = prioritized.map((record) => record.effect);
      effectRetentionPolicy = 'target_depth_mapped_then_unmapped_when_truncated';
    }
  }

  return {
    steps: trace.structLogs.length,
    processedSteps,
    stepLimit,
    stepsTruncated,
    opcodeCounts,
    unknownOpcodeCount: [...unknownOpcodes].reduce((count, opcode) => count + opcodeCounts[opcode], 0),
    unknownOpcodes: [...unknownOpcodes].sort(),
    effectCount,
    effectCountComplete: !stepsTruncated,
    targetEffectCount,
    unmappedTargetEffects,
    targetCodeStepCount,
    targetFrameDepthMismatchCount,
    frameIdentityState,
    sourceAttributionState: traceSourceAttributionState({targetEffectCount, unmappedTargetEffects, stepsTruncated,
      targetCodeStepCount, targetFrameDepthMismatchCount, frameIdentityState}),
    nonTargetEffects,
    effects,
    effectsTruncated: effects.length < effectCount,
    effectsLimit: effectLimit,
    mappedEffects,
    unmappedEffects,
    effectRetentionPolicy,
  };
}

function traceEvidenceState(stats) {
  const count = (name) => Number.isSafeInteger(stats?.[name]) && stats[name] >= 0 ? stats[name] : 0;
  const valid = count('valid');
  if (valid === 0) return count('requested') > 0 || count('invalid') > 0
    ? 'unavailable' : 'not_performed';
  return count('invalid') > 0 || count('truncated') > 0 || count('stepLimited') > 0 ||
    count('unknownOpcodeCount') > 0 ? 'partial' : 'available';
}

const RAW_CALLDATA_PATTERN = /^0x(?:[0-9a-fA-F]{2})*$/;
const MAX_RETAINED_CALLDATA_BYTES = 512 * 1024;
const MAX_TRANSACTION_RECORDS = 4096;
const EVM_HASH_PATTERN = /^0x[0-9a-fA-F]{64}$/;
const MAX_RETAINED_EVENTS = 256;
const MAX_EVENT_TOPICS = 32;
const ERC20_TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

function erc20TransferEvent(event) {
  if (event.topics.length !== 3 || event.topics[0] !== ERC20_TRANSFER_TOPIC ||
      !/^0x[0-9a-f]{64}$/.test(event.data)) return null;
  const indexedAddress = (topic) => /^0x0{24}[0-9a-f]{40}$/.test(topic)
    ? `0x${topic.slice(-40)}` : null;
  const from = indexedAddress(event.topics[1]);
  const to = indexedAddress(event.topics[2]);
  if (!from || !to) return null;
  return {
    kind: 'erc20_transfer_event',
    source: 'receipt_event',
    stateAuthority: 'not_balance_diff',
    token: event.address,
    from,
    to,
    amount: BigInt(event.data).toString(),
    logIndex: event.index,
  };
}

function normalizeReceiptEvents(value) {
  if (!Array.isArray(value)) return {state: 'unavailable'};
  if (value.length > MAX_RETAINED_EVENTS) {
    return {state: 'omitted', count: value.length, reason: 'event_log_count_exceeds_retention_limit'};
  }
  const events = [];
  for (const [index, raw] of value.entries()) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      return {state: 'invalid', reason: `event_${index}_must_be_an_object`};
    }
    const address = typeof raw.address === 'string' && /^0x[0-9a-fA-F]{40}$/.test(raw.address)
      ? raw.address.toLowerCase() : null;
    const data = raw.data ?? raw.input ?? '0x';
    const topics = raw.topics;
    if (!address || typeof data !== 'string' || !RAW_CALLDATA_PATTERN.test(data) ||
        !Array.isArray(topics) || topics.length > MAX_EVENT_TOPICS ||
        topics.some((topic) => typeof topic !== 'string' || !EVM_HASH_PATTERN.test(topic))) {
      return {state: 'invalid', reason: `event_${index}_has_invalid_address_topics_or_data`};
    }
    const event = {address, topics: topics.map((topic) => topic.toLowerCase()), data};
    if (Number.isSafeInteger(raw.index) && raw.index >= 0) event.index = raw.index;
    events.push(event);
  }
  const assetChanges = events.map(erc20TransferEvent).filter(Boolean);
  return {state: 'available', events, assetChanges};
}

function normalizeTransactionMetadata(metadata) {
  const input = metadata && typeof metadata === 'object' ? metadata : {};
  const result = {};
  for (const key of ['transactionHash', 'from', 'caller', 'to', 'value']) {
    const value = input[key];
    if (typeof value === 'string' && value.length <= 512) result[key] = value;
    else if (typeof value === 'bigint') result[key] = value.toString();
  }
  const raw = input.calldata ?? input.data ?? input.input ?? input.rawCalldata;
  if (raw === undefined || raw === null) {
    result.rawCalldataState = 'unavailable';
  } else if (typeof raw !== 'string' || !RAW_CALLDATA_PATTERN.test(raw)) {
    result.rawCalldataState = 'invalid';
    result.rawCalldataReason = 'calldata_must_be_even_length_0x_hex';
  } else if ((raw.length - 2) / 2 > MAX_RETAINED_CALLDATA_BYTES) {
    result.rawCalldataState = 'omitted';
    result.rawCalldataReason = 'calldata_exceeds_retention_limit';
    result.rawCalldataSha256 = stableHash(raw.toLowerCase());
    result.rawCalldataBytes = (raw.length - 2) / 2;
  } else {
    result.rawCalldataState = 'available';
    result.rawCalldata = raw;
    result.rawCalldataBytes = (raw.length - 2) / 2;
  }
  if (typeof input.sequenceId === 'string' && input.sequenceId.length <= 256 && input.sequenceId) {
    result.sequenceId = input.sequenceId;
  }
  for (const key of ['blockNumber', 'blockTime']) {
    const value = input[key];
    if (typeof value === 'bigint') result[key] = value.toString();
    else if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) result[key] = String(value);
    else if (typeof value === 'string' && value.length <= 80 && /^(?:0x[0-9a-fA-F]+|[0-9]+)$/.test(value)) result[key] = value;
  }
  if (typeof input.blockHash === 'string' && EVM_HASH_PATTERN.test(input.blockHash)) {
    result.blockHash = input.blockHash.toLowerCase();
  }
  if (Object.hasOwn(input, 'events')) {
    const normalizedEvents = normalizeReceiptEvents(input.events);
    result.eventsState = normalizedEvents.state;
    if (normalizedEvents.events) result.events = normalizedEvents.events;
    if (normalizedEvents.assetChanges) {
      result.assetChanges = normalizedEvents.assetChanges;
      result.assetChangesState = normalizedEvents.assetChanges.length ? 'available' : 'not_observed';
    }
    if (normalizedEvents.reason) result.eventsReason = normalizedEvents.reason;
    if (normalizedEvents.count !== undefined) result.eventsCount = normalizedEvents.count;
  }
  return result;
}

function mergeTransactionMetadata(record, metadata) {
  const normalized = normalizeTransactionMetadata(metadata);
  for (const [key, value] of Object.entries(normalized)) {
    if (key === 'rawCalldata' && record.rawCalldata !== undefined) continue;
    if (key === 'rawCalldataState' && record.rawCalldataState !== undefined && value === 'unavailable') continue;
    if (key === 'events' && record.events !== undefined) continue;
    if (key === 'eventsState' && record.eventsState === 'available') continue;
    record[key] = value;
  }
  return record;
}

// Keep transaction-level coverage separate from opcode evidence. A suite may
// pass its assertions while a target transaction reverted or its trace was
// unavailable, so callers need an explicit state for the sequence itself.
// The optional metadata path records the actual transaction envelope. This is
// deliberately independent of ABI decoding, so raw calldata remains evidence
// even when a selector has no known ABI fragment.
function createTransactionEvidenceTracker({maxTransactionRecords = MAX_TRANSACTION_RECORDS} = {}) {
  if (!Number.isSafeInteger(maxTransactionRecords) || maxTransactionRecords < 1) {
    throw new TypeError('maxTransactionRecords must be a positive safe integer');
  }
  const stats = {
    submitted: 0,
    committed: 0,
    reverted: 0,
    outcomeUnknown: 0,
    traceRequested: 0,
    traceValid: 0,
    tracePartial: 0,
    traceUnavailable: 0,
    skipped: 0,
    selectors: new Set(),
    scenarios: new Set(),
    transactions: [],
    sequencePositions: new Map(),
    transactionRecordsOmitted: 0,
    omittedTransactionIds: new Set(),
  };
  const noteContext = (scenario, selector) => {
    if (typeof scenario === 'string' && scenario) stats.scenarios.add(scenario);
    if (typeof selector === 'string' && selector) stats.selectors.add(selector);
  };
  const findTransaction = (metadata, scenario, unresolvedOnly = false) => {
    const transactionId = metadata && typeof metadata === 'object' ? metadata.transactionId : metadata;
    if (typeof transactionId === 'string') {
      const exact = stats.transactions.find((item) => item.id === transactionId);
      return exact || null;
    }
    for (let index = stats.transactions.length - 1; index >= 0; index--) {
      const item = stats.transactions[index];
      if (typeof scenario === 'string' && item.sequenceId !== scenario && item.scenario !== scenario) continue;
      if (unresolvedOnly && item.outcome !== null) continue;
      return item;
    }
    return null;
  };
  const sequenceIdFor = (scenario, metadata) => {
    const normalized = normalizeTransactionMetadata(metadata);
    return normalized.sequenceId || (typeof scenario === 'string' && scenario ? scenario : 'default');
  };
  return {
    submitted(scenario, metadata = {}) {
      const index = stats.submitted;
      stats.submitted++;
      const sequenceId = sequenceIdFor(scenario, metadata);
      noteContext(sequenceId);
      const sequencePosition = stats.sequencePositions.get(sequenceId) || 0;
      stats.sequencePositions.set(sequenceId, sequencePosition + 1);
      const transactionId = `tx-${index}`;
      if (stats.transactions.length >= maxTransactionRecords) {
        stats.transactionRecordsOmitted++;
        if (stats.omittedTransactionIds.size < maxTransactionRecords) {
          stats.omittedTransactionIds.add(transactionId);
        }
        return transactionId;
      }
      const transaction = {
        id: transactionId,
        index,
        sequenceId,
        scenario: typeof scenario === 'string' && scenario ? scenario : sequenceId,
        sequencePosition,
        outcome: null,
        selector: null,
        traceState: null,
        skipped: false,
      };
      mergeTransactionMetadata(transaction, metadata);
      stats.transactions.push(transaction);
      return transaction.id;
    },
    outcome(status, metadata = {}) {
      const scenario = metadata && typeof metadata === 'object' ? metadata.sequenceId || metadata.scenario : undefined;
      const transaction = findTransaction(metadata, scenario, true);
      // A submitted transaction without a final receipt is not complete
      // execution evidence, even when its opcode trace was collected.
      const omitted = !transaction && metadata && typeof metadata === 'object' &&
        typeof metadata.transactionId === 'string' && stats.omittedTransactionIds.has(metadata.transactionId);
      if (!transaction && !omitted) return false;
      if (transaction) {
        if (transaction.outcome !== null) return false;
        mergeTransactionMetadata(transaction, metadata);
        transaction.outcome = status === 'committed' || status === 'reverted' ? status : 'unknown';
      }
      if (omitted) stats.omittedTransactionIds.delete(metadata.transactionId);
      if (status === 'committed') stats.committed++;
      else if (status === 'reverted') stats.reverted++;
      else stats.outcomeUnknown++;
      return true;
    },
    trace(selector, evidence, scenario, metadata = {}) {
      stats.traceRequested++;
      noteContext(scenario, selector);
      const transaction = findTransaction(metadata, scenario, false);
      if (transaction) {
        transaction.selector = typeof selector === 'string' ? selector : transaction.selector;
        mergeTransactionMetadata(transaction, metadata);
      }
      if (!evidence || evidence.traceValid !== true) {
        stats.traceUnavailable++;
        if (transaction) transaction.traceState = 'unavailable';
        return;
      }
      stats.traceValid++;
      if (evidence.state === 'partial') stats.tracePartial++;
      if (transaction) transaction.traceState = evidence.state === 'partial' ? 'partial' : 'available';
    },
    skipped(selector, scenario, metadata = {}) {
      stats.skipped++;
      noteContext(scenario, selector);
      const transaction = findTransaction(metadata, scenario, false);
      if (transaction) {
        transaction.selector = typeof selector === 'string' ? selector : transaction.selector;
        transaction.traceState = 'skipped';
        transaction.skipped = true;
        mergeTransactionMetadata(transaction, metadata);
      }
    },
    snapshot() {
      const outcomeComplete = stats.outcomeUnknown === 0 &&
        stats.committed + stats.reverted === stats.submitted;
      let state = 'not_performed';
      if (stats.submitted > 0) {
        state = !outcomeComplete || stats.traceUnavailable > 0 || stats.outcomeUnknown > 0
          ? 'unavailable'
          : stats.tracePartial > 0 || stats.transactionRecordsOmitted > 0
            ? 'partial'
            : 'available';
      }
      const transactionRows = stats.transactions.map((item) => ({...item}));
      const rawCalldataCounts = transactionRows.reduce((counts, item) => {
        counts[item.rawCalldataState || 'unavailable'] = (counts[item.rawCalldataState || 'unavailable'] || 0) + 1;
        return counts;
      }, {});
      const rawAvailable = rawCalldataCounts.available || 0;
      const rawState = transactionRows.length === 0
        ? (stats.transactionRecordsOmitted > 0 ? 'omitted' : 'not_performed')
        : rawAvailable === transactionRows.length && stats.transactionRecordsOmitted === 0 ? 'available'
          : rawAvailable > 0 ? 'partial' : stats.transactionRecordsOmitted > 0 ? 'omitted' : 'unavailable';
      const sequenceRows = [...new Set(transactionRows.map((item) => item.sequenceId))].sort().map((sequenceId) => {
        const rows = transactionRows.filter((item) => item.sequenceId === sequenceId);
        const complete = rows.length > 0 && rows.every((item) => item.outcome === 'committed' || item.outcome === 'reverted');
        return {
          id: sequenceId,
          transactionIds: rows.map((item) => item.id),
          transactionCount: rows.length,
          outcomeState: complete ? 'available' : 'incomplete',
          rawCalldataState: rows.every((item) => item.rawCalldataState === 'available') ? 'available' :
            rows.some((item) => item.rawCalldataState === 'available') ? 'partial' : 'unavailable',
        };
      });
      const eventCounts = transactionRows.reduce((counts, item) => {
        const state = item.eventsState || 'unavailable';
        counts[state] = (counts[state] || 0) + 1;
        return counts;
      }, {});
      const eventAvailable = eventCounts.available || 0;
      const eventState = transactionRows.length === 0
        ? (stats.transactionRecordsOmitted > 0 ? 'omitted' : 'not_performed')
        : eventAvailable === transactionRows.length && stats.transactionRecordsOmitted === 0 ? 'available'
          : eventAvailable > 0 ? 'partial' : stats.transactionRecordsOmitted > 0 ? 'omitted' : 'unavailable';
      const assetChangeRows = transactionRows.filter((item) => item.assetChangesState === 'available');
      const assetChangeTransactions = transactionRows.filter((item) => ['available', 'not_observed'].includes(item.assetChangesState));
      const assetChangeCount = assetChangeRows.reduce((sum, item) => sum + item.assetChanges.length, 0);
      const assetChangeState = transactionRows.length === 0
        ? (stats.transactionRecordsOmitted > 0 ? 'omitted' : 'not_performed')
        : assetChangeTransactions.length === transactionRows.length && stats.transactionRecordsOmitted === 0
          ? (assetChangeCount > 0 ? 'available' : 'not_observed')
          : assetChangeTransactions.length > 0 ? 'partial' : stats.transactionRecordsOmitted > 0 ? 'omitted' : 'unavailable';
      const blockTimeRows = transactionRows.filter((item) => item.blockTime !== undefined);
      const blockTimeState = transactionRows.length > 0 && blockTimeRows.length === transactionRows.length && stats.transactionRecordsOmitted === 0
        ? 'available' : blockTimeRows.length > 0 ? 'partial' : stats.transactionRecordsOmitted > 0 ? 'omitted' : 'unavailable';
      return {
        state,
        submitted: stats.submitted,
        committed: stats.committed,
        reverted: stats.reverted,
        outcomeUnknown: stats.outcomeUnknown,
        outcomeComplete,
        traceRequested: stats.traceRequested,
        traceValid: stats.traceValid,
        tracePartial: stats.tracePartial,
        traceUnavailable: stats.traceUnavailable,
        skipped: stats.skipped,
        samplingBounded: stats.skipped > 0,
        selectorCount: stats.selectors.size,
        selectors: [...stats.selectors].sort(),
        scenarioCount: stats.scenarios.size,
        scenarios: [...stats.scenarios].sort(),
        transactionCount: transactionRows.length,
        transactionRecordsOmitted: stats.transactionRecordsOmitted,
        transactions: transactionRows,
        sequenceCount: sequenceRows.length,
        sequences: sequenceRows,
        rawCalldata: {
          state: rawState,
          transactionCount: transactionRows.length,
          availableCount: rawAvailable,
          unavailableCount: transactionRows.length - rawAvailable,
          omittedCount: stats.transactionRecordsOmitted,
          counts: rawCalldataCounts,
          abiIndependent: true,
        },
        blockTime: {
          state: blockTimeState,
          availableCount: blockTimeRows.length,
          transactionCount: transactionRows.length,
          omittedCount: stats.transactionRecordsOmitted,
        },
        events: {
          state: eventState,
          availableCount: eventAvailable,
          transactionCount: transactionRows.length,
          omittedCount: stats.transactionRecordsOmitted,
          counts: eventCounts,
        },
        assetChanges: {
          state: assetChangeState,
          source: 'receipt_event',
          stateAuthority: 'not_balance_diff',
          recognizedStandard: 'ERC-20 Transfer(address,address,uint256)',
          availableTransactionCount: assetChangeTransactions.length,
          transactionCount: transactionRows.length,
          transferEventCount: assetChangeCount,
          omittedTransactionCount: stats.transactionRecordsOmitted,
          scope: '仅按标准 ERC-20 Transfer 收据事件提取；不证明余额变化或资产实际转移',
        },
        transactionSequence: {
          state: transactionRows.length === 0
            ? (stats.transactionRecordsOmitted > 0 ? 'omitted' : 'not_performed')
            : outcomeComplete && stats.transactionRecordsOmitted === 0 ? 'available' : 'incomplete',
          ordered: stats.transactionRecordsOmitted === 0 && transactionRows.every((item, index) => item.index === index && item.sequencePosition >= 0),
          sequenceCount: sequenceRows.length,
          omittedCount: stats.transactionRecordsOmitted,
        },
        transactionRetention: {
          state: stats.transactionRecordsOmitted > 0 ? 'partial' : 'complete',
          limit: maxTransactionRecords,
          retained: transactionRows.length,
          omitted: stats.transactionRecordsOmitted,
        },
        scope: '目标合约交易级统计；明细受留档上限约束；不代表 fork、完整分支覆盖或部署状态可达性',
      };
    },
  };
}

async function captureTraceSafely(transactionHash, collect, onFailure = () => {}) {
  try {
    return await collect();
  } catch (error) {
    onFailure(error);
    const reason = error instanceof Error ? error.message : String(error);
    return {
      transactionHash,
      state: 'unavailable',
      traceValid: false,
      reason: (reason || 'trace collection failed').slice(0, 200),
    };
  }
}

function traceSupportHash(root) {
  const digest = crypto.createHash('sha256');
  for (const name of ['evm-source-map.cjs', 'dynamic-trace-support.cjs', 'dynamic-execution-boundary.cjs']) {
    digest.update(name, 'utf8');
    digest.update('\0', 'utf8');
    digest.update(fs.readFileSync(path.join(root, name)));
    digest.update('\0', 'utf8');
  }
  return digest.digest('hex');
}

module.exports = {
  createTraceSampler, markTraceSampleComplete, traceSummaryEvidenceState, traceSourceAttributionState,
  traceSourceAttributionEvidenceState, installHardhatFrameIdentityCapture, alignTraceFrameIdentities,
  stableHash, hasValidTraceSteps, summarizeTraceSteps, traceEvidenceState,
  createTransactionEvidenceTracker,
  captureTraceSafely, traceSupportHash, MAX_TRACE_STEPS,
};
