import test from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {createRequire} from 'node:module';
const {createTraceSampler,markTraceSampleComplete,traceSummaryEvidenceState,traceSourceAttributionState,traceSourceAttributionEvidenceState,installHardhatFrameIdentityCapture,alignTraceFrameIdentities,stableHash,hasValidTraceSteps,summarizeTraceSteps:summarizeTraceStepsRaw,traceEvidenceState,createTransactionEvidenceTracker,captureTraceSafely}=createRequire(import.meta.url)('../scripts/dynamic-trace-support.cjs');
const TEST_TARGET_CODE='0x1111111111111111111111111111111111111111';
const TEST_OTHER_CODE='0x2222222222222222222222222222222222222222';
function summarizeTraceSteps(trace,targetDepth,sourceLocations,sourceCoverage,effectLimit,stepLimit,frameIdentity) {
  if (frameIdentity === undefined) frameIdentity = {
    state:'available',targetCodeAddress:targetDepth===null?null:TEST_TARGET_CODE,
    codeAddresses:trace.structLogs.map(step=>targetDepth!==null&&step.depth===targetDepth?TEST_TARGET_CODE:TEST_OTHER_CODE),
  };
  return summarizeTraceStepsRaw(trace,targetDepth,sourceLocations,sourceCoverage,effectLimit,stepLimit,frameIdentity);
}

test('trace sampler keeps one committed and one reverted sample per selector', () => {
  const sampler = createTraceSampler();
  assert.equal(sampler.has('EngineChip', '0x12345678', false), false);
  sampler.markAttempted('EngineChip', '0x12345678', false);
  assert.equal(sampler.has('EngineChip', '0x12345678', false), true);
  assert.equal(sampler.has('EngineChip', '0x12345678', true), false);
  sampler.markAttempted('EngineChip', '0x12345678', true);
  assert.equal(sampler.has('EngineChip', '0x12345678', true), true);
  assert.equal(sampler.has('EngineChip', '0x87654321', false), false);
  assert.equal(sampler.has('AMTDepositPool', '0x12345678', false), false);
});

test('trace sampler separates colon-containing target and selector fields', () => {
  const sampler = createTraceSampler();
  sampler.markAttempted('A:B', 'C', false);
  assert.equal(sampler.has('A:B', 'C', false), true);
  assert.equal(sampler.has('A', 'B:C', false), false);
  sampler.markAttempted('A', 'B:C', false);
  assert.equal(sampler.has('A:B', 'C', false), true);
  assert.equal(sampler.has('A', 'B:C', false), true);
});

test('trace sampler commits only completed evidence so failed collection remains retryable', () => {
  const sampler = createTraceSampler();
  const target = 'VaultV2';
  const selector = 'withdraw(uint256)';
  assert.equal(markTraceSampleComplete(sampler, target, selector, true,
    {state:'unavailable', traceValid:false}), false);
  assert.equal(sampler.has(target, selector, true), false);
  assert.equal(markTraceSampleComplete(sampler, target, selector, true,
    {state:'available', traceValid:true}), true);
  assert.equal(sampler.has(target, selector, true), true);
});

test('partial trace summaries are valid samples and consume outcome quota', () => {
  const sampler = createTraceSampler();
  const target = 'EngineChip';
  const selector = '0x12345678';
  const partial = {stepsTruncated: false, effectsTruncated: true, effectCountComplete: true, unknownOpcodeCount: 0};
  assert.equal(traceSummaryEvidenceState(partial), 'partial');
  assert.equal(markTraceSampleComplete(sampler, target, selector, false,
    {state: traceSummaryEvidenceState(partial), traceValid: true}), true);
  assert.equal(sampler.has(target, selector, false), true);
  assert.equal(traceSummaryEvidenceState({stepsTruncated: false, effectsTruncated: false, effectCountComplete: true, unknownOpcodeCount: 0}), 'available');
});

test('stable source hashes ignore object insertion order but preserve array order', () => {
  assert.equal(stableHash({sources:{'A.sol':{content:'A'},'B.sol':{content:'B'}}}),
    stableHash({sources:{'B.sol':{content:'B'},'A.sol':{content:'A'}}}));
  assert.notEqual(stableHash({sources:['A.sol','B.sol']}), stableHash({sources:['B.sol','A.sol']}));
});

test('trace collection failures become unavailable evidence without throwing', async () => {
  let failures = 0;
  const result = await captureTraceSafely('0xabc', async () => {
    throw new Error('transaction lookup failed');
  }, () => { failures += 1; });
  assert.deepEqual(result, {
    transactionHash: '0xabc', state: 'unavailable', traceValid: false,
    reason: 'transaction lookup failed',
  });
  assert.equal(failures, 1);
});

test('trace collection preserves a valid result', async () => {
  const trace = { state: 'available', traceValid: true, effects: [] };
  assert.equal(await captureTraceSafely('0xabc', async () => trace), trace);
});

test('trace step validation requires usable program counters and positive depths', () => {
  const valid = { failed: false, structLogs: [{ op: 'PUSH1', pc: 0, depth: 1 }] };
  assert.equal(hasValidTraceSteps(valid), true);
  for (const step of [
    { op: 'SSTORE', pc: '5', depth: 1 },
    { op: 'SSTORE', pc: -1, depth: 1 },
    { op: 'SSTORE', pc: Number.MAX_SAFE_INTEGER + 1, depth: 1 },
    { op: 'SSTORE', pc: 5, depth: 0 },
    { op: 'SSTORE', pc: 5, depth: 1.5 },
    { op: '', pc: 5, depth: 1 },
    { op: '__proto__', pc: 5, depth: 1 },
  ]) assert.equal(hasValidTraceSteps({ failed: false, structLogs: [step] }), false);
  assert.equal(hasValidTraceSteps({ failed: false, structLogs: [] }), false);
  assert.equal(hasValidTraceSteps({ failed: false, structLogs: {} }), false);
  assert.equal(hasValidTraceSteps({ failed: 0, structLogs: [] }), false);
});

test('trace summarization rejects zero-based target depths', () => {
  const trace = {failed:false,structLogs:[{op:'PUSH1',pc:0,depth:1}]};
  assert.throws(() => summarizeTraceSteps(trace,0,new Map(),new Map()),
    /targetDepth must be a positive safe integer/);
  const summary = summarizeTraceSteps(trace,null,new Map([[0,{
    file:'Vault.sol',start:0,length:1,lineStart:1,lineEnd:1,sourceSha256:'a'.repeat(64),
  }]]),new Map());
  assert.equal(summary.targetEffectCount,0);
});

test('unknown opcodes remain visible and lower trace evidence to partial', () => {
  const summary = summarizeTraceSteps({failed:false,structLogs:[{op:'FUTUREOP',pc:0,depth:1}]},1,new Map(),new Map());
  assert.equal(summary.unknownOpcodeCount,1);
  assert.deepEqual(summary.unknownOpcodes,['FUTUREOP']);
  assert.equal(traceEvidenceState({requested:1,valid:1,invalid:0,truncated:0,unknownOpcodeCount:summary.unknownOpcodeCount}), 'partial');
});

test('Cancun MCOPY is treated as a known opcode', () => {
  const summary = summarizeTraceSteps({failed:false,structLogs:[{op:'MCOPY',pc:0,depth:1}]},1,new Map(),new Map());
  assert.equal(summary.unknownOpcodeCount,0);
  assert.equal(traceEvidenceState({requested:1,valid:1,invalid:0,truncated:0,unknownOpcodeCount:summary.unknownOpcodeCount}), 'available');
});

test('trace evidence distinguishes absent requests from failed collection', () => {
  assert.equal(traceEvidenceState({requested:0,valid:0,invalid:0,skipped:0,truncated:0}), 'not_performed');
  assert.equal(traceEvidenceState({requested:1,valid:0,invalid:1,skipped:0,truncated:0}), 'unavailable');
  assert.equal(traceEvidenceState({requested:1,valid:0,invalid:0,skipped:1,truncated:0}), 'unavailable');
  assert.equal(traceEvidenceState({requested:2,valid:1,invalid:1,skipped:0,truncated:0}), 'partial');
  assert.equal(traceEvidenceState({requested:1,valid:1,invalid:0,skipped:0,truncated:0}), 'available');
  assert.equal(traceEvidenceState({requested:1,valid:1,invalid:0,skipped:0,truncated:0,stepLimited:1}), 'partial');
});

test('transaction evidence records multi-transaction outcomes and partial traces', () => {
  const tracker = createTransactionEvidenceTracker();
  tracker.submitted('sequence-a');
  tracker.outcome('committed');
  tracker.trace('0x11111111', {traceValid: true, state: 'available'}, 'sequence-a');
  tracker.submitted('sequence-a');
  tracker.outcome('reverted');
  tracker.trace('0x11111111', {traceValid: true, state: 'partial'}, 'sequence-a');
  const snapshot = tracker.snapshot();
  assert.equal(snapshot.state, 'partial');
  assert.equal(snapshot.submitted, 2);
  assert.equal(snapshot.committed, 1);
  assert.equal(snapshot.reverted, 1);
  assert.equal(snapshot.outcomeComplete, true);
  assert.equal(snapshot.traceValid, 2);
  assert.equal(snapshot.tracePartial, 1);
  assert.deepEqual(snapshot.selectors, ['0x11111111']);
  assert.deepEqual(snapshot.scenarios, ['sequence-a']);
});

test('pending target transactions keep dynamic evidence unavailable until a final outcome is recorded', () => {
  const tracker = createTransactionEvidenceTracker();
  const transactionId = tracker.submitted('pending-sequence');
  tracker.trace('0x12345678', {traceValid: true, state: 'available'}, 'pending-sequence', {transactionId});

  const pending = tracker.snapshot();
  assert.equal(pending.state, 'unavailable');
  assert.equal(pending.outcomeComplete, false);
  assert.equal(pending.transactionSequence.state, 'incomplete');
  assert.equal(pending.transactions[0].outcome, null);

  assert.equal(tracker.outcome('committed', {transactionId}), true);
  assert.equal(tracker.outcome('reverted', {transactionId}), false);
  const completed = tracker.snapshot();
  assert.equal(completed.state, 'available');
  assert.equal(completed.outcomeComplete, true);
  assert.equal(completed.committed, 1);
  assert.equal(completed.reverted, 0);
});

test('outcomes for unknown transaction ids cannot make target evidence appear complete', () => {
  const tracker = createTransactionEvidenceTracker();
  const transactionId = tracker.submitted('mismatched-sequence');
  assert.equal(tracker.outcome('committed', {transactionId: 'tx-999'}), false);
  const snapshot = tracker.snapshot();
  assert.equal(snapshot.state, 'unavailable');
  assert.equal(snapshot.committed, 0);
  assert.equal(snapshot.outcomeComplete, false);
  assert.equal(snapshot.transactions[0].outcome, null);
});

test('transaction evidence marks missing traces unavailable and exposes fork boundary', () => {
  const tracker = createTransactionEvidenceTracker();
  tracker.submitted('sequence-b');
  tracker.outcome('committed');
  tracker.trace('fallback', {traceValid: false, state: 'unavailable'}, 'sequence-b');
  const snapshot = tracker.snapshot();
  assert.equal(snapshot.state, 'unavailable');
  assert.equal(snapshot.traceUnavailable, 1);
  assert.equal(snapshot.outcomeComplete, true);
  assert.match(snapshot.scope, /fork/);
});

test('bounded selector sampling remains available while recording skipped transactions', () => {
  const tracker = createTransactionEvidenceTracker();
  tracker.submitted('sequence-c');
  tracker.outcome('committed');
  tracker.skipped('0x22222222', 'sequence-c');
  const snapshot = tracker.snapshot();
  assert.equal(snapshot.state, 'available');
  assert.equal(snapshot.samplingBounded, true);
  assert.equal(snapshot.skipped, 1);
});

test('transaction evidence retains ordered raw calldata without ABI decoding', () => {
  const tracker = createTransactionEvidenceTracker();
  const committed = tracker.submitted('raw-sequence', {
    transactionHash: `0x${'1'.repeat(64)}`,
    from: `0x${'2'.repeat(40)}`,
    to: `0x${'3'.repeat(40)}`,
    value: 7n,
    calldata: '0xdeadbeef',
  });
  tracker.outcome('committed', {transactionId: committed});
  tracker.trace('0xdeadbeef', {traceValid: true, state: 'available'}, 'raw-sequence', {
    transactionId: committed,
  });
  const reverted = tracker.submitted('raw-sequence', {calldata: '0xabcdef'});
  tracker.outcome('reverted', {transactionId: reverted});
  tracker.trace('<fallback>', {traceValid: true, state: 'partial'}, 'raw-sequence', {
    transactionId: reverted,
  });

  const snapshot = tracker.snapshot();
  assert.equal(snapshot.transactionSequence.state, 'available');
  assert.equal(snapshot.transactionSequence.ordered, true);
  assert.equal(snapshot.rawCalldata.state, 'available');
  assert.equal(snapshot.rawCalldata.abiIndependent, true);
  assert.deepEqual(snapshot.transactions.map((item) => item.sequencePosition), [0, 1]);
  assert.equal(snapshot.transactions[0].rawCalldata, '0xdeadbeef');
  assert.equal(snapshot.transactions[0].rawCalldataState, 'available');
  assert.equal(snapshot.transactions[0].value, '7');
  assert.equal(snapshot.transactions[1].rawCalldata, '0xabcdef');
  assert.equal(snapshot.transactions[1].selector, '<fallback>');
  assert.equal(snapshot.sequences[0].transactionIds.length, 2);
});

test('raw calldata evidence fails closed when calldata is absent or malformed', () => {
  const tracker = createTransactionEvidenceTracker();
  const absent = tracker.submitted('raw-gap');
  tracker.outcome('committed', {transactionId: absent});
  const malformed = tracker.submitted('raw-gap', {calldata: '0xabc'});
  tracker.outcome('reverted', {transactionId: malformed});
  const snapshot = tracker.snapshot();

  assert.equal(snapshot.rawCalldata.state, 'unavailable');
  assert.equal(snapshot.rawCalldata.availableCount, 0);
  assert.equal(snapshot.transactions[0].rawCalldataState, 'unavailable');
  assert.equal(snapshot.transactions[1].rawCalldataState, 'invalid');
  assert.equal(snapshot.transactions[1].rawCalldata, undefined);
  assert.equal(snapshot.sequences[0].rawCalldataState, 'unavailable');
  assert.equal(snapshot.transactionSequence.state, 'available');
});

test('transaction evidence retains validated receipt block time and event topics', () => {
  const tracker = createTransactionEvidenceTracker();
  const id = tracker.submitted('receipt-sequence', {
    transactionHash: `0x${'4'.repeat(64)}`,
    calldata: '0xdeadbeef',
  });
  tracker.outcome('committed', {
    transactionId: id,
    blockNumber: 42,
    blockHash: `0x${'5'.repeat(64)}`,
    blockTime: 1700000000,
    events: [{
      address: `0x${'6'.repeat(40)}`,
      topics: [`0x${'7'.repeat(64)}`],
      data: '0x00ff',
      index: 0,
    }],
  });
  const snapshot = tracker.snapshot();
  assert.equal(snapshot.blockTime.state, 'available');
  assert.equal(snapshot.blockTime.availableCount, 1);
  assert.equal(snapshot.events.state, 'available');
  assert.deepEqual(snapshot.transactions[0].events[0], {
    address: `0x${'6'.repeat(40)}`,
    topics: [`0x${'7'.repeat(64)}`],
    data: '0x00ff',
    index: 0,
  });
  assert.equal(snapshot.transactions[0].blockTime, '1700000000');
  assert.equal(snapshot.transactions[0].blockHash, `0x${'5'.repeat(64)}`);
});

test('receipt event evidence fails closed for malformed logs and remains separate from calldata', () => {
  const tracker = createTransactionEvidenceTracker();
  const id = tracker.submitted('receipt-gap', {calldata: '0xabcdef'});
  tracker.outcome('committed', {
    transactionId: id,
    blockTime: 12,
    events: [{address: 'not-an-address', topics: [], data: '0x'}],
  });
  const snapshot = tracker.snapshot();
  assert.equal(snapshot.rawCalldata.state, 'available');
  assert.equal(snapshot.events.state, 'unavailable');
  assert.equal(snapshot.transactions[0].eventsState, 'invalid');
  assert.equal(snapshot.transactions[0].events, undefined);
});

test('receipt evidence extracts ERC-20 transfer event hints without claiming balance deltas', () => {
  const tracker = createTransactionEvidenceTracker();
  const id = tracker.submitted('transfer-sequence', {calldata: '0xdeadbeef'});
  tracker.outcome('committed', {
    transactionId: id,
    events: [{
      address: `0x${'a'.repeat(40)}`,
      topics: [
        '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
        `0x${'0'.repeat(24)}${'b'.repeat(40)}`,
        `0x${'0'.repeat(24)}${'c'.repeat(40)}`,
      ],
      data: `0x${(123456n).toString(16).padStart(64, '0')}`,
      index: 3,
    }],
  });
  const snapshot = tracker.snapshot();
  assert.deepEqual(snapshot.transactions[0].assetChanges, [{
    kind: 'erc20_transfer_event',
    source: 'receipt_event',
    stateAuthority: 'not_balance_diff',
    token: `0x${'a'.repeat(40)}`,
    from: `0x${'b'.repeat(40)}`,
    to: `0x${'c'.repeat(40)}`,
    amount: '123456',
    logIndex: 3,
  }]);
  assert.equal(snapshot.transactions[0].assetChangesState, 'available');
  assert.equal(snapshot.assetChanges.state, 'available');
  assert.equal(snapshot.assetChanges.transferEventCount, 1);
  assert.equal(snapshot.assetChanges.stateAuthority, 'not_balance_diff');
});

test('asset event hints distinguish no observed transfers, non-ERC20 Transfer logs, and unavailable receipts', () => {
  const tracker = createTransactionEvidenceTracker();
  const noTransfer = tracker.submitted('asset-sequence');
  tracker.outcome('committed', {transactionId: noTransfer, events: []});
  const nftTransfer = tracker.submitted('asset-sequence');
  tracker.outcome('committed', {transactionId: nftTransfer, events: [{
    address: `0x${'d'.repeat(40)}`,
    topics: [
      '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
      `0x${'0'.repeat(24)}${'e'.repeat(40)}`,
      `0x${'0'.repeat(24)}${'f'.repeat(40)}`,
      `0x${'1'.repeat(64)}`,
    ],
    data: '0x',
  }]});
  const unavailable = tracker.submitted('asset-sequence');
  tracker.outcome('committed', {transactionId: unavailable});
  const snapshot = tracker.snapshot();
  assert.equal(snapshot.transactions[0].assetChangesState, 'not_observed');
  assert.deepEqual(snapshot.transactions[0].assetChanges, []);
  assert.equal(snapshot.transactions[1].assetChangesState, 'not_observed');
  assert.deepEqual(snapshot.transactions[1].assetChanges, []);
  assert.equal(snapshot.transactions[2].assetChangesState, undefined);
  assert.equal(snapshot.assetChanges.state, 'partial');
});

test('transaction detail retention is bounded without hiding aggregate counts', () => {
  const tracker = createTransactionEvidenceTracker({maxTransactionRecords: 2});
  const first = tracker.submitted('bounded', {transactionHash: '0x1', calldata: '0x01'});
  const second = tracker.submitted('bounded', {transactionHash: '0x2', calldata: '0x02'});
  const omitted = tracker.submitted('bounded', {transactionHash: '0x3', calldata: '0x03'});
  tracker.outcome('committed', {transactionId: first});
  tracker.outcome('committed', {transactionId: second});
  assert.equal(tracker.outcome('committed', {transactionId: omitted}), true);
  assert.equal(tracker.outcome('committed', {transactionId: omitted}), false);
  const snapshot = tracker.snapshot();
  assert.equal(snapshot.state, 'partial');
  assert.equal(snapshot.submitted, 3);
  assert.equal(snapshot.committed, 3);
  assert.equal(snapshot.transactionCount, 2);
  assert.equal(snapshot.transactionRecordsOmitted, 1);
  assert.deepEqual(snapshot.transactionRetention, {state: 'partial', limit: 2, retained: 2, omitted: 1});
  assert.equal(snapshot.transactionSequence.state, 'incomplete');
  assert.equal(snapshot.transactionSequence.ordered, false);
  assert.equal(snapshot.rawCalldata.omittedCount, 1);
  assert.equal(snapshot.rawCalldata.state, 'partial');
});

test('trace summarization counts all effects while retaining only the bounded prefix', () => {
  const source = {file:'Vault.sol',start:4,length:3,lineStart:1,lineEnd:1,sourceSha256:'a'.repeat(64)};
  const trace = {failed:false,structLogs:[
    {op:'SSTORE',pc:0,depth:1}, {op:'CALL',pc:1,depth:2}, {op:'PUSH1',pc:2,depth:1},
  ]};
  const coverage = new Map();
  const summary = summarizeTraceSteps(trace,1,new Map([[0,source]]),coverage);
  assert.equal(summary.steps,3);
  assert.deepEqual(summary.opcodeCounts,{SSTORE:1,CALL:1,PUSH1:1});
  assert.equal(summary.effectCount,2);
  assert.equal(summary.effects.length,2);
  assert.equal(summary.effectsTruncated,false);
  assert.equal(summary.targetEffectCount,1);
  assert.equal(summary.mappedEffects,1);
  assert.equal(summary.unmappedTargetEffects,0);
  assert.equal(summary.nonTargetEffects,1);
  assert.equal(summary.unmappedEffects,1);
  assert.equal(summary.effects[0].effectSiteId.length,64);
  assert.equal(coverage.size,1);

  const repeated = {failed:false,structLogs:Array.from({length:3},(_,pc)=>({op:'SSTORE',pc,depth:1}))};
  const capped = summarizeTraceSteps(repeated,1,new Map(),new Map(),2);
  assert.equal(capped.effectCount,3);
  assert.equal(capped.effects.length,2);
  assert.equal(capped.effectsTruncated,true);
});

test('trace summary counts mapped effects beyond the output cap and commits coverage only after validation', () => {
  const source = {file:'Vault.sol',start:4,length:3,lineStart:1,lineEnd:1,sourceSha256:'a'.repeat(64)};
  const locations = new Map([[0,source],[1,source]]);
  const coverage = new Map();
  const capped = summarizeTraceSteps({failed:false,structLogs:[
    {op:'SSTORE',pc:0,depth:1}, {op:'SSTORE',pc:1,depth:1}, {op:'SSTORE',pc:2,depth:1},
  ]},1,locations,coverage,1);
  assert.equal(capped.effectCount,3);
  assert.equal(capped.targetEffectCount,3);
  assert.equal(capped.mappedEffects,2);
  assert.equal(capped.unmappedTargetEffects,1);
  assert.equal(capped.nonTargetEffects,0);
  assert.equal(capped.unmappedEffects,1);
  assert.equal(capped.effects.length,1);
  assert.equal(coverage.size,1);

  const unchangedCoverage = new Map();
  assert.throws(() => summarizeTraceSteps({failed:false,structLogs:[
    {op:'SSTORE',pc:0,depth:1}, {op:'SSTORE',pc:-1,depth:1},
  ]},1,locations,unchangedCoverage), /valid failed, structLogs, pc, op, or depth/);
  assert.equal(unchangedCoverage.size,0);
});

test('unmapped target effects lower source attribution without lowering trace structure state', () => {
  const source = {file:'Vault.sol',start:4,length:3,lineStart:1,lineEnd:1,sourceSha256:'a'.repeat(64)};
  const summary = summarizeTraceSteps({failed:false,structLogs:[
    {op:'SSTORE',pc:0,depth:1},
    {op:'CALL',pc:1,depth:2},
  ]},1,new Map([[0,source]]),new Map());

  assert.equal(summary.targetEffectCount,1);
  assert.equal(summary.unmappedTargetEffects,0);
  assert.equal(summary.sourceAttributionState,'available');
  assert.equal(traceSummaryEvidenceState(summary),'available');

  const unmapped = summarizeTraceSteps({failed:false,structLogs:[
    {op:'SSTORE',pc:1,depth:1},
  ]},1,new Map(),new Map());
  assert.equal(unmapped.targetEffectCount,1);
  assert.equal(unmapped.unmappedTargetEffects,1);
  assert.equal(unmapped.sourceAttributionState,'partial');
  assert.equal(traceSummaryEvidenceState(unmapped),'available');
});

test('source attribution requires the expected runtime code address and depth', () => {
  const source = {file:'Pool.sol',start:12,length:4,lineStart:2,lineEnd:2,sourceSha256:'b'.repeat(64)};
  const trace={failed:false,structLogs:[{op:'SSTORE',pc:4,depth:2}]};
  const wrongCodeCoverage=new Map();
  const wrongCode=summarizeTraceStepsRaw(trace,2,new Map([[4,source]]),wrongCodeCoverage,160,250000,
    {state:'available',targetCodeAddress:TEST_TARGET_CODE,codeAddresses:[TEST_OTHER_CODE]});
  assert.equal(wrongCode.targetEffectCount,0);
  assert.equal(wrongCode.effects[0].sourceLocation,null);
  assert.equal(wrongCodeCoverage.size,0);
  assert.equal(wrongCode.sourceAttributionState,'unavailable');

  const wrongDepth=summarizeTraceStepsRaw({failed:false,structLogs:[{op:'SSTORE',pc:4,depth:3}]},2,
    new Map([[4,source]]),new Map(),160,250000,
    {state:'available',targetCodeAddress:TEST_TARGET_CODE,codeAddresses:[TEST_TARGET_CODE]});
  assert.equal(wrongDepth.targetCodeStepCount,1);
  assert.equal(wrongDepth.targetFrameDepthMismatchCount,1);
  assert.equal(wrongDepth.targetEffectCount,0);
  assert.equal(wrongDepth.effects[0].sourceLocation,null);
  assert.equal(wrongDepth.sourceAttributionState,'partial');

  const missing=summarizeTraceStepsRaw(trace,2,new Map([[4,source]]),new Map());
  assert.equal(missing.frameIdentityState,'unavailable');
  assert.equal(missing.effects[0].sourceLocation,null);
  assert.equal(missing.sourceAttributionState,'unavailable');
});

test('frame identity validation rejects sparse addresses and still accepts valid mixed-case addresses', () => {
  const source = {file:'Pool.sol',start:12,length:4,lineStart:2,lineEnd:2,sourceSha256:'b'.repeat(64)};
  const trace={failed:false,structLogs:[
    {op:'SSTORE',pc:4,depth:1},
    {op:'SSTORE',pc:5,depth:1},
  ]};
  const sparseAddresses = new Array(2);
  sparseAddresses[0] = TEST_TARGET_CODE;
  const sparse = summarizeTraceStepsRaw(trace,1,new Map([[4,source],[5,source]]),new Map(),10,undefined,{
    state:'available',targetCodeAddress:TEST_TARGET_CODE,codeAddresses:sparseAddresses,
  });
  assert.equal(sparse.frameIdentityState,'unavailable');
  assert.equal(sparse.targetEffectCount,0);
  assert.equal(sparse.effects[0].sourceLocation,null);
  assert.equal(sparse.sourceAttributionState,'unavailable');

  const mixedCaseCode = TEST_TARGET_CODE.toUpperCase().replace('0X','0x');
  const mixedCase = summarizeTraceStepsRaw({failed:false,structLogs:[trace.structLogs[0]]},1,
    new Map([[4,source]]),new Map(),10,undefined,{
      state:'available',targetCodeAddress:TEST_TARGET_CODE,codeAddresses:[mixedCaseCode],
    });
  assert.equal(mixedCase.frameIdentityState,'available');
  assert.equal(mixedCase.targetEffectCount,1);
  assert.deepEqual(mixedCase.effects[0].sourceLocation,source);
});

test('nested proxy code at the configured target depth never receives the implementation source map', () => {
  const source = {file:'Pool.sol',start:12,length:4,lineStart:2,lineEnd:2,sourceSha256:'b'.repeat(64)};
  const proxyCode = '0x3333333333333333333333333333333333333333';
  const trace={failed:false,structLogs:[
    {op:'SSTORE',pc:4,depth:2},
    {op:'SSTORE',pc:4,depth:3},
  ]};
  const coverage=new Map();
  const summary=summarizeTraceStepsRaw(trace,2,new Map([[4,source]]),coverage,160,250000,
    {state:'available',targetCodeAddress:TEST_TARGET_CODE,codeAddresses:[proxyCode,TEST_TARGET_CODE]});

  assert.equal(summary.targetCodeStepCount,1);
  assert.equal(summary.targetFrameDepthMismatchCount,1);
  assert.equal(summary.targetEffectCount,0);
  assert.equal(summary.effects[0].sourceLocation,null);
  assert.equal(summary.effects[1].sourceLocation,null);
  assert.equal(coverage.size,0);
  assert.equal(summary.sourceAttributionState,'partial');
});

test('aggregate source attribution is separate from aggregate trace availability', () => {
  const stats = {requested:2,valid:2,invalid:0,stepLimited:0,unknownOpcodeCount:0,targetEffects:3,unmappedTargetEffects:1,
    frameIdentityAvailable:2,frameIdentityPartial:0,frameIdentityUnavailable:0,targetCodeStepCount:12,targetFrameDepthMismatchCount:0};
  assert.equal(traceEvidenceState(stats),'available');
  assert.equal(traceSourceAttributionEvidenceState(stats),'partial');
  assert.equal(traceSourceAttributionEvidenceState({...stats,unmappedTargetEffects:0}),'available');
  assert.equal(traceSourceAttributionEvidenceState({...stats,targetEffects:0,unmappedTargetEffects:0}),'not_applicable');
  assert.equal(traceSourceAttributionEvidenceState({...stats,invalid:1,unmappedTargetEffects:0}),'partial');
  assert.equal(traceSourceAttributionEvidenceState({...stats,stepLimited:1,unmappedTargetEffects:0}),'partial');
  assert.equal(traceSourceAttributionEvidenceState({...stats,frameIdentityPartial:1}),'partial');
  assert.equal(traceSourceAttributionEvidenceState({...stats,frameIdentityAvailable:0,frameIdentityUnavailable:2}),'unavailable');
  assert.equal(traceSourceAttributionEvidenceState({requested:0,valid:0,invalid:0,stepLimited:0,unknownOpcodeCount:0,targetEffects:0,unmappedTargetEffects:0,
    frameIdentityAvailable:0,frameIdentityPartial:0,frameIdentityUnavailable:0,targetCodeStepCount:0,targetFrameDepthMismatchCount:0}),'not_performed');
  assert.equal(traceSourceAttributionEvidenceState({requested:1,valid:0,invalid:1,stepLimited:0,unknownOpcodeCount:0,targetEffects:0,unmappedTargetEffects:0,
    frameIdentityAvailable:0,frameIdentityPartial:0,frameIdentityUnavailable:1,targetCodeStepCount:0,targetFrameDepthMismatchCount:0}),'unavailable');
});

test('frame identity capture attaches only to selected target sends and aligns raw events to debug steps', async () => {
  const events=new EventEmitter();
  const txHash='0x'+'a'.repeat(64);
  const provider={
    _node:{_vm:{evm:{events}}},
    async request(args){
      if(args.method==='eth_sendTransaction'){
        events.emit('beforeMessage',{to:TEST_TARGET_CODE,codeAddress:TEST_TARGET_CODE});
        events.emit('step',{pc:0n,depth:1,opcode:{name:'STOP'}});
        events.emit('step',{pc:0n,depth:1,opcode:{name:'STOP'}});
        events.emit('step',{pc:3n,depth:1,opcode:{name:'SSTORE'}});
        events.emit('afterMessage');
        return txHash;
      }
      return '0x1';
    },
  };
  const capture=installHardhatFrameIdentityCapture(provider,tx=>tx?.to===TEST_TARGET_CODE);
  assert.equal(capture.supported,true);
  await provider.request({method:'eth_sendTransaction',params:[{to:TEST_TARGET_CODE}]});
  const aligned=alignTraceFrameIdentities({structLogs:[
    {pc:0,depth:1,op:'STOP'}, {pc:3,depth:1,op:'SSTORE'},
  ]},capture.take(txHash));
  assert.deepEqual(aligned,{state:'available',codeAddresses:[TEST_TARGET_CODE,TEST_TARGET_CODE]});
  capture.dispose();
});

test('frame identity capture bounds stored steps and fails closed after overflow', async () => {
  const events=new EventEmitter();
  const txHash='0x'+'b'.repeat(64);
  const provider={
    _node:{_vm:{evm:{events}}},
    async request(){
      events.emit('beforeMessage',{to:TEST_TARGET_CODE,codeAddress:TEST_TARGET_CODE});
      for(let pc=0;pc<4;pc++) events.emit('step',{pc:BigInt(pc),depth:1,opcode:{name:'JUMPDEST'}});
      events.emit('afterMessage');
      return txHash;
    },
  };
  const capture=installHardhatFrameIdentityCapture(provider,()=>true,2);
  await provider.request({method:'eth_sendTransaction',params:[{to:TEST_TARGET_CODE}]});

  const recorded=capture.take(txHash);
  assert.equal(recorded.stepCount,2);
  assert.equal(recorded.invalid,true);
  assert.deepEqual(alignTraceFrameIdentities({structLogs:[
    {pc:0,depth:1,op:'JUMPDEST'}, {pc:1,depth:1,op:'JUMPDEST'},
  ]},recorded),
    {state:'unavailable',codeAddresses:[]});
  capture.dispose();
});

test('frame identity capture bounds stored steps succeeds at exact limit', async () => {
  const events=new EventEmitter();
  const txHash='0x'+'d'.repeat(64);
  const provider={
    _node:{_vm:{evm:{events}}},
    async request(){
      events.emit('beforeMessage',{to:TEST_TARGET_CODE,codeAddress:TEST_TARGET_CODE});
      for(let pc=0;pc<2;pc++) events.emit('step',{pc:BigInt(pc),depth:1,opcode:{name:'JUMPDEST'}});
      events.emit('afterMessage');
      return txHash;
    },
  };
  const capture=installHardhatFrameIdentityCapture(provider,()=>true,2);
  await provider.request({method:'eth_sendTransaction',params:[{to:TEST_TARGET_CODE}]});

  const recorded=capture.take(txHash);
  assert.equal(recorded.stepCount,2);
  assert.equal(recorded.invalid,false);
  assert.deepEqual(alignTraceFrameIdentities({structLogs:[
    {pc:0,depth:1,op:'JUMPDEST'}, {pc:1,depth:1,op:'JUMPDEST'},
  ]},recorded),
    {state:'available',codeAddresses:[TEST_TARGET_CODE,TEST_TARGET_CODE]});
  capture.dispose();
});

test('frame identity capture rejects zero-depth VM events before storing them', async () => {
  const events = new EventEmitter();
  const txHash = '0x' + 'e'.repeat(64);
  const provider = {
    _node: {_vm: {evm: {events}}},
    async request() {
      events.emit('beforeMessage', {to: TEST_TARGET_CODE, codeAddress: TEST_TARGET_CODE});
      events.emit('step', {pc: 0n, depth: 0, opcode: {name: 'STOP'}});
      events.emit('afterMessage');
      return txHash;
    },
  };
  const capture = installHardhatFrameIdentityCapture(provider, () => true, 4);
  await provider.request({method: 'eth_sendTransaction', params: [{to: TEST_TARGET_CODE}]});
  const recorded = capture.take(txHash);
  assert.equal(recorded.stepCount, 0);
  assert.equal(recorded.invalid, true);
  assert.deepEqual(alignTraceFrameIdentities({structLogs: []}, recorded),
    {state: 'unavailable', codeAddresses: []});
  capture.dispose();
});

test('disposing an in-flight frame capture removes listeners and prevents cache writes', async () => {
  const events=new EventEmitter();
  const txHash='0x'+'c'.repeat(64);
  let resolveRequest;
  const pending=new Promise(resolve=>{resolveRequest=resolve;});
  const provider={
    _node:{_vm:{evm:{events}}},
    request:()=>pending,
  };
  const capture=installHardhatFrameIdentityCapture(provider,()=>true);
  const request=provider.request({method:'eth_sendTransaction',params:[{to:TEST_TARGET_CODE}]});
  assert.deepEqual(['beforeMessage','afterMessage','step'].map(name=>events.listenerCount(name)),[1,1,1]);

  capture.dispose();
  assert.deepEqual(['beforeMessage','afterMessage','step'].map(name=>events.listenerCount(name)),[0,0,0]);
  resolveRequest(txHash);
  await request;
  assert.equal(capture.take(txHash),null);
});

test('frame identity alignment fails closed on a pc/op/depth mismatch', () => {
  const capture={invalid:false,steps:[{pc:2,depth:1,op:'SSTORE',codeAddress:TEST_TARGET_CODE}]};
  assert.deepEqual(alignTraceFrameIdentities({structLogs:[{pc:3,depth:1,op:'SSTORE'}]},capture),
    {state:'unavailable',codeAddresses:[]});
});

test('frame identity alignment rejects zero-depth debug steps', () => {
  const capture={invalid:false,steps:[{pc:0,depth:0,op:'STOP',codeAddress:TEST_TARGET_CODE}]};
  assert.deepEqual(alignTraceFrameIdentities({structLogs:[{pc:0,depth:0,op:'STOP'}]},capture),
    {state:'unavailable',codeAddresses:[]});
});

test('compact frame alignment rejects malformed interned code addresses', () => {
  const capture={invalid:false,stepCount:1,
    programCounters:Float64Array.of(1),depths:Uint32Array.of(1),opcodeIds:Uint32Array.of(1),
    codeAddressIds:Uint32Array.of(1),opcodes:['','SSTORE'],frameAddresses:[null,'not-an-address']};
  assert.deepEqual(alignTraceFrameIdentities({structLogs:[{pc:1,depth:1,op:'SSTORE'}]},capture),
    {state:'unavailable',codeAddresses:[]});
});

test('compact frame alignment rejects address ids that exceed the step-bounded dictionary', () => {
  const capture={invalid:false,stepCount:1,
    programCounters:Float64Array.of(1),depths:Uint32Array.of(1),opcodeIds:Uint32Array.of(1),
    codeAddressIds:Uint32Array.of(2),opcodes:['','SSTORE'],
    frameAddresses:[null,TEST_TARGET_CODE,TEST_OTHER_CODE]};
  assert.deepEqual(alignTraceFrameIdentities({structLogs:[{pc:1,depth:1,op:'SSTORE'}]},capture),
    {state:'unavailable',codeAddresses:[]});
});

test('compact frame alignment rejects a corrupted null-address sentinel', () => {
  const capture={invalid:false,stepCount:1,
    programCounters:Float64Array.of(1),depths:Uint32Array.of(1),opcodeIds:Uint32Array.of(1),
    codeAddressIds:Uint32Array.of(0),opcodes:['','SSTORE'],frameAddresses:[TEST_TARGET_CODE]};
  assert.deepEqual(alignTraceFrameIdentities({structLogs:[{pc:1,depth:1,op:'SSTORE'}]},capture),
    {state:'unavailable',codeAddresses:[]});
});

test('source attribution normalizes repeated mixed-case frame addresses', () => {
  const target='0x'+'ab'.repeat(20), upperTarget=target.toUpperCase().replace('0X','0x');
  const source={file:'Pool.sol',start:1,length:2,lineStart:1,lineEnd:1,sourceSha256:'c'.repeat(64)};
  const trace={failed:false,structLogs:[{op:'SSTORE',pc:1,depth:1},{op:'SSTORE',pc:2,depth:1}]};
  const summary=summarizeTraceStepsRaw(trace,1,new Map([[1,source],[2,source]]),new Map(),160,250000,
    {state:'available',targetCodeAddress:target,codeAddresses:[upperTarget,upperTarget]});
  assert.equal(summary.frameIdentityState,'available');
  assert.equal(summary.mappedEffects,2);
  assert.equal(summary.sourceAttributionState,'available');
});

test('truncated retention excludes proxy effects at the target depth', () => {
  const proxyCode = '0x3333333333333333333333333333333333333333';
  const trace = {failed:false,structLogs:Array.from({length:4},(_,pc)=>({op:'SSTORE',pc,depth:2}))};
  const frameIdentity = {
    state:'available',
    targetCodeAddress:TEST_TARGET_CODE,
    codeAddresses:[proxyCode,proxyCode,TEST_TARGET_CODE,TEST_TARGET_CODE],
  };
  const summary = summarizeTraceStepsRaw(trace,2,new Map(),new Map(),2,undefined,frameIdentity);

  assert.deepEqual(summary.effects.map(({pc})=>pc),[2,3]);
  assert.equal(summary.targetEffectCount,2);
  assert.equal(summary.unmappedTargetEffects,2);
  assert.equal(summary.nonTargetEffects,2);
  assert.equal(summary.effectRetentionPolicy,'target_depth_mapped_then_unmapped_when_truncated');
});

test('truncated effect retention keeps mapped target effects after unrelated nested effects', () => {
  const source = {file:'Vault.sol',start:4,length:3,lineStart:1,lineEnd:1,sourceSha256:'a'.repeat(64)};
  const trace = {failed:false,structLogs:[
    ...Array.from({length:160},(_,pc)=>({op:'REVERT',pc,depth:2})),
    {op:'SSTORE',pc:1000,depth:1},
  ]};
  const summary = summarizeTraceSteps(trace,1,new Map([[1000,source]]),new Map(),160);
  assert.equal(summary.steps,161);
  assert.equal(summary.processedSteps,161);
  assert.equal(summary.stepsTruncated,false);
  assert.equal(summary.effectCountComplete,true);
  assert.deepEqual(summary.opcodeCounts,{REVERT:160,SSTORE:1});
  assert.equal(summary.effectCount,161);
  assert.equal(summary.targetEffectCount,1);
  assert.equal(summary.mappedEffects,1);
  assert.equal(summary.unmappedTargetEffects,0);
  assert.equal(summary.nonTargetEffects,160);
  assert.equal(summary.unmappedEffects,160);
  assert.equal(summary.effects.length,160);
  assert.equal(summary.effectsLimit,160);
  assert.equal(summary.effects.at(-1).op,'SSTORE');
  assert.equal(summary.effects.at(-1).effectSiteId.length,64);
  assert.equal(summary.effectsTruncated,true);
  assert.equal(summary.effectRetentionPolicy,'target_depth_mapped_then_unmapped_when_truncated');
  assert.equal(traceSummaryEvidenceState(summary),'partial');
});

test('truncated retention prioritizes mapped target effects, then unmapped target effects, in trace order', () => {
  const source = {file:'Vault.sol',start:4,length:3,lineStart:1,lineEnd:1,sourceSha256:'a'.repeat(64)};
  const trace = {failed:false,structLogs:[
    {op:'REVERT',pc:0,depth:2},
    {op:'SSTORE',pc:1,depth:1},
    {op:'TSTORE',pc:2,depth:1},
    {op:'CALL',pc:3,depth:2},
  ]};
  const summary = summarizeTraceSteps(trace,1,new Map([[1,source]]),new Map(),2);
  assert.deepEqual(summary.effects.map(({op,pc})=>({op,pc})),[
    {op:'SSTORE',pc:1},
    {op:'TSTORE',pc:2},
  ]);
  assert.equal(summary.targetEffectCount,2);
  assert.equal(summary.mappedEffects,1);
  assert.equal(summary.unmappedTargetEffects,1);
  assert.equal(summary.nonTargetEffects,2);
  assert.equal(summary.effectRetentionPolicy,'target_depth_mapped_then_unmapped_when_truncated');

  const mappedOnly = summarizeTraceSteps({failed:false,structLogs:[
    {op:'REVERT',pc:0,depth:2},
    {op:'SSTORE',pc:1,depth:1},
    {op:'CALL',pc:2,depth:1},
    {op:'TSTORE',pc:3,depth:1},
  ]},1,new Map([[1,source],[2,{...source,start:8}],[3,{...source,start:12}]]),new Map(),2);
  assert.deepEqual(mappedOnly.effects.map(({op,pc})=>({op,pc})),[
    {op:'SSTORE',pc:1},
    {op:'CALL',pc:2},
  ]);
  assert.equal(mappedOnly.effectsTruncated,true);
});

test('truncated retention preserves mapped target REVERT events', () => {
  const source = {file:'Vault.sol',start:4,length:3,lineStart:1,lineEnd:1,sourceSha256:'a'.repeat(64)};
  const trace = {failed:true,structLogs:[
    ...Array.from({length:160},(_,pc)=>({op:'REVERT',pc,depth:2})),
    {op:'REVERT',pc:1000,depth:1},
  ]};
  const summary = summarizeTraceSteps(trace,1,new Map([[1000,source]]),new Map(),160);

  assert.equal(summary.effectCount,161);
  assert.equal(summary.targetEffectCount,1);
  assert.equal(summary.mappedEffects,1);
  assert.equal(summary.unmappedTargetEffects,0);
  assert.equal(summary.nonTargetEffects,160);
  assert.equal(summary.unmappedEffects,160);
  assert.equal(summary.effects.length,160);
  assert.equal(summary.effects.at(-1).op,'REVERT');
  assert.equal(summary.effects.at(-1).depth,1);
  assert.deepEqual(summary.effects.at(-1).sourceLocation,source);
  assert.equal(summary.effects.at(-1).effectSiteId,null);
  assert.equal(summary.effectsTruncated,true);
  assert.equal(summary.effectRetentionPolicy,'target_depth_mapped_then_unmapped_when_truncated');
});

test('zero retained-effect limit still counts and maps the full trace', () => {
  const source = {file:'Vault.sol',start:4,length:3,lineStart:1,lineEnd:1,sourceSha256:'a'.repeat(64)};
  const trace = {failed:false,structLogs:[{op:'SSTORE',pc:0,depth:1},{op:'CALL',pc:1,depth:1}]};
  const coverage = new Map();
  const summary = summarizeTraceSteps(trace,1,new Map([[0,source]]),coverage,0);
  assert.equal(summary.effectCount,2);
  assert.equal(summary.effects.length,0);
  assert.equal(summary.effectsTruncated,true);
  assert.equal(summary.targetEffectCount,2);
  assert.equal(summary.mappedEffects,1);
  assert.equal(summary.unmappedTargetEffects,1);
  assert.equal(summary.nonTargetEffects,0);
  assert.equal(summary.unmappedEffects,1);
  assert.equal(coverage.size,1);
});

test('source coverage keys do not collide across colon paths or source revisions', () => {
  const first = {file:'pkg:1',start:2,length:3,lineStart:1,lineEnd:1,sourceSha256:'a'.repeat(64)};
  const second = {file:'pkg',start:1,length:2,lineStart:1,lineEnd:1,sourceSha256:'b'.repeat(64)};
  const coverage = new Map();
  summarizeTraceSteps({failed:false,structLogs:[
    {op:'PUSH1',pc:0,depth:1}, {op:'PUSH1',pc:1,depth:1},
  ]},1,new Map([[0,first],[1,second]]),coverage);
  assert.equal(coverage.size,2);
});

test('trace step budget bounds summarization and exposes incomplete counts', () => {
  const source = {file:'Vault.sol',start:4,length:3,lineStart:1,lineEnd:1,sourceSha256:'a'.repeat(64)};
  const trace = {failed:false,structLogs:[
    {op:'SSTORE',pc:0,depth:1}, {op:'CALL',pc:1,depth:1}, {op:'SSTORE',pc:2,depth:1},
  ]};
  const coverage = new Map();
  const summary = summarizeTraceSteps(trace,1,new Map([[0,source],[2,{...source,start:8}]]),coverage,10,2);
  assert.equal(summary.steps,3);
  assert.equal(summary.processedSteps,2);
  assert.equal(summary.stepLimit,2);
  assert.equal(summary.stepsTruncated,true);
  assert.equal(summary.effectCount,2);
  assert.equal(summary.effectCountComplete,false);
  assert.equal(summary.targetEffectCount,2);
  assert.equal(summary.unmappedTargetEffects,1);
  assert.equal(summary.nonTargetEffects,0);
  assert.deepEqual(summary.opcodeCounts,{SSTORE:1,CALL:1});
  assert.equal(coverage.size,1);
  assert.equal(traceEvidenceState({requested:1,valid:1,invalid:0,skipped:0,truncated:1}), 'partial');
});

test('trace step budget ignores malformed steps outside the processed prefix', () => {
  const source = {file:'Vault.sol',start:4,length:3,lineStart:1,lineEnd:1,sourceSha256:'a'.repeat(64)};
  const coverage = new Map();
  const summary = summarizeTraceSteps({failed:false,structLogs:[
    {op:'SSTORE',pc:0,depth:1},
    {op:'SSTORE',pc:-1,depth:1},
  ]},1,new Map([[0,source]]),coverage,10,1);

  assert.equal(summary.steps,2);
  assert.equal(summary.processedSteps,1);
  assert.equal(summary.stepsTruncated,true);
  assert.equal(summary.effectCount,1);
  assert.equal(summary.effects[0].pc,0);
  assert.equal(coverage.size,1);
});

test('invalid mapped effects leave source coverage unchanged', () => {
  const valid = {file:'Vault.sol',start:4,length:3,lineStart:1,lineEnd:1,sourceSha256:'a'.repeat(64)};
  const invalid = {...valid,sourceSha256:'invalid'};
  const coverage = new Map();
  assert.throws(() => summarizeTraceSteps({failed:false,structLogs:[
    {op:'PUSH1',pc:0,depth:1},
    {op:'SSTORE',pc:1,depth:1},
  ]},1,new Map([[0,valid],[1,invalid]]),coverage), /effect site requires a source hash/);
  assert.equal(coverage.size,0);
});
