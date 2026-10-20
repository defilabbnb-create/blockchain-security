import { createHash, randomUUID } from 'node:crypto';

export const REPLAY_ARTIFACT_SCHEMA_VERSION = 1;
export const REPLAY_ARTIFACT_MAX_BYTES = 2 * 1024 * 1024;

const HASH_RE = /^[a-f0-9]{64}$/;
const EVM_HASH_RE = /^0x[a-fA-F0-9]{64}$/;
const ADDRESS_RE = /^0x[a-fA-F0-9]{40}$/;
const SLOT_RE = /^0x[a-fA-F0-9]{64}$/;
const HEX_BYTES_RE = /^0x(?:[a-fA-F0-9]{2})*$/;
const QUANTITY_RE = /^(?:0|[1-9][0-9]*|0x[0-9a-fA-F]+)$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}T/;
const REPLAY_KEYS = new Set([
  'transactions', 'sequence', 'traces', 'assetChanges', 'permissionChanges', 'stateDiff', 'storageDiff',
  'initialState', 'seed', 'fork', 'command',
]);
const TRANSACTION_KEYS = new Set([
  'txIndex', 'transactionHash', 'hash', 'from', 'caller', 'to', 'value', 'data', 'input', 'calldata',
  'gas', 'gasPrice', 'maxFeePerGas', 'maxPriorityFeePerGas', 'nonce', 'blockNumber', 'blockHash',
  'status', 'reverted', 'returnData', 'traceHash', 'stateDiffHash', 'storageDiffHash',
]);
const TRACE_KEYS = new Set([
  'txIndex', 'transactionHash', 'hash', 'traceHash', 'state', 'failed', 'steps', 'processedSteps',
  'effectCount', 'effectsHash', 'storageDiffHash', 'returnData', 'revertReason',
]);
const INITIAL_STATE_KEYS = new Set([
  'accounts', 'storage', 'chainId', 'blockNumber', 'blockHash', 'timestamp', 'stateRoot', 'source', 'hash',
]);
const ACCOUNT_KEYS = new Set(['address', 'balance', 'nonce', 'codeHash', 'storage']);
const STORAGE_ENTRY_KEYS = new Set(['address', 'slot', 'before', 'after', 'value', 'txIndex', 'transactionHash', 'changed']);
const ASSET_CHANGE_KEYS = new Set(['asset', 'assetType', 'token', 'from', 'to', 'before', 'after', 'delta', 'unit', 'txIndex', 'transactionHash', 'complete']);
const PERMISSION_CHANGE_KEYS = new Set(['role', 'account', 'before', 'after', 'txIndex', 'transactionHash', 'complete']);
const MAX_REPLAY_HEX_BYTES = 1024 * 1024;

function fail(message, ErrorType = TypeError) {
  throw new ErrorType(message);
}

// Clone while checking the JSON data model. Tracking ancestors (rather than
// every object ever visited) permits the same value to be referenced twice
// while still rejecting a cycle.
function cloneJson(value, path = '$', ancestors = new Set()) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail(`${path} must contain finite JSON numbers`);
    return value;
  }
  if (typeof value === 'function') fail(`${path} must not contain functions`);
  if (typeof value === 'undefined' || typeof value === 'bigint' || typeof value === 'symbol') {
    fail(`${path} contains a value that is not JSON serializable`);
  }
  if (typeof value !== 'object') fail(`${path} contains an unsupported value`);
  if (ancestors.has(value)) fail(`${path} contains a cyclic reference`);

  const nextAncestors = new Set(ancestors).add(value);
  if (Array.isArray(value)) {
    const copy = [];
    for (let index = 0; index < value.length; index += 1) {
      if (!Object.hasOwn(value, index)) fail(`${path}[${index}] is a sparse array entry`);
      copy.push(cloneJson(value[index], `${path}[${index}]`, nextAncestors));
    }
    for (const key of Reflect.ownKeys(value)) {
      if (key !== 'length' && !(typeof key === 'string' && /^(?:0|[1-9]\d*)$/.test(key) && Number(key) < value.length)) {
        fail(`${path} contains a non-index property`);
      }
    }
    return copy;
  }

  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) fail(`${path} must be a plain JSON object`);
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== 'string')) fail(`${path} contains a symbol property`);
  const copy = {};
  for (const key of keys.sort()) {
    Object.defineProperty(copy, key, {
      value: cloneJson(value[key], `${path}.${key}`, nextAncestors),
      enumerable: true,
      configurable: true,
      writable: true,
    });
  }
  return copy;
}

function canonicalJson(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

function hashBody(body) {
  return createHash('sha256').update(canonicalJson(body), 'utf8').digest('hex');
}

function serializedSize(value) {
  return Buffer.byteLength(canonicalJson(value), 'utf8');
}

function plainObject(value, path) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${path} must be an object`);
  return value;
}

function checkKeys(value, allowed, path) {
  for (const key of Object.keys(value)) if (!allowed.has(key)) fail(`${path} contains an unsupported field: ${key}`);
}

function checkAddress(value, path, { allowNull = false } = {}) {
  if (allowNull && value === null) return;
  if (typeof value !== 'string' || !ADDRESS_RE.test(value)) fail(`${path} must be an EVM address`);
}

function checkHash(value, path) {
  if (typeof value !== 'string' || !HASH_RE.test(value)) fail(`${path} must be sha256`);
}

function checkEvmHash(value, path) {
  if (typeof value !== 'string' || !EVM_HASH_RE.test(value)) fail(`${path} must be an EVM hash`);
}

function checkQuantity(value, path) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) fail(`${path} must be a non-negative quantity`);
    return;
  }
  if (typeof value !== 'string' || !QUANTITY_RE.test(value) ||
      (value.startsWith('0x') ? value.length > 66 : value.length > 78)) fail(`${path} must be a non-negative quantity`);
}

function quantityValue(value) {
  // All callers have already passed checkQuantity; BigInt keeps decimal and
  // hexadecimal JSON representations comparable without losing precision.
  return BigInt(value);
}

function quantitiesEqual(left, right) {
  return quantityValue(left) === quantityValue(right);
}

function checkHexBytes(value, path) {
  if (typeof value !== 'string' || value.length > (MAX_REPLAY_HEX_BYTES * 2) + 2 || !HEX_BYTES_RE.test(value)) {
    fail(`${path} must be an even-length 0x-prefixed byte string`);
  }
}

function checkStorageWord(value, path) {
  checkHexBytes(value, path);
  if (value.length !== 66) fail(`${path} must be a 32-byte storage word`);
}

function checkCount(value, path) {
  if (!Number.isSafeInteger(value) || value < 0) fail(`${path} must be a non-negative integer`);
}

function validateStorageEntry(value, path, { requireValue = false } = {}) {
  const entry = plainObject(value, path);
  checkKeys(entry, STORAGE_ENTRY_KEYS, path);
  if (entry.address !== undefined) checkAddress(entry.address, `${path}.address`);
  if (entry.slot !== undefined && (typeof entry.slot !== 'string' || !SLOT_RE.test(entry.slot))) fail(`${path}.slot must be a 32-byte storage slot`);
  if (entry.before !== undefined) checkStorageWord(entry.before, `${path}.before`);
  if (entry.after !== undefined) checkStorageWord(entry.after, `${path}.after`);
  if (entry.value !== undefined) checkStorageWord(entry.value, `${path}.value`);
  if (entry.before === undefined && entry.after === undefined && entry.value === undefined && requireValue) {
    fail(`${path} must include value or before/after`);
  }
  if (entry.txIndex !== undefined) checkCount(entry.txIndex, `${path}.txIndex`);
  if (entry.transactionHash !== undefined) checkEvmHash(entry.transactionHash, `${path}.transactionHash`);
  if (entry.changed !== undefined && typeof entry.changed !== 'boolean') fail(`${path}.changed must be boolean`);
  if (entry.address === undefined || entry.slot === undefined) {
    fail(`${path} must include address and slot`);
  }
  return entry;
}

function validateTransaction(value, path) {
  const transaction = plainObject(value, path);
  checkKeys(transaction, TRANSACTION_KEYS, path);
  if (transaction.txIndex !== undefined) checkCount(transaction.txIndex, `${path}.txIndex`);
  if (transaction.hash !== undefined) checkHash(transaction.hash, `${path}.hash`);
  if (transaction.transactionHash !== undefined) checkEvmHash(transaction.transactionHash, `${path}.transactionHash`);
  for (const key of ['from', 'caller']) if (transaction[key] !== undefined) checkAddress(transaction[key], `${path}.${key}`);
  if (transaction.to !== undefined) checkAddress(transaction.to, `${path}.to`, { allowNull: true });
  for (const key of ['value', 'gas', 'gasPrice', 'maxFeePerGas', 'maxPriorityFeePerGas', 'nonce', 'blockNumber']) {
    if (transaction[key] !== undefined) checkQuantity(transaction[key], `${path}.${key}`);
  }
  for (const key of ['data', 'input', 'calldata', 'returnData']) if (transaction[key] !== undefined) checkHexBytes(transaction[key], `${path}.${key}`);
  if (transaction.data !== undefined && transaction.input !== undefined && transaction.data !== transaction.input) fail(`${path}.data and input must match`);
  if (transaction.data !== undefined && transaction.calldata !== undefined && transaction.data !== transaction.calldata) fail(`${path}.data and calldata must match`);
  if (transaction.input !== undefined && transaction.calldata !== undefined && transaction.input !== transaction.calldata) fail(`${path}.input and calldata must match`);
  if (transaction.blockHash !== undefined) checkEvmHash(transaction.blockHash, `${path}.blockHash`);
  if (transaction.status !== undefined && !['success', 'reverted', 'failed', 'unknown', '0x0', '0x1', 0, 1].includes(transaction.status)) fail(`${path}.status is invalid`);
  if (transaction.reverted !== undefined && typeof transaction.reverted !== 'boolean') fail(`${path}.reverted must be boolean`);
  for (const key of ['traceHash', 'stateDiffHash', 'storageDiffHash']) if (transaction[key] !== undefined) checkHash(transaction[key], `${path}.${key}`);
  return transaction;
}

function validateTrace(value, path) {
  const trace = plainObject(value, path);
  checkKeys(trace, TRACE_KEYS, path);
  if (trace.txIndex !== undefined) checkCount(trace.txIndex, `${path}.txIndex`);
  if (trace.transactionHash !== undefined) checkEvmHash(trace.transactionHash, `${path}.transactionHash`);
  for (const key of ['hash', 'traceHash', 'effectsHash', 'storageDiffHash']) if (trace[key] !== undefined) checkHash(trace[key], `${path}.${key}`);
  if (trace.state !== undefined && !['available', 'partial', 'unavailable'].includes(trace.state)) fail(`${path}.state is invalid`);
  if (trace.failed !== undefined && typeof trace.failed !== 'boolean') fail(`${path}.failed must be boolean`);
  for (const key of ['steps', 'processedSteps', 'effectCount']) if (trace[key] !== undefined) checkCount(trace[key], `${path}.${key}`);
  if (trace.steps !== undefined && trace.processedSteps !== undefined && trace.processedSteps > trace.steps) fail(`${path}.processedSteps exceeds steps`);
  if (trace.returnData !== undefined) checkHexBytes(trace.returnData, `${path}.returnData`);
  if (trace.revertReason !== undefined && (typeof trace.revertReason !== 'string' || trace.revertReason.length > 2000)) fail(`${path}.revertReason must be a short string`);
  return trace;
}

function validateInitialState(value) {
  const initial = plainObject(value, 'replay.initialState');
  checkKeys(initial, INITIAL_STATE_KEYS, 'replay.initialState');
  if (initial.chainId !== undefined) checkQuantity(initial.chainId, 'replay.initialState.chainId');
  if (initial.blockNumber !== undefined) checkQuantity(initial.blockNumber, 'replay.initialState.blockNumber');
  if (initial.blockHash !== undefined) checkEvmHash(initial.blockHash, 'replay.initialState.blockHash');
  if (initial.stateRoot !== undefined) checkEvmHash(initial.stateRoot, 'replay.initialState.stateRoot');
  if (initial.timestamp !== undefined) checkQuantity(initial.timestamp, 'replay.initialState.timestamp');
  if (initial.source !== undefined && (typeof initial.source !== 'string' || initial.source.length > 200)) fail('replay.initialState.source must be short');
  if (initial.hash !== undefined) checkHash(initial.hash, 'replay.initialState.hash');
  if (initial.accounts !== undefined) {
    if (!Array.isArray(initial.accounts)) fail('replay.initialState.accounts must be an array');
    initial.accounts.forEach((account, index) => {
      const path = `replay.initialState.accounts[${index}]`;
      const item = plainObject(account, path);
      checkKeys(item, ACCOUNT_KEYS, path);
      checkAddress(item.address, `${path}.address`);
      for (const key of ['balance', 'nonce']) if (item[key] !== undefined) checkQuantity(item[key], `${path}.${key}`);
      if (item.codeHash !== undefined) checkHash(item.codeHash, `${path}.codeHash`);
      if (item.storage !== undefined) {
        if (!Array.isArray(item.storage)) fail(`${path}.storage must be an array`);
        item.storage.forEach((entry, entryIndex) => validateStorageEntry(entry, `${path}.storage[${entryIndex}]`, { requireValue: true }));
      }
    });
  }
  if (initial.storage !== undefined) {
    if (!Array.isArray(initial.storage)) fail('replay.initialState.storage must be an array');
    initial.storage.forEach((entry, index) => validateStorageEntry(entry, `replay.initialState.storage[${index}]`, { requireValue: true }));
  }
  return initial;
}

function validateSequence(value, transactions) {
  if (value === undefined) return undefined;
  if (!Array.isArray(value)) fail('replay.sequence must be an array');
  const seen = new Set();
  value.forEach((item, index) => {
    const path = `replay.sequence[${index}]`;
    const txIndex = typeof item === 'number' ? item : item?.txIndex;
    if (!Number.isSafeInteger(txIndex) || txIndex < 0) fail(`${path}.txIndex must be a non-negative integer`);
    if (seen.has(txIndex)) fail(`${path}.txIndex is duplicated`);
    seen.add(txIndex);
    if (typeof item === 'object' && item !== null) {
      checkKeys(item, new Set(['txIndex', 'transactionHash']), path);
      if (item.transactionHash !== undefined) checkEvmHash(item.transactionHash, `${path}.transactionHash`);
    } else if (typeof item !== 'number') fail(`${path} must be a transaction index or object`);
  });
  if (transactions?.length && transactions.every((item) => item.txIndex !== undefined)) {
    const known = new Set(transactions.map((item) => item.txIndex));
    for (const txIndex of seen) if (!known.has(txIndex)) fail(`replay.sequence references unknown transaction ${txIndex}`);
  }
  return value;
}

function validateChangeEntries(value, field) {
  if (value === undefined || !Array.isArray(value)) return;
  const allowed = field === 'assetChanges' ? ASSET_CHANGE_KEYS : PERMISSION_CHANGE_KEYS;
  value.forEach((entry, index) => {
    const path = `replay.${field}[${index}]`;
    const item = plainObject(entry, path);
    checkKeys(item, allowed, path);
    for (const key of ['token', 'from', 'to', 'account']) {
      if (item[key] !== undefined) checkAddress(item[key], `${path}.${key}`);
    }
    if (item.asset !== undefined && (typeof item.asset !== 'string' || item.asset.length < 1 || item.asset.length > 200)) fail(`${path}.asset must be a bounded asset identifier`);
    if (field === 'assetChanges') {
      if (item.assetType !== undefined && (typeof item.assetType !== 'string' || item.assetType.length > 40)) fail(`${path}.assetType must be short`);
      if (item.unit !== undefined && (typeof item.unit !== 'string' || item.unit.length > 40)) fail(`${path}.unit must be short`);
      for (const key of ['before', 'after', 'delta']) if (item[key] !== undefined) {
        if (typeof item[key] !== 'string' || item[key].length > 200) fail(`${path}.${key} must be a bounded value`);
      }
    } else {
      if (item.role !== undefined && (typeof item.role !== 'string' || item.role.length > 200)) fail(`${path}.role must be short`);
      for (const key of ['before', 'after']) if (item[key] !== undefined && typeof item[key] !== 'boolean') fail(`${path}.${key} must be boolean`);
    }
    if (item.txIndex !== undefined) checkCount(item.txIndex, `${path}.txIndex`);
    if (item.transactionHash !== undefined) checkEvmHash(item.transactionHash, `${path}.transactionHash`);
    if (item.complete !== undefined && typeof item.complete !== 'boolean') fail(`${path}.complete must be boolean`);
  });
}

function validateTransactionReferences(replay, transactions) {
  const rows = Array.isArray(transactions) ? transactions : [];
  const indexed = rows.length > 0 && rows.every((item) => item.txIndex !== undefined);
  const byIndex = new Map();
  const byTransactionHash = new Map();
  rows.forEach((transaction, index) => {
    if (transaction.txIndex !== undefined) byIndex.set(transaction.txIndex, transaction);
    if (transaction.transactionHash !== undefined) {
      if (byTransactionHash.has(transaction.transactionHash.toLowerCase())) {
        fail(`replay.transactions[${index}].transactionHash is duplicated`);
      }
      byTransactionHash.set(transaction.transactionHash.toLowerCase(), transaction);
    }
  });

  const resolve = (value, path) => {
    const txIndex = value?.txIndex;
    const transactionHash = value?.transactionHash;
    if (txIndex === undefined && transactionHash === undefined) return null;
    if (!rows.length) fail(`${path} references a transaction but replay.transactions is missing`);
    let transaction = null;
    if (txIndex !== undefined) {
      if (!indexed || !byIndex.has(txIndex)) fail(`${path}.txIndex references an unknown transaction ${txIndex}`);
      transaction = byIndex.get(txIndex);
    }
    if (transactionHash !== undefined) {
      const hashMatch = byTransactionHash.get(transactionHash.toLowerCase());
      if (!hashMatch) fail(`${path}.transactionHash references an unknown transaction`);
      if (transaction && hashMatch !== transaction) fail(`${path}.txIndex and transactionHash reference different transactions`);
      transaction = hashMatch;
    }
    if (transactionHash !== undefined && transaction.transactionHash !== undefined &&
        transaction.transactionHash.toLowerCase() !== transactionHash.toLowerCase()) {
      fail(`${path}.transactionHash does not match its transaction`);
    }
    return transaction;
  };

  (replay.sequence || []).forEach((item, index) => {
    resolve(typeof item === 'number' ? { txIndex: item } : item, `replay.sequence[${index}]`);
  });
  (replay.traces || []).forEach((trace, index) => resolve(trace, `replay.traces[${index}]`));
  for (const field of ['assetChanges', 'permissionChanges', 'stateDiff', 'storageDiff']) {
    const entries = replay[field];
    if (!Array.isArray(entries)) continue;
    entries.forEach((entry, index) => {
      if (entry && typeof entry === 'object' && !Array.isArray(entry)) {
        resolve(entry, `replay.${field}[${index}]`);
      }
    });
  }
}

function validateReplayAnchors(replay) {
  const initial = replay.initialState;
  const fork = replay.fork;
  if (!initial || !fork) return;
  for (const [field, label] of [
    ['chainId', 'chainId'], ['blockNumber', 'blockNumber'], ['timestamp', 'timestamp'],
  ]) {
    if (initial[field] !== undefined && fork[field] !== undefined && !quantitiesEqual(initial[field], fork[field])) {
      fail(`replay.initialState.${label} does not match replay.fork.${label}`);
    }
  }
  for (const field of ['blockHash', 'stateRoot']) {
    if (initial[field] !== undefined && fork[field] !== undefined &&
        initial[field].toLowerCase() !== fork[field].toLowerCase()) {
      fail(`replay.initialState.${field} does not match replay.fork.${field}`);
    }
  }
}

function validateReplayContext(value) {
  if (value === undefined) return undefined;
  const replay = cloneJson(value, 'replay');
  if (!replay || typeof replay !== 'object' || Array.isArray(replay)) fail('replay must be a plain object');
  const keys = Object.keys(replay);
  if (keys.some((key) => !REPLAY_KEYS.has(key))) fail('replay contains an unsupported field');
  if (replay.command !== undefined && (typeof replay.command !== 'string' || replay.command.length > 2000)) fail('replay.command must be a short string');
  if (replay.seed !== undefined && !(
    (typeof replay.seed === 'string' && replay.seed.length <= 200) ||
    (typeof replay.seed === 'number' && Number.isInteger(replay.seed) && Number.isSafeInteger(replay.seed))
  )) fail('replay.seed must be a string or safe integer');
  for (const field of ['transactions', 'traces']) {
    if (replay[field] === undefined) continue;
    if (!Array.isArray(replay[field])) fail(`replay.${field} must be an array`);
    replay[field].forEach((item, index) => field === 'transactions'
      ? validateTransaction(item, `replay.transactions[${index}]`)
      : validateTrace(item, `replay.traces[${index}]`));
  }
  const transactionIndexes = new Set();
  for (const [index, transaction] of (replay.transactions || []).entries()) {
    if (transaction.txIndex === undefined) continue;
    if (transactionIndexes.has(transaction.txIndex)) fail(`replay.transactions[${index}].txIndex is duplicated`);
    transactionIndexes.add(transaction.txIndex);
  }
  validateSequence(replay.sequence, replay.transactions);
  for (const field of ['assetChanges', 'permissionChanges', 'stateDiff']) {
    if (replay[field] !== undefined && !(
      Array.isArray(replay[field]) || (replay[field] && typeof replay[field] === 'object')
    )) fail(`replay.${field} must be an array or object`);
  }
  for (const field of ['assetChanges', 'permissionChanges']) {
    if (replay[field] !== undefined && !Array.isArray(replay[field])) fail(`replay.${field} must be an array`);
  }
  validateChangeEntries(replay.assetChanges, 'assetChanges');
  validateChangeEntries(replay.permissionChanges, 'permissionChanges');
  if (Array.isArray(replay.stateDiff)) {
    replay.stateDiff.forEach((entry, index) => {
      if (entry && typeof entry === 'object' && !Array.isArray(entry) && (entry.slot !== undefined || entry.address !== undefined)) {
        validateStorageEntry(entry, `replay.stateDiff[${index}]`, { requireValue: true });
      }
    });
  }
  if (replay.storageDiff !== undefined) {
    if (!Array.isArray(replay.storageDiff)) fail('replay.storageDiff must be an array');
    replay.storageDiff.forEach((entry, index) => validateStorageEntry(entry, `replay.storageDiff[${index}]`, { requireValue: true }));
  }
  if (replay.initialState !== undefined) validateInitialState(replay.initialState);
  if (replay.fork !== undefined) {
    if (!replay.fork || typeof replay.fork !== 'object' || Array.isArray(replay.fork)) fail('replay.fork must be an object');
    checkKeys(replay.fork, new Set(['chainId', 'blockNumber', 'blockHash', 'timestamp', 'stateRoot']), 'replay.fork');
    if (replay.fork.chainId === undefined || replay.fork.chainId === null) fail('replay.fork.chainId is required');
    checkQuantity(replay.fork.chainId, 'replay.fork.chainId');
    if (replay.fork.blockNumber === undefined) fail('replay.fork.blockNumber must be a non-negative quantity');
    checkQuantity(replay.fork.blockNumber, 'replay.fork.blockNumber');
    if (replay.fork.blockHash !== undefined && (typeof replay.fork.blockHash !== 'string' || !EVM_HASH_RE.test(replay.fork.blockHash))) fail('replay.fork.blockHash must be an EVM block hash');
    if (replay.fork.timestamp !== undefined) checkQuantity(replay.fork.timestamp, 'replay.fork.timestamp');
    if (replay.fork.stateRoot !== undefined) checkEvmHash(replay.fork.stateRoot, 'replay.fork.stateRoot');
  }
  validateTransactionReferences(replay, replay.transactions);
  validateReplayAnchors(replay);
  return replay;
}

function replayDimensionStatus(hasValue, complete = hasValue) {
  if (!hasValue) return 'unavailable';
  return complete ? 'available' : 'partial';
}

/**
 * Summarize replay evidence without turning it into a vulnerability verdict.
 * This is intentionally derived metadata: it is not included in the artifact
 * hash and `confirmationEligible` is always false until an independent
 * dynamic evidence policy verifies the execution itself.
 */
export function replayEvidenceStatus(value) {
  try {
    const replay = value === undefined ? undefined : validateReplayContext(value);
    if (!replay) {
      return {
        state: 'insufficient',
        replayable: false,
        confirmationEligible: false,
        dimensions: {
          rawCalldata: 'unavailable', transactionSequence: 'unavailable', initialState: 'unavailable',
          traces: 'unavailable', storageDiff: 'unavailable', assetChanges: 'unavailable', permissionChanges: 'unavailable',
          stateDiff: 'unavailable', seed: 'unavailable', fork: 'unavailable', replayCommand: 'unavailable',
        },
        limitations: ['replay_context_missing'],
      };
    }
    const transactions = Array.isArray(replay.transactions) ? replay.transactions : [];
    const calldataCount = transactions.filter((item) => item.data !== undefined || item.input !== undefined || item.calldata !== undefined).length;
    const transactionHashCount = transactions.filter((item) => item.transactionHash !== undefined).length;
    const rawCalldata = replayDimensionStatus(
      transactions.length > 0,
      calldataCount === transactions.length && transactionHashCount === transactions.length && transactions.length > 0,
    );
    const sequenceItems = replay.sequence === undefined ? transactions : replay.sequence;
    const sequenceComplete = transactions.length > 0 && sequenceItems.length === transactions.length &&
      new Set(sequenceItems.map((item) => typeof item === 'number' ? item : item.txIndex)).size === sequenceItems.length;
    const transactionSequence = replayDimensionStatus(transactions.length > 0, sequenceComplete);
    const initialState = replayDimensionStatus(
      replay.initialState !== undefined,
      replay.initialState !== undefined && (
        (Array.isArray(replay.initialState.accounts) && replay.initialState.accounts.some((account) => Object.keys(account).some((key) => key !== 'address'))) ||
        (Array.isArray(replay.initialState.storage) && replay.initialState.storage.length > 0) ||
        replay.initialState.stateRoot !== undefined
      ),
    );
    const traceRows = Array.isArray(replay.traces) ? replay.traces : [];
    const transactionIndexSet = new Set(transactions.filter((item) => item.txIndex !== undefined).map((item) => item.txIndex));
    const traceIndexSet = new Set(traceRows.filter((item) => item.txIndex !== undefined).map((item) => item.txIndex));
    const traceCoverage = transactions.length === 0 || (
      traceRows.length === transactions.length && (
        transactionIndexSet.size === 0 || (
          traceIndexSet.size === traceRows.filter((item) => item.txIndex !== undefined).length &&
          traceIndexSet.size === traceRows.length && [...traceIndexSet].every((txIndex) => transactionIndexSet.has(txIndex))
        )
      )
    );
    const traces = replayDimensionStatus(
      traceRows.length > 0,
      traceRows.length > 0 && traceCoverage && traceRows.every((trace) =>
        (trace.state === undefined || trace.state === 'available') && (trace.hash !== undefined || trace.traceHash !== undefined)),
    );
    const storageDiff = replayDimensionStatus(Array.isArray(replay.storageDiff), Array.isArray(replay.storageDiff));
    const assetChanges = replayDimensionStatus(replay.assetChanges !== undefined, replay.assetChanges !== undefined);
    const permissionChanges = replayDimensionStatus(replay.permissionChanges !== undefined, replay.permissionChanges !== undefined);
    const stateDiff = replayDimensionStatus(replay.stateDiff !== undefined, replay.stateDiff !== undefined);
    const dimensions = {
      rawCalldata,
      transactionSequence,
      initialState,
      traces,
      storageDiff,
      assetChanges,
      permissionChanges,
      stateDiff,
      seed: replay.seed === undefined ? 'unavailable' : 'available',
      fork: replay.fork === undefined ? 'unavailable' : replay.fork.blockHash === undefined ? 'partial' : 'available',
      replayCommand: replay.command === undefined ? 'unavailable' : 'available',
    };
    const core = [
      'rawCalldata', 'transactionSequence', 'initialState', 'traces', 'storageDiff',
      'assetChanges', 'permissionChanges', 'stateDiff', 'seed', 'fork',
    ];
    const availableCore = core.filter((name) => dimensions[name] === 'available').length;
    const partialCore = core.filter((name) => dimensions[name] === 'partial').length;
    const state = availableCore === core.length && dimensions.replayCommand === 'available'
      ? 'complete' : availableCore > 0 || partialCore > 0 ? 'partial' : 'insufficient';
    const limitations = [];
    for (const name of core) if (dimensions[name] !== 'available') limitations.push(`missing_or_partial_${name}`);
    if (dimensions.replayCommand !== 'available') limitations.push('replay_command_missing');
    return {
      state,
      replayable: state === 'complete',
      confirmationEligible: false,
      dimensions,
      transactionCount: transactions.length,
      traceCount: Array.isArray(replay.traces) ? replay.traces.length : 0,
      storageDiffCount: Array.isArray(replay.storageDiff) ? replay.storageDiff.length : 0,
      limitations,
    };
  } catch (error) {
    return {
      state: 'invalid',
      replayable: false,
      confirmationEligible: false,
      dimensions: null,
      limitations: ['replay_context_invalid'],
      reason: error instanceof Error ? error.message.slice(0, 200) : 'invalid replay context',
    };
  }
}

function validateEnvelope({ schemaVersion, artifactId, createdAt, analysisInput, events, evidenceRefs, replay }, { checkHash = false, sha256 } = {}) {
  if (schemaVersion !== REPLAY_ARTIFACT_SCHEMA_VERSION) fail(`schemaVersion must be ${REPLAY_ARTIFACT_SCHEMA_VERSION}`);
  if (typeof artifactId !== 'string' || artifactId.length < 1 || artifactId.length > 200) fail('artifactId must be a non-empty string');
  if (typeof createdAt !== 'string' || createdAt.length > 100 || !DATE_RE.test(createdAt) || !Number.isFinite(Date.parse(createdAt))) fail('createdAt must be an ISO timestamp');
  if (!Array.isArray(events)) fail('events must be an array');
  if (!Array.isArray(evidenceRefs)) fail('evidenceRefs must be an array');

  const body = {
    schemaVersion,
    artifactId,
    createdAt,
    analysisInput: cloneJson(analysisInput, 'analysisInput'),
    events: cloneJson(events, 'events'),
    evidenceRefs: cloneJson(evidenceRefs, 'evidenceRefs'),
  };
  const replayContext = validateReplayContext(replay);
  if (replayContext !== undefined) body.replay = replayContext;
  if (checkHash) {
    if (typeof sha256 !== 'string' || !HASH_RE.test(sha256)) return false;
    if (sha256 !== hashBody(body)) return false;
  }
  return body;
}

/**
 * Create a self-contained local replay record. Inputs are copied before the
 * hash is computed, so callers cannot change the artifact by retaining a
 * reference to one of the input objects.
 */
export function createReplayArtifact({
  analysisInput = {},
  input,
  events = [],
  evidenceRefs,
  evidence,
  replay,
  artifactId = randomUUID(),
  createdAt = new Date().toISOString(),
  schemaVersion = REPLAY_ARTIFACT_SCHEMA_VERSION,
} = {}) {
  const body = validateEnvelope({
    schemaVersion,
    artifactId,
    createdAt,
    analysisInput: input === undefined ? analysisInput : input,
    events,
    evidenceRefs: evidenceRefs === undefined ? (evidence === undefined ? [] : evidence) : evidenceRefs,
    replay,
  });
  const artifact = { ...body, sha256: hashBody(body) };
  if (serializedSize(artifact) > REPLAY_ARTIFACT_MAX_BYTES) fail(`replay artifact exceeds ${REPLAY_ARTIFACT_MAX_BYTES} bytes`, RangeError);
  return freezeDeep(artifact);
}

function freezeDeep(value, seen = new Set()) {
  if (!value || typeof value !== 'object' || seen.has(value)) return value;
  seen.add(value);
  for (const child of Object.values(value)) freezeDeep(child, seen);
  return Object.freeze(value);
}

/** Return true only when the artifact envelope, size, and content hash agree. */
export function verifyReplayArtifact(artifact) {
  try {
    if (!artifact || typeof artifact !== 'object' || Array.isArray(artifact)) return false;
    const baseKeys = ['schemaVersion', 'artifactId', 'createdAt', 'analysisInput', 'events', 'evidenceRefs', 'sha256'];
    const expectedKeys = new Set([...baseKeys, ...(Object.hasOwn(artifact, 'replay') ? ['replay'] : [])]);
    if (Reflect.ownKeys(artifact).some((key) => typeof key !== 'string' || !expectedKeys.has(key)) || Object.keys(artifact).length !== expectedKeys.size) return false;
    const { schemaVersion, artifactId, createdAt, analysisInput, events, evidenceRefs, replay, sha256 } = artifact;
    const body = validateEnvelope({ schemaVersion, artifactId, createdAt, analysisInput, events, evidenceRefs, replay }, { checkHash: true, sha256 });
    if (!body) return false;
    const candidate = { ...body, sha256 };
    return serializedSize(candidate) <= REPLAY_ARTIFACT_MAX_BYTES;
  } catch {
    return false;
  }
}

