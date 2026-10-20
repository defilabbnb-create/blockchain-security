import { createHash, randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { lstat, mkdir, open, readFile, realpath, stat, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

export const RESOURCE_TASK_PREFIX = 'v1-resource-';
export const RESOURCE_TASK_TYPES = Object.freeze(['projects', 'contracts', 'collection', 'bytecode', 'decompile'].map((name) => RESOURCE_TASK_PREFIX + name));
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const DEFAULT_EVIDENCE_ROOT = join(ROOT, 'work', 'resource-task-evidence');
const MAX_INPUT_BYTES = 16 * 1024 * 1024;
const MAX_BYTECODE_BYTES = 131_072;
const MAX_COLLECTION_BLOCKS = 128;
const MAX_COLLECTION_RESPONSE_BYTES = 8 * 1024 * 1024;
const MAX_COLLECTION_ARCHIVE_BYTES = 64 * 1024 * 1024;
const COLLECTION_RPC_METHODS = new Set(['eth_chainId', 'eth_getBlockByNumber', 'eth_getCode', 'eth_getLogs', 'eth_getTransactionReceipt', 'eth_getStorageAt', 'debug_traceTransaction', 'trace_transaction']);
const ZERO_ADDRESS = `0x${'00'.repeat(20)}`;
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const taskDirectory = (root, taskId) => join(root, sha256(String(taskId)));

function underRoot(candidate, root) {
  const child = relative(root, candidate);
  return child === '' || (child !== '..' && !child.startsWith('..' + sep) && !isAbsolute(child));
}

function json(value) { return JSON.stringify(value, null, 2) + '\n'; }

function validateInput(resource, input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('资源任务输入必须是对象');
  const allowed = {
    projects: ['projectId', 'sourcePath', 'outputPath', 'archiveRoot', 'maxFileBytes', 'maxTotalBytes', 'maxFiles', 'requestId', 'createdAt'],
    contracts: ['projectId', 'contractId', 'chainId', 'address', 'bytecodePath', 'metadata', 'requestId', 'createdAt'],
    collection: ['projectId', 'sourcePath', 'chainId', 'address', 'block', 'fromBlock', 'toBlock', 'rpcUrl', 'maxBlocks', 'includeTransactions', 'includeLogs', 'includeReceipts', 'includeTraces', 'storageSlots', 'maxTransactions', 'metadata', 'requestId', 'createdAt'],
    bytecode: ['projectId', 'contractId', 'inputPath', 'runtimeBytecode', 'chainId', 'address', 'block', 'hardfork', 'metadata', 'requestId', 'createdAt'],
    decompile: ['projectId', 'contractId', 'bytecodePath', 'runtimeBytecode', 'binary', 'outputPath', 'timeoutSeconds', 'hardfork', 'metadata', 'requestId', 'createdAt'],
  }[resource];
  if (!allowed || Object.keys(input).some((key) => !allowed.includes(key))) throw new Error('资源任务包含未支持的字段');
  if (resource === 'projects' && typeof input.sourcePath !== 'string') throw new Error('projects 任务缺少 sourcePath');
  if (resource === 'contracts') {
    if (typeof input.projectId !== 'string' || !input.projectId.trim() || typeof input.contractId !== 'string' || !input.contractId.trim()) throw new Error('contracts 任务需要 projectId 和已导入的 contractId');
    asInt(input.chainId, 'chainId', { max: 2_147_483_647 });
    collectionAddress(input.address);
  }
  if (resource === 'bytecode' && !input.runtimeBytecode && !input.inputPath && !input.contractId) throw new Error('bytecode 任务需要 runtimeBytecode、inputPath 或 contractId');
  if (resource === 'decompile' && !input.runtimeBytecode && !input.bytecodePath && !input.contractId) throw new Error('decompile 任务需要 runtimeBytecode、bytecodePath 或 contractId');
}

function collectionBlock(value, label) {
  if (typeof value === 'number') return asInt(value, label, { min: 0, max: Number.MAX_SAFE_INTEGER });
  if (typeof value !== 'string' || !/^(?:0x[0-9a-f]+|[0-9]+)$/i.test(value)) throw new Error(`${label} 必须是十进制或十六进制区块号`);
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 0) throw new Error(`${label} 超出允许范围`);
  return number;
}

function collectionAddress(value) {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string' || !/^0x[0-9a-f]{40}$/i.test(value)) throw new Error('address 必须是 20 字节十六进制地址');
  return value.toLowerCase();
}

function collectionRpcUrl(value, allowlist) {
  if (typeof value !== 'string' || !value.trim()) throw new Error('collection 需要显式 rpcUrl');
  let parsed;
  try { parsed = new URL(value); } catch { throw new Error('rpcUrl 不是有效 URL'); }
  if (!['https:', 'http:'].includes(parsed.protocol) || parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error('rpcUrl 只允许无凭据的 HTTP(S) endpoint');
  }
  const local = ['localhost', '127.0.0.1', '::1'].includes(parsed.hostname);
  if (parsed.protocol === 'http:' && !local) throw new Error('非本机 RPC 必须使用 HTTPS');
  const normalized = parsed.toString();
  if (allowlist && allowlist.size > 0 && !allowlist.has(normalized) && !allowlist.has(parsed.origin)) {
    throw new Error('rpcUrl 不在固定 allowlist 内');
  }
  return normalized;
}

function collectionConfig(input, rpcAllowlist, maxCollectionBlocks) {
  validateInput('collection', input);
  if (input.chainId === undefined) throw new Error('采集任务缺少 chainId');
  const chainId = asInt(input.chainId, 'chainId', { min: 1, max: 2_147_483_647 });
  const rpcUrl = collectionRpcUrl(input.rpcUrl, rpcAllowlist);
  const address = collectionAddress(input.address);
  const fromBlock = input.fromBlock === undefined ? collectionBlock(input.block, 'block') : collectionBlock(input.fromBlock, 'fromBlock');
  const toBlock = input.toBlock === undefined ? fromBlock : collectionBlock(input.toBlock, 'toBlock');
  if (toBlock < fromBlock) throw new Error('toBlock 不能小于 fromBlock');
  const configuredMax = input.maxBlocks === undefined ? maxCollectionBlocks : asInt(input.maxBlocks, 'maxBlocks', { min: 1, max: MAX_COLLECTION_BLOCKS });
  if (toBlock - fromBlock + 1 > configuredMax) throw new Error(`区块范围超过 ${configuredMax} 个区块上限`);
  const includeTransactions = input.includeTransactions === undefined ? false : input.includeTransactions;
  const includeLogs = input.includeLogs === undefined ? Boolean(address) : input.includeLogs;
  // Transaction bodies are useful on their own; receipt/trace reads are opt-in
  // because providers often bill or rate-limit them separately.
  const includeReceipts = input.includeReceipts === undefined ? false : input.includeReceipts;
  const includeTraces = input.includeTraces === undefined ? false : input.includeTraces;
  const storageSlots = input.storageSlots === undefined ? [] : input.storageSlots;
  if (typeof includeTransactions !== 'boolean' || typeof includeLogs !== 'boolean' || typeof includeReceipts !== 'boolean' || typeof includeTraces !== 'boolean') throw new Error('采集开关必须是布尔值');
  if (!Array.isArray(storageSlots) || storageSlots.length > 64 || storageSlots.some((slot) => typeof slot !== 'string' || !/^0x[0-9a-f]{64}$/i.test(slot))) throw new Error('storageSlots 必须是最多 64 个 32 字节十六进制槽位');
  if (storageSlots.length && !address) throw new Error('读取 storageSlots 需要 address');
  const maxTransactions = input.maxTransactions === undefined ? 64 : asInt(input.maxTransactions, 'maxTransactions', { min: 1, max: 256 });
  if ((includeReceipts || includeTraces) && !includeTransactions) throw new Error('采集 receipt/trace 需要 includeTransactions=true');
  return { schemaVersion: 1, projectId: String(input.projectId || 'unassigned'), chainId, address, rpcUrl, fromBlock, toBlock, maxBlocks: configuredMax, includeTransactions, includeLogs, includeReceipts, includeTraces, storageSlots: storageSlots.map((slot) => slot.toLowerCase()), maxTransactions };
}

function blockTag(block) { return `0x${block.toString(16)}`; }

function normalizeTransaction(tx, { hash, index, block }) {
  const row = {
    transactionHash: hash.toLowerCase(),
    transactionIndex: index,
    blockNumber: block.number,
    blockHash: block.hash,
    from: null,
    to: null,
    value: null,
    input: null,
    nonce: null,
    gas: null,
    gasPrice: null,
    maxFeePerGas: null,
    maxPriorityFeePerGas: null,
    type: null,
    transactionDetailsState: 'unavailable',
    receipt: null,
    trace: null,
  };
  if (typeof tx === 'string') return row;
  if (!tx || typeof tx !== 'object' || Array.isArray(tx)) return row;
  const exactAddress = (value) => typeof value === 'string' && /^0x[0-9a-f]{40}$/i.test(value) ? value.toLowerCase() : null;
  const quantity = (value) => typeof value === 'string' && /^0x[0-9a-f]+$/i.test(value) ? value.toLowerCase() : null;
  const data = (value) => typeof value === 'string' && /^0x(?:[0-9a-f]{2})*$/i.test(value) ? value.toLowerCase() : null;
  const observedHash = typeof tx.hash === 'string' && /^0x[0-9a-f]{64}$/i.test(tx.hash) ? tx.hash.toLowerCase() : null;
  if (observedHash && observedHash !== row.transactionHash) throw errorWithCode('交易对象 hash 与区块交易索引不一致', 'RPC_INVALID_RESULT');
  if (tx.blockHash !== undefined && (typeof tx.blockHash !== 'string' || tx.blockHash.toLowerCase() !== block.hash)) throw errorWithCode('交易对象 blockHash 与区块锚点不一致', 'RPC_INVALID_RESULT');
  if (tx.blockNumber !== undefined && collectionBlock(tx.blockNumber, 'transaction.blockNumber') !== block.number) throw errorWithCode('交易对象 blockNumber 与区块锚点不一致', 'RPC_INVALID_RESULT');
  row.from = exactAddress(tx.from);
  row.to = tx.to === null ? null : exactAddress(tx.to);
  row.value = quantity(tx.value);
  row.input = data(tx.input ?? tx.data);
  row.nonce = quantity(tx.nonce);
  row.gas = quantity(tx.gas);
  row.gasPrice = quantity(tx.gasPrice);
  row.maxFeePerGas = quantity(tx.maxFeePerGas);
  row.maxPriorityFeePerGas = quantity(tx.maxPriorityFeePerGas);
  row.type = quantity(tx.type);
  row.transactionDetailsState = row.from && row.value !== null && row.input !== null ? 'available' : 'partial';
  return row;
}

function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

function errorWithCode(message, code, extra = {}) {
  const error = new Error(message);
  error.code = code;
  Object.assign(error, extra);
  return error;
}

function capabilityFailure(error) {
  if (error?.code === 'RPC_UNSUPPORTED') return { state: 'unsupported', reason: 'RPC provider does not support this read method' };
  if (['RPC_TIMEOUT', 'RPC_TRANSPORT', 'RPC_RATE_LIMITED', 'RPC_HTTP_ERROR'].includes(error?.code) || error?.retryable) {
    return { state: 'unavailable', reason: 'RPC probe failed or timed out' };
  }
  return { state: 'invalid', reason: 'RPC probe returned an invalid result' };
}

function capabilityMethod(method, state, extra = {}) {
  return { method, state, ...extra };
}

function propagateCollectionFatal(error) {
  if (['ARCHIVE_BUDGET_EXCEEDED', 'RPC_RESPONSE_TOO_LARGE', 'COLLECTION_ABORTED', 'RPC_METHOD_BLOCKED'].includes(error?.code)) throw error;
}

async function defaultCollectionRpcRequest({ url, method, params, signal, timeoutMs = 15_000 }) {
  if (!COLLECTION_RPC_METHODS.has(method)) throw errorWithCode('RPC method is not in the read-only allowlist', 'RPC_METHOD_BLOCKED');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error('RPC request timeout')), timeoutMs);
  const abort = () => controller.abort(signal?.reason || new Error('collection aborted'));
  signal?.addEventListener('abort', abort, { once: true });
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'user-agent': 'BlockchainSecurityResearch/1.0' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
      signal: controller.signal,
      redirect: 'error',
    });
    const raw = Buffer.from(await response.arrayBuffer());
    if (raw.length > MAX_COLLECTION_RESPONSE_BYTES) throw errorWithCode('RPC response exceeds collection limit', 'RPC_RESPONSE_TOO_LARGE');
    if (!response.ok) throw errorWithCode(`RPC HTTP status ${response.status}`, response.status === 429 ? 'RPC_RATE_LIMITED' : 'RPC_HTTP_ERROR', { retryable: response.status >= 500 || response.status === 429 });
    let body;
    try { body = JSON.parse(raw.toString('utf8')); } catch { throw errorWithCode('RPC response is not valid JSON', 'RPC_INVALID_JSON'); }
    if (!body || body.jsonrpc !== '2.0' || body.id !== 1) throw errorWithCode('RPC response envelope is invalid', 'RPC_INVALID_ENVELOPE');
    if (body.error) {
      const rpcCode = Number(body.error.code);
      throw errorWithCode(`RPC error ${Number.isFinite(rpcCode) ? rpcCode : 'unknown'}`, rpcCode === -32601 || rpcCode === -32602 ? 'RPC_UNSUPPORTED' : 'RPC_ERROR', { rpcCode });
    }
    if (!Object.hasOwn(body, 'result')) throw errorWithCode('RPC response has no result', 'RPC_INVALID_ENVELOPE');
    return { value: body.result, raw };
  } catch (error) {
    if (error?.name === 'AbortError' || error?.code === 'ABORT_ERR') {
      if (signal?.aborted) throw errorWithCode('collection aborted', 'COLLECTION_ABORTED');
      throw errorWithCode('RPC request timed out', 'RPC_TIMEOUT', { retryable: true });
    }
    throw error;
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', abort);
  }
}

async function exclusiveBytes(path, bytes) {
  try {
    await writeFile(path, bytes, { flag: 'wx', mode: 0o600 });
    return;
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
    const existing = await readFile(path);
    if (!existing.equals(bytes)) throw errorWithCode(`immutable archive collision: ${path}`, 'ARCHIVE_COLLISION');
  }
}

async function archiveCollectionRaw({ archiveRoot, raw, kind, config, blockNumber = null, blockHash = null, contractAddress = null, codeHash = null, method, params, sequence }) {
  if (!Buffer.isBuffer(raw)) raw = Buffer.from(raw || '');
  if (raw.length > MAX_COLLECTION_RESPONSE_BYTES) throw errorWithCode('RPC response exceeds collection limit', 'RPC_RESPONSE_TOO_LARGE');
  const contentHash = sha256(raw);
  const directory = join(archiveRoot, 'raw', contentHash.slice(0, 2), contentHash);
  const payloadPath = join(directory, 'payload.bin');
  const createdAt = new Date().toISOString();
  const provenance = {
    project_id: config.projectId,
    chain_id: config.chainId,
    block_number: blockNumber,
    block_hash: blockHash,
    contract_address: contractAddress,
    code_hash: codeHash,
    content_hash: contentHash,
    schema_version: 1,
    tool_version: 'resource-collection/1',
    source_ref: { url: config.rpcUrl, method, params },
    created_at: createdAt,
    updated_at: createdAt,
    provenance: { responseParsed: true, sequence },
  };
  const metadata = { kind, byte_length: raw.length, compression: null, provenance, processing: { status: 'raw', error: null }, schema_version: 1 };
  const metadataBytes = Buffer.from(JSON.stringify(metadata, null, 2) + '\n');
  const metadataHash = sha256(metadataBytes);
  const metadataPath = join(directory, `${metadataHash}.metadata.json`);
  await mkdir(directory, { recursive: true });
  await exclusiveBytes(payloadPath, raw);
  await exclusiveBytes(metadataPath, metadataBytes);
  return { schemaVersion: 1, kind, contentHash, metadataHash, bytes: raw.length, path: payloadPath, metadataPath, sha256: contentHash, provenance };
}

function validateCollectionBlock(value, expectedNumber, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw errorWithCode(`${label} RPC result 不是对象`, 'RPC_INVALID_RESULT');
  const number = collectionBlock(value.number, `${label}.number`);
  if (number !== expectedNumber || typeof value.hash !== 'string' || !/^0x[0-9a-f]{64}$/i.test(value.hash)) throw errorWithCode(`${label} 区块锚点无效`, 'RPC_INVALID_RESULT');
  return { ...value, number, hash: value.hash.toLowerCase() };
}

function normalizedCollectionRecord({ config, block, address, code, blockArchive, codeArchive, logsCount, transactionsCount, transactions = [], storage = [], capabilities = null }) {
  const codeBytes = typeof code === 'string' && /^0x(?:[0-9a-f]{2})*$/i.test(code) ? Buffer.from(code.slice(2), 'hex') : null;
  const codeHash = codeBytes ? `0x${sha256(codeBytes)}` : null;
  const record = {
    blockNumber: block.number,
    blockHash: block.hash,
    timestamp: typeof block.timestamp === 'string' && /^0x[0-9a-f]+$/i.test(block.timestamp) ? Number(block.timestamp) : null,
    address,
    codeHash,
    codeBytes: codeBytes?.length ?? null,
    codeArchive: codeArchive?.path ?? null,
    logsCount,
    transactionsCount,
    transactions,
    storage,
    transactionsTruncated: transactionsCount !== null && transactions.length < transactionsCount,
  };
  const createdAt = new Date().toISOString();
  const sourceRef = {
    kind: 'rpc',
    rpcUrl: config.rpcUrl,
    block: {
      method: 'eth_getBlockByNumber',
      contentHash: blockArchive?.contentHash ?? null,
      path: blockArchive?.path ?? null,
    },
    ...(codeArchive ? {
      code: {
        method: 'eth_getCode',
        contentHash: codeArchive.contentHash ?? null,
        path: codeArchive.path ?? null,
      },
    } : {}),
    transactions: transactions.map((tx) => ({ transactionHash: tx.transactionHash, transactionIndex: tx.transactionIndex, receiptContentHash: tx.receipt?.contentHash ?? null, traceContentHash: tx.trace?.contentHash ?? null })),
    storage: storage.map((item) => ({ slot: item.slot, contentHash: item.contentHash ?? null })),
  };
  // Hash the normalized payload before adding timestamps and provenance so the
  // content identity remains stable when the same block is re-indexed.
  const contentHash = sha256(Buffer.from(canonicalJson(record), 'utf8'));
  return {
    ...record,
    capabilities: capabilities ? JSON.parse(JSON.stringify(capabilities)) : null,
    provenance: {
      project_id: config.projectId,
      chain_id: config.chainId,
      block_number: block.number,
      block_hash: block.hash,
      contract_address: address,
      code_hash: codeHash,
      content_hash: contentHash,
      schema_version: 1,
      tool_version: 'resource-collection/1',
      source_ref: sourceRef,
      created_at: createdAt,
      updated_at: createdAt,
      provenance: {
        recordKind: 'normalized_collection_block',
        sourceVerified: false,
        rawArchiveContentHashes: [blockArchive?.contentHash, codeArchive?.contentHash, ...transactions.flatMap((tx) => [tx.receipt?.contentHash, tx.trace?.contentHash]), ...storage.map((item) => item.contentHash)].filter(Boolean),
        capabilities,
      },
    },
  };
}

async function roots(realRoots) {
  return Promise.all(realRoots.map((root) => realpath(resolve(root))));
}

async function inputFile(path, allowedRoots, maxBytes = MAX_INPUT_BYTES) {
  if (typeof path !== 'string' || !path || path.includes('\0')) throw new Error('输入路径无效');
  const canonical = await realpath(resolve(path));
  if (!allowedRoots.some((root) => underRoot(canonical, root))) throw new Error('输入路径超出允许根目录');
  const info = await lstat(canonical);
  if (!info.isFile()) throw new Error('输入必须是普通文件');
  if (info.size < 1 || info.size > maxBytes) throw new Error(`输入文件大小必须在 1..${maxBytes} 字节`);
  const bytes = await readFile(canonical);
  if (bytes.length !== info.size) throw new Error('输入文件在读取时发生变化');
  return { path: canonical, bytes, sha256: sha256(bytes) };
}

async function inputDirectory(path, allowedRoots) {
  if (typeof path !== 'string' || !path || path.includes('\0')) throw new Error('项目路径无效');
  const canonical = await realpath(resolve(path));
  if (!allowedRoots.some((root) => underRoot(canonical, root))) throw new Error('项目路径超出允许根目录');
  const info = await lstat(canonical);
  if (!info.isDirectory()) throw new Error('项目路径必须是目录');
  return canonical;
}

async function runProcess({ args, cwd, stdoutPath, stderrPath, signal, timeoutMs, spawnProcess = spawn, killGraceMs = 500 }) {
  const stdout = await open(stdoutPath, 'wx', 0o600);
  let stderr;
  try { stderr = await open(stderrPath, 'wx', 0o600); }
  catch (error) { await stdout.close(); throw error; }
  let child, timer, killTimer, aborted = false, timedOut = false, spawnError = null;
  const kill = (name) => { if (child?.pid) try { process.kill(-child.pid, name); } catch (error) { if (error.code !== 'ESRCH') spawnError ??= error; } };
  const terminate = () => { kill('SIGTERM'); killTimer ??= setTimeout(() => kill('SIGKILL'), killGraceMs); };
  const abort = () => { aborted = true; terminate(); };
  try {
    if (signal?.aborted) return { exitCode: null, signal: null, aborted: true, timedOut: false };
    const env = { PATH: process.env.PATH || '/usr/bin:/bin', PYTHONHASHSEED: '0', LANG: 'C.UTF-8', TMPDIR: cwd };
    child = spawnProcess('python3', args, { cwd, env, shell: false, detached: true, stdio: ['ignore', stdout.fd, stderr.fd] });
    signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted) abort();
    timer = setTimeout(() => { timedOut = true; terminate(); }, timeoutMs);
    const closed = await new Promise((done) => {
      child.once('error', (error) => { spawnError = error; });
      child.once('close', (exitCode, exitSignal) => done({ exitCode, signal: exitSignal }));
    });
    if (aborted || timedOut) kill('SIGKILL');
    if (spawnError) throw spawnError;
    return { ...closed, aborted, timedOut };
  } finally {
    clearTimeout(timer); clearTimeout(killTimer); signal?.removeEventListener('abort', abort);
    await Promise.all([stdout.close(), stderr.close()]);
  }
}

async function artifact(path, kind) {
  const info = await lstat(path);
  if (!info.isFile()) throw new Error('生成的 artifact 必须是普通文件');
  const bytes = await readFile(path);
  return { path, kind, bytes: bytes.length, sha256: sha256(bytes) };
}

async function readJson(path, limit = 64 * 1024 * 1024) {
  const info = await stat(path);
  if (!info.isFile() || info.size > limit) throw new Error('工具报告类型或大小无效');
  const bytes = await readFile(path);
  if (bytes.length > limit) throw new Error('工具报告超过大小限制');
  return { value: JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)), bytes };
}

function validateBytecodeReport(report, inputHash, inputBytes) {
  if (!report || typeof report !== 'object' || Array.isArray(report)) throw new Error('工具报告必须是 JSON 对象');
  if (report.schemaVersion !== 1 || report.analysisType !== 'deterministic_evm_runtime_disassembly') {
    throw new Error('工具报告类型或版本无效');
  }
  if (typeof report.runtimeBytecode !== 'string' || !/^0x(?:[0-9a-f]{2})+$/i.test(report.runtimeBytecode)) {
    throw new Error('工具报告缺少有效 runtimeBytecode');
  }
  const reportBytes = Buffer.from(report.runtimeBytecode.slice(2), 'hex');
  if (reportBytes.length !== inputBytes || sha256(reportBytes) !== inputHash ||
      String(report.bytecodeSha256 || '').toLowerCase() !== inputHash || report.bytecodeBytes !== inputBytes) {
    throw new Error('工具报告与输入字节码指纹不匹配');
  }
}

function extractExpectedRuntimeBytecode(bytes) {
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  let value;
  try { value = JSON.parse(text); }
  catch { value = text.trim(); }
  let candidates = [];
  if (typeof value === 'string') candidates = [value];
  else if (value && typeof value === 'object' && !Array.isArray(value)) {
    const runtime = value.runtimeBytecode;
    candidates = [runtime && typeof runtime === 'object' ? runtime.onchainBytecode : runtime, value.runtimeCode];
  }
  candidates = candidates.filter((candidate) => typeof candidate === 'string' && candidate.startsWith('0x'));
  if (new Set(candidates.map((candidate) => candidate.toLowerCase())).size > 1) {
    throw new Error('输入文件包含冲突的 runtime bytecode');
  }
  const bytecode = candidates[0];
  if (typeof bytecode !== 'string' || !/^0x(?:[0-9a-f]{2})+$/i.test(bytecode) || bytecode.length > (MAX_BYTECODE_BYTES * 2) + 2) {
    throw new Error('输入文件缺少有效 runtime bytecode');
  }
  return Buffer.from(bytecode.slice(2), 'hex');
}

function asInt(value, label, { min = 1, max = Number.MAX_SAFE_INTEGER } = {}) {
  const number = typeof value === 'number' ? value : Number(value);
  if (!Number.isSafeInteger(number) || number < min || number > max) throw new Error(`${label} 超出允许范围`);
  return number;
}

function blocked(reason, checkpoint = undefined) {
  return { status: 'blocked', reason, ...(checkpoint ? { checkpoint } : {}) };
}

async function importedSourceUnit(taskStore, evidenceRoot, allowedRoots, projectId, contractId) {
  if (!taskStore || typeof taskStore.readSnapshot !== 'function') throw new Error('持久化任务状态未提供，无法解析项目来源');
  const snapshot = await taskStore.readSnapshot();
  const projects = snapshot.tasks.filter((task) => task.type === RESOURCE_TASK_PREFIX + 'projects' &&
    task.state === 'succeeded' && task.checkpoint?.complete === true &&
    task.checkpoint?.projectId === projectId && task.payload?.input?.projectId === projectId);
  for (const task of projects) {
    const checkpoint = task.checkpoint;
    const manifestArtifact = checkpoint.artifacts?.find((item) => item?.kind === 'project-import-manifest');
    if (!manifestArtifact || !checkpoint.attemptDirectory || !checkpoint.projectRoot) continue;
    try {
      const [evidenceRootPath, attemptPath, manifestPath] = await Promise.all([
        realpath(evidenceRoot), realpath(checkpoint.attemptDirectory), realpath(manifestArtifact.path),
      ]);
      if (!underRoot(attemptPath, evidenceRootPath) || !underRoot(manifestPath, attemptPath) ||
          !allowedRoots.some((root) => underRoot(manifestPath, root)) ||
          !Number.isSafeInteger(manifestArtifact.bytes) || !/^[a-f0-9]{64}$/i.test(String(manifestArtifact.sha256 || ''))) continue;
      const attemptInfo = await lstat(attemptPath), manifestInfo = await lstat(manifestPath);
      if (!attemptInfo.isDirectory() || attemptInfo.isSymbolicLink() || !manifestInfo.isFile() ||
          manifestInfo.isSymbolicLink() || manifestInfo.size !== manifestArtifact.bytes) continue;
      const manifestBytes = await readFile(manifestPath);
      if (manifestBytes.length !== manifestArtifact.bytes || sha256(manifestBytes) !== String(manifestArtifact.sha256).toLowerCase()) continue;
      const manifest = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(manifestBytes));
      if (manifest.kind !== 'local-project-import' || manifest.complete !== true || manifest.projectId !== projectId ||
          !/^[a-f0-9]{64}$/i.test(String(manifest.sourceFingerprint || '')) || !Array.isArray(manifest.files)) continue;
      for (const file of manifest.files) {
        if (!file || file.included !== true || file.kind !== 'source' || typeof file.path !== 'string' ||
            !file.path || file.path.includes('\\') || file.path.startsWith('/') || file.path.split('/').includes('..') ||
            !/^[a-f0-9]{64}$/i.test(String(file.sha256 || '')) || !Number.isSafeInteger(file.bytes) || file.bytes < 1) continue;
        const id = `source-${createHash('sha256').update(`${projectId}\0${manifest.sourceFingerprint}\0${file.path}\0${String(file.sha256).toLowerCase()}`).digest('hex').slice(0, 32)}`;
        if (id !== contractId) continue;
        const source = await inputFile(resolve(checkpoint.projectRoot, file.path), allowedRoots, Math.max(file.bytes, 1));
        if (source.bytes.length !== file.bytes || source.sha256 !== String(file.sha256).toLowerCase()) throw new Error('导入源文件已变化，SHA-256 与清单不一致');
        return {
          contractId: id, projectId, sourcePath: file.path, sourceSha256: source.sha256,
          sourceBytes: source.bytes.length, sourceFingerprint: String(manifest.sourceFingerprint).toLowerCase(),
          manifest: { path: manifestPath, sha256: String(manifestArtifact.sha256).toLowerCase(), bytes: manifestBytes.length },
          projectTaskId: task.taskId,
        };
      }
    } catch (error) {
      if (error.message.includes('SHA-256')) throw error;
    }
  }
  throw new Error('contractId 不属于完整且哈希有效的项目源码导入记录');
}

function makeContractsHandler({ taskStore, evidenceRoot }) {
  return async (input, context, allowedRoots) => {
    try { validateInput('contracts', input); }
    catch (error) { return blocked(error.message); }
    const address = collectionAddress(input.address);
    let chainId, source;
    try {
      chainId = asInt(input.chainId, 'chainId', { max: 2_147_483_647 });
      source = await importedSourceUnit(taskStore, evidenceRoot, allowedRoots, input.projectId, input.contractId);
    } catch (error) { return blocked(error.message); }
    const evidenceDirectory = taskDirectory(evidenceRoot, context.task.taskId);
    await mkdir(evidenceDirectory, { recursive: true });
    const attemptDirectory = join(evidenceDirectory, `attempt-${context.task.attempts}-${randomUUID()}`);
    await mkdir(attemptDirectory, { recursive: false });
    const binding = {
      schemaVersion: 1, kind: 'user_asserted_contract_binding',
      contractId: source.contractId, projectId: source.projectId,
      source: { path: source.sourcePath, sha256: source.sourceSha256, bytes: source.sourceBytes, sourceFingerprint: source.sourceFingerprint },
      deployment: { chainId, address },
      mapping: { state: 'user_asserted', sourceVerified: false, deployedCodeCheck: 'not_performed' },
      provenance: { projectTaskId: source.projectTaskId, manifest: source.manifest },
      interpretation: '用户将已导入的源码文件关联到链和地址；尚未读取部署代码或验证源码匹配。',
    };
    const bindingPath = join(attemptDirectory, 'contract-binding.json');
    const bytes = Buffer.from(json(binding));
    await writeFile(bindingPath, bytes, { flag: 'wx', mode: 0o600 });
    const checkpoint = {
      phase: 'evidence_ready', complete: true, attemptDirectory,
      contractId: source.contractId, projectId: source.projectId, chainId, address,
      mapping: binding.mapping, source: binding.source,
      artifacts: [{ path: bindingPath, kind: 'contract-binding', bytes: bytes.length, sha256: sha256(bytes) }],
      interpretation: binding.interpretation,
    };
    await context.checkpoint(checkpoint);
    return { status: 'succeeded', result: checkpoint, checkpoint };
  };
}

function makeProjectHandler({ root, evidenceRoot, allowedRoots, timeoutMs, spawnProcess }) {
  return async (input, context) => {
    if (input?.outputPath || input?.archiveRoot) return blocked('项目导入使用任务隔离目录；不支持指定输出或归档路径');
    validateInput('projects', input);
    let directory;
    try { directory = await inputDirectory(input.sourcePath, allowedRoots); }
    catch (error) { return blocked(error.message); }
    const evidenceDirectory = taskDirectory(evidenceRoot, context.task.taskId);
    if (underRoot(evidenceDirectory, directory)) return blocked('项目根目录包含任务证据目录；请缩小 sourcePath 后重试');
    await mkdir(evidenceDirectory, { recursive: true });
    const attemptDirectory = join(evidenceDirectory, `attempt-${context.task.attempts}-${randomUUID()}`);
    await mkdir(attemptDirectory, { recursive: false });
    const manifestPath = join(attemptDirectory, 'project-import.json');
    const archiveRoot = join(attemptDirectory, 'raw-archive');
    const args = [join(root, 'scripts', 'project_import.py'), directory, '--output', manifestPath, '--archive-root', archiveRoot];
    if (input.projectId) args.push('--project-id', String(input.projectId));
    for (const key of ['maxFileBytes', 'maxTotalBytes', 'maxFiles']) if (input[key] !== undefined) args.push('--' + key.replace(/[A-Z]/g, (letter) => '-' + letter.toLowerCase()), String(asInt(input[key], key, { max: 256 * 1024 * 1024 })));
    const stderrPath = join(attemptDirectory, 'stderr.log'), stdoutPath = join(attemptDirectory, 'stdout.log');
    await context.checkpoint({ phase: 'import_preparing', attemptDirectory, projectRoot: directory });
    const execution = await runProcess({ args, cwd: root, stdoutPath, stderrPath, signal: context.signal, timeoutMs, spawnProcess });
    if (execution.aborted) return { status: 'failed', reason: 'project import aborted', checkpoint: context.lastCheckpoint };
    let manifest;
    try { manifest = (await readJson(manifestPath)).value; }
    catch (error) { return { status: 'failed', error: `项目导入未生成有效清单：${error.message}`, checkpoint: context.lastCheckpoint }; }
    const artifacts = [await artifact(manifestPath, 'project-import-manifest'), await artifact(stdoutPath, 'stdout'), await artifact(stderrPath, 'stderr')];
    const checkpoint = { phase: 'evidence_ready', attemptDirectory, projectRoot: directory, projectId: manifest.projectId, sourceFingerprint: manifest.sourceFingerprint, complete: manifest.complete === true, fileCounts: manifest.fileCounts, errorCount: manifest.errorCount, execution, artifacts, interpretation: '项目文件导入与哈希归档；未运行项目构建、测试或安全审计。' };
    await writeFile(join(attemptDirectory, 'run-summary.json'), json(checkpoint), { flag: 'wx', mode: 0o600 });
    await context.checkpoint(checkpoint);
    if (execution.timedOut) return { status: 'partial', reason: '项目导入超时；仅保留已生成清单', checkpoint };
    if (execution.exitCode !== 0 && manifest.complete !== false) return { status: 'failed', error: '项目导入进程失败', checkpoint };
    return manifest.complete ? { status: 'succeeded', result: checkpoint, checkpoint } : { status: 'partial', reason: '项目导入有跳过项或错误', result: checkpoint, checkpoint };
  };
}

function resolveBytecodeInput(resource, input) {
  if (resource === 'bytecode') return input.inputPath;
  return input.bytecodePath;
}

async function importedRuntimeCode(taskStore, evidenceRoot, allowedRoots, input) {
  if (!taskStore || typeof taskStore.readSnapshot !== 'function') throw new Error('任务状态存储不可用，无法解析 contractId');
  for (const key of ['projectId', 'chainId', 'address', 'block']) {
    if (input[key] === undefined) throw new Error(`contractId 解析需要 ${key}`);
  }
  if (typeof input.projectId !== 'string' || !input.projectId.trim() || typeof input.contractId !== 'string' || !input.contractId.trim()) {
    throw new Error('contractId 引用无效');
  }
  const chainId = asInt(input.chainId, 'chainId', { max: 2_147_483_647 });
  const blockNumber = collectionBlock(input.block, 'block');
  const address = collectionAddress(input.address);
  const snapshot = await taskStore.readSnapshot();
  const binding = snapshot.tasks.find((task) => task.type === RESOURCE_TASK_PREFIX + 'contracts' && task.state === 'succeeded' &&
    task.payload?.input?.projectId === input.projectId && task.payload?.input?.contractId === input.contractId &&
    Number(task.checkpoint?.chainId) === chainId && String(task.checkpoint?.address || '').toLowerCase() === address.toLowerCase() &&
    task.checkpoint?.mapping?.state === 'user_asserted' && task.checkpoint?.mapping?.sourceVerified === false);
  if (!binding) throw new Error('contractId 没有与此链和地址匹配的成功绑定记录');
  const collection = snapshot.tasks.find((task) => task.type === RESOURCE_TASK_PREFIX + 'collection' && task.state === 'succeeded' &&
    task.checkpoint?.complete === true && task.payload?.input?.projectId === input.projectId &&
    Number(task.payload?.input?.chainId) === chainId && String(task.payload?.input?.address || '').toLowerCase() === address.toLowerCase() &&
    Array.isArray(task.checkpoint?.records) && task.checkpoint.records.some((record) => record.blockNumber === blockNumber &&
      String(record.address || '').toLowerCase() === address.toLowerCase() && record.provenance?.chain_id === chainId &&
      record.provenance?.project_id === input.projectId && record.provenance?.block_hash === record.blockHash && record.codeHash));
  if (!collection) throw new Error('没有匹配该项目、链、地址和区块的完整代码采集记录');
  const record = collection.checkpoint.records.find((item) => item.blockNumber === blockNumber &&
    String(item.address || '').toLowerCase() === address.toLowerCase() && item.provenance?.chain_id === chainId &&
    item.provenance?.project_id === input.projectId && item.provenance?.block_hash === item.blockHash && item.codeHash);
  const sourceRef = record.provenance?.source_ref?.code;
  const ref = collection.checkpoint.archiveRefs?.find((item) => item?.kind === 'rpc.eth_getCode' &&
    item.path === sourceRef?.path && item.contentHash === sourceRef?.contentHash && item.provenance?.block_number === blockNumber &&
    item.provenance?.block_hash === record.blockHash && item.provenance?.chain_id === chainId &&
    String(item.provenance?.contract_address || '').toLowerCase() === address.toLowerCase() && item.provenance?.code_hash === record.codeHash);
  if (!ref || !collection.checkpoint.archiveRoot || !collection.checkpoint.attemptDirectory ||
      !/^[a-f0-9]{64}$/i.test(String(ref.contentHash || '')) || !/^[a-f0-9]{64}$/i.test(String(ref.metadataHash || ''))) {
    throw new Error('采集 checkpoint 缺少完整的 eth_getCode 归档指纹');
  }
  const [evidencePath, attemptPath, archivePath, raw] = await Promise.all([
    realpath(evidenceRoot), realpath(collection.checkpoint.attemptDirectory), realpath(collection.checkpoint.archiveRoot),
    inputFile(ref.path, allowedRoots, MAX_COLLECTION_RESPONSE_BYTES),
  ]);
  const expectedArchiveDirectory = join(archivePath, 'raw', ref.contentHash.slice(0, 2), ref.contentHash);
  const [rawCanonical, metadataCanonical, expectedPayloadCanonical, expectedMetadataCanonical] = await Promise.all([
    realpath(raw.path), realpath(ref.metadataPath), realpath(join(expectedArchiveDirectory, 'payload.bin')),
    realpath(join(expectedArchiveDirectory, `${ref.metadataHash}.metadata.json`)),
  ]);
  if (!underRoot(attemptPath, evidencePath) || !underRoot(archivePath, attemptPath) ||
      rawCanonical !== expectedPayloadCanonical || metadataCanonical !== expectedMetadataCanonical) {
    throw new Error('代码归档路径超出本任务的证据目录或文件名不匹配');
  }
  if (raw.sha256 !== ref.contentHash || raw.bytes.length !== ref.bytes) throw new Error('原始 eth_getCode 响应 SHA-256 或长度不匹配');
  const metadataPath = ref.metadataPath;
  const metadataFile = await inputFile(metadataPath, allowedRoots, 64 * 1024);
  if (metadataFile.sha256 !== ref.metadataHash) throw new Error('eth_getCode 元数据 SHA-256 不匹配');
  const metadata = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(metadataFile.bytes));
  if (metadata.kind !== 'rpc.eth_getCode' || metadata.byte_length !== raw.bytes.length ||
      metadata.provenance?.content_hash !== ref.contentHash || metadata.provenance?.code_hash !== record.codeHash ||
      metadata.provenance?.block_number !== blockNumber || metadata.provenance?.block_hash !== record.blockHash ||
      metadata.provenance?.chain_id !== chainId || String(metadata.provenance?.contract_address || '').toLowerCase() !== address.toLowerCase()) {
    throw new Error('eth_getCode 元数据与采集记录不匹配');
  }
  const response = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw.bytes));
  const code = response?.result;
  if (typeof code !== 'string' || !/^0x(?:[0-9a-f]{2})+$/i.test(code) ||
      `0x${sha256(Buffer.from(code.slice(2), 'hex'))}` !== record.codeHash || Buffer.from(code.slice(2), 'hex').length !== record.codeBytes) {
    throw new Error('归档的运行时代码与区块记录指纹不一致');
  }
  return { runtimeBytecode: code.toLowerCase(), reference: {
    bindingTaskId: binding.taskId, collectionTaskId: collection.taskId,
    chainId, address, blockNumber, blockHash: record.blockHash,
    codeHash: record.codeHash, codeBytes: record.codeBytes, archiveContentHash: ref.contentHash,
    archiveSha256: raw.sha256, metadataSha256: metadataFile.sha256,
  } };
}

function makeBytecodeHandler({ resource, root, evidenceRoot, allowedRoots, timeoutMs, spawnProcess, taskStore }) {
  return async (input, context) => {
    let contractCodeReference = null;
    if (input?.contractId && (input?.runtimeBytecode || (resource === 'bytecode' ? input?.inputPath : input?.bytecodePath))) {
      return blocked('contractId 不能与显式字节码输入同时使用');
    }
    if (input?.contractId && !input?.runtimeBytecode && !(resource === 'bytecode' ? input?.inputPath : input?.bytecodePath)) {
      try {
        const resolved = await importedRuntimeCode(taskStore, evidenceRoot, allowedRoots, input);
        input = { ...input, runtimeBytecode: resolved.runtimeBytecode };
        contractCodeReference = resolved.reference;
      } catch (error) { return blocked(error.message); }
    }
    if (resource === 'decompile' && (input?.binary || input?.outputPath)) {
      return blocked('只允许项目固定的 Heimdall 二进制与任务隔离输出目录');
    }
    validateInput(resource, input);
    const evidenceDirectory = taskDirectory(evidenceRoot, context.task.taskId);
    await mkdir(evidenceDirectory, { recursive: true });
    const attemptDirectory = join(evidenceDirectory, `attempt-${context.task.attempts}-${randomUUID()}`);
    await mkdir(attemptDirectory, { recursive: false });
    let inputBytes, inputHash, expectedBytecodeHash, expectedBytecodeBytes, inputPath;
    if (input.runtimeBytecode !== undefined) {
      if (typeof input.runtimeBytecode !== 'string' || !/^0x(?:[0-9a-f]{2})+$/i.test(input.runtimeBytecode) || (input.runtimeBytecode.length - 2) / 2 > MAX_BYTECODE_BYTES) return blocked('runtimeBytecode 格式或长度无效');
      inputBytes = Buffer.from(input.runtimeBytecode.slice(2), 'hex');
      expectedBytecodeHash = sha256(inputBytes); expectedBytecodeBytes = inputBytes.length;
      inputPath = join(attemptDirectory, 'runtime-bytecode.hex');
      await writeFile(inputPath, input.runtimeBytecode + '\n', { flag: 'wx', mode: 0o400 });
      inputHash = sha256(inputBytes);
    } else {
      let inputFileValue;
      try { inputFileValue = await inputFile(resolveBytecodeInput(resource, input), allowedRoots); }
      catch (error) { return blocked(error.message); }
      inputBytes = inputFileValue.bytes; inputHash = inputFileValue.sha256;
      try {
        const expectedBytecode = extractExpectedRuntimeBytecode(inputBytes);
        expectedBytecodeHash = sha256(expectedBytecode); expectedBytecodeBytes = expectedBytecode.length;
      } catch (error) { return blocked(error.message); }
      inputPath = join(attemptDirectory, 'input-' + (resource === 'bytecode' ? 'bytecode' : 'runtime') + '.json');
      await writeFile(inputPath, inputBytes, { flag: 'wx', mode: 0o400 });
    }
    if (context.lastCheckpoint?.inputSha256 && context.lastCheckpoint.inputSha256 !== inputHash) {
      return blocked('输入 SHA-256 与上次检查点不一致；为避免混合不同字节码，任务未继续', context.lastCheckpoint);
    }
    const reportPath = join(attemptDirectory, 'bytecode-analysis.json'), irPath = join(attemptDirectory, 'unified-ir.json');
    const args = [join(root, 'scripts', 'bytecode_analysis.py'), inputPath, '--output', reportPath, '--ir-output', irPath];
    if (input.chainId !== undefined) args.push('--chain-id', String(asInt(input.chainId, 'chainId', { max: 2_147_483_647 })));
    if (input.address !== undefined) args.push('--address', String(input.address));
    if (input.block !== undefined) args.push('--block', String(input.block));
    const hardfork = input.hardfork;
    if (hardfork !== undefined) args.push('--evm-hardfork', String(hardfork));
    let decompilerOutput = null;
    if (resource === 'decompile') {
      decompilerOutput = join(attemptDirectory, 'decompilation');
      args.push('--decompiler', 'heimdall', '--decompiler-output-dir', decompilerOutput,
        '--decompiler-timeout', String(input.timeoutSeconds === undefined ? Math.min(120, Math.floor(timeoutMs / 1000)) : asInt(input.timeoutSeconds, 'timeoutSeconds', { max: 300 })),
        '--decompiler-hardfork', String(hardfork || 'latest'));
    }
    const stdoutPath = join(attemptDirectory, 'stdout.log'), stderrPath = join(attemptDirectory, 'stderr.log');
    const inputCheckpoint = { phase: 'analysis_preparing', attemptDirectory, inputSha256: inputHash, inputBytes: inputBytes.length, reportPath,
      ...(contractCodeReference ? { contractCodeReference } : {}) };
    await context.checkpoint(inputCheckpoint);
    const execution = await runProcess({ args, cwd: root, stdoutPath, stderrPath, signal: context.signal, timeoutMs, spawnProcess });
    if (execution.aborted) return { status: 'failed', reason: '字节码任务已中止', checkpoint: context.lastCheckpoint };
    let reportResult;
    try { reportResult = await readJson(reportPath); }
    catch (error) { return { status: execution.timedOut ? 'partial' : 'failed', error: `字节码分析未生成有效报告：${error.message}`, checkpoint: context.lastCheckpoint }; }
    const report = reportResult.value;
    let reportValidationError = null;
    try { validateBytecodeReport(report, expectedBytecodeHash, expectedBytecodeBytes); }
    catch (error) { reportValidationError = error; }
    const reportObject = report && typeof report === 'object' && !Array.isArray(report) ? report : {};
    const artifacts = [
      await artifact(reportPath, 'bytecode-analysis'), await artifact(irPath, 'unified-ir'),
      await artifact(stdoutPath, 'stdout'), await artifact(stderrPath, 'stderr'),
    ];
    const decompilerArtifactErrors = [];
    if (decompilerOutput) {
      const canonicalDecompilerRoot = await realpath(decompilerOutput).catch(() => null);
      const reportedArtifacts = reportObject.decompilation?.artifacts;
      if (!Array.isArray(reportedArtifacts) || reportedArtifacts.length === 0) {
        decompilerArtifactErrors.push('反编译报告未列出产物');
      }
      for (const entry of Array.isArray(reportedArtifacts) ? reportedArtifacts : []) {
        const relativePath = typeof entry?.path === 'string' ? entry.path.replaceAll('\\', '/').split('/') : [];
        if (!relativePath.length || relativePath[0] === '' || relativePath.includes('..') || entry.omittedReason) {
          decompilerArtifactErrors.push('反编译产物路径无效或被省略');
          continue;
        }
        const path = join(decompilerOutput, ...relativePath);
        try {
          const canonicalPath = await realpath(path);
          if (!canonicalDecompilerRoot || !underRoot(canonicalPath, canonicalDecompilerRoot)) {
            throw new Error('decompiler artifact escaped its output directory');
          }
          const item = await artifact(canonicalPath, entry.kind || 'decompiler-output');
          if ((entry.sha256 && entry.sha256 !== item.sha256) ||
              (Number.isInteger(entry.size) && entry.size !== item.bytes)) {
            decompilerArtifactErrors.push(`反编译产物指纹不匹配：${entry.path}`);
          }
          artifacts.push(item);
        } catch {
          decompilerArtifactErrors.push(`反编译产物缺失或不可读：${entry.path}`);
        }
      }
    }
    const decompilation = reportObject.decompilation || { state: 'not_performed' };
    const executionSucceeded = execution.exitCode === 0 && execution.signal === null && !execution.timedOut && !execution.aborted;
    const decompilerEvidenceComplete = decompilerArtifactErrors.length === 0;
    const complete = reportValidationError === null && (resource === 'bytecode' ? executionSucceeded : decompilation.state === 'completed' && executionSucceeded && decompilerEvidenceComplete);
    const checkpoint = {
      phase: 'evidence_ready', attemptDirectory, inputSha256: inputHash, inputBytes: inputBytes.length,
      bytecodeSha256: reportObject.bytecodeSha256 || null, bytecodeBytes: reportObject.bytecodeBytes || null,
      decompilationState: decompilation.state, sourceVerified: false, confirmedVulnerabilities: 0,
      ...(resource === 'decompile' ? {
        crossValidation: decompilation.crossValidation || {
          state: 'not_recorded',
          reason: 'cross_validation_metadata_missing',
          enginesConfigured: ['heimdall-rs'],
          enginesCompleted: [],
          comparedEngineCount: 0,
          comparedHighLevelEngineCount: 0,
          agreementScope: '未记录独立高层反编译器比对；opcode/PC 解码核对不验证伪码语义。',
          opcodePcCrossCheck: reportObject.opcodePcCrossCheck || null,
        },
      } : {}),
      ...(contractCodeReference ? { contractCodeReference } : {}),
      inputBinding: { matched: reportValidationError === null, ...(reportValidationError ? { error: reportValidationError.message } : {}) },
      decompilerArtifactValidation: decompilerOutput ? { complete: decompilerEvidenceComplete, errors: decompilerArtifactErrors } : null,
      execution, artifacts, reportSha256: sha256(reportResult.bytes), reportBytes: reportResult.bytes.length,
      interpretation: resource === 'decompile'
        ? '反汇编与单引擎启发式伪码；不代表恢复源码、语义证明或漏洞确认。'
        : '确定性字节码反汇编和结构化线索；不证明控制流可达性或漏洞。',
    };
    await writeFile(join(attemptDirectory, 'run-summary.json'), json(checkpoint), { flag: 'wx', mode: 0o600 });
    await context.checkpoint(checkpoint);
    if (complete) return { status: 'succeeded', result: checkpoint, checkpoint };
    if (reportValidationError) return { status: 'failed', error: reportValidationError.message, checkpoint };
    if (execution.timedOut) return { status: 'partial', reason: '字节码分析超时；已保留可读报告', checkpoint };
    if (resource === 'decompile' && ['partial', 'unavailable', 'timeout'].includes(decompilation.state)) {
      return { status: 'partial', reason: decompilation.error || `Heimdall 状态为 ${decompilation.state}`, result: checkpoint, checkpoint };
    }
    if (resource === 'decompile' && !decompilerEvidenceComplete) {
      return { status: 'failed', error: decompilerArtifactErrors.join('; '), checkpoint };
    }
    if (!executionSucceeded) return { status: 'failed', error: `字节码分析进程退出状态 ${execution.exitCode ?? execution.signal}`, checkpoint };
    return { status: 'failed', error: `字节码分析进程退出状态 ${execution.exitCode}`, checkpoint };
  };
}

function makeCollectionHandler({ evidenceRoot, timeoutMs, rpcRequest = defaultCollectionRpcRequest, rpcAllowlist = [], maxCollectionBlocks = MAX_COLLECTION_BLOCKS }) {
  const allowlist = new Set(Array.isArray(rpcAllowlist) ? rpcAllowlist : rpcAllowlist instanceof Set ? [...rpcAllowlist] : []);
  return async (input, context) => {
    let config;
    try { config = collectionConfig(input, allowlist, maxCollectionBlocks); }
    catch (error) { return blocked(error instanceof Error ? error.message : String(error)); }
    const evidenceDirectory = taskDirectory(evidenceRoot, context.task.taskId);
    await mkdir(evidenceDirectory, { recursive: true });
    const configBytes = Buffer.from(JSON.stringify(config, null, 2) + '\n');
    const configHash = sha256(configBytes);
    const prior = context.lastCheckpoint && context.lastCheckpoint.configSha256 ? context.lastCheckpoint : null;
    if (prior && prior.configSha256 !== configHash) return blocked('采集配置与上次检查点不一致；任务未继续', prior);
    let attemptDirectory;
    let archiveRoot;
    if (prior) {
      if (typeof prior.attemptDirectory !== 'string' || typeof prior.archiveRoot !== 'string' || !isAbsolute(prior.attemptDirectory) || !isAbsolute(prior.archiveRoot)) {
        return blocked('上次采集检查点缺少有效的证据目录', prior);
      }
      const canonicalEvidence = await realpath(evidenceDirectory).catch(() => null);
      const requestedAttempt = resolve(prior.attemptDirectory), requestedArchive = resolve(prior.archiveRoot);
      const canonicalAttempt = await realpath(requestedAttempt).catch(() => null);
      const canonicalArchive = await realpath(requestedArchive).catch(() => null);
      if (!canonicalEvidence || !canonicalAttempt || !canonicalArchive ||
          !underRoot(canonicalAttempt, canonicalEvidence) || !underRoot(canonicalArchive, canonicalAttempt)) {
        return blocked('上次采集证据目录无效、越界或包含符号链接', prior);
      }
      const [attemptInfo, archiveInfo] = await Promise.all([lstat(requestedAttempt), lstat(requestedArchive)]);
      if (attemptInfo.isSymbolicLink() || archiveInfo.isSymbolicLink() || !attemptInfo.isDirectory() || !archiveInfo.isDirectory()) return blocked('上次采集证据目录不是普通目录', prior);
      // Preserve the checkpoint's stable spelling (for example macOS /var) so
      // retries do not rewrite artifact references to another path alias.
      attemptDirectory = requestedAttempt;
      archiveRoot = requestedArchive;
    } else {
      attemptDirectory = join(evidenceDirectory, `attempt-${context.task.attempts}-${randomUUID()}`);
      await mkdir(attemptDirectory, { recursive: false });
      archiveRoot = join(attemptDirectory, 'raw-archive');
    }
    const configPath = join(attemptDirectory, 'collection-config.json');
    if (prior) {
      const existingConfig = await readFile(configPath).catch(() => null);
      if (!existingConfig || sha256(existingConfig) !== configHash) return blocked('上次采集配置缺失或哈希不匹配；任务未继续', prior);
    } else {
      await writeFile(configPath, configBytes, { flag: 'wx', mode: 0o600 });
    }
    let nextBlock = prior?.nextBlock === undefined ? config.fromBlock : collectionBlock(prior.nextBlock, 'checkpoint.nextBlock');
    let lastBlock = prior?.lastBlock === undefined ? null : collectionBlock(prior.lastBlock, 'checkpoint.lastBlock');
    let lastBlockHash = prior?.lastBlockHash || null;
    let records = Array.isArray(prior?.records) ? prior.records : [];
    let collectedTransactionCount = records.reduce((count, record) => count + (Array.isArray(record.transactions) ? record.transactions.length : 0), 0);
    let archiveRefs = Array.isArray(prior?.archiveRefs) ? prior.archiveRefs : [];
    let blockAnchors = prior?.blockAnchors && typeof prior.blockAnchors === 'object' ? { ...prior.blockAnchors } : {};
    let archiveBytes = Number.isSafeInteger(prior?.rawArchiveBytes) && prior.rawArchiveBytes >= 0 ? prior.rawArchiveBytes : 0;
    let sequence = archiveRefs.length;
    let capabilities = prior?.capabilities && typeof prior.capabilities === 'object' && !Array.isArray(prior.capabilities)
      ? JSON.parse(JSON.stringify(prior.capabilities))
      : {
        schemaVersion: 1,
        toolVersion: 'resource-collection/1',
        observedAt: null,
        methods: {},
        transactions: { requested: config.includeTransactions, receipts: null, traces: null },
        storage: { requested: config.storageSlots.length > 0, slots: [] },
      };
    capabilities.transactions ??= { requested: config.includeTransactions, receipts: null, traces: null };
    capabilities.transactions.requested = config.includeTransactions;
    capabilities.transactions.receipts = config.includeReceipts
      ? (capabilities.transactions.receipts || capabilityMethod('eth_getTransactionReceipt', 'not_probed', { reason: 'no transaction has been sampled yet' }))
      : capabilityMethod('eth_getTransactionReceipt', 'not_requested', { reason: 'includeReceipts=false' });
    capabilities.transactions.traces = config.includeTraces
      ? (capabilities.transactions.traces || capabilityMethod('trace_transaction', 'not_probed', { alternatives: ['debug_traceTransaction'] }))
      : capabilityMethod('trace_transaction', 'not_requested', { reason: 'includeTraces=false', alternatives: ['debug_traceTransaction'] });
    capabilities.storage ??= { requested: config.storageSlots.length > 0, slots: [] };
    capabilities.storage.requested = config.storageSlots.length > 0;
    const checkpoint = async (phase, extra = {}) => {
      const value = {
        phase, attemptDirectory, archiveRoot, configSha256: configHash, fromBlock: config.fromBlock, toBlock: config.toBlock,
        nextBlock, lastBlock, lastBlockHash, blockCursor: { nextBlock, completedThrough: lastBlock },
        addressCursor: { address: config.address, index: config.address ? 1 : 0, total: config.address ? 1 : 0 },
        txCursor: extra.txCursor ?? { block: lastBlock, index: 0 }, blockAnchors, records, archiveRefs: archiveRefs.slice(-512),
        rawArchiveBytes: archiveBytes, sourceVerified: false, confirmedVulnerabilities: 0, capabilities, ...extra,
      };
      await context.checkpoint(value);
      return value;
    };
    const call = async (method, params, provenance = {}) => {
      if (!COLLECTION_RPC_METHODS.has(method)) throw errorWithCode('RPC method is not in the read-only allowlist', 'RPC_METHOD_BLOCKED');
      if (context.signal?.aborted) throw errorWithCode('collection aborted', 'COLLECTION_ABORTED');
      let response;
      try { response = await rpcRequest({ url: config.rpcUrl, method, params, signal: context.signal, timeoutMs: Math.min(15_000, timeoutMs) }); }
      catch (error) {
        if (error?.code) throw error;
        throw errorWithCode(`RPC 请求失败：${error instanceof Error ? error.message : String(error)}`, 'RPC_TRANSPORT', { retryable: true });
      }
      let value = response?.value;
      let raw = response?.raw;
      if (value === undefined && response && Object.hasOwn(response, 'result')) value = response.result;
      if (value === undefined && (typeof response !== 'object' || response === null || Array.isArray(response))) value = response;
      if (raw === undefined) raw = Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: 1, result: value }));
      if (typeof raw === 'string') raw = Buffer.from(raw);
      const derivedCodeHash = provenance.deriveCodeHash && typeof value === 'string' && /^0x(?:[0-9a-f]{2})*$/i.test(value)
        ? `0x${sha256(Buffer.from(value.slice(2), 'hex'))}` : provenance.codeHash ?? null;
      const ref = await archiveCollectionRaw({ archiveRoot, raw, kind: `rpc.${method}`, config,
        blockNumber: provenance.blockNumber ?? null, blockHash: provenance.blockHash ?? null,
        contractAddress: provenance.contractAddress ?? config.address, codeHash: derivedCodeHash,
        method, params, sequence: ++sequence });
      archiveBytes += ref.bytes;
      if (archiveBytes > MAX_COLLECTION_ARCHIVE_BYTES) throw errorWithCode('采集原始归档超过任务预算', 'ARCHIVE_BUDGET_EXCEEDED');
      archiveRefs.push(ref);
      return { value, ref };
    };
    const runSummary = (state, extra = {}) => ({ schemaVersion: 1, state, config, configSha256: configHash, attemptDirectory,
      rawArchive: { directory: archiveRoot, bytes: archiveBytes, references: archiveRefs.slice(-512) }, records,
      capabilities,
      limitations: ['固定只读 RPC 方法', '仅采集显式区块范围', '交易详情受 maxTransactions 上限约束', '区块哈希不一致时 fail-closed', '未执行交易、未确认漏洞'], ...extra });
    try {
      await checkpoint('collection_preparing', { artifacts: [{ path: configPath, kind: 'collection-config', bytes: configBytes.length, sha256: configHash }] });
      const probeBlockTag = blockTag(config.fromBlock);
      const probeAddress = config.address || ZERO_ADDRESS;
      const probeSpecs = [
        { key: 'eth_chainId', method: 'eth_chainId', params: [] },
        { key: 'eth_getBlockByNumber', method: 'eth_getBlockByNumber', params: [probeBlockTag, config.includeTransactions] },
        { key: 'eth_getCode', method: 'eth_getCode', params: [probeAddress, probeBlockTag], provenance: { contractAddress: config.address || null, deriveCodeHash: true } },
        { key: 'eth_getLogs', method: 'eth_getLogs', params: [{ fromBlock: probeBlockTag, toBlock: probeBlockTag, ...(config.address ? { address: config.address } : {}) }] },
      ];
      const probeResults = {};
      capabilities.observedAt = new Date().toISOString();
      for (const spec of probeSpecs) {
        try {
          const result = await call(spec.method, spec.params, { ...(spec.provenance || {}), blockNumber: config.fromBlock });
          if (spec.method === 'eth_chainId') {
            const chainValue = typeof result.value === 'string' && /^0x[0-9a-f]+$/i.test(result.value) ? Number(result.value) : Number(result.value);
            if (!Number.isSafeInteger(chainValue)) throw errorWithCode('RPC chainId result is invalid', 'RPC_INVALID_RESULT');
          } else if (spec.method === 'eth_getBlockByNumber') {
            validateCollectionBlock(result.value, config.fromBlock, 'capability probe block');
          } else if (spec.method === 'eth_getCode') {
            if (typeof result.value !== 'string' || !/^0x(?:[0-9a-f]{2})*$/i.test(result.value)) throw errorWithCode('RPC code result is invalid', 'RPC_INVALID_RESULT');
          } else if (!Array.isArray(result.value)) {
            throw errorWithCode('RPC logs result is invalid', 'RPC_INVALID_RESULT');
          }
          capabilities.methods[spec.key] = capabilityMethod(spec.method, 'available', { blockNumber: config.fromBlock });
          probeResults[spec.key] = result;
        } catch (error) {
          if (error?.code === 'ARCHIVE_BUDGET_EXCEEDED' || error?.code === 'RPC_RESPONSE_TOO_LARGE' || error?.code === 'COLLECTION_ABORTED') throw error;
          const failure = capabilityFailure(error);
          capabilities.methods[spec.key] = capabilityMethod(spec.method, failure.state, { reason: failure.reason, blockNumber: config.fromBlock });
        }
      }
      if (config.storageSlots.length) capabilities.storage.slots = config.storageSlots.map((slot) => capabilityMethod('eth_getStorageAt', 'not_probed', { slot }));
      await checkpoint('capabilities_probed', { capabilityProbe: { methods: probeSpecs.map(({ key }) => key), observedAt: capabilities.observedAt } });
      const chain = probeResults.eth_chainId || await call('eth_chainId', []);
      const observedChainId = typeof chain.value === 'string' && /^0x[0-9a-f]+$/i.test(chain.value) ? Number(chain.value) : Number(chain.value);
      if (!Number.isSafeInteger(observedChainId) || observedChainId !== config.chainId) return blocked(`RPC chainId ${String(chain.value)} 与任务 chainId ${config.chainId} 不一致`);
      if (lastBlock !== null && lastBlockHash) {
        const previous = await call('eth_getBlockByNumber', [blockTag(lastBlock), config.includeTransactions], { blockNumber: lastBlock });
        const previousBlock = validateCollectionBlock(previous.value, lastBlock, 'checkpoint block');
        if (previousBlock.hash !== String(lastBlockHash).toLowerCase()) {
          const reorg = runSummary('reorg_detected', { expectedBlockHash: lastBlockHash, observedBlockHash: previousBlock.hash, reorgAtBlock: lastBlock });
          const reportPath = join(attemptDirectory, 'reorg-report.json');
          await writeFile(reportPath, JSON.stringify(reorg, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
          return { status: 'blocked', reason: `检测到区块 ${lastBlock} 哈希变化，已 fail-closed`, result: reorg,
            checkpoint: { ...(context.lastCheckpoint || {}), ...reorg, phase: 'reorg_detected', rawArchiveBytes: archiveBytes, archiveRefs: archiveRefs.slice(-512), artifacts: [{ path: reportPath, kind: 'reorg-report', bytes: Buffer.byteLength(JSON.stringify(reorg, null, 2) + '\n'), sha256: sha256(Buffer.from(JSON.stringify(reorg, null, 2) + '\n')) }, ...archiveRefs.map((ref) => ({ path: ref.path, kind: ref.kind, bytes: ref.bytes, sha256: ref.sha256 }))] } };
        }
      }
      await checkpoint('collecting', { chainIdObserved: observedChainId });
      for (; nextBlock <= config.toBlock; nextBlock += 1) {
        const tag = blockTag(nextBlock);
        const blockResult = await call('eth_getBlockByNumber', [tag, config.includeTransactions], { blockNumber: nextBlock });
        const block = validateCollectionBlock(blockResult.value, nextBlock, `block ${nextBlock}`);
        const expected = blockAnchors[nextBlock];
        if (expected && String(expected).toLowerCase() !== block.hash) {
          const reorg = runSummary('reorg_detected', { expectedBlockHash: expected, observedBlockHash: block.hash, reorgAtBlock: nextBlock });
          const reportPath = join(attemptDirectory, 'reorg-report.json');
          const reportBytes = Buffer.from(JSON.stringify(reorg, null, 2) + '\n');
          await writeFile(reportPath, reportBytes, { flag: 'wx', mode: 0o600 });
          return { status: 'blocked', reason: `检测到区块 ${nextBlock} 哈希变化，已 fail-closed`, result: reorg,
            checkpoint: { ...(context.lastCheckpoint || {}), ...reorg, phase: 'reorg_detected', rawArchiveBytes: archiveBytes, archiveRefs: archiveRefs.slice(-512), artifacts: [{ path: reportPath, kind: 'reorg-report', bytes: reportBytes.length, sha256: sha256(reportBytes) }, ...archiveRefs.map((ref) => ({ path: ref.path, kind: ref.kind, bytes: ref.bytes, sha256: ref.sha256 }))] } };
        }
        blockAnchors[nextBlock] = block.hash;
        let code = null, codeArchive = null, logsCount = null;
        if (config.address) {
          const codeResult = await call('eth_getCode', [config.address, tag], { blockNumber: nextBlock, blockHash: block.hash, contractAddress: config.address, deriveCodeHash: true });
          if (typeof codeResult.value !== 'string' || !/^0x(?:[0-9a-f]{2})*$/i.test(codeResult.value)) throw errorWithCode(`block ${nextBlock} 的 code 结果无效`, 'RPC_INVALID_RESULT');
          code = codeResult.value.toLowerCase();
          codeArchive = codeResult.ref;
        }
        if (config.includeLogs) {
          const filter = { fromBlock: tag, toBlock: tag, ...(config.address ? { address: config.address } : {}) };
          const logsResult = await call('eth_getLogs', [filter], { blockNumber: nextBlock, blockHash: block.hash, contractAddress: config.address });
          if (!Array.isArray(logsResult.value)) throw errorWithCode(`block ${nextBlock} 的 logs 结果无效`, 'RPC_INVALID_RESULT');
          logsCount = logsResult.value.length;
        }
        const blockTransactions = Array.isArray(block.transactions) ? block.transactions : [];
        const txCount = Array.isArray(block.transactions) ? block.transactions.length : null;
        const txEvidence = [];
        for (let txIndex = 0; txIndex < blockTransactions.length && collectedTransactionCount + txEvidence.length < config.maxTransactions; txIndex += 1) {
          const tx = blockTransactions[txIndex];
          const txHash = typeof tx === 'string' ? tx : tx?.hash;
          if (typeof txHash !== 'string' || !/^0x[0-9a-f]{64}$/i.test(txHash)) continue;
          const row = normalizeTransaction(tx, { hash: txHash, index: txIndex, block });
          if (config.includeReceipts) {
            try {
              const receiptResult = await call('eth_getTransactionReceipt', [row.transactionHash], { blockNumber: nextBlock, blockHash: block.hash, contractAddress: config.address });
              const receipt = receiptResult.value;
              if (receipt === null) {
                row.receipt = { state: 'unavailable', reason: 'receipt not available for this transaction' };
                capabilities.transactions.receipts = capabilityMethod('eth_getTransactionReceipt', 'available', { reason: 'RPC responded with null for at least one transaction' });
              } else {
                if (!receipt || typeof receipt !== 'object' || String(receipt.transactionHash || '').toLowerCase() !== row.transactionHash || String(receipt.blockHash || '').toLowerCase() !== block.hash || (receipt.blockNumber !== undefined && collectionBlock(receipt.blockNumber, 'receipt.blockNumber') !== nextBlock)) throw errorWithCode('receipt 与交易/区块锚点不一致', 'RPC_INVALID_RESULT');
                row.receipt = { state: 'available', value: receipt, contentHash: receiptResult.ref.contentHash, archivePath: receiptResult.ref.path };
                capabilities.transactions.receipts = capabilityMethod('eth_getTransactionReceipt', 'available');
              }
            } catch (error) {
              propagateCollectionFatal(error);
              const failure = capabilityFailure(error);
              row.receipt = { state: failure.state === 'unsupported' ? 'unavailable' : failure.state, reason: failure.reason };
              capabilities.transactions.receipts = capabilityMethod('eth_getTransactionReceipt', failure.state, { reason: failure.reason });
            }
          }
          if (config.includeTraces) {
            let traceResult = null, traceMethod = null, traceError = null;
            for (const method of ['debug_traceTransaction', 'trace_transaction']) {
              try {
                const params = method === 'debug_traceTransaction' ? [row.transactionHash, {}] : [row.transactionHash];
                const result = await call(method, params, { blockNumber: nextBlock, blockHash: block.hash, contractAddress: config.address });
                if (!result.value || typeof result.value !== 'object') throw errorWithCode('trace RPC result is invalid', 'RPC_INVALID_RESULT');
                traceResult = result; traceMethod = method; break;
              } catch (error) {
                propagateCollectionFatal(error);
                traceError = error;
                if (error?.code !== 'RPC_UNSUPPORTED') break;
              }
            }
            if (traceResult) {
              const traceHash = sha256(Buffer.from(canonicalJson(traceResult.value)));
              row.trace = { state: 'available', method: traceMethod, hash: traceHash, contentHash: traceResult.ref.contentHash, archivePath: traceResult.ref.path, value: traceResult.value };
              capabilities.transactions.traces = capabilityMethod(traceMethod, 'available', { alternatives: [traceMethod === 'debug_traceTransaction' ? 'trace_transaction' : 'debug_traceTransaction'] });
            } else {
              const failure = capabilityFailure(traceError);
              row.trace = { state: failure.state === 'unsupported' ? 'unavailable' : failure.state, reason: failure.reason };
              capabilities.transactions.traces = capabilityMethod('debug_traceTransaction', failure.state, { reason: failure.reason, alternatives: ['trace_transaction'] });
            }
          }
          txEvidence.push(row);
        }
        collectedTransactionCount += txEvidence.length;
        const storage = [];
        for (const slot of config.storageSlots) {
          try {
            const result = await call('eth_getStorageAt', [config.address, slot, tag], { blockNumber: nextBlock, blockHash: block.hash, contractAddress: config.address });
            if (typeof result.value !== 'string' || !/^0x[0-9a-f]{64}$/i.test(result.value)) throw errorWithCode('storage RPC result is invalid', 'RPC_INVALID_RESULT');
            storage.push({ slot, value: result.value.toLowerCase(), contentHash: result.ref.contentHash, archivePath: result.ref.path });
            const capability = capabilities.storage.slots.find((item) => item.slot === slot);
            if (capability) Object.assign(capability, capabilityMethod('eth_getStorageAt', 'available', { slot }));
          } catch (error) {
            propagateCollectionFatal(error);
            const failure = capabilityFailure(error);
            storage.push({ slot, state: failure.state, reason: failure.reason });
            const capability = capabilities.storage.slots.find((item) => item.slot === slot);
            if (capability) Object.assign(capability, capabilityMethod('eth_getStorageAt', failure.state, { slot, reason: failure.reason }));
          }
        }
        records.push(normalizedCollectionRecord({ config, block, address: config.address, code, blockArchive: blockResult.ref, codeArchive, logsCount, transactionsCount: txCount, transactions: txEvidence, storage, capabilities }));
        lastBlock = nextBlock; lastBlockHash = block.hash; nextBlock += 1;
        await checkpoint(nextBlock > config.toBlock ? 'finalizing' : 'collecting', { txCursor: { block: lastBlock, index: txCount ?? 0 } });
        nextBlock -= 1;
      }
      const report = runSummary('completed', { complete: true, completedThrough: lastBlock, sourceVerified: false, confirmedVulnerabilities: 0 });
      const reportBytes = Buffer.from(JSON.stringify(report, null, 2) + '\n');
      const reportPath = join(attemptDirectory, 'collection-report.json');
      await writeFile(reportPath, reportBytes, { flag: 'wx', mode: 0o600 });
      const artifacts = [{ path: configPath, kind: 'collection-config', bytes: configBytes.length, sha256: configHash },
        { path: reportPath, kind: 'collection-report', bytes: reportBytes.length, sha256: sha256(reportBytes) },
        ...archiveRefs.map((ref) => ({ path: ref.path, kind: ref.kind, bytes: ref.bytes, sha256: ref.sha256 }))];
      const finalCheckpoint = await checkpoint('evidence_ready', { complete: true, reportPath, artifacts, reportSha256: sha256(reportBytes), reportBytes: reportBytes.length });
      return { status: 'succeeded', result: report, checkpoint: finalCheckpoint };
    } catch (error) {
      const checkpointValue = context.lastCheckpoint;
      if (error?.code === 'COLLECTION_ABORTED' || context.signal?.aborted) return { status: 'failed', reason: '采集任务已中止', checkpoint: checkpointValue };
      if (error?.code === 'RPC_UNSUPPORTED') return { status: 'partial', reason: `RPC 不支持采集方法：${error.rpcCode ?? ''}`.trim(), checkpoint: checkpointValue };
      if (error?.code === 'RPC_TRANSPORT' || error?.retryable || ['RPC_TIMEOUT', 'RPC_RATE_LIMITED', 'RPC_HTTP_ERROR'].includes(error?.code)) {
        return { status: 'failed', error: error.message, retryable: true, checkpoint: checkpointValue };
      }
      if (error?.code === 'ARCHIVE_BUDGET_EXCEEDED' || error?.code === 'RPC_RESPONSE_TOO_LARGE') {
        return { status: 'partial', reason: error.message, checkpoint: checkpointValue };
      }
      return { status: 'failed', error: error instanceof Error ? error.message : String(error), checkpoint: checkpointValue };
    }
  };
}

export function createResourceTaskHandlers({ root = ROOT, evidenceRoot = DEFAULT_EVIDENCE_ROOT, artifactRoots = [join(root, 'work'), join(root, 'flare-scan', 'reports'), join(root, 'flare-scan', 'contracts')], timeoutMs = 300_000, spawnProcess = spawn, rpcRequest = defaultCollectionRpcRequest, rpcAllowlist = [], maxCollectionBlocks = MAX_COLLECTION_BLOCKS, taskStore = null } = {}) {
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 900_000) throw new RangeError('resource task timeout must be 100..900000 ms');
  const configuredRoots = artifactRoots.map((path) => resolve(path));
  const initRoots = roots(configuredRoots);
  const wrap = (resource, handler) => async (payload, context) => {
    if (context.task.type !== RESOURCE_TASK_PREFIX + resource || payload?.resource !== resource) return blocked('任务资源类型与 handler 不匹配');
    const allowedRoots = await initRoots;
    return handler(payload.input, context, allowedRoots);
  };
  return {
    [RESOURCE_TASK_PREFIX + 'projects']: wrap('projects', (input, context, allowedRoots) => makeProjectHandler({ root, evidenceRoot, allowedRoots, timeoutMs, spawnProcess })(input, context)),
    [RESOURCE_TASK_PREFIX + 'contracts']: wrap('contracts', (input, context, allowedRoots) => makeContractsHandler({ taskStore, evidenceRoot })(input, context, allowedRoots)),
    [RESOURCE_TASK_PREFIX + 'collection']: wrap('collection', (input, context) => makeCollectionHandler({ evidenceRoot, timeoutMs, rpcRequest, rpcAllowlist, maxCollectionBlocks })(input, context)),
    [RESOURCE_TASK_PREFIX + 'bytecode']: wrap('bytecode', (input, context, allowedRoots) => makeBytecodeHandler({ resource: 'bytecode', root, evidenceRoot, allowedRoots, timeoutMs, spawnProcess, taskStore })(input, context)),
    [RESOURCE_TASK_PREFIX + 'decompile']: wrap('decompile', (input, context, allowedRoots) => makeBytecodeHandler({ resource: 'decompile', root, evidenceRoot, allowedRoots, timeoutMs, spawnProcess, taskStore })(input, context)),
  };
}
