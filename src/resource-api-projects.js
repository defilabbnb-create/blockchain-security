import { createHash, randomUUID } from 'node:crypto';
import { lstat, readFile, realpath } from 'node:fs/promises';
import { isAbsolute, relative, resolve } from 'node:path';

export const RESOURCE_API_VERSION = 'v1';
export const RESOURCE_API_SCHEMA_VERSION = 1;
export const MAX_RESOURCE_ARTIFACT_BYTES = 64 * 1024 * 1024;
export const RESOURCE_NAMES = Object.freeze(['projects', 'contracts', 'collection', 'bytecode', 'decompile']);

const PATH_KEYS = new Set([
  'artifactPath', 'manifestPath', 'reportPath', 'bytecodePath', 'decompilationPath',
  'outputPath', 'evidencePath', 'archivePath',
]);
const SHA256 = /^[0-9a-f]{64}$/i;
const HEX_BYTECODE = /^0x(?:[0-9a-f]{2})+$/i;

export class ResourceApiError extends Error {
  constructor(code, message, status = 400, details = undefined) {
    super(message);
    this.name = 'ResourceApiError';
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

function fail(code, message, status = 400, details) {
  throw new ResourceApiError(code, message, status, details);
}

function text(value, name, { max = 300, optional = false } = {}) {
  if (value === undefined && optional) return undefined;
  if (typeof value !== 'string' || value.length < 1 || value.length > max || !value.trim()) {
    fail('invalid_field', `${name} 必须是 1-${max} 个字符`);
  }
  return value.trim();
}

function integer(value, name, { min = 0, max = Number.MAX_SAFE_INTEGER, optional = false } = {}) {
  if (value === undefined && optional) return undefined;
  if (!Number.isSafeInteger(value) || value < min || value > max) fail('invalid_field', `${name} 必须是 ${min}..${max} 的整数`);
  return value;
}

function collectionQuantity(value, name, { min = 0 } = {}) {
  if (typeof value !== 'string' || !/^(?:0x[0-9a-f]+|[0-9]+)$/i.test(value)) {
    fail('invalid_field', `${name} 必须是十进制或十六进制区块号`);
  }
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < min) fail('invalid_field', `${name} 超出允许范围`);
  return number;
}

function validateCollectionEndpoint(value) {
  let parsed;
  try { parsed = new URL(value); } catch { fail('invalid_field', 'rpcUrl 不是有效 URL'); }
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password || parsed.search || parsed.hash) {
    fail('invalid_field', 'rpcUrl 只允许无凭据的 HTTP(S) endpoint');
  }
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname) || parsed.hostname === '::1';
  if (parsed.protocol === 'http:' && !local) fail('invalid_field', '非本机 RPC 必须使用 HTTPS');
}

function bodyObject(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) fail('invalid_request', '请求体必须是 JSON 对象');
  return body;
}

function unknownFields(body, allowed) {
  const unknown = Object.keys(body).filter((key) => !allowed.includes(key));
  if (unknown.length) fail('unknown_field', `请求包含未知字段：${unknown.join(', ')}`);
}

function resourceFromPath(pathname) {
  const match = String(pathname || '').match(/^\/api\/v1\/(projects|contracts|collection|collections|bytecode|decompile|decompilations)(?:\/([^/]+))?\/?$/);
  if (!match) return null;
  const resource = match[1] === 'collections' ? 'collection' : match[1] === 'decompilations' ? 'decompile' : match[1];
  let id = null;
  if (match[2]) {
    try { id = decodeURIComponent(match[2]); } catch { fail('invalid_id', '资源 ID 编码无效'); }
    text(id, 'id', { max: 200 });
  }
  return { resource, id };
}

function parseQuery(searchParams) {
  const params = searchParams instanceof URLSearchParams ? searchParams : new URLSearchParams(searchParams || '');
  const allowed = new Set(['limit', 'cursor', 'projectId', 'chainId', 'address', 'state']);
  for (const key of new Set(params.keys())) {
    if (!allowed.has(key)) fail('unknown_query_parameter', `不支持的查询参数：${key}`);
    if (params.getAll(key).length > 1) fail('duplicate_query_parameter', `查询参数重复：${key}`);
  }
  const rawLimit = params.get('limit');
  const limit = rawLimit === null ? 100 : integer(Number(rawLimit), 'limit', { min: 1, max: 1000 });
  if (rawLimit !== null && !/^\d+$/.test(rawLimit)) fail('invalid_limit', 'limit 必须是 1..1000 的整数');
  const result = { limit };
  for (const key of ['cursor', 'projectId', 'chainId', 'address', 'state']) {
    const value = params.get(key);
    if (value !== null) result[key] = text(value, key, { max: 512 });
  }
  return result;
}

function hashBuffer(buffer) {
  return createHash('sha256').update(buffer).digest('hex');
}

function underRoot(candidate, root) {
  const rel = relative(root, candidate);
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${requirePathSeparator()}`) && !isAbsolute(rel));
}

function requirePathSeparator() {
  // Both separators are rejected so records remain portable across hosts.
  return '/';
}

async function configuredRoot(root) {
  if (typeof root !== 'string' || !root.trim()) fail('invalid_root', 'artifact root 必须是非空路径', 500);
  try { return await realpath(resolve(root)); }
  catch (error) { fail('artifact_root_unavailable', `artifact root 不可读取：${error.code || 'error'}`, 503); }
}

async function verifyArtifact(descriptor, roots, maxBytes) {
  const item = typeof descriptor === 'string' ? { path: descriptor } : descriptor;
  if (!item || typeof item !== 'object' || Array.isArray(item)) fail('invalid_artifact', 'artifact 描述必须是对象');
  const pathValue = text(item.path, 'artifact.path', { max: 2000 });
  const expectedHash = item.sha256 === undefined ? undefined : text(item.sha256, 'artifact.sha256', { max: 64 });
  if (expectedHash !== undefined && !SHA256.test(expectedHash)) fail('invalid_artifact', 'artifact.sha256 必须是 SHA-256');
  const expectedBytes = item.bytes === undefined ? undefined : integer(item.bytes, 'artifact.bytes', { min: 0, max: maxBytes });
  const absolute = resolve(pathValue);
  let canonical;
  try { canonical = await realpath(absolute); }
  catch (error) { fail('artifact_unavailable', `artifact 不可读取：${error.code || 'error'}`, 409); }
  if (!roots.some((root) => underRoot(canonical, root))) fail('artifact_path_forbidden', 'artifact 路径不在允许的根目录内', 403);
  let info;
  try { info = await lstat(canonical); }
  catch (error) { fail('artifact_unavailable', `artifact stat 失败：${error.code || 'error'}`, 409); }
  if (!info.isFile()) fail('artifact_invalid_type', 'artifact 必须是普通文件', 409);
  if (info.size > maxBytes) fail('artifact_too_large', `artifact 超过 ${maxBytes} 字节限制`, 413);
  if (expectedBytes !== undefined && info.size !== expectedBytes) fail('artifact_integrity_mismatch', 'artifact 大小与记录不匹配', 409);
  let content;
  try { content = await readFile(canonical); }
  catch (error) { fail('artifact_unavailable', `artifact 读取失败：${error.code || 'error'}`, 409); }
  const sha256 = hashBuffer(content);
  if (expectedHash !== undefined && sha256.toLowerCase() !== expectedHash.toLowerCase()) fail('artifact_integrity_mismatch', 'artifact SHA-256 与记录不匹配', 409);
  return { path: canonical, bytes: content.length, sha256, ...(item.kind === undefined ? {} : { kind: item.kind }) };
}

function artifactDescriptors(record) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) fail('invalid_record', '持久化资源记录必须是对象', 500);
  const descriptors = [];
  if (Array.isArray(record.artifacts)) descriptors.push(...record.artifacts);
  for (const key of PATH_KEYS) if (record[key] !== undefined) {
    descriptors.push({ path: record[key], sha256: record[`${key.replace(/Path$/, '')}Sha256`] ?? record.sha256, bytes: record[`${key.replace(/Path$/, '')}Bytes`] ?? record.bytes });
  }
  return descriptors;
}

async function verifyRecord(record, roots, maxBytes) {
  const artifacts = [];
  for (const descriptor of artifactDescriptors(record)) artifacts.push(await verifyArtifact(descriptor, roots, maxBytes));
  return artifacts.length ? { ...record, artifacts } : { ...record };
}

async function validateCreatePaths(input, roots) {
  const existing = ['sourcePath', 'inputPath', 'bytecodePath'];
  for (const key of existing) {
    if (input[key] === undefined) continue;
    const candidate = resolve(input[key]);
    let canonical;
    try { canonical = await realpath(candidate); }
    catch (error) { fail('input_path_unavailable', `${key} 不可读取：${error.code || 'error'}`, 409); }
    if (!roots.some((root) => underRoot(canonical, root))) fail('input_path_forbidden', `${key} 不在允许的根目录内`, 403);
    let info;
    try { info = await lstat(canonical); } catch (error) { fail('input_path_unavailable', `${key} stat 失败：${error.code || 'error'}`, 409); }
    if (key === 'sourcePath' ? !info.isDirectory() : !info.isFile()) fail('input_path_invalid_type', `${key} 类型不正确`, 409);
    if (info.isFile() && info.size > MAX_RESOURCE_ARTIFACT_BYTES) fail('artifact_too_large', `${key} 超过 ${MAX_RESOURCE_ARTIFACT_BYTES} 字节限制`, 413);
  }
  // Output paths may be created by a worker later; validate their existing
  // parent without reading or creating anything here.
  for (const key of ['outputPath', 'archiveRoot']) {
    if (input[key] === undefined) continue;
    const candidate = resolve(input[key]);
    let parent;
    try { parent = await realpath(candidate); }
    catch {
      try { parent = await realpath(resolve(candidate, '..')); }
      catch (error) { fail('output_path_unavailable', `${key} 父目录不可读取：${error.code || 'error'}`, 409); }
    }
    if (!roots.some((root) => underRoot(parent, root))) fail('output_path_forbidden', `${key} 不在允许的根目录内`, 403);
  }
}

function validateBytecodeRecord(record) {
  if (!record || typeof record !== 'object') fail('invalid_record', 'bytecode 记录无效', 500);
  const runtime = record.runtimeBytecode;
  if (runtime !== undefined && (typeof runtime !== 'string' || !HEX_BYTECODE.test(runtime))) fail('invalid_bytecode', 'runtimeBytecode 格式无效', 409);
  if (runtime !== undefined) {
    const bytes = (runtime.length - 2) / 2;
    if (bytes > 131072) fail('artifact_too_large', 'runtimeBytecode 超过 131072 字节限制', 413);
    const actualHash = hashBuffer(Buffer.from(runtime.slice(2), 'hex'));
    if (record.bytecodeBytes !== undefined && record.bytecodeBytes !== bytes) fail('artifact_integrity_mismatch', 'bytecodeBytes 与 runtimeBytecode 不匹配', 409);
    if (record.bytecodeSha256 !== undefined && String(record.bytecodeSha256).toLowerCase() !== actualHash) fail('artifact_integrity_mismatch', 'bytecodeSha256 与 runtimeBytecode 不匹配', 409);
  }
}

const POST_FIELDS = Object.freeze({
  projects: ['projectId', 'sourcePath', 'outputPath', 'archiveRoot', 'maxFileBytes', 'maxTotalBytes', 'maxFiles', 'metadata'],
  contracts: ['projectId', 'contractId', 'chainId', 'address', 'bytecodePath', 'metadata'],
  collection: ['projectId', 'sourcePath', 'chainId', 'address', 'block', 'fromBlock', 'toBlock', 'rpcUrl', 'maxBlocks', 'includeTransactions', 'includeLogs', 'includeReceipts', 'includeTraces', 'storageSlots', 'maxTransactions', 'metadata'],
  bytecode: ['projectId', 'contractId', 'inputPath', 'runtimeBytecode', 'chainId', 'address', 'block', 'hardfork', 'metadata'],
  decompile: ['projectId', 'contractId', 'bytecodePath', 'runtimeBytecode', 'binary', 'outputPath', 'timeoutSeconds', 'hardfork', 'metadata'],
});

function validateCreateInput(resource, input) {
  unknownFields(input, POST_FIELDS[resource]);
  if (resource === 'projects') text(input.sourcePath, 'sourcePath');
  if (resource === 'contracts') {
    for (const key of ['projectId', 'contractId', 'chainId', 'address']) {
      if (input[key] === undefined) fail('missing_field', `contracts 需要 ${key}`);
    }
    collectionQuantity(input.chainId, 'chainId', { min: 1 });
    if (Number(input.chainId) > 2_147_483_647) fail('invalid_field', 'chainId 超出允许范围');
    if (typeof input.address !== 'string' || !/^0x[0-9a-f]{40}$/i.test(input.address)) {
      fail('invalid_field', 'address 必须是 20 字节十六进制地址');
    }
  }
  if (resource === 'collection') {
    if (!input.projectId && !input.sourcePath) fail('missing_field', 'collection 需要 projectId 或 sourcePath');
    if (input.chainId === undefined) fail('missing_field', 'collection 需要 chainId');
    if (input.rpcUrl === undefined) fail('missing_field', 'collection 需要 rpcUrl');
    if (input.block === undefined && input.fromBlock === undefined) fail('missing_field', 'collection 需要 block 或 fromBlock');
    collectionQuantity(input.chainId, 'chainId', { min: 1 });
    validateCollectionEndpoint(input.rpcUrl);
    const fromBlock = input.fromBlock === undefined ? collectionQuantity(input.block, 'block') : collectionQuantity(input.fromBlock, 'fromBlock');
    const toBlock = input.toBlock === undefined ? fromBlock : collectionQuantity(input.toBlock, 'toBlock');
    if (toBlock < fromBlock) fail('invalid_field', 'toBlock 不能小于 fromBlock');
    const maxBlocks = input.maxBlocks === undefined ? 128 : input.maxBlocks;
    if (!Number.isSafeInteger(maxBlocks) || maxBlocks < 1 || maxBlocks > 128) fail('invalid_field', 'maxBlocks 必须是 1..128 的整数');
    if (toBlock - fromBlock + 1 > maxBlocks) fail('invalid_field', '区块范围超过 maxBlocks 限制');
    if (input.address !== undefined && (typeof input.address !== 'string' || !/^0x[0-9a-f]{40}$/i.test(input.address))) {
      fail('invalid_field', 'address 必须是 20 字节十六进制地址');
    }
    if (input.storageSlots?.length && !input.address) fail('missing_field', '读取 storageSlots 需要 address');
    if ((input.includeReceipts || input.includeTraces) && input.includeTransactions !== true) fail('invalid_field', '采集 receipt/trace 需要 includeTransactions=true');
  }
  if ((resource === 'bytecode' || resource === 'decompile') && input.contractId !== undefined) {
    const explicitInput = resource === 'bytecode' ? input.inputPath || input.runtimeBytecode : input.bytecodePath || input.runtimeBytecode;
    if (explicitInput) fail('invalid_field', `${resource} 使用 contractId 时不能同时提交显式字节码输入`);
    for (const key of ['projectId', 'chainId', 'address', 'block']) {
      if (input[key] === undefined) fail('missing_field', `${resource} 使用 contractId 时需要 ${key}`);
    }
    collectionQuantity(input.chainId, 'chainId', { min: 1 });
    if (Number(input.chainId) > 2_147_483_647) fail('invalid_field', 'chainId 超出允许范围');
    collectionQuantity(input.block, 'block');
    if (typeof input.address !== 'string' || !/^0x[0-9a-f]{40}$/i.test(input.address)) {
      fail('invalid_field', 'address 必须是 20 字节十六进制地址');
    }
  }
  if (resource === 'bytecode' && !input.inputPath && !input.runtimeBytecode && !input.contractId) fail('missing_field', 'bytecode 需要 inputPath、runtimeBytecode 或 contractId');
  if (resource === 'decompile' && !input.bytecodePath && !input.runtimeBytecode && !input.contractId) fail('missing_field', 'decompile 需要 bytecodePath、runtimeBytecode 或 contractId');
  for (const key of ['projectId', 'contractId', 'sourcePath', 'outputPath', 'archiveRoot', 'inputPath', 'bytecodePath', 'binary', 'chainId', 'address', 'block', 'fromBlock', 'toBlock', 'rpcUrl', 'hardfork']) {
    if (input[key] !== undefined) text(input[key], key, { max: 2000 });
  }
  for (const key of ['maxFileBytes', 'maxTotalBytes', 'maxFiles']) if (input[key] !== undefined) integer(input[key], key, { min: 1, max: 256 * 1024 * 1024 });
  if (input.maxBlocks !== undefined) integer(input.maxBlocks, 'maxBlocks', { min: 1, max: 128 });
  for (const key of ['includeTransactions', 'includeLogs', 'includeReceipts', 'includeTraces']) if (input[key] !== undefined && typeof input[key] !== 'boolean') fail('invalid_field', `${key} 必须是布尔值`);
  if (input.storageSlots !== undefined && (!Array.isArray(input.storageSlots) || input.storageSlots.length > 64 || input.storageSlots.some((slot) => typeof slot !== 'string' || !/^0x[0-9a-f]{64}$/i.test(slot)))) fail('invalid_field', 'storageSlots 必须是最多 64 个 32 字节十六进制槽位');
  if (input.maxTransactions !== undefined) integer(input.maxTransactions, 'maxTransactions', { min: 1, max: 256 });
  if (input.runtimeBytecode !== undefined && !HEX_BYTECODE.test(input.runtimeBytecode)) fail('invalid_bytecode', 'runtimeBytecode 格式无效');
  if (input.runtimeBytecode !== undefined && (input.runtimeBytecode.length - 2) / 2 > 131072) fail('artifact_too_large', 'runtimeBytecode 超过 131072 字节限制', 413);
  if (input.metadata !== undefined && (typeof input.metadata !== 'object' || Array.isArray(input.metadata))) fail('invalid_field', 'metadata 必须是 JSON 对象');
  return input;
}

async function storeList(store, resource, query) {
  if (typeof store.listResources === 'function') return store.listResources(resource, query);
  if (typeof store.list === 'function') return store.list(resource, query);
  fail('store_unavailable', '资源持久化 store 未提供 listResources(resource, query)', 503);
}

async function storeGet(store, resource, id) {
  if (typeof store.getResource === 'function') return store.getResource(resource, id);
  if (typeof store.get === 'function') return store.get(resource, id);
  fail('store_unavailable', '资源持久化 store 未提供 getResource(resource, id)', 503);
}

async function storeCreate(store, resource, payload) {
  if (typeof store.createTask === 'function') return store.createTask({ resource, payload, audit: { requestId: payload.requestId, at: payload.createdAt } });
  if (typeof store.createResourceTask === 'function') return store.createResourceTask(resource, payload);
  fail('store_unavailable', '资源持久化 store 未提供 createTask({ resource, payload })', 503);
}

export const RESOURCE_STORE_CONTRACT = Object.freeze({
  listResources: 'async (resource, query) => records[] | {items, nextCursor, revision}',
  getResource: 'async (resource, id) => record | null',
  createTask: 'async ({resource, payload, audit}) => persisted task record',
  integrity: 'Records reference generated artifacts with path, sha256, and bytes; handlers verify all three before returning data.',
});

export function createResourceApiV1({ store, artifactRoots = [], maxArtifactBytes = MAX_RESOURCE_ARTIFACT_BYTES, clock = () => new Date() } = {}) {
  if (!store) fail('store_unavailable', '资源 API 需要注入持久化 store', 503);
  if (!Array.isArray(artifactRoots) || artifactRoots.length === 0) fail('invalid_root', '资源 API 需要至少一个 artifact root', 500);
  if (!Number.isSafeInteger(maxArtifactBytes) || maxArtifactBytes < 1 || maxArtifactBytes > MAX_RESOURCE_ARTIFACT_BYTES) fail('invalid_limit', `maxArtifactBytes 必须是 1..${MAX_RESOURCE_ARTIFACT_BYTES}`, 500);
  const rootsPromise = Promise.all(artifactRoots.map(configuredRoot));
  return async function handleResourceApiV1({ method = 'GET', pathname, searchParams, body, requestId = randomUUID() } = {}) {
    const route = resourceFromPath(pathname);
    if (!route) return null;
    const generatedAt = clock().toISOString();
    const envelope = (data) => ({ apiVersion: RESOURCE_API_VERSION, schemaVersion: RESOURCE_API_SCHEMA_VERSION, generatedAt, requestId, ...data });
    try {
      const roots = await rootsPromise;
      if (method === 'GET') {
        const query = parseQuery(searchParams);
        if (route.id) {
          const record = await storeGet(store, route.resource, route.id);
          if (!record) fail('not_found', `${route.resource} 资源不存在`, 404);
          const verified = await verifyRecord(route.resource === 'bytecode' ? (validateBytecodeRecord(record), record) : record, roots, maxArtifactBytes);
          return { status: 200, body: envelope({ data: verified }) };
        }
        const result = await storeList(store, route.resource, query);
        const rows = Array.isArray(result) ? result : result?.items;
        if (!Array.isArray(rows)) fail('store_invalid_response', '资源 store list 必须返回数组或 {items}', 500);
        const items = [];
        for (const row of rows) items.push(await verifyRecord(route.resource === 'bytecode' ? (validateBytecodeRecord(row), row) : row, roots, maxArtifactBytes));
        return { status: 200, body: envelope({ items, page: { limit: query.limit, hasMore: Array.isArray(result) ? false : result?.hasMore === true, nextCursor: Array.isArray(result) ? null : result?.nextCursor ?? null }, ...(Array.isArray(result) ? {} : { consistency: result?.revision === undefined ? undefined : { revision: result.revision, asOf: generatedAt } }) }) };
      }
      if (method !== 'POST') fail('method_not_allowed', '该资源只支持 GET 和 POST', 405);
      if (route.id) fail('method_not_allowed', '资源详情不支持 POST', 405);
      const input = validateCreateInput(route.resource, bodyObject(body));
      await validateCreatePaths(input, roots);
      const task = await storeCreate(store, route.resource, { ...input, requestId, createdAt: generatedAt });
      if (!task || typeof task !== 'object' || Array.isArray(task)) fail('store_invalid_response', '资源 store 未返回持久化任务', 500);
      return { status: 202, body: envelope({ data: task, accepted: true }) };
    } catch (error) {
      if (error instanceof ResourceApiError) return { status: error.status, body: envelope({ error: { code: error.code, message: error.message, ...(error.details === undefined ? {} : { details: error.details }) } }) };
      return { status: 500, body: envelope({ error: { code: 'internal_error', message: '资源接口处理失败' } }) };
    }
  };
}

export const resourceApiV1Route = createResourceApiV1;
export const createV1ResourceRouter = createResourceApiV1;
export const routeResourceApiV1 = createResourceApiV1;
export const createProjectsResourceApi = createResourceApiV1;
export const createResourceApiProjects = createResourceApiV1;
export default createResourceApiV1;

