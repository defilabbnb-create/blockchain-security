import { randomUUID } from 'node:crypto';
import { mkdir, open, readFile, rename, stat, unlink, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, resolve } from 'node:path';
import { FINDING_TRIAGE_STATUSES, normalizeFindingTriagePatch } from './finding-triage.js';

export const RESOURCE_API_VERSION = 'v1';
export const RESOURCE_SCHEMA_VERSION = 1;
export const DEFAULT_RESOURCE_LEASE_TTL_MS = 45_000;

const MAX_JSON_BYTES = 32 * 1024 * 1024;
const MAX_PAGE_SIZE = 1000;
const RESOURCE_KINDS = Object.freeze(['rules', 'invariants']);

export class ResourceApiError extends Error {
  constructor(code, message, status = 400, details = undefined) {
    super(String(message));
    this.name = 'ResourceApiError';
    this.code = code;
    this.status = status;
    if (details !== undefined) this.details = details;
  }
}

function clone(value, label = 'value') {
  try {
    const text = JSON.stringify(value);
    if (text === undefined || Buffer.byteLength(text) > MAX_JSON_BYTES) throw new Error('value is too large or undefined');
    return JSON.parse(text);
  } catch (error) {
    throw new ResourceApiError('invalid_json_value', `${label} 必须是可序列化的 JSON 值`, 400, { cause: error.message });
  }
}

function object(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ResourceApiError('invalid_object', `${label} 必须是对象`);
  return value;
}

function text(value, label, { optional = false, max = 300 } = {}) {
  if (value === undefined && optional) return undefined;
  if (typeof value !== 'string' || value.length < 1 || value.length > max) throw new ResourceApiError('invalid_field', `${label} 必须是 1..${max} 个字符的字符串`);
  return value;
}

function integer(value, label, { optional = false, min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  if (value === undefined && optional) return undefined;
  if (!Number.isSafeInteger(value) || value < min || value > max) throw new ResourceApiError('invalid_field', `${label} 必须是 ${min}..${max} 的安全整数`);
  return value;
}

function bool(value, label, { optional = false } = {}) {
  if (value === undefined && optional) return undefined;
  if (typeof value !== 'boolean') throw new ResourceApiError('invalid_field', `${label} 必须是布尔值`);
  return value;
}

function timestamp(value, label, { optional = false } = {}) {
  if (value === undefined && optional) return undefined;
  const result = text(value, label, { max: 80 });
  if (!Number.isFinite(Date.parse(result))) throw new ResourceApiError('invalid_field', `${label} 必须是有效 ISO 时间戳`);
  return result;
}

function id(value, label) {
  const result = text(value, label, { max: 200 });
  if (result.includes('/') || result.includes('\\') || result === '.' || result === '..' || result.split('/').includes('..')) {
    throw new ResourceApiError('invalid_path', `${label} 不能包含路径分隔符或 ..`);
  }
  return result;
}

function assertKnown(body, allowed, label) {
  object(body, label);
  const unknown = Object.keys(body).filter((key) => !allowed.has(key));
  if (unknown.length) throw new ResourceApiError('unknown_field', `${label} 包含未知字段：${unknown.join(', ')}`);
}

function positiveTtl(value, fallback, label = 'ttlMs') {
  return integer(value === undefined ? fallback : value, label, { min: 1, max: 86_400_000 });
}

function nowValue(clock) {
  const value = typeof clock === 'function' ? clock() : clock;
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) throw new ResourceApiError('invalid_clock', 'clock 必须返回有效时间');
  return { ms: date.getTime(), iso: date.toISOString() };
}

function leaseExpired(lease, nowMs) {
  if (!lease || typeof lease !== 'object') return true;
  const expiry = Date.parse(lease.expiresAt);
  return !Number.isFinite(expiry) || nowMs >= expiry;
}

function encodeCursor(value) {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function decodeCursor(value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 512) throw new ResourceApiError('invalid_cursor', 'cursor 无效');
  try {
    const decoded = JSON.parse(Buffer.from(value, 'base64url').toString('utf8'));
    if (!decoded || typeof decoded !== 'object' || Array.isArray(decoded) || typeof decoded.key !== 'string' || typeof decoded.id !== 'string') throw new Error('invalid cursor');
    return decoded;
  } catch {
    throw new ResourceApiError('invalid_cursor', 'cursor 无效');
  }
}

function singleQuery(searchParams, key) {
  const values = searchParams.getAll(key);
  if (values.length > 1) throw new ResourceApiError('duplicate_query_parameter', `查询参数重复：${key}`);
  return values[0];
}

export function parseResourcePageQuery(searchParams, { allowed = [] } = {}) {
  if (!searchParams || typeof searchParams.keys !== 'function') throw new TypeError('searchParams is required');
  const allowedKeys = new Set(['limit', 'cursor', ...allowed]);
  for (const key of new Set([...searchParams.keys()])) if (!allowedKeys.has(key)) throw new ResourceApiError('unknown_query_parameter', `不支持的查询参数：${key}`);
  const limitText = singleQuery(searchParams, 'limit');
  let limit = 100;
  if (limitText !== undefined) {
    if (!/^\d+$/.test(limitText)) throw new ResourceApiError('invalid_limit', 'limit 必须是 1..1000 的整数');
    limit = Number(limitText);
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_PAGE_SIZE) throw new ResourceApiError('invalid_limit', 'limit 必须是 1..1000 的整数');
  }
  const cursor = singleQuery(searchParams, 'cursor');
  if (cursor !== undefined) decodeCursor(cursor);
  const result = { limit, ...(cursor === undefined ? {} : { cursor }) };
  for (const key of allowed) {
    const value = singleQuery(searchParams, key);
    if (value !== undefined) result[key] = value;
  }
  return result;
}

function compareRows(a, b) {
  return a.key.localeCompare(b.key) || a.id.localeCompare(b.id);
}

function pageRows(rows, { limit = 100, cursor } = {}) {
  integer(limit, 'limit', { min: 1, max: MAX_PAGE_SIZE });
  const sorted = [...rows].sort(compareRows);
  const decoded = cursor === undefined ? null : decodeCursor(cursor);
  let start = 0;
  if (decoded) {
    start = sorted.findIndex((row) => compareRows(row, decoded) > 0);
    if (start < 0) start = sorted.length;
  }
  const items = sorted.slice(start, start + limit).map((row) => clone(row.value, 'resource item'));
  const hasMore = start + items.length < sorted.length;
  const last = hasMore ? sorted[start + items.length - 1] : null;
  return { items, hasMore, nextCursor: last ? encodeCursor({ key: last.key, id: last.id }) : null };
}

function sourcePath(value, label) {
  if (value === undefined || value === null) return null;
  const result = text(value, label, { max: 1000 });
  if (!isAbsolute(result)) throw new ResourceApiError('invalid_path', `${label} 必须是绝对路径`);
  return resolve(result);
}

async function readJsonFile(path, label) {
  try {
    const info = await stat(path);
    if (!info.isFile()) throw new ResourceApiError('invalid_source', `${label} 不是普通文件`, 422);
    if (info.size > MAX_JSON_BYTES) throw new ResourceApiError('source_too_large', `${label} 超过大小限制`, 422);
    return JSON.parse(await readFile(path, 'utf8'));
  } catch (error) {
    if (error instanceof ResourceApiError) throw error;
    if (error.code === 'ENOENT') throw new ResourceApiError('config_not_found', `${label} 不存在`, 503);
    if (error instanceof SyntaxError) throw new ResourceApiError('config_invalid_json', `${label} 不是有效 JSON`, 422);
    throw new ResourceApiError('config_read_failed', `${label} 读取失败`, 503, { cause: error.message });
  }
}

function normalizeConfigList(raw, kind, source) {
  let list = raw;
  if (!Array.isArray(list) && raw && typeof raw === 'object') list = raw[kind] ?? raw.items;
  if (list === undefined || list === null) return [];
  if (!Array.isArray(list)) throw new ResourceApiError('config_invalid', `${source} 的 ${kind} 必须是数组`, 422);
  return list.map((item, index) => normalizeVersionRecord(item, kind, { sourcePath: source, index }));
}

const RULE_FIELDS = new Set(['ruleId', 'id', 'version', 'name', 'description', 'severity', 'enabled', 'config', 'query', 'pattern', 'tags', 'source', 'sourcePath', 'createdAt', 'updatedAt', 'metadata']);
const INVARIANT_FIELDS = new Set(['invariantId', 'id', 'version', 'name', 'description', 'expression', 'severity', 'enabled', 'config', 'query', 'pattern', 'tags', 'source', 'sourcePath', 'createdAt', 'updatedAt', 'metadata']);

function normalizeVersionRecord(input, kind, { sourcePath: configuredSource = null } = {}) {
  object(input, `${kind} 项`);
  const fields = kind === 'rules' ? RULE_FIELDS : INVARIANT_FIELDS;
  assertKnown(input, fields, `${kind} 项`);
  const idField = kind === 'rules' ? 'ruleId' : 'invariantId';
  const resourceId = id(input[idField] ?? input.id, `${idField}`);
  const version = integer(input.version === undefined ? 1 : input.version, 'version', { min: 1, max: 1_000_000 });
  const normalized = { schemaVersion: RESOURCE_SCHEMA_VERSION, [idField]: resourceId, version };
  for (const key of ['name', 'description', 'severity', 'query', 'pattern', 'expression']) if (input[key] !== undefined) normalized[key] = text(input[key], key, { max: 20_000 });
  if (input.enabled !== undefined) normalized.enabled = bool(input.enabled, 'enabled');
  if (input.tags !== undefined) {
    if (!Array.isArray(input.tags) || input.tags.some((tag) => typeof tag !== 'string' || tag.length < 1 || tag.length > 100)) throw new ResourceApiError('invalid_field', 'tags 必须是非空字符串数组');
    normalized.tags = [...input.tags];
  }
  for (const key of ['config', 'metadata']) if (input[key] !== undefined) normalized[key] = clone(input[key], key);
  const source = input.source ?? configuredSource;
  if (source !== undefined && source !== null) normalized.source = text(source, 'source', { max: 1000 });
  if (input.sourcePath !== undefined) normalized.sourcePath = sourcePath(input.sourcePath, 'sourcePath');
  for (const key of ['createdAt', 'updatedAt']) if (input[key] !== undefined) normalized[key] = timestamp(input[key], key);
  return normalized;
}

function normalizeWorkerInput(input, clock) {
  assertKnown(input, new Set(['workerId', 'name', 'capabilities', 'metadata', 'ttlMs', 'version']), 'worker');
  const workerId = id(input.workerId, 'workerId');
  const name = input.name === undefined ? undefined : text(input.name, 'name', { max: 300 });
  const capabilities = input.capabilities === undefined ? [] : input.capabilities;
  if (!Array.isArray(capabilities) || capabilities.some((value) => typeof value !== 'string' || value.length < 1 || value.length > 200) || capabilities.length > 200) throw new ResourceApiError('invalid_field', 'capabilities 必须是 0..200 个字符串');
  const metadata = input.metadata === undefined ? {} : clone(input.metadata, 'metadata');
  object(metadata, 'metadata');
  const ttlMs = positiveTtl(input.ttlMs, DEFAULT_RESOURCE_LEASE_TTL_MS);
  const version = integer(input.version === undefined ? 1 : input.version, 'version', { min: 1, max: 1_000_000 });
  const { iso } = nowValue(clock);
  return { schemaVersion: RESOURCE_SCHEMA_VERSION, workerId, ...(name === undefined ? {} : { name }), capabilities: [...capabilities], metadata, version, registeredAt: iso, updatedAt: iso, ttlMs };
}

function emptyState() {
  return { schemaVersion: RESOURCE_SCHEMA_VERSION, revision: 0, workers: {}, rules: {}, invariants: {}, findingTriage: {}, sources: { rules: null, invariants: null } };
}

function validateState(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || value.schemaVersion !== RESOURCE_SCHEMA_VERSION || !Number.isSafeInteger(value.revision) || value.revision < 0) throw new ResourceApiError('state_corrupt', '资源状态文件格式无效', 500);
  for (const key of ['workers', 'rules', 'invariants']) if (!value[key] || typeof value[key] !== 'object' || Array.isArray(value[key])) throw new ResourceApiError('state_corrupt', `资源状态 ${key} 无效`, 500);
  if (value.findingTriage === undefined) value.findingTriage = {};
  if (!value.findingTriage || typeof value.findingTriage !== 'object' || Array.isArray(value.findingTriage)) throw new ResourceApiError('state_corrupt', '资源状态 findingTriage 无效', 500);
  for (const [findingId, item] of Object.entries(value.findingTriage)) {
    if (!item || typeof item !== 'object' || Array.isArray(item) || item.findingId !== findingId
      || !FINDING_TRIAGE_STATUSES.includes(item.triageStatus) || (item.assignee !== null && typeof item.assignee !== 'string')
      || !Array.isArray(item.tags) || !Array.isArray(item.notes) || !Array.isArray(item.history)) {
      throw new ResourceApiError('state_corrupt', '漏洞处置记录格式无效', 500);
    }
  }
  if (!value.sources || typeof value.sources !== 'object' || Array.isArray(value.sources)) value.sources = { rules: null, invariants: null };
  return value;
}

export class ResourceApiOperations {
  constructor(options = {}) {
    if (typeof options === 'string') options = { path: options };
    const { path, auditPath = null, rulesPath = null, invariantsPath = null, clock = () => Date.now(), defaultLeaseTtlMs = DEFAULT_RESOURCE_LEASE_TTL_MS } = options;
    if (typeof path !== 'string' || !path) throw new TypeError('resource state path is required');
    this.path = resolve(path);
    this.lockPath = `${this.path}.lock`;
    this.auditPath = auditPath === null ? null : resolve(auditPath);
    this.sources = { rules: sourcePath(rulesPath, 'rulesPath'), invariants: sourcePath(invariantsPath, 'invariantsPath') };
    this.clock = clock;
    this.defaultLeaseTtlMs = positiveTtl(defaultLeaseTtlMs, DEFAULT_RESOURCE_LEASE_TTL_MS, 'defaultLeaseTtlMs');
    this.locked = false;
    this.waiters = [];
  }

  _now() { return nowValue(this.clock); }

  async _acquireFileLock() {
    await mkdir(dirname(this.path), { recursive: true });
    const token = randomUUID();
    const started = Date.now();
    while (Date.now() - started < 15_000) {
      try {
        const handle = await open(this.lockPath, 'wx', 0o600);
        await handle.writeFile(JSON.stringify({ token, pid: process.pid, createdAt: new Date().toISOString() }));
        return { handle, token };
      } catch (error) {
        if (error.code !== 'EEXIST') throw error;
        try {
          const info = await stat(this.lockPath);
          let ownerAlive = false;
          try {
            const marker = JSON.parse(await readFile(this.lockPath, 'utf8'));
            if (Number.isInteger(marker.pid)) process.kill(marker.pid, 0);
            ownerAlive = true;
          } catch (ownerError) {
            ownerAlive = ownerError?.code !== 'ESRCH' && ownerError?.code !== 'ENOENT';
          }
          if (Date.now() - info.mtimeMs > 30_000 && !ownerAlive) await unlink(this.lockPath).catch(() => {});
        } catch (stale) { if (stale.code !== 'ENOENT') throw stale; }
        await new Promise((resolveWait) => setTimeout(resolveWait, 10));
      }
    }
    throw new ResourceApiError('lock_timeout', '资源状态锁超时', 503);
  }

  async _withLock(fn) {
    while (this.locked) await new Promise((resolveWait) => this.waiters.push(resolveWait));
    this.locked = true;
    let handle = null;
    let token = null;
    try {
      ({ handle, token } = await this._acquireFileLock());
      return await fn();
    } finally {
      await handle?.close().catch(() => {});
      try {
        const marker = await readFile(this.lockPath, 'utf8');
        if (marker.includes(token)) await unlink(this.lockPath);
      } catch {}
      this.locked = false;
      this.waiters.shift()?.();
    }
  }

  async _read() {
    try {
      const raw = JSON.parse(await readFile(this.path, 'utf8'));
      return validateState(raw);
    } catch (error) {
      if (error.code === 'ENOENT') return emptyState();
      if (error instanceof SyntaxError) throw new ResourceApiError('state_corrupt', '资源状态不是有效 JSON', 500);
      throw error;
    }
  }

  async _write(value) {
    await mkdir(dirname(this.path), { recursive: true });
    const temp = `${this.path}.${randomUUID()}.tmp`;
    try { await writeFile(temp, `${JSON.stringify(value, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 }); await rename(temp, this.path); }
    finally { await unlink(temp).catch(() => {}); }
  }

  async _initializeSources(data) {
    let changed = false;
    for (const kind of RESOURCE_KINDS) {
      if (data.sources[kind] !== null && data.sources[kind] !== undefined) continue;
      const configured = this.sources[kind];
      data.sources[kind] = configured ? { path: configured, loadedAt: this._now().iso, count: 0 } : { kind: 'empty', reason: 'no_configured_source', loadedAt: this._now().iso, count: 0 };
      if (configured) {
        const raw = await readJsonFile(configured, `${kind} 配置`);
        const records = normalizeConfigList(raw, kind, configured);
        const idField = kind === 'rules' ? 'ruleId' : 'invariantId';
        for (const record of records) {
          const bucket = data[kind][record[idField]] || { latestVersion: 0, versions: {} };
          if (bucket.versions[String(record.version)]) throw new ResourceApiError('duplicate_version', `${kind} ${record[idField]} v${record.version} 重复`, 422);
          bucket.versions[String(record.version)] = { ...record, sourcePath: record.sourcePath || configured };
          bucket.latestVersion = Math.max(bucket.latestVersion, record.version);
          data[kind][record[idField]] = bucket;
        }
        data.sources[kind].count = records.length;
      }
      changed = true;
    }
    return changed;
  }

  async _mutate(fn, { expectedRevision } = {}) {
    return this._withLock(async () => {
      const data = await this._read();
      const initialized = await this._initializeSources(data);
      if (expectedRevision !== undefined) {
        integer(expectedRevision, 'expectedRevision');
        if (data.revision !== expectedRevision) throw new ResourceApiError('REVISION_MISMATCH', `资源状态 revision 不匹配：期望 ${expectedRevision}，当前 ${data.revision}`, 412, { expectedRevision, actualRevision: data.revision });
      }
      const result = await fn(data);
      if (initialized || result?.__changed === true) data.revision += 1;
      await this._write(data);
      return clone(result?.__changed === true ? result.value : result, 'resource result');
    });
  }

  async _readOperation(fn) {
    return this._withLock(async () => {
      const data = await this._read();
      const initialized = await this._initializeSources(data);
      if (initialized) data.revision += 1;
      const result = await fn(data);
      if (initialized) await this._write(data);
      return clone(result, 'resource result');
    });
  }

  async registerWorker(input, { expectedRevision } = {}) {
    const normalized = normalizeWorkerInput(input, this.clock);
    return this._mutate((data) => {
      const current = data.workers[normalized.workerId];
      const sequence = Number(current?.lease?.sequence || 0) + 1;
      const { ms, iso } = this._now();
      const worker = { ...normalized, registeredAt: current?.registeredAt || normalized.registeredAt, updatedAt: iso, status: 'healthy', lease: { workerId: normalized.workerId, fencingToken: randomUUID(), heartbeatAt: iso, expiresAt: new Date(ms + normalized.ttlMs).toISOString(), ttlMs: normalized.ttlMs, sequence } };
      data.workers[normalized.workerId] = worker;
      return { __changed: true, value: worker };
    }, { expectedRevision });
  }

  async heartbeatWorker(workerId, fencingToken, { ttlMs, expectedRevision } = {}) {
    const workerKey = id(workerId, 'workerId');
    text(fencingToken, 'fencingToken', { max: 200 });
    return this._mutate((data) => {
      const worker = data.workers[workerKey];
      if (!worker) throw new ResourceApiError('not_found', `worker 不存在：${workerKey}`, 404);
      if (!worker.lease || worker.lease.fencingToken !== fencingToken) throw new ResourceApiError('lease_not_owned', 'worker lease 不属于调用者', 409);
      const { ms, iso } = this._now();
      if (leaseExpired(worker.lease, ms)) throw new ResourceApiError('lease_expired', 'worker lease 已过期', 409);
      const nextTtl = positiveTtl(ttlMs, worker.lease.ttlMs);
      worker.lease = { ...worker.lease, heartbeatAt: iso, expiresAt: new Date(ms + nextTtl).toISOString(), ttlMs: nextTtl, sequence: worker.lease.sequence + 1 };
      worker.updatedAt = iso; worker.ttlMs = nextTtl; worker.status = 'healthy';
      return { __changed: true, value: worker };
    }, { expectedRevision });
  }

  async getWorker(workerId) {
    const workerKey = id(workerId, 'workerId');
    return this._readOperation((data) => data.workers[workerKey] ? this._workerView(data.workers[workerKey]) : null);
  }

  _workerView(worker) {
    const { ms } = this._now();
    const expired = leaseExpired(worker.lease, ms);
    return { ...clone(worker, 'worker'), status: expired ? 'expired' : 'healthy', healthy: !expired, leaseExpired: expired };
  }

  async getWorkerHealth(workerId) {
    const worker = await this.getWorker(workerId);
    if (!worker) throw new ResourceApiError('not_found', `worker 不存在：${workerId}`, 404);
    return { workerId: worker.workerId, status: worker.status, healthy: worker.healthy, leaseExpired: worker.leaseExpired, heartbeatAt: worker.lease?.heartbeatAt || null, expiresAt: worker.lease?.expiresAt || null, observedAt: this._now().iso };
  }

  async readSnapshot() {
    return this._readOperation((data) => ({
      revision: data.revision,
      consistency: { revision: data.revision, asOf: this._now().iso },
      workers: Object.values(data.workers).map((worker) => this._workerView(worker)),
      rules: Object.fromEntries(Object.entries(data.rules).map(([key, value]) => [key, clone(value, 'rules')])),
      invariants: Object.fromEntries(Object.entries(data.invariants).map(([key, value]) => [key, clone(value, 'invariants')])),
      findingTriage: Object.fromEntries(Object.entries(data.findingTriage).map(([key, value]) => [key, clone(value, 'finding triage')])),
      sources: clone(data.sources, 'resource sources'),
    }));
  }

  async readFindingTriages(findingIds = undefined) {
    if (findingIds !== undefined && (!Array.isArray(findingIds) || findingIds.length > 1000)) throw new ResourceApiError('invalid_field', 'findingIds 必须是最多 1000 项的数组');
    const keys = findingIds === undefined ? null : new Set(findingIds.map((value) => id(value, 'findingId')));
    return this._readOperation((data) => ({
      items: Object.fromEntries(Object.entries(data.findingTriage).filter(([key]) => keys === null || keys.has(key)).map(([key, value]) => [key, clone(value, 'finding triage')])),
      revision: data.revision,
      consistency: { revision: data.revision, asOf: this._now().iso },
    }));
  }

  async updateFindingTriage(findingId, input, { expectedRevision, requestId } = {}) {
    const key = id(findingId, 'findingId');
    let patch;
    try { patch = normalizeFindingTriagePatch(input); }
    catch (error) { throw new ResourceApiError('invalid_finding_triage', error.message, 400); }
    const request = requestId === undefined ? undefined : text(requestId, 'requestId', { max: 200 });
    return this._mutate((data) => {
      const { iso } = this._now();
      const current = data.findingTriage[key] || {
        schemaVersion: RESOURCE_SCHEMA_VERSION, findingId: key, triageStatus: 'unreviewed',
        assignee: null, tags: [], notes: [], history: [], createdAt: iso, updatedAt: iso,
      };
      if (current.history.length >= 1000 || (patch.note && current.notes.length >= 500)) {
        throw new ResourceApiError('history_limit', '该记录的处置历史已达到上限', 413);
      }
      const next = { ...current };
      for (const field of ['triageStatus', 'assignee', 'tags']) if (Object.hasOwn(patch, field)) next[field] = clone(patch[field], field);
      if (patch.note) next.notes = [...current.notes, { note: patch.note, at: iso, ...(request ? { requestId: request } : {}) }];
      next.updatedAt = iso;
      next.history = [...current.history, { at: iso, ...(request ? { requestId: request } : {}), patch: clone(patch, 'finding triage patch') }];
      data.findingTriage[key] = next;
      return { __changed: true, value: { triage: next, revision: data.revision + 1, consistency: { revision: data.revision + 1, asOf: iso } } };
    }, { expectedRevision });
  }

  async listWorkers({ limit = 100, cursor } = {}) {
    return this._readOperation((data) => {
      const rows = Object.values(data.workers).map((worker) => ({ key: worker.workerId, id: worker.workerId, value: this._workerView(worker) }));
      const page = pageRows(rows, { limit, cursor });
      return { ...page, revision: data.revision, consistency: { revision: data.revision, asOf: this._now().iso } };
    });
  }

  async unregisterWorker(workerId, { expectedRevision } = {}) {
    const workerKey = id(workerId, 'workerId');
    return this._mutate((data) => {
      if (!data.workers[workerKey]) throw new ResourceApiError('not_found', `worker 不存在：${workerKey}`, 404);
      delete data.workers[workerKey];
      return { __changed: true, value: null };
    }, { expectedRevision });
  }

  async _listVersioned(kind, options = {}) {
    if (!RESOURCE_KINDS.includes(kind)) throw new ResourceApiError('invalid_resource', `未知资源：${kind}`);
    const { limit = 100, cursor, allVersions = false } = options;
    if (typeof allVersions !== 'boolean') throw new ResourceApiError('invalid_field', 'allVersions 必须是布尔值');
    return this._readOperation((data) => {
      const idField = kind === 'rules' ? 'ruleId' : 'invariantId';
      const rows = [];
      for (const [resourceId, bucket] of Object.entries(data[kind])) {
        const versions = Object.values(bucket.versions || {});
        const selected = allVersions ? versions : versions.filter((item) => item.version === bucket.latestVersion);
        for (const value of selected) rows.push({ key: resourceId, id: `${resourceId}@${value.version}`, value: clone(value, kind) });
      }
      const page = pageRows(rows, { limit, cursor });
      return { ...page, revision: data.revision, consistency: { revision: data.revision, asOf: this._now().iso }, resource: kind, empty: page.items.length === 0 && rows.length === 0, idField };
    });
  }

  async listRules(options = {}) { return this._listVersioned('rules', options); }
  async listInvariants(options = {}) { return this._listVersioned('invariants', options); }
  async listResource(kind, options = {}) {
    if (kind === 'workers') return this.listWorkers(options);
    if (kind === 'rules') return this.listRules(options);
    if (kind === 'invariants') return this.listInvariants(options);
    if (kind === 'review-audit' || kind === 'reviews') return this.listReviewAudits(options);
    throw new ResourceApiError('invalid_resource', `未知资源：${kind}`);
  }

  async getVersioned(kind, resourceId, version) {
    if (!RESOURCE_KINDS.includes(kind)) throw new ResourceApiError('invalid_resource', `未知资源：${kind}`);
    const valueId = id(resourceId, `${kind} id`);
    const requestedVersion = version === undefined ? undefined : integer(version, 'version', { min: 1, max: 1_000_000 });
    return this._readOperation((data) => {
      const bucket = data[kind][valueId];
      if (!bucket) throw new ResourceApiError('not_found', `${kind} 不存在：${valueId}`, 404);
      const selectedVersion = requestedVersion ?? bucket.latestVersion;
      const result = bucket.versions?.[String(selectedVersion)];
      if (!result) throw new ResourceApiError('not_found', `${kind} ${valueId} v${selectedVersion} 不存在`, 404);
      return { data: clone(result, kind), revision: data.revision, consistency: { revision: data.revision, asOf: this._now().iso } };
    });
  }

  async createVersioned(kind, input, { expectedRevision } = {}) {
    if (!RESOURCE_KINDS.includes(kind)) throw new ResourceApiError('invalid_resource', `未知资源：${kind}`);
    object(input, kind);
    const idField = kind === 'rules' ? 'ruleId' : 'invariantId';
    const resourceId = id(input[idField] ?? input.id, idField);
    return this._mutate((data) => {
      const bucket = data[kind][resourceId] || { latestVersion: 0, versions: {} };
      const nextVersion = input.version === undefined ? bucket.latestVersion + 1 : integer(input.version, 'version', { min: 1, max: 1_000_000 });
      if (bucket.versions[String(nextVersion)]) throw new ResourceApiError('duplicate_version', `${kind} ${resourceId} v${nextVersion} 已存在`, 409);
      const normalized = normalizeVersionRecord({ ...input, [idField]: resourceId, version: nextVersion }, kind);
      const { iso } = this._now();
      normalized.createdAt ||= iso; normalized.updatedAt = iso;
      bucket.versions[String(nextVersion)] = normalized; bucket.latestVersion = Math.max(bucket.latestVersion, nextVersion); data[kind][resourceId] = bucket;
      return { __changed: true, value: normalized };
    }, { expectedRevision });
  }

  async createRuleVersion(input, options = {}) { return this.createVersioned('rules', input, options); }
  async createInvariantVersion(input, options = {}) { return this.createVersioned('invariants', input, options); }

  async appendReviewAudit(input) {
    object(input, 'review audit');
    const allowed = new Set(['at', 'requestId', 'manifestSha256', 'decision', 'allowed', 'reasonCodes', 'findingCount', 'severities', 'model', 'taskId', 'metadata']);
    assertKnown(input, allowed, 'review audit');
    const entry = clone(input, 'review audit');
    if (entry.at === undefined) entry.at = this._now().iso; else timestamp(entry.at, 'at');
    if (entry.requestId !== undefined) text(entry.requestId, 'requestId', { max: 200 });
    if (entry.manifestSha256 !== undefined) text(entry.manifestSha256, 'manifestSha256', { max: 128 });
    if (entry.decision !== undefined) text(entry.decision, 'decision', { max: 40 });
    if (entry.allowed !== undefined) bool(entry.allowed, 'allowed');
    if (entry.findingCount !== undefined) integer(entry.findingCount, 'findingCount', { min: 0 });
    if (entry.reasonCodes !== undefined && (!Array.isArray(entry.reasonCodes) || entry.reasonCodes.some((item) => typeof item !== 'string'))) throw new ResourceApiError('invalid_field', 'reasonCodes 必须是字符串数组');
    if (this.auditPath === null) throw new ResourceApiError('audit_not_configured', 'review audit 持久化路径未配置', 503);
    await this._withLock(async () => {
      await mkdir(dirname(this.auditPath), { recursive: true });
      await writeFile(this.auditPath, `${JSON.stringify(entry)}\n`, { encoding: 'utf8', mode: 0o600, flag: 'a' });
    });
    return entry;
  }

  async _readAudit() {
    if (this.auditPath === null) return [];
    let raw;
    try { raw = await readFile(this.auditPath, 'utf8'); }
    catch (error) { if (error.code === 'ENOENT') return []; throw new ResourceApiError('audit_read_failed', '审查审计读取失败', 503, { cause: error.message }); }
    const lines = raw.split(/\r?\n/).filter((line) => line.trim());
    return lines.map((line, index) => { try { return clone(JSON.parse(line), `review audit line ${index + 1}`); } catch { throw new ResourceApiError('audit_corrupt', `审查审计第 ${index + 1} 行无效`, 500); } });
  }

  async listReviewAudits({ limit = 100, cursor, decision, manifestSha256, requestId } = {}) {
    for (const [value, label] of [[decision, 'decision'], [manifestSha256, 'manifestSha256'], [requestId, 'requestId']]) if (value !== undefined) text(value, label, { max: 200 });
    return this._withLock(async () => {
      const entries = await this._readAudit();
      const filtered = entries.filter((entry) => (decision === undefined || entry.decision === decision) && (manifestSha256 === undefined || entry.manifestSha256 === manifestSha256) && (requestId === undefined || entry.requestId === requestId));
      const rows = filtered.map((value, index) => ({ key: String(index).padStart(16, '0'), id: String(index), value }));
      const page = pageRows(rows, { limit, cursor });
      return { ...page, revision: entries.length, consistency: { revision: entries.length, asOf: this._now().iso }, resource: 'review-audit', empty: filtered.length === 0 };
    });
  }

  async getReviewAudit(requestId) {
    text(requestId, 'requestId', { max: 200 });
    const result = await this.listReviewAudits({ requestId, limit: 2 });
    return result.items[0] || null;
  }
}

export function resourceEnvelope(data, generatedAt = new Date().toISOString()) {
  return { apiVersion: RESOURCE_API_VERSION, schemaVersion: RESOURCE_SCHEMA_VERSION, generatedAt, ...data };
}

export function resourceErrorBody(error, requestId = null) {
  const status = error?.status || 400;
  const errorBody = {
    code: error?.code || 'invalid_request',
    message: String(error?.message || '资源请求失败'),
    ...(requestId ? { requestId } : {}),
    ...(error?.details ? { details: error.details } : {}),
  };
  return { status, body: resourceEnvelope({ error: errorBody }) };
}

export { decodeCursor as decodeResourceCursor, encodeCursor as encodeResourceCursor, leaseExpired as isResourceLeaseExpired };
