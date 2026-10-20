import { mkdir, open, readFile, rename, stat, unlink, writeFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { dirname } from 'node:path';

export const TASK_STATES = Object.freeze([
  'queued', 'preparing', 'running', 'checkpointing', 'paused',
  'cancelling', 'cancelled', 'succeeded', 'partial', 'failed', 'blocked',
]);

const ACTIVE_STATES = new Set(['preparing', 'running', 'checkpointing']);
const LEASED_STATES = new Set([...ACTIVE_STATES, 'cancelling']);
const TERMINAL_STATES = new Set(['cancelled', 'succeeded', 'partial', 'failed', 'blocked']);
const TRANSITIONS = Object.freeze({
  queued: ['preparing', 'paused', 'cancelling', 'cancelled'],
  preparing: ['preparing', 'running', 'queued', 'paused', 'cancelling', 'cancelled', 'failed', 'blocked'],
  running: ['preparing', 'checkpointing', 'queued', 'paused', 'cancelling', 'succeeded', 'partial', 'failed', 'blocked'],
  checkpointing: ['preparing', 'running', 'queued', 'paused', 'cancelling', 'succeeded', 'partial', 'failed', 'blocked'],
  paused: ['preparing', 'queued', 'cancelling', 'cancelled'],
  cancelling: ['cancelled'],
  failed: ['queued'],
  cancelled: [], succeeded: [], partial: [], blocked: [],
});
const MAX_HISTORY = 100;
const DEFAULT_TTL_MS = 45_000;
const DEFAULT_RETRY_DELAY_MS = 1_000;
const MAX_RETRY_DELAY_MS = 86_400_000;

export function compareTaskOrder(a, b) {
  return b.priority - a.priority || a.createdAt.localeCompare(b.createdAt) || a.taskId.localeCompare(b.taskId);
}

export function encodeTaskCursor(task) {
  if (!task || typeof task !== 'object' || typeof task.taskId !== 'string' || !Number.isInteger(task.priority) || typeof task.createdAt !== 'string') {
    throw new TypeError('task cursor requires a task order key');
  }
  return Buffer.from(JSON.stringify({ priority: task.priority, createdAt: task.createdAt, taskId: task.taskId }), 'utf8').toString('base64url');
}

export function decodeTaskCursor(cursor) {
  if (typeof cursor !== 'string' || cursor.length < 1 || cursor.length > 512) throw new TypeError('invalid task cursor');
  let value;
  try { value = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8')); } catch { throw new TypeError('invalid task cursor'); }
  if (!value || typeof value !== 'object' || Array.isArray(value) || !Number.isInteger(value.priority) || typeof value.createdAt !== 'string' || !Number.isFinite(Date.parse(value.createdAt)) || typeof value.taskId !== 'string' || !value.taskId) throw new TypeError('invalid task cursor');
  return value;
}

function clone(value, label = 'value') {
  try {
    const text = JSON.stringify(value);
    if (text === undefined) throw new Error('undefined is not JSON data');
    return JSON.parse(text);
  } catch (error) {
    throw new TypeError(`${label} must be JSON-serializable: ${error.message}`);
  }
}

function clockValue(clock) {
  const value = typeof clock === 'function' ? clock() : clock;
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) throw new TypeError('clock must return a valid Date or timestamp');
  return { ms: date.getTime(), iso: date.toISOString() };
}

function ensureState(state) {
  if (!TASK_STATES.includes(state)) throw new Error(`unknown task state: ${state}`);
}

function historyEvent(from, to, reason, at, details = {}) {
  const safeDetails = clone(details, 'history details');
  if (!safeDetails || typeof safeDetails !== 'object' || Array.isArray(safeDetails)) throw new TypeError('history details must be an object');
  return { ...safeDetails, from, to, reason: String(reason || ''), at };
}

function withHistory(task, event, at) {
  const history = Array.isArray(task.history) ? task.history : [];
  return { ...task, updatedAt: at, history: [...history, event].slice(-MAX_HISTORY) };
}

export function isLeaseExpired(lease, now = Date.now()) {
  if (!lease || typeof lease !== 'object') return true;
  const expiresAt = Date.parse(lease.expiresAt);
  const nowMs = now instanceof Date ? now.getTime() : Number(now);
  return !Number.isFinite(expiresAt) || !Number.isFinite(nowMs) || nowMs >= expiresAt;
}

export function transitionTask(current, next, reason = '', now = Date.now(), details = {}) {
  if (!current || typeof current !== 'object') throw new TypeError('current task must be an object');
  ensureState(current.state);
  ensureState(next);
  if (!TRANSITIONS[current.state]?.includes(next)) throw new Error(`invalid task transition: ${current.state} -> ${next}`);
  const { iso } = clockValue(now);
  const event = historyEvent(current.state, next, reason, iso, details);
  const updated = { ...clone(current, 'task'), state: next };
  if (TERMINAL_STATES.has(next) || next === 'queued' || next === 'paused') updated.lease = null;
  updated.resumePending = next === 'queued' && current.state === 'paused';
  return withHistory(updated, event, iso);
}

function assertTaskRecord(task) {
  if (!task || typeof task !== 'object' || task.schemaVersion !== 1 || typeof task.taskId !== 'string' || !task.taskId) {
    throw new Error('invalid task record');
  }
  ensureState(task.state);
  if (typeof task.type !== 'string' || !task.type || !Number.isInteger(task.priority)) throw new Error('invalid task metadata');
  for (const field of ['createdAt', 'updatedAt']) if (typeof task[field] !== 'string' || !Number.isFinite(Date.parse(task[field]))) throw new Error(`invalid task timestamp: ${field}`);
  if (!Array.isArray(task.history) || !Number.isInteger(task.attempts) || task.attempts < 0 ||
      !Number.isInteger(task.maxAttempts) || task.maxAttempts < 1 || task.attempts > task.maxAttempts || !Number.isInteger(task.checkpointSeq) || task.checkpointSeq < 0) throw new Error('invalid task counters');
  if (task.resumePending !== undefined && typeof task.resumePending !== 'boolean') throw new Error('invalid task resume marker');
  for (const event of task.history) {
    if (!event || typeof event !== 'object' || (event.from !== null && !TASK_STATES.includes(event.from)) || !TASK_STATES.includes(event.to) || typeof event.reason !== 'string' || typeof event.at !== 'string' || !Number.isFinite(Date.parse(event.at))) throw new Error('invalid task history');
  }
  if (task.nextRetryAt !== null && (typeof task.nextRetryAt !== 'string' || !Number.isFinite(Date.parse(task.nextRetryAt)))) throw new Error('invalid retry timestamp');
  if (LEASED_STATES.has(task.state) && task.lease === null) throw new Error('active task must have a lease');
  if (!LEASED_STATES.has(task.state) && task.lease !== null) throw new Error('inactive task must not have a lease');
  if (task.lease !== null) {
    const lease = task.lease;
    if (!lease || typeof lease !== 'object' || typeof lease.workerId !== 'string' || !lease.workerId || typeof lease.fencingToken !== 'string' || !lease.fencingToken || lease.fencingToken.length > 200 || typeof lease.heartbeatAt !== 'string' || typeof lease.expiresAt !== 'string' || !Number.isFinite(Date.parse(lease.heartbeatAt)) || !Number.isFinite(Date.parse(lease.expiresAt)) || !Number.isInteger(lease.ttlMs) || lease.ttlMs < 1 || !Number.isInteger(lease.sequence) || lease.sequence < 1) throw new Error('invalid task lease');
  }
  clone(task.payload, 'task payload');
  if (task.checkpoint !== null && task.checkpoint !== undefined) clone(task.checkpoint, 'task checkpoint');
  return task;
}

export class TaskStateStore {
  constructor(options = {}) {
    if (typeof options === 'string') options = { path: options };
    const { path, clock = () => Date.now(), defaultLeaseTtlMs = DEFAULT_TTL_MS } = options;
    if (!path || typeof path !== 'string') throw new TypeError('task state path is required');
    this.path = path;
    this.clock = clock;
    this.defaultLeaseTtlMs = this._ttl(defaultLeaseTtlMs);
    this.lockPath = `${path}.lock`;
    this.locked = false;
    this.waiters = [];
  }

  _now() { return clockValue(this.clock); }

  _ttl(value) {
    const ttl = Number(value);
    if (!Number.isInteger(ttl) || ttl < 1 || ttl > 86_400_000) throw new RangeError('lease TTL must be 1..86400000 ms');
    return ttl;
  }

  async _withLock(fn) {
    while (this.locked) await new Promise((resolve) => this.waiters.push(resolve));
    this.locked = true;
    let handle = null;
    let token = null;
    try {
      ({ handle, token } = await this._acquireFileLock());
      return await fn();
    } finally {
      if (handle) {
        await handle.close().catch(() => {});
        try {
          const marker = await readFile(this.lockPath, 'utf8');
          if (marker.includes(token)) await unlink(this.lockPath);
        } catch {}
      }
      this.locked = false;
      this.waiters.shift()?.();
    }
  }

  async _acquireFileLock() {
    await mkdir(dirname(this.path), { recursive: true });
    const started = Date.now();
    const token = randomUUID();
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
          if (Date.now() - info.mtimeMs > 30_000 && !ownerAlive) await unlink(this.lockPath);
        } catch (staleError) {
          if (staleError.code !== 'ENOENT') throw staleError;
        }
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
    }
    throw new Error('task state lock timeout');
  }

  async _read() {
    try {
      const raw = JSON.parse(await readFile(this.path, 'utf8'));
      if (!raw || raw.schemaVersion !== 1 || !raw.tasks || typeof raw.tasks !== 'object' || Array.isArray(raw.tasks) || (raw.revision !== undefined && (!Number.isSafeInteger(raw.revision) || raw.revision < 0))) {
        throw new Error('expected schemaVersion 1 with a tasks object');
      }
      for (const [key, task] of Object.entries(raw.tasks)) {
        assertTaskRecord(task);
        if (key !== task.taskId) throw new Error(`task key does not match taskId: ${key}`);
      }
      return { ...raw, revision: Number.isSafeInteger(raw.revision) ? raw.revision : 0 };
    } catch (error) {
      if (error.code === 'ENOENT') return { schemaVersion: 1, revision: 0, tasks: {} };
      if (error instanceof SyntaxError) throw new Error(`invalid task state JSON: ${error.message}`);
      throw error;
    }
  }

  async _write(value) {
    await mkdir(dirname(this.path), { recursive: true });
    const temp = `${this.path}.${randomUUID()}.tmp`;
    try {
      await writeFile(temp, `${JSON.stringify(value, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
      await rename(temp, this.path);
    } finally { await unlink(temp).catch(() => {}); }
  }

  async _mutate(fn, { expectedRevision } = {}) {
    return this._withLock(async () => {
      const data = await this._read();
      if (expectedRevision !== undefined && data.revision !== expectedRevision) {
        const error = new Error(`task state revision mismatch: expected ${expectedRevision}, current ${data.revision}`);
        error.code = 'REVISION_MISMATCH'; error.expectedRevision = expectedRevision; error.actualRevision = data.revision;
        throw error;
      }
      const result = await fn(data);
      data.revision += 1;
      await this._write(data);
      return clone(result, 'task result');
    });
  }

  async create({ taskId = randomUUID(), type, payload = {}, priority = 0, maxAttempts = 3 } = {}) {
    if (typeof taskId !== 'string' || !taskId || typeof type !== 'string' || !type) throw new TypeError('taskId and type are required');
    if (!Number.isInteger(priority)) throw new TypeError('priority must be an integer');
    if (!Number.isInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 100) throw new RangeError('maxAttempts must be 1..100');
    const safePayload = clone(payload, 'task payload');
    return this._mutate((data) => {
      if (data.tasks[taskId]) throw new Error(`task already exists: ${taskId}`);
      const { iso } = this._now();
      const task = { schemaVersion: 1, taskId, type, priority, createdAt: iso, updatedAt: iso,
        state: 'queued', payload: safePayload, checkpoint: null, checkpointSeq: 0,
        history: [{ from: null, to: 'queued', reason: 'created', at: iso }], attempts: 0,
        maxAttempts, lease: null, nextRetryAt: null, resumePending: false };
      data.tasks[taskId] = task;
      return task;
    });
  }

  async get(taskId) {
    const data = await this._read();
    return data.tasks[taskId] ? clone(data.tasks[taskId], 'task') : null;
  }

  async readSnapshot() {
    const data = await this._read();
    return { revision: data.revision, tasks: Object.values(data.tasks).map((task) => clone(task, 'task')) };
  }

  async readTask(taskId) {
    const data = await this._read();
    return { revision: data.revision, task: data.tasks[taskId] ? clone(data.tasks[taskId], 'task') : null };
  }

  async list({ state, limit = 100, offset = 0 } = {}) {
    if (state !== undefined) ensureState(state);
    if (!Number.isSafeInteger(offset) || offset < 0) throw new RangeError('offset must be a non-negative safe integer');
    const count = Math.min(Math.max(Number(limit) || 100, 1), 1000);
    const data = await this._read();
    return Object.values(data.tasks).filter((task) => state === undefined || task.state === state)
      .sort(compareTaskOrder)
      .slice(offset, offset + count).map((task) => clone(task, 'task'));
  }

  async listPage({ state, limit = 100, cursor } = {}) {
    if (state !== undefined) ensureState(state);
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000) throw new RangeError('limit must be an integer in the range 1..1000');
    const decoded = cursor === undefined ? null : decodeTaskCursor(cursor);
    const data = await this._read();
    const items = Object.values(data.tasks).filter((task) => state === undefined || task.state === state).sort(compareTaskOrder);
    const start = decoded ? items.findIndex((task) => compareTaskOrder(task, decoded) > 0) : 0;
    const offset = decoded && start < 0 ? items.length : start;
    const page = items.slice(offset, offset + limit).map((task) => clone(task, 'task'));
    const hasMore = offset + page.length < items.length;
    return { revision: data.revision, items, page, hasMore, nextCursor: hasMore ? encodeTaskCursor(page[page.length - 1]) : null };
  }

  async transition(taskId, next, reason = '', details = {}) {
    return this._mutate((data) => {
      const current = data.tasks[taskId];
      if (!current) throw new Error(`task not found: ${taskId}`);
      if (LEASED_STATES.has(current.state)) {
        throw new Error('active task transitions require an owned lease');
      }
      const updated = transitionTask(current, next, reason, this._now().ms, details);
      if (ACTIVE_STATES.has(next)) throw new Error('active task transitions require an owned lease');
      data.tasks[taskId] = updated;
      return updated;
    });
  }

  async transitionIfRevision(taskId, next, { expectedRevision, reason = '', details = {} } = {}) {
    return this._mutate((data) => {
      const current = data.tasks[taskId];
      if (!current) throw new Error(`task not found: ${taskId}`);
      if (LEASED_STATES.has(current.state)) throw new Error('active task transitions require an owned lease');
      const updated = transitionTask(current, next, reason, this._now().ms, details);
      if (ACTIVE_STATES.has(next)) throw new Error('active task transitions require an owned lease');
      data.tasks[taskId] = updated;
      return updated;
    }, { expectedRevision });
  }

  async transitionOwned(taskId, next, workerId, fencingToken, reason = '', details = {}) {
    if (typeof workerId !== 'string' || !workerId) throw new TypeError('workerId is required');
    if (typeof fencingToken !== 'string' || !fencingToken) throw new TypeError('fencingToken is required');
    return this._mutate((data) => {
      const current = data.tasks[taskId];
      if (!current) throw new Error(`task not found: ${taskId}`);
      const { ms } = this._now();
      if (!LEASED_STATES.has(current.state) || current.lease?.workerId !== workerId || current.lease?.fencingToken !== fencingToken) throw new Error('task lease is not owned by worker');
      if (isLeaseExpired(current.lease, ms)) throw new Error('task lease expired');
      const updated = transitionTask(current, next, reason, ms, details);
      data.tasks[taskId] = updated;
      return updated;
    });
  }

  async claim(workerId, { ttlMs = this.defaultLeaseTtlMs, taskId = null } = {}) {
    if (typeof workerId !== 'string' || !workerId) throw new TypeError('workerId is required');
    const ttl = this._ttl(ttlMs);
    return this._mutate((data) => {
      const { ms, iso } = this._now();
      for (const task of Object.values(data.tasks)) {
        if (task.state === 'cancelling' && isLeaseExpired(task.lease, ms)) {
          data.tasks[task.taskId] = transitionTask(task, 'cancelled', 'cancellation lease expired', ms, { recovery: true });
        } else if (ACTIVE_STATES.has(task.state) && isLeaseExpired(task.lease, ms) && task.attempts >= task.maxAttempts) {
          const failed = transitionTask(task, 'failed', 'lease expired after max attempts', ms, { recovery: true, attempts: task.attempts });
          failed.error = 'worker lease expired after max attempts';
          data.tasks[task.taskId] = failed;
        }
      }
      const candidates = Object.values(data.tasks).filter((task) => {
        if (taskId !== null && task.taskId !== taskId) return false;
        if (task.state === 'queued') return !task.nextRetryAt || Date.parse(task.nextRetryAt) <= ms;
        return ACTIVE_STATES.has(task.state) && isLeaseExpired(task.lease, ms);
      }).filter((task) => task.attempts < task.maxAttempts || (task.state === 'queued' && task.resumePending === true))
        .sort((a, b) => b.priority - a.priority || a.createdAt.localeCompare(b.createdAt) || a.taskId.localeCompare(b.taskId));
      const task = candidates[0];
      if (!task) return null;
      const recovered = task.state !== 'queued';
      const next = 'preparing';
      const continuingPausedAttempt = task.state === 'queued' && task.resumePending === true;
      const attempts = task.attempts + (continuingPausedAttempt ? 0 : 1);
      const updated = transitionTask(task, next, recovered ? 'lease reclaimed' : 'claimed', ms, {
        workerId,
        attempts,
        ...(continuingPausedAttempt ? { resumed: true } : {}),
        ...(recovered ? { recovery: true, previousWorkerId: task.lease?.workerId ?? null } : {}),
      });
      updated.attempts = attempts;
      updated.resumePending = false;
      updated.lease = { workerId, fencingToken: randomUUID(), heartbeatAt: iso, expiresAt: new Date(ms + ttl).toISOString(), ttlMs: ttl, sequence: 1 };
      updated.nextRetryAt = null;
      data.tasks[task.taskId] = updated;
      return updated;
    });
  }

  async heartbeat(taskId, workerId, { ttlMs = this.defaultLeaseTtlMs, fencingToken } = {}) {
    const ttl = this._ttl(ttlMs);
    if (typeof fencingToken !== 'string' || !fencingToken) throw new TypeError('fencingToken is required');
    return this._mutate((data) => {
      const task = data.tasks[taskId];
      if (!task) throw new Error(`task not found: ${taskId}`);
      if (!ACTIVE_STATES.has(task.state) || task.lease?.workerId !== workerId || task.lease?.fencingToken !== fencingToken) throw new Error('task lease is not owned by worker');
      const { ms, iso } = this._now();
      if (isLeaseExpired(task.lease, ms)) throw new Error('task lease expired');
      const updated = { ...task, lease: { ...task.lease, heartbeatAt: iso, expiresAt: new Date(ms + ttl).toISOString(), ttlMs: ttl, sequence: Number(task.lease.sequence || 0) + 1 } };
      data.tasks[taskId] = withHistory(updated, historyEvent(task.state, task.state, 'heartbeat', iso, { workerId }), iso);
      return data.tasks[taskId];
    });
  }

  async checkpoint(taskId, checkpoint, workerId, fencingToken) {
    const safeCheckpoint = clone(checkpoint, 'task checkpoint');
    if (typeof fencingToken !== 'string' || !fencingToken) throw new TypeError('fencingToken is required');
    return this._mutate((data) => {
      const task = data.tasks[taskId];
      if (!task) throw new Error(`task not found: ${taskId}`);
      if (!ACTIVE_STATES.has(task.state) || task.lease?.workerId !== workerId || task.lease?.fencingToken !== fencingToken) throw new Error('task lease is not owned by worker');
      const { ms, iso } = this._now();
      if (isLeaseExpired(task.lease, ms)) throw new Error('task lease expired');
      const updated = task.state === 'running' ? transitionTask(task, 'checkpointing', 'checkpoint', ms, { workerId }) : clone(task, 'task');
      updated.checkpoint = safeCheckpoint;
      updated.checkpointSeq = Number(task.checkpointSeq || 0) + 1;
      updated.checkpointedAt = iso;
      updated.lease = { ...updated.lease, heartbeatAt: iso, expiresAt: new Date(ms + updated.lease.ttlMs).toISOString(), sequence: Number(updated.lease.sequence || 0) + 1 };
      if (task.state === 'checkpointing') data.tasks[taskId] = withHistory(updated, historyEvent(task.state, task.state, 'checkpoint', iso, { workerId }), iso);
      else data.tasks[taskId] = updated;
      return data.tasks[taskId];
    });
  }

  async fail(taskId, { workerId, fencingToken, retryable = false, blocked = false, error = null, retryDelayMs } = {}) {
    return this._mutate((data) => {
      const task = data.tasks[taskId];
      if (!task) throw new Error(`task not found: ${taskId}`);
      const { ms, iso } = this._now();
      if (ACTIVE_STATES.has(task.state)) {
        if (!workerId || !fencingToken || task.lease?.workerId !== workerId || task.lease?.fencingToken !== fencingToken) throw new Error('task lease is not owned by worker');
        if (isLeaseExpired(task.lease, ms)) throw new Error('task lease expired');
      } else if (workerId && (task.lease?.workerId !== workerId || task.lease?.fencingToken !== fencingToken)) {
        throw new Error('task lease is not owned by worker');
      }
      const canRetry = retryable && task.attempts < task.maxAttempts;
      const next = blocked ? 'blocked' : canRetry ? 'queued' : 'failed';
      const updated = transitionTask(task, next, 'failed', ms, { error: error ? String(error) : null, retryable, attempts: task.attempts });
      const defaultRetryDelayMs = Math.min(DEFAULT_RETRY_DELAY_MS * (2 ** Math.max(task.attempts - 1, 0)), MAX_RETRY_DELAY_MS);
      const retryDelay = retryDelayMs === undefined
        ? defaultRetryDelayMs
        : retryDelayMs > 0 ? Math.min(Number(retryDelayMs) || 0, MAX_RETRY_DELAY_MS) : 0;
      updated.nextRetryAt = canRetry && retryDelay > 0 ? new Date(ms + retryDelay).toISOString() : null;
      updated.error = error ? String(error).slice(0, 2000) : null;
      data.tasks[taskId] = updated;
      return updated;
    });
  }

  async cancel(taskId, reason = 'cancelled') {
    return this._mutate((data) => {
      const task = data.tasks[taskId];
      if (!task) throw new Error(`task not found: ${taskId}`);
      if (task.state === 'cancelling' || TERMINAL_STATES.has(task.state)) return task;
      const { ms } = this._now();
      const next = ACTIVE_STATES.has(task.state) ? 'cancelling' : 'cancelled';
      const updated = transitionTask(task, next, reason, ms);
      data.tasks[taskId] = updated;
      return updated;
    });
  }

  async cancelIfRevision(taskId, reason = 'cancelled', expectedRevision) {
    return this._mutate((data) => {
      const task = data.tasks[taskId];
      if (!task) throw new Error(`task not found: ${taskId}`);
      if (task.state === 'cancelling' || TERMINAL_STATES.has(task.state)) return task;
      const { ms } = this._now();
      const next = ACTIVE_STATES.has(task.state) ? 'cancelling' : 'cancelled';
      const updated = transitionTask(task, next, reason, ms);
      data.tasks[taskId] = updated;
      return updated;
    }, { expectedRevision });
  }

  async pauseIfRevision(taskId, reason = 'paused', expectedRevision) {
    return this._mutate((data) => {
      const task = data.tasks[taskId];
      if (!task) throw new Error(`task not found: ${taskId}`);
      if (task.state === 'paused') return task;
      if (task.state !== 'queued' && !ACTIVE_STATES.has(task.state)) {
        throw new Error(`task cannot be paused from ${task.state}`);
      }
      const updated = transitionTask(task, 'paused', reason, this._now().ms);
      data.tasks[taskId] = updated;
      return updated;
    }, { expectedRevision });
  }

  async finishCancellation(taskId, reason = 'cancelled', workerId, fencingToken) {
    if (typeof workerId !== 'string' || !workerId || typeof fencingToken !== 'string' || !fencingToken) {
      throw new TypeError('workerId and fencingToken are required');
    }
    return this.transitionOwned(taskId, 'cancelled', workerId, fencingToken, reason);
  }

  async resume(taskId, reason = 'resumed') {
    return this._mutate((data) => {
      const task = data.tasks[taskId];
      if (!task) throw new Error(`task not found: ${taskId}`);
      if (task.state === 'failed' && task.attempts >= task.maxAttempts) throw new Error('task reached max attempts and cannot resume');
      const updated = transitionTask(task, 'queued', reason, this._now().ms);
      data.tasks[taskId] = updated;
      return updated;
    });
  }

  async resumeIfRevision(taskId, reason = 'resumed', expectedRevision) {
    return this._mutate((data) => {
      const task = data.tasks[taskId];
      if (!task) throw new Error(`task not found: ${taskId}`);
      if (task.state === 'failed' && task.attempts >= task.maxAttempts) throw new Error('task reached max attempts and cannot resume');
      const updated = transitionTask(task, 'queued', reason, this._now().ms);
      data.tasks[taskId] = updated;
      return updated;
    }, { expectedRevision });
  }
}
