import { randomUUID } from 'node:crypto';

const TERMINAL_OUTCOMES = new Set(['succeeded', 'partial', 'blocked']);
const SUCCESS_OUTCOMES = new Set(['success', 'succeeded', 'complete', 'completed', 'ok']);
const DEFAULT_MAX_HANDLER_RUNTIME_MS = 30 * 60_000;

function jsonValue(value) {
  try {
    const text = JSON.stringify(value);
    if (text === undefined) return undefined;
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function positiveInteger(value, fallback, name, maximum = 86_400_000) {
  const number = Number(value ?? fallback);
  if (!Number.isInteger(number) || number < 1 || number > maximum) {
    throw new RangeError(`${name} must be an integer in the range 1..${maximum}`);
  }
  return number;
}

function normalizeStatus(value) {
  if (typeof value !== 'string') return null;
  const status = value.toLowerCase();
  if (SUCCESS_OUTCOMES.has(status)) return 'succeeded';
  if (TERMINAL_OUTCOMES.has(status)) return status;
  if (status === 'failed' || status === 'failure' || status === 'error') return 'failed';
  return null;
}

function normalizeOutcome(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return { status: 'succeeded', result: value };
  }
  const status = normalizeStatus(value.status ?? value.state ?? value.outcome ?? value.resultState);
  const hasStatusField = ['status', 'state', 'outcome', 'resultState']
    .some((field) => Object.prototype.hasOwnProperty.call(value, field));
  if (!status && hasStatusField) {
    throw new Error(`unknown handler outcome status: ${String(value.status ?? value.state ?? value.outcome ?? value.resultState)}`);
  }
  if (!status) return { status: 'succeeded', result: value };
  return {
    status,
    result: value.result,
    checkpoint: value.checkpoint,
    error: value.error,
    reason: value.reason,
    retryable: value.retryable === true,
    retryDelayMs: value.retryDelayMs,
  };
}

function normalizeError(error) {
  if (error && typeof error === 'object') {
    const status = normalizeStatus(error.status ?? error.state ?? error.outcome);
    return {
      status: status === 'succeeded' ? 'failed' : status || 'failed',
      error: error.error ?? error.message ?? String(error),
      reason: error.reason,
      retryable: error.retryable === true,
      retryDelayMs: error.retryDelayMs,
      blocked: error.blocked === true,
    };
  }
  return { status: 'failed', error: String(error), retryable: false };
}

/**
 * Error type for handlers that need to select a persisted terminal outcome.
 * Plain thrown errors become non-retryable failed tasks.
 */
export class TaskWorkerError extends Error {
  constructor(message, options = {}) {
    super(String(message));
    this.name = 'TaskWorkerError';
    Object.assign(this, options);
  }
}

/**
 * Persistent task runner. A stopped runner intentionally leaves active leases
 * untouched so another worker can reclaim them after the lease expires.
 */
export class TaskWorker {
  constructor(options = {}) {
    const { store, workerId = `worker-${randomUUID()}`, handlers = {}, onEvent = null,
      concurrency = 1, leaseTtlMs, heartbeatIntervalMs, pollIntervalMs = 250,
      maxHandlerRuntimeMs = DEFAULT_MAX_HANDLER_RUNTIME_MS } = options;
    if (!store || typeof store.claim !== 'function' || typeof store.transitionOwned !== 'function') {
      throw new TypeError('a compatible task state store is required');
    }
    if (typeof workerId !== 'string' || !workerId) throw new TypeError('workerId is required');
    if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 1024) {
      throw new RangeError('concurrency must be an integer in the range 1..1024');
    }
    if (typeof onEvent !== 'function' && onEvent !== null) throw new TypeError('onEvent must be a function');
    this.store = store;
    this.workerId = workerId;
    this.concurrency = concurrency;
    this.leaseTtlMs = positiveInteger(leaseTtlMs ?? store.defaultLeaseTtlMs ?? 45_000, 45_000, 'leaseTtlMs');
    this.heartbeatIntervalMs = heartbeatIntervalMs === undefined
      ? Math.max(1, Math.floor(this.leaseTtlMs / 3))
      : positiveInteger(heartbeatIntervalMs, 1, 'heartbeatIntervalMs');
    if (this.heartbeatIntervalMs >= this.leaseTtlMs) throw new RangeError('heartbeatIntervalMs must be less than leaseTtlMs');
    this.pollIntervalMs = positiveInteger(pollIntervalMs, 250, 'pollIntervalMs');
    this.maxHandlerRuntimeMs = positiveInteger(maxHandlerRuntimeMs, DEFAULT_MAX_HANDLER_RUNTIME_MS, 'maxHandlerRuntimeMs');
    this.onEvent = onEvent;
    this.handlers = new Map();
    this.active = new Map();
    this.running = false;
    this.stopping = false;
    this._loopPromise = null;
    this._pollTimer = null;
    this._wake = null;
    this._generation = 0;
    this._pumpPromise = null;
    for (const [type, handler] of Object.entries(handlers)) this.register(type, handler);
  }

  register(type, handler) {
    if (typeof type !== 'string' || !type) throw new TypeError('handler type is required');
    if (typeof handler !== 'function') throw new TypeError(`handler for ${type} must be a function`);
    this.handlers.set(type, handler);
    this._wake?.();
    return this;
  }

  registerHandler(type, handler) {
    return this.register(type, handler);
  }

  unregister(type) {
    this.handlers.delete(type);
    return this;
  }

  unregisterHandler(type) {
    return this.unregister(type);
  }

  handlerTypes() {
    return [...this.handlers.keys()];
  }

  start() {
    if (this.running) return this;
    if (this.active.size > 0 || this._pumpPromise) throw new Error('cannot restart while previous task executions or claims are active');
    this.stopping = false;
    this.running = true;
    const generation = ++this._generation;
    this._emit('started', { workerId: this.workerId });
    if (this.running && generation === this._generation) this._loopPromise = this._runLoop(generation);
    return this;
  }

  async stop({ abort = true, wait = false, timeoutMs = 10_000 } = {}) {
    if (!this.running && this.active.size === 0 && !this._pumpPromise) return this;
    this.stopping = true;
    this.running = false;
    this._generation += 1;
    this._wake?.();
    this._loopPromise = null;
    for (const entry of this.active.values()) {
      clearInterval(entry.heartbeatTimer);
      if (abort) entry.controller.abort(new Error('worker stopped'));
    }
    if (wait) await this.waitForIdle({ timeoutMs });
    this._emit('stopped', { workerId: this.workerId, active: this.active.size });
    return this;
  }

  async runOnce() {
    const claimed = await this._pumpOnce();
    return { claimed, active: [...this.active.keys()] };
  }

  async waitForIdle({ timeoutMs = 10_000 } = {}) {
    const timeout = positiveInteger(timeoutMs, 10_000, 'timeoutMs');
    const deadline = Date.now() + timeout;
    while (this.active.size > 0 || this._pumpPromise) {
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw new Error('timed out waiting for task worker to become idle');
      const promises = [...this.active.values()].map((entry) => Promise.resolve(entry.promise).catch(() => {}));
      if (this._pumpPromise) promises.push(this._pumpPromise.catch(() => {}));
      await Promise.race([Promise.all(promises), delay(Math.min(remaining, 25))]);
    }
    return this;
  }

  async _runLoop(generation) {
    try {
      while (this.running && generation === this._generation) {
        try {
          await this._pumpOnce();
        } catch (error) {
          this._emit('error', { error: error instanceof Error ? error.message : String(error) });
        }
        if (!this.running || generation !== this._generation) break;
        await new Promise((resolve) => {
          let timer;
          const wake = () => {
            clearTimeout(timer);
            if (this._pollTimer === timer) this._pollTimer = null;
            if (this._wake === wake) this._wake = null;
            resolve();
          };
          this._wake = wake;
          timer = setTimeout(wake, this.pollIntervalMs);
          this._pollTimer = timer;
        });
      }
    } finally {
      if (generation === this._generation) {
        this.running = false;
        this._loopPromise = null;
      }
    }
  }

  async _candidateTasks(limit) {
    const candidates = [];
    const candidateLimit = Math.max(limit * 2, 8);
    const pageSize = Math.min(1000, Math.max(candidateLimit, 128));
    const clock = typeof this.store.clock === 'function' ? this.store.clock() : Date.now();
    const now = new Date(clock).getTime();
    for (const state of ['queued', 'preparing', 'running', 'checkpointing', 'cancelling']) {
      const seenPage = new Set();
      let accepted = 0;
      for (let offset = 0; !this.stopping && accepted < candidateLimit; offset += pageSize) {
        const tasks = await this.store.list({ state, limit: pageSize, offset });
        let unseen = 0;
        for (const task of tasks) {
          if (seenPage.has(task.taskId)) continue;
          seenPage.add(task.taskId);
          unseen += 1;
          if ((!this.handlers.has(task.type) && state !== 'cancelling') || this.active.has(task.taskId)) continue;
          if (task.state === 'queued') {
            if (task.nextRetryAt && Date.parse(task.nextRetryAt) > now) continue;
            if (task.attempts >= task.maxAttempts && task.resumePending !== true) continue;
          } else if (task.lease && Date.parse(task.lease.expiresAt) > now) continue;
          candidates.push(task);
          accepted += 1;
          if (accepted >= candidateLimit) break;
        }
        // Older compatible stores may ignore offset; do not loop on their first page.
        if (!unseen || tasks.length < pageSize) break;
      }
    }
    const seen = new Set();
    return candidates.filter((task) => {
      if (seen.has(task.taskId) || this.active.has(task.taskId)) return false;
      seen.add(task.taskId);
      return true;
    }).sort((a, b) => b.priority - a.priority || a.createdAt.localeCompare(b.createdAt));
  }

  async _pumpOnce() {
    if (this._pumpPromise) {
      await this._pumpPromise;
      return 0;
    }
    const pump = this._pumpAvailable();
    this._pumpPromise = pump;
    try {
      return await pump;
    } finally {
      if (this._pumpPromise === pump) this._pumpPromise = null;
    }
  }

  async _pumpAvailable() {
    if (this.stopping) return 0;
    const slots = this.concurrency - this.active.size;
    if (slots <= 0) return 0;
    const candidates = await this._candidateTasks(slots);
    let claimed = 0;
    for (const candidate of candidates) {
      if (this.stopping || this.active.size >= this.concurrency) break;
      const handler = this.handlers.get(candidate.type);
      if (!handler && candidate.state !== 'cancelling') continue;
      let task;
      try {
        task = await this.store.claim(this.workerId, { ttlMs: this.leaseTtlMs, taskId: candidate.taskId });
      } catch (error) {
        this._emit('error', { taskId: candidate.taskId, error: error instanceof Error ? error.message : String(error) });
        continue;
      }
      if (!task) continue;
      claimed += 1;
      const entry = { task, handler, controller: new AbortController(), fencingToken: task.lease?.fencingToken ?? null, promise: null, leaseLost: false, finalized: false, finalizing: false, operation: Promise.resolve(), heartbeatPromise: null };
      this.active.set(task.taskId, entry);
      entry.promise = Promise.resolve().then(() => this._execute(entry)).catch((error) => {
        this._emit('error', { taskId: task.taskId, error: error instanceof Error ? error.message : String(error) });
      }).finally(() => {
        if (this.active.get(task.taskId) === entry) this.active.delete(task.taskId);
        this._wake?.();
      });
    }
    return claimed;
  }

  _tokenOptions(entry) {
    return entry.fencingToken ? { fencingToken: entry.fencingToken } : {};
  }

  async _ownedTransition(entry, next, reason, details = {}) {
    return this._withEntryLock(entry, () => {
      this._assertActive(entry);
      return this._transitionOwned(entry, next, reason, details);
    });
  }

  _withEntryLock(entry, operation) {
    const promise = entry.operation.then(operation);
    entry.operation = promise.catch(() => {});
    return promise;
  }

  _assertActive(entry) {
    if (this.stopping || entry.leaseLost || entry.finalized || entry.controller.signal.aborted) throw new Error('task worker is no longer active');
  }

  async _transitionOwned(entry, next, reason, details = {}) {
    if (typeof entry.fencingToken !== 'string' || !entry.fencingToken) throw new Error('task lease fencing token is missing');
    const task = await this.store.transitionOwned(entry.task.taskId, next, this.workerId, entry.fencingToken, reason, details);
    entry.task = task;
    entry.fencingToken = task.lease?.fencingToken ?? entry.fencingToken;
    if (!task.lease) {
      entry.finalized = true;
      clearInterval(entry.heartbeatTimer);
    }
    return task;
  }

  async _heartbeat(entry) {
    const timeoutPending = Boolean(entry.timeoutError);
    if (this.stopping || entry.leaseLost || entry.finalized || entry.finalizing || (entry.controller.signal.aborted && !timeoutPending)) return null;
    if (entry.heartbeatPromise) return entry.heartbeatPromise;
    entry.heartbeatPromise = this._withEntryLock(entry, async () => {
      if (this.stopping || entry.leaseLost || entry.finalized || entry.finalizing || (entry.controller.signal.aborted && !entry.timeoutError)) return null;
      try {
        const task = await this.store.heartbeat(entry.task.taskId, this.workerId, { ttlMs: this.leaseTtlMs, ...this._tokenOptions(entry) });
        entry.task = task;
        entry.fencingToken = task.lease?.fencingToken ?? entry.fencingToken;
        this._emit('heartbeat', { taskId: task.taskId, task });
        return task;
      } catch (error) {
        const cancelled = await this._finishCancellationOwned(entry);
        if (cancelled) return cancelled;
        entry.leaseLost = true;
        clearInterval(entry.heartbeatTimer);
        entry.controller.abort(error);
        this._emit('lease-lost', { taskId: entry.task.taskId, error: error instanceof Error ? error.message : String(error) });
        return null;
      }
    }).finally(() => { entry.heartbeatPromise = null; });
    return entry.heartbeatPromise;
  }

  async _checkpoint(entry, value) {
    return this._withEntryLock(entry, () => {
      this._assertActive(entry);
      return this._checkpointOwned(entry, value);
    });
  }

  async _checkpointOwned(entry, value) {
    if (typeof entry.fencingToken !== 'string' || !entry.fencingToken) throw new Error('task lease fencing token is missing');
    let task = await this.store.checkpoint(entry.task.taskId, value, this.workerId, entry.fencingToken);
    entry.task = task;
    entry.fencingToken = task.lease?.fencingToken ?? entry.fencingToken;
    if (task.state === 'checkpointing') task = await this._transitionOwned(entry, 'running', 'checkpoint complete', { workerId: this.workerId });
    this._emit('checkpoint', { taskId: task.taskId, task, checkpoint: value });
    return task;
  }

  _context(entry) {
    return {
      get task() { return entry.task; },
      payload: entry.task.payload,
      get lastCheckpoint() { return entry.task.checkpoint; },
      signal: entry.controller.signal,
      workerId: this.workerId,
      heartbeat: () => this._heartbeat(entry),
      checkpoint: (value) => this._checkpoint(entry, value),
      transition: (next, reason = '', details = {}) => this._ownedTransition(entry, next, reason, details),
      emit: (type, data = {}) => this._emit(type, { taskId: entry.task.taskId, ...data }),
    };
  }

  async _runHandler(entry) {
    let timer;
    const clearTimerOnAbort = () => {
      if (!entry.timeoutError) clearTimeout(timer);
    };
    entry.controller.signal.addEventListener('abort', clearTimerOnAbort, { once: true });
    const handlerPromise = Promise.resolve().then(() => entry.handler(entry.task.payload, this._context(entry)));
    const timedOut = new Promise((resolve) => {
      timer = setTimeout(() => {
        const error = new TaskWorkerError(`handler timed out after ${this.maxHandlerRuntimeMs} ms`, {
          timedOut: true,
          retryable: true,
        });
        entry.timeoutError = error;
        entry.controller.abort(error);
        resolve({ timedOut: true, error, handlerPromise });
      }, this.maxHandlerRuntimeMs);
    });
    try {
      const result = await Promise.race([
        handlerPromise.then((value) => ({ value }), (error) => ({ error })),
        timedOut,
      ]);
      if (entry.timeoutError) return { timedOut: true, error: entry.timeoutError, handlerPromise };
      if (Object.hasOwn(result, 'error')) throw result.error;
      return { value: result.value, handlerPromise };
    } finally {
      clearTimeout(timer);
      entry.controller.signal.removeEventListener('abort', clearTimerOnAbort);
    }
  }

  _details(outcome) {
    const details = { workerId: this.workerId, outcome: outcome.status };
    const result = jsonValue(outcome.result);
    if (result !== undefined) details.result = result;
    if (outcome.error !== undefined && outcome.error !== null) details.error = String(outcome.error).slice(0, 2000);
    if (outcome.retryable === true) details.retryable = true;
    return details;
  }

  async _finishCancellation(entry) {
    return this._withEntryLock(entry, () => this._finishCancellationOwned(entry));
  }

  async _finishCancellationOwned(entry) {
    if (entry.finalized) return entry.task.state === 'cancelled' ? entry.task : null;
    const current = await this.store.get(entry.task.taskId).catch(() => null);
    if (current?.state === 'cancelled') {
      entry.task = current;
      entry.finalized = true;
      clearInterval(entry.heartbeatTimer);
      entry.controller.abort(new Error('task cancelled'));
      return current;
    }
    if (current?.state !== 'cancelling') return null;
    if (typeof entry.fencingToken !== 'string' || !entry.fencingToken) return null;
    try {
      const cancelled = await this._transitionOwned(entry, 'cancelled', 'worker observed cancellation');
      entry.task = cancelled;
      entry.finalized = true;
      clearInterval(entry.heartbeatTimer);
      entry.controller.abort(new Error('task cancelled'));
      this._emit('cancelled', { taskId: cancelled.taskId, task: cancelled });
      return cancelled;
    } catch (error) {
      this._emit('error', { taskId: entry.task.taskId, error: error instanceof Error ? error.message : String(error) });
      return null;
    }
  }

  async _applyOutcome(entry, outcome, { allowRuntimeTimeout = false } = {}) {
    entry.finalizing = true;
    return this._withEntryLock(entry, async () => {
      if (allowRuntimeTimeout && entry.timeoutError) {
        if (entry.leaseLost || entry.finalized) throw new Error('task worker is no longer active');
      } else {
        this._assertActive(entry);
      }
      if (outcome.checkpoint !== undefined) await this._checkpointOwned(entry, outcome.checkpoint);
      if (outcome.status === 'failed') {
        const task = await this.store.fail(entry.task.taskId, {
          workerId: this.workerId,
          retryable: outcome.retryable === true,
          error: outcome.error ?? 'handler failed',
          retryDelayMs: outcome.retryDelayMs,
          ...this._tokenOptions(entry),
        });
        entry.task = task;
        entry.finalized = !task.lease;
        clearInterval(entry.heartbeatTimer);
        this._emit('failed', { taskId: task.taskId, task, error: task.error });
        return task;
      }
      const task = await this._transitionOwned(entry, outcome.status, outcome.reason || `handler ${outcome.status}`, this._details(outcome));
      this._emit(outcome.status, { taskId: task.taskId, task, result: outcome.result });
      return task;
    });
  }

  async _execute(entry) {
    const handler = entry.handler;
    if (!handler) return null;
    let heartbeatTimer;
    try {
      this._emit('claimed', { taskId: entry.task.taskId, task: entry.task });
      if (this.stopping) return null;
      await this._ownedTransition(entry, 'running', 'handler started', { workerId: this.workerId });
      if (this.stopping || entry.leaseLost || entry.controller.signal.aborted) {
        this._emit('stopped-task', { taskId: entry.task.taskId });
        return null;
      }
      this._emit('running', { taskId: entry.task.taskId, task: entry.task });
      this._assertActive(entry);
      heartbeatTimer = setInterval(() => { void this._heartbeat(entry); }, this.heartbeatIntervalMs);
      entry.heartbeatTimer = heartbeatTimer;
      const execution = await this._runHandler(entry);
      if (execution.timedOut) {
        // Keep ownership until an in-process handler has actually stopped. A
        // handler that ignores abort must not be retried concurrently elsewhere.
        await execution.handlerPromise.catch(() => {});
        const cancelled = await this._finishCancellation(entry);
        if (cancelled) return cancelled;
        if (entry.leaseLost || entry.finalized) {
          this._emit('stopped-task', { taskId: entry.task.taskId });
          return null;
        }
        const outcome = {
          status: 'failed',
          error: execution.error.message,
          retryable: true,
        };
        const task = await this._applyOutcome(entry, outcome, { allowRuntimeTimeout: true });
        this._emit('timeout', { taskId: task.taskId, task, timeoutMs: this.maxHandlerRuntimeMs, error: execution.error.message });
        return task;
      }
      const value = execution.value;
      const cancelled = await this._finishCancellation(entry);
      if (cancelled) return cancelled;
      if (this.stopping || entry.leaseLost || entry.finalized || entry.controller.signal.aborted) {
        this._emit('stopped-task', { taskId: entry.task.taskId });
        return null;
      }
      const outcome = normalizeOutcome(value);
      return await this._applyOutcome(entry, outcome);
    } catch (error) {
      const cancelled = await this._finishCancellation(entry);
      if (cancelled) return cancelled;
      if (this.stopping || entry.leaseLost || entry.finalized || entry.controller.signal.aborted) {
        this._emit('stopped-task', { taskId: entry.task.taskId });
        return null;
      }
      const outcome = normalizeError(error);
      if (outcome.blocked) outcome.status = 'blocked';
      this._emit('handler-error', { taskId: entry.task.taskId, error: outcome.error, status: outcome.status });
      try {
        return await this._applyOutcome(entry, outcome);
      } catch (applyError) {
        this._emit('error', { taskId: entry.task.taskId, error: applyError instanceof Error ? applyError.message : String(applyError) });
        return null;
      }
    } finally {
      if (heartbeatTimer) clearInterval(heartbeatTimer);
    }
  }

  _emit(type, data = {}) {
    if (!this.onEvent) return;
    const event = { type, at: new Date().toISOString(), workerId: this.workerId, ...data };
    try {
      const result = this.onEvent(event);
      if (result && typeof result.then === 'function') result.catch(() => {});
    } catch {
      // Event observers must not be able to stop task execution.
    }
  }
}

export default TaskWorker;
