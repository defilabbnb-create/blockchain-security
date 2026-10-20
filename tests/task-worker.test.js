import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { TaskStateStore } from '../src/task-state.js';
import { TaskWorker, TaskWorkerError } from '../src/task-worker.js';

async function fixture({ now = Date.parse('2026-01-01T00:00:00.000Z'), ttl = 100 } = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'task-worker-'));
  let current = now;
  const store = new TaskStateStore({ path: join(dir, 'tasks.json'), clock: () => current, defaultLeaseTtlMs: ttl });
  return {
    dir,
    store,
    setNow(value) { current = value instanceof Date ? value.getTime() : value; },
    now() { return current; },
    async cleanup() { await rm(dir, { recursive: true, force: true }); },
  };
}

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

async function eventually(predicate, timeoutMs = 1000) {
  const deadline = Date.now() + timeoutMs;
  while (!await predicate()) {
    if (Date.now() >= deadline) throw new Error('condition did not become true');
    await new Promise((resolve) => setTimeout(resolve, 2));
  }
}

test('worker claims a task, checkpoints, and persists a successful outcome', async () => {
  const f = await fixture();
  const events = [];
  try {
    await f.store.create({ taskId: 'success', type: 'unit', payload: { value: 4 } });
    const worker = new TaskWorker({
      store: f.store,
      workerId: 'worker-success',
      heartbeatIntervalMs: 20,
      onEvent: (event) => events.push(event.type),
      handlers: {
        unit: async (payload, context) => {
          assert.deepEqual(payload, { value: 4 });
          assert.equal(context.task.checkpoint, null);
          await context.checkpoint({ offset: 4 });
          return { status: 'succeeded', result: { scanned: payload.value } };
        },
      },
    });
    assert.deepEqual(await worker.runOnce(), { claimed: 1, active: ['success'] });
    await worker.waitForIdle();
    const task = await f.store.get('success');
    assert.equal(task.state, 'succeeded');
    assert.deepEqual(task.checkpoint, { offset: 4 });
    assert.deepEqual(task.history.map((entry) => entry.to), ['queued', 'preparing', 'running', 'checkpointing', 'running', 'succeeded']);
    assert.ok(events.includes('claimed'));
    assert.ok(events.includes('checkpoint'));
    assert.ok(events.includes('succeeded'));
  } finally {
    await f.cleanup();
  }
});

test('worker enforces concurrency and leaves unsupported task types queued', async () => {
  const f = await fixture();
  try {
    for (const taskId of ['a', 'b', 'c']) await f.store.create({ taskId, type: 'slow' });
    await f.store.create({ taskId: 'unsupported', type: 'other' });
    let active = 0;
    let maximum = 0;
    const worker = new TaskWorker({
      store: f.store,
      workerId: 'worker-concurrent',
      concurrency: 2,
      heartbeatIntervalMs: 20,
      handlers: {
        slow: async () => {
          active += 1;
          maximum = Math.max(maximum, active);
          await new Promise((resolve) => setTimeout(resolve, 5));
          active -= 1;
          return { status: 'success' };
        },
      },
    });
    assert.equal((await worker.runOnce()).claimed, 2);
    await worker.waitForIdle();
    assert.equal(maximum, 2);
    assert.equal((await worker.runOnce()).claimed, 1);
    await worker.waitForIdle();
    assert.equal((await f.store.get('unsupported')).state, 'queued');
    assert.deepEqual((await f.store.list({ state: 'succeeded' })).map((task) => task.taskId).sort(), ['a', 'b', 'c']);
  } finally {
    await f.cleanup();
  }
});

test('worker maps partial, blocked, and retryable handler results to task states', async () => {
  const f = await fixture();
  try {
    await f.store.create({ taskId: 'partial', type: 'partial' });
    await f.store.create({ taskId: 'blocked', type: 'blocked' });
    await f.store.create({ taskId: 'retry', type: 'retry', maxAttempts: 2 });
    const worker = new TaskWorker({
      store: f.store,
      workerId: 'worker-outcomes',
      concurrency: 3,
      handlers: {
        partial: () => ({ status: 'partial', reason: 'incomplete evidence', checkpoint: { phase: 'partial' } }),
        blocked: () => { throw new TaskWorkerError('needs review', { status: 'blocked' }); },
        retry: () => ({ status: 'failed', error: 'temporary dependency', retryable: true }),
      },
    });
    assert.equal((await worker.runOnce()).claimed, 3);
    await worker.waitForIdle();
    const partial = await f.store.get('partial');
    assert.equal(partial.state, 'partial');
    assert.deepEqual(partial.checkpoint, { phase: 'partial' });
    assert.equal((await f.store.get('blocked')).state, 'blocked');
    const retry = await f.store.get('retry');
    assert.equal(retry.state, 'queued');
    assert.equal(retry.attempts, 1);
    assert.equal(retry.error, 'temporary dependency');
  } finally {
    await f.cleanup();
  }
});

test('stopping a worker aborts handlers without finalizing the lease, allowing recovery', async () => {
  const start = Date.parse('2026-02-01T00:00:00.000Z');
  const f = await fixture({ now: start, ttl: 20 });
  try {
    await f.store.create({ taskId: 'recover', type: 'hang' });
    const worker = new TaskWorker({ store: f.store, workerId: 'worker-old', leaseTtlMs: 20, heartbeatIntervalMs: 5, handlers: {
      hang: (_payload, { signal }) => new Promise((resolve, reject) => {
        signal.addEventListener('abort', () => reject(signal.reason), { once: true });
      }),
    } });
    assert.equal((await worker.runOnce()).claimed, 1);
    await worker.stop({ wait: true });
    const retained = await f.store.get('recover');
    assert.equal(retained.state, 'running');
    assert.equal(retained.lease.workerId, 'worker-old');
    f.setNow(start + 20);
    const replacement = await f.store.claim('worker-new');
    assert.equal(replacement.taskId, 'recover');
    assert.equal(replacement.lease.workerId, 'worker-new');
    assert.equal(replacement.attempts, 2);
  } finally {
    await f.cleanup();
  }
});

test('worker resumes a persisted checkpoint after lease recovery', async () => {
  const start = Date.parse('2026-02-01T00:00:00.000Z');
  const f = await fixture({ now: start, ttl: 20 });
  const started = deferred();
  const checkpoint = { phase: 'static', cursor: 7 };
  let oldWorker;
  let newWorker;
  let recovered = null;
  try {
    await f.store.create({ taskId: 'recover-checkpoint', type: 'resume' });
    oldWorker = new TaskWorker({
      store: f.store,
      workerId: 'old-checkpoint',
      leaseTtlMs: 20,
      heartbeatIntervalMs: 5,
      handlers: {
        resume: async (_payload, context) => {
          await context.checkpoint(checkpoint);
          started.resolve();
          await new Promise((resolve, reject) => {
            context.signal.addEventListener('abort', () => reject(context.signal.reason), { once: true });
          });
        },
      },
    });
    assert.equal((await oldWorker.runOnce()).claimed, 1);
    await started.promise;
    await oldWorker.stop({ wait: true });

    const interrupted = await f.store.get('recover-checkpoint');
    assert.equal(interrupted.state, 'running');
    assert.deepEqual(interrupted.checkpoint, checkpoint);

    f.setNow(start + 20);
    newWorker = new TaskWorker({
      store: f.store,
      workerId: 'new-checkpoint',
      leaseTtlMs: 20,
      heartbeatIntervalMs: 5,
      handlers: {
        resume: async (_payload, context) => {
          recovered = context.lastCheckpoint;
          return { status: 'succeeded' };
        },
      },
    });
    assert.equal((await newWorker.runOnce()).claimed, 1);
    await newWorker.waitForIdle();

    assert.deepEqual(recovered, checkpoint);
    const completed = await f.store.get('recover-checkpoint');
    assert.equal(completed.state, 'succeeded');
    assert.deepEqual(completed.checkpoint, checkpoint);
  } finally {
    await oldWorker?.stop({ wait: true });
    await newWorker?.stop({ wait: true });
    await f.cleanup();
  }
});

test('worker continues a paused checkpoint at maxAttempts without spending another attempt', async () => {
  const f = await fixture();
  try {
    await f.store.create({ taskId: 'paused-at-limit', type: 'unit', maxAttempts: 1 });
    const claimed = await f.store.claim('worker-old');
    await f.store.transitionOwned('paused-at-limit', 'running', 'worker-old', claimed.lease.fencingToken);
    await f.store.checkpoint('paused-at-limit', { phase: 'analysis', cursor: 4 }, 'worker-old', claimed.lease.fencingToken);
    await f.store.transitionOwned('paused-at-limit', 'paused', 'worker-old', claimed.lease.fencingToken);
    await f.store.resume('paused-at-limit');

    let resumedCheckpoint;
    const worker = new TaskWorker({ store: f.store, workerId: 'worker-new', handlers: {
      unit: async (_payload, context) => {
        resumedCheckpoint = context.lastCheckpoint;
        await context.checkpoint({ phase: 'analysis', cursor: 8 });
        return { status: 'succeeded' };
      },
    } });
    assert.equal((await worker.runOnce()).claimed, 1);
    await worker.waitForIdle();
    const completed = await f.store.get('paused-at-limit');
    assert.equal(completed.state, 'succeeded');
    assert.equal(completed.attempts, 1);
    assert.deepEqual(resumedCheckpoint, { phase: 'analysis', cursor: 4 });
    assert.deepEqual(completed.checkpoint, { phase: 'analysis', cursor: 8 });
  } finally {
    await f.cleanup();
  }
});

test('plain handler errors become failed tasks and explicit retry policy is honored', async () => {
  const f = await fixture();
  try {
    await f.store.create({ taskId: 'plain-error', type: 'error' });
    const worker = new TaskWorker({ store: f.store, workerId: 'worker-error', handlers: {
      error: () => { throw new Error('bad input'); },
    } });
    await worker.runOnce();
    await worker.waitForIdle();
    const task = await f.store.get('plain-error');
    assert.equal(task.state, 'failed');
    assert.equal(task.error, 'bad input');
  } finally {
    await f.cleanup();
  }
});

test('runtime timeouts abort handlers and use the task retry limit with backoff', async () => {
  const start = Date.parse('2026-02-01T00:00:00.000Z');
  const f = await fixture({ now: start });
  const events = [];
  let signal;
  let worker;
  try {
    await f.store.create({ taskId: 'runtime-timeout', type: 'wait', maxAttempts: 2 });
    worker = new TaskWorker({
      store: f.store,
      workerId: 'runtime-limited',
      maxHandlerRuntimeMs: 25,
      onEvent: (event) => events.push(event.type),
      handlers: {
        wait: async (_payload, context) => {
          signal = context.signal;
          await new Promise((resolve, reject) => {
            signal.addEventListener('abort', () => reject(signal.reason), { once: true });
          });
        },
      },
    });

    assert.equal((await worker.runOnce()).claimed, 1);
    await worker.waitForIdle();
    const firstAttempt = await f.store.get('runtime-timeout');
    assert.equal(signal.aborted, true);
    assert.equal(signal.reason.timedOut, true);
    assert.equal(firstAttempt.state, 'queued');
    assert.equal(firstAttempt.attempts, 1);
    assert.equal(firstAttempt.error, 'handler timed out after 25 ms');
    assert.equal(Date.parse(firstAttempt.nextRetryAt), start + 1000);
    assert.ok(events.includes('timeout'));

    f.setNow(start + 1000);
    assert.equal((await worker.runOnce()).claimed, 1);
    await worker.waitForIdle();
    const exhausted = await f.store.get('runtime-timeout');
    assert.equal(exhausted.state, 'failed');
    assert.equal(exhausted.attempts, 2);
    assert.equal(exhausted.error, 'handler timed out after 25 ms');
    assert.equal(exhausted.nextRetryAt, null);
  } finally {
    await worker?.stop({ wait: true });
    await f.cleanup();
  }
});

test('worker validates maxHandlerRuntimeMs bounds', () => {
  const store = { claim: async () => null, transitionOwned: async () => ({}) };
  assert.equal(new TaskWorker({ store }).maxHandlerRuntimeMs, 30 * 60_000);
  assert.equal(new TaskWorker({ store, maxHandlerRuntimeMs: 1 }).maxHandlerRuntimeMs, 1);
  assert.equal(new TaskWorker({ store, maxHandlerRuntimeMs: 86_400_000 }).maxHandlerRuntimeMs, 86_400_000);
  assert.throws(() => new TaskWorker({ store, maxHandlerRuntimeMs: 0 }), {
    name: 'RangeError',
    message: /maxHandlerRuntimeMs/,
  });
  assert.throws(() => new TaskWorker({ store, maxHandlerRuntimeMs: 86_400_001 }), {
    name: 'RangeError',
    message: /maxHandlerRuntimeMs/,
  });
});

test('runtime timeout retains its lease until an abort-ignoring handler actually settles', async () => {
  const f = await fixture({ ttl: 20 });
  const started = deferred();
  const release = deferred();
  let worker;
  let replacement;
  let context;
  try {
    await f.store.create({ taskId: 'ignored-runtime-timeout', type: 'wait', maxAttempts: 1 });
    worker = new TaskWorker({ store: f.store, leaseTtlMs: 20, heartbeatIntervalMs: 5, maxHandlerRuntimeMs: 20, handlers: {
      wait: async (_payload, value) => {
        context = value;
        started.resolve();
        await release.promise;
      },
    } });
    assert.equal((await worker.runOnce()).claimed, 1);
    await started.promise;
    await eventually(() => context.signal.aborted);
    assert.equal(context.signal.aborted, true);
    assert.equal(worker.active.size, 1);

    f.setNow(f.now() + 10);
    await eventually(async () => Date.parse((await f.store.get('ignored-runtime-timeout')).lease.expiresAt) > f.now());
    replacement = new TaskWorker({ store: f.store, workerId: 'replacement', handlers: { wait: () => ({ status: 'succeeded' }) } });
    assert.equal((await replacement.runOnce()).claimed, 0);
    assert.equal((await f.store.get('ignored-runtime-timeout')).state, 'running');

    release.resolve();
    await worker.waitForIdle();
    const task = await f.store.get('ignored-runtime-timeout');
    assert.equal(task.state, 'failed');
    assert.equal(task.error, 'handler timed out after 20 ms');
  } finally {
    release.resolve();
    await replacement?.stop({ wait: true });
    await worker?.stop({ wait: true });
    await f.cleanup();
  }
});

test('worker completes a user cancellation instead of leaving cancelling forever', async () => {
  const f = await fixture();
  try {
    await f.store.create({ taskId: 'cancel', type: 'slow-cancel' });
    const worker = new TaskWorker({ store: f.store, workerId: 'worker-cancel', handlers: {
      'slow-cancel': async () => {
        await new Promise((resolve) => setTimeout(resolve, 5));
        return { status: 'succeeded' };
      },
    } });
    await worker.runOnce();
    await f.store.cancel('cancel', 'user requested');
    await worker.waitForIdle();
    assert.equal((await f.store.get('cancel')).state, 'cancelled');
  } finally {
    await f.cleanup();
  }
});

test('heartbeat cancellation finalizes with the current fencing token', async () => {
  const f = await fixture({ ttl: 30 });
  let started;
  const startedPromise = new Promise((resolve) => { started = resolve; });
  try {
    await f.store.create({ taskId: 'heartbeat-cancel', type: 'wait' });
    const worker = new TaskWorker({
      store: f.store,
      workerId: 'worker-heartbeat-cancel',
      leaseTtlMs: 30,
      heartbeatIntervalMs: 2,
      handlers: {
        wait: async (_payload, { signal }) => {
          started();
          await new Promise((resolve, reject) => {
            signal.addEventListener('abort', () => reject(signal.reason), { once: true });
          });
          return { status: 'succeeded' };
        },
      },
    });
    assert.equal((await worker.runOnce()).claimed, 1);
    await startedPromise;
    await f.store.cancel('heartbeat-cancel', 'user requested');
    await worker.waitForIdle();
    const task = await f.store.get('heartbeat-cancel');
    assert.equal(task.state, 'cancelled');
    assert.equal(task.lease, null);
  } finally {
    await f.cleanup();
  }
});

test('unknown handler outcomes and forged success errors fail the task', async () => {
  const f = await fixture();
  try {
    await f.store.create({ taskId: 'unknown-outcome', type: 'unknown' });
    await f.store.create({ taskId: 'forged-error', type: 'forged' });
    const worker = new TaskWorker({ store: f.store, workerId: 'worker-validation', concurrency: 2, handlers: {
      unknown: () => ({ status: 'garbage', result: 'must not succeed' }),
      forged: () => { throw new TaskWorkerError('forged success', { status: 'succeeded' }); },
    } });
    assert.equal((await worker.runOnce()).claimed, 2);
    await worker.waitForIdle();
    const unknown = await f.store.get('unknown-outcome');
    const forged = await f.store.get('forged-error');
    assert.equal(unknown.state, 'failed');
    assert.match(unknown.error, /unknown handler outcome status/);
    assert.equal(forged.state, 'failed');
    assert.equal(forged.error, 'forged success');
  } finally {
    await f.cleanup();
  }
});

test('worker pages past unsupported tasks and skips delayed retries and healthy leases', async () => {
  const f = await fixture();
  let worker;
  try {
    const base = await f.store.create({ taskId: 'base', type: 'unsupported', priority: 100 });
    // Populate the store in one atomic test write to exercise a queue longer than its 1000-item cap.
    await f.store._mutate((data) => {
      for (let index = 0; index < 1005; index += 1) {
        const taskId = `unsupported-${index}`;
        data.tasks[taskId] = { ...base, taskId };
      }
      return true;
    });
    await f.store.create({ taskId: 'delayed', type: 'unit', priority: 20 });
    const delayed = await f.store.claim('previous', { taskId: 'delayed' });
    await f.store.fail('delayed', { workerId: 'previous', fencingToken: delayed.lease.fencingToken, retryable: true, retryDelayMs: 500 });
    await f.store.create({ taskId: 'leased', type: 'unit', priority: 10 });
    await f.store.claim('other-worker', { taskId: 'leased' });
    await f.store.create({ taskId: 'ready', type: 'unit' });
    worker = new TaskWorker({ store: f.store, handlers: { unit: () => ({ status: 'succeeded' }) } });
    assert.equal((await worker.runOnce()).claimed, 1);
    await worker.waitForIdle();
    assert.equal((await f.store.get('ready')).state, 'succeeded');
    assert.equal((await f.store.get('delayed')).state, 'queued');
    assert.equal((await f.store.get('leased')).lease.workerId, 'other-worker');
  } finally {
    await worker?.stop();
    await f.cleanup();
  }
});

test('concurrent runOnce calls share one claim pump and respect the concurrency limit', async () => {
  const f = await fixture();
  const release = deferred();
  let worker;
  let maximum = 0;
  let active = 0;
  try {
    for (const taskId of ['first', 'second', 'third']) await f.store.create({ taskId, type: 'unit' });
    worker = new TaskWorker({ store: f.store, concurrency: 1, handlers: { unit: async () => {
      active += 1;
      maximum = Math.max(maximum, active);
      await release.promise;
      active -= 1;
      return { status: 'succeeded' };
    } } });
    const rounds = await Promise.all(Array.from({ length: 12 }, () => worker.runOnce()));
    assert.equal(rounds.reduce((sum, result) => sum + result.claimed, 0), 1);
    assert.equal(worker.active.size, 1);
    release.resolve();
    await worker.waitForIdle();
    assert.equal(maximum, 1);
    assert.equal((await f.store.list({ state: 'queued' })).length, 2);
  } finally {
    release.resolve();
    await worker?.stop({ wait: true });
    await f.cleanup();
  }
});

test('stop waits for an in-flight claim and never launches its handler after stopping', async () => {
  const f = await fixture();
  const entered = deferred();
  const release = deferred();
  const claim = f.store.claim.bind(f.store);
  let worker;
  let executed = false;
  try {
    await f.store.create({ taskId: 'claiming', type: 'unit' });
    f.store.claim = async (...args) => { entered.resolve(); await release.promise; return claim(...args); };
    worker = new TaskWorker({ store: f.store, handlers: { unit: () => { executed = true; } } });
    const round = worker.runOnce();
    await entered.promise;
    const stopping = worker.stop({ wait: true, timeoutMs: 1000 });
    assert.throws(() => worker.start(), /claims are active/);
    release.resolve();
    await Promise.all([round, stopping]);
    assert.equal(executed, false);
    assert.equal(worker.active.size, 0);
    assert.equal((await f.store.get('claiming')).state, 'preparing');
  } finally {
    release.resolve();
    await worker?.stop({ wait: true });
    await f.cleanup();
  }
});

test('waking and restarting the loop clears poll timers and keeps one scheduler generation', async () => {
  const f = await fixture();
  const worker = new TaskWorker({ store: f.store, pollIntervalMs: 60_000 });
  try {
    worker.start();
    await eventually(() => worker._pollTimer !== null);
    const timer = worker._pollTimer;
    worker.register('unit', () => ({ status: 'succeeded' }));
    assert.equal(timer._destroyed, true);
    await eventually(() => worker._pollTimer !== null);
    const previous = worker._loopPromise;
    await worker.stop();
    worker.start();
    await previous;
    assert.equal(worker.running, true);
    assert.notEqual(worker._loopPromise, null);
    await eventually(() => worker._pollTimer !== null);
    await worker.stop({ wait: true });
    assert.equal(worker._pollTimer, null);
    assert.equal(worker._wake, null);
  } finally {
    await worker.stop({ wait: true });
    await f.cleanup();
  }
});

test('background loop recovers from a transient candidate-list error', async () => {
  const f = await fixture();
  const list = f.store.list.bind(f.store);
  const events = [];
  let fail = true;
  let worker;
  try {
    await f.store.create({ taskId: 'after-error', type: 'unit' });
    f.store.list = async (...args) => { if (fail) { fail = false; throw new Error('transient read'); } return list(...args); };
    worker = new TaskWorker({ store: f.store, pollIntervalMs: 2, onEvent: (event) => events.push(event.type), handlers: { unit: () => ({ status: 'succeeded' }) } });
    worker.start();
    await eventually(async () => (await f.store.get('after-error')).state === 'succeeded');
    assert.ok(events.includes('error'));
    assert.equal(worker.running, true);
  } finally {
    await worker?.stop({ wait: true });
    await f.cleanup();
  }
});

test('heartbeat calls coalesce and cannot overwrite a terminal result', async () => {
  const f = await fixture({ ttl: 1000 });
  const heartbeat = f.store.heartbeat.bind(f.store);
  const entered = deferred();
  const release = deferred();
  let calls = 0;
  let worker;
  const events = [];
  try {
    await f.store.create({ taskId: 'heartbeat-race', type: 'unit' });
    f.store.heartbeat = async (...args) => { calls += 1; entered.resolve(); await release.promise; return heartbeat(...args); };
    worker = new TaskWorker({ store: f.store, heartbeatIntervalMs: 100, onEvent: (event) => events.push(event.type), handlers: { unit: async (_payload, context) => {
      const beats = Array.from({ length: 12 }, () => context.heartbeat());
      await entered.promise;
      release.resolve();
      await Promise.all(beats);
      await Promise.all([context.checkpoint({ offset: 1 }), context.checkpoint({ offset: 2 })]);
      return { status: 'succeeded', result: { complete: true } };
    } } });
    await worker.runOnce();
    await worker.waitForIdle();
    const task = await f.store.get('heartbeat-race');
    assert.equal(calls, 1);
    assert.equal(task.state, 'succeeded');
    assert.equal(task.checkpointSeq, 2);
    assert.deepEqual(task.checkpoint, { offset: 2 });
    assert.ok(!events.includes('lease-lost'));
  } finally {
    release.resolve();
    await worker?.stop({ wait: true });
    await f.cleanup();
  }
});

test('lease loss aborts the handler and preserves a replacement fencing token', async () => {
  const f = await fixture({ ttl: 20 });
  const started = deferred();
  const events = [];
  let worker;
  let signal;
  try {
    await f.store.create({ taskId: 'takeover', type: 'unit' });
    worker = new TaskWorker({ store: f.store, workerId: 'old', heartbeatIntervalMs: 10, onEvent: (event) => events.push(event.type), handlers: { unit: async (_payload, context) => {
      signal = context.signal;
      started.resolve();
      await new Promise((resolve) => signal.addEventListener('abort', resolve, { once: true }));
      return { status: 'succeeded', checkpoint: { forbidden: true } };
    } } });
    await worker.runOnce();
    await started.promise;
    f.setNow(f.now() + 20);
    const replacement = await f.store.claim('new', { taskId: 'takeover' });
    await worker.waitForIdle();
    const current = await f.store.get('takeover');
    assert.equal(signal.aborted, true);
    assert.equal(current.state, 'preparing');
    assert.equal(current.lease.fencingToken, replacement.lease.fencingToken);
    assert.equal(current.checkpoint, null);
    assert.ok(events.includes('lease-lost'));
  } finally {
    await worker?.stop({ wait: true });
    await f.cleanup();
  }
});

test('an uncooperative handler remains counted after stop instead of freeing a concurrency slot', async () => {
  const f = await fixture();
  const started = deferred();
  const release = deferred();
  let worker;
  let context;
  try {
    await f.store.create({ taskId: 'ignores-abort', type: 'unit' });
    worker = new TaskWorker({ store: f.store, handlers: { unit: async (_payload, value) => { context = value; started.resolve(); await release.promise; } } });
    await worker.runOnce();
    await started.promise;
    await assert.rejects(worker.stop({ wait: true, timeoutMs: 20 }), /timed out/);
    assert.equal(context.signal.aborted, true);
    assert.equal(worker.active.size, 1);
    assert.throws(() => worker.start(), /executions or claims are active/);
    await assert.rejects(context.checkpoint({ forbidden: true }), /no longer active/);
    release.resolve();
    await worker.waitForIdle();
    assert.equal((await f.store.get('ignores-abort')).state, 'running');
  } finally {
    release.resolve();
    await worker?.stop({ wait: true });
    await f.cleanup();
  }
});

test('a running event observer can stop the worker before its handler starts', async () => {
  const f = await fixture();
  let worker;
  let executed = false;
  try {
    await f.store.create({ taskId: 'event-stop', type: 'unit' });
    worker = new TaskWorker({ store: f.store, onEvent: (event) => {
      if (event.type === 'running') void worker.stop();
    }, handlers: { unit: () => { executed = true; } } });
    await worker.runOnce();
    await worker.waitForIdle();
    assert.equal(executed, false);
    assert.equal((await f.store.get('event-stop')).state, 'running');
  } finally {
    await worker?.stop({ wait: true });
    await f.cleanup();
  }
});

test('expired cancelling tasks converge even when their type has no registered handler', async () => {
  const f = await fixture();
  const worker = new TaskWorker({ store: f.store });
  try {
    await f.store.create({ taskId: 'expired-cancel', type: 'unsupported' });
    await f.store.claim('old', { taskId: 'expired-cancel' });
    await f.store.cancel('expired-cancel');
    f.setNow(f.now() + 100);
    assert.equal((await worker.runOnce()).claimed, 0);
    assert.equal((await f.store.get('expired-cancel')).state, 'cancelled');
  } finally {
    await worker.stop();
    await f.cleanup();
  }
});

test('unregistering a handler after claim does not abandon the claimed execution', async () => {
  const f = await fixture();
  let worker;
  let executed = false;
  try {
    await f.store.create({ taskId: 'claimed-handler', type: 'unit' });
    const claim = f.store.claim.bind(f.store);
    f.store.claim = async (...args) => {
      const task = await claim(...args);
      worker.unregister('unit');
      return task;
    };
    worker = new TaskWorker({ store: f.store, handlers: { unit: () => { executed = true; return { status: 'succeeded' }; } } });
    await worker.runOnce();
    await worker.waitForIdle();
    assert.equal(executed, true);
    assert.equal((await f.store.get('claimed-handler')).state, 'succeeded');
  } finally {
    await worker?.stop({ wait: true });
    await f.cleanup();
  }
});
