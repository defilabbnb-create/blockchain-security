import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { TaskStateStore, transitionTask } from '../src/task-state.js';

const ISO = (ms) => new Date(ms).toISOString();

test('list paginates after priority sorting and validates offsets', async () => {
  const f = await fixture();
  try {
    for (const [taskId, priority] of [['low', 1], ['high', 3], ['middle', 2]]) {
      await f.store.create({ taskId, type: 'unit', priority });
    }
    assert.deepEqual((await f.store.list({ limit: 1, offset: 1 })).map(x => x.taskId), ['middle']);
    assert.deepEqual((await f.store.list({ state: 'queued', limit: 2, offset: 2 })).map(x => x.taskId), ['low']);
    assert.deepEqual(await f.store.list({ offset: 99 }), []);
    for (const offset of [-1, 0.5, NaN, '1', Number.MAX_SAFE_INTEGER + 1]) {
      await assert.rejects(f.store.list({ offset }), /offset/);
    }
  } finally { await f.cleanup(); }
});

test('list uses taskId as a stable tie-break for equal priority and creation time', async () => {
  const f = await fixture();
  try {
    for (const taskId of ['zeta', 'alpha', 'middle']) {
      await f.store.create({ taskId, type: 'unit', priority: 2 });
    }
    assert.deepEqual((await f.store.list()).map((task) => task.taskId), ['alpha', 'middle', 'zeta']);
    assert.deepEqual((await f.store.list({ limit: 2 })).map((task) => task.taskId), ['alpha', 'middle']);
  } finally { await f.cleanup(); }
});

test('claim uses the same stable taskId tie-break as list', async () => {
  const f = await fixture();
  try {
    for (const taskId of ['zeta', 'alpha', 'middle']) {
      await f.store.create({ taskId, type: 'unit', priority: 2 });
    }
    assert.equal((await f.store.claim('worker-a')).taskId, 'alpha');
  } finally { await f.cleanup(); }
});

test('read snapshots expose a monotonic revision for task mutations', async () => {
  const f = await fixture();
  try {
    const empty = await f.store.readSnapshot();
    assert.equal(empty.revision, 0);
    assert.deepEqual(empty.tasks, []);

    await f.store.create({ taskId: 'revisioned', type: 'unit' });
    const created = await f.store.readTask('revisioned');
    assert.equal(created.revision, 1);
    assert.equal(created.task.state, 'queued');

    const cancelled = await f.store.cancelIfRevision('revisioned', 'operator requested', created.revision);
    assert.equal(cancelled.state, 'cancelled');
    const after = await f.store.readSnapshot();
    assert.equal(after.revision, 2);
    assert.equal(after.tasks[0].state, 'cancelled');
  } finally { await f.cleanup(); }
});

test('cursor pages follow stable order and do not include new items before the cursor', async () => {
  const f = await fixture();
  try {
    for (const taskId of ['zeta', 'alpha', 'middle']) {
      await f.store.create({ taskId, type: 'unit', priority: 2 });
    }

    const first = await f.store.listPage({ limit: 2 });
    assert.equal(first.revision, 3);
    assert.deepEqual(first.page.map((task) => task.taskId), ['alpha', 'middle']);
    assert.equal(first.hasMore, true);
    assert.ok(first.nextCursor);

    await f.store.create({ taskId: 'aardvark', type: 'unit', priority: 2 });
    const second = await f.store.listPage({ limit: 2, cursor: first.nextCursor });
    assert.equal(second.revision, 4);
    assert.deepEqual(second.page.map((task) => task.taskId), ['zeta']);
    assert.equal(second.hasMore, false);
    assert.equal(second.nextCursor, null);
    await assert.rejects(f.store.listPage({ limit: 2, cursor: 'not-a-cursor' }), /invalid task cursor/);
  } finally { await f.cleanup(); }
});

test('conditional writes reject stale revisions and accept the current revision atomically', async () => {
  const f = await fixture();
  try {
    await f.store.create({ taskId: 'conditional', type: 'unit', maxAttempts: 2 });
    const initial = await f.store.readTask('conditional');
    assert.equal(initial.revision, 1);

    await f.store.create({ taskId: 'concurrent', type: 'unit' });
    await assert.rejects(
      f.store.transitionIfRevision('conditional', 'cancelled', { expectedRevision: initial.revision }),
      (error) => error.code === 'REVISION_MISMATCH' && error.expectedRevision === 1 && error.actualRevision === 2,
    );
    assert.equal((await f.store.readTask('conditional')).task.state, 'queued');

    const cancelled = await f.store.cancelIfRevision('conditional', 'operator requested', 2);
    assert.equal(cancelled.state, 'cancelled');
    const afterCancel = await f.store.readTask('conditional');
    assert.equal(afterCancel.revision, 3);
  } finally { await f.cleanup(); }
});

test('resumeIfRevision uses the same atomic revision guard as other operator writes', async () => {
  const f = await fixture();
  try {
    await f.store.create({ taskId: 'resume-guard', type: 'unit' });
    const claimed = await f.store.claim('worker-a');
    const paused = await f.store.transitionOwned('resume-guard', 'paused', 'worker-a', claimed.lease.fencingToken);
    const current = await f.store.readTask('resume-guard');
    assert.equal(current.revision, 3);
    assert.equal(paused.state, 'paused');

    await assert.rejects(
      f.store.resumeIfRevision('resume-guard', 'stale resume', 2),
      (error) => error.code === 'REVISION_MISMATCH' && error.actualRevision === 3,
    );
    const resumed = await f.store.resumeIfRevision('resume-guard', 'fresh resume', current.revision);
    assert.equal(resumed.state, 'queued');
    assert.equal((await f.store.readTask('resume-guard')).revision, 4);
  } finally { await f.cleanup(); }
});

async function fixture({ now = Date.parse('2026-01-01T00:00:00.000Z'), defaultLeaseTtlMs = 45_000 } = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'task-state-'));
  const path = join(dir, 'state.json');
  let current = now;
  const store = new TaskStateStore({
    path,
    clock: () => current,
    defaultLeaseTtlMs,
  });
  return {
    dir,
    path,
    store,
    setNow(value) { current = value instanceof Date ? value.getTime() : value; },
    now() { return current; },
    async cleanup() { await rm(dir, { recursive: true, force: true }); },
  };
}

test('rejects illegal transitions and leaves the input task unchanged', async () => {
  const f = await fixture();
  try {
    const created = await f.store.create({ taskId: 'illegal', type: 'unit' });
    const before = structuredClone(created);
    await assert.rejects(f.store.transition('illegal', 'running'), /invalid task transition/);
    assert.deepEqual(created, before);

    const transitioned = transitionTask(created, 'preparing', 'claim', f.now());
    assert.deepEqual(created, before);
    transitioned.history[0].reason = 'changed copy';
    assert.equal(created.history[0].reason, 'created');
  } finally {
    await f.cleanup();
  }
});

test('history audit fields cannot be overridden by transition details', async () => {
  const f = await fixture();
  try {
    const created = await f.store.create({ taskId: 'audit', type: 'unit' });
    const updated = transitionTask(created, 'preparing', 'real reason', f.now(), { from: 'fake', to: 'succeeded', reason: 'forged', at: 'forged' });
    const event = updated.history.at(-1);
    assert.deepEqual({ from: event.from, to: event.to, reason: event.reason, at: event.at }, {
      from: 'queued', to: 'preparing', reason: 'real reason', at: ISO(f.now()),
    });
    assert.equal(event.workerId, undefined);
  } finally {
    await f.cleanup();
  }
});

test('create clones payload and writes an atomic, parseable JSON file', async () => {
  const f = await fixture();
  try {
    const payload = { nested: { value: 1 }, list: ['a'] };
    await f.store.create({ taskId: 'atomic', type: 'unit', payload });
    payload.nested.value = 99;
    payload.list.push('mutated');

    const task = await f.store.get('atomic');
    assert.deepEqual(task.payload, { nested: { value: 1 }, list: ['a'] });
    const raw = await readFile(f.path, 'utf8');
    assert.doesNotThrow(() => JSON.parse(raw));
    assert.match(raw, /\n$/);
    const names = await readdir(f.dir);
    assert.deepEqual(names.filter((name) => name.includes('.tmp')), []);
  } finally {
    await f.cleanup();
  }
});

test('state survives a new store instance and preserves lease/checkpoint data', async () => {
  const f = await fixture({ now: Date.parse('2026-01-02T00:00:00Z') });
  try {
    await f.store.create({ taskId: 'restart', type: 'unit', payload: { value: 7 } });
    const claimed = await f.store.claim('worker-a');
    await f.store.transitionOwned('restart', 'running', 'worker-a', claimed.lease.fencingToken);
    await f.store.checkpoint('restart', { offset: 3 }, 'worker-a', claimed.lease.fencingToken);
    const reopened = new TaskStateStore({ path: f.path, clock: f.store.clock });
    const task = await reopened.get('restart');
    assert.equal(task.state, 'checkpointing');
    assert.equal(task.lease.workerId, 'worker-a');
    assert.deepEqual(task.checkpoint, { offset: 3 });
  } finally {
    await f.cleanup();
  }
});

test('bad JSON is rejected without overwriting the existing state file', async () => {
  const f = await fixture();
  try {
    const malformed = '{"schemaVersion":1,"tasks":';
    await writeFile(f.path, malformed, 'utf8');
    await assert.rejects(f.store.create({ taskId: 'preserve', type: 'unit' }), /invalid task state JSON/);
    assert.equal(await readFile(f.path, 'utf8'), malformed);
  } finally {
    await f.cleanup();
  }
});

test('rejects task records whose storage key disagrees with taskId', async () => {
  const f = await fixture();
  try {
    await writeFile(f.path, JSON.stringify({ schemaVersion: 1, tasks: { wrong: {
      schemaVersion: 1, taskId: 'right', type: 'unit', priority: 0,
      createdAt: ISO(f.now()), updatedAt: ISO(f.now()), state: 'queued', payload: {},
      checkpoint: null, checkpointSeq: 0, history: [], attempts: 0, maxAttempts: 1,
      lease: null, nextRetryAt: null,
    } } }), 'utf8');
    await assert.rejects(f.store.get('wrong'), /task key does not match taskId/);
  } finally {
    await f.cleanup();
  }
});

test('rejects corrupted task metadata and lease records before scheduling', async () => {
  const f = await fixture();
  try {
    await writeFile(f.path, JSON.stringify({ schemaVersion: 1, tasks: { corrupt: {
      schemaVersion: 1, taskId: 'corrupt', type: 'unit', priority: 0,
      createdAt: ISO(f.now()), updatedAt: ISO(f.now()), state: 'preparing', payload: {},
      checkpoint: null, checkpointSeq: 0, history: [{ from: null, to: 'queued', reason: 'created', at: ISO(f.now()) }],
      attempts: 1, maxAttempts: 1, nextRetryAt: 'not-a-date',
      lease: { workerId: 'worker', heartbeatAt: ISO(f.now()), expiresAt: ISO(f.now() + 10), ttlMs: 10, sequence: 1 },
    } } }), 'utf8');
    await assert.rejects(f.store.list(), /invalid retry timestamp/);
  } finally {
    await f.cleanup();
  }
});

test('uses the injected clock for task and lease timestamps', async () => {
  const start = Date.parse('2026-02-03T04:05:06.000Z');
  const f = await fixture({ now: start, defaultLeaseTtlMs: 5_000 });
  try {
    const created = await f.store.create({ taskId: 'clocked', type: 'unit' });
    assert.equal(created.createdAt, ISO(start));
    f.setNow(start + 1_000);
    const claimed = await f.store.claim('worker-a');
    assert.equal(claimed.lease.heartbeatAt, ISO(start + 1_000));
    assert.equal(claimed.lease.expiresAt, ISO(start + 6_000));
  } finally {
    await f.cleanup();
  }
});

test('claim and list honor priority, then oldest createdAt', async () => {
  const start = Date.parse('2026-03-01T00:00:00.000Z');
  const f = await fixture({ now: start });
  try {
    await f.store.create({ taskId: 'old-low', type: 'unit', priority: 1 });
    f.setNow(start + 1_000);
    await f.store.create({ taskId: 'new-low', type: 'unit', priority: 1 });
    f.setNow(start + 2_000);
    await f.store.create({ taskId: 'high', type: 'unit', priority: 10 });

    const listed = await f.store.list();
    assert.deepEqual(listed.map((task) => task.taskId), ['high', 'old-low', 'new-low']);
    const first = await f.store.claim('worker-a');
    assert.equal(first.taskId, 'high');
    const second = await f.store.claim('worker-b');
    assert.equal(second.taskId, 'old-low');
  } finally {
    await f.cleanup();
  }
});

test('expired leases can be reclaimed while unexpired leases remain owned', async () => {
  const start = Date.parse('2026-04-01T00:00:00.000Z');
  const f = await fixture({ now: start, defaultLeaseTtlMs: 10 });
  try {
    await f.store.create({ taskId: 'lease', type: 'unit' });
    const first = await f.store.claim('worker-a');
    assert.equal(first.lease.expiresAt, ISO(start + 10));
    f.setNow(start + 9);
    assert.equal(await f.store.claim('worker-b'), null);
    f.setNow(start + 10);
    const reclaimed = await f.store.claim('worker-b');
    assert.equal(reclaimed.taskId, 'lease');
    assert.equal(reclaimed.lease.workerId, 'worker-b');
    assert.equal(reclaimed.attempts, 2);
    const recovery = reclaimed.history.at(-1);
    assert.equal(recovery.reason, 'lease reclaimed');
    assert.equal(recovery.recovery, true);
    assert.equal(recovery.previousWorkerId, 'worker-a');
  } finally {
    await f.cleanup();
  }
});

test('expired checkpointing leases retain the last checkpoint and classify recovery', async () => {
  const start = Date.parse('2026-04-01T00:00:00.000Z');
  const f = await fixture({ now: start, defaultLeaseTtlMs: 10 });
  try {
    await f.store.create({ taskId: 'checkpoint-recovery', type: 'unit', maxAttempts: 2 });
    const first = await f.store.claim('worker-a');
    await f.store.transitionOwned('checkpoint-recovery', 'running', 'worker-a', first.lease.fencingToken);
    const checkpoint = await f.store.checkpoint(
      'checkpoint-recovery', { phase: 'static', cursor: 7 }, 'worker-a', first.lease.fencingToken,
    );
    assert.equal(checkpoint.state, 'checkpointing');
    f.setNow(start + 10);

    const recovered = await f.store.claim('worker-b', { taskId: 'checkpoint-recovery' });
    assert.equal(recovered.state, 'preparing');
    assert.equal(recovered.attempts, 2);
    assert.deepEqual(recovered.checkpoint, { phase: 'static', cursor: 7 });
    assert.equal(recovered.history.at(-1).from, 'checkpointing');
    assert.equal(recovered.history.at(-1).reason, 'lease reclaimed');
    assert.equal(recovered.history.at(-1).recovery, true);
    assert.equal(recovered.history.at(-1).previousWorkerId, 'worker-a');
  } finally {
    await f.cleanup();
  }
});

test('independent stores serialize claims on the same state file', async () => {
  const f = await fixture();
  try {
    await f.store.create({ taskId: 'cross-store', type: 'unit' });
    const a = new TaskStateStore({ path: f.path, clock: f.store.clock });
    const b = new TaskStateStore({ path: f.path, clock: f.store.clock });
    const [first, second] = await Promise.all([a.claim('worker-a'), b.claim('worker-b')]);
    assert.equal([first, second].filter(Boolean).length, 1);
    assert.equal((await f.store.get('cross-store')).attempts, 1);
  } finally {
    await f.cleanup();
  }
});

test('fencing token rejects stale worker operations after lease replacement', async () => {
  const start = Date.parse('2026-04-01T00:00:00Z');
  const f = await fixture({ now: start, defaultLeaseTtlMs: 10 });
  try {
    await f.store.create({ taskId: 'fenced', type: 'unit', maxAttempts: 3 });
    const first = await f.store.claim('worker-a');
    f.setNow(start + 10);
    const second = await f.store.claim('worker-a');
    assert.notEqual(first.lease.fencingToken, second.lease.fencingToken);
    await assert.rejects(f.store.heartbeat('fenced', 'worker-a', { fencingToken: first.lease.fencingToken }), /lease is not owned/);
    await assert.rejects(f.store.checkpoint('fenced', { stale: true }, 'worker-a', first.lease.fencingToken), /lease is not owned/);
    await assert.rejects(f.store.transitionOwned('fenced', 'running', 'worker-a', first.lease.fencingToken), /lease is not owned/);
    await assert.rejects(f.store.fail('fenced', { workerId: 'worker-a', fencingToken: first.lease.fencingToken }), /lease is not owned/);
    const updated = await f.store.heartbeat('fenced', 'worker-a', { fencingToken: second.lease.fencingToken });
    assert.equal(updated.lease.fencingToken, second.lease.fencingToken);
  } finally {
    await f.cleanup();
  }
});

test('generic transitions cannot create an active task without a lease', async () => {
  const f = await fixture();
  try {
    await f.store.create({ taskId: 'unowned-active', type: 'unit' });
    await assert.rejects(f.store.transition('unowned-active', 'preparing'), /owned lease/);
    assert.equal((await f.store.get('unowned-active')).state, 'queued');
  } finally {
    await f.cleanup();
  }
});

test('generic transitions cannot bypass ownership for an active task', async () => {
  const f = await fixture();
  try {
    await f.store.create({ taskId: 'owned-active', type: 'unit' });
    const claimed = await f.store.claim('worker-a');
    await f.store.transitionOwned('owned-active', 'running', 'worker-a', claimed.lease.fencingToken);

    await assert.rejects(f.store.transition('owned-active', 'succeeded'), /owned lease/);
    await assert.rejects(f.store.transition('owned-active', 'cancelling'), /owned lease/);

    const current = await f.store.get('owned-active');
    assert.equal(current.state, 'running');
    assert.equal(current.lease.workerId, 'worker-a');
    assert.equal(current.lease.fencingToken, claimed.lease.fencingToken);

    await f.store.cancel('owned-active');
    await assert.rejects(f.store.transition('owned-active', 'cancelled'), /owned lease/);
  } finally {
    await f.cleanup();
  }
});

test('expired lease at max attempts is recovered as failed', async () => {
  const start = Date.parse('2026-04-02T00:00:00Z');
  const f = await fixture({ now: start, defaultLeaseTtlMs: 10 });
  try {
    await f.store.create({ taskId: 'maxed', type: 'unit', maxAttempts: 1 });
    const claimed = await f.store.claim('worker-a');
    f.setNow(start + 10);
    assert.equal(await f.store.claim('worker-b'), null);
    const failed = await f.store.get('maxed');
    assert.equal(failed.state, 'failed');
    assert.equal(failed.lease, null);
  } finally {
    await f.cleanup();
  }
});

test('expired cancellation lease is recovered as cancelled', async () => {
  const start = Date.parse('2026-04-03T00:00:00Z');
  const f = await fixture({ now: start, defaultLeaseTtlMs: 10 });
  try {
    await f.store.create({ taskId: 'cancel-recovery', type: 'unit' });
    await f.store.claim('worker-a');
    await f.store.cancel('cancel-recovery');
    f.setNow(start + 10);
    await f.store.claim('worker-b');
    assert.equal((await f.store.get('cancel-recovery')).state, 'cancelled');
  } finally {
    await f.cleanup();
  }
});

test('maxed failed tasks cannot be resumed into an unclaimable queue', async () => {
  const f = await fixture();
  try {
    await f.store.create({ taskId: 'no-resume', type: 'unit', maxAttempts: 1 });
    const claimed = await f.store.claim('worker-a');
    await f.store.fail('no-resume', { workerId: 'worker-a', fencingToken: claimed.lease.fencingToken, retryable: true });
    assert.equal((await f.store.get('no-resume')).state, 'failed');
    await assert.rejects(f.store.resume('no-resume'), /max attempts/);
  } finally {
    await f.cleanup();
  }
});

test('paused tasks resume the current attempt even when the retry budget is exhausted', async () => {
  const f = await fixture();
  try {
    await f.store.create({ taskId: 'resume-paused-at-limit', type: 'unit', maxAttempts: 1 });
    const claimed = await f.store.claim('worker-a');
    await f.store.transitionOwned('resume-paused-at-limit', 'running', 'worker-a', claimed.lease.fencingToken);
    await f.store.checkpoint('resume-paused-at-limit', { phase: 'analysis', cursor: 12 }, 'worker-a', claimed.lease.fencingToken);
    const paused = await f.store.transitionOwned('resume-paused-at-limit', 'paused', 'worker-a', claimed.lease.fencingToken);
    assert.equal(paused.attempts, 1);

    const resumed = await f.store.resumeIfRevision('resume-paused-at-limit', 'resumed', (await f.store.readTask('resume-paused-at-limit')).revision);
    assert.equal(resumed.state, 'queued');
    assert.equal(resumed.resumePending, true);
    const restartedStore = new TaskStateStore({ path: f.path, clock: f.store.clock });
    const continuation = await restartedStore.claim('worker-b');
    assert.equal(continuation.attempts, 1);
    assert.equal(continuation.resumePending, false);
    assert.deepEqual(continuation.checkpoint, { phase: 'analysis', cursor: 12 });
    assert.equal(continuation.history.at(-1).resumed, true);

    const failed = await restartedStore.fail('resume-paused-at-limit', {
      workerId: 'worker-b', fencingToken: continuation.lease.fencingToken, retryable: true, error: 'still failing',
    });
    assert.equal(failed.state, 'failed');
    assert.equal(failed.nextRetryAt, null);
    assert.equal(await restartedStore.claim('worker-c'), null);
  } finally {
    await f.cleanup();
  }
});

test('heartbeat requires the current worker and advances lease sequence', async () => {
  const start = Date.parse('2026-05-01T00:00:00.000Z');
  const f = await fixture({ now: start, defaultLeaseTtlMs: 100 });
  try {
    await f.store.create({ taskId: 'heartbeat', type: 'unit' });
    const claimed = await f.store.claim('worker-a');
    f.setNow(start + 50);
    await assert.rejects(f.store.heartbeat('heartbeat', 'worker-b', { fencingToken: claimed.lease.fencingToken }), /lease is not owned/);
    const updated = await f.store.heartbeat('heartbeat', 'worker-a', { fencingToken: claimed.lease.fencingToken });
    assert.equal(updated.lease.sequence, 2);
    assert.equal(updated.lease.heartbeatAt, ISO(start + 50));
    assert.equal(updated.lease.expiresAt, ISO(start + 150));
    f.setNow(start + 151);
    await assert.rejects(f.store.heartbeat('heartbeat', 'worker-a', { fencingToken: claimed.lease.fencingToken }), /lease expired/);
  } finally {
    await f.cleanup();
  }
});

test('checkpoint increments sequence and refreshes the worker lease', async () => {
  const start = Date.parse('2026-06-01T00:00:00.000Z');
  const f = await fixture({ now: start, defaultLeaseTtlMs: 100 });
  try {
    await f.store.create({ taskId: 'checkpoint', type: 'unit' });
    const claimed = await f.store.claim('worker-a');
    await f.store.transitionOwned('checkpoint', 'running', 'worker-a', claimed.lease.fencingToken);
    f.setNow(start + 10);
    const first = await f.store.checkpoint('checkpoint', { block: 1 }, 'worker-a', claimed.lease.fencingToken);
    assert.equal(first.state, 'checkpointing');
    assert.equal(first.checkpointSeq, 1);
    assert.equal(first.lease.sequence, 2);
    assert.equal(first.checkpointedAt, ISO(start + 10));
    f.setNow(start + 20);
    const second = await f.store.checkpoint('checkpoint', { block: 2 }, 'worker-a', claimed.lease.fencingToken);
    assert.equal(second.state, 'checkpointing');
    assert.equal(second.checkpointSeq, 2);
    assert.equal(second.lease.sequence, 3);
    assert.deepEqual(second.checkpoint, { block: 2 });
  } finally {
    await f.cleanup();
  }
});

test('retryable failures use increasing default backoff and become claimable when due', async () => {
  const start = Date.parse('2026-07-01T00:00:00.000Z');
  const f = await fixture({ defaultLeaseTtlMs: 100, now: start });
  try {
    await f.store.create({ taskId: 'retry', type: 'unit', maxAttempts: 3 });
    const first = await f.store.claim('worker-a');
    assert.equal(first.attempts, 1);
    const queued = await f.store.fail('retry', { workerId: 'worker-a', fencingToken: first.lease.fencingToken, retryable: true, error: 'temporary' });
    assert.equal(queued.state, 'queued');
    assert.equal(queued.nextRetryAt, ISO(start + 1_000));
    assert.equal(queued.lease, null);

    assert.equal(await f.store.claim('worker-b'), null);
    f.setNow(start + 999);
    assert.equal(await f.store.claim('worker-b'), null);
    f.setNow(start + 1_000);
    const second = await f.store.claim('worker-b');
    assert.equal(second.attempts, 2);
    const failed = await f.store.fail('retry', { workerId: 'worker-b', fencingToken: second.lease.fencingToken, retryable: true, error: 'still broken' });
    assert.equal(failed.state, 'queued');
    assert.equal(failed.nextRetryAt, ISO(start + 3_000));

    f.setNow(start + 2_999);
    assert.equal(await f.store.claim('worker-c'), null);
    f.setNow(start + 3_000);
    const third = await f.store.claim('worker-c');
    assert.equal(third.attempts, 3);
    const exhausted = await f.store.fail('retry', { workerId: 'worker-c', fencingToken: third.lease.fencingToken, retryable: true, error: 'still broken' });
    assert.equal(exhausted.state, 'failed');
    assert.equal(exhausted.nextRetryAt, null);
    assert.equal(exhausted.error, 'still broken');
  } finally {
    await f.cleanup();
  }
});

test('default retry backoff is capped at 24 hours', async () => {
  const start = Date.parse('2026-07-02T00:00:00.000Z');
  const f = await fixture({ defaultLeaseTtlMs: 100, now: start });
  try {
    await f.store.create({ taskId: 'capped-retry', type: 'unit', maxAttempts: 20 });
    const delays = [];
    let claimed = await f.store.claim('worker');
    for (let attempt = 1; attempt <= 20; attempt += 1) {
      const failed = await f.store.fail('capped-retry', {
        workerId: 'worker', fencingToken: claimed.lease.fencingToken, retryable: true,
      });
      if (attempt === 20) {
        assert.equal(failed.state, 'failed');
        assert.equal(failed.nextRetryAt, null);
        break;
      }

      const delay = Date.parse(failed.nextRetryAt) - f.now();
      delays.push(delay);
      assert.ok(delay > 0 && delay <= 86_400_000);
      f.setNow(Date.parse(failed.nextRetryAt));
      claimed = await f.store.claim('worker');
      assert.equal(claimed.attempts, attempt + 1);
    }
    assert.equal(delays[15], 32_768_000);
    assert.equal(delays[16], 65_536_000);
    assert.equal(delays[17], 86_400_000);
    assert.equal(delays[18], 86_400_000);
  } finally {
    await f.cleanup();
  }
});

test('explicit retryDelayMs overrides the default backoff, including zero', async () => {
  const start = Date.parse('2026-07-03T00:00:00.000Z');
  const f = await fixture({ defaultLeaseTtlMs: 100, now: start });
  try {
    await f.store.create({ taskId: 'override-retry', type: 'unit', maxAttempts: 3 });
    const first = await f.store.claim('worker-a');
    const delayed = await f.store.fail('override-retry', {
      workerId: 'worker-a', fencingToken: first.lease.fencingToken, retryable: true, retryDelayMs: 250,
    });
    assert.equal(delayed.nextRetryAt, ISO(start + 250));

    f.setNow(start + 250);
    const second = await f.store.claim('worker-b');
    const immediate = await f.store.fail('override-retry', {
      workerId: 'worker-b', fencingToken: second.lease.fencingToken, retryable: true, retryDelayMs: 0,
    });
    assert.equal(immediate.nextRetryAt, null);
    assert.equal((await f.store.claim('worker-c')).attempts, 3);
  } finally {
    await f.cleanup();
  }
});

test('maxed retryable failures do not retain a retry timestamp', async () => {
  const f = await fixture();
  try {
    await f.store.create({ taskId: 'maxed-retry', type: 'unit', maxAttempts: 1 });
    const claimed = await f.store.claim('worker-a');
    const failed = await f.store.fail('maxed-retry', {
      workerId: 'worker-a', fencingToken: claimed.lease.fencingToken, retryable: true,
    });
    assert.equal(failed.state, 'failed');
    assert.equal(failed.nextRetryAt, null);
  } finally {
    await f.cleanup();
  }
});

test('blocked failure enters the blocked terminal state', async () => {
  const f = await fixture();
  try {
    await f.store.create({ taskId: 'blocked', type: 'unit' });
    const claimed = await f.store.claim('worker-a');
    const blocked = await f.store.fail('blocked', { workerId: 'worker-a', fencingToken: claimed.lease.fencingToken, blocked: true, error: 'needs review' });
    assert.equal(blocked.state, 'blocked');
    assert.equal(blocked.lease, null);
    assert.equal((await f.store.claim('worker-b')), null);
  } finally {
    await f.cleanup();
  }
});

test('active cancellation moves through cancelling to cancelled', async () => {
  const f = await fixture();
  try {
    await f.store.create({ taskId: 'cancel', type: 'unit' });
    const cancelling = await f.store.cancel('cancel', 'user requested');
    assert.equal(cancelling.state, 'cancelled');

    await f.store.create({ taskId: 'active-cancel', type: 'unit' });
    const claimed = await f.store.claim('worker-a');
    const pending = await f.store.cancel('active-cancel', 'user requested');
    assert.equal(pending.state, 'cancelling');
    const cancelled = await f.store.finishCancellation('active-cancel', 'cancelled', 'worker-a', claimed.lease.fencingToken);
    assert.equal(cancelled.state, 'cancelled');
    assert.equal(cancelled.lease, null);
  } finally {
    await f.cleanup();
  }
});

test('repeated active cancellation preserves the worker lease until confirmation', async () => {
  const f = await fixture();
  try {
    for (const method of ['cancel', 'cancelIfRevision']) {
      const taskId = `repeat-${method}`;
      await f.store.create({ taskId, type: 'unit' });
      const claimed = await f.store.claim('worker-a');
      let current = await f.store.readTask(taskId);
      const cancel = (reason, revision) => method === 'cancel'
        ? f.store.cancel(taskId, reason)
        : f.store.cancelIfRevision(taskId, reason, revision);

      const first = await cancel('first cancel', current.revision);
      assert.equal(first.state, 'cancelling');
      assert.deepEqual(first.lease, claimed.lease);

      current = await f.store.readTask(taskId);
      if (method === 'cancelIfRevision') {
        await assert.rejects(
          f.store.cancelIfRevision(taskId, 'stale cancel', current.revision - 1),
          (error) => error.code === 'REVISION_MISMATCH',
        );
        const afterStale = await f.store.readTask(taskId);
        assert.equal(afterStale.revision, current.revision);
        assert.deepEqual(afterStale.task.lease, claimed.lease);
      }

      current = await f.store.readTask(taskId);
      const repeated = await cancel('repeat cancel', current.revision);
      assert.equal(repeated.state, 'cancelling');
      assert.deepEqual(repeated.lease, claimed.lease);

      const cancelled = await f.store.finishCancellation(taskId, 'worker confirmed', 'worker-a', claimed.lease.fencingToken);
      assert.equal(cancelled.state, 'cancelled');
      assert.equal(cancelled.lease, null);
    }
  } finally {
    await f.cleanup();
  }
});

test('concurrent claims yield exactly one worker lease', async () => {
  const f = await fixture();
  try {
    await f.store.create({ taskId: 'single', type: 'unit' });
    const results = await Promise.all([
      f.store.claim('worker-a'),
      f.store.claim('worker-b'),
    ]);
    assert.equal(results.filter(Boolean).length, 1);
    const claimed = results.find(Boolean);
    assert.equal(claimed.taskId, 'single');
    assert.equal((await f.store.get('single')).attempts, 1);
  } finally {
    await f.cleanup();
  }
});
