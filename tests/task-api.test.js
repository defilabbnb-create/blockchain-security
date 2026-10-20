import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { TaskStateStore } from '../src/task-state.js';
import { startServer } from '../src/web-server.js';

async function serverFixture(t) {
  const dir = await mkdtemp(join(tmpdir(), 'task-api-'));
  let current = Date.parse('2026-10-18T00:00:00Z');
  const store = new TaskStateStore({ path: join(dir, 'tasks.json'), clock: () => current });
  const snapshotProvider = async () => ({ generatedAt: '2026-10-18T00:00:00.000Z', activeTask: null, activeChain: null, queue: [] });
  const server = startServer({ port: 0, snapshotProvider, taskStore: store });
  await once(server, 'listening');
  t.after(async () => {
    server.stop();
    if (server.listening) await once(server, 'close');
    await rm(dir, { recursive: true, force: true });
  });
  return { base: `http://127.0.0.1:${server.address().port}`, store, setNow(value) { current = value; } };
}

async function json(base, path, options = {}) {
  const response = await fetch(`${base}${path}`, { headers: { 'content-type': 'application/json' }, ...options });
  return { response, body: await response.json() };
}

test('task API persists create/list/get and preserves snapshot compatibility fields', async (t) => {
  const { base } = await serverFixture(t);
  const created = await json(base, '/api/tasks', { method: 'POST', body: JSON.stringify({ taskId: 'api-task', type: 'analysis', payload: { address: '0x1' }, priority: 4, maxAttempts: 2 }) });
  assert.equal(created.response.status, 200);
  assert.equal(created.body.task.taskId, 'api-task');
  const listed = await json(base, '/api/tasks');
  assert.equal(listed.response.status, 200);
  assert.equal(listed.body.tasks.length, 1);
  assert.deepEqual(listed.body.queue, []);
  const fetched = await json(base, '/api/tasks/api-task');
  assert.equal(fetched.response.status, 200);
  assert.equal(fetched.body.task.payload.address, '0x1');
});

test('task API enforces worker ownership through claim, heartbeat, checkpoint, pause and resume', async (t) => {
  const { base } = await serverFixture(t);
  await json(base, '/api/tasks', { method: 'POST', body: JSON.stringify({ taskId: 'owned', type: 'analysis' }) });
  const claim = await json(base, '/api/tasks/owned/claim', { method: 'POST', body: JSON.stringify({ workerId: 'worker-a', ttlMs: 1000 }) });
  assert.equal(claim.response.status, 200);
  assert.equal(claim.body.task.lease.workerId, 'worker-a');
  const fencingToken = claim.body.task.lease.fencingToken;
  const denied = await json(base, '/api/tasks/owned/heartbeat', { method: 'POST', body: JSON.stringify({ workerId: 'worker-b', fencingToken }) });
  assert.equal(denied.response.status, 400);
  const running = await json(base, '/api/tasks/owned/transition', { method: 'POST', body: JSON.stringify({ state: 'running', workerId: 'worker-a', fencingToken, reason: 'worker started' }) });
  assert.equal(running.body.task.state, 'running');
  const checkpoint = await json(base, '/api/tasks/owned/checkpoint', { method: 'POST', body: JSON.stringify({ workerId: 'worker-a', fencingToken, checkpoint: { block: 12 } }) });
  assert.equal(checkpoint.body.task.checkpoint.block, 12);
  const paused = await json(base, '/api/tasks/owned/pause', { method: 'POST', body: JSON.stringify({ workerId: 'worker-a', fencingToken }) });
  assert.equal(paused.body.task.state, 'paused');
  const resumed = await json(base, '/api/tasks/owned/resume', { method: 'POST', body: JSON.stringify({}) });
  assert.equal(resumed.body.task.state, 'queued');
});

test('task API rejects malformed or unknown input and does not expose unmatched paths as success', async (t) => {
  const { base } = await serverFixture(t);
  const malformed = await fetch(`${base}/api/tasks`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{' });
  assert.equal(malformed.status, 400);
  const unknown = await json(base, '/api/tasks', { method: 'POST', body: JSON.stringify({ type: 'analysis', execute: 'rm -rf /' }) });
  assert.equal(unknown.response.status, 400);
  const badTransition = await json(base, '/api/tasks/missing/transition', { method: 'POST', body: JSON.stringify({ state: 'running' }) });
  assert.equal(badTransition.response.status, 404);
  const unmatched = await json(base, '/api/taskshack');
  assert.equal(unmatched.response.status, 404);
  const malformedId = await json(base, '/api/tasks/%E0%A4%A');
  assert.equal(malformedId.response.status, 400);
  const postGet = await json(base, '/api/tasks/missing', { method: 'POST', body: JSON.stringify({}) });
  assert.equal(postGet.response.status, 405);
  const unknownState = await json(base, '/api/tasks', { method: 'POST', body: JSON.stringify({ type: 'analysis', taskId: 'bad-state' }) });
  assert.equal(unknownState.response.status, 200);
  const transition = await json(base, '/api/tasks/bad-state/transition', { method: 'POST', body: JSON.stringify({ state: 'nope' }) });
  assert.equal(transition.response.status, 400);
  const duplicate = await json(base, '/api/tasks', { method: 'POST', body: JSON.stringify({ taskId: 'bad-state', type: 'analysis' }) });
  assert.equal(duplicate.response.status, 409);
});

test('task API can cancel active work and rejects unauthenticated failure', async (t) => {
  const { base } = await serverFixture(t);
  await json(base, '/api/tasks', { method: 'POST', body: JSON.stringify({ taskId: 'cancel-me', type: 'analysis' }) });
  const claim = await json(base, '/api/tasks/cancel-me/claim', { method: 'POST', body: JSON.stringify({ workerId: 'worker-a' }) });
  const fail = await json(base, '/api/tasks/cancel-me/fail', { method: 'POST', body: JSON.stringify({ workerId: 'worker-b', fencingToken: claim.body.task.lease.fencingToken, retryable: true }) });
  assert.equal(fail.response.status, 400);
  const cancel = await json(base, '/api/tasks/cancel-me/cancel', { method: 'POST', body: JSON.stringify({ reason: 'operator requested' }) });
  assert.equal(cancel.response.status, 200);
  assert.equal(cancel.body.task.state, 'cancelling');
  const forgedFinish = await json(base, '/api/tasks/cancel-me/transition', { method: 'POST', body: JSON.stringify({ state: 'cancelled' }) });
  assert.equal(forgedFinish.response.status, 400);
});

test('task API fail route uses default backoff and honors an explicit zero delay', async (t) => {
  const { base, setNow } = await serverFixture(t);
  const start = Date.parse('2026-10-18T00:00:00Z');
  await json(base, '/api/tasks', { method: 'POST', body: JSON.stringify({ taskId: 'api-default-backoff', type: 'analysis', maxAttempts: 2 }) });
  const first = await json(base, '/api/tasks/api-default-backoff/claim', { method: 'POST', body: JSON.stringify({ workerId: 'worker-a' }) });
  const failed = await json(base, '/api/tasks/api-default-backoff/fail', {
    method: 'POST',
    body: JSON.stringify({ workerId: 'worker-a', fencingToken: first.body.task.lease.fencingToken, retryable: true }),
  });
  assert.equal(failed.response.status, 200);
  assert.equal(failed.body.task.nextRetryAt, new Date(start + 1_000).toISOString());

  const tooSoon = await json(base, '/api/tasks/api-default-backoff/claim', { method: 'POST', body: JSON.stringify({ workerId: 'worker-b' }) });
  assert.equal(tooSoon.response.status, 409);
  setNow(start + 999);
  const beforeDue = await json(base, '/api/tasks/api-default-backoff/claim', { method: 'POST', body: JSON.stringify({ workerId: 'worker-b' }) });
  assert.equal(beforeDue.response.status, 409);
  setNow(start + 1_000);
  const due = await json(base, '/api/tasks/api-default-backoff/claim', { method: 'POST', body: JSON.stringify({ workerId: 'worker-b' }) });
  assert.equal(due.response.status, 200);
  assert.equal(due.body.task.attempts, 2);

  await json(base, '/api/tasks', { method: 'POST', body: JSON.stringify({ taskId: 'api-zero-delay', type: 'analysis', maxAttempts: 2 }) });
  const zeroFirst = await json(base, '/api/tasks/api-zero-delay/claim', { method: 'POST', body: JSON.stringify({ workerId: 'worker-a' }) });
  const zeroFail = await json(base, '/api/tasks/api-zero-delay/fail', {
    method: 'POST',
    body: JSON.stringify({ workerId: 'worker-a', fencingToken: zeroFirst.body.task.lease.fencingToken, retryable: true, retryDelayMs: 0 }),
  });
  assert.equal(zeroFail.response.status, 200);
  assert.equal(zeroFail.body.task.nextRetryAt, null);
  const immediate = await json(base, '/api/tasks/api-zero-delay/claim', { method: 'POST', body: JSON.stringify({ workerId: 'worker-b' }) });
  assert.equal(immediate.response.status, 200);
  assert.equal(immediate.body.task.attempts, 2);
});

test('task API reports missing or busy claims and rejects forged transition ownership', async (t) => {
  const { base } = await serverFixture(t);
  const missing = await json(base, '/api/tasks/no-task/claim', { method: 'POST', body: JSON.stringify({ workerId: 'worker-a' }) });
  assert.equal(missing.response.status, 404);
  await json(base, '/api/tasks', { method: 'POST', body: JSON.stringify({ taskId: 'owned-by-a', type: 'analysis' }) });
  const claim = await json(base, '/api/tasks/owned-by-a/claim', { method: 'POST', body: JSON.stringify({ workerId: 'worker-a' }) });
  const forged = await json(base, '/api/tasks/owned-by-a/transition', { method: 'POST', body: JSON.stringify({ state: 'succeeded', workerId: 'worker-b', fencingToken: claim.body.task.lease.fencingToken }) });
  assert.equal(forged.response.status, 400);
  const missingOwner = await json(base, '/api/tasks/owned-by-a/transition', { method: 'POST', body: JSON.stringify({ state: 'succeeded' }) });
  assert.equal(missingOwner.response.status, 400);
  const busy = await json(base, '/api/tasks/owned-by-a/claim', { method: 'POST', body: JSON.stringify({ workerId: 'worker-b' }) });
  assert.equal(busy.response.status, 409);
  const primitiveCancel = await json(base, '/api/tasks/owned-by-a/cancel', { method: 'POST', body: JSON.stringify(false) });
  assert.equal(primitiveCancel.response.status, 400);
});

test('task API cannot bypass claim or reuse a stale fencing token', async (t) => {
  const { base, setNow } = await serverFixture(t);
  await json(base, '/api/tasks', { method: 'POST', body: JSON.stringify({ taskId: 'api-fenced', type: 'analysis' }) });
  const bypass = await json(base, '/api/tasks/api-fenced/transition', { method: 'POST', body: JSON.stringify({ state: 'preparing' }) });
  assert.equal(bypass.response.status, 400);
  const first = await json(base, '/api/tasks/api-fenced/claim', { method: 'POST', body: JSON.stringify({ workerId: 'worker-a', ttlMs: 1 }) });
  const token = first.body.task.lease.fencingToken;
  setNow(Date.parse('2026-10-18T00:00:00.001Z'));
  const second = await json(base, '/api/tasks/api-fenced/claim', { method: 'POST', body: JSON.stringify({ workerId: 'worker-a', ttlMs: 1000 }) });
  assert.notEqual(second.body.task.lease.fencingToken, token);
  const stale = await json(base, '/api/tasks/api-fenced/heartbeat', { method: 'POST', body: JSON.stringify({ workerId: 'worker-a', fencingToken: token }) });
  assert.equal(stale.response.status, 400);
  const fresh = await json(base, '/api/tasks/api-fenced/heartbeat', { method: 'POST', body: JSON.stringify({ workerId: 'worker-a', fencingToken: second.body.task.lease.fencingToken }) });
  assert.equal(fresh.response.status, 200);
});
