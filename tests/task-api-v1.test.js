import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, mkdtemp, rm, symlink, truncate, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { TaskStateStore } from '../src/task-state.js';
import { startServer } from '../src/web-server.js';
import { ANALYSIS_TASK_TYPE } from '../src/analysis-task-handler.js';

async function serverFixture(t) {
  const dir = await mkdtemp(join(tmpdir(), 'task-api-v1-'));
  const evidenceRoot = join(dir, 'evidence');
  await mkdir(evidenceRoot);
  let current = Date.parse('2026-10-18T00:00:00.000Z');
  const store = new TaskStateStore({ path: join(dir, 'tasks.json'), clock: () => current });
  const server = startServer({
    port: 0,
    taskStore: store,
    evidenceRoot,
    snapshotProvider: async () => ({ generatedAt: '2026-10-18T00:00:00.000Z', activeTask: null, activeChain: null, queue: [] }),
  });
  await once(server, 'listening');
  t.after(async () => {
    server.stop();
    if (server.listening) await once(server, 'close');
    await rm(dir, { recursive: true, force: true });
  });
  return { base: `http://127.0.0.1:${server.address().port}`, dir, evidenceRoot, store, setNow(value) { current = value; } };
}

async function fixture(t) {
  return (await serverFixture(t)).base;
}

async function completedReportFixture(context, {
  taskId = 'report-task',
  type = ANALYSIS_TASK_TYPE,
  reportText = JSON.stringify({ state: 'completed', findings: [] }),
  reportBuffer = Buffer.from(reportText),
  writeReport = true,
  attemptDirectoryOverride,
  phase = 'evidence_ready',
  finalState = 'succeeded',
  reportBytesOverride,
  reportSha256Override,
} = {}) {
  await context.store.create({ taskId, type });
  const workerId = 'report-worker';
  const claimed = await context.store.claim(workerId, { taskId });
  const fencingToken = claimed.lease.fencingToken;
  await context.store.transitionOwned(taskId, 'running', workerId, fencingToken);

  const taskDirectory = join(context.evidenceRoot, createHash('sha256').update(taskId).digest('hex'));
  const attemptName = `attempt-1-${randomUUID()}`;
  const attemptDirectory = attemptDirectoryOverride || join(taskDirectory, attemptName);
  const reportPath = join(attemptDirectory, 'static-analysis.json');
  await mkdir(attemptDirectory, { recursive: true });
  if (writeReport) await writeFile(reportPath, reportBuffer);
  const reportBytes = reportBytesOverride ?? reportBuffer.length;
  const reportSha256 = reportSha256Override ?? createHash('sha256').update(reportBuffer).digest('hex');
  await context.store.checkpoint(taskId, {
    schemaVersion: 1,
    phase,
    attempt: 1,
    attemptDirectory,
    reportPath,
    reportBytes,
    reportSha256,
  }, workerId, fencingToken);
  await context.store.transitionOwned(taskId, finalState, workerId, fencingToken);
  return { taskId, taskDirectory, attemptDirectory, reportPath };
}

async function completedReverseArtifactFixture(context, {
  taskId = 'reverse-artifact-task',
  type = 'v1-resource-decompile',
  state = 'succeeded',
  artifacts = [
    { name: 'decompiled.sol', kind: 'solidity-pseudocode', content: 'contract Recovered { function ping() external {} }\n' },
    { name: 'unified-ir.json', kind: 'unified-ir', content: '{"schemaVersion":1,"functions":[]}\n' },
  ],
} = {}) {
  await context.store.create({ taskId, type });
  const workerId = 'reverse-artifact-worker';
  const claimed = await context.store.claim(workerId, { taskId });
  const fencingToken = claimed.lease.fencingToken;
  await context.store.transitionOwned(taskId, 'running', workerId, fencingToken);
  const taskDirectory = join(context.evidenceRoot, createHash('sha256').update(taskId).digest('hex'));
  const attemptDirectory = join(taskDirectory, `attempt-1-${randomUUID()}`);
  await mkdir(attemptDirectory, { recursive: true });
  const descriptors = [];
  for (const item of artifacts) {
    const path = item.path || join(attemptDirectory, item.name);
    const bytes = item.buffer || Buffer.from(item.content);
    if (item.symlinkTo) {
      await writeFile(item.symlinkTo, bytes);
      await symlink(item.symlinkTo, path);
    } else await writeFile(path, bytes);
    descriptors.push({ path, kind: item.kind, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') });
  }
  await context.store.checkpoint(taskId, { phase: 'evidence_ready', attemptDirectory, artifacts: descriptors }, workerId, fencingToken);
  await context.store.transitionOwned(taskId, state, workerId, fencingToken);
  return { taskId, attemptDirectory, artifacts: descriptors };
}

async function json(base, path, options = {}) {
  const response = await fetch(`${base}${path}`, {
    ...options,
    headers: { 'content-type': 'application/json', ...(options.headers || {}) },
  });
  return { response, body: await response.json() };
}

test('v1 task list uses a stable cursor and rejects loose query parameters', async (t) => {
  const base = await fixture(t);
  for (const taskId of ['task-c', 'task-a', 'task-b']) {
    const created = await json(base, '/api/v1/tasks', { method: 'POST', body: JSON.stringify({ taskId, type: 'analysis', priority: 2 }) });
    assert.equal(created.response.status, 201);
    assert.equal(created.body.apiVersion, 'v1');
    assert.equal(created.body.schemaVersion, 1);
    assert.equal(created.body.data.taskId, taskId);
    assert.equal(typeof created.body.consistency.revision, 'number');
  }
  const first = await json(base, '/api/v1/tasks?state=queued&limit=2');
  assert.equal(first.response.status, 200);
  assert.deepEqual(first.body.items.map((task) => task.taskId), ['task-a', 'task-b']);
  assert.equal(first.body.page.limit, 2);
  assert.equal(first.body.page.hasMore, true);
  assert.ok(first.body.page.nextCursor);

  const second = await json(base, `/api/v1/tasks?state=queued&limit=2&cursor=${encodeURIComponent(first.body.page.nextCursor)}`);
  assert.equal(second.response.status, 200);
  assert.deepEqual(second.body.items.map((task) => task.taskId), ['task-c']);
  assert.equal(second.body.page.hasMore, false);

  for (const query of ['unknown=x', 'limit=0', 'limit=1.5', 'limit=1&limit=2', 'cursor=not-a-cursor']) {
    const bad = await json(base, `/api/v1/tasks?${query}`);
    assert.equal(bad.response.status, 400, query);
    assert.equal(bad.body.apiVersion, 'v1');
    assert.ok(bad.body.error?.requestId);
    if (query === 'cursor=not-a-cursor') assert.equal(bad.body.error.code, 'invalid_cursor');
  }

  for (const query of [
    'state=queued&state=failed',
    `cursor=${encodeURIComponent(first.body.page.nextCursor)}&cursor=${encodeURIComponent(first.body.page.nextCursor)}`,
  ]) {
    const duplicate = await json(base, `/api/v1/tasks?${query}`);
    assert.equal(duplicate.response.status, 400, query);
    assert.equal(duplicate.body.apiVersion, 'v1');
    assert.equal(duplicate.body.error.code, 'duplicate_query_parameter');
  }
});

test('v1 task reads and worker actions return data with current consistency', async (t) => {
  const base = await fixture(t);
  const created = await json(base, '/api/v1/tasks', { method: 'POST', body: JSON.stringify({ taskId: 'worker-task', type: 'analysis' }) });
  const claim = await json(base, '/api/v1/tasks/worker-task/claim', { method: 'POST', body: JSON.stringify({ workerId: 'worker-a', ttlMs: 1000 }) });
  assert.equal(claim.response.status, 200);
  assert.equal(claim.body.data.state, 'preparing');
  assert.equal(claim.body.data.lease.workerId, 'worker-a');
  const fetched = await json(base, '/api/v1/tasks/worker-task');
  assert.equal(fetched.response.status, 200);
  assert.equal(fetched.body.data.taskId, 'worker-task');
  assert.equal(fetched.body.consistency.revision, claim.body.consistency.revision);
  assert.ok(fetched.body.consistency.asOf);
  assert.notEqual(created.body.consistency.revision, claim.body.consistency.revision);
});

test('v1 fail route uses default backoff and honors an explicit zero delay', async (t) => {
  const { base, setNow } = await serverFixture(t);
  const start = Date.parse('2026-10-18T00:00:00Z');
  await json(base, '/api/v1/tasks', { method: 'POST', body: JSON.stringify({ taskId: 'v1-default-backoff', type: 'analysis', maxAttempts: 2 }) });
  const first = await json(base, '/api/v1/tasks/v1-default-backoff/claim', { method: 'POST', body: JSON.stringify({ workerId: 'worker-a' }) });
  const failed = await json(base, '/api/v1/tasks/v1-default-backoff/fail', {
    method: 'POST',
    body: JSON.stringify({ workerId: 'worker-a', fencingToken: first.body.data.lease.fencingToken, retryable: true }),
  });
  assert.equal(failed.response.status, 200);
  assert.equal(failed.body.data.nextRetryAt, new Date(start + 1_000).toISOString());

  const tooSoon = await json(base, '/api/v1/tasks/v1-default-backoff/claim', { method: 'POST', body: JSON.stringify({ workerId: 'worker-b' }) });
  assert.equal(tooSoon.response.status, 409);
  setNow(start + 999);
  const beforeDue = await json(base, '/api/v1/tasks/v1-default-backoff/claim', { method: 'POST', body: JSON.stringify({ workerId: 'worker-b' }) });
  assert.equal(beforeDue.response.status, 409);
  setNow(start + 1_000);
  const due = await json(base, '/api/v1/tasks/v1-default-backoff/claim', { method: 'POST', body: JSON.stringify({ workerId: 'worker-b' }) });
  assert.equal(due.response.status, 200);
  assert.equal(due.body.data.attempts, 2);

  await json(base, '/api/v1/tasks', { method: 'POST', body: JSON.stringify({ taskId: 'v1-zero-delay', type: 'analysis', maxAttempts: 2 }) });
  const zeroFirst = await json(base, '/api/v1/tasks/v1-zero-delay/claim', { method: 'POST', body: JSON.stringify({ workerId: 'worker-a' }) });
  const zeroFail = await json(base, '/api/v1/tasks/v1-zero-delay/fail', {
    method: 'POST',
    body: JSON.stringify({ workerId: 'worker-a', fencingToken: zeroFirst.body.data.lease.fencingToken, retryable: true, retryDelayMs: 0 }),
  });
  assert.equal(zeroFail.response.status, 200);
  assert.equal(zeroFail.body.data.nextRetryAt, null);
  const immediate = await json(base, '/api/v1/tasks/v1-zero-delay/claim', { method: 'POST', body: JSON.stringify({ workerId: 'worker-b' }) });
  assert.equal(immediate.response.status, 200);
  assert.equal(immediate.body.data.attempts, 2);
});

test('v1 completed local-source-analysis report returns parsed JSON, SHA-256, and consistency', async (t) => {
  const context = await serverFixture(t);
  const reportText = JSON.stringify({ state: 'completed', findingCount: 2, findings: [{ id: 'A' }, { id: 'B' }] });
  const report = await completedReportFixture(context, { reportText });
  const result = await json(context.base, `/api/v1/tasks/${report.taskId}/report`);
  assert.equal(result.response.status, 200);
  assert.equal(result.body.apiVersion, 'v1');
  assert.equal(result.body.schemaVersion, 1);
  assert.deepEqual(result.body.data.report, JSON.parse(reportText));
  assert.equal(result.body.data.sha256, createHash('sha256').update(reportText).digest('hex'));
  assert.equal(typeof result.body.consistency.revision, 'number');
  assert.ok(result.body.consistency.asOf);
});

test('v1 report rejects post-completion replacement even when the task revision is unchanged', async (t) => {
  const context = await serverFixture(t);
  const reportText = JSON.stringify({ state: 'completed', findings: [{ id: 'A' }] });
  const report = await completedReportFixture(context, { taskId: 'tampered-report', reportText });
  const first = await json(context.base, `/api/v1/tasks/${report.taskId}/report`);
  assert.equal(first.response.status, 200);
  const taskBefore = await context.store.readTask(report.taskId);
  await writeFile(report.reportPath, JSON.stringify({ state: 'completed', findings: [{ id: 'B' }] }));
  const replaced = await json(context.base, `/api/v1/tasks/${report.taskId}/report`);
  assert.equal(replaced.response.status, 409);
  assert.equal(replaced.body.error.code, 'report_integrity_mismatch');
  const taskAfter = await context.store.readTask(report.taskId);
  assert.equal(taskAfter.revision, taskBefore.revision);
});

test('v1 report requires a valid checkpoint byte count and SHA-256 binding', async (t) => {
  const context = await serverFixture(t);
  const badLength = await completedReportFixture(context, { taskId: 'bad-report-length', reportBytesOverride: 1 });
  const lengthResult = await json(context.base, `/api/v1/tasks/${badLength.taskId}/report`);
  assert.equal(lengthResult.response.status, 409);
  assert.equal(lengthResult.body.error.code, 'report_integrity_mismatch');

  const badDigest = await completedReportFixture(context, { taskId: 'bad-report-digest', reportSha256Override: '0'.repeat(64) });
  const digestResult = await json(context.base, `/api/v1/tasks/${badDigest.taskId}/report`);
  assert.equal(digestResult.response.status, 409);
  assert.equal(digestResult.body.error.code, 'report_integrity_mismatch');

  const invalidBinding = await completedReportFixture(context, { taskId: 'invalid-report-binding', reportSha256Override: 'invalid' });
  const bindingResult = await json(context.base, `/api/v1/tasks/${invalidBinding.taskId}/report`);
  assert.equal(bindingResult.response.status, 409);
  assert.equal(bindingResult.body.error.code, 'invalid_evidence_checkpoint');
});

test('v1 report rejects wrong task types, unknown tasks, and missing evidence', async (t) => {
  const context = await serverFixture(t);
  await completedReportFixture(context, { taskId: 'wrong-type', type: 'analysis' });
  const wrongType = await json(context.base, '/api/v1/tasks/wrong-type/report');
  assert.equal(wrongType.response.status, 409);
  assert.equal(wrongType.body.error.code, 'wrong_task_type');

  const unknown = await json(context.base, '/api/v1/tasks/unknown-task/report');
  assert.equal(unknown.response.status, 404);

  await completedReportFixture(context, { taskId: 'missing-evidence', writeReport: false });
  const missing = await json(context.base, '/api/v1/tasks/missing-evidence/report');
  assert.equal(missing.response.status, 404);

  await completedReportFixture(context, { taskId: 'not-ready', phase: 'input_validated' });
  const notReady = await json(context.base, '/api/v1/tasks/not-ready/report');
  assert.equal(notReady.response.status, 409);
  assert.equal(notReady.body.error.code, 'evidence_not_ready');
});

test('v1 report rejects checkpoints escaping the hashed task evidence directory and symlinked evidence', async (t) => {
  const context = await serverFixture(t);
  const escapedPath = join(context.dir, `attempt-1-${randomUUID()}`);
  const escaped = await completedReportFixture(context, { taskId: 'escaped-report', attemptDirectoryOverride: escapedPath });
  const escapedResult = await json(context.base, `/api/v1/tasks/${escaped.taskId}/report`);
  assert.equal(escapedResult.response.status, 403);

  const linked = await completedReportFixture(context, { taskId: 'linked-report', writeReport: false });
  const outside = join(context.dir, 'outside');
  await mkdir(outside);
  await writeFile(join(outside, 'static-analysis.json'), '{"state":"completed"}');
  await rm(linked.attemptDirectory, { recursive: true });
  await symlink(outside, linked.attemptDirectory);
  const linkedResult = await json(context.base, `/api/v1/tasks/${linked.taskId}/report`);
  assert.equal(linkedResult.response.status, 403);
});

test('v1 report rejects query strings and non-GET methods', async (t) => {
  const context = await serverFixture(t);
  const report = await completedReportFixture(context);
  const query = await json(context.base, `/api/v1/tasks/${report.taskId}/report?download=1`);
  assert.equal(query.response.status, 400);
  assert.equal(query.body.error.code, 'unknown_query_parameter');
  const method = await json(context.base, `/api/v1/tasks/${report.taskId}/report`, { method: 'POST', body: '{}' });
  assert.equal(method.response.status, 405);
  assert.equal(method.body.error.code, 'method_not_allowed');
});

test('v1 report rejects malformed and oversized report files', async (t) => {
  const context = await serverFixture(t);
  const malformed = await completedReportFixture(context, { taskId: 'malformed-report', reportText: '{broken' });
  const malformedResult = await json(context.base, `/api/v1/tasks/${malformed.taskId}/report`);
  assert.equal(malformedResult.response.status, 422);

  const oversized = await completedReportFixture(context, { taskId: 'oversized-report', writeReport: false });
  await writeFile(oversized.reportPath, '');
  await truncate(oversized.reportPath, 64 * 1024 * 1024 + 1);
  const oversizedResult = await json(context.base, `/api/v1/tasks/${oversized.taskId}/report`);
  assert.equal(oversizedResult.response.status, 413);
});

test('v1 report rejects invalid UTF-8 after verifying the checkpoint fingerprint', async (t) => {
  const context = await serverFixture(t);
  const report = await completedReportFixture(context, {
    taskId: 'invalid-utf8-report',
    reportBuffer: Buffer.from([0x7b, 0x22, 0x78, 0x22, 0x3a, 0xff, 0x7d]),
  });
  const result = await json(context.base, `/api/v1/tasks/${report.taskId}/report`);
  assert.equal(result.response.status, 422);
  assert.equal(result.body.error.code, 'invalid_report');
});

test('v1 report parsing rejects concurrent reads while a report is being processed', async (t) => {
  const context = await serverFixture(t);
  const report = await completedReportFixture(context, { taskId: 'busy-report' });
  const originalReadTask = context.store.readTask.bind(context.store);
  let releaseRead;
  let enteredRead;
  let held = false;
  const readHeld = new Promise((resolve) => { enteredRead = resolve; });
  const release = new Promise((resolve) => { releaseRead = resolve; });
  context.store.readTask = async (...args) => {
    const result = await originalReadTask(...args);
    if (!held && args[0] === report.taskId) {
      held = true;
      enteredRead();
      await release;
    }
    return result;
  };

  const firstRequest = json(context.base, `/api/v1/tasks/${report.taskId}/report`);
  await readHeld;
  const secondRequest = await json(context.base, `/api/v1/tasks/${report.taskId}/report`);
  assert.equal(secondRequest.response.status, 503);
  assert.equal(secondRequest.body.error.code, 'report_read_busy');
  releaseRead();
  const firstResponse = await firstRequest;
  assert.equal(firstResponse.response.status, 200);
});

test('v1 reverse artifact reads expose only current checkpointed text with verified integrity', async (t) => {
  const context = await serverFixture(t);
  const fixture = await completedReverseArtifactFixture(context);
  for (const descriptor of fixture.artifacts) {
    const response = await json(context.base, `/api/v1/tasks/${fixture.taskId}/artifacts/${descriptor.sha256}/content`);
    assert.equal(response.response.status, 200, JSON.stringify(response.body));
    assert.equal(response.body.data.content, descriptor.kind === 'unified-ir'
      ? '{"schemaVersion":1,"functions":[]}\n'
      : 'contract Recovered { function ping() external {} }\n');
    assert.equal(response.body.data.sha256, descriptor.sha256);
    assert.equal(response.body.data.bytes, descriptor.bytes);
  }

  await writeFile(fixture.artifacts[0].path, 'contract Tampered {}\n');
  const tampered = await json(context.base, `/api/v1/tasks/${fixture.taskId}/artifacts/${fixture.artifacts[0].sha256}/content`);
  assert.equal(tampered.response.status, 409);
  assert.equal(tampered.body.error.code, 'artifact_integrity_mismatch');
  assert.doesNotMatch(JSON.stringify(tampered.body), /Desktop|evidence|attempt-/);
});

test('v1 reverse artifact reads reject unknown, wrong-type, and unfinished tasks', async (t) => {
  const context = await serverFixture(t);
  const valid = await completedReverseArtifactFixture(context, { taskId: 'artifact-valid' });
  const wrongType = await completedReverseArtifactFixture(context, { taskId: 'artifact-wrong-type', type: 'analysis' });
  const queued = await context.store.create({ taskId: 'artifact-queued', type: 'v1-resource-decompile' });
  assert.ok(queued);

  const unknown = await json(context.base, `/api/v1/tasks/missing-artifact-task/artifacts/${valid.artifacts[0].sha256}/content`);
  assert.equal(unknown.response.status, 404);
  const wrong = await json(context.base, `/api/v1/tasks/${wrongType.taskId}/artifacts/${wrongType.artifacts[0].sha256}/content`);
  assert.equal(wrong.response.status, 409);
  assert.equal(wrong.body.error.code, 'wrong_task_type');
  const notReady = await json(context.base, `/api/v1/tasks/artifact-queued/artifacts/${valid.artifacts[0].sha256}/content`);
  assert.equal(notReady.response.status, 409);
  assert.equal(notReady.body.error.code, 'evidence_not_ready');
  const unregistered = await json(context.base, `/api/v1/tasks/${valid.taskId}/artifacts/${'a'.repeat(64)}/content`);
  assert.equal(unregistered.response.status, 404);
});

test('v1 reverse artifact reads reject escaped paths, symlinks, oversized files, and invalid text', async (t) => {
  const context = await serverFixture(t);
  const escapedPath = join(context.dir, 'escaped.sol');
  const escaped = await completedReverseArtifactFixture(context, {
    taskId: 'artifact-escaped-path',
    artifacts: [{ name: 'unused.sol', path: escapedPath, kind: 'solidity-pseudocode', content: 'contract Escaped {}' }],
  });
  const escapedResult = await json(context.base, `/api/v1/tasks/${escaped.taskId}/artifacts/${escaped.artifacts[0].sha256}/content`);
  assert.equal(escapedResult.response.status, 403);
  assert.equal(escapedResult.body.error.code, 'artifact_path_forbidden');

  const linked = await completedReverseArtifactFixture(context, {
    taskId: 'artifact-symlink',
    artifacts: [{ name: 'linked.sol', symlinkTo: join(context.dir, 'link-target.sol'), kind: 'solidity-pseudocode', content: 'contract Linked {}' }],
  });
  const linkedResult = await json(context.base, `/api/v1/tasks/${linked.taskId}/artifacts/${linked.artifacts[0].sha256}/content`);
  assert.equal(linkedResult.response.status, 403);

  const oversized = await completedReverseArtifactFixture(context, {
    taskId: 'artifact-oversized',
    artifacts: [{ name: 'large.sol', kind: 'solidity-pseudocode', buffer: Buffer.alloc(4 * 1024 * 1024 + 1, 0x20) }],
  });
  const largeResult = await json(context.base, `/api/v1/tasks/${oversized.taskId}/artifacts/${oversized.artifacts[0].sha256}/content`);
  assert.equal(largeResult.response.status, 413);
  assert.equal(largeResult.body.error.code, 'artifact_too_large');

  const invalidUtf8 = await completedReverseArtifactFixture(context, {
    taskId: 'artifact-invalid-utf8',
    artifacts: [{ name: 'invalid.sol', kind: 'solidity-pseudocode', buffer: Buffer.from([0x63, 0x6f, 0x6e, 0xff]) }],
  });
  const invalidText = await json(context.base, `/api/v1/tasks/${invalidUtf8.taskId}/artifacts/${invalidUtf8.artifacts[0].sha256}/content`);
  assert.equal(invalidText.response.status, 422);
  assert.equal(invalidText.body.error.code, 'artifact_invalid_text');

  const invalidJson = await completedReverseArtifactFixture(context, {
    taskId: 'artifact-invalid-json',
    artifacts: [{ name: 'invalid.json', kind: 'unified-ir', content: '{broken json}' }],
  });
  const badJson = await json(context.base, `/api/v1/tasks/${invalidJson.taskId}/artifacts/${invalidJson.artifacts[0].sha256}/content`);
  assert.equal(badJson.response.status, 422);
  assert.equal(badJson.body.error.code, 'artifact_invalid_json');
});

test('v1 reverse artifact reads reject concurrent reads without blocking task operations', async (t) => {
  const context = await serverFixture(t);
  const fixture = await completedReverseArtifactFixture(context, { taskId: 'artifact-busy' });
  const originalReadTask = context.store.readTask.bind(context.store);
  let releaseRead;
  let enteredRead;
  let held = false;
  const readHeld = new Promise((resolve) => { enteredRead = resolve; });
  const release = new Promise((resolve) => { releaseRead = resolve; });
  context.store.readTask = async (...args) => {
    const result = await originalReadTask(...args);
    if (!held && args[0] === fixture.taskId) {
      held = true;
      enteredRead();
      await release;
    }
    return result;
  };
  const firstRequest = json(context.base, `/api/v1/tasks/${fixture.taskId}/artifacts/${fixture.artifacts[0].sha256}/content`);
  await readHeld;
  const secondRequest = await json(context.base, `/api/v1/tasks/${fixture.taskId}/artifacts/${fixture.artifacts[0].sha256}/content`);
  assert.equal(secondRequest.response.status, 503);
  assert.equal(secondRequest.body.error.code, 'artifact_read_busy');
  releaseRead();
  const firstResponse = await firstRequest;
  assert.equal(firstResponse.response.status, 200);
});

test('v1 operator mutations require the observed revision and reject stale writes', async (t) => {
  const base = await fixture(t);
  const created = await json(base, '/api/v1/tasks', { method: 'POST', body: JSON.stringify({ taskId: 'operator-task', type: 'analysis' }) });
  const revision = created.body.consistency.revision;
  const cancelled = await json(base, '/api/v1/tasks/operator-task/cancel', {
    method: 'POST',
    headers: { 'if-match': `W/"${revision}"` },
    body: JSON.stringify({ reason: 'operator requested' }),
  });
  assert.equal(cancelled.response.status, 200);
  assert.equal(cancelled.body.data.state, 'cancelled');

  const stale = await json(base, '/api/v1/tasks/operator-task/resume', {
    method: 'POST',
    body: JSON.stringify({ expectedRevision: revision }),
  });
  assert.equal(stale.response.status, 412);
  assert.equal(stale.body.apiVersion, 'v1');
  assert.equal(stale.body.error.code, 'REVISION_MISMATCH');
  assert.ok(stale.body.error.requestId);

  const currentRevision = cancelled.body.consistency.revision;
  const repeatedCancel = await json(base, '/api/v1/tasks/operator-task/cancel', {
    method: 'POST',
    body: JSON.stringify({ expectedRevision: currentRevision, reason: 'confirm cancellation' }),
  });
  assert.equal(repeatedCancel.response.status, 200);
  assert.equal(repeatedCancel.body.data.state, 'cancelled');

  const resumable = await json(base, '/api/v1/tasks', { method: 'POST', body: JSON.stringify({ taskId: 'resumable-task', type: 'analysis' }) });
  const claim = await json(base, '/api/v1/tasks/resumable-task/claim', { method: 'POST', body: JSON.stringify({ workerId: 'worker-a' }) });
  await json(base, '/api/v1/tasks/resumable-task/pause', { method: 'POST', body: JSON.stringify({ workerId: 'worker-a', fencingToken: claim.body.data.lease.fencingToken }) });
  const paused = await json(base, '/api/v1/tasks/resumable-task');
  const resumed = await json(base, '/api/v1/tasks/resumable-task/resume', {
    method: 'POST',
    body: JSON.stringify({ expectedRevision: paused.body.consistency.revision, reason: 'retry' }),
  });
  assert.equal(resumed.response.status, 200);
  assert.equal(resumed.body.data.state, 'queued');

  const duplicateRevision = await json(base, '/api/v1/tasks/operator-task/cancel', {
    method: 'POST',
    headers: { 'if-match': String(repeatedCancel.body.consistency.revision) },
    body: JSON.stringify({ expectedRevision: repeatedCancel.body.consistency.revision }),
  });
  assert.equal(duplicateRevision.response.status, 400);
  assert.equal(duplicateRevision.body.error.code, 'duplicate_revision');
});

test('v1 operator pause is revision checked for queued and active work and can be resumed', async (t) => {
  const base = await fixture(t);
  const queued = await json(base, '/api/v1/tasks', { method: 'POST', body: JSON.stringify({ taskId: 'operator-pause-queued', type: 'analysis' }) });
  const pausedQueued = await json(base, '/api/v1/tasks/operator-pause-queued/pause', {
    method: 'POST', body: JSON.stringify({ expectedRevision: queued.body.consistency.revision }),
  });
  assert.equal(pausedQueued.response.status, 200);
  assert.equal(pausedQueued.body.data.state, 'paused');
  assert.equal(pausedQueued.body.data.lease, null);
  const stale = await json(base, '/api/v1/tasks/operator-pause-queued/pause', {
    method: 'POST', body: JSON.stringify({ expectedRevision: queued.body.consistency.revision }),
  });
  assert.equal(stale.response.status, 412);
  const resumed = await json(base, '/api/v1/tasks/operator-pause-queued/resume', {
    method: 'POST', body: JSON.stringify({ expectedRevision: pausedQueued.body.consistency.revision }),
  });
  assert.equal(resumed.response.status, 200);
  assert.equal(resumed.body.data.state, 'queued');

  await json(base, '/api/v1/tasks', { method: 'POST', body: JSON.stringify({ taskId: 'operator-pause-active', type: 'analysis' }) });
  const claim = await json(base, '/api/v1/tasks/operator-pause-active/claim', { method: 'POST', body: JSON.stringify({ workerId: 'worker-a' }) });
  const active = await json(base, '/api/v1/tasks/operator-pause-active');
  const pausedActive = await json(base, '/api/v1/tasks/operator-pause-active/pause', {
    method: 'POST', headers: { 'if-match': `W/"${active.body.consistency.revision}"` }, body: JSON.stringify({ reason: 'operator paused' }),
  });
  assert.equal(pausedActive.response.status, 200);
  assert.equal(pausedActive.body.data.state, 'paused');
  assert.equal(pausedActive.body.data.lease, null);
  assert.notEqual(claim.body.data.lease.fencingToken, pausedActive.body.data.lease?.fencingToken);
});

test('v1 resume continues a paused task at maxAttempts without granting another retry', async (t) => {
  const base = await fixture(t);
  const created = await json(base, '/api/v1/tasks', {
    method: 'POST',
    body: JSON.stringify({ taskId: 'api-resume-at-limit', type: 'analysis', maxAttempts: 1 }),
  });
  const firstClaim = await json(base, '/api/v1/tasks/api-resume-at-limit/claim', {
    method: 'POST', body: JSON.stringify({ workerId: 'worker-a' }),
  });
  await json(base, '/api/v1/tasks/api-resume-at-limit/checkpoint', {
    method: 'POST',
    body: JSON.stringify({ workerId: 'worker-a', fencingToken: firstClaim.body.data.lease.fencingToken, checkpoint: { phase: 'analysis', cursor: 9 } }),
  });
  await json(base, '/api/v1/tasks/api-resume-at-limit/pause', {
    method: 'POST',
    body: JSON.stringify({ workerId: 'worker-a', fencingToken: firstClaim.body.data.lease.fencingToken }),
  });
  const paused = await json(base, '/api/v1/tasks/api-resume-at-limit');
  const resumed = await json(base, '/api/v1/tasks/api-resume-at-limit/resume', {
    method: 'POST', body: JSON.stringify({ expectedRevision: paused.body.consistency.revision }),
  });
  assert.equal(resumed.response.status, 200);
  assert.equal(resumed.body.data.resumePending, true);

  const continuation = await json(base, '/api/v1/tasks/api-resume-at-limit/claim', {
    method: 'POST', body: JSON.stringify({ workerId: 'worker-b' }),
  });
  assert.equal(continuation.response.status, 200);
  assert.equal(continuation.body.data.attempts, 1);
  assert.equal(continuation.body.data.resumePending, false);
  assert.deepEqual(continuation.body.data.checkpoint, { phase: 'analysis', cursor: 9 });

  const exhausted = await json(base, '/api/v1/tasks/api-resume-at-limit/fail', {
    method: 'POST',
    body: JSON.stringify({ workerId: 'worker-b', fencingToken: continuation.body.data.lease.fencingToken, retryable: true, error: 'still failing' }),
  });
  assert.equal(exhausted.body.data.state, 'failed');
  assert.equal(exhausted.body.data.nextRetryAt, null);
  assert.equal(created.body.data.maxAttempts, 1);
});

