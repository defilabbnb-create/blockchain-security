import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { TaskStateStore } from '../src/task-state.js';
import { runAnalysisTasks } from '../scripts/run-analysis-tasks.mjs';
import { ResourceApiOperations } from '../src/resource-api-operations.js';
import { startServer } from '../src/web-server.js';

async function fixture(t, snapshotProvider = async () => ({ generatedAt: new Date().toISOString(), activeTask: null, activeChain: null, queue: [], findings: [], vulnerabilityChains: [] })) {
  const dir = await mkdtemp(join(tmpdir(), 'resource-api-http-'));
  const artifactRoot = join(dir, 'artifacts');
  await mkdir(artifactRoot);
  const taskStore = new TaskStateStore({ path: join(dir, 'tasks.json') });
  const operations = new ResourceApiOperations({ path: join(dir, 'resources.json'), auditPath: join(dir, 'review-audit.jsonl') });
  const server = startServer({
    port: 0,
    taskStore,
    resourceOperations: operations,
    resourceArtifactRoots: [dir],
    evidenceRoot: join(dir, 'analysis-task-evidence'),
    snapshotProvider,
  });
  await once(server, 'listening');
  const base = `http://127.0.0.1:${server.address().port}`;
  t.after(async () => {
    server.stop();
    if (server.listening) await once(server, 'close');
    await rm(dir, { recursive: true, force: true });
  });
  return { base, artifactRoot, dir };
}

async function request(base, path, options = {}) {
  const response = await fetch(`${base}${path}`, {
    ...options,
    headers: { ...(options.body === undefined ? {} : { 'content-type': 'application/json' }), ...(options.headers || {}) },
  });
  const body = response.status === 204 ? null : await response.json();
  return { response, body };
}

test('v1 capabilities and project resources are wired to persistent tasks', async (t) => {
  const { base, artifactRoot } = await fixture(t);
  const capabilities = await request(base, '/api/v1/capabilities');
  assert.equal(capabilities.response.status, 200);
  const advertised = capabilities.body.capabilities;
  for (const resource of ['projects', 'bytecode', 'decompile']) {
    assert.equal(advertised[resource].state, 'available');
    assert.equal(advertised[resource].executionState, 'available');
  }
  for (const [resource, limitation] of [
    ['collection', /只读采集.*RPC/],
  ]) {
    assert.equal(advertised[resource].state, 'available', `${resource} HTTP route must remain advertised`);
    assert.equal(advertised[resource].executionState, 'available');
    assert.match(advertised[resource].limitation, limitation);
  }
  assert.equal(advertised.contracts.state, 'available');
  assert.equal(advertised.contracts.executionState, 'available');
  assert.match(advertised.contracts.limitation, /尚未验证部署代码/);
  const collection = await request(base, '/api/v1/collection', {
    method: 'POST',
    body: JSON.stringify({ projectId: 'demo', chainId: '1', rpcUrl: 'http://127.0.0.1:8545', fromBlock: '10', toBlock: '10' }),
  });
  assert.equal(collection.response.status, 202, JSON.stringify(collection.body));
  assert.equal(collection.body.accepted, true);
  assert.match(collection.body.data.taskId, /^[0-9a-f-]{36}$/);
  const created = await request(base, '/api/v1/projects', { method: 'POST', body: JSON.stringify({ projectId: 'demo', sourcePath: artifactRoot }) });
  assert.equal(created.response.status, 202, JSON.stringify(created.body));
  assert.equal(created.body.accepted, true);
  assert.match(created.body.data.taskId, /^[0-9a-f-]{36}$/);
  const listed = await request(base, '/api/v1/projects?limit=1');
  assert.equal(listed.response.status, 200);
  assert.equal(listed.body.items.length, 1);
  assert.equal(listed.body.items[0].input.sourcePath, artifactRoot);
  assert.equal(listed.body.items[0].state, created.body.data.state);

  const taskId = created.body.data.taskId;
  const taskRead = await request(base, `/api/v1/tasks/${taskId}`);
  assert.equal(taskRead.response.status, 200);
  assert.equal(taskRead.body.data.state, 'queued');
  assert.equal(taskRead.body.consistency.revision, listed.body.consistency.revision);

  const claimed = await request(base, `/api/v1/tasks/${taskId}/claim`, {
    method: 'POST', body: JSON.stringify({ workerId: 'resource-worker' }),
  });
  assert.equal(claimed.response.status, 200);
  assert.equal(claimed.body.data.state, 'preparing');

  const preparingList = await request(base, '/api/v1/projects?state=preparing');
  const preparingDetail = await request(base, `/api/v1/projects/${taskId}`);
  const preparingTask = await request(base, `/api/v1/tasks/${taskId}`);
  assert.equal(preparingList.response.status, 200);
  assert.equal(preparingList.body.items.length, 1);
  assert.equal(preparingList.body.items[0].state, preparingTask.body.data.state);
  assert.equal(preparingDetail.body.data.state, preparingTask.body.data.state);
  assert.equal(preparingList.body.consistency.revision, preparingTask.body.consistency.revision);
});

test('project API tasks run through the shared queue and expose integrity-checked artifacts', async (t) => {
  const { base, artifactRoot, dir } = await fixture(t);
  await (await import('node:fs/promises')).writeFile(join(artifactRoot, 'README.md'), '# fixture\n');
  await (await import('node:fs/promises')).mkdir(join(artifactRoot, 'contracts'));
  await (await import('node:fs/promises')).writeFile(join(artifactRoot, 'contracts', 'Vault.sol'), 'pragma solidity ^0.8.20; contract Vault {}\n');
  const created = await request(base, '/api/v1/projects', {
    method: 'POST', body: JSON.stringify({ projectId: 'runner-fixture', sourcePath: artifactRoot }),
  });
  assert.equal(created.response.status, 202);
  const drained = await runAnalysisTasks(['drain', '--test-state-path', join(dir, 'tasks.json'), '--timeout-ms', '60000'], {
    handlerOptions: { artifactRoots: [dir], evidenceRoot: join(dir, 'analysis-task-evidence') },
  });
  assert.equal(drained.state, 'completed', JSON.stringify(drained));
  const task = await request(base, `/api/v1/projects/${created.body.data.taskId}`);
  assert.equal(task.response.status, 200, JSON.stringify(task.body));
  assert.equal(task.body.data.state, 'succeeded');
  assert.ok(task.body.data.artifacts.some((artifact) => artifact.kind === 'project-import-manifest'));
  const contracts = await request(base, '/api/v1/contracts?projectId=runner-fixture');
  assert.equal(contracts.response.status, 200, JSON.stringify(contracts.body));
  assert.equal(contracts.body.items.length, 1);
  const sourceUnit = contracts.body.items[0];
  assert.equal(sourceUnit.sourcePath, 'contracts/Vault.sol');
  assert.equal(sourceUnit.language, 'solidity');
  assert.equal(sourceUnit.address, null);
  assert.equal(sourceUnit.mapping.state, 'source_file');
  assert.equal(sourceUnit.taskId, created.body.data.taskId);
  assert.match(sourceUnit.sourceSha256, /^[a-f0-9]{64}$/);
  const contractsAgain = await request(base, '/api/v1/contracts?projectId=runner-fixture');
  assert.equal(contractsAgain.body.items[0].contractId, sourceUnit.contractId);
  const detail = await request(base, `/api/v1/contracts/${sourceUnit.contractId}`);
  assert.equal(detail.response.status, 200);
  assert.equal(detail.body.data.sourceFingerprint, sourceUnit.sourceFingerprint);
  const missingBindingFields = await request(base, '/api/v1/contracts', {
    method: 'POST', body: JSON.stringify({ projectId: 'runner-fixture', contractId: sourceUnit.contractId }),
  });
  assert.equal(missingBindingFields.response.status, 400);
  const invalidAddress = await request(base, '/api/v1/contracts', {
    method: 'POST', body: JSON.stringify({ projectId: 'runner-fixture', contractId: sourceUnit.contractId, chainId: '1', address: '0x1234' }),
  });
  assert.equal(invalidAddress.response.status, 400);
  const mixedBytecode = await request(base, '/api/v1/bytecode', {
    method: 'POST', body: JSON.stringify({ projectId: 'runner-fixture', contractId: sourceUnit.contractId, chainId: '1', address: `0x${'1'.repeat(40)}`, block: '1', runtimeBytecode: '0x6000' }),
  });
  assert.equal(mixedBytecode.response.status, 400);
  const binding = await request(base, '/api/v1/contracts', {
    method: 'POST', body: JSON.stringify({ projectId: 'runner-fixture', contractId: sourceUnit.contractId, chainId: '1', address: `0x${'1'.repeat(40)}` }),
  });
  assert.equal(binding.response.status, 202, JSON.stringify(binding.body));
  const invalidBinding = await request(base, '/api/v1/contracts', {
    method: 'POST', body: JSON.stringify({ projectId: 'runner-fixture', contractId: 'not-bound', chainId: '1', address: `0x${'2'.repeat(40)}` }),
  });
  assert.equal(invalidBinding.response.status, 202, JSON.stringify(invalidBinding.body));
  const drainedBindings = await runAnalysisTasks(['drain', '--test-state-path', join(dir, 'tasks.json'), '--timeout-ms', '60000'], {
    handlerOptions: { artifactRoots: [dir], evidenceRoot: join(dir, 'analysis-task-evidence') },
  });
  assert.equal(drainedBindings.state, 'blocked');
  const contractTasks = await request(base, '/api/v1/contracts');
  const validTask = contractTasks.body.items.find((item) => item.input.contractId === sourceUnit.contractId);
  const blockedTask = contractTasks.body.items.find((item) => item.input.contractId === 'not-bound');
  assert.equal(validTask.state, 'succeeded');
  assert.equal(validTask.checkpoint.mapping.state, 'user_asserted');
  assert.equal(validTask.checkpoint.mapping.sourceVerified, false);
  assert.equal(validTask.checkpoint.mapping.deployedCodeCheck, 'not_performed');
  assert.equal(blockedTask.state, 'blocked');
});

test('contracts remain empty when no verified import manifest exists', async (t) => {
  const { base } = await fixture(t);
  const result = await request(base, '/api/v1/contracts');
  assert.equal(result.response.status, 200);
  assert.deepEqual(result.body.items, []);
});

test('contracts remain empty for a partial project import manifest', async (t) => {
  const { base, artifactRoot, dir } = await fixture(t);
  await (await import('node:fs/promises')).writeFile(join(artifactRoot, 'Vault.sol'), 'contract Vault {}\n');
  await (await import('node:fs/promises')).writeFile(join(artifactRoot, '.env'), 'SYNTHETIC_FIXTURE_SECRET=omitted\n');
  const created = await request(base, '/api/v1/projects', {
    method: 'POST', body: JSON.stringify({ projectId: 'partial-contracts-fixture', sourcePath: artifactRoot }),
  });
  assert.equal(created.response.status, 202, JSON.stringify(created.body));
  const drained = await runAnalysisTasks(['drain', '--test-state-path', join(dir, 'tasks.json'), '--timeout-ms', '60000'], {
    handlerOptions: { artifactRoots: [dir], evidenceRoot: join(dir, 'analysis-task-evidence') },
  });
  assert.equal(drained.state, 'partial', JSON.stringify(drained));
  const project = await request(base, `/api/v1/projects/${created.body.data.taskId}`);
  assert.equal(project.body.data.checkpoint.complete, false);
  const contracts = await request(base, '/api/v1/contracts?projectId=partial-contracts-fixture');
  assert.equal(contracts.response.status, 200, JSON.stringify(contracts.body));
  assert.deepEqual(contracts.body.items, []);
});

test('contracts fail closed when the bound manifest changes after import', async (t) => {
  const { base, artifactRoot, dir } = await fixture(t);
  await (await import('node:fs/promises')).writeFile(join(artifactRoot, 'Vault.sol'), 'contract Vault {}\n');
  const created = await request(base, '/api/v1/projects', { method: 'POST', body: JSON.stringify({ projectId: 'tampered-contracts-fixture', sourcePath: artifactRoot }) });
  await runAnalysisTasks(['drain', '--test-state-path', join(dir, 'tasks.json'), '--timeout-ms', '60000'], { handlerOptions: { artifactRoots: [dir], evidenceRoot: join(dir, 'analysis-task-evidence') } });
  const project = await request(base, `/api/v1/projects/${created.body.data.taskId}`);
  const manifest = project.body.data.artifacts.find((artifact) => artifact.kind === 'project-import-manifest');
  await (await import('node:fs/promises')).appendFile(manifest.path, '\n');
  const contracts = await request(base, '/api/v1/contracts?projectId=tampered-contracts-fixture');
  assert.equal(contracts.response.status, 200);
  assert.deepEqual(contracts.body.items, []);
});

test('decompile endpoint accepts the documented maximum-sized class of pasted runtime code', async (t) => {
  const { base } = await fixture(t);
  const runtimeBytecode = '0x' + '60'.repeat(8192);
  const created = await request(base, '/api/v1/decompile', {
    method: 'POST', body: JSON.stringify({ projectId: 'large-code', runtimeBytecode }),
  });
  assert.equal(created.response.status, 202, JSON.stringify(created.body));
  assert.equal(created.body.accepted, true);
  assert.match(created.body.data.taskId, /^[0-9a-f-]{36}$/);
});

test('worker lease requires the current fencing token and persists health', async (t) => {
  const { base } = await fixture(t);
  const registered = await request(base, '/api/v1/workers', { method: 'POST', body: JSON.stringify({ workerId: 'worker-a', ttlMs: 5000 }) });
  assert.equal(registered.response.status, 201);
  const token = registered.body.data.lease.fencingToken;
  const bad = await request(base, '/api/v1/workers/worker-a/heartbeat', { method: 'POST', body: JSON.stringify({ fencingToken: 'wrong' }) });
  assert.equal(bad.response.status, 409);
  assert.equal(bad.body.error.code, 'lease_not_owned');
  const heartbeat = await request(base, '/api/v1/workers/worker-a/heartbeat', { method: 'POST', body: JSON.stringify({ fencingToken: token }) });
  assert.equal(heartbeat.response.status, 200);
  const health = await request(base, '/api/v1/workers/worker-a/health');
  assert.equal(health.response.status, 200);
  assert.equal(health.body.data.healthy, true);
});

test('rules use versioned durable state and reject duplicate query parameters', async (t) => {
  const { base } = await fixture(t);
  const created = await request(base, '/api/v1/rules', { method: 'POST', body: JSON.stringify({ ruleId: 'rule-a', name: 'Rule A', severity: 'Medium', enabled: true, query: 'x' }) });
  assert.equal(created.response.status, 201);
  assert.equal(created.body.data.version, 1);
  const read = await request(base, '/api/v1/rules/rule-a');
  assert.equal(read.response.status, 200);
  assert.equal(read.body.data.ruleId, 'rule-a');
  const duplicate = await request(base, '/api/v1/rules?limit=1&limit=2');
  assert.equal(duplicate.response.status, 400);
  assert.equal(duplicate.body.error.code, 'duplicate_query_parameter');
});

test('analysis resources expose explicit empty data and reject unknown filters', async (t) => {
  const { base } = await fixture(t);
  const findings = await request(base, '/api/v1/findings');
  assert.equal(findings.response.status, 200);
  assert.deepEqual(findings.body.items, []);
  const bad = await request(base, '/api/v1/findings?unknown=1');
  assert.equal(bad.response.status, 422);
  assert.equal(bad.body.error.code, 'unknown_query_parameter');
});

test('analysis HTTP routes reject stale pagination and hide snapshot provider errors', async (t) => {
  let snapshot = {
    syncVersion: 'v1',
    findings: [
      { id: 'one', target: 'Vault', check: 'one', impact: 'Low' },
      { id: 'two', target: 'Vault', check: 'two', impact: 'Low' },
    ],
    vulnerabilityChains: [],
  };
  let shouldFail = false;
  const { base } = await fixture(t, async () => {
    if (shouldFail) throw new Error('/private/server/state/snapshot.json missing');
    return snapshot;
  });
  const first = await request(base, '/api/v1/findings?limit=1');
  assert.equal(first.response.status, 200);
  assert.ok(first.body.page.nextCursor);

  snapshot = { ...snapshot, syncVersion: 'v2', findings: [...snapshot.findings, { id: 'three', target: 'Vault', check: 'three', impact: 'Low' }] };
  const stale = await request(base, `/api/v1/findings?limit=1&cursor=${encodeURIComponent(first.body.page.nextCursor)}`);
  assert.equal(stale.response.status, 409);
  assert.equal(stale.body.error.code, 'stale_cursor');

  shouldFail = true;
  const failed = await request(base, '/api/v1/findings');
  assert.equal(failed.response.status, 503);
  assert.equal(failed.body.error.code, 'internal_error');
  assert.equal(JSON.stringify(failed.body).includes('/private/server/state/snapshot.json'), false);
});
