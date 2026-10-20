import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createResourceApiV1 } from '../src/resource-api-projects.js';

const sha256 = (value) => createHash('sha256').update(value).digest('hex');

async function fixture() {
  const dir = await mkdtemp(join(tmpdir(), 'resource-api-v1-'));
  const artifacts = join(dir, 'artifacts');
  const outside = join(dir, 'outside');
  await Promise.all([mkdir(artifacts), mkdir(outside)]);
  const manifest = Buffer.from(JSON.stringify({ schemaVersion: 1, kind: 'local-project-import', projectId: 'demo', complete: true }));
  const manifestPath = join(artifacts, 'project-import.json');
  await writeFile(manifestPath, manifest);
  const records = {
    projects: [{ id: 'demo', projectId: 'demo', kind: 'local-project-import', manifestPath, manifestSha256: sha256(manifest), manifestBytes: manifest.length }],
    contracts: [{ id: 'contract-1', projectId: 'demo', address: '0xabc' }],
    collection: [{ id: 'collection-1', projectId: 'demo', manifestPath, manifestSha256: sha256(manifest), manifestBytes: manifest.length }],
    bytecode: [{ id: 'bytecode-1', projectId: 'demo', runtimeBytecode: '0x6000', bytecodeSha256: sha256(Buffer.from('6000', 'hex')), bytecodeBytes: 2 }],
    decompile: [{ id: 'decompile-1', projectId: 'demo', manifestPath, manifestSha256: sha256(manifest), manifestBytes: manifest.length }],
  };
  const tasks = [];
  const store = {
    async listResources(resource, query) { return { items: records[resource].slice(0, query.limit), nextCursor: null, revision: 4 }; },
    async getResource(resource, id) { return records[resource].find((row) => row.id === id) ?? null; },
    async createTask(value) { tasks.push(value); return { taskId: `task-${tasks.length}`, state: 'queued', resource: value.resource, payload: value.payload, audit: value.audit }; },
  };
  const api = createResourceApiV1({ store, artifactRoots: [artifacts] });
  return { dir, artifacts, outside, manifestPath, records, tasks, api };
}

test('lists and reads persisted resources with verified artifacts', async (t) => {
  const context = await fixture();
  t.after(() => rm(context.dir, { recursive: true, force: true }));
  const list = await context.api({ pathname: '/api/v1/projects', method: 'GET', searchParams: new URLSearchParams('limit=1') });
  assert.equal(list.status, 200);
  assert.equal(list.body.items[0].projectId, 'demo');
  assert.equal(list.body.items[0].artifacts[0].bytes, JSON.stringify({ schemaVersion: 1, kind: 'local-project-import', projectId: 'demo', complete: true }).length);
  assert.equal(list.body.consistency.revision, 4);
  const detail = await context.api({ pathname: '/api/v1/projects/demo', method: 'GET' });
  assert.equal(detail.status, 200);
  assert.equal(detail.body.data.artifacts[0].sha256, context.records.projects[0].manifestSha256);
  const bytecode = await context.api({ pathname: '/api/v1/bytecode/bytecode-1', method: 'GET' });
  assert.equal(bytecode.status, 200);
  assert.equal(bytecode.body.data.runtimeBytecode, '0x6000');
});

test('rejects tampered, oversized, and out-of-root artifacts', async (t) => {
  const context = await fixture();
  t.after(() => rm(context.dir, { recursive: true, force: true }));
  context.records.projects[0].manifestSha256 = '0'.repeat(64);
  const tampered = await context.api({ pathname: '/api/v1/projects/demo', method: 'GET' });
  assert.equal(tampered.status, 409);
  assert.equal(tampered.body.error.code, 'artifact_integrity_mismatch');
  context.records.projects[0].manifestSha256 = sha256(await import('node:fs/promises').then(({ readFile }) => readFile(context.manifestPath)));
  context.records.projects[0].manifestPath = join(context.outside, 'outside.json');
  await writeFile(context.records.projects[0].manifestPath, '{}');
  const forbidden = await context.api({ pathname: '/api/v1/projects/demo', method: 'GET' });
  assert.equal(forbidden.status, 403);
  context.records.projects[0].manifestPath = context.manifestPath;
  context.records.projects[0].manifestBytes = 1;
  const wrongSize = await context.api({ pathname: '/api/v1/projects/demo', method: 'GET' });
  assert.equal(wrongSize.status, 409);
});

test('POST creates durable tasks through the injected store and never fabricates resources', async (t) => {
  const context = await fixture();
  t.after(() => rm(context.dir, { recursive: true, force: true }));
  const created = await context.api({ pathname: '/api/v1/projects', method: 'POST', body: { projectId: 'demo', sourcePath: context.artifacts } });
  assert.equal(created.status, 202);
  assert.equal(created.body.accepted, true);
  assert.equal(context.tasks[0].resource, 'projects');
  assert.equal(context.tasks[0].payload.sourcePath, context.artifacts);
  const contractCreate = await context.api({ pathname: '/api/v1/contracts', method: 'POST', body: {
    projectId: 'demo', contractId: 'contract-2', chainId: '1', address: `0x${'1'.repeat(40)}`,
  } });
  assert.equal(contractCreate.status, 202);
  assert.equal(context.tasks[1].resource, 'contracts');
  const missing = await context.api({ pathname: '/api/v1/projects/unknown', method: 'GET' });
  assert.equal(missing.status, 404);
});

test('rejects query and input contract violations without calling the store', async (t) => {
  const context = await fixture();
  t.after(() => rm(context.dir, { recursive: true, force: true }));
  const unknown = await context.api({ pathname: '/api/v1/projects', method: 'GET', searchParams: new URLSearchParams('fake=1') });
  assert.equal(unknown.status, 400);
  assert.equal(unknown.body.error.code, 'unknown_query_parameter');
  const badBytecode = await context.api({ pathname: '/api/v1/bytecode', method: 'POST', body: { runtimeBytecode: '0x1' } });
  assert.equal(badBytecode.status, 400);
  assert.equal(context.tasks.length, 0);
  const noSource = await context.api({ pathname: '/api/v1/projects', method: 'POST', body: { projectId: 'x' } });
  assert.equal(noSource.status, 400);
  const storageWithoutAddress = await context.api({ pathname: '/api/v1/collection', method: 'POST', body: {
    projectId: 'demo', chainId: '1', rpcUrl: 'https://rpc.example', fromBlock: '1', storageSlots: ['0x' + '00'.repeat(32)],
  } });
  assert.equal(storageWithoutAddress.status, 400);
  const receiptWithoutTransactions = await context.api({ pathname: '/api/v1/collection', method: 'POST', body: {
    projectId: 'demo', chainId: '1', rpcUrl: 'https://rpc.example', fromBlock: '1', includeReceipts: true,
  } });
  assert.equal(receiptWithoutTransactions.status, 400);
  assert.equal(context.tasks.length, 0);
});

