import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { normalizeFindingTriagePatch } from '../src/finding-triage.js';
import { ResourceApiOperations } from '../src/resource-api-operations.js';
import { startServer } from '../src/web-server.js';

test('finding triage patch validates partial updates without inventing fields', () => {
  assert.deepEqual(normalizeFindingTriagePatch({ assignee: ' reviewer ', tags: [' access ', 'access'], note: ' check path ' }), {
    assignee: 'reviewer', tags: ['access'], note: 'check path',
  });
  assert.deepEqual(normalizeFindingTriagePatch({ tags: [] }), { tags: [] });
  assert.deepEqual(normalizeFindingTriagePatch({ assignee: null }), { assignee: null });
  assert.throws(() => normalizeFindingTriagePatch({}), TypeError);
  assert.throws(() => normalizeFindingTriagePatch({ status: 'confirmed' }), TypeError);
  assert.throws(() => normalizeFindingTriagePatch({ triageStatus: 'fixed' }), /同时填写原因/);
  assert.throws(() => normalizeFindingTriagePatch({ triageStatus: 'accepted_risk', note: ' ' }), /备注长度/);
  assert.throws(() => normalizeFindingTriagePatch({ assignee: 4 }), /指派人必须/);
  assert.throws(() => normalizeFindingTriagePatch({ tags: [4] }), /标签必须是字符串/);
  assert.throws(() => normalizeFindingTriagePatch({ note: 'ok', extra: true }), /不支持的处置字段/);
});

test('finding triage is durable, revision checked, and separate from security evidence', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'finding-triage-'));
  const statePath = join(dir, 'resources.json');
  const operations = new ResourceApiOperations({ path: statePath });
  const snapshot = {
    generatedAt: '2026-10-19T01:00:00.000Z',
    findings: [{ findingId: 'finding-a', title: 'Vault issue', severity: 'High', status: 'hypothesis', confirmed: false }],
    vulnerabilityChains: [],
  };
  const server = startServer({ port: 0, resourceOperations: operations, snapshotProvider: async () => snapshot });
  await once(server, 'listening');
  const base = `http://127.0.0.1:${server.address().port}`;
  t.after(async () => {
    server.stop();
    if (server.listening) await once(server, 'close');
    await rm(dir, { recursive: true, force: true });
  });
  const request = async (path, options = {}) => {
    const response = await fetch(`${base}${path}`, {
      ...options,
      headers: { ...(options.body === undefined ? {} : { 'content-type': 'application/json' }), ...(options.headers || {}) },
    });
    return { response, body: await response.json() };
  };

  const initial = await request('/api/v1/findings/finding-a');
  assert.equal(initial.response.status, 200);
  assert.equal(initial.body.data.finding.triage.triageStatus, 'unreviewed');
  const firstRevision = initial.body.consistency.revision;
  const assigned = await request('/api/v1/findings/finding-a/triage', {
    method: 'PATCH', headers: { 'if-match': String(firstRevision) },
    body: JSON.stringify({ assignee: 'analyst', tags: ['accounting'], note: 'Compare internal and external balances.' }),
  });
  assert.equal(assigned.response.status, 200, JSON.stringify(assigned.body));
  assert.equal(assigned.body.data.triage.assignee, 'analyst');
  assert.equal(assigned.body.data.triage.triageStatus, 'unreviewed');
  assert.equal(assigned.body.data.triage.history[0].requestId.length > 0, true);

  const stale = await request('/api/v1/findings/finding-a/triage', {
    method: 'PATCH', headers: { 'if-match': String(firstRevision) }, body: JSON.stringify({ tags: [] }),
  });
  assert.equal(stale.response.status, 412);
  assert.equal(stale.body.error.code, 'REVISION_MISMATCH');

  const closed = await request('/api/v1/findings/finding-a/triage', {
    method: 'PATCH', headers: { 'if-match': String(assigned.body.consistency.revision) },
    body: JSON.stringify({ triageStatus: 'accepted_risk', note: 'Accepted by the protocol owner.' }),
  });
  assert.equal(closed.response.status, 200);
  assert.equal(closed.body.data.triage.triageStatus, 'accepted_risk');
  const reloadedOperations = new ResourceApiOperations({ path: statePath });
  const persisted = await reloadedOperations.readFindingTriages(['finding-a']);
  assert.equal(persisted.items['finding-a'].triageStatus, 'accepted_risk');

  const list = await request('/api/v1/findings?triageStatus=accepted_risk');
  assert.equal(list.response.status, 200);
  assert.equal(list.body.items.length, 1);
  assert.equal(list.body.items[0].status, 'hypothesis');
  assert.equal(list.body.items[0].confirmed, false);
  assert.equal(list.body.items[0].severity, 'High');

  const invalid = await request('/api/v1/findings/finding-a/triage', {
    method: 'PATCH', headers: { 'if-match': String(list.body.consistency.revision) },
    body: JSON.stringify({ triageStatus: 'false_positive' }),
  });
  assert.equal(invalid.response.status, 400);
  const missingRevision = await request('/api/v1/findings/finding-a/triage', {
    method: 'PATCH', body: JSON.stringify({ tags: [] }),
  });
  assert.equal(missingRevision.response.status, 400);
});
