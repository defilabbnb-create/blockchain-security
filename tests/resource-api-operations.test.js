import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  ResourceApiError,
  ResourceApiOperations,
  isResourceLeaseExpired,
  parseResourcePageQuery,
} from '../src/resource-api-operations.js';

async function fixture(t, options = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'resource-api-v1-'));
  const store = new ResourceApiOperations({ path: join(dir, 'resources.json'), ...options });
  t.after(async () => { await import('node:fs/promises').then(({ rm }) => rm(dir, { recursive: true, force: true })); });
  return { dir, store };
}

test('resource page query rejects unknown, duplicate, and invalid pagination values', () => {
  assert.deepEqual(parseResourcePageQuery(new URLSearchParams('limit=2&status=healthy'), { allowed: ['status'] }), { limit: 2, status: 'healthy' });
  for (const query of ['limit=0', 'limit=1001', 'limit=1.5', 'cursor=x']) assert.throws(() => parseResourcePageQuery(new URLSearchParams(query)), ResourceApiError);
  assert.throws(() => parseResourcePageQuery(new URLSearchParams('limit=1&limit=2')), { code: 'duplicate_query_parameter' });
  assert.throws(() => parseResourcePageQuery(new URLSearchParams('status=x')), { code: 'unknown_query_parameter' });
});

test('worker registration persists a fenced lease and health expires with the injected clock', async (t) => {
  let now = Date.parse('2026-10-19T00:00:00.000Z');
  const { store } = await fixture(t, { clock: () => now });
  const registered = await store.registerWorker({ workerId: 'worker-a', capabilities: ['scan'], ttlMs: 1000 });
  assert.equal(registered.status, 'healthy');
  assert.equal(registered.lease.workerId, 'worker-a');
  assert.equal(registered.lease.ttlMs, 1000);
  const healthy = await store.getWorkerHealth('worker-a');
  assert.equal(healthy.healthy, true);
  now += 1000;
  const expired = await store.getWorkerHealth('worker-a');
  assert.equal(expired.status, 'expired');
  assert.equal(expired.healthy, false);
  assert.equal(isResourceLeaseExpired(registered.lease, now), true);
  await assert.rejects(() => store.heartbeatWorker('worker-a', registered.lease.fencingToken), { code: 'lease_expired' });
});

test('worker heartbeat requires the current fencing token and survives a restart', async (t) => {
  let now = Date.parse('2026-10-19T00:00:00.000Z');
  const context = await fixture(t, { clock: () => now });
  const first = await context.store.registerWorker({ workerId: 'worker-a', ttlMs: 1000 });
  await assert.rejects(() => context.store.heartbeatWorker('worker-a', 'wrong-token'), { code: 'lease_not_owned' });
  now += 100;
  const beat = await context.store.heartbeatWorker('worker-a', first.lease.fencingToken, { ttlMs: 2000 });
  assert.equal(beat.lease.sequence, 2);
  const restarted = new ResourceApiOperations({ path: join(context.dir, 'resources.json'), clock: () => now });
  const read = await restarted.getWorker('worker-a');
  assert.equal(read.lease.fencingToken, first.lease.fencingToken);
  assert.equal(read.healthy, true);
});

test('worker list is stable and paginated', async (t) => {
  const { store } = await fixture(t);
  for (const workerId of ['worker-c', 'worker-a', 'worker-b']) await store.registerWorker({ workerId });
  const first = await store.listWorkers({ limit: 2 });
  assert.deepEqual(first.items.map((item) => item.workerId), ['worker-a', 'worker-b']);
  assert.equal(first.hasMore, true);
  const second = await store.listWorkers({ limit: 2, cursor: first.nextCursor });
  assert.deepEqual(second.items.map((item) => item.workerId), ['worker-c']);
});

test('rules and invariants load configured data and expose explicit empty sets', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'resource-config-'));
  const rulesPath = join(dir, 'rules.json');
  const invariantsPath = join(dir, 'invariants.json');
  await writeFile(rulesPath, JSON.stringify({ rules: [{ ruleId: 'reentrancy', version: 1, severity: 'P1', enabled: true }] }));
  await writeFile(invariantsPath, JSON.stringify({ invariants: [] }));
  const { store } = await fixture(t, { rulesPath, invariantsPath });
  const rules = await store.listRules();
  assert.equal(rules.items[0].ruleId, 'reentrancy');
  assert.equal(rules.items[0].sourcePath, rulesPath);
  const invariants = await store.listInvariants();
  assert.deepEqual(invariants.items, []);
  assert.equal(invariants.empty, true);
});

test('versioned creation increments versions and rejects duplicates', async (t) => {
  const { store } = await fixture(t);
  const first = await store.createRuleVersion({ ruleId: 'access-control', name: 'admin checks' });
  const second = await store.createRuleVersion({ ruleId: 'access-control', name: 'admin checks v2' });
  assert.equal(first.version, 1);
  assert.equal(second.version, 2);
  assert.equal((await store.getVersioned('rules', 'access-control')).data.version, 2);
  await assert.rejects(() => store.createRuleVersion({ ruleId: 'access-control', version: 2 }), { code: 'duplicate_version' });
  const all = await store.listRules({ allVersions: true });
  assert.deepEqual(all.items.map((item) => item.version), [1, 2]);
});

test('review audit appends to JSONL and supports filtered pagination', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'resource-audit-'));
  const auditPath = join(dir, 'review-audit.jsonl');
  const { store } = await fixture(t, { auditPath });
  await store.appendReviewAudit({ requestId: 'r1', decision: 'allow', allowed: true, findingCount: 0 });
  await store.appendReviewAudit({ requestId: 'r2', decision: 'block', allowed: false, findingCount: 1 });
  const page = await store.listReviewAudits({ decision: 'block' });
  assert.equal(page.items.length, 1);
  assert.equal(page.items[0].requestId, 'r2');
  assert.equal(page.revision, 2);
  assert.equal((await readFile(auditPath, 'utf8')).trim().split('\n').length, 2);
  assert.equal((await store.getReviewAudit('r1')).decision, 'allow');
});

test('configured path and resource identifiers are validated', async (t) => {
  await assert.rejects(async () => fixture(t, { rulesPath: 'relative/rules.json' }), { code: 'invalid_path' });
  const { store } = await fixture(t);
  await assert.rejects(() => store.registerWorker({ workerId: '../escape' }), { code: 'invalid_path' });
  await assert.rejects(() => store.createInvariantVersion({ invariantId: 'a/b' }), { code: 'invalid_path' });
});
