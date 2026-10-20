import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createReplayArtifact } from '../src/replay-artifact.js';
import { createAnalysisResourceApi, handleAnalysisResource } from '../src/resource-api-analysis.js';

const digest = (value) => createHash('sha256').update(value).digest('hex');
const task = (taskId, checkpoint = null) => ({
  schemaVersion: 1, taskId, type: 'local-source-analysis', state: 'succeeded', priority: 1,
  createdAt: '2026-10-18T00:00:00.000Z', updatedAt: '2026-10-18T00:01:00.000Z', attempts: 1,
  maxAttempts: 3, checkpointSeq: checkpoint ? 1 : 0, checkpoint, history: [], lease: null,
  nextRetryAt: null, payload: {},
});

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'analysis-api-'));
  const evidenceRoot = join(root, 'evidence');
  const taskId = 'task-api-resource';
  const attempt = 'attempt-1-123e4567-e89b-12d3-a456-426614174000';
  const report = { state: 'completed', contracts: 1, detectors: 1, findingCount: 1, findings: [{ id: 'det-1', check: 'timestamp', impact: 'Medium', confidence: 'High', target: 'Vault', source: 'contracts/Vault.sol#L10' }] };
  const bytes = Buffer.from(JSON.stringify(report));
  const reportPath = join(evidenceRoot, digest(taskId), attempt, 'static-analysis.json');
  await mkdir(join(evidenceRoot, digest(taskId), attempt), { recursive: true });
  await writeFile(reportPath, bytes);
  const checkpoint = { phase: 'evidence_ready', attempt: 1, attemptDirectory: join(evidenceRoot, digest(taskId), attempt), reportPath, reportBytes: bytes.length, reportSha256: digest(bytes) };
  const tasks = [task(taskId, checkpoint), { ...task('queued-analysis'), state: 'queued', checkpoint: null }];
  const store = { readSnapshot: async () => ({ revision: 7, tasks }), readTask: async (id) => ({ revision: 7, task: tasks.find((item) => item.taskId === id) || null }) };
  const snapshot = { generatedAt: '2026-10-18T00:02:00.000Z', findings: [{ id: 'det-1', target: 'Vault', check: 'timestamp', impact: 'Medium', confidence: 'High', source: 'contracts/Vault.sol#L10' }], vulnerabilityChains: [] };
  return { root, evidenceRoot, taskId, store, snapshot, report, api: createAnalysisResourceApi({ taskStore: store, evidenceRoot, snapshotProvider: async () => snapshot }) };
}

test('analysis resources expose task state, static findings, and bound report', async () => {
  const f = await fixture();
  const request = (url) => f.api({ method: 'GET', url });
  const analysis = await request('/api/v1/analysis?limit=1');
  assert.equal(analysis.status, 200);
  assert.equal(analysis.body.items.length, 1);
  assert.ok([f.taskId, 'queued-analysis'].includes(analysis.body.items[0].taskId));
  const finding = await request('/api/v1/findings');
  assert.equal(finding.status, 200);
  assert.equal(finding.body.items[0].severity, 'Medium');
  const report = await request(`/api/v1/reports/${f.taskId}`);
  assert.equal(report.status, 200);
  assert.deepEqual(report.body.data.report, f.report);
  assert.equal(report.body.data.sha256.length, 64);
});

test('report export returns explicit JSON/SARIF/HTML formats without changing evidence status', async () => {
  const f = await fixture();
  const json = await f.api({ method: 'GET', url: `/api/v1/reports/${f.taskId}?format=json` });
  assert.equal(json.raw.contentType, 'application/json; charset=utf-8');
  assert.deepEqual(JSON.parse(json.raw.body), f.report);
  const sarif = await f.api({ method: 'GET', url: `/api/v1/reports/${f.taskId}?format=sarif` });
  assert.equal(sarif.status, 200);
  assert.equal(sarif.raw.contentType, 'application/sarif+json; charset=utf-8');
  assert.equal(sarif.raw.sourceSha256, f.store.readSnapshot ? (await f.store.readTask(f.taskId)).task.checkpoint.reportSha256 : null);
  const sarifBody = JSON.parse(sarif.raw.body);
  assert.equal(sarifBody.version, '2.1.0');
  assert.equal(sarifBody.runs[0].results[0].properties.status, 'hypothesis');
  assert.equal(sarifBody.runs[0].results[0].properties.confirmed, false);

  const html = await f.api({ method: 'GET', url: `/api/v1/reports/${f.taskId}?format=html` });
  assert.equal(html.raw.contentType, 'text/html; charset=utf-8');
  assert.match(html.raw.body, /候选结果不等于确认漏洞/);
  assert.match(html.raw.body, /timestamp/);

  const bad = await handleAnalysisResource({ method: 'GET', url: `/api/v1/reports/${f.taskId}?format=xml` }, { taskStore: f.store, evidenceRoot: f.evidenceRoot, snapshotProvider: async () => f.snapshot });
  assert.equal(bad.status, 422);
  assert.equal(bad.body.error.code, 'invalid_format');
});

test('report exports escape untrusted HTML fields and preserve SARIF source ranges', async () => {
  const f = await fixture();
  const hostile = {
    ...f.report,
    findings: [{
      id: 'det-hostile', check: '<script>alert(1)</script>', impact: 'Low',
      target: 'Vault <img src=x>', source: 'contracts/Vault.sol#L10-L12',
      evidenceStatus: 'hypothesis', confirmed: false,
    }],
  };
  const reportPath = join(f.evidenceRoot, digest(f.taskId), 'attempt-1-123e4567-e89b-12d3-a456-426614174000', 'static-analysis.json');
  const bytes = Buffer.from(JSON.stringify(hostile));
  await writeFile(reportPath, bytes);
  const taskRecord = (await f.store.readTask(f.taskId)).task;
  taskRecord.checkpoint.reportSha256 = digest(bytes);
  taskRecord.checkpoint.reportBytes = bytes.length;

  const html = await f.api({ method: 'GET', url: `/api/v1/reports/${f.taskId}?format=html` });
  assert.equal(html.status, 200);
  assert.doesNotMatch(html.raw.body, /<script>|<img src=x>/);
  assert.match(html.raw.body, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.match(html.raw.body, /Vault &lt;img src=x&gt;/);

  const sarif = await f.api({ method: 'GET', url: `/api/v1/reports/${f.taskId}?format=sarif` });
  const result = JSON.parse(sarif.raw.body).runs[0].results[0];
  assert.deepEqual(result.locations[0].physicalLocation.region, { startLine: 10, endLine: 12 });
  assert.equal(result.properties.status, 'hypothesis');
  assert.equal(result.properties.confirmed, false);
});

test('scans, evidence, and replay use real snapshot/report data', async () => {
  const f = await fixture();
  const api = createAnalysisResourceApi({ taskStore: f.store, evidenceRoot: f.evidenceRoot, snapshotProvider: async () => ({ ...f.snapshot, vulnerabilityChains: [{ title: 'chain', evidence: [{ findingId: 'finding-1', evidenceStatus: 'hypothesis', source: 'contracts/Vault.sol#L10' }] }] }) });
  const scans = await api({ method: 'GET', url: '/api/v1/scans' });
  assert.equal(scans.body.items.length, 2);
  const evidence = await api({ method: 'GET', url: '/api/v1/evidence' });
  assert.equal(evidence.body.items.length, 2);
  const artifact = createReplayArtifact({ artifactId: 'replay-1', analysisInput: { taskId: f.taskId } });
  const replayApi = createAnalysisResourceApi({ taskStore: f.store, evidenceRoot: f.evidenceRoot, snapshotProvider: async () => f.snapshot, reportReader: async () => ({ report: { ...f.report, replay: artifact }, sha256: f.store.readSnapshot ? (await f.store.readTask(f.taskId)).task.checkpoint.reportSha256 : null, bytes: 1 }) });
  const replay = await replayApi({ method: 'GET', url: '/api/v1/replay/replay-1' });
  assert.equal(replay.status, 200);
  assert.equal(replay.body.data.artifact.artifactId, 'replay-1');
  assert.equal(replay.body.data.replayEvidence.state, 'insufficient');
  assert.equal(replay.body.data.replayEvidence.confirmationEligible, false);
});

test('replay resource exposes derived evidence completeness without changing artifact hash', async () => {
  const f = await fixture();
  const artifact = createReplayArtifact({
    artifactId: 'replay-structured',
    replay: {
      seed: 42,
      command: 'npx hardhat test --grep replay',
      fork: { chainId: 31337, blockNumber: 12, blockHash: `0x${'c'.repeat(64)}` },
      transactions: [{ txIndex: 0, transactionHash: `0x${'a'.repeat(64)}`, from: `0x${'1'.repeat(40)}`, to: `0x${'2'.repeat(40)}`, data: '0x00' }],
      initialState: { blockNumber: 12, accounts: [{ address: `0x${'1'.repeat(40)}`, balance: '0' }] },
      traces: [{ txIndex: 0, traceHash: 'b'.repeat(64), state: 'available', steps: 1 }],
      storageDiff: [],
      assetChanges: [],
      permissionChanges: [],
      stateDiff: [],
    },
  });
  const api = createAnalysisResourceApi({
    taskStore: f.store,
    evidenceRoot: f.evidenceRoot,
    snapshotProvider: async () => f.snapshot,
    reportReader: async () => ({ report: { replay: artifact }, sha256: f.store.readSnapshot ? (await f.store.readTask(f.taskId)).task.checkpoint.reportSha256 : null, bytes: 1 }),
  });
  const result = await api({ method: 'GET', url: '/api/v1/replay/replay-structured' });
  assert.equal(result.status, 200);
  assert.equal(result.body.data.artifact.sha256, artifact.sha256);
  assert.equal(result.body.data.replayEvidence.state, 'complete');
  assert.equal(result.body.data.replayEvidence.replayable, true);
  assert.equal(result.body.data.replayEvidence.confirmationEligible, false);
});

test('invalid pagination and report tampering return explicit errors', async () => {
  const f = await fixture();
  const bad = await handleAnalysisResource({ method: 'GET', url: '/api/v1/findings?limit=0' }, { taskStore: f.store, evidenceRoot: f.evidenceRoot, snapshotProvider: async () => f.snapshot });
  assert.equal(bad.status, 422);
  assert.equal(bad.body.error.code, 'invalid_limit');
  await writeFile(join(f.evidenceRoot, digest(f.taskId), 'attempt-1-123e4567-e89b-12d3-a456-426614174000', 'static-analysis.json'), '{}');
  const tampered = await handleAnalysisResource({ method: 'GET', url: `/api/v1/reports/${f.taskId}` }, { taskStore: f.store, evidenceRoot: f.evidenceRoot, snapshotProvider: async () => f.snapshot });
  assert.equal(tampered.status, 409);
  assert.equal(tampered.body.error.code, 'report_integrity_mismatch');
});

test('analysis pagination rejects a cursor after its data revision changes', async () => {
  const f = await fixture();
  let snapshot = {
    ...f.snapshot,
    syncVersion: 'snapshot-1',
    findings: [
      { id: 'one', target: 'Vault', check: 'one', impact: 'Low' },
      { id: 'two', target: 'Vault', check: 'two', impact: 'Low' },
    ],
  };
  const api = createAnalysisResourceApi({ taskStore: f.store, snapshotProvider: async () => snapshot });
  const first = await api({ method: 'GET', url: '/api/v1/findings?limit=1' });
  assert.equal(first.status, 200);
  assert.ok(first.body.page.nextCursor);

  snapshot = { ...snapshot, syncVersion: 'snapshot-2', findings: [...snapshot.findings, { id: 'three', target: 'Vault', check: 'three', impact: 'Low' }] };
  const next = await handleAnalysisResource({ method: 'GET', url: `/api/v1/findings?limit=1&cursor=${encodeURIComponent(first.body.page.nextCursor)}` }, { taskStore: f.store, snapshotProvider: async () => snapshot });
  assert.equal(next.status, 409);
  assert.equal(next.body.error.code, 'stale_cursor');
});

test('snapshot provider failures return a generic service error without internal paths', async () => {
  const f = await fixture();
  const privatePath = '/private/runtime/state/snapshot.json';
  const result = await handleAnalysisResource({ method: 'GET', url: '/api/v1/findings' }, {
    taskStore: f.store,
    snapshotProvider: async () => { throw new Error(`failed to read ${privatePath}`); },
  });
  assert.equal(result.status, 503);
  assert.equal(result.body.error.code, 'internal_error');
  assert.equal(result.body.error.message, '分析快照暂时不可用');
  assert.equal(JSON.stringify(result.body).includes(privatePath), false);
});

test('project-root report lookup rejects symlinks that resolve outside the project', async (t) => {
  const f = await fixture();
  t.after(() => rm(f.root, { recursive: true, force: true }));
  const projectReports = join(f.root, 'reports');
  const outsideReport = join(f.root, 'outside.json');
  await mkdir(projectReports);
  await writeFile(outsideReport, JSON.stringify({ private: true }));
  await symlink(outsideReport, join(projectReports, 'linked.json'));
  const result = await handleAnalysisResource({ method: 'GET', url: '/api/v1/reports/reports/linked.json' }, { taskStore: f.store, evidenceRoot: f.evidenceRoot, projectRoot: f.root, snapshotProvider: async () => f.snapshot });
  assert.equal(result.status, 403);
  assert.equal(result.body.error.code, 'invalid_report_path');
});
