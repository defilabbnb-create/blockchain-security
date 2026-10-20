import test from 'node:test';
import assert from 'node:assert/strict';
import { createSnapshotStore, answerQuestion } from '../src/status-store.js';
import { startServer } from '../src/web-server.js';
const buildSnapshot = createSnapshotStore(null);

test('status snapshot merges broad screening with focused quote evidence', async () => {
  const snapshot = await buildSnapshot();
  assert.equal(snapshot.totals.configuredChains, 19);
  assert.equal(snapshot.totals.candidates, 8);
  assert.equal(snapshot.totals.ready, 4);
  assert.equal(snapshot.totals.quoteVerified, 1);
  assert.equal(snapshot.chains.find((chain) => chain.name === 'Flare')?.transferability, 'quote_verified');
  assert.equal(new Set(snapshot.chains.map((chain) => chain.name)).size, snapshot.chains.length);
  assert.ok(snapshot.sources.reports.length >= 3);
  assert.equal(snapshot.staticAnalysis.unifiedIR.semanticsProven, false);
  assert.equal(snapshot.staticAnalysis.unifiedIR, snapshot.campaign?.unifiedIR || snapshot.staticAnalysis.unifiedIR);
});

test('status snapshots expose only sanitized cloud AI configuration and never probe it', async (t) => {
  const keys = ['DEFI_CLOUD_AI_BASE_URL', 'DEFI_CLOUD_AI_API_KEY', 'DEFI_CLOUD_AI_MODEL'];
  const previous = Object.fromEntries(keys.map((key) => [key, process.env[key]]));
  Object.assign(process.env, {
    DEFI_CLOUD_AI_BASE_URL: 'https://review.example.com/v1',
    DEFI_CLOUD_AI_API_KEY: 'secret-status-test-key',
    DEFI_CLOUD_AI_MODEL: 'review-model',
  });
  t.after(async () => {
    for (const key of keys) { if (previous[key] === undefined) delete process.env[key]; else process.env[key] = previous[key]; }
    await buildSnapshot({ force: true });
  });
  const snapshot = await buildSnapshot({ force: true });
  assert.deepEqual(snapshot.model, {
    provider: 'external_cloud_ai', configured: true, baseUrlHost: 'review.example.com', model: 'review-model',
    participatesInSecurityAnalysis: true, role: 'cloud-review',
  });
  assert.equal(JSON.stringify(snapshot.model).includes('secret-status-test-key'), false);
  assert.equal(snapshot.model.available, undefined);
  assert.equal(snapshot.model.endpoint, undefined);
});

test('structured DSH answers keep transfer safety boundary explicit', async () => {
  const snapshot = await buildSnapshot();
  const answer = answerQuestion(snapshot, '哪些链可以真实跨链？');
  assert.equal(answer.mode, 'structured');
  assert.match(answer.answer, /quote_verified|connection_only/);
  assert.match(answer.answer, /不执行授权|签名|广播/);
});

test('concurrent status refreshes leave an atomic snapshot', async () => {
  const snapshots = await Promise.all([buildSnapshot(), buildSnapshot(), buildSnapshot()]);
  assert.equal(snapshots.length, 3);
  assert.ok(snapshots.every((snapshot) => snapshot.totals.ready === 4));
});

test('vulnerability chains preserve evidence stages and confirmation boundary', async () => {
  const snapshot = await buildSnapshot({ force: true });
  assert.equal(snapshot.vulnerabilityChains.length, 3);
  for (const chain of snapshot.vulnerabilityChains) {
    assert.equal(chain.confirmed, false);
    assert.equal(chain.steps.length, 4);
    assert.ok(['tested', 'test_available', 'needs_test'].includes(chain.status));
    assert.ok(chain.sourceChecks.length >= 2);
    for (const check of chain.sourceChecks.filter((item) => item.ok)) {
      assert.ok(check.line > 0);
      assert.ok(check.snippet.includes(check.pattern));
      assert.match(check.ref, new RegExp(`#L${check.line}$`));
    }
    assert.ok(Array.isArray(chain.caveats) && chain.caveats.some((caveat) => /Slither|确认/.test(caveat)));
  }
});

test('health and vulnerability APIs expose operational state', async () => {
  const server = startServer({ port: 0, snapshotProvider: buildSnapshot });
  await new Promise((resolve) => server.once('listening', resolve));
  const port = server.address().port;
  try {
    const health = await fetch(`http://127.0.0.1:${port}/api/health`);
    assert.equal(health.status, 200);
    const healthBody = await health.json();
    assert.ok(['ok', 'degraded'].includes(healthBody.status));
    assert.equal(typeof healthBody.uptimeSec, 'number');
    assert.ok(healthBody.progress && typeof healthBody.progress.overall.percent === 'number');
    assert.equal(typeof healthBody.snapshots.generatedAt, 'string');
    assert.equal(typeof healthBody.snapshots.syncVersion, 'string');
    assert.ok(['current', 'historical', 'interrupted', 'running'].includes(healthBody.dataFreshness.state));
    assert.equal(healthBody.dataFreshness.interpretation.includes('服务在线不等于'), true);
    const chains = await fetch(`http://127.0.0.1:${port}/api/vulnerability-chains`);
    assert.equal(chains.status, 200);
    const chainBody = await chains.json();
    assert.equal(chainBody.vulnerabilityChains.length, 3);
    const sync = await fetch(`http://127.0.0.1:${port}/api/sync`);
    assert.equal(sync.status, 200);
    const syncBody = await sync.json();
    assert.equal(syncBody.unifiedIR.semanticsProven, false);
    assert.deepEqual(syncBody.progress, healthBody.progress);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
