import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MAX_STABILITY_DURATION_MS, options, readinessPreflight, startHighSpeedRun } from '../scripts/high-speed-stability.mjs';

const fixedNow = Date.now();
const timestamp = new Date(fixedNow).toISOString();
const baseConfig = { baseUrl: 'http://127.0.0.1:8787', requestTimeoutMs: 100, readinessTimeoutMs: 1000, readinessRetryMs: 1 };

function payloads(syncVersion = 'v1', overrides = {}) {
  return {
    '/api/status': { syncVersion, chains: [], generatedAt: timestamp },
    '/api/sync': { syncVersion, consumers: ['dsh', 'dhlsh'], updatedAt: timestamp },
    '/api/health': {
      status: 'ok', instanceId: 'instance-1', sourceFingerprint: 'fingerprint-1', now: timestamp,
      memory: { rss: 1 }, snapshots: { stale: false, lastBuiltAt: timestamp, lastError: null },
      dsh: { available: true, syncVersion },
      ...overrides.health,
    },
  };
}

function response(data) {
  return { ok: true, status: 200, json: async () => data };
}

test('readiness preflight refreshes status before sync and health, then requires two stable samples', async () => {
  const calls = [];
  let statusCalls = 0;
  const fetchImpl = async (url) => {
    const path = new URL(url).pathname;
    calls.push(path);
    if (path === '/api/status') {
      statusCalls++;
      return response(payloads(statusCalls === 1 ? 'old-status' : 'stable-version')[path]);
    }
    if (path === '/api/sync') return response(payloads(statusCalls === 1 ? 'new-sync' : 'stable-version')[path]);
    return response(payloads('stable-version')[path]);
  };
  let fingerprintCalls = 0;
  const result = await readinessPreflight(baseConfig, {
    fetchImpl,
    fingerprint: async () => { fingerprintCalls++; return 'fingerprint-1'; },
    now: () => fixedNow,
    sleep: async () => {},
  });
  assert.equal(result.passed, true);
  assert.equal(result.attempts, 3);
  assert.equal(result.syncVersion, 'stable-version');
  assert.deepEqual(calls, [
    '/api/status', '/api/sync', '/api/health',
    '/api/status', '/api/sync', '/api/health',
    '/api/status', '/api/sync', '/api/health',
  ]);
  assert.equal(fingerprintCalls, 4);
});

test('readiness rejects missing exact health sync version and reports a bounded failure', async () => {
  const calls = [];
  const data = payloads('current', { health: { dsh: { available: true } } });
  const started = performance.now();
  await assert.rejects(readinessPreflight({ ...baseConfig, readinessTimeoutMs: 150, readinessRetryMs: 5 }, {
    fetchImpl: async (url) => { const path = new URL(url).pathname; calls.push(path); return response(data[path]); },
    fingerprint: async () => 'fingerprint-1',
    now: () => fixedNow,
  }), /readiness preflight failed .*health and status snapshot versions mismatch or health version is missing/);
  assert.ok(performance.now() - started < 500);
  assert.ok(calls.length >= 3);
  assert.deepEqual(calls.slice(0, 3), ['/api/status', '/api/sync', '/api/health']);
});

test('entrypoint readiness failure leaves existing report and journal untouched', async () => {
  const folder = await mkdtemp(join(tmpdir(), 'high-speed-preflight-'));
  try {
    const output = join(folder, 'report.json');
    const journal = `${output}.samples.jsonl`;
    await writeFile(output, 'previous report\n');
    await writeFile(journal, 'previous samples\n');
    const data = payloads('old-version');
    data['/api/sync'].syncVersion = 'different-version';
    await assert.rejects(startHighSpeedRun({
      ...baseConfig,
      output,
      readinessTimeoutMs: 150,
      readinessRetryMs: 5,
    }, {
      fingerprint: async () => 'fingerprint-1',
      now: () => fixedNow,
      fetchImpl: async (url) => response(data[new URL(url).pathname]),
    }), /readiness preflight failed .*syncVersion mismatch/);
    assert.equal(await readFile(output, 'utf8'), 'previous report\n');
    assert.equal(await readFile(journal, 'utf8'), 'previous samples\n');
  } finally { await rm(folder, { recursive: true, force: true }); }
});

test('readiness timeout is configurable and bounded', () => {
  assert.equal(options(['--readiness-timeout-ms', '20000']).readinessTimeoutMs, 20000);
  assert.throws(() => options(['--readiness-timeout-ms', '120001']), /预检超时/);
});

test('stability runner accepts the required 72-hour observation window and rejects longer runs', () => {
  assert.equal(options(['--duration-ms', String(MAX_STABILITY_DURATION_MS)]).durationMs, MAX_STABILITY_DURATION_MS);
  assert.throws(() => options(['--duration-ms', String(MAX_STABILITY_DURATION_MS + 1)]), /时长需 ≤72h/);
});
