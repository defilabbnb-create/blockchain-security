import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { createReviewManifest } from '../src/review-manifest.js';
import { startServer } from '../src/web-server.js';

async function fixture(t, { diff = '+ change' } = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'review-api-'));
  const auditPath = join(dir, 'audit.jsonl');
  const server = startServer({
    port: 0,
    reviewAuditPath: auditPath,
    snapshotProvider: async () => ({ generatedAt: '2026-10-18T00:00:00.000Z', activeTask: null, activeChain: null, queue: [] }),
  });
  await once(server, 'listening');
  t.after(async () => {
    server.stop();
    if (server.listening) await once(server, 'close');
    await rm(dir, { recursive: true, force: true });
  });
  const manifest = createReviewManifest({
    manifestId: 'review-api-manifest',
    createdAt: '2026-10-18T00:00:00.000Z',
    changedFiles: [{ path: 'src/example.js' }],
    diff,
    tests: [{ name: 'unit', status: 'passed', required: true }],
    dependencies: [],
  });
  return { base: `http://127.0.0.1:${server.address().port}`, auditPath, manifest };
}

async function post(base, body) {
  const response = await fetch(`${base}/api/v1/reviews/evaluate`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { response, body: await response.json() };
}

test('v1 review evaluation uses the deterministic gate and records privacy-minimal audit data', async (t) => {
  const { base, auditPath, manifest } = await fixture(t);
  const result = await post(base, {
    manifest,
    review: { schemaVersion: 1, manifestSha256: manifest.manifestSha256, decision: 'allow', evidenceComplete: true, findings: [
      { findingId: 'note-1', severity: 'P2', title: 'Bearer top-secret-token', summary: 'review note', file: 'src/example.js', line: 3, confidence: 0.8, evidenceComplete: true },
    ] },
    checks: [{ name: 'integration', status: 'passed', required: true }],
  });
  assert.equal(result.response.status, 200, JSON.stringify(result.body));
  assert.equal(result.body.apiVersion, 'v1');
  assert.equal(result.body.data.allowed, true);
  const audit = await readFile(auditPath, 'utf8');
  assert.equal(audit.includes('top-secret-token'), false);
  assert.match(audit, /"findingCount":1/);
  assert.match(audit, /"P2":1/);
});

test('v1 review evaluation blocks P1 and rejects a review bound to another manifest', async (t) => {
  const { base, manifest } = await fixture(t);
  const blocked = await post(base, {
    manifest,
    review: { schemaVersion: 1, manifestSha256: manifest.manifestSha256, decision: 'allow', evidenceComplete: true, findings: [
      { findingId: 'p1', severity: 'P1', title: 'critical path', summary: 'security impact', file: 'src/example.js', line: 3, confidence: 0.95, evidenceComplete: true },
    ] },
  });
  assert.equal(blocked.response.status, 200, JSON.stringify(blocked.body));
  assert.equal(blocked.body.data.allowed, false);
  assert.ok(blocked.body.data.reasons.some((reason) => reason.code === 'blocking_finding'));

  const mismatch = await post(base, {
    manifest,
    review: { schemaVersion: 1, manifestSha256: '0'.repeat(64), decision: 'allow', evidenceComplete: true, findings: [] },
  });
  assert.equal(mismatch.response.status, 400);
  assert.equal(mismatch.body.apiVersion, 'v1');
  assert.ok(mismatch.body.error.requestId);
});

test('v1 review evaluation accepts bounded diffs larger than the general API body limit', async (t) => {
  const { base, manifest } = await fixture(t, { diff: `+${'x'.repeat(24 * 1024)}` });
  const result = await post(base, {
    manifest,
    review: { schemaVersion: 1, manifestSha256: manifest.manifestSha256, decision: 'allow', evidenceComplete: true, findings: [] },
  });
  assert.equal(result.response.status, 200, JSON.stringify(result.body));
  assert.equal(result.body.data.allowed, true);
});
