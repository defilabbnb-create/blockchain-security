import test from 'node:test';
import assert from 'node:assert/strict';
import { createReviewManifest, evaluateMergeGate, validateCloudReview, verifyReviewManifest } from '../src/review-manifest.js';

function manifest(overrides = {}) {
  return createReviewManifest({
    manifestId: 'manifest-1',
    createdAt: '2026-10-18T00:00:00.000Z',
    baseRevision: 'base-1',
    headRevision: 'head-1',
    changedFiles: [{ path: 'src/example.js', status: 'modified', additions: 2, deletions: 1 }],
    diff: 'diff --git a/src/example.js b/src/example.js\n+safe change\n+api_key=secret-value',
    tests: [{ name: 'unit', status: 'passed', required: true }],
    dependencies: [],
    risks: [],
    environment: { api_key: 'secret-value', node: 'v26' },
    localModel: { model: 'local-test-model', api_key: 'another-secret' },
    ...overrides,
  });
}

test('creates an immutable, hashed and redacted review manifest', () => {
  const value = manifest();
  assert.equal(value.schemaVersion, 1);
  assert.match(value.manifestSha256, /^[a-f0-9]{64}$/);
  assert.equal(value.environment.api_key, '[REDACTED]');
  assert.equal(value.localModel.api_key, '[REDACTED]');
  assert.equal(value.diff.includes('secret-value'), false);
  assert.equal(value.privacy.redacted, true);
  assert.ok(value.privacy.redactionCount >= 2);
  assert.equal(Object.isFrozen(value), true);
  assert.throws(() => { value.changedFiles[0].path = 'changed'; }, TypeError);
  assert.equal(verifyReviewManifest(value), true);
  assert.equal(verifyReviewManifest({ ...value, diff: 'tampered' }), false);
});

test('redacts credential formats embedded in ordinary diff text', () => {
  const value = manifest({ diff: [
    '-----BEGIN PRIVATE KEY-----\\nsecret-material\\n-----END PRIVATE KEY-----',
    'jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature-value',
    'token=ghp_123456789012345678901234567890123456',
    'rpc=https://user:password@example.invalid/rpc',
  ].join('\\n') });
  assert.equal(value.diff.includes('secret-material'), false);
  assert.equal(value.diff.includes('eyJhbGciOiJIUzI1NiJ9'), false);
  assert.equal(value.diff.includes('ghp_123456789012345678901234567890123456'), false);
  assert.equal(value.diff.includes('user:password@'), false);
  assert.ok(value.privacy.redactionCount >= 4);
  assert.equal(verifyReviewManifest(value), true);
});

test('redacts camelCase credential fields and required test text', () => {
  const value = manifest({
    environment: {
      apiKey: 'api-secret',
      accessToken: 'access-secret',
      clientApiKey: 'client-secret',
      accessTokenValue: 'token-secret',
      harmlessValue: 'keep-me',
    },
  });
  assert.equal(value.environment.apiKey, '[REDACTED]');
  assert.equal(value.environment.accessToken, '[REDACTED]');
  assert.equal(value.environment.clientApiKey, '[REDACTED]');
  assert.equal(value.environment.accessTokenValue, '[REDACTED]');
  assert.equal(value.environment.harmlessValue, 'keep-me');

  const review = validateCloudReview({
    schemaVersion: 1,
    manifestSha256: value.manifestSha256,
    decision: 'allow',
    evidenceComplete: true,
    findings: [{
      findingId: 'f-secret',
      severity: 'P2',
      title: 'review note',
      summary: 'required setup',
      confidence: 0.8,
      evidenceComplete: true,
      requiredTests: ['run apiKey=required-secret and accessToken: token-secret'],
    }],
  }, value);
  assert.equal(review.findings[0].requiredTests[0], 'run apiKey=[REDACTED] and accessToken: [REDACTED]');
  assert.equal(review.privacy.redacted, true);
  assert.ok(review.privacy.redactionCount >= 2);
});

test('validates cloud review against the exact manifest and changed files', () => {
  const value = manifest();
  const review = validateCloudReview({
    schemaVersion: 1,
    manifestSha256: value.manifestSha256,
    decision: 'allow',
    evidenceComplete: true,
    findings: [{ findingId: 'f-1', severity: 'P2', title: 'review note', summary: 'needs follow-up', file: 'src/example.js', line: 4, confidence: 0.7, evidenceComplete: true }],
  }, value);
  assert.equal(review.findings[0].file, 'src/example.js');
  assert.throws(() => validateCloudReview({ schemaVersion: 1, manifestSha256: '0'.repeat(64), decision: 'allow', evidenceComplete: true, findings: [] }, value), /does not match/);
  assert.throws(() => validateCloudReview({ schemaVersion: 1, manifestSha256: value.manifestSha256, decision: 'allow', evidenceComplete: true, findings: [{ findingId: 'f-2', severity: 'P2', title: 'bad', summary: 'bad', file: 'src/other.js', line: 1, confidence: 0.5, evidenceComplete: true }] }, value), /unchanged file/);
});

test('blocks merge on P0/P1, required failures, incomplete evidence, and unexplained dependencies', () => {
  const value = manifest({
    dependencies: [{ name: 'package-x', changed: true, from: '1', to: '2' }],
    tests: [{ name: 'unit', status: 'failed', required: true }],
  });
  const result = evaluateMergeGate({
    manifest: value,
    review: {
      schemaVersion: 1,
      manifestSha256: value.manifestSha256,
      decision: 'allow',
      evidenceComplete: false,
      findings: [{ findingId: 'f-1', severity: 'P1', title: 'blocking', summary: 'blocking', confidence: 0.9, evidenceComplete: false }],
    },
    checks: [{ name: 'integration', status: 'failed', required: true }],
  });
  assert.equal(result.allowed, false);
  assert.deepEqual(new Set(result.reasons.map((reason) => reason.code)), new Set([
    'required_check_failed', 'required_test_failed', 'evidence_incomplete', 'blocking_finding', 'finding_evidence_incomplete', 'unexplained_dependency_change',
  ]));
});

test('allows a complete P2 review when all required checks pass', () => {
  const value = manifest();
  const result = evaluateMergeGate({
    manifest: value,
    review: { schemaVersion: 1, manifestSha256: value.manifestSha256, decision: 'allow', evidenceComplete: true, findings: [{ findingId: 'f-1', severity: 'P2', title: 'note', summary: 'reviewed', confidence: 0.8, evidenceComplete: true }] },
    checks: [{ name: 'integration', status: 'passed', required: true }],
  });
  assert.deepEqual(result, { allowed: true, status: 'allowed', reasons: [], manifestSha256: value.manifestSha256 });
});

test('blocks an unapproved blocking flag and missing required test evidence', () => {
  const value = manifest({ tests: [] });
  const result = evaluateMergeGate({
    manifest: value,
    review: { schemaVersion: 1, manifestSha256: value.manifestSha256, decision: 'allow', evidenceComplete: true, findings: [
      { findingId: 'block-p2', severity: 'P2', title: 'blocking review', summary: 'blocking by explicit flag', confidence: 0.9, evidenceComplete: true, blocking: true },
    ] },
  });
  assert.equal(result.allowed, false);
  assert.ok(result.reasons.some((reason) => reason.code === 'required_test_evidence_missing'));
  assert.ok(result.reasons.some((reason) => reason.code === 'blocking_finding'));
});

test('accepts an empty diff, rejects unsafe paths, duplicate findings, and non-approval', () => {
  const empty = manifest({ diff: '' });
  assert.equal(verifyReviewManifest(empty), true);
  assert.throws(() => manifest({ changedFiles: [{ path: '../outside.js' }] }), /repository-relative/);

  assert.throws(() => validateCloudReview({
    schemaVersion: 1,
    manifestSha256: empty.manifestSha256,
    decision: 'allow',
    evidenceComplete: true,
    findings: [
      { findingId: 'duplicate', severity: 'P2', title: 'a', summary: 'a', file: 'src/example.js', line: 1, confidence: 0.5, evidenceComplete: true },
      { findingId: 'duplicate', severity: 'P2', title: 'b', summary: 'b', file: 'src/example.js', line: 2, confidence: 0.5, evidenceComplete: true },
    ],
  }, empty), /duplicate findingId/);

  const needsChanges = evaluateMergeGate({
    manifest: empty,
    review: { schemaVersion: 1, manifestSha256: empty.manifestSha256, decision: 'needs_changes', evidenceComplete: true, findings: [] },
    checks: [{ name: 'unit', status: 'passed', required: true }],
  });
  assert.equal(needsChanges.allowed, false);
  assert.ok(needsChanges.reasons.some((reason) => reason.code === 'cloud_review_not_approved'));
});
