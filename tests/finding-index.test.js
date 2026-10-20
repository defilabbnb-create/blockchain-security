import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { writeFindingIndex } from '../src/status-store.js';

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'finding-index-'));
  return { root, workDir: join(root, 'work'), runId: 'run-test', contract: join(root, 'work', 'defi-campaign', 'run-test', 'contracts', '1-0xabc') };
}

async function writeJson(path, value) {
  await mkdir(join(path, '..'), { recursive: true });
  await writeFile(path, JSON.stringify(value));
}

test('finding index handles an empty campaign directory and writes its versioned envelope', async (t) => {
  const data = await fixture();
  t.after(() => rm(data.root, { recursive: true, force: true }));
  await mkdir(data.workDir, { recursive: true });
  const index = await writeFindingIndex(data.workDir, '2026-01-02T03:04:05.000Z');
  assert.deepEqual(index, { schemaVersion: 1, generatedAt: '2026-01-02T03:04:05.000Z', findings: [] });
  assert.deepEqual(JSON.parse(await readFile(join(data.workDir, 'finding-index.json'), 'utf8')), index);
});

test('finding index ignores observations with missing required evidence fields', async (t) => {
  const data = await fixture();
  t.after(() => rm(data.root, { recursive: true, force: true }));
  await mkdir(data.contract, { recursive: true });
  await writeJson(join(data.contract, 'evidence.json'), { protocol: '示例协议', chain: '示例链', address: '0xabc', source: { sha256: 'a'.repeat(64) } });
  await writeJson(join(data.contract, 'cloud-review-evidence.json'), { manifestSha256: 'b'.repeat(64) });
  await writeJson(join(data.contract, 'review.json'), { observations: [
    { kind: 'risk_hypothesis', title: '缺少行号', evidence: [{ file: 'A.sol', quote: 'x' }] },
    { kind: 'risk_hypothesis', title: '缺少引文', evidence: [{ file: 'A.sol', lineStart: 1, lineEnd: 1 }] },
  ] });
  assert.deepEqual((await writeFindingIndex(data.workDir)).findings, []);
});

test('finding index deduplicates identical source, kind, and line references', async (t) => {
  const data = await fixture();
  t.after(() => rm(data.root, { recursive: true, force: true }));
  await mkdir(data.contract, { recursive: true });
  await writeJson(join(data.contract, 'evidence.json'), { protocol: '示例协议', chain: '示例链', address: '0xabc', source: { sha256: 'c'.repeat(64) }, finishedAt: '2026-01-01T00:00:00Z' });
  await writeJson(join(data.contract, 'cloud-review-evidence.json'), { manifestSha256: 'd'.repeat(64) });
  await writeJson(join(data.contract, 'review.json'), { observations: [1, 2].map(() => ({
    kind: 'risk_hypothesis', title: '重复观察', confidence: 'medium', evidence: [{ file: 'src/Vault.sol', lineStart: 10, lineEnd: 12, quote: 'withdraw();' }],
  })) });
  const findings = (await writeFindingIndex(data.workDir)).findings;
  assert.equal(findings.length, 1);
  assert.equal(findings[0].origin, 'campaign');
  assert.equal(findings[0].status, 'unconfirmed_observation');
  assert.equal(findings[0].sourceSha256, 'c'.repeat(64));
  assert.equal(findings[0].evidence[0].lineStart, 10);
});

test('finding index rejects parent traversal in source evidence paths', async (t) => {
  const data = await fixture();
  t.after(() => rm(data.root, { recursive: true, force: true }));
  await mkdir(data.contract, { recursive: true });
  await writeJson(join(data.contract, 'evidence.json'), { protocol: '示例协议', chain: '示例链', address: '0xabc', source: { sha256: 'e'.repeat(64) } });
  await writeJson(join(data.contract, 'cloud-review-evidence.json'), { manifestSha256: 'f'.repeat(64) });
  await writeJson(join(data.contract, 'review.json'), { observations: [{
    kind: 'risk_hypothesis', title: '越界路径', confidence: 'high', evidence: [{ file: '../outside.sol', lineStart: 1, lineEnd: 1, quote: 'sensitive' }],
  }] });
  assert.deepEqual((await writeFindingIndex(data.workDir)).findings, []);
  assert.equal(await readFile(join(data.root, 'outside.sol')).then(() => true, () => false), false);
});

test('finding index emits a static signal for bytecode-only functions', async (t) => {
  const data = await fixture();
  t.after(() => rm(data.root, { recursive: true, force: true }));
  await mkdir(data.contract, { recursive: true });
  await writeJson(join(data.contract, 'evidence.json'), { protocol: '示例协议', chain: '示例链', address: '0xabc', source: { sha256: '9'.repeat(64) }, finishedAt: '2026-01-01T00:00:00Z' });
  await writeJson(join(data.contract, 'ir-reconciliation.json'), { sourceFaithfulnessScore: 0.5,
    bytecodeOnlyFunctions: [{ selector: '0xdeadbeef', riskHints: ['DELEGATECALL'] }] });
  const findings = (await writeFindingIndex(data.workDir)).findings;
  const finding = findings.find((item) => item.kind === 'source_bytecode_divergence');
  assert.ok(finding);
  assert.equal(finding.status, 'static_signal');
  assert.equal(finding.origin, 'campaign');
  assert.equal(finding.sourceSha256, '9'.repeat(64));
  assert.match(finding.evidence[0].quote, /0xdeadbeef/);
});

test('finding index records invariant violations without confirming a vulnerability', async (t) => {
  const data = await fixture();
  t.after(() => rm(data.root, { recursive: true, force: true }));
  await mkdir(data.contract, { recursive: true });
  await writeJson(join(data.contract, 'evidence.json'), { protocol: '示例协议', chain: '示例链', address: '0xabc', source: { sha256: '8'.repeat(64) }, finishedAt: '2026-01-01T00:00:00Z' });
  await writeJson(join(data.contract, 'dynamic-result.json'), { invariantId: 'a'.repeat(64), mode: 'local', state: 'violated', evidenceSha256: 'b'.repeat(64) });
  const findings = (await writeFindingIndex(data.workDir)).findings;
  const finding = findings.find((item) => item.kind === 'invariant_violated');
  assert.ok(finding);
  assert.equal(finding.status, 'invariant_violated');
  assert.equal(finding.confirmedVulnerability, undefined);
  assert.equal(finding.origin, 'campaign');
});

test('finding index attaches PoC confirmation and severity factors only to the matching finding ID', async (t) => {
  const data = await fixture();
  t.after(() => rm(data.root, { recursive: true, force: true }));
  await mkdir(data.contract, { recursive: true });
  const sourceSha256 = '7'.repeat(64);
  const findingId = createHash('sha256').update(`${sourceSha256}risk_hypothesis22`).digest('hex');
  await writeJson(join(data.contract, 'evidence.json'), { protocol: '示例协议', chain: '示例链', address: '0xabc', source: { sha256: sourceSha256 }, finishedAt: '2026-01-01T00:00:00Z' });
  await writeJson(join(data.contract, 'review.json'), { observations: [{
    kind: 'risk_hypothesis', title: '重入候选', evidence: [{ file: 'Vault.sol', lineStart: 2, lineEnd: 2, quote: 'token.transfer(msg.sender, amount);' }],
  }] });
  await writeJson(join(data.contract, 'poc-result.json'), { findingId, pocState: 'confirmed', confirmedVulnerability: true,
    sourceSha256, pocEvidenceSha256: '1'.repeat(64), evidenceSha256: '2'.repeat(64),
    severityFactors: { categoryWeight: 5, triggerDifficulty: 0.5, reachableAssetsUsd: 1000 }, severityScore: 2500,
    minCapitalRequiredWei: '17', pocArtifactPath: 'work/harness/poc/test.t.sol' });
  const findings = (await writeFindingIndex(data.workDir)).findings;
  const finding = findings.find((item) => item.id === findingId);
  assert.ok(finding);
  assert.equal(finding.status, 'poc_confirmed');
  assert.equal(finding.confirmedVulnerability, true);
  assert.equal(finding.severityScore, 2500);
  assert.equal(finding.minCapitalRequiredWei, '17');
});
