#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { mkdir, rename, writeFile, unlink } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { access } from 'node:fs/promises';
import { evidenceFingerprint } from '../src/evidence-fingerprint.js';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
const CORE = join(ROOT, 'flare-scan', 'contracts', 'firelight-core');
const OUTPUT = resolve(process.env.SECURITY_TEST_REPORT_PATH || join(ROOT, 'work', 'security-test-report.json'));
const timeoutMs = Number(process.env.SECURITY_TEST_TIMEOUT_MS || 900_000);

const suites = [
  {
    id: 'incident-payout-path',
    label: 'IncidentManager payout path',
    command: 'node_modules/.bin/hardhat',
    args: ['test', 'test/incidentManager/IncidentManager.test.js', 'test/FirelightVault/reentrancy.js'],
  },
  {
    id: 'cover-order-premium-pull',
    label: 'CoverOrderAllocator settlement path',
    command: 'node_modules/.bin/hardhat',
    args: ['test', 'test/coverOrderAllocator/commitAllocation.js', 'test/coverOrderAllocator/createCoverOrder.js', 'test/coverOrderAllocator/testVectors.js', 'test/security/dshConservation.js'],
  },
  {
    id: 'capacity-oracle-commitment',
    label: 'Capacity / oracle commitment path',
    command: 'node_modules/.bin/hardhat',
    args: ['test', 'test/coverOrderAllocator/commitAllocation.js', 'test/coverOrderAllocator/capacityConfigCheckpoints.js', 'test/coverOrderAllocator/testVectors.js'],
  },
];

function runCommand(suite) {
  return new Promise((resolveResult) => {
    const startedAt = new Date().toISOString();
    const start = Date.now();
    const child = spawn(suite.command, suite.args, {
      cwd: CORE,
      env: { ...process.env, NO_COLOR: '1', FORCE_COLOR: '0' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let output = '';
    const append = (chunk) => { output += chunk.toString(); if (output.length > 24_000) output = output.slice(-24_000); };
    child.stdout.on('data', append);
    child.stderr.on('data', append);
    let timedOut = false;
    let timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGTERM');
      setTimeout(() => child.kill('SIGKILL'), 2500).unref();
    }, timeoutMs);
    child.on('error', (error) => {
      clearTimeout(timer);
      resolveResult({ id: suite.id, label: suite.label, status: 'error', exitCode: null, startedAt, finishedAt: new Date().toISOString(), durationMs: Date.now() - start, outputTail: `${output}\n${error.message}`.slice(-4000) });
    });
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      const passing = output.match(/(\d+) passing\b/) || output.match(/:\s*(\d+) tests passed,\s*\d+ failed,\s*\d+ skipped\b/);
      resolveResult({ id: suite.id, label: suite.label, status: timedOut ? 'timeout' : code === 0 ? 'passed' : 'failed', exitCode: code, signal, startedAt, finishedAt: new Date().toISOString(), durationMs: Date.now() - start, passing: Number(passing?.[1] || 0), command: [suite.command, ...suite.args], outputTail: output.slice(-5000) });
    });
  });
}

async function findForge() {
  const local = join(ROOT, 'work', 'tools', 'forge');
  try { await access(local); return local; } catch {}
  return null;
}

async function writeAtomic(value) {
  await mkdir(dirname(OUTPUT), { recursive: true });
  const temp = `${OUTPUT}.${randomUUID()}.tmp`;
  try {
    await writeFile(temp, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
    await rename(temp, OUTPUT);
  } finally {
    await unlink(temp).catch(() => {});
  }
}

const selected = process.argv.includes('--quick') ? suites.slice(0, 2) : suites;
const startedAt = new Date().toISOString();
const sourceFingerprint = await evidenceFingerprint(CORE);
const results = [];
for (const suite of selected) {
  console.log(`开始本地安全测试：${suite.label}`);
  const result = await runCommand(suite);
  results.push(result);
  console.log(`${result.status}: ${suite.label} (${result.durationMs}ms)`);
}
const forge = await findForge();
const foundryId = 'foundry-regression-invariant';
if (forge && !process.argv.includes('--quick')) {
  console.log('开始 Foundry 回归 / fuzz / invariant 测试');
  const result = await runCommand({ id: foundryId, label: 'Foundry regression / invariant suites', command: forge, args: ['test', '--threads', '2'] });
  results.push(result);
  console.log(`${result.status}: Foundry (${result.durationMs}ms)`);
} else {
  results.push({ id: foundryId, label: 'Foundry regression / invariant suites', status: forge ? 'not_run' : 'skipped_missing_tool', durationMs: 0, outputTail: forge ? 'quick 模式未运行 Foundry' : 'forge 未安装' });
}
const sourceUnchanged = sourceFingerprint === await evidenceFingerprint(CORE);
const requiredComplete = sourceUnchanged && suites.every((suite) => results.some((result) => result.id === suite.id && result.status === 'passed'));
const missingSuites = [...suites.map((s) => s.id), foundryId].filter((id) => !results.some((result) => result.id === id && result.status === 'passed'));
const report = {
  schemaVersion: 1,
  generatedAt: new Date().toISOString(),
  root: ROOT,
  suites: results,
  requiredComplete,
  sourceFingerprint,
  sourceUnchanged,
  // complete means every declared suite, including Foundry, is available and passing.
  complete: requiredComplete && missingSuites.length === 0 && results.every((result) => result.status === 'passed'),
  missingSuites,
  caveat: missingSuites.length
    ? '存在缺失、失败或未运行的套件；全套覆盖不完整。通过仅代表本地源码及测试场景，不代表部署合约或所有状态组合安全。'
    : '通过代表本地测试场景通过，不代表部署合约或所有状态组合安全。',
};
await writeAtomic(report);
console.log(JSON.stringify({ output: OUTPUT, complete: report.complete, requiredComplete, missingSuites, suites: results.map(({ id, status }) => ({ id, status })) }, null, 2));
// A full run must include Foundry. Quick mode succeeds only for its selected
// suites, while its report still explicitly marks full coverage incomplete.
process.exitCode = (process.argv.includes('--quick')
  ? sourceUnchanged && selected.every((suite) => results.some((r) => r.id === suite.id && r.status === 'passed'))
  : report.complete) ? 0 : 1;
