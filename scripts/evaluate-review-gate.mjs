#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { link, mkdir, readFile, realpath, unlink, writeFile } from 'node:fs/promises';
import { dirname, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { evaluateMergeGate } from '../src/review-manifest.js';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));

function usage() {
  return [
    '用法：node scripts/evaluate-review-gate.mjs --manifest PATH --review PATH --checks PATH --output PATH',
    '  只校验本地 JSON；不调用 AI、不验证审查者身份、不执行合并。',
    '  checks 文件格式为数组或 {"checks":[...]}。',
  ].join('\n');
}

function parseArgs(argv) {
  const values = {};
  const allowed = new Set(['manifest', 'review', 'checks', 'output']);
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--help' || arg === '-h') { console.log(usage()); process.exit(0); }
    if (!arg.startsWith('--') || !allowed.has(arg.slice(2))) throw new Error(`未知参数：${arg}`);
    const key = arg.slice(2);
    if (values[key] !== undefined) throw new Error(`参数重复：${arg}`);
    const value = argv[index + 1];
    if (value === undefined || value.startsWith('--')) throw new Error(`参数缺少值：${arg}`);
    values[key] = value;
    index += 1;
  }
  for (const key of allowed) if (!values[key]) throw new Error(`缺少参数：--${key}`);
  return values;
}

async function safePath(value, label, { output = false } = {}) {
  const path = resolve(ROOT, value);
  const root = await realpath(ROOT);
  let actual;
  if (output) {
    let candidate = path;
    while (true) {
      try { actual = await realpath(candidate); break; }
      catch (error) {
        if (!['ENOENT', 'ENOTDIR'].includes(error.code)) throw error;
        const parent = dirname(candidate);
        if (parent === candidate) throw error;
        candidate = parent;
      }
    }
  } else actual = await realpath(path);
  const fromRoot = relative(root, actual);
  if (fromRoot === '..' || fromRoot.startsWith(`..${sep}`) || fromRoot.startsWith(sep)) throw new Error(`${label} 的真实路径越出项目目录`);
  return path;
}

async function readJson(path, label) {
  const bytes = await readFile(path);
  let value;
  try { value = JSON.parse(bytes.toString('utf8')); }
  catch { throw new Error(`${label} 不是有效 JSON`); }
  return { value, sha256: createHash('sha256').update(bytes).digest('hex') };
}

async function writeNewFile(path, value) {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.${process.pid}.${Date.now()}.tmp`;
  try {
    await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    await link(temporary, path);
  } finally {
    await unlink(temporary).catch(() => {});
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const paths = {};
  for (const key of ['manifest', 'review', 'checks']) paths[key] = await safePath(args[key], key);
  paths.output = await safePath(args.output, 'output', { output: true });
  const [manifest, review, checksInput] = await Promise.all([
    readJson(paths.manifest, 'manifest'), readJson(paths.review, 'review'), readJson(paths.checks, 'checks'),
  ]);
  const checks = Array.isArray(checksInput.value) ? checksInput.value : checksInput.value?.checks;
  if (!Array.isArray(checks)) throw new Error('checks 文件必须是数组或包含 checks 数组的对象');
  const gate = evaluateMergeGate({ manifest: manifest.value, review: review.value, checks });
  const result = {
    schemaVersion: 1,
    evaluatedAt: new Date().toISOString(),
    gate,
    inputs: { manifestSha256: manifest.sha256, reviewSha256: review.sha256, checksSha256: checksInput.sha256 },
    reviewOrigin: { suppliedAs: 'local-json', identityVerified: false },
    mergePerformed: false,
    interpretation: '门禁结果仅反映本地规则对已提供材料的校验；不证明审查者身份，不执行或授权合并。',
  };
  await writeNewFile(paths.output, result);
  console.log(JSON.stringify({ output: paths.output, allowed: gate.allowed, status: gate.status, reasons: gate.reasons.length, manifestSha256: gate.manifestSha256, reviewOriginIdentityVerified: false, mergePerformed: false }, null, 2));
  if (!gate.allowed) process.exitCode = 1;
}

main().catch((error) => {
  console.error(`review gate 失败：${error.message}`);
  console.error(usage());
  process.exitCode = 2;
});
