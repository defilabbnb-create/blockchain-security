#!/usr/bin/env node
import { execFile } from 'node:child_process';
import { mkdir, readFile, realpath, rename, unlink, writeFile } from 'node:fs/promises';
import { promisify } from 'node:util';
import { dirname, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createReviewManifest } from '../src/review-manifest.js';

const execFileAsync = promisify(execFile);
const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));

function usage() {
  return [
    '用法：node scripts/create-review-manifest.mjs [选项]',
    '  --output PATH                 输出 manifest JSON（默认 work/review-manifest.json）',
    '  --base REVISION               git 基线 revision',
    '  --head REVISION               git 目标 revision（默认工作区）',
    '  --diff-file PATH              使用指定脱敏前 diff 文件',
    '  --changed-files-file PATH     JSON 数组或 {"files":[...]}',
    '  --tests-file PATH             JSON 测试结果数组或 {"tests":[...]}',
    '  --dependencies-file PATH      JSON 依赖变化数组或 {"dependencies":[...]}',
    '  --model NAME                  本地审查模型名称（仅记录，不调用模型）',
    '  --round N                     审查轮次，默认 0',
  ].join('\n');
}

function parseArgs(argv) {
  const values = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--help' || arg === '-h') { console.log(usage()); process.exit(0); }
    if (!arg.startsWith('--')) throw new Error(`未知参数：${arg}`);
    const key = arg.slice(2);
    if (!['output', 'base', 'head', 'diff-file', 'changed-files-file', 'tests-file', 'dependencies-file', 'model', 'round'].includes(key)) throw new Error(`未知参数：${arg}`);
    const value = argv[index + 1];
    if (value === undefined || value.startsWith('--')) throw new Error(`参数缺少值：${arg}`);
    values[key] = value;
    index += 1;
  }
  return values;
}

function localPath(value, label) {
  if (!value) return null;
  const path = resolve(ROOT, value);
  if (path !== ROOT && !path.startsWith(`${ROOT}/`)) throw new Error(`${label} 必须位于项目目录内`);
  return path;
}

async function nearestExistingRealPath(path) {
  let candidate = path;
  while (true) {
    try {
      return await realpath(candidate);
    } catch (error) {
      if (!['ENOENT', 'ENOTDIR'].includes(error.code)) throw error;
      const parent = dirname(candidate);
      if (parent === candidate) throw error;
      candidate = parent;
    }
  }
}

async function assertRealPathInsideRoot(path, label, { output = false } = {}) {
  const realRoot = await realpath(ROOT);
  const realPath = output ? await nearestExistingRealPath(path) : await realpath(path);
  const pathFromRoot = relative(realRoot, realPath);
  if (pathFromRoot === '..' || pathFromRoot.startsWith(`..${sep}`) || pathFromRoot.startsWith(sep)) {
    throw new Error(`${label} 的真实路径越出项目目录（可能经由符号链接）`);
  }
}

async function readOptionalJson(value, label, fallback) {
  const path = localPath(value, label);
  if (!path) return fallback;
  await assertRealPathInsideRoot(path, label);
  const parsed = JSON.parse(await readFile(path, 'utf8'));
  if (Array.isArray(parsed)) return parsed;
  if (parsed && typeof parsed === 'object' && Array.isArray(parsed[label])) return parsed[label];
  throw new Error(`${label} 文件必须是数组或包含 ${label} 数组的对象`);
}

async function gitOutput(args) {
  try {
    const { stdout } = await execFileAsync('git', args, { cwd: ROOT, maxBuffer: 8 * 1024 * 1024 });
    return stdout;
  } catch (error) {
    throw new Error(`git 命令失败：${String(error.stderr || error.message).trim().slice(0, 500)}`);
  }
}

async function gitOutputWithExpectedChanges(args) {
  try {
    const { stdout } = await execFileAsync('git', args, { cwd: ROOT, maxBuffer: 8 * 1024 * 1024 });
    return stdout;
  } catch (error) {
    if (error.code === 1 && typeof error.stdout === 'string') return error.stdout;
    throw new Error(`git 命令失败：${String(error.stderr || error.message).trim().slice(0, 500)}`);
  }
}

async function hasHeadRevision() {
  try {
    await execFileAsync('git', ['rev-parse', '--verify', 'HEAD'], { cwd: ROOT });
    return true;
  } catch { return false; }
}

function revisionRange(options) {
  if (options.base && options.head) return [`${options.base}..${options.head}`];
  if (options.base) return [options.base];
  if (options.head) return [`HEAD..${options.head}`];
  return [];
}

function parseChangedFiles(text) {
  const fields = text.split('\0');
  const files = [];
  for (let index = 0; index < fields.length;) {
    const status = fields[index++];
    if (!status) continue;
    const firstPath = fields[index++];
    const isRenameOrCopy = status.startsWith('R') || status.startsWith('C');
    const path = isRenameOrCopy ? fields[index++] : firstPath;
    if (!path) throw new Error('git changed file output contains an empty path');
    files.push({ path, status });
  }
  return files;
}

async function writeAtomic(path, value) {
  await mkdir(dirname(path), { recursive: true });
  const temp = `${path}.${process.pid}.${Date.now()}.tmp`;
  try {
    await writeFile(temp, `${JSON.stringify(value, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
    await rename(temp, path);
  } finally { await unlink(temp).catch(() => {}); }
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const output = localPath(options.output || 'work/review-manifest.json', 'output');
  await assertRealPathInsideRoot(output, 'output', { output: true });
  const range = revisionRange(options);
  const explicitChangedFiles = Boolean(options['changed-files-file']);
  const explicitDiff = Boolean(options['diff-file']);
  const hasHead = await hasHeadRevision();
  if (!hasHead && (!explicitChangedFiles || !explicitDiff)) throw new Error('仓库没有可比较的 HEAD；请同时提供 --changed-files-file 和 --diff-file，避免生成空基线清单');
  if (explicitChangedFiles !== explicitDiff) throw new Error('--changed-files-file 与 --diff-file 必须成对提供，确保文件清单与 diff 一致');
  const compare = range.length ? range : ['HEAD'];
  const untracked = explicitChangedFiles || !hasHead
    ? []
    : (await gitOutput(['ls-files', '--others', '--exclude-standard', '-z'])).split('\0').filter((path) => path && !path.startsWith('work/'));
  const changedFiles = explicitChangedFiles
    ? await readOptionalJson(options['changed-files-file'], 'files', [])
    : [
      ...parseChangedFiles(await gitOutput(['diff', '--no-ext-diff', '--name-status', '-z', ...compare])),
      ...untracked.map((path) => ({ path, status: 'added' })),
    ];
  let diff;
  if (explicitDiff) {
    const diffPath = localPath(options['diff-file'], 'diff-file');
    await assertRealPathInsideRoot(diffPath, 'diff-file');
    diff = await readFile(diffPath, 'utf8');
  }
  else {
    diff = await gitOutput(['diff', '--no-ext-diff', '--binary', ...compare]);
    for (const path of untracked) {
      const fileDiff = await gitOutputWithExpectedChanges(['diff', '--no-index', '--binary', '--', '/dev/null', path]);
      diff += fileDiff;
      if (diff.length > 4_000_000) throw new Error('未跟踪文件 diff 超过 4 MB；请显式选择审查文件');
    }
  }
  if (!hasHead && (changedFiles.length === 0 || !diff.trim())) {
    throw new Error('仓库没有可比较的 HEAD；显式 changed files 和 diff 均不得为空');
  }
  const tests = await readOptionalJson(options['tests-file'], 'tests', []);
  const dependencies = await readOptionalJson(options['dependencies-file'], 'dependencies', []);
  const reviewRound = options.round === undefined ? 0 : Number(options.round);
  const manifest = createReviewManifest({
    baseRevision: options.base || null,
    headRevision: options.head || null,
    changedFiles,
    diff,
    tests,
    dependencies,
    environment: { node: process.version, platform: process.platform, architecture: process.arch },
    localModel: options.model ? { model: options.model, mode: 'record-only' } : null,
    reviewRound,
  });
  await writeAtomic(output, manifest);
  console.log(JSON.stringify({ output, manifestSha256: manifest.manifestSha256, changedFiles: manifest.changedFiles.length, tests: manifest.tests.length, dependencies: manifest.dependencies.length, redactions: manifest.privacy.redactionCount }, null, 2));
}

try { await main(); }
catch (error) { console.error(`review manifest 失败：${error.message}`); console.error(usage()); process.exitCode = 2; }
