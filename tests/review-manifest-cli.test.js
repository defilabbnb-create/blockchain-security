import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { copyFile, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { promisify } from 'node:util';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createReviewManifest } from '../src/review-manifest.js';

const execFileAsync = promisify(execFile);
const ROOT = fileURLToPath(new URL('..', import.meta.url));

test('review:gate records a local gate result without authenticating review origin or merging', async () => {
  const dir = await mkdtemp(join(ROOT, 'work', 'review-gate-cli-'));
  try {
    const manifest = createReviewManifest({
      manifestId: 'gate-manifest', createdAt: '2026-10-20T00:00:00.000Z',
      changedFiles: [{ path: 'src/example.js', status: 'modified' }], diff: '+safe change',
      tests: [{ name: 'unit', status: 'passed', required: true }],
    });
    const review = { schemaVersion: 1, manifestSha256: manifest.manifestSha256, decision: 'allow', evidenceComplete: true, findings: [] };
    const inputs = {
      manifest: join(dir, 'manifest.json'), review: join(dir, 'review.json'), checks: join(dir, 'checks.json'),
    };
    await writeFile(inputs.manifest, JSON.stringify(manifest));
    await writeFile(inputs.review, JSON.stringify(review));
    await writeFile(inputs.checks, JSON.stringify({ checks: [{ name: 'integration', status: 'passed', required: true }] }));
    const output = join(dir, 'gate.json');
    const args = ['scripts/evaluate-review-gate.mjs', '--manifest', inputs.manifest, '--review', inputs.review, '--checks', inputs.checks, '--output', output];
    const { stdout } = await execFileAsync(process.execPath, args, { cwd: ROOT });
    assert.equal(JSON.parse(stdout).allowed, true);
    const result = JSON.parse(await readFile(output, 'utf8'));
    assert.equal(result.gate.allowed, true);
    assert.equal(result.reviewOrigin.identityVerified, false);
    assert.equal(result.mergePerformed, false);
    assert.match(result.inputs.reviewSha256, /^[a-f0-9]{64}$/);
    await assert.rejects(execFileAsync(process.execPath, args, { cwd: ROOT }), (error) => error.code === 2 && error.stderr.includes('EEXIST'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('review:gate persists blocked decisions and rejects a review bound to another manifest', async () => {
  const dir = await mkdtemp(join(ROOT, 'work', 'review-gate-blocked-'));
  try {
    const manifest = createReviewManifest({
      manifestId: 'blocked-manifest', createdAt: '2026-10-20T00:00:00.000Z',
      changedFiles: [{ path: 'src/example.js', status: 'modified' }], diff: '+safe change',
      tests: [{ name: 'unit', status: 'passed', required: true }],
    });
    const files = { manifest: join(dir, 'manifest.json'), review: join(dir, 'review.json'), checks: join(dir, 'checks.json') };
    await writeFile(files.manifest, JSON.stringify(manifest));
    await writeFile(files.review, JSON.stringify({ schemaVersion: 1, manifestSha256: manifest.manifestSha256, decision: 'needs_changes', evidenceComplete: true, findings: [] }));
    await writeFile(files.checks, JSON.stringify([{ name: 'unit', status: 'passed', required: true }]));
    const output = join(dir, 'blocked.json');
    const args = ['scripts/evaluate-review-gate.mjs', '--manifest', files.manifest, '--review', files.review, '--checks', files.checks, '--output', output];
    await assert.rejects(execFileAsync(process.execPath, args, { cwd: ROOT }), (error) => error.code === 1 && error.stdout.includes('"allowed": false'));
    const blocked = JSON.parse(await readFile(output, 'utf8'));
    assert.equal(blocked.gate.status, 'blocked');
    assert.equal(blocked.mergePerformed, false);

    const invalidOutput = join(dir, 'invalid.json');
    await writeFile(files.review, JSON.stringify({ schemaVersion: 1, manifestSha256: '0'.repeat(64), decision: 'allow', evidenceComplete: true, findings: [] }));
    const invalidArgs = [...args];
    invalidArgs[invalidArgs.length - 1] = invalidOutput;
    await assert.rejects(execFileAsync(process.execPath, invalidArgs, { cwd: ROOT }), (error) => error.code === 2 && error.stderr.includes('does not match'));
    await assert.rejects(readFile(invalidOutput), (error) => error.code === 'ENOENT');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('review:manifest builds an auditable manifest from explicit local inputs', async () => {
  const dir = await mkdtemp(join(ROOT, 'work', 'review-cli-'));
  try {
    const diff = join(dir, 'change.diff');
    const files = join(dir, 'files.json');
    const tests = join(dir, 'tests.json');
    const dependencies = join(dir, 'dependencies.json');
    const output = join(dir, 'manifest.json');
    await writeFile(diff, 'api_key=do-not-share\n');
    await writeFile(files, JSON.stringify([{ path: 'src/example.js', status: 'modified' }]));
    await writeFile(tests, JSON.stringify([{ name: 'unit', status: 'passed', required: true }]));
    await writeFile(dependencies, JSON.stringify([{ name: 'dep', changed: true, reason: 'security update' }]));
    const { stdout } = await execFileAsync(process.execPath, ['scripts/create-review-manifest.mjs', '--output', output, '--diff-file', diff, '--changed-files-file', files, '--tests-file', tests, '--dependencies-file', dependencies, '--model', 'local-model'], { cwd: ROOT });
    const summary = JSON.parse(stdout);
    const manifest = JSON.parse(await readFile(output, 'utf8'));
    assert.equal(summary.output, output);
    assert.equal(manifest.changedFiles.length, 1);
    assert.equal(manifest.tests[0].status, 'passed');
    assert.equal(manifest.dependencies[0].reason, 'security update');
    assert.equal(manifest.diff.includes('do-not-share'), false);
    assert.equal(manifest.localModel.model, 'local-model');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('review:manifest rejects implicit empty review baseline when git has no HEAD', async () => {
  const fixture = await mkdtemp(join(ROOT, 'work', 'review-cli-no-head-'));
  try {
    await mkdir(join(fixture, 'src'), { recursive: true });
    await mkdir(join(fixture, 'scripts'), { recursive: true });
    await mkdir(join(fixture, 'work'), { recursive: true });
    await copyFile(join(ROOT, 'scripts', 'create-review-manifest.mjs'), join(fixture, 'scripts', 'create-review-manifest.mjs'));
    await copyFile(join(ROOT, 'src', 'review-manifest.js'), join(fixture, 'src', 'review-manifest.js'));
    await writeFile(join(fixture, 'package.json'), JSON.stringify({ type: 'module' }));
    await execFileAsync('git', ['init'], { cwd: fixture });
    const output = join(fixture, 'work', 'manifest.json');
    await assert.rejects(
      execFileAsync(process.execPath, ['scripts/create-review-manifest.mjs', '--output', output], { cwd: fixture }),
      (error) => {
        assert.equal(error.code, 2);
        assert.ok(error.stderr.includes('仓库没有可比较的 HEAD'));
        return true;
      }
    );
    await assert.rejects(
      readFile(output, 'utf8'),
      (error) => {
        assert.equal(error.code, 'ENOENT');
        return true;
      }
    );
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
});

test('review:manifest rejects explicit empty changed files and diff together', async () => {
  const fixture = await mkdtemp(join(ROOT, 'work', 'review-cli-empty-explicit-'));
  try {
    await mkdir(join(fixture, 'src'), { recursive: true });
    await mkdir(join(fixture, 'scripts'), { recursive: true });
    await mkdir(join(fixture, 'work'), { recursive: true });
    await copyFile(join(ROOT, 'scripts', 'create-review-manifest.mjs'), join(fixture, 'scripts', 'create-review-manifest.mjs'));
    await copyFile(join(ROOT, 'src', 'review-manifest.js'), join(fixture, 'src', 'review-manifest.js'));
    await writeFile(join(fixture, 'package.json'), JSON.stringify({ type: 'module' }));
    await execFileAsync('git', ['init'], { cwd: fixture });
    const output = join(fixture, 'work', 'manifest.json');
    const changedFiles = join(fixture, 'work', 'changed-files.json');
    const diff = join(fixture, 'work', 'change.diff');
    await writeFile(changedFiles, JSON.stringify([]));
    await writeFile(diff, '');
    await assert.rejects(
      execFileAsync(process.execPath, ['scripts/create-review-manifest.mjs', '--output', output, '--changed-files-file', changedFiles, '--diff-file', diff], { cwd: fixture }),
      (error) => {
        assert.equal(error.code, 2);
        assert.ok(error.stderr.includes('显式 changed files 和 diff 均不得为空'));
        return true;
      }
    );
    await assert.rejects(
      readFile(output, 'utf8'),
      (error) => {
        assert.equal(error.code, 'ENOENT');
        return true;
      }
    );
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
});

test('review:manifest rejects explicit changed files without a diff when git has HEAD', async () => {
  const fixture = await mkdtemp(join(ROOT, 'work', 'review-cli-changed-files-no-diff-'));
  try {
    await mkdir(join(fixture, 'src'), { recursive: true });
    await mkdir(join(fixture, 'scripts'), { recursive: true });
    await mkdir(join(fixture, 'work'), { recursive: true });
    await copyFile(join(ROOT, 'scripts', 'create-review-manifest.mjs'), join(fixture, 'scripts', 'create-review-manifest.mjs'));
    await copyFile(join(ROOT, 'src', 'review-manifest.js'), join(fixture, 'src', 'review-manifest.js'));
    await writeFile(join(fixture, 'package.json'), JSON.stringify({ type: 'module' }));
    await execFileAsync('git', ['init'], { cwd: fixture });
    await execFileAsync('git', ['config', 'user.name', 'Test'], { cwd: fixture });
    await execFileAsync('git', ['config', 'user.email', 'test@localhost'], { cwd: fixture });
    await writeFile(join(fixture, 'src', 'baseline.js'), '// baseline\n');
    await execFileAsync('git', ['add', 'src/baseline.js'], { cwd: fixture });
    await execFileAsync('git', ['commit', '-m', 'baseline'], { cwd: fixture });
    const output = join(fixture, 'work', 'manifest.json');
    const changedFiles = join(fixture, 'work', 'changed-files.json');
    await writeFile(changedFiles, JSON.stringify([{ path: 'src/baseline.js', status: 'modified' }]));
    await assert.rejects(
      execFileAsync(process.execPath, ['scripts/create-review-manifest.mjs', '--output', output, '--changed-files-file', changedFiles], { cwd: fixture }),
      (error) => {
        assert.equal(error.code, 2);
        assert.ok(error.stderr.includes('--changed-files-file 与 --diff-file 必须成对提供'));
        return true;
      }
    );
    await assert.rejects(
      readFile(output, 'utf8'),
      (error) => {
        assert.equal(error.code, 'ENOENT');
        return true;
      }
    );
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
});

test('review:manifest rejects real-path containment violations via symlinks', async () => {
  const fixture = await mkdtemp(join(ROOT, 'work', 'review-cli-symlink-'));
  const outside = await mkdtemp(join(ROOT, 'work', 'review-cli-symlink-outside-'));
  try {
    await mkdir(join(fixture, 'src'), { recursive: true });
    await mkdir(join(fixture, 'scripts'), { recursive: true });
    await mkdir(join(fixture, 'work'), { recursive: true });
    await copyFile(join(ROOT, 'scripts', 'create-review-manifest.mjs'), join(fixture, 'scripts', 'create-review-manifest.mjs'));
    await copyFile(join(ROOT, 'src', 'review-manifest.js'), join(fixture, 'src', 'review-manifest.js'));
    await writeFile(join(fixture, 'package.json'), JSON.stringify({ type: 'module' }));
    await writeFile(join(outside, 'diff.txt'), 'outside diff\n');
    await symlink(resolve(outside), join(fixture, 'work', 'external'));
    await symlink(resolve(outside), join(fixture, 'work', 'external-output'));
    const changedFiles = join(fixture, 'work', 'changed-files.json');
    await writeFile(changedFiles, JSON.stringify([{ path: 'src/example.js', status: 'modified' }]));
    await assert.rejects(
      execFileAsync(process.execPath, ['scripts/create-review-manifest.mjs', '--output', join(fixture, 'work', 'manifest.json'), '--diff-file', join(fixture, 'work', 'external', 'diff.txt'), '--changed-files-file', changedFiles], { cwd: fixture }),
      (error) => {
        assert.equal(error.code, 2);
        assert.ok(error.stderr.includes('diff-file 的真实路径越出项目目录'));
        return true;
      }
    );
    await assert.rejects(
      readFile(join(fixture, 'work', 'manifest.json'), 'utf8'),
      (error) => {
        assert.equal(error.code, 'ENOENT');
        return true;
      }
    );
    await assert.rejects(
      execFileAsync(process.execPath, ['scripts/create-review-manifest.mjs', '--output', join(fixture, 'work', 'external-output', 'manifest.json')], { cwd: fixture }),
      (error) => {
        assert.equal(error.code, 2);
        assert.ok(error.stderr.includes('output 的真实路径越出项目目录'));
        return true;
      }
    );
    await assert.rejects(
      readFile(join(outside, 'manifest.json'), 'utf8'),
      (error) => {
        assert.equal(error.code, 'ENOENT');
        return true;
      }
    );
  } finally {
    await rm(fixture, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});

test('review:manifest rejects oversized untracked text without writing a manifest', async () => {
  const fixture = await mkdtemp(join(ROOT, 'work', 'review-cli-oversized-'));
  try {
    await mkdir(join(fixture, 'src'), { recursive: true });
    await mkdir(join(fixture, 'scripts'), { recursive: true });
    await mkdir(join(fixture, 'work'), { recursive: true });
    await copyFile(join(ROOT, 'scripts', 'create-review-manifest.mjs'), join(fixture, 'scripts', 'create-review-manifest.mjs'));
    await copyFile(join(ROOT, 'src', 'review-manifest.js'), join(fixture, 'src', 'review-manifest.js'));
    await writeFile(join(fixture, 'package.json'), JSON.stringify({ type: 'module' }));
    await execFileAsync('git', ['init'], { cwd: fixture });
    await execFileAsync('git', ['config', 'user.name', 'Test'], { cwd: fixture });
    await execFileAsync('git', ['config', 'user.email', 'test@localhost'], { cwd: fixture });
    await writeFile(join(fixture, 'src', 'baseline.js'), '// baseline\n');
    await execFileAsync('git', ['add', 'package.json', 'scripts/create-review-manifest.mjs', 'src/review-manifest.js', 'src/baseline.js'], { cwd: fixture });
    await execFileAsync('git', ['commit', '-m', 'baseline'], { cwd: fixture });
    await writeFile(join(fixture, 'src', 'oversized.txt'), 'A'.repeat(4_100_000));
    const output = join(fixture, 'work', 'manifest.json');
    await assert.rejects(
      execFileAsync(process.execPath, ['scripts/create-review-manifest.mjs', '--output', output], { cwd: fixture }),
      (error) => {
        assert.equal(error.code, 2);
        assert.ok(error.stderr.includes('未跟踪文件 diff 超过 4 MB'));
        return true;
      }
    );
    await assert.rejects(
      readFile(output, 'utf8'),
      (error) => {
        assert.equal(error.code, 'ENOENT');
        return true;
      }
    );
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
});

test('review:manifest preserves untracked paths containing newline and tab', async () => {
  const fixture = await mkdtemp(join(ROOT, 'work', 'review-cli-newline-tab-'));
  try {
    await mkdir(join(fixture, 'src'), { recursive: true });
    await mkdir(join(fixture, 'scripts'), { recursive: true });
    await mkdir(join(fixture, 'work'), { recursive: true });
    await copyFile(join(ROOT, 'scripts', 'create-review-manifest.mjs'), join(fixture, 'scripts', 'create-review-manifest.mjs'));
    await copyFile(join(ROOT, 'src', 'review-manifest.js'), join(fixture, 'src', 'review-manifest.js'));
    await writeFile(join(fixture, 'package.json'), JSON.stringify({ type: 'module' }));
    await execFileAsync('git', ['init'], { cwd: fixture });
    await execFileAsync('git', ['config', 'user.name', 'Test'], { cwd: fixture });
    await execFileAsync('git', ['config', 'user.email', 'test@localhost'], { cwd: fixture });
    await writeFile(join(fixture, 'src', 'baseline.js'), '// baseline\n');
    await execFileAsync('git', ['add', 'package.json', 'scripts/create-review-manifest.mjs', 'src/review-manifest.js', 'src/baseline.js'], { cwd: fixture });
    await execFileAsync('git', ['commit', '-m', 'baseline'], { cwd: fixture });
    const untrackedPath = 'src/line\nname\tpart.sol';
    await writeFile(join(fixture, untrackedPath), 'unique-marker-12345\n');
    const output = join(fixture, 'work', 'manifest.json');
    await execFileAsync(process.execPath, ['scripts/create-review-manifest.mjs', '--output', output], { cwd: fixture });
    const manifest = JSON.parse(await readFile(output, 'utf8'));
    assert.equal(manifest.changedFiles.length, 1);
    assert.equal(manifest.changedFiles[0].path, untrackedPath);
    assert.equal(manifest.changedFiles[0].status, 'added');
    assert.ok(manifest.diff.includes('unique-marker-12345'));
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
});
