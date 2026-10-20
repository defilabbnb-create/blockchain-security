import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, writeFile, chmod, rm, stat, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { TaskStateStore } from '../src/task-state.js';
import { TaskWorker } from '../src/task-worker.js';
import { ANALYSIS_TASK_TYPE, ANALYSIS_ROOT, enqueueLocalSourceTask, createLocalSourceAnalysisHandler, classifyAnalysis, runFixedAnalysis } from '../src/analysis-task-handler.js';
import { resolveTaskPaths, runAnalysisTasks } from '../scripts/run-analysis-tasks.mjs';

const bundle = () => ({ runtimeMatch: 'match', compilation: { language: 'Solidity', compilerVersion: '0.8.28+commit.7893614a' }, metadata: { settings: { compilationTarget: { 'C.sol': 'C' } } }, sources: { 'C.sol': { content: 'pragma solidity 0.8.28; contract C {}' } } });
const completed = () => ({ state: 'completed', staticStages: { compile: 'completed', detectors: 'completed', callGraph: 'completed' }, localTests: { state: 'passed', tests: 1, passed: 1, failed: 0, results: [{ id: 'fixture-property', state: 'passed' }] }, contracts: 1, detectors: 100, findingCount: 0, findings: [], discoveryPlan: { state: 'planned' } });

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), 'local-analysis-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const sourcePath = join(directory, 'source with spaces;not-a-command.json'), evidenceRoot = join(directory, 'evidence');
  await writeFile(sourcePath, JSON.stringify(bundle()));
  const store = new TaskStateStore({ path: join(directory, 'queue.json') });
  return { directory, sourcePath, evidenceRoot, store };
}

const writeReport = (report, execution = { exitCode: 0, signal: null, aborted: false, timedOut: false }) => async ({ stdoutPath, stderrPath }) => {
  await writeFile(stdoutPath, JSON.stringify(report), { flag: 'wx' });
  await writeFile(stderrPath, '', { flag: 'wx' });
  return execution;
};

test('stage mapping rejects unknown states and never succeeds on missing dynamic coverage', () => {
  assert.equal(classifyAnalysis(completed(), { exitCode: 0 }).status, 'succeeded');
  for (const state of ['failed', 'unavailable', 'not_performed', 'garbage', undefined]) {
    const report = completed(); report.localTests.state = state;
    assert.notEqual(classifyAnalysis(report, { exitCode: 0 }).status, 'succeeded');
  }
  for (const state of ['failed', 'partial', 'unavailable', 'succeeded', undefined]) {
    const report = completed(); report.state = state;
    assert.notEqual(classifyAnalysis(report, { exitCode: 0 }).status, 'succeeded');
  }
  for (const execution of [{ exitCode: 1 }, { exitCode: 0, timedOut: true }, { exitCode: 0, aborted: true }, { exitCode: 0, signal: 'SIGTERM' }, {}]) assert.equal(classifyAnalysis(completed(), execution).status, 'failed');
  const failedStage = completed(); failedStage.staticStages.detectors = 'failed'; failedStage.state = 'partial';
  assert.equal(classifyAnalysis(failedStage, { exitCode: 0 }).status, 'failed');
  for (const patch of [{ tests: 0, passed: 0, results: [] }, { results: undefined }, { tests: 2 }, { passed: 0 }, { failed: 1 }, { tests: '1' }, { results: [{ state: 'failed' }] }]) {
    const report = completed(); Object.assign(report.localTests, patch);
    assert.equal(classifyAnalysis(report, { exitCode: 0 }).status, 'failed');
  }
  for (const field of ['contracts', 'detectors', 'findingCount']) {
    for (const value of [-1, 1.5, '1', undefined]) { const report = completed(); report[field] = value; assert.equal(classifyAnalysis(report, { exitCode: 0 }).status, 'failed'); }
  }
  for (const state of ['unavailable', 'partial']) { const report = completed(); report.discoveryPlan.state = state; assert.equal(classifyAnalysis(report, { exitCode: 0 }).status, 'partial'); }
  const unknown = completed(); unknown.staticStages.callGraph = 'ok'; assert.equal(classifyAnalysis(unknown, { exitCode: 0 }).status, 'failed');
});

test('enqueue binds an immutable input snapshot, worker persists evidence and a terminal outcome', { timeout: 10_000 }, async (t) => {
  const f = await fixture(t), { task, binding } = await enqueueLocalSourceTask(f.store, { sourcePath: f.sourcePath }, { evidenceRoot: f.evidenceRoot });
  assert.deepEqual(Object.keys(task.payload), ['sourcePath']);
  await writeFile(f.sourcePath, 'original input can change without altering frozen task');
  const worker = new TaskWorker({ store: f.store, handlers: { [ANALYSIS_TASK_TYPE]: createLocalSourceAnalysisHandler({ evidenceRoot: f.evidenceRoot, runner: writeReport(completed()) }) } });
  await worker.runOnce(); await worker.waitForIdle();
  const finished = await f.store.get(task.taskId);
  assert.equal(finished.state, 'succeeded');
  assert.equal(finished.checkpoint.input.sourceSha256, binding.sourceSha256);
  assert.equal(finished.checkpoint.phase, 'evidence_ready');
  const reportBytes = await readFile(finished.checkpoint.reportPath);
  assert.equal(finished.checkpoint.reportBytes, reportBytes.length);
  assert.equal(finished.checkpoint.reportSha256, createHash('sha256').update(reportBytes).digest('hex'));
  assert.ok(reportBytes.length > 0);
  assert.equal(JSON.parse(await readFile(join(finished.checkpoint.attemptDirectory, 'run-summary.json'), 'utf8')).result.dynamicState, 'passed');
  assert.equal(finished.lease, null);
});

test('analysis handler fails malformed UTF-8 output instead of classifying replacement characters', async (t) => {
  const f = await fixture(t);
  const { task } = await enqueueLocalSourceTask(f.store, { sourcePath: f.sourcePath }, { evidenceRoot: f.evidenceRoot });
  const invalidBytes = Buffer.from([0x7b, 0x22, 0x73, 0x74, 0x61, 0x74, 0x65, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d]);
  const handler = createLocalSourceAnalysisHandler({
    evidenceRoot: f.evidenceRoot,
    runner: async ({ stdoutPath, stderrPath }) => {
      await writeFile(stdoutPath, invalidBytes, { flag: 'wx' });
      await writeFile(stderrPath, '', { flag: 'wx' });
      return { exitCode: 0, signal: null, aborted: false, timedOut: false };
    },
  });
  const result = await handler(task.payload, {
    task: { ...task, attempts: 1 },
    lastCheckpoint: null,
    signal: new AbortController().signal,
    checkpoint: async () => {},
  });
  assert.equal(result.status, 'failed');
  assert.match(result.reason, /invalid analysis JSON/);
  assert.equal(result.checkpoint.reportBytes, invalidBytes.length);
  assert.match(result.checkpoint.reportSha256, /^[a-f0-9]{64}$/);
});

test('payload allowlist and provenance validation prevent arbitrary execution', async (t) => {
  const f = await fixture(t);
  await assert.rejects(enqueueLocalSourceTask(f.store, { sourcePath: f.sourcePath, command: 'touch /tmp/forbidden' }, { evidenceRoot: f.evidenceRoot }), /only accepts/);
  await assert.rejects(enqueueLocalSourceTask(f.store, { sourcePath: 'https://example.invalid/C.json' }, { evidenceRoot: f.evidenceRoot }), /local file/);
  const bad = bundle(); delete bad.runtimeMatch;
  await writeFile(f.sourcePath, JSON.stringify(bad));
  await assert.rejects(enqueueLocalSourceTask(f.store, { sourcePath: f.sourcePath }, { evidenceRoot: f.evidenceRoot }), /verification match/);
});

test('recovery checks input hashes and creates a new exclusive attempt instead of reusing old output', { timeout: 10_000 }, async (t) => {
  const f = await fixture(t), { task } = await enqueueLocalSourceTask(f.store, { sourcePath: f.sourcePath }, { evidenceRoot: f.evidenceRoot });
  let saved = null, runs = 0;
  const handler = createLocalSourceAnalysisHandler({ evidenceRoot: f.evidenceRoot, runner: async (options) => { runs++; return writeReport(completed())(options); } });
  const context = { task: { ...task, attempts: 1 }, lastCheckpoint: null, signal: new AbortController().signal, checkpoint: async (value) => { saved = value; } };
  const first = await handler(task.payload, context);
  assert.equal(first.status, 'succeeded');
  const second = await handler(task.payload, { ...context, task: { ...task, attempts: 2 }, lastCheckpoint: saved });
  assert.equal(second.status, 'succeeded');
  assert.notEqual(first.checkpoint.attemptDirectory, second.checkpoint.attemptDirectory);
  assert.equal(runs, 2);
  await chmod(task.payload.sourcePath, 0o600);
  const changed = bundle(); changed.sources['C.sol'].content += '\n// changed';
  await writeFile(task.payload.sourcePath, JSON.stringify(changed));
  const tampered = await handler(task.payload, { ...context, task: { ...task, attempts: 3 }, lastCheckpoint: saved });
  assert.equal(tampered.status, 'failed'); assert.match(tampered.error, /hash changed/); assert.equal(runs, 2);
});

test('worker maps dynamic failure to failed and unavailable checks to partial', { timeout: 10_000 }, async (t) => {
  const f = await fixture(t);
  for (const dynamicState of ['failed', 'unavailable', 'unrecognized']) {
    const { task } = await enqueueLocalSourceTask(f.store, { sourcePath: f.sourcePath }, { evidenceRoot: f.evidenceRoot });
    const report = completed(); report.localTests.state = dynamicState;
    const worker = new TaskWorker({ store: f.store, handlers: { [ANALYSIS_TASK_TYPE]: createLocalSourceAnalysisHandler({ evidenceRoot: f.evidenceRoot, runner: writeReport(report) }) } });
    await worker.runOnce(); await worker.waitForIdle();
    assert.equal((await f.store.get(task.taskId)).state, dynamicState === 'unavailable' ? 'partial' : 'failed');
  }
});

test('fixed runner uses argv without a shell and records stdout separately', { timeout: 10_000 }, async (t) => {
  const f = await fixture(t), pythonRoot = join(f.directory, 'fake-project');
  await mkdir(join(pythonRoot, 'scripts'), { recursive: true });
  await writeFile(join(pythonRoot, 'scripts', 'review-static.py'), 'import json, sys\nprint(json.dumps({"args":sys.argv[1:]}))\nprint("diagnostic",file=sys.stderr)\n');
  let observed;
  const result = await runFixedAnalysis({ root: pythonRoot, sourcePath: f.sourcePath, stdoutPath: join(f.directory, 'stdout.json'), stderrPath: join(f.directory, 'stderr.log'), timeoutMs: 5_000, spawnProcess: (command, args, options) => { observed = { command, args, options }; return spawn(command, args, options); } });
  assert.equal(result.exitCode, 0); assert.equal(observed.command, 'python3'); assert.equal(observed.options.shell, false); assert.equal(observed.options.detached, true);
  assert.equal(observed.args[0], join(pythonRoot, 'scripts', 'review-static.py'));
  assert.deepEqual(JSON.parse(await readFile(join(f.directory, 'stdout.json'), 'utf8')).args, [f.sourcePath]);
  assert.match(await readFile(join(f.directory, 'stderr.log'), 'utf8'), /diagnostic/);
});

test('timeout and abort terminate the spawned process group including descendants', { timeout: 15_000 }, async (t) => {
  const f = await fixture(t), pythonRoot = join(f.directory, 'fake-project');
  await mkdir(join(pythonRoot, 'scripts'), { recursive: true });
  const childCode = 'import subprocess,sys,signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); p=subprocess.Popen([sys.executable,"-c","import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(30)"]); print(p.pid,flush=True); time.sleep(30)';
  await writeFile(join(pythonRoot, 'scripts', 'review-static.py'), 'import subprocess, sys, time\np=subprocess.Popen([sys.executable,"-c",' + JSON.stringify(childCode) + '])\nprint(p.pid,flush=True)\ntime.sleep(30)\n');
  for (const mode of ['timeout', 'abort']) {
    const controller = new AbortController(), output = join(f.directory, mode + '.log');
    const timer = mode === 'abort' ? setTimeout(() => controller.abort(), 200) : null;
    const result = await runFixedAnalysis({ root: pythonRoot, sourcePath: f.sourcePath, stdoutPath: output, stderrPath: join(f.directory, mode + '-stderr.log'), signal: controller.signal, timeoutMs: mode === 'timeout' ? 200 : 5_000, killGraceMs: 40 });
    clearTimeout(timer);
    assert.equal(result[mode === 'timeout' ? 'timedOut' : 'aborted'], true);
    const descendantPids = (await readFile(output, 'utf8')).trim().split(/\s+/).map(Number);
    assert.equal(descendantPids.length, 2, 'expected a real child and grandchild');
    for (const childPid of descendantPids) {
      assert.ok(Number.isInteger(childPid) && childPid > 1);
      let alive = true;
      for (let i = 0; i < 40 && alive; i++) { try { process.kill(childPid, 0); await new Promise((resolve) => setTimeout(resolve, 20)); } catch (error) { if (error.code === 'ESRCH') alive = false; else throw error; } }
      assert.equal(alive, false, 'spawned descendant remains alive');
    }
  }
});

test('CLI test path is confined to a dedicated temp directory and concurrency is bounded', async (t) => {
  const f = await fixture(t);
  await assert.rejects(resolveTaskPaths(join(ANALYSIS_ROOT, 'work', 'not-test.json')), /temporary subdirectory/);
  await assert.rejects(resolveTaskPaths(join(tmpdir(), 'not-dedicated.json')), /temporary subdirectory/);
  const paths = await resolveTaskPaths(join(f.directory, 'queue.json'));
  assert.equal(paths.statePath, join(await import('node:fs/promises').then(({ realpath }) => realpath(f.directory)), 'queue.json'));
  await assert.rejects(runAnalysisTasks(['drain', '--test-state-path', join(f.directory, 'queue.json'), '--concurrency', '3']), /concurrency/);
  await assert.rejects(runAnalysisTasks(['enqueue', '--source', f.sourcePath, '--script', '/tmp/arbitrary']), /unknown/);
  await symlink(join(ANALYSIS_ROOT, 'work', 'analysis-tasks.json'), join(f.directory, 'linked.json'));
  await assert.rejects(resolveTaskPaths(join(f.directory, 'linked.json')), /symlinks/);
});

test('CLI enqueue and drain consume only the allowlisted type through TaskWorker', { timeout: 10_000 }, async (t) => {
  const f = await fixture(t), statePath = join(f.directory, 'cli-queue.json');
  const created = await runAnalysisTasks(['enqueue', '--source', f.sourcePath, '--test-state-path', statePath]);
  const store = new TaskStateStore({ path: created.statePath });
  await store.create({ type: 'arbitrary-command', payload: { command: 'must not run' } });
  const drained = await runAnalysisTasks(['drain', '--test-state-path', statePath, '--concurrency', '2'], { handlerOptions: { runner: writeReport(completed()) } });
  assert.equal(drained.state, 'partial'); assert.equal(drained.consumed, 1); assert.equal(drained.tasks[0].state, 'succeeded');
  assert.deepEqual(drained.pending.map(({ type }) => type), ['arbitrary-command']);
  assert.equal((await store.list({ state: 'queued' })).length, 1);
});
