import { createHash, randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdir, open, readFile, realpath, stat, writeFile } from 'node:fs/promises';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

export const ANALYSIS_TASK_TYPE = 'local-source-analysis';
export const ANALYSIS_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const ANALYSIS_EVIDENCE_ROOT = join(ANALYSIS_ROOT, 'work', 'analysis-task-evidence');
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
const taskDirectory = (root, taskId) => join(root, digest(String(taskId)));
const json = (value) => JSON.stringify(value, null, 2) + '\n';

function validatePayload(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload) || Object.keys(payload).some((key) => !['sourcePath', 'dependencyPath'].includes(key))) throw new TypeError('payload only accepts sourcePath and optional dependencyPath');
  for (const key of ['sourcePath', ...(Object.hasOwn(payload, 'dependencyPath') ? ['dependencyPath'] : [])]) {
    if (typeof payload[key] !== 'string' || !payload[key] || payload[key].includes('\0') || /^[a-z][a-z0-9+.-]*:\/\//i.test(payload[key])) throw new TypeError(key + ' must be a local file path');
  }
}

async function readBundle(filename) {
  const path = await realpath(resolve(filename)), handle = await open(path, 'r');
  let bytes;
  try {
    const info = await handle.stat();
    if (!info.isFile() || info.size < 1 || info.size > 32 * 1024 * 1024) throw new Error('bundle must be a nonempty regular file no larger than 32 MiB');
    bytes = await handle.readFile();
    if (bytes.length > 32 * 1024 * 1024) throw new Error('bundle exceeds input limit');
  } finally { await handle.close(); }
  const bundle = JSON.parse(bytes.toString('utf8'));
  if (!bundle || Array.isArray(bundle) || !bundle.sources || typeof bundle.sources !== 'object' || Array.isArray(bundle.sources) || !Object.keys(bundle.sources).length || Object.values(bundle.sources).some((source) => !source || typeof source.content !== 'string')) throw new Error('verified bundle requires inlined Solidity source contents');
  const version = bundle.compilation?.compilerVersion, targets = bundle.metadata?.settings?.compilationTarget;
  if (typeof version !== 'string' || !/^0\.\d+\.\d+(?:\+[^\s]+)?$/.test(version) || bundle.compilation?.language !== 'Solidity' || !targets || typeof targets !== 'object' || Array.isArray(targets) || !Object.keys(targets).length || Object.entries(targets).some(([source, name]) => !Object.hasOwn(bundle.sources, source) || typeof name !== 'string' || !name)) throw new Error('verified bundle requires Solidity compilation metadata and explicit targets');
  if (![bundle.runtimeMatch, bundle.creationMatch, bundle.match].some((value) => ['match', 'exact_match', 'perfect'].includes(value))) throw new Error('bundle lacks a recognized recorded verification match');
  return { path, bytes, sha256: digest(bytes), version: version.split('+')[0] };
}

async function assertOfflineCompiler(root, version) {
  const suffix = { '0.8.19': '0819', '0.8.23': '0823', '0.8.28': '0828' }[version];
  if (suffix) {
    if (!(await stat(join(root, 'flare-scan', 'tools', 'solc-' + suffix, 'node_modules', 'solc', 'soljson.js'))).isFile()) throw new Error('local compiler is not a regular file');
    return;
  }
  // The analyzer can download a missing compiler; this consumer requires a prewarmed cache.
  const cache = join(root, 'work', 'compiler-cache'), index = JSON.parse(await readFile(join(cache, 'list.json'), 'utf8'));
  const filename = index.releases?.[version];
  if (typeof filename !== 'string' || !/^soljson-[a-zA-Z0-9.+-]+\.js$/.test(filename)) throw new Error('compiler absent from local catalog');
  const entry = index.builds?.find((build) => build.path === filename), bytes = await readFile(join(cache, filename.replace(/\.js$/, '.cjs')));
  if (!entry?.sha256 || '0x' + digest(bytes) !== entry.sha256) throw new Error('cached compiler checksum mismatch');
}

/** Freeze enqueue-time inputs. Payload contains local paths, never executable commands. */
export async function enqueueLocalSourceTask(store, payload, { evidenceRoot = ANALYSIS_EVIDENCE_ROOT, taskId = randomUUID(), maxAttempts = 3 } = {}) {
  validatePayload(payload);
  const source = await readBundle(payload.sourcePath), dependency = payload.dependencyPath ? await readBundle(payload.dependencyPath) : null;
  await mkdir(evidenceRoot, { recursive: true });
  const directory = taskDirectory(evidenceRoot, taskId);
  await mkdir(directory);
  const sourcePath = join(directory, 'source-input.json'), dependencyPath = dependency ? join(directory, 'dependency-input.json') : null;
  await writeFile(sourcePath, source.bytes, { flag: 'wx', mode: 0o400 });
  if (dependency) await writeFile(dependencyPath, dependency.bytes, { flag: 'wx', mode: 0o400 });
  const binding = { schemaVersion: 1, taskId, sourcePath, sourceSha256: source.sha256, originalSourcePath: source.path, dependencyPath, dependencySha256: dependency?.sha256 ?? null, originalDependencyPath: dependency?.path ?? null, verificationScope: 'Recorded bundle provenance only; no live deployment equivalence verification.' };
  await writeFile(join(directory, 'input-binding.json'), json(binding), { flag: 'wx', mode: 0o400 });
  const task = await store.create({ taskId, type: ANALYSIS_TASK_TYPE, payload: { sourcePath, ...(dependencyPath ? { dependencyPath } : {}) }, maxAttempts });
  return { task, binding };
}

/** Task completion is not a safety verdict. Unknown or missing states never succeed. */
export function classifyAnalysis(report, execution = {}) {
  if (execution.timedOut || execution.aborted || execution.signal || execution.exitCode !== 0) return { status: 'failed', reason: execution.timedOut ? 'analysis timeout' : execution.aborted ? 'analysis aborted' : 'analysis process failed' };
  if (!report || typeof report !== 'object' || Array.isArray(report) || !['completed', 'partial', 'failed', 'unavailable'].includes(report.state)) return { status: 'failed', reason: 'invalid or unknown analysis state' };
  if (report.state === 'failed' || report.localTests?.state === 'failed') return { status: 'failed', reason: report.error || 'static or dynamic analysis failed' };
  const dynamicState = report.localTests?.state;
  if (!['passed', 'not_performed', 'unavailable'].includes(dynamicState)) return { status: 'failed', reason: 'missing or unknown dynamic analysis state' };
  if (dynamicState === 'passed') {
    const local = report.localTests;
    if (!Number.isSafeInteger(local.tests) || local.tests < 1 || !Number.isSafeInteger(local.passed) || local.passed < 0 || !Number.isSafeInteger(local.failed) || local.failed < 0 || !Array.isArray(local.results) || local.results.length !== local.tests || local.passed + local.failed !== local.tests || local.results.some((row) => !row || !['passed', 'failed'].includes(row.state)) || local.results.filter((row) => row.state === 'passed').length !== local.passed || local.results.filter((row) => row.state === 'failed').length !== local.failed || local.failed !== 0) return { status: 'failed', reason: 'inconsistent or empty dynamic test evidence' };
  }
  if (report.state === 'unavailable') return { status: 'partial', reason: 'analysis unavailable' };
  if (!report.staticStages || ['compile', 'detectors', 'callGraph'].some((stage) => !['completed', 'partial', 'failed', 'not_run'].includes(report.staticStages[stage])) || Object.values(report.staticStages).some((state) => !['completed', 'partial', 'failed', 'not_run'].includes(state))) return { status: 'failed', reason: 'missing or unknown static stage state' };
  if (Object.values(report.staticStages).some((state) => state === 'failed')) return { status: 'failed', reason: 'a static stage failed' };
  if (!Number.isSafeInteger(report.contracts) || report.contracts < 1 || !Number.isSafeInteger(report.detectors) || report.detectors < 1 || !Number.isSafeInteger(report.findingCount) || report.findingCount < 0 || !Array.isArray(report.findings) || report.findings.length !== report.findingCount) return { status: 'failed', reason: 'invalid static analysis counts or finding evidence' };
  if (report.state === 'partial' || dynamicState !== 'passed' || ['compile', 'detectors', 'callGraph'].some((stage) => report.staticStages[stage] !== 'completed')) return { status: 'partial', reason: 'incomplete stages or dynamic checks' };
  if (!['planned', 'partial', 'unavailable'].includes(report.discoveryPlan?.state)) return { status: 'failed', reason: 'missing or unknown discovery plan state' };
  if (report.discoveryPlan.state !== 'planned') return { status: 'partial', reason: 'discovery plan unavailable or incomplete' };
  return { status: 'succeeded', reason: 'local stages completed; not a contract safety verdict' };
}

export async function runFixedAnalysis({ root = ANALYSIS_ROOT, sourcePath, dependencyPath, stdoutPath, stderrPath, signal, timeoutMs = 180_000, killGraceMs = 500, spawnProcess = spawn, killGroup = (pid, sig) => process.kill(-pid, sig) }) {
  const stdout = await open(stdoutPath, 'wx', 0o600);
  let stderr;
  try { stderr = await open(stderrPath, 'wx', 0o600); } catch (error) { await stdout.close(); throw error; }
  let child, timer, killTimer, aborted = false, timedOut = false, spawnError = null;
  const startedAt = new Date().toISOString();
  const kill = (sig) => { if (child?.pid) try { killGroup(child.pid, sig); } catch (error) { if (error.code !== 'ESRCH') spawnError ??= error; } };
  const terminate = () => { kill('SIGTERM'); killTimer ??= setTimeout(() => kill('SIGKILL'), killGraceMs); };
  const abort = () => { aborted = true; terminate(); };
  try {
    if (signal?.aborted) return { exitCode: null, signal: null, aborted: true, timedOut: false, startedAt, endedAt: new Date().toISOString() };
    const env = { ...process.env, PYTHONHASHSEED: '0' };
    delete env.SOLC_VERSION; delete env.CAMPAIGN_SOLJSON;
    child = spawnProcess('python3', [join(root, 'scripts', 'review-static.py'), sourcePath, ...(dependencyPath ? [dependencyPath] : [])], { cwd: root, env, shell: false, detached: true, stdio: ['ignore', stdout.fd, stderr.fd] });
    signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted) abort();
    timer = setTimeout(() => { timedOut = true; terminate(); }, timeoutMs);
    const closed = await new Promise((resolveClose) => {
      child.once('error', (error) => { spawnError = error; });
      child.once('close', (exitCode, exitSignal) => resolveClose({ exitCode, signal: exitSignal }));
    });
    // Kill descendants too when a cooperative parent exits before its child processes.
    if (aborted || timedOut) kill('SIGKILL');
    if (spawnError) throw spawnError;
    return { ...closed, aborted, timedOut, startedAt, endedAt: new Date().toISOString() };
  } finally {
    clearTimeout(timer); clearTimeout(killTimer); signal?.removeEventListener('abort', abort);
    await Promise.all([stdout.close(), stderr.close()]);
  }
}

export function createLocalSourceAnalysisHandler({ root = ANALYSIS_ROOT, evidenceRoot = ANALYSIS_EVIDENCE_ROOT, timeoutMs = 180_000, killGraceMs = 500, runner = runFixedAnalysis } = {}) {
  if (!Number.isInteger(timeoutMs) || timeoutMs < 10 || timeoutMs > 900_000) throw new RangeError('analysis timeout must be 10..900000 ms');
  return async (payload, context) => {
    let attemptDirectory = null, checkpoint = null;
    try {
      validatePayload(payload);
      if (context.task.type !== ANALYSIS_TASK_TYPE) throw new Error('unsupported analysis task type');
      const directory = taskDirectory(evidenceRoot, context.task.taskId), bindingBytes = await readFile(join(directory, 'input-binding.json')), binding = JSON.parse(bindingBytes.toString('utf8'));
      if (binding.taskId !== context.task.taskId || binding.sourcePath !== payload.sourcePath || (binding.dependencyPath ?? null) !== (payload.dependencyPath ?? null)) throw new Error('task input differs from enqueue-time binding');
      const source = await readBundle(payload.sourcePath), dependency = payload.dependencyPath ? await readBundle(payload.dependencyPath) : null;
      const input = { sourceSha256: source.sha256, dependencySha256: dependency?.sha256 ?? null, bindingSha256: digest(bindingBytes) };
      if (source.sha256 !== binding.sourceSha256 || input.dependencySha256 !== binding.dependencySha256) throw new Error('input hash changed since enqueue');
      const previous = context.lastCheckpoint?.input;
      if (previous && Object.keys(input).some((key) => input[key] !== previous[key])) throw new Error('input differs from previous attempt checkpoint');
      await assertOfflineCompiler(root, source.version);
      if (dependency) await assertOfflineCompiler(root, dependency.version);
      attemptDirectory = join(directory, 'attempt-' + context.task.attempts + '-' + randomUUID());
      await mkdir(attemptDirectory);
      const stagedSource = join(attemptDirectory, 'verified-source.json'), stagedDependency = dependency ? join(attemptDirectory, 'verified-dependency.json') : null;
      await writeFile(stagedSource, source.bytes, { flag: 'wx', mode: 0o400 });
      if (dependency) await writeFile(stagedDependency, dependency.bytes, { flag: 'wx', mode: 0o400 });
      checkpoint = { schemaVersion: 1, phase: 'input_validated', input, attempt: context.task.attempts, attemptDirectory, reportPath: join(attemptDirectory, 'static-analysis.json'), stderrPath: join(attemptDirectory, 'stderr.log'), sourcePath: stagedSource, dependencyPath: stagedDependency };
      await context.checkpoint(checkpoint);
      const execution = await runner({ root, sourcePath: stagedSource, dependencyPath: stagedDependency, stdoutPath: checkpoint.reportPath, stderrPath: checkpoint.stderrPath, signal: context.signal, timeoutMs, killGraceMs });
      let report = null, parseError = null, reportBytes = null, reportSha256 = null;
      try {
        if ((await stat(checkpoint.reportPath)).size > 64 * 1024 * 1024) throw new Error('analysis output exceeds parsing limit');
        const bytes = await readFile(checkpoint.reportPath);
        if (bytes.length > 64 * 1024 * 1024) throw new Error('analysis output exceeds parsing limit');
        reportBytes = bytes.length;
        reportSha256 = digest(bytes);
        report = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
      } catch (error) { parseError = error.message; }
      const outcome = classifyAnalysis(report, execution);
      if (parseError) { outcome.status = 'failed'; outcome.reason = 'invalid analysis JSON: ' + parseError; }
      checkpoint = { ...checkpoint, phase: 'evidence_ready', execution, outcome: outcome.status, reportBytes, reportSha256 };
      const result = { ...checkpoint, staticState: report?.state ?? null, dynamicState: report?.localTests?.state ?? null, findingCount: report?.findingCount ?? null, companionEvidenceDirectory: attemptDirectory, confirmedVulnerabilities: 0, interpretation: 'Task outcome only; findings and local tests do not prove exploitability or safety.' };
      await writeFile(join(attemptDirectory, 'run-summary.json'), json({ ...outcome, result }), { flag: 'wx', mode: 0o600 });
      if (!context.signal.aborted) await context.checkpoint(checkpoint);
      return { ...outcome, result, checkpoint, retryable: false, ...(outcome.status === 'failed' ? { error: outcome.reason } : {}) };
    } catch (error) {
      const outcome = { status: 'failed', error: error.message, retryable: false, ...(checkpoint ? { checkpoint } : {}) };
      if (attemptDirectory) await writeFile(join(attemptDirectory, 'handler-error.json'), json({ ...outcome, aborted: context.signal.aborted }), { flag: 'wx', mode: 0o600 }).catch(() => {});
      return outcome;
    }
  };
}
