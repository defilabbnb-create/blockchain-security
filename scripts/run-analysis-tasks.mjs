#!/usr/bin/env node
import { realpath, lstat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve, relative, sep, basename } from 'node:path';
import { pathToFileURL } from 'node:url';
import { TaskStateStore } from '../src/task-state.js';
import { TaskWorker } from '../src/task-worker.js';
import { ANALYSIS_ROOT, ANALYSIS_TASK_TYPE, ANALYSIS_EVIDENCE_ROOT, createLocalSourceAnalysisHandler, enqueueLocalSourceTask } from '../src/analysis-task-handler.js';
import { createResourceTaskHandlers } from '../src/resource-task-handlers.js';

export async function resolveTaskPaths(testStatePath) {
  if (testStatePath === undefined) return { statePath: join(ANALYSIS_ROOT, 'work', 'task-state.json'), evidenceRoot: ANALYSIS_EVIDENCE_ROOT };
  const candidate = resolve(testStatePath);
  if (!candidate.endsWith('.json')) throw new Error('--test-state-path requires a JSON filename');
  const parent = await realpath(resolve(candidate, '..')), temporary = await realpath(tmpdir()), child = relative(temporary, parent);
  if (!child || child === '..' || child.startsWith('..' + sep) || resolve(temporary, child) !== parent) throw new Error('--test-state-path must be inside a dedicated temporary subdirectory');
  for (const target of [join(parent, basename(candidate)), join(parent, 'analysis-task-evidence')]) {
    try { if ((await lstat(target)).isSymbolicLink()) throw new Error('--test-state-path cannot follow queue or evidence symlinks'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  return { statePath: join(parent, basename(candidate)), evidenceRoot: join(parent, 'analysis-task-evidence') };
}

function parseArguments(args) {
  const command = args[0];
  if (!['enqueue', 'drain'].includes(command)) throw new Error('usage: run-analysis-tasks.mjs enqueue --source FILE [--dependency FILE] | drain [--concurrency 1|2] [--timeout-ms N] [--test-state-path TEMP/queue.json]');
  const options = {}, allowed = new Set(['--test-state-path', ...(command === 'enqueue' ? ['--source', '--dependency'] : ['--concurrency', '--timeout-ms'])]);
  for (let index = 1; index < args.length; index += 2) {
    const key = args[index], value = args[index + 1];
    if (!allowed.has(key) || value === undefined || Object.hasOwn(options, key)) throw new Error('unknown, duplicated or valueless option: ' + key);
    options[key] = value;
  }
  if (command === 'enqueue' && !options['--source']) throw new Error('enqueue requires --source');
  return { command, options };
}

export async function runAnalysisTasks(args, { signal, onEvent = () => {}, handlerOptions = {} } = {}) {
  const { command, options } = parseArguments(args), { statePath, evidenceRoot } = await resolveTaskPaths(options['--test-state-path']);
  const store = new TaskStateStore({ path: statePath });
  if (command === 'enqueue') {
    const created = await enqueueLocalSourceTask(store, { sourcePath: options['--source'], ...(options['--dependency'] ? { dependencyPath: options['--dependency'] } : {}) }, { evidenceRoot });
    return { state: 'queued', statePath, taskId: created.task.taskId, input: created.binding };
  }
  const concurrency = Number(options['--concurrency'] ?? 1), timeoutMs = Number(options['--timeout-ms'] ?? 180_000);
  if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 2) throw new RangeError('concurrency must be 1 or 2');
  const taskIds = new Set(), errors = [];
  const handlerEvidenceRoot = handlerOptions.evidenceRoot || evidenceRoot;
  const handlers = {
    [ANALYSIS_TASK_TYPE]: createLocalSourceAnalysisHandler({ ...handlerOptions, evidenceRoot: handlerEvidenceRoot, timeoutMs }),
    ...createResourceTaskHandlers({ ...handlerOptions, evidenceRoot: handlerEvidenceRoot, timeoutMs, taskStore: store }),
  };
  const worker = new TaskWorker({ store, concurrency, heartbeatIntervalMs: 5_000, handlers, onEvent: (event) => {
    if (event.type === 'claimed') taskIds.add(event.taskId);
    if (event.type === 'error') errors.push(event.error);
    onEvent(event);
  } });
  const stop = () => { void worker.stop({ abort: true }); };
  signal?.addEventListener('abort', stop, { once: true });
  try {
    while (!signal?.aborted) {
      const { claimed } = await worker.runOnce();
      await worker.waitForIdle({ timeoutMs: Math.min(900_000, timeoutMs + 15_000) });
      if (!claimed) break;
    }
  } finally {
    signal?.removeEventListener('abort', stop);
    await worker.stop({ abort: true, wait: true, timeoutMs: 10_000 });
  }
  const tasks = await Promise.all([...taskIds].map((taskId) => store.get(taskId)));
  const pending = [];
  for (const pendingState of ['queued', 'preparing', 'running', 'checkpointing', 'cancelling']) {
    const rows = await store.list({ state: pendingState, limit: 1000 });
    pending.push(...rows.map(({ taskId, type, state, nextRetryAt }) => ({ taskId, type, state, nextRetryAt, handlerAvailable: Boolean(handlers[type]) })));
  }
  const state = signal?.aborted ? 'interrupted' : errors.length || tasks.some((task) => !['succeeded', 'partial', 'blocked'].includes(task.state)) ? 'failed' : pending.length ? 'partial' : tasks.some((task) => task.state === 'blocked') ? 'blocked' : tasks.some((task) => task.state === 'partial') ? 'partial' : 'completed';
  return { state, statePath, concurrency, consumed: tasks.length, tasks: tasks.map(({ taskId, state, attempts, checkpoint, error }) => ({ taskId, state, attempts, checkpoint, error })), pending, errors, interpretation: '仅 allowlist 内的本地处理器会执行；未注册类型仍排队并在 pending 明示。partial/blocked 代表覆盖缺口，不代表审计完成。' };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const controller = new AbortController(), stop = () => controller.abort(new Error('CLI interrupted'));
  process.once('SIGINT', stop); process.once('SIGTERM', stop);
  try {
    const result = await runAnalysisTasks(process.argv.slice(2), { signal: controller.signal, onEvent: (event) => {
      if (['claimed', 'succeeded', 'partial', 'failed', 'error'].includes(event.type)) process.stderr.write(JSON.stringify({ event: event.type, taskId: event.taskId, error: event.error }) + '\n');
    } });
    process.stdout.write(JSON.stringify(result) + '\n');
    process.exitCode = result.state === 'interrupted' ? 130 : result.state === 'failed' ? 1 : 0;
  } catch (error) { process.stderr.write(error.message + '\n'); process.exitCode = 1; }
  finally { process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop); }
}
