import { createServer } from 'node:http';
import { constants as fsConstants } from 'node:fs';
import { lstat, open, readFile, realpath, readdir, statfs } from 'node:fs/promises';
import { loadavg } from 'node:os';
import { basename, extname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, randomUUID } from 'node:crypto';
import { answerQuestion, buildSnapshot, PROJECT_ROOT } from './status-store.js';
import { boundedSingleFlight } from './bounded-work.js';
import { runtimeFingerprint } from './runtime-fingerprint.js';
import { TaskStateStore } from './task-state.js';
import { TaskWorker } from './task-worker.js';
import { ANALYSIS_EVIDENCE_ROOT, ANALYSIS_TASK_TYPE } from './analysis-task-handler.js';
import { createResourceTaskHandlers } from './resource-task-handlers.js';
import { evaluateMergeGate, REVIEW_SEVERITIES } from './review-manifest.js';
import { createResourceApiV1 } from './resource-api-projects.js';
import { handleAnalysisResource } from './resource-api-analysis.js';
import { ResourceApiOperations, resourceErrorBody, resourceEnvelope, parseResourcePageQuery } from './resource-api-operations.js';
import {
  TaskApiV1Error,
  parseExpectedRevision,
  parseTaskPageQuery,
  taskConsistency,
  taskEnvelope,
  taskErrorBody,
} from './task-api-v1.js';
import { CorpusControlPlane, corpusErrorBody, isChainCollectionStart } from './corpus-control.js';

const WEB_ROOT = join(PROJECT_ROOT, 'web');
const loopback = new Set(['localhost', '127.0.0.1', '[::1]']);
const mime = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml' };
const assets = new Set(['/', '/index.html', '/styles.css', '/app.js', '/lib/api.js', '/lib/format.js', '/lib/severity.js', '/views/overview.js', '/views/protocol.js', '/views/finding.js', '/views/execution.js', '/views/corpus.js']);
const securityHeaders = {
  'cache-control': 'no-store', 'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'content-security-policy': "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
};
const ANALYSIS_REPORT_MAX_BYTES = 64 * 1024 * 1024;
const REVERSE_TEXT_ARTIFACT_MAX_BYTES = 4 * 1024 * 1024;
const PROJECT_MANIFEST_MAX_BYTES = 64 * 1024 * 1024;
const SOURCE_FILE_EXTENSIONS = new Set(['.sol', '.vy', '.vyi', '.yul']);
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SSE_HISTORY_LIMIT = 128;
const COLLECTION_WORKER_TASK_TYPE = 'v1-resource-collection';
const API_V1_CAPABILITIES = Object.freeze({
  // `state` describes the HTTP surface; `executionState` describes the
  // currently registered worker implementation for that capability.
  tasks: { state: 'available', executionState: 'available', path: '/api/v1/tasks' },
  reviews: { state: 'available', executionState: 'available', path: '/api/v1/reviews/evaluate' },
  health: { state: 'available', executionState: 'available', path: '/api/v1/health' },
  projects: { state: 'available', executionState: 'available', path: '/api/v1/projects' },
  contracts: {
    state: 'available', executionState: 'available', readState: 'available', path: '/api/v1/contracts',
    limitation: '可将完整导入的源码文件关联到链和地址；关联由用户提供，尚未验证部署代码与源码匹配',
  },
  collection: {
    state: 'available', executionState: 'available', path: '/api/v1/collection',
    limitation: '只读采集 worker 支持显式 RPC、有限固定区块范围和哈希锚定；生产入口默认持续消费，嵌入式测试可显式关闭；遇重组会 fail-closed',
  },
  bytecode: { state: 'available', executionState: 'available', path: '/api/v1/bytecode' },
  decompile: { state: 'available', executionState: 'available', path: '/api/v1/decompile' },
  analysis: { state: 'available', executionState: 'available', path: '/api/v1/analysis' },
  scans: { state: 'available', executionState: 'available', path: '/api/v1/scans' },
  workers: { state: 'available', executionState: 'available', path: '/api/v1/workers' },
  findings: { state: 'available', executionState: 'available', path: '/api/v1/findings' },
  evidence: { state: 'available', executionState: 'available', path: '/api/v1/evidence' },
  replay: { state: 'available', executionState: 'available', path: '/api/v1/replay' },
  rules: { state: 'available', executionState: 'available', path: '/api/v1/rules' },
  invariants: { state: 'available', executionState: 'available', path: '/api/v1/invariants' },
  reports: { state: 'available', executionState: 'available', path: '/api/v1/reports', formats: ['json', 'sarif', 'html'], formatQuery: 'format' },
  corpus: {
    state: 'available', executionState: 'available', path: '/api/v1/corpus/overview',
    limitation: '只做离线语料任务控制；链上采集启动请求由后端拒绝，不在本阶段开放。',
  },
});

function sendJson(response, status, value) {
  if (response.destroyed || response.writableEnded) return;
  response.writeHead(status, { ...securityHeaders, 'content-type': 'application/json; charset=utf-8' });
  response.end(JSON.stringify(value));
}

function sendRaw(response, result) {
  if (response.destroyed || response.writableEnded) return;
  const raw = result?.raw || {};
  const body = Buffer.from(String(raw.body ?? ''), 'utf8');
  const safeTaskId = typeof raw.taskId === 'string' && /^[a-zA-Z0-9._-]{1,120}$/.test(raw.taskId) ? raw.taskId : null;
  response.writeHead(result.status || 200, {
    ...securityHeaders,
    'content-type': raw.contentType || 'application/octet-stream',
    'content-length': String(body.length),
    ...(raw.contentDisposition ? { 'content-disposition': raw.contentDisposition } : {}),
    ...(raw.sourceSha256 ? { 'x-source-report-sha256': raw.sourceSha256 } : {}),
    ...(safeTaskId ? { 'x-report-task-id': safeTaskId } : {}),
  });
  response.end(body);
}
async function parseBody(request, maxBytes = 16 * 1024) {
  if (!String(request.headers['content-type'] || '').startsWith('application/json')) throw Object.assign(new Error('需要 application/json'), { status: 415 });
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > maxBytes) throw Object.assign(new Error('请求过大'), { status: 413 });
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch { throw Object.assign(new Error('JSON 格式无效'), { status: 400 }); }
}

function taskBody(body, allowed, required = []) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw Object.assign(new Error('任务请求必须是 JSON 对象'), { status: 400 });
  const unknown = Object.keys(body).filter((key) => !allowed.includes(key));
  if (unknown.length) throw Object.assign(new Error(`任务请求包含未知字段：${unknown.join(', ')}`), { status: 400 });
  for (const key of required) if (!(key in body)) throw Object.assign(new Error(`缺少任务字段：${key}`), { status: 400 });
  return body;
}

function taskString(value, name, { optional = false, max = 300 } = {}) {
  if (value === undefined && optional) return undefined;
  if (typeof value !== 'string' || !value.trim() || value.length > max) throw Object.assign(new Error(`${name} 必须是 1-${max} 个字符`), { status: 400 });
  return value.trim();
}

function taskInteger(value, name, { optional = false, min = -Infinity, max = Infinity } = {}) {
  if (value === undefined && optional) return undefined;
  if (!Number.isInteger(value) || value < min || value > max) throw Object.assign(new Error(`${name} 必须是 ${min}..${max} 的整数`), { status: 400 });
  return value;
}

function classifyTaskError(error) {
  if (error?.status) return error;
  const message = String(error?.message || '');
  if (/task not found/i.test(message)) error.status = 404;
  else if (/already exists/i.test(message)) error.status = 409;
  else if (/lease|transition|task .*owned|cannot|must be|invalid|unknown task state|expected schema/i.test(message)) error.status = 400;
  return error;
}

async function taskRoute(store, pathname, method, body) {
  const match = pathname.match(/^\/api\/tasks(?:\/([^/]+)(?:\/(transition|claim|heartbeat|checkpoint|fail|cancel|resume|pause))?)?$/);
  if (!match) return null;
  if (!store) throw Object.assign(new Error('持久化任务状态未启用'), { status: 503 });
  let taskId = null;
  try { taskId = match[1] ? decodeURIComponent(match[1]) : null; }
  catch { throw Object.assign(new Error('任务 ID 编码无效'), { status: 400 }); }
  const action = match[2] || null;
  if (!taskId && action) throw Object.assign(new Error('任务 ID 缺失'), { status: 400 });
  if (!taskId && method === 'GET') return { tasks: await store.list() };
  if (!taskId && method === 'POST') {
    const input = taskBody(body, ['taskId', 'type', 'payload', 'priority', 'maxAttempts'], ['type']);
    const type = taskString(input.type, 'type', { max: 120 });
    const taskIdValue = input.taskId === undefined ? undefined : taskString(input.taskId, 'taskId', { max: 120 });
    const priority = taskInteger(input.priority === undefined ? 0 : input.priority, 'priority');
    const maxAttempts = taskInteger(input.maxAttempts === undefined ? 3 : input.maxAttempts, 'maxAttempts', { min: 1, max: 100 });
    return { task: await store.create({ taskId: taskIdValue, type, payload: input.payload === undefined ? {} : input.payload, priority, maxAttempts }) };
  }
  if (!taskId) throw Object.assign(new Error('任务路径或方法不支持'), { status: 405 });
  if (!action && method === 'GET') {
    const task = await store.get(taskId);
    if (!task) throw Object.assign(new Error(`task not found: ${taskId}`), { status: 404 });
    return { task };
  }
  if (!action) throw Object.assign(new Error('任务读取只支持 GET'), { status: 405 });
  if (method !== 'POST') throw Object.assign(new Error('任务接口只支持 POST'), { status: 405 });
  if (action === null) {
    const task = await store.get(taskId);
    if (!task) throw Object.assign(new Error(`task not found: ${taskId}`), { status: 404 });
    return { task };
  }
  if (action === 'transition') {
    const input = taskBody(body, ['state', 'reason', 'details', 'workerId', 'fencingToken'], ['state']);
    const state = taskString(input.state, 'state', { max: 40 });
    const reason = input.reason === undefined ? '' : taskString(input.reason, 'reason');
    const current = await store.get(taskId);
    if (!current) throw Object.assign(new Error(`task not found: ${taskId}`), { status: 404 });
    if (['preparing', 'running', 'checkpointing', 'cancelling'].includes(current.state)) {
      const workerId = taskString(input.workerId, 'workerId', { max: 160 });
      const fencingToken = taskString(input.fencingToken, 'fencingToken', { max: 200 });
      return { task: await store.transitionOwned(taskId, state, workerId, fencingToken, reason, input.details === undefined ? {} : input.details) };
    }
    if (input.workerId !== undefined) taskString(input.workerId, 'workerId', { max: 160 });
    if (input.fencingToken !== undefined) taskString(input.fencingToken, 'fencingToken', { max: 200 });
    return { task: await store.transition(taskId, state, reason, input.details === undefined ? {} : input.details) };
  }
  if (action === 'claim') {
    const input = taskBody(body, ['workerId', 'ttlMs'], ['workerId']);
    const workerId = taskString(input.workerId, 'workerId', { max: 160 });
    const ttlMs = taskInteger(input.ttlMs, 'ttlMs', { optional: true, min: 1, max: 86_400_000 });
    if (!await store.get(taskId)) throw Object.assign(new Error(`task not found: ${taskId}`), { status: 404 });
    const task = await store.claim(workerId, ttlMs === undefined ? { taskId } : { ttlMs, taskId });
    if (!task) throw Object.assign(new Error('task is not claimable'), { status: 409 });
    return { task };
  }
  if (action === 'heartbeat') {
    const input = taskBody(body, ['workerId', 'fencingToken', 'ttlMs'], ['workerId', 'fencingToken']);
    const workerId = taskString(input.workerId, 'workerId', { max: 160 });
    const fencingToken = taskString(input.fencingToken, 'fencingToken', { max: 200 });
    const ttlMs = taskInteger(input.ttlMs, 'ttlMs', { optional: true, min: 1, max: 86_400_000 });
    return { task: await store.heartbeat(taskId, workerId, { ...(ttlMs === undefined ? {} : { ttlMs }), fencingToken }) };
  }
  if (action === 'checkpoint') {
    const input = taskBody(body, ['workerId', 'fencingToken', 'checkpoint'], ['workerId', 'fencingToken', 'checkpoint']);
    return { task: await store.checkpoint(taskId, input.checkpoint, taskString(input.workerId, 'workerId', { max: 160 }), taskString(input.fencingToken, 'fencingToken', { max: 200 })) };
  }
  if (action === 'fail') {
    const input = taskBody(body, ['workerId', 'fencingToken', 'retryable', 'blocked', 'error', 'retryDelayMs'], ['workerId', 'fencingToken']);
    const workerId = taskString(input.workerId, 'workerId', { max: 160 });
    const fencingToken = taskString(input.fencingToken, 'fencingToken', { max: 200 });
    for (const key of ['retryable', 'blocked']) if (input[key] !== undefined && typeof input[key] !== 'boolean') throw Object.assign(new Error(`${key} 必须是布尔值`), { status: 400 });
    const error = input.error === undefined || input.error === null ? null : taskString(input.error, 'error', { max: 2000 });
    const retryDelayMs = taskInteger(input.retryDelayMs, 'retryDelayMs', { optional: true, min: 0, max: 86_400_000 });
    return { task: await store.fail(taskId, { workerId, fencingToken, retryable: input.retryable === true, blocked: input.blocked === true, error, retryDelayMs }) };
  }
  if (action === 'cancel') {
    const input = taskBody(body, ['reason']);
    const reason = input.reason === undefined ? 'cancelled' : taskString(input.reason, 'reason');
    return { task: await store.cancel(taskId, reason) };
  }
  if (action === 'resume') {
    taskBody(body, []);
    return { task: await store.resume(taskId) };
  }
  if (action === 'pause') {
    const input = taskBody(body, ['workerId', 'fencingToken', 'reason'], ['workerId', 'fencingToken']);
    const workerId = taskString(input.workerId, 'workerId', { max: 160 });
    const fencingToken = taskString(input.fencingToken, 'fencingToken', { max: 200 });
    return { task: await store.transitionOwned(taskId, 'paused', workerId, fencingToken, input.reason === undefined ? 'paused' : taskString(input.reason, 'reason')) };
  }
  throw Object.assign(new Error('任务操作不存在'), { status: 404 });
}

function v1TaskBody(body, allowed, required = []) {
  return taskBody(body, allowed, required);
}

function v1TaskId(pathPart) {
  try {
    const taskId = decodeURIComponent(pathPart);
    if (!taskId || taskId.length > 120) throw new Error('任务 ID 无效');
    return taskId;
  } catch (error) {
    throw new TaskApiV1Error('invalid_task_id', '任务 ID 编码无效', 400, { cause: error });
  }
}

function v1NoQuery(url) {
  if ([...url.searchParams.keys()].length) throw new TaskApiV1Error('unknown_query_parameter', '该任务接口不接受查询参数');
}

function v1TaskEnvelope(task, revision, generatedAt = new Date().toISOString()) {
  return taskEnvelope({ data: task, consistency: taskConsistency(revision, generatedAt) }, generatedAt);
}

async function v1ReadTask(store, taskId, generatedAt = new Date().toISOString()) {
  const result = await store.readTask(taskId);
  if (!result.task) throw Object.assign(new Error(`task not found: ${taskId}`), { status: 404 });
  return v1TaskEnvelope(result.task, result.revision, generatedAt);
}

function insideDirectory(directory, candidate) {
  const rel = relative(directory, candidate);
  return rel === '' || (!rel.startsWith('..' + sep) && rel !== '..' && !isAbsolute(rel));
}

async function readAnalysisReport(store, taskId, evidenceRoot) {
  const result = await store.readTask(taskId);
  const task = result.task;
  if (!task) throw new TaskApiV1Error('not_found', '任务不存在', 404);
  if (task.type !== ANALYSIS_TASK_TYPE) throw new TaskApiV1Error('wrong_task_type', '该任务不是本地源码分析任务', 409);
  if (!['succeeded', 'partial'].includes(task.state) || task.checkpoint?.phase !== 'evidence_ready') {
    throw new TaskApiV1Error('evidence_not_ready', '分析证据尚未就绪', 409);
  }

  const checkpoint = task.checkpoint;
  if (!Number.isSafeInteger(checkpoint.attempt) || checkpoint.attempt < 1 || checkpoint.attempt !== task.attempts ||
      typeof checkpoint.attemptDirectory !== 'string' || typeof checkpoint.reportPath !== 'string' ||
      !Number.isSafeInteger(checkpoint.reportBytes) || checkpoint.reportBytes < 0 || checkpoint.reportBytes > ANALYSIS_REPORT_MAX_BYTES ||
      typeof checkpoint.reportSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(checkpoint.reportSha256) ||
      checkpoint.attemptDirectory.includes('\0') || checkpoint.reportPath.includes('\0')) {
    throw new TaskApiV1Error('invalid_evidence_checkpoint', '分析证据 checkpoint 无效', 409);
  }
  const attemptName = basename(checkpoint.attemptDirectory);
  const attemptMatch = attemptName.match(/^attempt-(\d+)-([0-9a-f-]+)$/i);
  if (!attemptMatch || !UUID_PATTERN.test(attemptMatch[2]) || attemptMatch[1] !== String(checkpoint.attempt)) {
    throw new TaskApiV1Error('invalid_evidence_checkpoint', '分析证据路径不符合 checkpoint', 409);
  }

  const configuredRoot = resolve(evidenceRoot);
  let canonicalRoot;
  try {
    const rootInfo = await lstat(evidenceRoot);
    if (rootInfo.isSymbolicLink() || !rootInfo.isDirectory()) throw new TaskApiV1Error('invalid_evidence_root', '分析证据根目录无效', 403);
    canonicalRoot = await realpath(evidenceRoot);
  }
  catch (error) {
    if (error.code === 'ENOENT') throw new TaskApiV1Error('report_not_found', '分析报告不存在', 404);
    throw error;
  }
  const taskDirectory = join(configuredRoot, createHash('sha256').update(taskId).digest('hex'));
  const canonicalTaskDirectory = join(canonicalRoot, createHash('sha256').update(taskId).digest('hex'));
  const attemptDirectory = join(taskDirectory, attemptName);
  const canonicalAttemptDirectory = join(canonicalTaskDirectory, attemptName);
  const reportPath = join(attemptDirectory, 'static-analysis.json');
  const canonicalReportPath = join(canonicalAttemptDirectory, 'static-analysis.json');
  if (!isAbsolute(checkpoint.attemptDirectory) || !isAbsolute(checkpoint.reportPath) ||
      resolve(checkpoint.attemptDirectory) !== attemptDirectory || resolve(checkpoint.reportPath) !== reportPath ||
      !insideDirectory(configuredRoot, taskDirectory) || !insideDirectory(taskDirectory, attemptDirectory) || !insideDirectory(attemptDirectory, reportPath) ||
      !insideDirectory(canonicalRoot, canonicalTaskDirectory) || !insideDirectory(canonicalTaskDirectory, canonicalAttemptDirectory) || !insideDirectory(canonicalAttemptDirectory, canonicalReportPath)) {
    throw new TaskApiV1Error('invalid_evidence_checkpoint', '分析证据路径超出允许目录', 403);
  }

  let handle;
  try {
    for (const [path, canonicalPath] of [[taskDirectory, canonicalTaskDirectory], [attemptDirectory, canonicalAttemptDirectory]]) {
      const info = await lstat(path);
      if (info.isSymbolicLink() || !info.isDirectory()) throw new TaskApiV1Error('invalid_evidence_path', '分析证据路径无效', 403);
      if (await realpath(path) !== canonicalPath) throw new TaskApiV1Error('invalid_evidence_path', '分析证据路径包含符号链接', 403);
    }
    const fileInfo = await lstat(reportPath);
    if (fileInfo.isSymbolicLink() || !fileInfo.isFile()) throw new TaskApiV1Error('invalid_evidence_file', '分析报告必须是普通文件', 403);
    if (await realpath(reportPath) !== canonicalReportPath) throw new TaskApiV1Error('invalid_evidence_file', '分析报告路径包含符号链接', 403);
    if (fileInfo.size > ANALYSIS_REPORT_MAX_BYTES) throw new TaskApiV1Error('report_too_large', '分析报告超过 64 MiB 限制', 413);
    handle = await open(reportPath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);
    const openedInfo = await handle.stat();
    if (!openedInfo.isFile() || openedInfo.dev !== fileInfo.dev || openedInfo.ino !== fileInfo.ino) {
      throw new TaskApiV1Error('invalid_evidence_file', '分析报告在读取期间发生变化', 403);
    }
    if (openedInfo.size > ANALYSIS_REPORT_MAX_BYTES) throw new TaskApiV1Error('report_too_large', '分析报告超过 64 MiB 限制', 413);
    const buffer = Buffer.allocUnsafe(Math.min(fileInfo.size, ANALYSIS_REPORT_MAX_BYTES) + 1);
    let total = 0;
    while (total < buffer.length) {
      const { bytesRead } = await handle.read(buffer, total, Math.min(64 * 1024, buffer.length - total), null);
      if (bytesRead === 0) break;
      total += bytesRead;
    }
    if (total > ANALYSIS_REPORT_MAX_BYTES) throw new TaskApiV1Error('report_too_large', '分析报告超过 64 MiB 限制', 413);
    const bytes = buffer.subarray(0, total);
    const actualSha256 = createHash('sha256').update(bytes).digest('hex');
    if (total !== checkpoint.reportBytes || actualSha256 !== checkpoint.reportSha256) {
      throw new TaskApiV1Error('report_integrity_mismatch', '分析报告内容与完成时固定指纹不一致', 409);
    }
    let report;
    try { report = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
    catch { throw new TaskApiV1Error('invalid_report', '分析报告不是有效的 UTF-8 JSON', 422); }
    if (!report || typeof report !== 'object' || Array.isArray(report)) throw new TaskApiV1Error('invalid_report', '分析报告 JSON 必须是对象', 422);
    return { report, sha256: actualSha256, revision: result.revision };
  } catch (error) {
    if (error instanceof TaskApiV1Error) throw error;
    if (error.code === 'ENOENT' || error.code === 'ENOTDIR') throw new TaskApiV1Error('report_not_found', '分析报告不存在', 404);
    throw error;
  } finally {
    await handle?.close();
  }
}

async function readReverseTextArtifact(store, taskId, artifactSha256, evidenceRoot) {
  const result = await store.readTask(taskId);
  const task = result.task;
  if (!task) throw new TaskApiV1Error('not_found', '任务不存在', 404);
  if (!['v1-resource-bytecode', 'v1-resource-decompile'].includes(task.type)) {
    throw new TaskApiV1Error('wrong_task_type', '该任务没有可查看的代码产物', 409);
  }
  if (!['succeeded', 'partial'].includes(task.state) || task.checkpoint?.phase !== 'evidence_ready') {
    throw new TaskApiV1Error('evidence_not_ready', '代码产物尚未就绪', 409);
  }
  const checkpoint = task.checkpoint;
  if (!Number.isSafeInteger(task.attempts) || task.attempts < 1 || typeof checkpoint.attemptDirectory !== 'string' ||
      checkpoint.attemptDirectory.includes('\0') || !Array.isArray(checkpoint.artifacts)) {
    throw new TaskApiV1Error('invalid_artifact_checkpoint', '代码产物记录无效', 409);
  }
  const artifact = checkpoint.artifacts.find((item) => item?.sha256 === artifactSha256);
  if (!artifact) throw new TaskApiV1Error('artifact_not_found', '当前任务没有该代码产物', 404);
  const kind = artifact.kind;
  const extension = typeof artifact.path === 'string' ? extname(artifact.path).toLowerCase() : '';
  const isUnifiedIr = kind === 'unified-ir' && extension === '.json';
  const isPseudoCode = ['solidity-pseudocode', 'yul-pseudocode', 'decompiler-output'].includes(kind) && ['.sol', '.yul', '.txt'].includes(extension);
  if (!isUnifiedIr && !isPseudoCode) throw new TaskApiV1Error('artifact_not_text', '该产物类型不支持网页文本查看', 415);
  if (Number.isSafeInteger(artifact.bytes) && artifact.bytes > REVERSE_TEXT_ARTIFACT_MAX_BYTES) {
    throw new TaskApiV1Error('artifact_too_large', '代码产物超过网页查看上限', 413);
  }
  if (!Number.isSafeInteger(artifact.bytes) || artifact.bytes < 0 ||
      !/^[0-9a-f]{64}$/.test(String(artifact.sha256 || '')) || typeof artifact.path !== 'string' ||
      artifact.path.includes('\0') || !isAbsolute(artifact.path)) {
    throw new TaskApiV1Error('invalid_artifact_checkpoint', '代码产物校验信息无效', 409);
  }

  const configuredRoot = resolve(evidenceRoot);
  let canonicalRoot;
  try {
    const rootInfo = await lstat(evidenceRoot);
    if (rootInfo.isSymbolicLink() || !rootInfo.isDirectory()) throw new TaskApiV1Error('invalid_evidence_root', '证据根目录无效', 403);
    canonicalRoot = await realpath(evidenceRoot);
  } catch (error) {
    if (error.code === 'ENOENT') throw new TaskApiV1Error('artifact_not_found', '代码产物不存在', 404);
    throw error;
  }
  const taskDirectory = join(configuredRoot, createHash('sha256').update(taskId).digest('hex'));
  const attemptName = basename(checkpoint.attemptDirectory);
  const attemptMatch = attemptName.match(/^attempt-(\d+)-([0-9a-f-]+)$/i);
  if (!attemptMatch || !UUID_PATTERN.test(attemptMatch[2]) || attemptMatch[1] !== String(task.attempts)) {
    throw new TaskApiV1Error('invalid_artifact_checkpoint', '代码产物路径与任务尝试记录不匹配', 409);
  }
  const attemptDirectory = join(taskDirectory, attemptName);
  const canonicalTaskDirectory = join(canonicalRoot, createHash('sha256').update(taskId).digest('hex'));
  const canonicalAttemptDirectory = join(canonicalTaskDirectory, attemptName);
  const artifactPath = resolve(artifact.path);
  const canonicalArtifactPath = join(canonicalAttemptDirectory, relative(attemptDirectory, artifactPath));
  if (resolve(checkpoint.attemptDirectory) !== attemptDirectory || !insideDirectory(configuredRoot, taskDirectory) ||
      !insideDirectory(taskDirectory, attemptDirectory) || !insideDirectory(attemptDirectory, artifactPath) ||
      !insideDirectory(canonicalRoot, canonicalTaskDirectory) || !insideDirectory(canonicalTaskDirectory, canonicalAttemptDirectory) ||
      !insideDirectory(canonicalAttemptDirectory, canonicalArtifactPath)) {
    throw new TaskApiV1Error('artifact_path_forbidden', '代码产物路径超出任务目录', 403);
  }

  let handle;
  try {
    for (const [path, canonicalPath] of [[taskDirectory, canonicalTaskDirectory], [attemptDirectory, canonicalAttemptDirectory]]) {
      const info = await lstat(path);
      if (info.isSymbolicLink() || !info.isDirectory() || await realpath(path) !== canonicalPath) {
        throw new TaskApiV1Error('invalid_artifact_path', '代码产物目录无效', 403);
      }
    }
    const fileInfo = await lstat(artifactPath);
    if (fileInfo.isSymbolicLink() || !fileInfo.isFile() || await realpath(artifactPath) !== canonicalArtifactPath) {
      throw new TaskApiV1Error('invalid_artifact_file', '代码产物必须是任务目录内的普通文件', 403);
    }
    if (fileInfo.size > REVERSE_TEXT_ARTIFACT_MAX_BYTES) throw new TaskApiV1Error('artifact_too_large', '代码产物超过网页查看上限', 413);
    handle = await open(artifactPath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);
    const openedInfo = await handle.stat();
    if (!openedInfo.isFile() || openedInfo.dev !== fileInfo.dev || openedInfo.ino !== fileInfo.ino) {
      throw new TaskApiV1Error('invalid_artifact_file', '代码产物在读取期间发生变化', 403);
    }
    const buffer = Buffer.allocUnsafe(Math.min(openedInfo.size, REVERSE_TEXT_ARTIFACT_MAX_BYTES) + 1);
    let total = 0;
    while (total < buffer.length) {
      const { bytesRead } = await handle.read(buffer, total, Math.min(64 * 1024, buffer.length - total), null);
      if (!bytesRead) break;
      total += bytesRead;
    }
    if (total > REVERSE_TEXT_ARTIFACT_MAX_BYTES) throw new TaskApiV1Error('artifact_too_large', '代码产物超过网页查看上限', 413);
    const bytes = buffer.subarray(0, total);
    const actualSha256 = createHash('sha256').update(bytes).digest('hex');
    if (total !== artifact.bytes || actualSha256 !== artifact.sha256) {
      throw new TaskApiV1Error('artifact_integrity_mismatch', '代码产物与完成时记录不一致', 409);
    }
    let content;
    try { content = new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
    catch { throw new TaskApiV1Error('artifact_invalid_text', '代码产物不是有效的 UTF-8 文本', 422); }
    if (isUnifiedIr) {
      try { JSON.parse(content); }
      catch { throw new TaskApiV1Error('artifact_invalid_json', '统一代码记录不是有效 JSON', 422); }
    }
    return { content, kind, bytes: total, sha256: actualSha256, revision: result.revision };
  } catch (error) {
    if (error instanceof TaskApiV1Error) throw error;
    if (error.code === 'ENOENT' || error.code === 'ENOTDIR') throw new TaskApiV1Error('artifact_not_found', '代码产物不存在', 404);
    throw error;
  } finally {
    await handle?.close();
  }
}

function v1ParseRevision(request, body) {
  return parseExpectedRevision(request, body);
}

async function taskRouteV1(store, request, url, body, evidenceRoot, withReportReadSlot, withArtifactReadSlot) {
  if (!store) throw Object.assign(new Error('持久化任务状态未启用'), { status: 503 });
  const pathname = url.pathname;
  const artifactMatch = pathname.match(/^\/api\/v1\/tasks\/([^/]+)\/artifacts\/([0-9a-f]{64})\/content$/i);
  if (artifactMatch) {
    const taskId = v1TaskId(artifactMatch[1]);
    if (url.search !== '') throw new TaskApiV1Error('unknown_query_parameter', '代码产物接口不接受查询参数');
    if (request.method !== 'GET') throw new TaskApiV1Error('method_not_allowed', '代码产物只支持 GET', 405);
    const generatedAt = new Date().toISOString();
    const data = await withArtifactReadSlot(() => readReverseTextArtifact(store, taskId, artifactMatch[2].toLowerCase(), evidenceRoot));
    return { status: 200, body: taskEnvelope({ data: { content: data.content, kind: data.kind, bytes: data.bytes, sha256: data.sha256 }, consistency: taskConsistency(data.revision, generatedAt) }, generatedAt) };
  }
  const match = pathname.match(/^\/api\/v1\/tasks(?:\/([^/]+)(?:\/(transition|claim|heartbeat|checkpoint|fail|cancel|resume|pause|report))?)?$/);
  if (!match) return null;
  const method = request.method;
  const taskPart = match[1] || null;
  const action = match[2] || null;
  if (!taskPart) {
    if (method === 'GET') {
      const query = parseTaskPageQuery(url.searchParams);
      const result = await store.listPage(query);
      const generatedAt = new Date().toISOString();
      return { status: 200, body: taskEnvelope({
        items: result.page,
        page: { limit: query.limit, hasMore: result.hasMore, nextCursor: result.nextCursor },
        consistency: taskConsistency(result.revision, generatedAt),
      }, generatedAt) };
    }
    if (method === 'POST') {
      const input = v1TaskBody(body, ['taskId', 'type', 'payload', 'priority', 'maxAttempts'], ['type']);
      const type = taskString(input.type, 'type', { max: 120 });
      const taskId = input.taskId === undefined ? undefined : taskString(input.taskId, 'taskId', { max: 120 });
      const priority = taskInteger(input.priority === undefined ? 0 : input.priority, 'priority');
      const maxAttempts = taskInteger(input.maxAttempts === undefined ? 3 : input.maxAttempts, 'maxAttempts', { min: 1, max: 100 });
      const created = await store.create({ taskId, type, payload: input.payload === undefined ? {} : input.payload, priority, maxAttempts });
      const current = await store.readTask(created.taskId);
      const generatedAt = new Date().toISOString();
      return { status: 201, body: v1TaskEnvelope(current.task, current.revision, generatedAt) };
    }
    throw new TaskApiV1Error('method_not_allowed', '任务集合只支持 GET 或 POST', 405);
  }

  const taskId = v1TaskId(taskPart);
  if (action === 'report') {
    if (url.search !== '') throw new TaskApiV1Error('unknown_query_parameter', '分析报告接口不接受查询参数');
    if (method !== 'GET') throw new TaskApiV1Error('method_not_allowed', '分析报告只支持 GET', 405);
    const generatedAt = new Date().toISOString();
    const { report, sha256, revision } = await withReportReadSlot(() => readAnalysisReport(store, taskId, evidenceRoot));
    return { status: 200, body: taskEnvelope({ data: { report, sha256 }, consistency: taskConsistency(revision, generatedAt) }, generatedAt) };
  }
  if (!action) {
    v1NoQuery(url);
    if (method !== 'GET') throw new TaskApiV1Error('method_not_allowed', '单个任务只支持 GET', 405);
    return { status: 200, body: await v1ReadTask(store, taskId) };
  }
  v1NoQuery(url);
  if (!['POST', 'PATCH'].includes(method)) throw new TaskApiV1Error('method_not_allowed', '任务操作只支持 POST', 405);
  if (action !== 'transition' && method === 'PATCH') throw new TaskApiV1Error('method_not_allowed', '该任务操作只支持 POST', 405);

  if (action === 'claim') {
    const input = v1TaskBody(body, ['workerId', 'ttlMs'], ['workerId']);
    const workerId = taskString(input.workerId, 'workerId', { max: 160 });
    const ttlMs = taskInteger(input.ttlMs, 'ttlMs', { optional: true, min: 1, max: 86_400_000 });
    if (!await store.get(taskId)) throw Object.assign(new Error(`task not found: ${taskId}`), { status: 404 });
    const task = await store.claim(workerId, ttlMs === undefined ? { taskId } : { ttlMs, taskId });
    if (!task) throw Object.assign(new Error('task is not claimable'), { status: 409 });
    return { status: 200, body: await v1ReadTask(store, taskId) };
  }
  if (action === 'heartbeat') {
    const input = v1TaskBody(body, ['workerId', 'fencingToken', 'ttlMs'], ['workerId', 'fencingToken']);
    const workerId = taskString(input.workerId, 'workerId', { max: 160 });
    const fencingToken = taskString(input.fencingToken, 'fencingToken', { max: 200 });
    const ttlMs = taskInteger(input.ttlMs, 'ttlMs', { optional: true, min: 1, max: 86_400_000 });
    await store.heartbeat(taskId, workerId, { ...(ttlMs === undefined ? {} : { ttlMs }), fencingToken });
    return { status: 200, body: await v1ReadTask(store, taskId) };
  }
  if (action === 'checkpoint') {
    const input = v1TaskBody(body, ['workerId', 'fencingToken', 'checkpoint'], ['workerId', 'fencingToken', 'checkpoint']);
    await store.checkpoint(taskId, input.checkpoint, taskString(input.workerId, 'workerId', { max: 160 }), taskString(input.fencingToken, 'fencingToken', { max: 200 }));
    return { status: 200, body: await v1ReadTask(store, taskId) };
  }
  if (action === 'fail') {
    const input = v1TaskBody(body, ['workerId', 'fencingToken', 'retryable', 'blocked', 'error', 'retryDelayMs'], ['workerId', 'fencingToken']);
    const workerId = taskString(input.workerId, 'workerId', { max: 160 });
    const fencingToken = taskString(input.fencingToken, 'fencingToken', { max: 200 });
    for (const key of ['retryable', 'blocked']) if (input[key] !== undefined && typeof input[key] !== 'boolean') throw Object.assign(new Error(`${key} 必须是布尔值`), { status: 400 });
    const error = input.error === undefined || input.error === null ? null : taskString(input.error, 'error', { max: 2000 });
    const retryDelayMs = taskInteger(input.retryDelayMs, 'retryDelayMs', { optional: true, min: 0, max: 86_400_000 });
    await store.fail(taskId, { workerId, fencingToken, retryable: input.retryable === true, blocked: input.blocked === true, error, retryDelayMs });
    return { status: 200, body: await v1ReadTask(store, taskId) };
  }
  if (action === 'pause') {
    const input = v1TaskBody(body, ['workerId', 'fencingToken', 'reason', 'expectedRevision']);
    const reason = input.reason === undefined ? 'paused' : taskString(input.reason, 'reason');
    if (input.workerId !== undefined || input.fencingToken !== undefined) {
      if (input.workerId === undefined || input.fencingToken === undefined || input.expectedRevision !== undefined) {
        throw new TaskApiV1Error('invalid_pause_request', 'workerId 和 fencingToken 必须同时提供，且不能与 expectedRevision 混用');
      }
      await store.transitionOwned(taskId, 'paused', taskString(input.workerId, 'workerId', { max: 160 }), taskString(input.fencingToken, 'fencingToken', { max: 200 }), reason);
    } else {
      await store.pauseIfRevision(taskId, reason, v1ParseRevision(request, input));
    }
    return { status: 200, body: await v1ReadTask(store, taskId) };
  }

  if (action === 'transition') {
    const input = v1TaskBody(body, ['state', 'reason', 'details', 'workerId', 'fencingToken', 'expectedRevision'], ['state']);
    const state = taskString(input.state, 'state', { max: 40 });
    const reason = input.reason === undefined ? '' : taskString(input.reason, 'reason');
    const current = await store.get(taskId);
    if (!current) throw Object.assign(new Error(`task not found: ${taskId}`), { status: 404 });
    const hasWorker = input.workerId !== undefined || input.fencingToken !== undefined;
    if (hasWorker) {
      const workerId = taskString(input.workerId, 'workerId', { max: 160 });
      const fencingToken = taskString(input.fencingToken, 'fencingToken', { max: 200 });
      await store.transitionOwned(taskId, state, workerId, fencingToken, reason, input.details === undefined ? {} : input.details);
    } else {
      const expectedRevision = v1ParseRevision(request, input);
      await store.transitionIfRevision(taskId, state, { expectedRevision, reason, details: input.details === undefined ? {} : input.details });
    }
    return { status: 200, body: await v1ReadTask(store, taskId) };
  }
  if (action === 'cancel') {
    const input = v1TaskBody(body, ['reason', 'expectedRevision']);
    const reason = input.reason === undefined ? 'cancelled' : taskString(input.reason, 'reason');
    const expectedRevision = v1ParseRevision(request, input);
    await store.cancelIfRevision(taskId, reason, expectedRevision);
    return { status: 200, body: await v1ReadTask(store, taskId) };
  }
  if (action === 'resume') {
    const input = v1TaskBody(body, ['reason', 'expectedRevision']);
    const reason = input.reason === undefined ? 'resumed' : taskString(input.reason, 'reason');
    const expectedRevision = v1ParseRevision(request, input);
    await store.resumeIfRevision(taskId, reason, expectedRevision);
    return { status: 200, body: await v1ReadTask(store, taskId) };
  }
  throw Object.assign(new Error('任务操作不存在'), { status: 404 });
}

function wrapTaskV1Error(error) {
  if (error instanceof TaskApiV1Error) return error;
  const status = error?.status || (error?.code === 'REVISION_MISMATCH' ? 412 : 400);
  let code = error?.code === 'REVISION_MISMATCH' ? 'REVISION_MISMATCH' : null;
  if (!code) code = status === 404 ? 'not_found' : status === 405 ? 'method_not_allowed' : status === 409 ? 'conflict' : status >= 500 ? 'internal_error' : 'invalid_request';
  return new TaskApiV1Error(code, String(error?.message || '任务请求失败'), status);
}

function manifestSourceUnitRows(task, manifestArtifact, manifest) {
  if (task?.state !== 'succeeded' || task?.checkpoint?.complete !== true || !manifest || manifest.kind !== 'local-project-import' || manifest.complete !== true || !Array.isArray(manifest.files) || typeof manifest.projectId !== 'string' || !manifest.projectId || !/^[0-9a-f]{64}$/i.test(String(manifest.sourceFingerprint || ''))) return [];
  const manifestSha256 = String(manifestArtifact.sha256 || '').toLowerCase();
  const manifestBytes = manifestArtifact.bytes;
  if (!/^[0-9a-f]{64}$/.test(manifestSha256) || !Number.isSafeInteger(manifestBytes) || manifestBytes < 0) return [];
  const projectState = typeof task.state === 'string' ? task.state : 'unknown';
  const createdAt = task.createdAt || null;
  const updatedAt = task.updatedAt || null;
  const rows = [];
  for (const file of manifest.files) {
    if (!file || file.included !== true || file.kind !== 'source' || typeof file.path !== 'string' || !file.path || !/^[0-9a-f]{64}$/i.test(String(file.sha256 || '')) || !Number.isSafeInteger(file.bytes) || file.bytes < 0) continue;
    const extension = extname(file.path).toLowerCase();
    if (!SOURCE_FILE_EXTENSIONS.has(extension) || file.path.includes('\\') || file.path.startsWith('/') || file.path.split('/').includes('..')) continue;
    const contractId = `source-${createHash('sha256').update(`${manifest.projectId}\0${manifest.sourceFingerprint}\0${file.path}\0${String(file.sha256).toLowerCase()}`).digest('hex').slice(0, 32)}`;
    rows.push({
      id: contractId,
      contractId,
      taskId: task.taskId,
      resource: 'contracts',
      projectId: manifest.projectId,
      state: projectState,
      createdAt,
      updatedAt,
      sourcePath: file.path,
      sourceSha256: String(file.sha256).toLowerCase(),
      sourceBytes: file.bytes,
      language: extension === '.sol' ? 'solidity' : extension === '.yul' ? 'yul' : 'vyper',
      address: null,
      chainId: null,
      manifestPath: manifestArtifact.path,
      manifestSha256,
      manifestBytes,
      sourceFingerprint: String(manifest.sourceFingerprint).toLowerCase(),
      mapping: { state: 'source_file', contractName: null, address: 'unavailable', chain: 'unavailable', interpretation: '这是导入清单中的源文件单元，不代表已部署合约；名称、地址和链需要后续编译或链上绑定。' },
      provenance: { kind: 'project-import-manifest', taskId: task.taskId, manifestPath: manifestArtifact.path, sourcePath: file.path },
    });
  }
  return rows;
}

function createTaskResourceStore(taskStore, evidenceRoot = null) {
  const resourceType = (resource) => `v1-resource-${resource}`;
  const crossValidationView = (value) => {
    const record = value && typeof value === 'object' && !Array.isArray(value) ? value : {};
    const compared = Number.isSafeInteger(record.comparedHighLevelEngineCount) && record.comparedHighLevelEngineCount > 0
      ? record.comparedHighLevelEngineCount : 0;
    return {
      state: typeof record.state === 'string' ? record.state : 'not_recorded',
      scope: typeof record.agreementScope === 'string'
        ? record.agreementScope
        : '未记录独立高层反编译器比对；opcode/PC 解码核对不验证伪码语义。',
      highLevelEngineComparison: {
        state: compared > 0 ? 'compared' : 'not_performed',
        configuredEngines: Array.isArray(record.enginesConfigured) ? record.enginesConfigured : ['heimdall-rs'],
        completedEngines: Array.isArray(record.enginesCompleted) ? record.enginesCompleted : [],
        comparedEngineCount: compared,
        reason: compared > 0 ? null : (record.reason || 'single_decompiler_engine_configured'),
      },
      opcodePcCrossCheck: record.opcodePcCrossCheck || null,
      semanticsProven: false,
    };
  };
  const view = (task) => ({
    id: task.taskId,
    taskId: task.taskId,
    resource: task.payload?.resource,
    state: task.state,
    createdAt: task.createdAt,
    updatedAt: task.updatedAt,
    attempts: task.attempts,
    checkpoint: task.checkpoint || null,
    ...(task.payload?.resource === 'decompile' ? {
      crossValidation: crossValidationView(task.checkpoint?.crossValidation),
    } : {}),
    artifacts: Array.isArray(task.checkpoint?.artifacts) ? task.checkpoint.artifacts : [],
    error: task.error || null,
    input: task.payload?.input || {},
  });
  const snapshot = async () => {
    if (!taskStore) return { revision: 0, tasks: [] };
    if (typeof taskStore.readSnapshot === 'function') return taskStore.readSnapshot();
    return { revision: 0, tasks: await taskStore.list() };
  };
  const projectManifest = async (task) => {
    const checkpoint = task?.checkpoint;
    const artifact = Array.isArray(checkpoint?.artifacts)
      ? checkpoint.artifacts.find((item) => item && item.kind === 'project-import-manifest' && typeof item.path === 'string')
      : null;
    if (!artifact || typeof checkpoint?.attemptDirectory !== 'string' || !evidenceRoot) return null;
    const attemptDirectory = resolve(checkpoint.attemptDirectory);
    const manifestPath = resolve(artifact.path);
    const root = resolve(evidenceRoot);
    if (!insideDirectory(attemptDirectory, manifestPath) || !Number.isSafeInteger(artifact.bytes) || artifact.bytes < 0 || artifact.bytes > PROJECT_MANIFEST_MAX_BYTES || !/^[0-9a-f]{64}$/i.test(String(artifact.sha256 || ''))) return null;
    try {
      const [canonicalRoot, canonicalAttempt, canonicalManifest] = await Promise.all([realpath(root), realpath(attemptDirectory), realpath(manifestPath)]);
      if (!insideDirectory(canonicalRoot, canonicalAttempt) || !insideDirectory(canonicalAttempt, canonicalManifest)) return null;
      const attemptInfo = await lstat(canonicalAttempt), manifestInfo = await lstat(canonicalManifest);
      if (!attemptInfo.isDirectory() || attemptInfo.isSymbolicLink() || !manifestInfo.isFile() || manifestInfo.isSymbolicLink() || manifestInfo.size !== artifact.bytes) return null;
      const bytes = await readFile(canonicalManifest);
      if (bytes.length !== artifact.bytes || createHash('sha256').update(bytes).digest('hex') !== String(artifact.sha256).toLowerCase()) return null;
      const manifest = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
      return { artifact: { path: canonicalManifest, sha256: String(artifact.sha256).toLowerCase(), bytes: bytes.length }, manifest };
    } catch { return null; }
  };
  const mappedContracts = async (state) => {
    const rows = [];
    for (const task of state.tasks.filter((item) => item.type === resourceType('projects'))) {
      const loaded = await projectManifest(task);
      if (loaded) rows.push(...manifestSourceUnitRows(task, loaded.artifact, loaded.manifest));
    }
    return rows;
  };
  return {
    async listResources(resource, query) {
      const state = await snapshot();
      let rows = state.tasks.filter((task) => task.type === resourceType(resource));
      if (resource === 'contracts') rows = rows.map(view).concat(await mappedContracts(state));
      else rows = rows.map(view);
      for (const key of ['projectId', 'chainId', 'address']) if (query[key] !== undefined) rows = rows.filter((item) => String(item[key] ?? item.payload?.input?.[key] ?? '') === query[key]);
      if (query.state !== undefined) rows = rows.filter((task) => task.state === query.state);
      rows = rows.sort((a, b) => String(a.id || a.taskId || '').localeCompare(String(b.id || b.taskId || '')));
      const filterKey = JSON.stringify({ projectId: query.projectId || null, chainId: query.chainId || null, address: query.address || null, state: query.state || null });
      let start = 0;
      if (query.cursor !== undefined) {
        let cursor;
        try { cursor = JSON.parse(Buffer.from(query.cursor, 'base64url').toString('utf8')); } catch { throw Object.assign(new Error('cursor 无效'), { status: 400, code: 'invalid_cursor' }); }
        if (!cursor || cursor.resource !== resource || cursor.filterKey !== filterKey || typeof cursor.after !== 'string') throw Object.assign(new Error('cursor 与资源或过滤条件不匹配'), { status: 400, code: 'invalid_cursor' });
        start = rows.findIndex((task) => String(task.id || task.taskId || '') > cursor.after);
        if (start < 0) start = rows.length;
      }
      const page = rows.slice(start, start + query.limit);
      const hasMore = start + page.length < rows.length;
      const nextCursor = hasMore ? Buffer.from(JSON.stringify({ resource, filterKey, after: String(page.at(-1).id || page.at(-1).taskId || '') })).toString('base64url') : null;
      return { items: page, hasMore, nextCursor, revision: state.revision };
    },
    async getResource(resource, id) {
      const state = await snapshot();
      const task = state.tasks.find((item) => item.taskId === id && item.type === resourceType(resource));
      if (task) return view(task);
      if (resource === 'contracts') return (await mappedContracts(state)).find((item) => item.id === id || item.contractId === id) || null;
      return null;
    },
    async createTask({ resource, payload }) {
      if (!taskStore) throw Object.assign(new Error('持久化任务状态未启用'), { status: 503, code: 'task_store_unavailable' });
      return taskStore.create({ type: resourceType(resource), payload: { resource, input: payload } });
    },
  };
}

function resourcePageBody(result, generatedAt, requestId) {
  return resourceEnvelope({
    items: result.items,
    page: { limit: result.limit, hasMore: result.hasMore, nextCursor: result.nextCursor },
    consistency: { revision: result.revision, asOf: result.consistency?.asOf || generatedAt },
    requestId,
  }, generatedAt);
}

function parseResourceRevision(request, body) {
  if (request.headers['if-match'] === undefined && !(body && Object.hasOwn(body, 'expectedRevision'))) return undefined;
  return parseExpectedRevision(request, body);
}

async function operationsResourceRoute(request, url, body, operations, requestId) {
  const pathname = url.pathname;
  const method = request.method;
  const generatedAt = new Date().toISOString();
  const workerMatch = pathname.match(/^\/api\/v1\/workers(?:\/([^/]+)(?:\/(heartbeat|health))?)?$/);
  const versionedMatch = pathname.match(/^\/api\/v1\/(rules|invariants)(?:\/([^/]+)(?:\/versions\/(\d+))?)?$/);
  const auditMatch = pathname.match(/^\/api\/v1\/reviews\/audit(?:\/([^/]+))?$/);
  try {
    const noQuery = () => {
      if ([...url.searchParams.keys()].length) throw Object.assign(new Error('该资源路径不接受查询参数'), { status: 400, code: 'unknown_query_parameter' });
    };
    if (workerMatch) {
      const [, rawId, action] = workerMatch;
      if (!rawId) {
        if (method === 'GET') {
          const query = parseResourcePageQuery(url.searchParams);
          const result = await operations.listWorkers(query);
          return { status: 200, body: resourcePageBody({ ...result, limit: query.limit }, generatedAt, requestId) };
        }
        if (method === 'POST') {
          const { expectedRevision: _expectedRevision, ...input } = body || {};
          const value = await operations.registerWorker(input, { expectedRevision: parseResourceRevision(request, body) });
          const state = await operations.readSnapshot();
          return { status: 201, body: resourceEnvelope({ data: value, consistency: { revision: state.revision, asOf: generatedAt }, requestId }, generatedAt) };
        }
        throw Object.assign(new Error('workers 集合只支持 GET 和 POST'), { status: 405, code: 'method_not_allowed' });
      }
      noQuery();
      let workerId;
      try { workerId = decodeURIComponent(rawId); } catch { throw Object.assign(new Error('worker ID 编码无效'), { status: 400, code: 'invalid_id' }); }
      if (action === 'health' && method === 'GET') return { status: 200, body: resourceEnvelope({ data: await operations.getWorkerHealth(workerId), requestId }, generatedAt) };
      if (action === 'heartbeat' && method === 'POST') {
        const allowed = ['workerId', 'fencingToken', 'ttlMs', 'expectedRevision'];
        const unknown = Object.keys(body || {}).filter((key) => !allowed.includes(key));
        if (unknown.length) throw Object.assign(new Error(`请求包含未知字段：${unknown.join(', ')}`), { status: 400, code: 'unknown_field' });
        if (body.workerId !== undefined && body.workerId !== workerId) throw Object.assign(new Error('workerId 与路径不匹配'), { status: 400, code: 'invalid_field' });
        const value = await operations.heartbeatWorker(workerId, body.fencingToken, { ttlMs: body.ttlMs, expectedRevision: parseResourceRevision(request, body) });
        return { status: 200, body: resourceEnvelope({ data: value, requestId }, generatedAt) };
      }
      if (!action && method === 'GET') {
        const value = await operations.getWorker(workerId);
        if (!value) throw Object.assign(new Error('worker 不存在'), { status: 404, code: 'not_found' });
        return { status: 200, body: resourceEnvelope({ data: value, requestId }, generatedAt) };
      }
      if (!action && method === 'DELETE') {
        await operations.unregisterWorker(workerId, { expectedRevision: parseResourceRevision(request, body) });
        return { status: 204, body: null };
      }
      throw Object.assign(new Error('worker 路径或方法不支持'), { status: 405, code: 'method_not_allowed' });
    }
    if (versionedMatch) {
      const [, kind, rawId, rawVersion] = versionedMatch;
      if (!rawId) {
        if (method === 'GET') {
          const query = parseResourcePageQuery(url.searchParams, { allowed: ['allVersions'] });
          const allVersions = url.searchParams.get('allVersions');
          const enabled = allVersions === null ? false : allVersions === 'true' ? true : allVersions === 'false' ? false : null;
          if (enabled === null) throw Object.assign(new Error('allVersions 必须是 true 或 false'), { status: 400, code: 'invalid_field' });
          const result = kind === 'rules' ? await operations.listRules({ ...query, allVersions: enabled }) : await operations.listInvariants({ ...query, allVersions: enabled });
          return { status: 200, body: resourcePageBody({ ...result, limit: query.limit }, generatedAt, requestId) };
        }
        if (method === 'POST') {
          const { expectedRevision: _expectedRevision, ...input } = body || {};
          const value = kind === 'rules'
            ? await operations.createRuleVersion(input, { expectedRevision: parseResourceRevision(request, body) })
            : await operations.createInvariantVersion(input, { expectedRevision: parseResourceRevision(request, body) });
          const state = await operations.readSnapshot();
          return { status: 201, body: resourceEnvelope({ data: value, consistency: { revision: state.revision, asOf: generatedAt }, requestId }, generatedAt) };
        }
        throw Object.assign(new Error(`${kind} 集合只支持 GET 和 POST`), { status: 405, code: 'method_not_allowed' });
      }
      noQuery();
      if (method !== 'GET') throw Object.assign(new Error(`${kind} 资源只支持 GET`), { status: 405, code: 'method_not_allowed' });
      let id;
      try { id = decodeURIComponent(rawId); } catch { throw Object.assign(new Error('资源 ID 编码无效'), { status: 400, code: 'invalid_id' }); }
      const result = await operations.getVersioned(kind, id, rawVersion === undefined ? undefined : Number(rawVersion));
      return { status: 200, body: resourceEnvelope({ data: result.data, consistency: result.consistency, requestId }, generatedAt) };
    }
    if (auditMatch) {
      if (method !== 'GET') throw Object.assign(new Error('审查审计只支持 GET'), { status: 405, code: 'method_not_allowed' });
      const [, rawId] = auditMatch;
      if (rawId) {
        noQuery();
        let id;
        try { id = decodeURIComponent(rawId); } catch { throw Object.assign(new Error('requestId 编码无效'), { status: 400, code: 'invalid_id' }); }
        const entry = await operations.getReviewAudit(id);
        if (!entry) throw Object.assign(new Error('审查审计不存在'), { status: 404, code: 'not_found' });
        return { status: 200, body: resourceEnvelope({ data: entry, requestId }, generatedAt) };
      }
      const query = parseResourcePageQuery(url.searchParams, { allowed: ['decision', 'manifestSha256', 'requestId'] });
      const filters = Object.fromEntries(['decision', 'manifestSha256', 'requestId'].filter((key) => url.searchParams.has(key)).map((key) => [key, url.searchParams.get(key)]));
      const result = await operations.listReviewAudits({ ...query, ...filters });
      return { status: 200, body: resourcePageBody({ ...result, limit: query.limit }, generatedAt, requestId) };
    }
    return null;
  } catch (error) {
    const failure = resourceErrorBody(error, requestId);
    return { status: failure.status, body: failure.body };
  }
}

async function resourceUsage() {
  const result = { loadavg: loadavg(), disk: null, fileDescriptors: null, warnings: [] };
  try {
    const usage = await statfs(PROJECT_ROOT);
    const blockSize = Number(usage.bsize || usage.frsize || 0);
    const available = Number(usage.bavail || 0) * blockSize;
    const total = Number(usage.blocks || 0) * blockSize;
    result.disk = { availableBytes: available, totalBytes: total, usedBytes: Math.max(0, total - available) };
    if (total > 0 && available / total < 0.05) result.warnings.push('disk_low');
  } catch (error) { result.warnings.push(`disk_unavailable:${error.code || 'error'}`); }
  try {
    const entries = await readdir('/dev/fd');
    result.fileDescriptors = { open: entries.length };
  } catch (error) { result.warnings.push(`fd_unavailable:${error.code || 'error'}`); }
  return result;
}

function cloudAiConfiguration() {
  const baseUrl = process.env.DEFI_CLOUD_AI_BASE_URL?.trim() || '';
  const apiKey = process.env.DEFI_CLOUD_AI_API_KEY?.trim() || '';
  const model = process.env.DEFI_CLOUD_AI_MODEL?.trim() || '';
  let url = null;
  try { url = new URL(baseUrl); } catch {}
  const valid = url?.protocol === 'https:' && !url.username && !url.password && !url.search && !url.hash;
  return valid && apiKey && model ? { baseUrl: url.href.replace(/\/$/, ''), apiKey, model } : null;
}

async function callExternalCloudAi(question, context, signal, configuration) {
  const baseUrl = configuration.baseUrl.replace(/\/(?:chat\/completions|v1)\/$/, '').replace(/\/(?:chat\/completions|v1)$/, '');
  const endpoint = `${baseUrl}/v1/chat/completions`;
  const manifest = { question, context, model: configuration.model };
  const manifestSha256 = createHash('sha256').update(JSON.stringify(manifest)).digest('hex');
  const response = await fetch(endpoint, {
    method: 'POST', redirect: 'error', signal: AbortSignal.any([signal, AbortSignal.timeout(90_000)]),
    headers: { authorization: `Bearer ${configuration.apiKey}`, 'content-type': 'application/json' },
    body: JSON.stringify({ model: configuration.model, temperature: 0.2, max_tokens: 520, stream: false, messages: [
      { role: 'system', content: '你是区块链安全项目的云端状态解释助手。只根据提供的状态事实解释进度、时间和服务状态，不推断安全结论。不要猜测或补全缺失数据。generatedAt 是当前快照生成时间；sourceReportAt 是源报告时间；soakUpdatedAt 是稳定性观测更新时间，三者必须分开。简洁中文，先结论后依据。' },
      { role: 'user', content: JSON.stringify({ context, question }) },
    ] }),
  });
  if (!response.ok) throw new Error('cloud_ai_http_error');
  const declaredLength = Number(response.headers.get('content-length'));
  if (Number.isFinite(declaredLength) && declaredLength > 2 * 1024 * 1024) throw new Error('cloud_ai_response_too_large');
  const responseBytes = Buffer.from(await response.arrayBuffer());
  if (responseBytes.length > 2 * 1024 * 1024) throw new Error('cloud_ai_response_too_large');
  const payload = JSON.parse(responseBytes.toString('utf8'));
  const content = payload?.choices?.[0]?.message?.content;
  if (typeof content !== 'string' || !content.trim()) throw new Error('cloud_ai_invalid_response');
  return {
    explanation: content.trim().slice(0, 2800),
    provider: 'external_cloud_ai',
    model: configuration.model,
    evidence: { manifestSha256, responseSha256: createHash('sha256').update(responseBytes).digest('hex') },
  };
}

export function startServer({ port = Number(process.env.PORT || 8788), host = process.env.HOST || '127.0.0.1', snapshotProvider = buildSnapshot, explanationProvider = null, eventIntervalMs = 15000, readTimeoutMs = 5000, sourceFingerprint = null, taskStore = null, resourceStore = null, resourceOperations = null, resourceArtifactRoots = [join(PROJECT_ROOT, 'work'), join(PROJECT_ROOT, 'flare-scan', 'reports'), join(PROJECT_ROOT, 'flare-scan', 'contracts')], evidenceRoot = ANALYSIS_EVIDENCE_ROOT, reviewAuditPath = join(PROJECT_ROOT, 'work', 'review-audit.jsonl'), eventSink = null, startCollectionWorker = false, collectionWorkerId = null, collectionWorkerConcurrency = 1, collectionWorkerPollIntervalMs = 250, collectionWorkerLeaseTtlMs = 45_000, collectionWorkerMaxHandlerRuntimeMs = 300_000, collectionWorkerRpcRequest = null, chainCollectionEnabled = null } = {}) {
  if (!loopback.has(host)) throw new Error('本地服务只能绑定 loopback 地址');
  // 链上采集守卫：离线阶段的服务实例默认拒绝创建链上采集任务。
  // 库调用方保持历史行为（默认不拦截），命令行服务显式传入 chainCollectionEnabled。
  const chainCollectionOn = chainCollectionEnabled === null ? true : chainCollectionEnabled === true;
  const started = Date.now();
  const instanceId = randomUUID();
  const clients = new Set();
  const eventHistory = [];
  let eventSequence = 0;
  // Task workers run in a separate process in production.  Bridge their
  // durable history into SSE by observing new history entries instead of
  // relying on an in-process callback that a restarted worker cannot keep.
  const taskEventSeen = new Map();
  let taskEventBaselineReady = false;
  let taskEventSyncPromise = null;
  const metrics = { total: 0, failures: 0, clientErrors: 0, active: 0, snapshotReads: 0, snapshotFailures: 0, cloudAiCalls: 0, cloudAiFailures: 0, cloudAiActive: 0, lastSnapshotAt: null, lastSnapshotError: null };
  const operations = resourceOperations || new ResourceApiOperations({ path: join(PROJECT_ROOT, 'work', 'resource-api-state.json'), auditPath: reviewAuditPath });
  const corpusControl = new CorpusControlPlane({ projectRoot: PROJECT_ROOT });
  const projectResourceApi = createResourceApiV1({ store: resourceStore || createTaskResourceStore(taskStore, evidenceRoot), artifactRoots: resourceArtifactRoots });
  const collectionWorkerRuntime = {
    enabled: startCollectionWorker === true,
    state: startCollectionWorker === true ? 'starting' : 'disabled',
    workerId: null,
    handlerTypes: [COLLECTION_WORKER_TASK_TYPE],
    startedAt: null,
    stoppedAt: null,
    lastEventAt: null,
    lastError: null,
    active: 0,
  };
  let collectionWorker = null;
  let collectionWorkerStopPromise = null;
  const collectionWorkerEvent = (event) => {
    collectionWorkerRuntime.lastEventAt = new Date().toISOString();
    collectionWorkerRuntime.active = collectionWorker?.active?.size || 0;
    if (event.type === 'started') {
      collectionWorkerRuntime.state = 'running';
      collectionWorkerRuntime.startedAt = collectionWorkerRuntime.lastEventAt;
    } else if (event.type === 'stopped') {
      collectionWorkerRuntime.state = 'stopped';
      collectionWorkerRuntime.stoppedAt = collectionWorkerRuntime.lastEventAt;
      collectionWorkerRuntime.active = 0;
    } else if (event.type === 'error' || event.type === 'handler-error' || event.type === 'lease-lost') {
      collectionWorkerRuntime.lastError = String(event.error || '采集 worker 运行失败').slice(0, 500);
    }
    const eventType = event.type === 'heartbeat' ? 'worker_heartbeat'
      : event.type === 'claimed' || event.type === 'running' ? 'collection_stage_started'
        : event.type === 'succeeded' || event.type === 'partial' ? 'collection_stage_completed'
          : event.type === 'failed' || event.type === 'blocked' ? 'task_failed' : null;
    if (eventType) publishEvent(eventType, {
      workerId: collectionWorkerRuntime.workerId,
      taskId: event.taskId || null,
      state: event.task?.state || event.status || null,
      error: event.error ? String(event.error).slice(0, 500) : null,
    }, event.taskId || null);
  };
  if (startCollectionWorker === true && taskStore) {
    try {
      const handlers = createResourceTaskHandlers({
        root: PROJECT_ROOT,
        evidenceRoot,
        artifactRoots: resourceArtifactRoots,
        timeoutMs: collectionWorkerMaxHandlerRuntimeMs,
        taskStore,
        ...(typeof collectionWorkerRpcRequest === 'function' ? { rpcRequest: collectionWorkerRpcRequest } : {}),
      });
      const handler = handlers[COLLECTION_WORKER_TASK_TYPE];
      collectionWorker = new TaskWorker({
        store: taskStore,
        workerId: collectionWorkerId || `collection-worker-${randomUUID()}`,
        concurrency: collectionWorkerConcurrency,
        pollIntervalMs: collectionWorkerPollIntervalMs,
        leaseTtlMs: collectionWorkerLeaseTtlMs,
        maxHandlerRuntimeMs: collectionWorkerMaxHandlerRuntimeMs,
        handlers: { [COLLECTION_WORKER_TASK_TYPE]: handler },
        onEvent: collectionWorkerEvent,
      });
      collectionWorkerRuntime.workerId = collectionWorker.workerId;
    } catch (error) {
      collectionWorkerRuntime.state = 'failed';
      collectionWorkerRuntime.lastError = String(error?.message || error).slice(0, 500);
    }
  } else if (startCollectionWorker === true) {
    collectionWorkerRuntime.state = 'unavailable';
    collectionWorkerRuntime.lastError = '持久化任务状态未启用';
  }
  const workerStatus = () => ({ ...collectionWorkerRuntime, active: collectionWorker?.active?.size || collectionWorkerRuntime.active, running: collectionWorkerRuntime.state === 'running', handlerTypes: [...collectionWorkerRuntime.handlerTypes] });
  let reportReadActive = false;
  let artifactReadActive = false;
  async function withReportReadSlot(operation) {
    if (reportReadActive) throw new TaskApiV1Error('report_read_busy', '已有报告正在解析，请稍后重试', 503);
    reportReadActive = true;
    try { return await operation(); }
    finally { reportReadActive = false; }
  }
  async function withArtifactReadSlot(operation) {
    if (artifactReadActive) throw new TaskApiV1Error('artifact_read_busy', '已有代码产物正在读取，请稍后重试', 503);
    artifactReadActive = true;
    try { return await operation(); }
    finally { artifactReadActive = false; }
  }
  let latest = null;
  const refresh = boundedSingleFlight(async () => {
    const data = await snapshotProvider();
    latest = data; metrics.snapshotReads++; metrics.lastSnapshotAt = new Date().toISOString(); metrics.lastSnapshotError = null;
    return data;
  }, readTimeoutMs);
  const assetReaders = new Map([...assets].map((path) => [path, boundedSingleFlight(() => readFile(join(WEB_ROOT, path === '/' ? 'index.html' : path.slice(1))), readTimeoutMs)]));
  async function snapshot() {
    try { return await refresh(); }
    catch (error) { metrics.snapshotFailures++; metrics.lastSnapshotError = String(error.message).slice(0, 200); throw error; }
  }
  function eventFrame({ id, event, data }) {
    return `event: ${event}\nid: ${id}\ndata: ${JSON.stringify(data)}\n\n`;
  }
  function sendEvent(response, item) {
    if (!response.destroyed && !response.writableEnded) {
      if (response.writableLength > 512 * 1024) return false;
      response.write(eventFrame(item));
      return true;
    }
    return false;
  }
  function publishEvent(type, payload = {}, taskId = null) {
    if (typeof type !== 'string' || !type || type.length > 80) throw new TypeError('event type must be a non-empty string');
    const item = {
      id: String(++eventSequence), event: 'lifecycle',
      data: { schemaVersion: 1, id: String(eventSequence), type, at: new Date().toISOString(), taskId: taskId || null, payload },
    };
    eventHistory.push(item);
    if (eventHistory.length > SSE_HISTORY_LIMIT) eventHistory.splice(0, eventHistory.length - SSE_HISTORY_LIMIT);
    for (const client of clients) if (!sendEvent(client, item)) clients.delete(client);
    try { eventSink?.(item.data); } catch { /* event observers must not affect request handling */ }
    return item.data;
  }
  if (collectionWorker) {
    try {
      collectionWorker.start();
    } catch (error) {
      collectionWorkerRuntime.state = 'failed';
      collectionWorkerRuntime.lastError = String(error?.message || error).slice(0, 500);
    }
  }
  function taskHistoryKey(taskId, event) {
    return JSON.stringify([taskId, event?.at || null, event?.from || null, event?.to || null,
      event?.reason || null, event?.workerId || null, event?.checkpointSeq || null,
      event?.attempts || null, event?.recovery === true]);
  }
  function taskHistoryEventType(event) {
    if (event?.from === null && event?.to === 'queued') return 'task_created';
    if (event?.reason === 'heartbeat') return 'worker_heartbeat';
    if (event?.reason === 'checkpoint') return 'task_checkpoint';
    if (event?.recovery === true) return 'task_recovered';
    if (event?.to === 'preparing' || event?.to === 'running') return 'stage_started';
    if (event?.to === 'succeeded' || event?.to === 'partial') return 'stage_completed';
    if (event?.to === 'failed' || event?.to === 'blocked') return 'task_failed';
    if (event?.to === 'paused') return 'task_paused';
    if (event?.to === 'cancelled') return 'task_cancelled';
    if (event?.to === 'queued' && event?.reason === 'resumed') return 'task_resumed';
    return 'task_transition';
  }
  function taskHistoryPayload(task, event) {
    return {
      state: task.state,
      from: event?.from ?? null,
      to: event?.to ?? null,
      reason: typeof event?.reason === 'string' ? event.reason.slice(0, 200) : '',
      at: event?.at || null,
      workerId: typeof event?.workerId === 'string' ? event.workerId : null,
      attempts: Number.isSafeInteger(task.attempts) ? task.attempts : null,
      checkpointSeq: Number.isSafeInteger(task.checkpointSeq) ? task.checkpointSeq : null,
      recovery: event?.recovery === true,
      stage: typeof event?.stage === 'string' ? event.stage.slice(0, 120) : null,
    };
  }
  async function syncTaskEvents() {
    if (!taskStore || typeof taskStore.readSnapshot !== 'function' || taskEventSyncPromise) return;
    taskEventSyncPromise = (async () => {
      const snapshotData = await taskStore.readSnapshot();
      const tasks = Array.isArray(snapshotData?.tasks) ? snapshotData.tasks : [];
      for (const task of tasks) {
        if (!task || typeof task.taskId !== 'string' || !Array.isArray(task.history)) continue;
        let seen = taskEventSeen.get(task.taskId);
        const firstObservation = !seen;
        if (!seen) taskEventSeen.set(task.taskId, seen = new Set());
        for (const event of task.history) {
          if (!event || typeof event !== 'object') continue;
          const key = taskHistoryKey(task.taskId, event);
          if (seen.has(key)) continue;
          seen.add(key);
          // Existing tasks at process startup form the baseline.  New tasks
          // and later history entries are emitted as lifecycle events.
          if (!taskEventBaselineReady && firstObservation) continue;
          publishEvent(taskHistoryEventType(event), taskHistoryPayload(task, event), task.taskId);
        }
        // Task history is bounded; discard keys that cannot recur after a
        // restart or truncation while retaining the current history window.
        const currentKeys = new Set(task.history.map((event) => taskHistoryKey(task.taskId, event)));
        for (const key of seen) if (!currentKeys.has(key)) seen.delete(key);
      }
      taskEventBaselineReady = true;
    })().catch(() => {}).finally(() => { taskEventSyncPromise = null; });
    await taskEventSyncPromise;
  }
  async function push(response) {
    try {
      const data = await snapshot();
      const item = { id: String(++eventSequence), event: 'snapshot', data };
      if (!sendEvent(response, item)) response.destroy();
    } catch {
      sendEvent(response, { id: String(++eventSequence), event: 'snapshot-error', data: { error: '快照刷新失败' } });
    }
  }
  void syncTaskEvents();
  const eventTimer = setInterval(() => {
    void syncTaskEvents();
    for (const response of clients) void push(response);
  }, eventIntervalMs).unref();
  const apiRoutes = new Set(['/api/status', '/api/chains', '/api/findings', '/api/vulnerability-chains', '/api/tasks', '/api/sync', '/api/ask', '/api/campaign', '/api/rpc-pool']);
  async function appendReviewAudit(entry) {
    await operations.appendReviewAudit(entry);
  }
  async function route(request, response) {
    const origin = request.headers.origin;
    let originOK = !origin;
    try { if (origin) originOK = loopback.has(new URL(origin).hostname); } catch {}
    const hostname = new URL(`http://${request.headers.host || 'localhost'}`).hostname;
    if (!loopback.has(hostname) || !originOK) return sendJson(response, 403, { error: '只允许本机访问' });
    const requestUrl = new URL(request.url || '/', 'http://localhost');
    const pathname = requestUrl.pathname;
    if ((pathname === '/api/health' || pathname === '/api/v1/health') && request.method === 'GET') {
      if (pathname === '/api/v1/health' && [...requestUrl.searchParams.keys()].length) return sendJson(response, 400, { apiVersion: 'v1', schemaVersion: 2, error: { code: 'unknown_query_parameter', message: '健康接口不接受查询参数' } });
      const initialGeneratedAt = latest?.generatedAt || metrics.lastSnapshotAt;
      const initialSnapshotTimestamp = Date.parse(initialGeneratedAt || '');
      const initialSnapshotStale = !metrics.lastSnapshotAt
        || (Number.isFinite(initialSnapshotTimestamp) && Date.now() - initialSnapshotTimestamp > 60000)
        || Date.now() - Date.parse(metrics.lastSnapshotAt) > 60000;
      if (!latest || initialSnapshotStale) await snapshot().catch(() => {});
      const snapshotGeneratedAt = latest?.generatedAt || metrics.lastSnapshotAt;
      const snapshotTimestamp = Date.parse(snapshotGeneratedAt || '');
      const stale = !metrics.lastSnapshotAt || (Number.isFinite(snapshotTimestamp) && Date.now() - snapshotTimestamp > 60000) || Date.now() - Date.parse(metrics.lastSnapshotAt) > 60000;
      const sourceReportAt = latest?.lastReportAt || null;
      const sourceReportTimestamp = Date.parse(sourceReportAt || '');
      const campaign = latest?.campaign || null;
      const campaignState = typeof campaign?.state === 'string' ? campaign.state : null;
      const campaignUpdatedAt = campaign?.updatedAt || null;
      const sourceReportAgeMs = Number.isFinite(sourceReportTimestamp) ? Math.max(0, Date.now() - sourceReportTimestamp) : null;
      const dataState = campaignState === 'interrupted' ? 'interrupted' : campaignState === 'running' ? 'running' : sourceReportAgeMs !== null && sourceReportAgeMs > 24 * 60 * 60 * 1000 ? 'historical' : 'current';
      return sendJson(response, 200, {
        apiVersion: pathname === '/api/v1/health' ? 'v1' : undefined,
        schemaVersion: 2, instanceId, sourceFingerprint, status: stale || metrics.lastSnapshotError ? 'degraded' : 'ok',
        now: new Date().toISOString(), startedAt: new Date(started).toISOString(), uptimeSec: (Date.now() - started) / 1000,
        requests: { total: metrics.total, failures: metrics.failures, clientErrors: metrics.clientErrors, active: metrics.active }, sseClients: clients.size,
        snapshots: { reads: metrics.snapshotReads, failures: metrics.snapshotFailures, lastBuiltAt: metrics.lastSnapshotAt, generatedAt: snapshotGeneratedAt || null, sourceReportAt, syncVersion: latest?.syncVersion || null, lastError: metrics.lastSnapshotError, stale },
        dataFreshness: { state: dataState, campaignState, campaignUpdatedAt, sourceReportAt, sourceReportAgeMs, interpretation: '服务在线不等于采集或分析数据已完成；请同时查看 dataFreshness 和 progress。' },
        memory: process.memoryUsage(),
        resources: await resourceUsage(),
        events: { nextId: String(eventSequence + 1), retained: eventHistory.length, retentionLimit: SSE_HISTORY_LIMIT },
        dsh: { available: false, endpoint: null, calls: 0, failures: 0, active: 0, syncVersion: latest?.syncVersion, updatedAt: latest?.generatedAt },
        cloudAI: { configured: latest?.model?.configured === true, provider: 'external_cloud_ai', model: latest?.model?.model || null, baseUrlHost: latest?.model?.baseUrlHost || null, calls: metrics.cloudAiCalls, failures: metrics.cloudAiFailures, active: metrics.cloudAiActive, syncVersion: latest?.syncVersion, updatedAt: latest?.generatedAt },
        workers: { collection: workerStatus() },
        progress: latest?.progress || latest?.campaign?.progress || null,
      });
    }
    if (pathname === '/api/v1/capabilities' && request.method === 'GET') {
      if ([...requestUrl.searchParams.keys()].length) return sendJson(response, 400, { apiVersion: 'v1', schemaVersion: 1, error: { code: 'unknown_query_parameter', message: '能力清单不接受查询参数' } });
      return sendJson(response, 200, { apiVersion: 'v1', schemaVersion: 1, generatedAt: new Date().toISOString(), capabilities: { ...API_V1_CAPABILITIES, collection: { ...API_V1_CAPABILITIES.collection, runtimeState: workerStatus().state } }, workers: { collection: workerStatus() }, interpretation: 'executionState 表示已有处理器实现；runtimeState 和 workers.collection 表示当前进程是否正在运行。不可用或未生成的数据保持显式缺失状态。' });
    }
    if (pathname === '/api/v1/corpus' || pathname.startsWith('/api/v1/corpus/')) {
      const requestId = randomUUID();
      try {
        const body = ['POST', 'PUT', 'PATCH'].includes(request.method) ? await parseBody(request) : null;
        const result = await corpusControl.handle(request, requestUrl, body);
        if (!result) return sendJson(response, 404, { apiVersion: 'v1', schemaVersion: 1, generatedAt: new Date().toISOString(), error: { code: 'not_found', message: '语料控制台接口不存在', requestId } });
        return sendJson(response, result.status, result.body);
      } catch (error) {
        const failure = corpusErrorBody(error, requestId);
        return sendJson(response, failure.status, failure.body);
      }
    }
    if (/^\/api\/v1\/(projects|contracts|collection|collections|bytecode|decompile|decompilations)(?:\/|$)/.test(pathname)) {
      const requestId = randomUUID();
      try {
        const body = request.method === 'POST' ? await parseBody(request, 12 * 1024 * 1024) : null;
        // 离线阶段后端拒绝链上采集启动请求：前端置灰只是提示，真正的拒绝在后端。
        if (!chainCollectionOn && isChainCollectionStart(pathname, request.method, body)) {
          throw new TaskApiV1Error('chain_collection_disabled', '离线阶段不开放链上采集，链上采集启动请求已被后端拒绝。', 400);
        }
        const result = await projectResourceApi({ method: request.method, pathname, searchParams: requestUrl.searchParams, body, requestId });
        if (result) return sendJson(response, result.status, result.body);
      } catch (error) {
        const wrapped = error instanceof TaskApiV1Error ? error : new TaskApiV1Error('invalid_request', String(error?.message || '资源请求失败'), error?.status || 400);
        const failure = taskErrorBody(wrapped, requestId);
        return sendJson(response, failure.status, failure.body);
      }
    }
    if (/^\/api\/v1\/(analysis|scans|findings|evidence|replay|reports)(?:\/|$)/.test(pathname)) {
      const requestId = randomUUID();
      let analysisRequest = request;
      if (request.method === 'PATCH' && /^\/api\/v1\/findings\/[^/]+\/triage$/.test(pathname)) {
        analysisRequest = {
          method: request.method, url: request.url, headers: request.headers,
          requestId, body: await parseBody(request, 16 * 1024),
        };
      }
      const result = await handleAnalysisResource(analysisRequest, {
        taskStore, resourceOperations: operations, snapshotProvider, evidenceRoot, projectRoot: PROJECT_ROOT,
        onFindingTriage: (event) => publishEvent('finding_triage_updated', event),
      }, requestUrl);
      if (result) return result.raw ? sendRaw(response, result) : sendJson(response, result.status, result.body);
    }
    if (/^\/api\/v1\/(workers|rules|invariants|reviews\/audit)(?:\/|$)/.test(pathname)) {
      const requestId = randomUUID();
      const body = ['POST', 'PUT', 'PATCH'].includes(request.method) ? await parseBody(request) : null;
      const result = await operationsResourceRoute(request, requestUrl, body, operations, requestId);
      if (result) return result.status === 204 ? (response.writeHead(204, securityHeaders), response.end()) : sendJson(response, result.status, result.body);
    }
    if (pathname === '/api/v1/reviews/evaluate') {
      const requestId = randomUUID();
      try {
        if (request.method !== 'POST') throw new TaskApiV1Error('method_not_allowed', '审查评估只支持 POST', 405);
        if ([...requestUrl.searchParams.keys()].length) throw new TaskApiV1Error('unknown_query_parameter', '该审查接口不接受查询参数');
        const body = await parseBody(request, 12 * 1024 * 1024);
        if (!body || typeof body !== 'object' || Array.isArray(body)) throw new TaskApiV1Error('invalid_request', '审查请求必须是 JSON 对象');
        const unknown = Object.keys(body).filter((key) => !['manifest', 'review', 'checks'].includes(key));
        if (unknown.length) throw new TaskApiV1Error('unknown_field', `审查请求包含未知字段：${unknown.join(', ')}`);
        if (!body.manifest || !body.review) throw new TaskApiV1Error('missing_review_input', '需要 manifest 和 review');
        const gate = evaluateMergeGate({ manifest: body.manifest, review: body.review, checks: body.checks === undefined ? [] : body.checks });
        const review = body.review;
        const severities = Object.fromEntries(REVIEW_SEVERITIES.map((severity) => [severity, review.findings.filter((finding) => finding.severity === severity).length]));
        try {
          await appendReviewAudit({ at: new Date().toISOString(), requestId, manifestSha256: gate.manifestSha256, decision: review.decision, allowed: gate.allowed, reasonCodes: gate.reasons.map((reason) => reason.code), findingCount: review.findings.length, severities });
        } catch (error) {
          throw Object.assign(new Error('审查审计写入失败'), { status: 500, code: 'audit_write_failed', cause: error });
        }
        return sendJson(response, 200, taskEnvelope({ data: gate, requestId }));
      } catch (error) {
        const failure = taskErrorBody(error instanceof TaskApiV1Error ? error : wrapTaskV1Error(error), requestId);
        return sendJson(response, failure.status, failure.body);
      }
    }
    if (pathname === '/api/events' && request.method === 'GET') {
      if (clients.size >= 16) return sendJson(response, 503, { error: '实时连接已满' });
      response.writeHead(200, { ...securityHeaders, 'content-type': 'text/event-stream; charset=utf-8', connection: 'keep-alive', 'x-accel-buffering': 'no' });
      response.write('retry: 3000\n\n');
      clients.add(response);
      response.once('close', () => clients.delete(response));
      const lastEventId = Number.parseInt(request.headers['last-event-id'] || requestUrl.searchParams.get('since') || '', 10);
      if (Number.isSafeInteger(lastEventId) && lastEventId >= 0) {
        for (const item of eventHistory) if (Number(item.id) > lastEventId && !sendEvent(response, item)) break;
      }
      await push(response);
      return;
    }
    if (pathname === '/api/v1/tasks' || pathname.startsWith('/api/v1/tasks/')) {
      const requestId = randomUUID();
      try {
        const body = ['POST', 'PUT', 'PATCH'].includes(request.method) ? await parseBody(request) : null;
        // 离线阶段后端拒绝链上采集任务创建：类型命中采集语义时直接拒绝。
        if (!chainCollectionOn && isChainCollectionStart(pathname, request.method, body)) {
          throw new TaskApiV1Error('chain_collection_disabled', '离线阶段不开放链上采集，链上采集启动请求已被后端拒绝。', 400);
        }
        const result = await taskRouteV1(taskStore, request, requestUrl, body, evidenceRoot, withReportReadSlot, withArtifactReadSlot);
        if (!result) return sendJson(response, 404, taskEnvelope({ error: { code: 'not_found', message: '任务接口不存在', requestId } }));
        return sendJson(response, result.status, result.body);
      } catch (error) {
        const wrapped = wrapTaskV1Error(classifyTaskError(error));
        const failure = taskErrorBody(wrapped, requestId);
        return sendJson(response, failure.status, failure.body);
      }
    }
    if (pathname === '/api/tasks' || pathname.startsWith('/api/tasks/')) {
      if (pathname !== '/api/tasks' || request.method !== 'GET') {
        const body = ['POST', 'PUT', 'PATCH'].includes(request.method) ? await parseBody(request) : null;
        let result;
        try { result = await taskRoute(taskStore, pathname, request.method, body); }
        catch (error) { throw classifyTaskError(error); }
        if (!result) return sendJson(response, 404, { error: '任务接口不存在' });
        if (result?.tasks) {
          const data = await snapshot();
          return sendJson(response, 200, { generatedAt: data.generatedAt, activeTask: data.activeTask, activeChain: data.activeChain, queue: data.queue, tasks: result.tasks });
        }
        return sendJson(response, 200, { ...result, generatedAt: new Date().toISOString() });
      }
    }
    if (apiRoutes.has(pathname)) {
      if (request.method !== (pathname === '/api/ask' ? 'POST' : 'GET')) return sendJson(response, 405, { error: '请求方法不支持' });
      const body = pathname === '/api/ask' ? await parseBody(request) : null;
      if (pathname === '/api/ask' && (!body || typeof body !== 'object' || Array.isArray(body) || typeof (body.question ?? body.prompt) !== 'string' || (body.useModel !== undefined && typeof body.useModel !== 'boolean'))) return sendJson(response, 400, { error: '需要 question 文本和可选 useModel 布尔值' });
      const question = body ? String(body.question || body.prompt || '').trim() : null;
      if (body && (!question || question.length > 2000)) return sendJson(response, 400, { error: '问题长度需为 1–2000 字' });
      const data = await snapshot();
      if (pathname === '/api/status') return sendJson(response, 200, data);
      if (pathname === '/api/campaign') return sendJson(response, 200, { generatedAt: data.generatedAt, campaign: data.campaign });
      if (pathname === '/api/rpc-pool') return sendJson(response, 200, { generatedAt: data.generatedAt, rpcPool: data.rpcPool });
      if (pathname === '/api/chains') return sendJson(response, 200, { generatedAt: data.generatedAt, chains: data.chains, queue: data.queue });
      if (pathname === '/api/findings') return sendJson(response, 200, { generatedAt: data.generatedAt, findings: data.findings, highPriorityFindings: data.highPriorityFindings, staticAnalysis: data.staticAnalysis });
      if (pathname === '/api/vulnerability-chains') return sendJson(response, 200, { generatedAt: data.generatedAt, vulnerabilityChains: data.vulnerabilityChains, totals: { tested: data.totals.testedChains, highSignal: data.totals.highSignalChains } });
      if (pathname === '/api/tasks') {
        const tasks = taskStore ? await taskStore.list() : [];
        return sendJson(response, 200, { generatedAt: data.generatedAt, activeTask: data.activeTask, activeChain: data.activeChain, queue: data.queue, tasks });
      }
      if (pathname === '/api/sync') return sendJson(response, 200, { generatedAt: data.generatedAt, syncVersion: data.syncVersion, activeTask: data.activeTask, activeChain: data.activeChain, totals: data.totals, progress: data.progress, model: data.model, unifiedIR: data.staticAnalysis.unifiedIR, localSecurityTests: data.staticAnalysis.localSecurityTests, soak: data.soak, campaign: data.campaign, rpcPool: data.rpcPool, consumers: ['dsh', 'dhlsh'], intendedConsumers: ['dsh', 'dhlsh'], consumptionVerified: false, consumerAcknowledgements: { dsh: null, dhlsh: null } });
      const answer = {
        ...answerQuestion(data, question),
        asOf: data.generatedAt,
        sourceReportAt: data.lastReportAt,
        soakUpdatedAt: data.soak?.updatedAt || null,
        syncVersion: data.syncVersion,
        timeSemantics: 'asOf=当前快照生成时间；sourceReportAt=源报告时间；soakUpdatedAt=稳定性观测更新时间',
      };
      if (body.useModel !== true) return sendJson(response, 200, answer);
      const configuration = cloudAiConfiguration();
      if (!configuration) return sendJson(response, 200, { ...answer, explanation: null, reason: 'cloud_ai_not_configured' });
      if (metrics.cloudAiActive) return sendJson(response, 200, { ...answer, explanation: null, reason: 'cloud_ai_busy' });
      metrics.cloudAiActive++; metrics.cloudAiCalls++;
      const controller = new AbortController();
      const abort = () => { if (!response.writableEnded) controller.abort(); };
      response.once('close', abort);
      try {
        const context = {
          activeTask: data.activeTask ? { id: data.activeTask.id, status: data.activeTask.status } : null,
          activeChain: data.activeChain ? { name: data.activeChain.name, chainId: data.activeChain.chainId } : null,
          progress: data.progress || null,
          generatedAt: data.generatedAt,
          sourceReportAt: data.lastReportAt,
          soakUpdatedAt: data.soak?.updatedAt || null,
        };
        const modelAnswer = explanationProvider
          ? await explanationProvider(question, context, controller.signal, { provider: 'external_cloud_ai', model: configuration.model })
          : await callExternalCloudAi(question, context, controller.signal, configuration);
        const manifestSha256 = modelAnswer.evidence?.manifestSha256 || createHash('sha256').update(JSON.stringify({ question, context, model: configuration.model })).digest('hex');
        const responseSha256 = modelAnswer.evidence?.responseSha256 || createHash('sha256').update(String(modelAnswer.explanation || modelAnswer.answer || '')).digest('hex');
        return sendJson(response, 200, { ...answer, explanation: modelAnswer.explanation || modelAnswer.answer || null, provider: 'external_cloud_ai', model: modelAnswer.model || configuration.model, manifestSha256, responseSha256, mode: 'cloud_ai' });
      } catch {
        metrics.cloudAiFailures++;
        return sendJson(response, 200, { ...answer, explanation: null, reason: 'cloud_ai_unavailable' });
      } finally { metrics.cloudAiActive--; response.removeListener('close', abort); }
    }
    if (pathname.startsWith('/api/')) return sendJson(response, 404, { error: '接口不存在' });
    if (!assets.has(pathname) || !['GET', 'HEAD'].includes(request.method)) return sendJson(response, 404, { error: '页面不存在' });
    const file = pathname === '/' ? 'index.html' : pathname.slice(1);
    const bytes = await assetReaders.get(pathname)();
    if (response.destroyed || response.writableEnded) return;
    response.writeHead(200, { ...securityHeaders, 'content-type': mime[extname(file)], 'content-length': bytes.length });
    response.end(request.method === 'HEAD' ? undefined : bytes);
  }
  const server = createServer((request, response) => {
    metrics.total++; metrics.active++;
    let settled = false;
    const done = () => {
      if (settled) return; settled = true; metrics.active--;
      if (response.statusCode >= 500) metrics.failures++;
      else if (response.statusCode >= 400) metrics.clientErrors++;
    };
    response.once('finish', done); response.once('close', done);
    route(request, response).catch((error) => {
      if (!response.headersSent) sendJson(response, error.status || 500, { error: error.status ? error.message : '状态读取失败' });
      else response.destroy();
    });
  });
  server.requestTimeout = 15000; server.headersTimeout = 10000;
  server.on('close', () => { clearInterval(eventTimer); for (const client of clients) client.destroy(); clients.clear(); });
  server.collectionWorker = collectionWorker;
  server.collectionWorkerStatus = workerStatus;
  server.stop = () => {
    if (collectionWorkerStopPromise) return collectionWorkerStopPromise;
    clearInterval(eventTimer);
    for (const client of clients) client.end();
    collectionWorkerStopPromise = (async () => {
      if (collectionWorker) {
        try {
          await collectionWorker.stop({ abort: true, wait: true, timeoutMs: Math.max(10_000, collectionWorkerMaxHandlerRuntimeMs + 1_000) });
        } catch (error) {
          collectionWorkerRuntime.state = 'failed';
          collectionWorkerRuntime.lastError = String(error?.message || error).slice(0, 500);
        }
      }
      if (server.listening) await new Promise((resolveClose) => server.close(resolveClose));
    })();
    return collectionWorkerStopPromise;
  };
  server.publishEvent = publishEvent;
  server.listen(port, host, () => console.log(`区块链安全：http://${host}:${server.address().port}`));
  return server;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const taskStore = new TaskStateStore({ path: join(PROJECT_ROOT, 'work', 'task-state.json') });
  // 离线阶段（代号 LaneW）：默认不启动链上采集 worker，且后端拒绝链上采集启动请求。
  // 需要显式设置 WEB_COLLECTION_WORKER=1 与 CORPUS_CHAIN_COLLECTION=1 才放开。
  const workerEnabled = ['1', 'true', 'on', 'yes'].includes(String(process.env.WEB_COLLECTION_WORKER || '').toLowerCase());
  const chainEnabled = ['1', 'true', 'on', 'yes'].includes(String(process.env.CORPUS_CHAIN_COLLECTION || '').toLowerCase());
  const server = startServer({
    sourceFingerprint: await runtimeFingerprint(),
    taskStore,
    startCollectionWorker: workerEnabled,
    chainCollectionEnabled: chainEnabled,
  });
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => { void server.stop().finally(() => process.exit(0)); });
}
