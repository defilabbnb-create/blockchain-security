import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { lstat, open, readFile, realpath } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { parseExpectedRevision, taskEnvelope, taskConsistency } from './task-api-v1.js';
import { TASK_STATES } from './task-state.js';
import { buildStableFindingId, normalizeFindingEvidence } from './vulnerability-evidence.js';
import { replayEvidenceStatus, verifyReplayArtifact } from './replay-artifact.js';
import { FINDING_TRIAGE_STATUSES, normalizeFindingTriagePatch } from './finding-triage.js';
import { exportReport } from './report-export.js';

// Read-only resource routes for the analysis evidence that already exists on
// disk.  The web server deliberately owns route registration; this module is
// a small dependency-injected router so it can also be used by other clients.
export const ANALYSIS_RESOURCE_NAMES = Object.freeze(['analysis', 'scans', 'findings', 'evidence', 'replay', 'reports']);
const SHA256 = /^[a-f0-9]{64}$/;
const TASK_TYPES = new Set(['analysis', 'local-source-analysis']);
const SEVERITIES = new Set(['High', 'Medium', 'Low', 'Informational', 'Critical']);
const EVIDENCE_STATES = new Set(['insufficient', 'hypothesis', 'observed', 'reproduced', 'confirmed', 'rejected']);
const MAX_RESOURCE_REPORT_BYTES = 64 * 1024 * 1024;

export class AnalysisResourceApiError extends Error {
  constructor(code, message, status = 400, details = undefined) {
    super(message);
    this.name = 'AnalysisResourceApiError';
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

function fail(code, message, status = 400, details) { throw new AnalysisResourceApiError(code, message, status, details); }
function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
}
function sha(value) { return createHash('sha256').update(typeof value === 'string' || Buffer.isBuffer(value) ? value : canonical(value)).digest('hex'); }
function clone(value) { return value === undefined ? undefined : JSON.parse(JSON.stringify(value)); }
function pathInside(root, candidate) {
  const base = resolve(root), value = resolve(candidate);
  return value === base || value.startsWith(`${base}/`);
}
function decodeId(value, label = 'resource id', { allowSlash = false } = {}) {
  try {
    const decoded = decodeURIComponent(value);
    if (!decoded || decoded.length > 300 || decoded.includes('\0') || (!allowSlash && decoded.includes('/'))) fail('invalid_id', `${label} 无效`, 422);
    return decoded;
  } catch { fail('invalid_id', `${label} 编码无效`, 422); }
}
function one(search, name) {
  const values = search.getAll(name);
  if (values.length > 1) fail('duplicate_query_parameter', `查询参数重复：${name}`, 422);
  return values[0];
}
function pageQuery(search, allowed, filters = {}) {
  for (const key of new Set(search.keys())) if (!allowed.has(key)) fail('unknown_query_parameter', `不支持的查询参数：${key}`, 422);
  const limitText = one(search, 'limit');
  let limit = 100;
  if (limitText !== undefined) {
    if (!/^\d+$/.test(limitText) || (limit = Number(limitText)) < 1 || limit > 1000 || !Number.isSafeInteger(limit)) fail('invalid_limit', 'limit 必须是 1..1000 的整数', 422);
  }
  const cursor = one(search, 'cursor');
  if (cursor !== undefined && (cursor.length < 1 || cursor.length > 512)) fail('invalid_cursor', 'cursor 无效', 422);
  return { ...filters, limit, ...(cursor === undefined ? {} : { cursor }) };
}
function cursorFor(index, filterKey, revision) { return Buffer.from(JSON.stringify({ index, filterKey, revision }), 'utf8').toString('base64url'); }
function decodeCursor(value, filterKey, revision) {
  if (value === undefined) return 0;
  let decoded;
  try { decoded = JSON.parse(Buffer.from(value, 'base64url').toString('utf8')); } catch { fail('invalid_cursor', 'cursor 无效', 422); }
  if (!decoded || !Number.isSafeInteger(decoded.index) || decoded.index < 0 || typeof decoded.filterKey !== 'string' || typeof decoded.revision !== 'string') fail('invalid_cursor', 'cursor 无效', 422);
  if (decoded.filterKey !== filterKey) fail('invalid_cursor', 'cursor 与当前过滤条件不匹配', 422);
  if (decoded.revision !== revision) fail('stale_cursor', '数据已变化，请从第一页重新读取', 409);
  return decoded.index;
}
function revisionRows(items) {
  return items.map((item) => {
    if (!item || typeof item !== 'object' || Array.isArray(item)) return item;
    const { snapshotGeneratedAt, ...stable } = item;
    return stable;
  });
}
function dataRevision(stateRevision, items, snapshotRevision = null) {
  return sha({ stateRevision, snapshotRevision, items: revisionRows(items) });
}
function paginate(items, query, filterInput, revision) {
  const filterKey = sha(filterInput);
  const start = decodeCursor(query.cursor, filterKey, revision);
  const page = items.slice(start, start + query.limit);
  const hasMore = start + page.length < items.length;
  return { items: clone(page), page: { limit: query.limit, hasMore, nextCursor: hasMore ? cursorFor(start + page.length, filterKey, revision) : null } };
}
function response(data, status = 200, revision = undefined, generatedAt = new Date().toISOString()) {
  const body = taskEnvelope(data && Object.hasOwn(data, 'items') ? { ...data, data } : { data }, generatedAt);
  if (revision !== undefined) body.consistency = taskConsistency(revision, generatedAt);
  return { status, body };
}
function rawReportResponse(report, format, { taskId, sha256, revision }) {
  const exported = exportReport(report, format, { taskId, sourceSha256: sha256 });
  const safeId = String(taskId || 'report').replace(/[^a-zA-Z0-9._-]+/g, '_').slice(0, 96) || 'report';
  return {
    status: 200,
    raw: {
      body: exported.body,
      contentType: exported.contentType,
      contentDisposition: `attachment; filename="${safeId}.${exported.format === 'sarif' ? 'sarif' : exported.format === 'html' ? 'html' : 'json'}"`,
      sourceSha256: sha256,
      taskId: taskId || null,
      revision,
    },
  };
}
function errorResponse(error, requestId) {
  const status = error?.status || 400;
  return { status, body: taskEnvelope({ error: { code: error?.code || (status === 404 ? 'not_found' : 'invalid_request'), message: String(error?.message || '请求失败'), ...(requestId ? { requestId } : {}) } }) };
}
function requestUrl(request, supplied) {
  if (supplied instanceof URL) return supplied;
  if (typeof supplied === 'string') return new URL(supplied, 'http://localhost');
  return new URL(request.url || '/', 'http://localhost');
}
async function readTasks(taskStore) {
  if (!taskStore) return { revision: 0, tasks: [] };
  if (typeof taskStore.readSnapshot === 'function') return taskStore.readSnapshot();
  if (typeof taskStore.listPage === 'function') {
    const result = await taskStore.listPage({ limit: 1000 });
    return { revision: result.revision, tasks: result.items || result.page || [] };
  }
  if (typeof taskStore.list === 'function') return { revision: 0, tasks: await taskStore.list({ limit: 1000 }) };
  fail('task_store_unavailable', '任务状态存储不可用', 503);
}
async function readTask(taskStore, taskId) {
  if (!taskStore) return null;
  if (typeof taskStore.readTask === 'function') return (await taskStore.readTask(taskId)).task || null;
  if (typeof taskStore.get === 'function') return taskStore.get(taskId);
  const snapshot = await readTasks(taskStore);
  return snapshot.tasks.find((task) => task.taskId === taskId) || null;
}
function analysisTask(task) { return task && TASK_TYPES.has(task.type); }
function taskView(task) {
  return { taskId: task.taskId, type: task.type, state: task.state, priority: task.priority, createdAt: task.createdAt, updatedAt: task.updatedAt, attempts: task.attempts, maxAttempts: task.maxAttempts, checkpointSeq: task.checkpointSeq, checkpointedAt: task.checkpointedAt || null, hasReport: Boolean(task.checkpoint?.reportPath && task.checkpoint?.reportSha256), error: task.error || null };
}
function findingView(finding, snapshot) {
  const source = finding.source || finding.first_markdown_element || null;
  const findingId = finding.findingId || buildStableFindingId({ chainId: finding.chainId || finding.target || 'unknown', target: finding.target, check: finding.check, source, impact: finding.impact, element: finding.element || finding.contract });
  return { ...clone(finding), findingId, severity: finding.severity || finding.impact || 'Informational', status: finding.evidenceStatus || finding.status || 'hypothesis', confirmed: finding.confirmed === true, snapshotGeneratedAt: snapshot?.generatedAt || null };
}
function findingsFromSnapshot(snapshot) {
  const staticRows = Array.isArray(snapshot?.findings) ? snapshot.findings : [];
  const rows = staticRows.map((item) => findingView(item, snapshot));
  for (const chain of Array.isArray(snapshot?.vulnerabilityChains) ? snapshot.vulnerabilityChains : []) {
    for (const evidence of Array.isArray(chain?.evidence) ? chain.evidence : []) {
      const row = findingView({ ...evidence, chainId: chain.chainId || chain.id || chain.title, target: evidence.target || chain.title, check: evidence.check || chain.title, impact: evidence.impact || chain.severity, source: evidence.source, findingId: evidence.findingId || chain.findingId }, snapshot);
      if (!rows.some((existing) => existing.findingId === row.findingId)) rows.push(row);
    }
  }
  return rows;
}
function evidenceFromSnapshot(snapshot) {
  const rows = [];
  for (const chain of Array.isArray(snapshot?.vulnerabilityChains) ? snapshot.vulnerabilityChains : []) {
    for (const item of Array.isArray(chain?.evidence) ? chain.evidence : []) {
      const findingId = item.findingId || chain.findingId || buildStableFindingId({ chainId: chain.chainId || chain.id || chain.title, target: item.target || chain.title, check: item.check || chain.title, source: item.source, impact: item.impact || chain.severity });
      const evidenceId = item.evidenceId || `evidence-${sha({ findingId, item }).slice(0, 24)}`;
      rows.push({ ...clone(item), evidenceId, findingId, status: item.evidenceStatus || item.status || 'hypothesis', confirmed: item.confirmed === true });
    }
  }
  for (const finding of Array.isArray(snapshot?.findings) ? snapshot.findings : []) {
    const normalized = normalizeFindingEvidence({ chainId: finding.chainId || finding.target, target: finding.target, finding });
    const findingId = finding.findingId || normalized.findingId;
    if (!rows.some((row) => row.findingId === findingId)) rows.push({ ...normalized, evidenceId: `evidence-${sha(normalized).slice(0, 24)}` });
  }
  return rows;
}
async function safeBoundReport(task, evidenceRoot, reportReader) {
  const checkpoint = task?.checkpoint;
  if (!checkpoint || typeof checkpoint !== 'object' || !checkpoint.reportPath || !checkpoint.attemptDirectory || !SHA256.test(String(checkpoint.reportSha256 || '')) || !Number.isSafeInteger(checkpoint.reportBytes) || checkpoint.reportBytes < 0) fail('evidence_not_ready', '任务没有可读取的报告 checkpoint', 409);
  if (typeof reportReader === 'function') {
    const value = await reportReader(task, checkpoint);
    if (!value || typeof value !== 'object' || !value.report) fail('invalid_report', '报告读取器返回了无效报告', 422);
    if (value.sha256 && value.sha256 !== checkpoint.reportSha256) fail('report_integrity_mismatch', '报告 SHA-256 与 checkpoint 不一致', 409);
    return { report: clone(value.report), sha256: value.sha256 || checkpoint.reportSha256, bytes: value.bytes ?? checkpoint.reportBytes };
  }
  if (!evidenceRoot || typeof evidenceRoot !== 'string') fail('evidence_unavailable', '分析证据根目录未配置', 503);
  const root = resolve(evidenceRoot), taskDir = join(root, sha(task.taskId)), attemptDir = resolve(taskDir, basename(checkpoint.attemptDirectory));
  const reportPath = resolve(attemptDir, 'static-analysis.json');
  if (!pathInside(root, taskDir) || !pathInside(taskDir, attemptDir) || !pathInside(attemptDir, reportPath) || resolve(checkpoint.attemptDirectory) !== attemptDir || resolve(checkpoint.reportPath) !== reportPath) fail('invalid_evidence_checkpoint', '分析证据路径超出任务绑定目录', 403);
  try {
    const rootInfo = await lstat(root); if (rootInfo.isSymbolicLink() || !rootInfo.isDirectory()) fail('invalid_evidence_root', '分析证据根目录无效', 403);
    const canonicalRoot = await realpath(root), canonicalTask = await realpath(taskDir), canonicalAttempt = await realpath(attemptDir), canonicalReport = await realpath(reportPath);
    if (canonicalTask !== join(canonicalRoot, sha(task.taskId)) || canonicalAttempt !== join(canonicalTask, basename(attemptDir)) || canonicalReport !== join(canonicalAttempt, 'static-analysis.json')) fail('invalid_evidence_path', '分析证据路径包含符号链接', 403);
    const info = await lstat(reportPath); if (info.isSymbolicLink() || !info.isFile()) fail('invalid_evidence_file', '分析报告必须是普通文件', 403);
    const bytes = await readFile(reportPath);
    if (bytes.length !== checkpoint.reportBytes || sha(bytes) !== checkpoint.reportSha256) fail('report_integrity_mismatch', '分析报告内容与 checkpoint 固定指纹不一致', 409);
    let report; try { report = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { fail('invalid_report', '分析报告不是有效 JSON', 422); }
    if (!report || typeof report !== 'object' || Array.isArray(report)) fail('invalid_report', '分析报告 JSON 必须是对象', 422);
    return { report, sha256: checkpoint.reportSha256, bytes: bytes.length };
  } catch (error) {
    if (error instanceof AnalysisResourceApiError) throw error;
    if (error.code === 'ENOENT' || error.code === 'ENOTDIR') fail('report_not_found', '分析报告不存在', 404);
    throw error;
  }
}
async function reportsFromTasks(taskStore, evidenceRoot, reportReader) {
  const state = await readTasks(taskStore);
  const items = [];
  for (const task of state.tasks.filter(analysisTask)) {
    const checkpoint = task.checkpoint;
    items.push({ reportId: task.taskId, taskId: task.taskId, state: task.state, createdAt: task.createdAt, updatedAt: task.updatedAt, sha256: checkpoint?.reportSha256 || null, bytes: checkpoint?.reportBytes ?? null, available: Boolean(checkpoint?.reportPath && checkpoint?.reportSha256), path: checkpoint?.reportPath || null });
  }
  return { state, items };
}
async function artifactsFromTasks(taskStore, evidenceRoot, reportReader) {
  const state = await readTasks(taskStore), items = [];
  for (const task of state.tasks.filter(analysisTask)) {
    if (!task.checkpoint?.reportPath) continue;
    let loaded; try { loaded = await safeBoundReport(task, evidenceRoot, reportReader); } catch (error) { if (error.code === 'report_not_found' || error.code === 'evidence_not_ready') continue; throw error; }
    const candidates = [];
    if (loaded.report?.replay && typeof loaded.report.replay === 'object') candidates.push(loaded.report.replay);
    if (Array.isArray(loaded.report?.replayArtifacts)) candidates.push(...loaded.report.replayArtifacts);
    for (const artifact of candidates) {
      if (!verifyReplayArtifact(artifact)) continue;
      // Derived status is exposed beside the immutable artifact. It is not
      // inserted into the artifact itself, so its SHA-256 remains verifiable.
      items.push({ ...clone(artifact), taskId: task.taskId, replayEvidence: replayEvidenceStatus(artifact.replay) });
    }
  }
  return { state, items };
}

export function createAnalysisResourceApi({ taskStore = null, resourceOperations = null, snapshotProvider = async () => ({}), evidenceRoot = null, reportReader = null, projectRoot = process.cwd(), onFindingTriage = null } = {}) {
  if (typeof snapshotProvider !== 'function') throw new TypeError('snapshotProvider must be a function');
  if (onFindingTriage !== null && typeof onFindingTriage !== 'function') throw new TypeError('onFindingTriage must be a function');
  return async function analysisResourceRoute(request = {}, suppliedUrl = undefined) {
    const url = requestUrl(request, suppliedUrl), method = String(request.method || 'GET').toUpperCase();
    const triageMatch = url.pathname.match(/^\/api\/v1\/findings\/([^/]+)\/triage$/);
    const match = triageMatch
      ? ['findings', 'findings', triageMatch[1], 'triage']
      : url.pathname.match(/^\/api\/v1\/(analysis|scans|findings|evidence|replay|reports)(?:\/(.+))?$/);
    if (!match) return null;
    const resource = match[1], id = match[2] ? decodeId(match[2], `${resource} id`, { allowSlash: resource === 'reports' }) : null;
    const triageAction = match[3] === 'triage';
    if (triageAction && (resource !== 'findings' || !id)) fail('not_found', '漏洞处置路径不存在', 404);
    if (triageAction && method === 'PATCH') {
      if ([...url.searchParams.keys()].length) fail('unknown_query_parameter', '处置更新不接受查询参数', 422);
      if (!resourceOperations || typeof resourceOperations.updateFindingTriage !== 'function') fail('triage_unavailable', '漏洞处置存储不可用', 503);
      let patch;
      try { patch = normalizeFindingTriagePatch(request.body); }
      catch (error) { fail('invalid_finding_triage', error.message, 400); }
      let expectedRevision;
      try { expectedRevision = parseExpectedRevision(request, null); }
      catch (error) { fail(error.code || 'missing_revision', error.message, error.status || 400); }
      let snapshot;
      try { snapshot = await snapshotProvider(); }
      catch { fail('internal_error', '分析快照暂时不可用', 503); }
      if (!findingsFromSnapshot(snapshot).some((item) => item.findingId === id || item.id === id)) fail('not_found', `漏洞不存在：${id}`, 404);
      let updated;
      try { updated = await resourceOperations.updateFindingTriage(id, patch, { expectedRevision, requestId: request.requestId }); }
      catch (error) { fail(error.code || 'triage_update_failed', error.message || '漏洞处置更新失败', error.status || 400); }
      try { onFindingTriage?.({ findingId: id, triageStatus: updated.triage.triageStatus, updatedAt: updated.triage.updatedAt }); } catch {}
      return response({ findingId: id, triage: updated.triage }, 200, updated.revision, updated.consistency.asOf);
    }
    if (triageAction) fail('method_not_allowed', '漏洞处置只支持 PATCH', 405);
    if (method !== 'GET') fail('method_not_allowed', `${resource} 资源只支持 GET`, 405);
    let snapshot;
    try { snapshot = await snapshotProvider(); }
    catch { fail('internal_error', '分析快照暂时不可用', 503); }
    const state = await readTasks(taskStore);
    if (resource === 'analysis') {
      const tasks = state.tasks.filter(analysisTask);
      if (id) { const task = tasks.find((item) => item.taskId === id); if (!task) fail('not_found', `分析任务不存在：${id}`, 404); return response({ analysis: taskView(task) }, 200, state.revision); }
      const query = pageQuery(url.searchParams, new Set(['state', 'limit', 'cursor']), { state: one(url.searchParams, 'state') });
      if (query.state !== undefined && !TASK_STATES.includes(query.state)) fail('invalid_state', `未知任务状态：${query.state}`, 422);
      const filtered = tasks.filter((task) => query.state === undefined || task.state === query.state).sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)) || a.taskId.localeCompare(b.taskId));
      const rows = filtered.map(taskView);
      const page = paginate(rows, query, { resource, state: query.state || null }, dataRevision(state.revision, rows));
      return response(page, 200, state.revision);
    }
    if (resource === 'scans') {
      const source = Array.isArray(snapshot?.scans) ? snapshot.scans : state.tasks.filter(analysisTask).map((task) => ({ scanId: task.taskId, taskId: task.taskId, state: task.state, createdAt: task.createdAt, updatedAt: task.updatedAt, type: task.type }));
      if (id) { const scan = source.find((item) => String(item.scanId || item.id || item.taskId) === id); if (!scan) fail('not_found', `扫描不存在：${id}`, 404); return response({ scan: clone(scan) }, 200, state.revision); }
      const query = pageQuery(url.searchParams, new Set(['state', 'limit', 'cursor']), { state: one(url.searchParams, 'state') });
      if (query.state !== undefined && !TASK_STATES.includes(query.state)) fail('invalid_state', `未知扫描状态：${query.state}`, 422);
      const filtered = source.filter((scan) => query.state === undefined || scan.state === query.state);
      return response(paginate(filtered, query, { resource, state: query.state || null }, dataRevision(state.revision, source, snapshot?.syncVersion ?? snapshot?.revision ?? null)), 200, state.revision);
    }
    if (resource === 'findings') {
      const base = findingsFromSnapshot(snapshot);
      const triageState = resourceOperations && typeof resourceOperations.readFindingTriages === 'function'
        ? await resourceOperations.readFindingTriages()
        : { items: {}, revision: state.revision };
      const all = base.map((finding) => ({
        ...finding,
        triage: triageState.items[finding.findingId] || { triageStatus: 'unreviewed', assignee: null, tags: [], notes: [], history: [], updatedAt: null },
      }));
      if (id) { const finding = all.find((item) => item.findingId === id || item.id === id); if (!finding) fail('not_found', `finding 不存在：${id}`, 404); return response({ finding }, 200, triageState.revision); }
      const query = pageQuery(url.searchParams, new Set(['severity', 'status', 'triageStatus', 'target', 'check', 'limit', 'cursor']), { severity: one(url.searchParams, 'severity'), status: one(url.searchParams, 'status'), triageStatus: one(url.searchParams, 'triageStatus'), target: one(url.searchParams, 'target'), check: one(url.searchParams, 'check') });
      if (query.severity !== undefined && !SEVERITIES.has(query.severity)) fail('invalid_filter', 'severity 无效', 422);
      if (query.status !== undefined && !EVIDENCE_STATES.has(query.status)) fail('invalid_filter', 'status 无效', 422);
      if (query.triageStatus !== undefined && !FINDING_TRIAGE_STATUSES.includes(query.triageStatus)) fail('invalid_filter', 'triageStatus 无效', 422);
      const filtered = all.filter((item) => (query.severity === undefined || item.severity === query.severity) && (query.status === undefined || item.status === query.status) && (query.triageStatus === undefined || item.triage.triageStatus === query.triageStatus) && (query.target === undefined || item.target === query.target) && (query.check === undefined || item.check === query.check));
      return response(paginate(filtered, query, { resource, severity: query.severity || null, status: query.status || null, triageStatus: query.triageStatus || null, target: query.target || null, check: query.check || null }, dataRevision(triageState.revision, all, snapshot?.syncVersion ?? snapshot?.revision ?? null)), 200, triageState.revision);
    }
    if (resource === 'evidence') {
      const all = evidenceFromSnapshot(snapshot);
      if (id) { const item = all.find((row) => row.evidenceId === id || row.findingId === id); if (!item) fail('not_found', `evidence 不存在：${id}`, 404); return response({ evidence: item }, 200, state.revision); }
      const query = pageQuery(url.searchParams, new Set(['findingId', 'status', 'limit', 'cursor']), { findingId: one(url.searchParams, 'findingId'), status: one(url.searchParams, 'status') });
      if (query.status !== undefined && !EVIDENCE_STATES.has(query.status)) fail('invalid_filter', 'status 无效', 422);
      const filtered = all.filter((item) => (query.findingId === undefined || item.findingId === query.findingId) && (query.status === undefined || item.status === query.status));
      return response(paginate(filtered, query, { resource, findingId: query.findingId || null, status: query.status || null }, dataRevision(state.revision, all, snapshot?.syncVersion ?? snapshot?.revision ?? null)), 200, state.revision);
    }
    if (resource === 'reports') {
      const reports = await reportsFromTasks(taskStore, evidenceRoot, reportReader);
      if (id) {
        const formatValues = url.searchParams.getAll('format');
        if (formatValues.length > 1) fail('duplicate_query_parameter', '查询参数重复：format', 422);
        const formatParam = formatValues[0];
        const format = formatParam || 'json';
        for (const key of url.searchParams.keys()) if (key !== 'format') fail('unknown_query_parameter', `不支持的查询参数：${key}`, 422);
        const task = state.tasks.find((item) => analysisTask(item) && item.taskId === id);
        if (task) {
          const loaded = await safeBoundReport(task, evidenceRoot, reportReader);
          if (formatParam !== undefined) return rawReportResponse(loaded.report, format, { taskId: id, sha256: loaded.sha256, revision: state.revision });
          return response({ reportId: id, taskId: id, report: loaded.report, sha256: loaded.sha256, bytes: loaded.bytes }, 200, state.revision);
        }
        const relativePath = id;
        if (relativePath.includes('..') || isAbsolute(relativePath)) fail('invalid_id', '报告路径无效', 422);
        const canonicalRoot = await realpath(projectRoot);
        const reportPath = resolve(canonicalRoot, relativePath);
        if (!pathInside(canonicalRoot, reportPath)) fail('invalid_id', '报告路径超出项目目录', 403);
        let handle;
        try {
          const info = await lstat(reportPath);
          if (info.isSymbolicLink() || !info.isFile()) fail('invalid_report_path', '报告必须是项目目录内的普通文件', 403);
          if (info.size > MAX_RESOURCE_REPORT_BYTES) fail('report_too_large', '报告超过 64 MiB 限制', 413);
          if (!pathInside(canonicalRoot, await realpath(reportPath))) fail('invalid_id', '报告真实路径超出项目目录', 403);
          handle = await open(reportPath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);
          const opened = await handle.stat();
          if (!opened.isFile() || opened.dev !== info.dev || opened.ino !== info.ino) fail('invalid_report_path', '报告在读取期间发生变化', 403);
          const buffer = Buffer.allocUnsafe(opened.size + 1);
          let total = 0;
          while (total < buffer.length) {
            const { bytesRead } = await handle.read(buffer, total, Math.min(64 * 1024, buffer.length - total), null);
            if (!bytesRead) break;
            total += bytesRead;
          }
          if (total > MAX_RESOURCE_REPORT_BYTES) fail('report_too_large', '报告超过 64 MiB 限制', 413);
          const bytes = buffer.subarray(0, total);
          let report;
          try { report = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { fail('invalid_report', '报告不是有效 UTF-8 JSON', 422); }
          if (!report || typeof report !== 'object' || Array.isArray(report)) fail('invalid_report', '报告 JSON 必须是对象', 422);
          const reportSha256 = sha(bytes);
          if (formatParam !== undefined) return rawReportResponse(report, format, { taskId: relativePath, sha256: reportSha256, revision: state.revision });
          return response({ reportId: relativePath, report, sha256: reportSha256, bytes: bytes.length }, 200, state.revision);
        } catch (error) {
          if (error instanceof AnalysisResourceApiError) throw error;
          if (error.code === 'ENOENT' || error.code === 'ENOTDIR') fail('not_found', '报告不存在', 404);
          throw error;
        } finally { await handle?.close(); }
      }
      const query = pageQuery(url.searchParams, new Set(['taskId', 'limit', 'cursor']), { taskId: one(url.searchParams, 'taskId') });
      const filtered = reports.items.filter((item) => query.taskId === undefined || item.taskId === query.taskId);
      return response(paginate(filtered, query, { resource, taskId: query.taskId || null }, dataRevision(reports.state.revision, reports.items)), 200, reports.state.revision);
    }
    const artifacts = await artifactsFromTasks(taskStore, evidenceRoot, reportReader);
    if (id) {
      const artifact = artifacts.items.find((item) => item.artifactId === id);
      if (!artifact) fail('not_found', `重放产物不存在：${id}`, 404);
      const { replayEvidence, ...verifiedArtifact } = artifact;
      return response({ artifact: verifiedArtifact, replayEvidence }, 200, artifacts.state.revision);
    }
    const query = pageQuery(url.searchParams, new Set(['taskId', 'limit', 'cursor']), { taskId: one(url.searchParams, 'taskId') });
    const filtered = artifacts.items.filter((item) => query.taskId === undefined || item.taskId === query.taskId);
    return response(paginate(filtered, query, { resource, taskId: query.taskId || null }, dataRevision(artifacts.state.revision, artifacts.items)), 200, artifacts.state.revision);
  };
}

export const createAnalysisResourceRouter = createAnalysisResourceApi;
export const createResourceApiAnalysis = createAnalysisResourceApi;

export async function handleAnalysisResource(request, deps, url) {
  try { return await createAnalysisResourceApi(deps)(request, url); }
  catch (error) { return errorResponse(error, request?.requestId || request?.headers?.['x-request-id']); }
}

export default createAnalysisResourceApi;
