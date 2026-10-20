import { decodeTaskCursor, TASK_STATES } from './task-state.js';

export const TASK_API_VERSION = 'v1';
export const TASK_API_SCHEMA_VERSION = 1;

export class TaskApiV1Error extends Error {
  constructor(code, message, status = 400) {
    super(message);
    this.name = 'TaskApiV1Error';
    this.code = code;
    this.status = status;
  }
}

function singleParam(searchParams, name) {
  const values = searchParams.getAll(name);
  if (values.length > 1) throw new TaskApiV1Error('duplicate_query_parameter', `查询参数重复：${name}`);
  return values[0];
}

export function parseTaskPageQuery(searchParams) {
  const allowed = new Set(['state', 'limit', 'cursor']);
  for (const key of new Set([...searchParams.keys()])) if (!allowed.has(key)) throw new TaskApiV1Error('unknown_query_parameter', `不支持的查询参数：${key}`);
  const state = singleParam(searchParams, 'state');
  if (state !== undefined && !TASK_STATES.includes(state)) throw new TaskApiV1Error('invalid_state', `未知任务状态：${state}`);
  const limitText = singleParam(searchParams, 'limit');
  let limit = 100;
  if (limitText !== undefined) {
    if (!/^\d+$/.test(limitText)) throw new TaskApiV1Error('invalid_limit', 'limit 必须是 1..1000 的整数');
    limit = Number(limitText);
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000) throw new TaskApiV1Error('invalid_limit', 'limit 必须是 1..1000 的整数');
  }
  const cursor = singleParam(searchParams, 'cursor');
  if (cursor !== undefined && (!cursor || cursor.length > 512)) throw new TaskApiV1Error('invalid_cursor', 'cursor 无效');
  if (cursor !== undefined) {
    try { decodeTaskCursor(cursor); }
    catch { throw new TaskApiV1Error('invalid_cursor', 'cursor 无效'); }
  }
  return { ...(state === undefined ? {} : { state }), limit, ...(cursor === undefined ? {} : { cursor }) };
}

export function parseExpectedRevision(request, body = null) {
  const header = request.headers['if-match'];
  const bodyValue = body && typeof body === 'object' && !Array.isArray(body) ? body.expectedRevision : undefined;
  if (header !== undefined && bodyValue !== undefined) throw new TaskApiV1Error('duplicate_revision', 'If-Match 与 expectedRevision 不能同时提供');
  const raw = header ?? bodyValue;
  if (raw === undefined) throw new TaskApiV1Error('missing_revision', '需要 If-Match 或 expectedRevision');
  const text = String(raw).replace(/^W\//, '').replace(/^"|"$/g, '');
  if (!/^\d+$/.test(text)) throw new TaskApiV1Error('invalid_revision', 'revision 必须是非负整数');
  const revision = Number(text);
  if (!Number.isSafeInteger(revision)) throw new TaskApiV1Error('invalid_revision', 'revision 必须是安全整数');
  return revision;
}

export function taskEnvelope(data, generatedAt = new Date().toISOString()) {
  return { apiVersion: TASK_API_VERSION, schemaVersion: TASK_API_SCHEMA_VERSION, generatedAt, ...data };
}

export function taskConsistency(revision, asOf = new Date().toISOString()) {
  return { revision, asOf };
}

export function taskErrorBody(error, requestId) {
  const status = error?.code === 'REVISION_MISMATCH' ? 412 : error?.status || 400;
  const code = error?.code || (status === 404 ? 'not_found' : status === 405 ? 'method_not_allowed' : 'invalid_request');
  return { status, body: taskEnvelope({ error: { code, message: String(error?.message || '任务请求失败'), requestId } }) };
}
