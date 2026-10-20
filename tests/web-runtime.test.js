import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startServer } from '../src/web-server.js';
import { TaskStateStore } from '../src/task-state.js';
import { ResourceApiOperations } from '../src/resource-api-operations.js';
import { createSnapshotStore, answerQuestion } from '../src/status-store.js';
import { runSoak, validate, options } from '../scripts/soak-test.mjs';
const stateDir = await mkdtemp(join(tmpdir(), 'dsh-web-state-'));
const buildSnapshot = createSnapshotStore(stateDir);
const STATUS_FILE = join(stateDir, 'dsh-status.json');
const SYNC_FILE = join(stateDir, 'dsh-sync.json');
after(() => rm(stateDir, { recursive: true }));

async function serverFor(t, overrides = {}) {
  const snapshot = await buildSnapshot();
  const server = startServer({ port: 0, snapshotProvider: async () => snapshot, ...overrides });
  await once(server, 'listening');
  t.after(async () => { server.stop(); server.closeAllConnections(); if (server.listening) await once(server, 'close'); });
  return `http://127.0.0.1:${server.address().port}`;
}
test('specific questions take precedence over generic 当前 and do not reuse another chain quote', async () => {
  const s = await buildSnapshot();
  assert.match(answerQuestion(s, '当前有哪些高优先级告警？').answer, /High/);
  assert.match(answerQuestion(s, '当前 Gnosis 跨链报价').answer, /没有 quote_verified/);
  assert.match(answerQuestion(s, '当前三小时稳定性').answer, /稳定性/);
  assert.match(answerQuestion(s, '当前测试情况').answer, /Hardhat/);
});
test('synchronized files share the canonical snapshot version', async () => {
  const s = await buildSnapshot({ force: true });
  const [status, sync] = await Promise.all([STATUS_FILE, SYNC_FILE].map(async (file) => JSON.parse(await readFile(file, 'utf8'))));
  assert.equal(status.syncVersion, s.syncVersion);
  assert.equal(sync.syncVersion, s.syncVersion);
});

test('Chinese console exposes explicit evidence and analysis state labels', async (t) => {
  const base = await serverFor(t);
  const [indexResponse, appResponse] = await Promise.all([
    fetch(`${base}/`),
    fetch(`${base}/app.js`),
  ]);
  assert.equal(indexResponse.status, 200);
  assert.equal(appResponse.status, 200);
  const [index, app] = await Promise.all([indexResponse.text(), appResponse.text()]);
  for (const label of ['可深挖', '有报价证据', '只读', '静态分析', '漏洞链路', '采集 → 处理 → 分析 → 结果', 'stage-summary-updated', '云端审查通道', '待核验线索不是已确认漏洞']) assert.match(index, new RegExp(label));
  for (const label of ['部分完成', '未执行', '动态已确认', '静态候选', '反编译推断', '严重', '高危', 'renderStageSummary', "kind: 'results'", '待人工核对', '本地模拟未通过']) assert.match(app, new RegExp(label));
  assert.doesNotMatch(app, /证据进度/);
  assert.doesNotMatch(index, /progress-overall|progress-code|progress-window/);
  assert.match(app, /更新于/);
  assert.doesNotMatch(index, /id="use-model"/);
  assert.doesNotMatch(app, /useModel:\s*true/);
  assert.match(app, /useModel:\s*false/);
  assert.match(app, /cloudReviewCompletions/);
  assert.match(app, /历史审查记录/);
  assert.match(app, /状态问答与云端审查通道/);
  assert.doesNotMatch(app, /本地开发模型|向本地模型提问/);
  assert.doesNotMatch(index, /\b(?:READY|READ ONLY|TRANSFERABILITY|VULNERABILITY CHAINS|STATIC ANALYSIS)\b/);
});
test('dynamic and code-recovery workspaces are backed by versioned evidence routes', async (t) => {
  const base = await serverFor(t, { eventIntervalMs: 60_000 });
  const [indexResponse, appResponse, campaignResponse, bytecodeResponse, decompileResponse] = await Promise.all([
    fetch(`${base}/`), fetch(`${base}/app.js`), fetch(`${base}/api/campaign`),
    fetch(`${base}/api/v1/bytecode?limit=1`), fetch(`${base}/api/v1/decompile?limit=1`),
  ]);
  assert.equal(indexResponse.status, 200);
  assert.equal(appResponse.status, 200);
  assert.equal(campaignResponse.status, 200);
  assert.equal(bytecodeResponse.status, 200);
  assert.equal(decompileResponse.status, 200);
  const [index, app] = await Promise.all([indexResponse.text(), appResponse.text()]);
  assert.match(index, /动态检查/);
  assert.match(index, /代码查看/);
  assert.match(index, /阶段数字来自已保存记录/);
  assert.doesNotMatch(index, /链节点接口（RPC）|合约执行环境（EVM）|\bTVL\b/);
  assert.match(app, /renderDynamicWorkspace/);
  assert.match(app, /renderReverseWorkspace/);
  assert.match(app, /reverseArtifactControls/);
  assert.match(app, /查看还原代码/);
  assert.match(app, /查看代码结构/);
  assert.match(app, /target\.textContent = response\.data\?\.content/);
  assert.ok(app.includes('/artifacts/${encodeURIComponent(button.dataset.artifactSha)}/content'));
  assert.match(app, /明确未执行/);
  assert.match(app, /已生成易读版本/);
  assert.match(app, /不是项目原始源码/);
  assert.match(app, /尚未由另一种代码工具独立确认/);
  assert.match(app, /机器指令与位置核对一致/);
  assert.match(app, /不能证明还原出的代码含义正确/);
  assert.match(app, /data-resource-form="scan"/);
  assert.match(app, /data-resource-form="decompile"/);
  assert.ok(app.includes('/api/v1/decompile'));
  assert.match(app, /catch \{ return \{ name: 'overview', anchor: 'overview' \}; \}/);
});
test('each Chinese workspace is wired to implemented API resources and scan inputs match the worker contract', async (t) => {
  const taskStore = new TaskStateStore({ path: join(stateDir, 'workspace-tasks.json') });
  const operations = new ResourceApiOperations({ path: join(stateDir, 'workspace-operations.json'), auditPath: join(stateDir, 'workspace-audit.jsonl') });
  const base = await serverFor(t, { taskStore, resourceOperations: operations, eventIntervalMs: 60_000 });
  const paths = [
    '/api/v1/projects?limit=100', '/api/v1/contracts?limit=100', '/api/v1/collection?limit=100',
    '/api/v1/capabilities', '/api/v1/analysis?limit=100', '/api/v1/scans?limit=100',
    '/api/v1/tasks?limit=100', '/api/v1/findings?limit=1000', '/api/v1/evidence?limit=100',
    '/api/v1/replay?limit=100', '/api/v1/reports?limit=100', '/api/v1/bytecode?limit=100',
    '/api/v1/decompile?limit=100', '/api/v1/rules?limit=100&allVersions=false',
    '/api/v1/invariants?limit=100&allVersions=false', '/api/v1/reviews/audit?limit=100',
    '/api/campaign', '/api/status', '/api/health',
  ];
  for (const path of paths) {
    const response = await fetch(`${base}${path}`);
    assert.equal(response.status, 200, `${path} should be readable`);
    const payload = await response.json();
    assert.ok(payload && typeof payload === 'object' && !Array.isArray(payload), `${path} should return structured JSON`);
    if (path.includes('/api/v1/')) assert.equal(payload.apiVersion, 'v1', `${path} should be versioned`);
  }
  const queuedDecompile = await fetch(`${base}/api/v1/decompile`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ runtimeBytecode: '0x6000' }),
  });
  assert.equal(queuedDecompile.status, 202);
  const decompileList = await (await fetch(`${base}/api/v1/decompile?limit=100`)).json();
  const decompileView = decompileList.items.find((item) => item.taskId === queuedDecompile.headers.get('x-task-id'))
    || decompileList.items.find((item) => item.input?.runtimeBytecode === '0x6000');
  assert.ok(decompileView, 'created decompile task should appear in resource API');
  assert.equal(decompileView.crossValidation.highLevelEngineComparison.state, 'not_performed');
  assert.deepEqual(decompileView.crossValidation.highLevelEngineComparison.configuredEngines, ['heimdall-rs']);
  assert.equal(decompileView.crossValidation.semanticsProven, false);
  const app = await (await fetch(`${base}/app.js`)).text();
  for (const path of ['/api/v1/projects?limit=100', '/api/v1/contracts?limit=100', '/api/v1/collection?limit=100', '/api/v1/analysis?limit=100', '/api/v1/scans?limit=100', '/api/v1/tasks?limit=100', '/api/v1/findings?limit=1000', '/api/v1/evidence?findingId=', '/api/v1/replay?limit=100', '/api/v1/bytecode?limit=100', '/api/v1/decompile?limit=100', '/api/v1/rules?limit=100&allVersions=false', '/api/v1/invariants?limit=100&allVersions=false', '/api/v1/reviews/audit?limit=100']) assert.ok(app.includes(path), `workspace should read ${path}`);
  assert.match(app, /\/api\/v1\/findings\/\$\{encodeURIComponent\(form\.dataset\.findingTriage\)\}\/triage/);
  assert.match(app, /data-finding-triage=/);
  assert.match(app, /exportFindingList/);
  assert.match(app, /已验证源码包文件路径/);
  assert.match(app, /dependencyPath/);
  assert.doesNotMatch(app, /name="invariants"|name="contractId"|name="block"/);
  assert.match(app, /body = \{ type: 'local-source-analysis', payload \}/);
});
test('malformed JSON and foreign origins cannot invoke cloud explanations or poison health', async (t) => {
  let calls = 0;
  const base = await serverFor(t, { explanationProvider: async () => { calls++; } });
  const invalid = await fetch(`${base}/api/ask`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{' });
  assert.equal(invalid.status, 400);
  const remote = await fetch(`${base}/api/ask`, { method: 'POST', headers: { origin: 'https://example.com', 'content-type': 'application/json' }, body: JSON.stringify({ question: 'test', useModel: true }) });
  assert.equal(remote.status, 403);
  assert.equal(calls, 0);
  const health = await (await fetch(`${base}/api/health`)).json();
  assert.equal(health.requests.failures, 0);
  assert.equal(health.requests.clientErrors, 2);
  assert.equal(health.snapshots.failures, 0);
});
test('failed snapshots recover and health counts each failed request exactly once', async (t) => {
  let fail = true;
  const good = await buildSnapshot();
  const base = await serverFor(t, { snapshotProvider: async () => { if (fail) throw Error('fixture unavailable'); return good; } });
  assert.equal((await fetch(`${base}/api/status`)).status, 500);
  fail = false;
  assert.equal((await fetch(`${base}/api/status`)).status, 200);
  const health = await (await fetch(`${base}/api/health`)).json();
  assert.equal(health.requests.failures, 1);
  assert.equal(health.snapshots.failures, 1);
  assert.equal(health.snapshots.lastError, null);
});
test('health refreshes an expired snapshot before reporting service state', async (t) => {
  const current = await buildSnapshot({ force: true });
  const old = { ...current, generatedAt: new Date(Date.now() - 120_000).toISOString() };
  let calls = 0;
  const base = await serverFor(t, { snapshotProvider: async () => (++calls === 1 ? old : current) });
  assert.equal((await fetch(`${base}/api/status`)).status, 200);
  assert.equal(calls, 1);
  const health = await (await fetch(`${base}/api/health`)).json();
  assert.equal(calls, 2);
  assert.equal(health.snapshots.generatedAt, current.generatedAt);
  assert.equal(health.snapshots.stale, false);
  assert.equal(health.status, 'ok');
});
test('blocked reads time out without multiplying work, then recover after permission returns', async (t) => {
  let release;
  let calls = 0;
  const good = await buildSnapshot();
  const pending = new Promise((resolve) => { release = resolve; });
  const base = await serverFor(t, { readTimeoutMs: 25, snapshotProvider: () => { calls++; return pending; } });
  const results = await Promise.all(Array.from({ length: 6 }, () => fetch(`${base}/api/status`)));
  assert.ok(results.every((response) => response.status === 503));
  assert.equal(calls, 1);
  const degraded = await (await fetch(`${base}/api/health`)).json();
  assert.equal(degraded.status, 'degraded');
  assert.equal(calls, 1);
  release(good);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal((await fetch(`${base}/api/status`)).status, 200);
  assert.equal((await (await fetch(`${base}/api/health`)).json()).snapshots.lastError, null);
});
test('JSON primitives and incorrectly typed questions return 400, not server failures', async (t) => {
  const base = await serverFor(t);
  for (const body of [null, [], 42, { question: {} }, { question: '当前情况', useModel: 'false' }]) {
    const response = await fetch(`${base}/api/ask`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    assert.equal(response.status, 400);
  }
  const health = await (await fetch(`${base}/api/health`)).json();
  assert.equal(health.requests.failures, 0);
});
test('ask defaults to structured answers and explicitly reports missing cloud configuration', async (t) => {
  let calls = 0;
  const previous = Object.fromEntries(['DEFI_CLOUD_AI_BASE_URL', 'DEFI_CLOUD_AI_API_KEY', 'DEFI_CLOUD_AI_MODEL'].map((key) => [key, process.env[key]]));
  for (const key of Object.keys(previous)) delete process.env[key];
  t.after(() => { for (const [key, value] of Object.entries(previous)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; } });
  const base = await serverFor(t, { explanationProvider: async () => { calls++; } });
  const structured = await (await fetch(`${base}/api/ask`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ question: '一个未知的普通问题' }) })).json();
  assert.equal(structured.explanation, undefined);
  assert.equal(calls, 0);
  const unavailable = await (await fetch(`${base}/api/ask`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ question: '一个未知的普通问题', useModel: true }) })).json();
  assert.equal(unavailable.explanation, null);
  assert.equal(unavailable.reason, 'cloud_ai_not_configured');
  assert.equal(calls, 0);
  assert.equal(validate('/api/ask', structured), null);
});
test('ask time fields distinguish live snapshot, source report, and soak observation', async (t) => {
  const snapshot = await buildSnapshot({ force: true });
  const base = await serverFor(t, { snapshotProvider: async () => snapshot });
  const response = await fetch(`${base}/api/ask`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ question: '当前状态' }) });
  const answer = await response.json();
  assert.equal(answer.asOf, snapshot.generatedAt);
  assert.equal(answer.sourceReportAt, snapshot.lastReportAt);
  assert.equal(answer.soakUpdatedAt, snapshot.soak?.updatedAt || null);
  assert.match(answer.timeSemantics, /asOf=当前快照生成时间/);
  assert.notEqual(answer.asOf, answer.sourceReportAt);
});
test('explicit cloud explanations use HTTPS, reject redirects, and return request evidence hashes', async (t) => {
  const snapshot = await buildSnapshot({ force: true });
  const keys = ['DEFI_CLOUD_AI_BASE_URL', 'DEFI_CLOUD_AI_API_KEY', 'DEFI_CLOUD_AI_MODEL'];
  const previous = Object.fromEntries(keys.map((key) => [key, process.env[key]]));
  Object.assign(process.env, { DEFI_CLOUD_AI_BASE_URL: 'https://api.example.com/v1', DEFI_CLOUD_AI_API_KEY: 'secret-test-key', DEFI_CLOUD_AI_MODEL: 'review-model' });
  const originalFetch = globalThis.fetch;
  const timeoutDescriptor = Object.getOwnPropertyDescriptor(AbortSignal, 'timeout');
  let timeoutMs = null;
  Object.defineProperty(AbortSignal, 'timeout', { ...timeoutDescriptor, value: (milliseconds) => { timeoutMs = milliseconds; return timeoutDescriptor.value.call(AbortSignal, milliseconds); } });
  let request;
  globalThis.fetch = async (input, options) => {
    const url = new URL(input);
    if (url.hostname !== 'api.example.com') return originalFetch(input, options);
    request = { url, options, payload: JSON.parse(options.body) };
    return new Response(JSON.stringify({ choices: [{ message: { content: '云端状态解释' } }] }), { status: 200, headers: { 'content-type': 'application/json' } });
  };
  t.after(() => {
    globalThis.fetch = originalFetch;
    Object.defineProperty(AbortSignal, 'timeout', timeoutDescriptor);
    for (const key of keys) { if (previous[key] === undefined) delete process.env[key]; else process.env[key] = previous[key]; }
  });
  const base = await serverFor(t, { snapshotProvider: async () => snapshot });
  const answer = await (await fetch(`${base}/api/ask`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ question: '请解释当前服务状态', useModel: true }) })).json();
  assert.equal(request.url.href, 'https://api.example.com/v1/chat/completions');
  assert.equal(request.options.redirect, 'error');
  assert.equal(timeoutMs, 90_000);
  assert.equal(request.payload.model, 'review-model');
  assert.equal(request.options.headers.authorization, 'Bearer secret-test-key');
  assert.equal(request.payload.messages[1].content.includes('staticAnalysis'), false);
  assert.equal(answer.mode, 'cloud_ai');
  assert.equal(answer.provider, 'external_cloud_ai');
  assert.equal(answer.model, 'review-model');
  assert.match(answer.manifestSha256, /^[a-f0-9]{64}$/);
  assert.match(answer.responseSha256, /^[a-f0-9]{64}$/);
  assert.equal(answer.explanation, '云端状态解释');
  assert.equal(JSON.stringify(answer).includes('secret-test-key'), false);
});

test('cloud explanation failures are explicit and do not fail health checks', async (t) => {
  const keys = ['DEFI_CLOUD_AI_BASE_URL', 'DEFI_CLOUD_AI_API_KEY', 'DEFI_CLOUD_AI_MODEL'];
  const previous = Object.fromEntries(keys.map((key) => [key, process.env[key]]));
  Object.assign(process.env, { DEFI_CLOUD_AI_BASE_URL: 'https://api.example.com/v1', DEFI_CLOUD_AI_API_KEY: 'secret-test-key', DEFI_CLOUD_AI_MODEL: 'review-model' });
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input, options) => new URL(input).hostname === 'api.example.com' ? new Response('', { status: 503 }) : originalFetch(input, options);
  t.after(() => {
    globalThis.fetch = originalFetch;
    for (const key of keys) { if (previous[key] === undefined) delete process.env[key]; else process.env[key] = previous[key]; }
  });
  const base = await serverFor(t);
  const answer = await (await fetch(`${base}/api/ask`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ question: '当前普通状态', useModel: true }) })).json();
  assert.equal(answer.explanation, null);
  assert.equal(answer.reason, 'cloud_ai_unavailable');
  assert.equal((await (await fetch(`${base}/api/health`)).json()).status, 'ok');
});
test('SSE disconnect releases active connections and timers', async (t) => {
  const base = await serverFor(t, { eventIntervalMs: 20 });
  const controller = new AbortController();
  const response = await fetch(`${base}/api/events`, { signal: controller.signal });
  const reader = response.body.getReader();
  await reader.read();
  controller.abort();
  await reader.cancel().catch(() => {});
  await new Promise((resolve) => setTimeout(resolve, 40));
  const health = await (await fetch(`${base}/api/health`)).json();
  assert.equal(health.sseClients, 0);
  assert.equal(health.requests.active, 1);
});
test('SSE frames carry ids and lifecycle events replay after Last-Event-ID', async (t) => {
  const snapshot = await buildSnapshot();
  const server = startServer({ port: 0, snapshotProvider: async () => snapshot, eventIntervalMs: 60_000 });
  await once(server, 'listening');
  t.after(async () => { server.stop(); if (server.listening) await once(server, 'close'); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const first = await fetch(`${base}/api/events`);
  const reader = first.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  async function nextFrame(stream) {
    while (true) {
      const boundary = buffer.indexOf('\n\n');
      if (boundary >= 0) { const frame = buffer.slice(0, boundary); buffer = buffer.slice(boundary + 2); if (frame) return frame; }
      const chunk = await stream.read();
      if (chunk.done) throw new Error('SSE ended before a frame');
      buffer += decoder.decode(chunk.value, { stream: true });
    }
  }
  const retry = await nextFrame(reader);
  assert.equal(retry, 'retry: 3000');
  const initial = await nextFrame(reader);
  assert.match(initial, /^event: snapshot\nid: 1\ndata: /);
  server.publishEvent('task_checkpoint', { phase: 'evidence_ready' }, 'task-1');
  const lifecycle = await nextFrame(reader);
  assert.match(lifecycle, /^event: lifecycle\nid: 2\ndata: /);
  const envelope = JSON.parse(lifecycle.split('\ndata: ')[1]);
  assert.deepEqual({ id: envelope.id, type: envelope.type, taskId: envelope.taskId }, { id: '2', type: 'task_checkpoint', taskId: 'task-1' });
  await reader.cancel();
  const resumed = await fetch(`${base}/api/events`, { headers: { 'last-event-id': '1' } });
  const resumedReader = resumed.body.getReader();
  buffer = '';
  assert.equal(await nextFrame(resumedReader), 'retry: 3000');
  const replay = await nextFrame(resumedReader);
  assert.match(replay, /^event: lifecycle\nid: 2\ndata: /);
  await resumedReader.cancel();
});
test('SSE bridges durable task history into lifecycle events', async (t) => {
  const taskStore = new TaskStateStore({ path: join(stateDir, 'task-events.json') });
  const events = [];
  const snapshot = await buildSnapshot();
  const server = startServer({ port: 0, snapshotProvider: async () => snapshot, taskStore, eventIntervalMs: 20, eventSink: (event) => events.push(event) });
  await once(server, 'listening');
  t.after(async () => { server.stop(); server.closeAllConnections(); if (server.listening) await once(server, 'close'); });
  await new Promise((resolve) => setTimeout(resolve, 35));
  await taskStore.create({ taskId: 'durable-task', type: 'analysis' });
  await new Promise((resolve) => setTimeout(resolve, 45));
  assert.ok(events.some((event) => event.type === 'task_created' && event.taskId === 'durable-task'));
  const task = await taskStore.claim('event-worker');
  await new Promise((resolve) => setTimeout(resolve, 45));
  const claimed = events.find((event) => event.type === 'stage_started' && event.taskId === 'durable-task');
  assert.ok(claimed);
  assert.equal(claimed.payload.workerId, 'event-worker');
  assert.equal(claimed.payload.state, task.state);
});
test('v1 capabilities and health expose implemented resources and runtime resource evidence', async (t) => {
  const base = await serverFor(t, { eventIntervalMs: 60_000 });
  const capabilities = await (await fetch(`${base}/api/v1/capabilities`)).json();
  assert.equal(capabilities.apiVersion, 'v1');
  assert.equal(capabilities.capabilities.tasks.state, 'available');
  assert.equal(capabilities.capabilities.projects.state, 'available');
  const healthResponse = await fetch(`${base}/api/v1/health`);
  assert.equal(healthResponse.status, 200);
  const health = await healthResponse.json();
  assert.equal(health.apiVersion, 'v1');
  assert.ok(Array.isArray(health.resources.loadavg));
  assert.ok('events' in health && Number.isInteger(health.events.retained));
});
test('v1 resource routes preserve explicit validation and unknown-resource 404s', async (t) => {
  const base = await serverFor(t, { eventIntervalMs: 60_000 });
  const response = await fetch(`${base}/api/v1/projects/project-1`);
  assert.equal(response.status, 404);
  const body = await response.json();
  assert.equal(body.apiVersion, 'v1');
  assert.equal(body.error.code, 'not_found');

  const alias = await fetch(`${base}/api/v1/collections`);
  assert.equal(alias.status, 200);
  assert.deepEqual((await alias.json()).items, []);

  const method = await fetch(`${base}/api/v1/projects`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
  assert.equal(method.status, 400);
  assert.equal((await method.json()).error.code, 'invalid_field');

  const query = await fetch(`${base}/api/v1/projects?limit=10`);
  assert.equal(query.status, 200);
  assert.deepEqual((await query.json()).items, []);

  const unknown = await fetch(`${base}/api/v1/unknown-resource`);
  assert.equal(unknown.status, 404);
});
test('soak records completed duration, compact memory data and rejects invalid replies', async (t) => {
  const base = await serverFor(t, { eventIntervalMs: 20 });
  const dir = await mkdtemp(join(tmpdir(), 'dsh-soak-'));
  t.after(() => rm(dir, { recursive: true }));
  const report = await runSoak({ ...options(), baseUrl: base, output: join(dir, 'soak.json'), durationMs: 100, intervalMs: 50, modelProbe: false, sourceCheck: false });
  assert.equal(report.state, 'completed');
  assert.ok(report.durationMs >= 100);
  assert.equal(report.failures, 0);
  assert.ok(report.sampleCount >= 2);
  assert.ok(report.samples[0].checks.find((check) => check.path === '/api/health').data.memory.rss > 0);
  assert.equal(validate('/api/status', {}), 'invalid status schema');
  assert.throws(() => options(['--duration-ms', '-1']));
  assert.equal(validate('/api/status', { syncVersion: 'x', chains: [], vulnerabilityChains: [], generatedAt: 'invalid' }), 'snapshot stale');
});
test('soak refuses a server running an older source version', async (t) => {
  const base = await serverFor(t, { eventIntervalMs: 20, sourceFingerprint: 'older-build' });
  const dir = await mkdtemp(join(tmpdir(), 'dsh-version-'));
  t.after(() => rm(dir, { recursive: true }));
  const report = await runSoak({ ...options(), baseUrl: base, output: join(dir, 'soak.json'), durationMs: 60, intervalMs: 30, modelProbe: false });
  assert.equal(report.state, 'failed');
  assert.ok(report.failureDetails.some((check) => check.path === 'source-continuity'));
});
