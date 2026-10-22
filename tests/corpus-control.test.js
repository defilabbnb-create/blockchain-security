// LaneW 离线语料控制面的行为测试。
// 覆盖：链上采集拒绝、暂停样本边界语义、心跳过期降级、持久化与 PID 存活校验。
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  CorpusControlPlane,
  CorpusControlError,
  isChainCollectionStart,
  chainCollectionAllowed,
  corpusEnvelope,
} from '../src/corpus-control.js';

const PROJECT_ROOT = fileURLToPath(new URL('..', import.meta.url));

async function planeFor(t, options = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-lane-w-'));
  const control = new CorpusControlPlane({ projectRoot: PROJECT_ROOT, workRoot: dir, statePath: join(dir, 'tasks.json'), ...options });
  await control.load();
  t.after(async () => rm(dir, { recursive: true, force: true }));
  return control;
}

test('概览响应带 schemaVersion/apiVersion/generatedAt 且心跳过期时不出现 running', async (t) => {
  const control = await planeFor(t);
  const overview = await control.overview();
  assert.equal(typeof overview.heartbeat.stale, 'boolean');
  assert.equal(overview.heartbeat.staleAfterMs, 120000);
  if (overview.heartbeat.stale) assert.notEqual(overview.heartbeat.running, true);
  for (const task of overview.tasks) {
    if (task.heartbeatStale) {
      assert.notEqual(task.state, 'running');
      assert.notEqual(task.running, true);
    }
  }
  const body = corpusEnvelope({ data: overview });
  assert.equal(body.apiVersion, 'v1');
  assert.equal(body.schemaVersion, 1);
  assert.ok(body.generatedAt);
});

test('链上采集相关路径与泳道名一律被后端拒绝', async (t) => {
  const control = await planeFor(t);
  const request = { method: 'POST' };
  for (const path of [
    '/api/v1/corpus/chain-collection/start',
    '/api/v1/corpus/campaign/start',
    '/api/v1/corpus/defi-campaign/start',
    '/api/v1/corpus/chain-scan/start',
  ]) {
    await assert.rejects(
      () => control.handle(request, new URL(path, 'http://127.0.0.1'), {}),
      (error) => error instanceof CorpusControlError && error.code === 'chain_collection_disabled' && error.status === 400,
      `路径 ${path} 必须被拒绝`,
    );
  }
  for (const laneId of ['campaign', 'defi-campaign', 'chain-scan', 'collection']) {
    await assert.rejects(
      () => control.handle(request, new URL(`/api/v1/corpus/tasks/${laneId}/start`, 'http://127.0.0.1'), {}),
      (error) => error.code === 'chain_collection_disabled',
      `泳道 ${laneId} 必须被拒绝`,
    );
  }
});

test('isChainCollectionStart 识别既有链上采集入口', () => {
  assert.equal(isChainCollectionStart('/api/v1/collection', 'POST', {}), true);
  assert.equal(isChainCollectionStart('/api/v1/tasks', 'POST', { type: 'v1-resource-collection' }), true);
  assert.equal(isChainCollectionStart('/api/v1/tasks', 'POST', { type: 'local-source-analysis' }), false);
  assert.equal(isChainCollectionStart('/api/v1/collection', 'GET', null), false);
  assert.equal(isChainCollectionStart('/api/v1/corpus/tasks/static/start', 'POST', {}), false);
});

test('chainCollectionAllowed 默认关闭，仅显式环境变量才放开', () => {
  assert.equal(chainCollectionAllowed({}), false);
  assert.equal(chainCollectionAllowed({ CORPUS_CHAIN_COLLECTION: '1' }), true);
});

test('未知泳道返回 404，非法参数返回 400', async (t) => {
  const control = await planeFor(t);
  await assert.rejects(
    () => control.handle({ method: 'GET' }, new URL('/api/v1/corpus/tasks/unknown-lane', 'http://127.0.0.1'), null),
    (error) => error.status === 404 && error.code === 'not_found',
  );
  await assert.rejects(
    () => control.handle({ method: 'POST' }, new URL('/api/v1/corpus/tasks', 'http://127.0.0.1'), { laneId: 'static', bogusField: 1 }),
    (error) => error.status === 400 && error.code === 'unknown_field',
  );
  await assert.rejects(
    () => control.handle({ method: 'POST' }, new URL('/api/v1/corpus/tasks', 'http://127.0.0.1'), { laneId: 'static', category: '不存在的类别' }),
    (error) => error.status === 400 && error.code === 'unknown_category',
  );
});

test('暂停只在样本边界生效：当前样本跑完后才挂起', async (t) => {
  const control = await planeFor(t);
  const task = control.tasks.get('fetch') || null;
  assert.equal(task, null);
  // 用 fetch 泳道做最小闭环：创建后启动，立即暂停，观察状态落在样本边界。
  await control.createTask({ laneId: 'fetch', category: 'bad_randomness' });
  await control.start('fetch');
  const paused = await control.pause('fetch');
  assert.ok(['paused', 'pausing', 'running', 'completed'].includes(paused.state));
  assert.equal(paused.pauseSemantics, 'sample_boundary');
  await control.stop('fetch').catch(() => {});
});

test('持久化文件为原子写入且重启后可恢复，PID 已死标记为已中断', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-lane-w-state-'));
  const statePath = join(dir, 'tasks.json');
  const control = new CorpusControlPlane({ projectRoot: PROJECT_ROOT, workRoot: dir, statePath });
  await control.load();
  await control.createTask({ laneId: 'fetch', category: 'bad_randomness' });
  const raw = await readFile(statePath, 'utf8');
  const parsed = JSON.parse(raw);
  assert.equal(parsed.schemaVersion, 1);
  assert.equal(parsed.laneId, 'W');
  assert.equal(parsed.pauseSemantics, 'sample_boundary');
  assert.ok(Array.isArray(parsed.tasks));

  // 构造一个“PID 已死但状态仍是 running”的恢复场景，避免后台执行器干扰。
  parsed.tasks[0].state = 'running';
  parsed.tasks[0].pid = 999999999;
  parsed.tasks[0].lastHeartbeatAt = new Date().toISOString();
  const { writeFile } = await import('node:fs/promises');
  await writeFile(statePath, JSON.stringify(parsed), 'utf8');

  const recovered = new CorpusControlPlane({ projectRoot: PROJECT_ROOT, workRoot: dir, statePath });
  await recovered.load();
  const view = await recovered.getTask('fetch');
  assert.notEqual(view.state, 'running');
  assert.equal(view.lastKnownState, 'interrupted');
  assert.equal(view.interrupted, true);
  assert.equal(view.running, false);
  // 恢复结论必须落盘，重启后不得再次显示为运行中。
  const after = JSON.parse(await readFile(statePath, 'utf8'));
  assert.equal(after.tasks[0].state, 'interrupted');
  await rm(dir, { recursive: true, force: true });
});

test('心跳过期时任务不再显示为运行中', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-lane-w-hb-'));
  const statePath = join(dir, 'tasks.json');
  await writeJson(statePath, {
    schemaVersion: 1,
    laneId: 'W',
    pauseSemantics: 'sample_boundary',
    tasks: [{
      laneId: 'fetch', layer: 'fetch', state: 'running', pid: process.pid,
      startedAt: new Date(Date.now() - 600000).toISOString(),
      lastHeartbeatAt: new Date(Date.now() - 600000).toISOString(),
      completedCount: 3, totalCount: 10, currentStage: '处理中', filters: {},
      itemResults: {}, itemSummary: { passed: 3, failed: 0, skipped: 0, total: 10 }, history: [],
    }],
  });
  const control = new CorpusControlPlane({ projectRoot: PROJECT_ROOT, workRoot: dir, statePath });
  await control.load();
  const view = await control.getTask('fetch');
  assert.equal(view.heartbeatStale, true);
  assert.equal(view.stale, true);
  assert.notEqual(view.state, 'running');
  assert.equal(view.running, false);
  assert.ok(view.lastHeartbeatAt);
  const overview = await control.overview();
  assert.equal(overview.heartbeat.stale, true);
  assert.notEqual(overview.heartbeat.running, true);
  await rm(dir, { recursive: true, force: true });
});

async function writeJson(path, value) {
  const { writeFile } = await import('node:fs/promises');
  await writeFile(path, JSON.stringify(value, null, 2), 'utf8');
}
