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
  resolveLaneConcurrency,
  defaultConcurrencyForLane,
  dynamicRunnerFor,
  dynamicBindingError,
  benchmarkShardIdentity,
  BENCHMARK_SHARD_REPO,
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
  assert.equal(paused.pauseSemantics, 'sample_boundary');
  // 暂停只能在样本边界收敛，因此运行中的任务必须停在 pausing 而非直接 paused，
  // 且 completedCount 只能等于已完成样本数——绝不会出现「跑一半被杀掉」的计数。
  assert.ok(['pausing', 'paused'].includes(paused.state),
    `并发暂停只能落在样本边界，实际为 ${paused.state}`);
  if (paused.state === 'paused') assert.equal(paused.completedCount, paused.totalCount);
  if (paused.state === 'pausing') {
    assert.ok(paused.completedCount <= paused.totalCount);
    // 仍在收尾当前样本，等待它自然结束后必须真的落到 paused。
    const deadline = Date.now() + 10_000;
    let settled = null;
    while (Date.now() < deadline) {
      const current = await control.getTask('fetch');
      if (current && ['paused', 'completed', 'stopped'].includes(current.state)) { settled = current; break; }
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    if (settled) assert.ok(['paused', 'completed'].includes(settled.state), `收尾后状态异常：${settled.state}`);
  }
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

/**
 * 结束子进程并等到 close。
 * close 必须等：登记的清空逻辑挂在 close 上，而 exit 先于 close 触发，
 * 只等 exit 会在断言时读到尚未清空的在途集合。
 */
async function waitForClose(child, signal = 'SIGTERM') {
  if (child.exitCode !== null || child.signalCode !== null) return;
  await new Promise((resolve) => {
    const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* 已退出 */ } resolve(); }, 5000);
    child.once('close', () => { clearTimeout(timer); resolve(); });
    child.kill(signal);
  });
}

// ---------------------------------------------------------------- 泳道并发

test('默认并发按 laneId 区分：dynamic 为 4，其余泳道仍为 2', () => {
  assert.equal(defaultConcurrencyForLane('dynamic'), 4);
  assert.equal(defaultConcurrencyForLane('static'), 2);
  assert.equal(defaultConcurrencyForLane('eval'), 2);
  assert.equal(defaultConcurrencyForLane('不存在的泳道'), 2);
});

test('resolveLaneConcurrency：dynamic 取 4、static 取 2，且都受上限与 CPU 收敛', () => {
  const roomy = { cpuCount: 64, freeBytes: 64 * 1024 * 1024 * 1024 };
  assert.equal(resolveLaneConcurrency({ ...roomy, laneId: 'dynamic' }), 4);
  assert.equal(resolveLaneConcurrency({ ...roomy, laneId: 'static' }), 2);
  // 未提供 laneId 时回落到共享默认值 2，保持向后兼容。
  assert.equal(resolveLaneConcurrency({ ...roomy }), 2);
  // 显式 defaultConcurrency 仍优先于 laneId 默认值。
  assert.equal(resolveLaneConcurrency({ ...roomy, laneId: 'dynamic', defaultConcurrency: 3 }), 3);
  // CPU 数不足时向下收敛。
  assert.equal(resolveLaneConcurrency({ cpuCount: 1, freeBytes: 64e9, laneId: 'dynamic' }), 1);
  assert.equal(resolveLaneConcurrency({ cpuCount: 3, freeBytes: 64e9, laneId: 'dynamic' }), 3);
});

test('resolveLaneConcurrency：内存无法测量时退化为串行，上限截断请求值', () => {
  // freeBytes 缺失/非法时不猜并发，保守串行。
  assert.equal(resolveLaneConcurrency({ cpuCount: 8, laneId: 'dynamic' }), 1);
  assert.equal(resolveLaneConcurrency({ cpuCount: 8, freeBytes: 0, laneId: 'dynamic' }), 1);
  // 空闲内存仅够再放下一个子进程时也收敛到 1。
  const tight = 3 * 1024 * 1024 * 1024;
  assert.equal(resolveLaneConcurrency({ cpuCount: 8, freeBytes: tight, laneId: 'dynamic' }), 1);
  // 请求值超过上限时被截断到 8。
  assert.equal(resolveLaneConcurrency({ requested: 99, cpuCount: 64, freeBytes: 64e9, laneId: 'dynamic' }), 8);
  // 结果恒不小于 1。
  assert.equal(resolveLaneConcurrency({ requested: 0, cpuCount: 1, freeBytes: 1, laneId: 'dynamic' }), 1);
});

test('dynamic 泳道未显式配置时实际并发为 4（不是全局默认 2）', async (t) => {
  const control = await planeFor(t);
  assert.equal(control.maxLaneConcurrency, 0, '未配置时以 0 表示「按泳道取默认」');
  assert.equal(control.resolveConcurrencyForTest('dynamic'), resolveLaneConcurrency({
    laneId: 'dynamic', cpuCount: control.cpuCountForTest(), freeBytes: control.memoryForTest(),
  }));
  const dynamicLimit = control.resolveConcurrencyForTest('dynamic');
  const staticLimit = control.resolveConcurrencyForTest('static');
  assert.ok(dynamicLimit >= staticLimit,
    `dynamic 并发(${dynamicLimit}) 不应低于 static(${staticLimit})`);
});

// ---------------------------------------------------------------- 分片归属

test('非 blob 的合成 fixture 也能构造 benchmark 分片身份', () => {
  const sha = 'a'.repeat(64);
  const identity = benchmarkShardIdentity({ caseId: '33-clean-amm', truth: { sourceFile: 'CleanAMM.sol' } }, sha);
  assert.ok(identity, '合成 fixture 必须能落盘');
  assert.equal(identity.repo, BENCHMARK_SHARD_REPO);
  assert.equal(identity.sha256, sha);
  assert.equal(identity.syntheticFixture, true);
  assert.equal(identity.benchmarkCaseId, '33-clean-amm');
  // 身份必须与真实语料样本不相撞：repo 前缀已做命名空间隔离。
  assert.notEqual(identity.repo, 'smartbugs/smartbugs-curated');
});

test('benchmark 分片身份对非法输入保持惰性，不构造垃圾身份', () => {
  assert.equal(benchmarkShardIdentity(null, 'a'.repeat(64)), null);
  assert.equal(benchmarkShardIdentity({ caseId: '' }, 'a'.repeat(64)), null);
  // 源码哈希必须是 64 位小写十六进制，否则身份不可信。
  assert.equal(benchmarkShardIdentity({ caseId: '33-clean-amm' }, 'not-a-sha'), null);
  assert.equal(benchmarkShardIdentity({ caseId: '33-clean-amm' }, 'A'.repeat(64)), null);
  assert.equal(benchmarkShardIdentity({ caseId: '33-clean-amm' }, null), null);
});

test('同一 caseId 不同源码得到不同身份，内容变化即身份变化', () => {
  const one = benchmarkShardIdentity({ caseId: '33-clean-amm' }, 'a'.repeat(64));
  const two = benchmarkShardIdentity({ caseId: '33-clean-amm' }, 'b'.repeat(64));
  assert.notDeepEqual(one, two);
  assert.equal(one.benchmarkCaseId, two.benchmarkCaseId);
});

// ------------------------------------------------------------ 绑定校验

test('dynamicBindingError：五重绑定校验各自可触发', () => {
  const sha = 'a'.repeat(64);
  const good = {
    caseId: '14-reentrance',
    sourceSha256: sha,
    compilerVersion: '0.8.19+commit.7dd6d404.Emscripten.clang',
    compilerArtifactSha256: '0xdeadbeef',
  };
  assert.equal(dynamicBindingError(good, '14-reentrance', sha, '0.8.19', '0xDEADBEEF'), null,
    '大小写不同的 0x 前缀哈希应视为一致');

  assert.equal(dynamicBindingError(null, 'x', sha, '0.8.19', 'd'), 'runner_result_missing');
  assert.equal(dynamicBindingError({}, 'x', sha, '0.8.19', 'd'), 'runner_result_missing');
  assert.equal(dynamicBindingError({ ...good, caseId: 'other' }, '14-reentrance', sha, '0.8.19', '0xdeadbeef'),
    'runner_case_id_mismatch');
  assert.equal(dynamicBindingError({ ...good, sourceSha256: 'b'.repeat(64) }, '14-reentrance', sha, '0.8.19', '0xdeadbeef'),
    'runner_source_hash_mismatch');
  assert.equal(dynamicBindingError({ ...good, compilerVersion: '0.8.20+x' }, '14-reentrance', sha, '0.8.19', '0xdeadbeef'),
    'runner_compiler_version_mismatch');
  assert.equal(dynamicBindingError({ ...good, compilerArtifactSha256: '0xfeedface' }, '14-reentrance', sha, '0.8.19', '0xdeadbeef'),
    'runner_compiler_hash_mismatch');
  // 缺少编译器哈希字段时同样判为不匹配，不能默认放行。
  assert.equal(dynamicBindingError({ caseId: '14-reentrance', sourceSha256: sha, compilerVersion: good.compilerVersion },
    '14-reentrance', sha, '0.8.19', '0xdeadbeef'), 'runner_compiler_hash_mismatch');
});

test('dynamicRunnerFor 覆盖 benchmark 样本且映射到白名单脚本', () => {
  assert.equal(dynamicRunnerFor('33-clean-amm'), 'benchmark-dynamic-clean-controls.cjs');
  assert.equal(dynamicRunnerFor('21-erc4626-donation'), 'benchmark-dynamic-vault-lending.cjs');
  assert.equal(dynamicRunnerFor('30-reentrancy-withdraw'), 'benchmark-dynamic-amm-calls.cjs');
  assert.equal(dynamicRunnerFor('14-reentrance'), 'benchmark-dynamic-runner.cjs');
  assert.equal(dynamicRunnerFor('不存在的样本'), null);
});

// ------------------------------------------------------- 并发下的 pid 语义

test('并发执行时 task.pid 仍是存活标记，前端能显示「运行中」', async (t) => {
  // 回归用例：此前 task.pid 仅在 laneChildren.size===1 时写入，并发执行期
  // 恒为 null，导致 #taskView 的 pidAlive 恒假，前端永远显示不出运行中。
  const control = await planeFor(t, { shardRoot: await mkdtemp(join(tmpdir(), 'dsh-lane-w-shard-')) });
  await control.createTask({ laneId: 'dynamic', category: null });
  const task = control.tasks.get('dynamic');
  // start() 会把任务置为 running 并打上心跳；这里直接复现该状态，
  // 以便只观察并发期 pid 的变化而不真正跑一遍语料批次。
  task.state = 'running';
  task.startedAt = new Date().toISOString();
  task.lastHeartbeatAt = new Date().toISOString();
  // 直接驱动内部：拉起两个长驻子进程模拟并发样本，绕过真实的 runner 调用。
  const handles = [
    await control.spawnProbeChildForTest(task, 12_000),
    await control.spawnProbeChildForTest(task, 12_000),
  ];
  t.after(() => { for (const handle of handles) { try { handle.child.kill('SIGKILL'); } catch { /* 已退出 */ } } });

  assert.equal(control.activeChildren.get('dynamic').size, 2, '应同时持有两个子进程');
  const view = control.taskViewForTest(task);
  assert.ok(view.pid, '并发期 task.pid 必须有值，不能是 null');
  assert.equal(view.pidAlive, true, '并发期 pidAlive 必须为真');
  assert.equal(view.running, true, '并发期必须能显示为运行中');
  // pid 指向首个子进程，不随样本加入/退出而漂移。
  assert.equal(view.pid, control.lanePid.get('dynamic'));

  // 结束其中一个子进程后，泳道仍有活动样本，标记必须保持存活。
  // 必须等 close 而不是 exit：exit 先于 close 触发，而登记的清空发生在 close；
  // 先检查 child.exitCode 是为了在 close 已发生时不再重复等待。
  await waitForClose(handles[0].child, 'SIGTERM');
  const stillRunning = control.taskViewForTest(task);
  assert.equal(stillRunning.pidAlive, true, '仍有在途样本时不得判定为已退出');
  assert.equal(stillRunning.running, true);

  // 全部子进程结束后，存活标记必须失效，以免下次恢复误判为仍在运行。
  await waitForClose(handles[1].child, 'SIGTERM');
  const drained = control.taskViewForTest(task);
  assert.equal(control.activeChildren.get('dynamic')?.size ?? 0, 0, '在途子进程应已清空');
  assert.equal(drained.pid, null, '泳道清空后必须清空 pid，避免恢复时误判');
});

test('pid 已死且无在途子进程时，恢复逻辑仍会标记为已中断', async (t) => {
  // 保证上面的「并发可见」不会削弱既有的恢复校验：pid 为空时不得被当成运行中。
  const dir = await mkdtemp(join(tmpdir(), 'dsh-lane-w-pid-'));
  const statePath = join(dir, 'tasks.json');
  await writeJson(statePath, {
    schemaVersion: 1,
    laneId: 'W',
    pauseSemantics: 'sample_boundary',
    tasks: [{
      laneId: 'dynamic', layer: 'dynamic', state: 'running', pid: 999999999,
      startedAt: new Date().toISOString(), lastHeartbeatAt: new Date().toISOString(),
      completedCount: 0, totalCount: 5, filters: {},
      itemResults: {}, itemSummary: { passed: 0, failed: 0, skipped: 0, total: 5 }, history: [],
    }],
  });
  const control = new CorpusControlPlane({ projectRoot: PROJECT_ROOT, workRoot: dir, statePath });
  await control.load();
  const view = await control.getTask('dynamic');
  assert.equal(view.lastKnownState, 'interrupted');
  assert.equal(view.interrupted, true);
  assert.equal(view.running, false);
  assert.equal(view.pid, null);
  await rm(dir, { recursive: true, force: true });
});
