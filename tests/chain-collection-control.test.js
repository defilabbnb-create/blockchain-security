import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ChainCollectionControl, ChainCollectionError, selectChains, unmatchedChainFilters } from '../src/chain-collection-control.js';

const CHAINS = [
  { chainId: 14, name: 'Flare', llamaName: 'Flare' },
  { chainId: 100, name: 'Gnosis', llamaName: 'xDai' },
  { chainId: 42220, name: 'Celo', llamaName: 'Celo' },
];

async function project({ env = {}, campaign = null, lock = null, chains = CHAINS } = {}) {
  const root = await mkdtemp(join(tmpdir(), 'chain-collection-'));
  await mkdir(join(root, 'work'), { recursive: true });
  await mkdir(join(root, 'flare-scan'), { recursive: true });
  await writeFile(join(root, 'flare-scan', 'chains.json'), JSON.stringify({ chains }));
  if (campaign !== null) await writeFile(join(root, 'work', 'defi-campaign.json'), JSON.stringify(campaign));
  if (lock !== null) await writeFile(join(root, 'work', 'defi-campaign.lock'), JSON.stringify(lock));
  return root;
}

function fakeSpawn(pid = 4242) {
  const calls = [];
  const spawnProcess = (command, args, options) => {
    calls.push({ command, args, options });
    return { pid, on() {} };
  };
  return { spawnProcess, calls };
}

const RUNNING_CAMPAIGN = {
  kind: 'defi-source-campaign',
  runId: 'run-1',
  pid: 999,
  state: 'running',
  startedAt: '2026-10-25T00:00:00Z',
  updatedAt: '2026-10-25T00:00:30Z',
  heartbeatAt: '2026-10-25T00:00:30Z',
  lease: { runId: 'run-1', pid: 999, heartbeatAt: '2026-10-25T00:00:30Z', expiresAt: '2026-10-25T00:01:15Z', ttlSec: 45 },
};

test('链筛选：空筛选返回全部，按 chainId/name/llamaName 大小写不敏感匹配', () => {
  assert.equal(selectChains(CHAINS, []).length, 3);
  assert.deepEqual(selectChains(CHAINS, ['14']).map((c) => c.chainId), [14]);
  assert.deepEqual(selectChains(CHAINS, ['flare']).map((c) => c.chainId), [14]);
  assert.deepEqual(selectChains(CHAINS, ['xDai']).map((c) => c.chainId), [100]);
  assert.deepEqual(selectChains(CHAINS, ['14', '42220']).map((c) => c.chainId), [14, 42220]);
});

test('链筛选：匹配不到的 ID 如实报告为 unmatched，不被静默忽略', () => {
  assert.deepEqual(unmatchedChainFilters(CHAINS, ['999']), ['999']);
  assert.deepEqual(unmatchedChainFilters(CHAINS, ['14', '999']), ['999']);
  assert.deepEqual(unmatchedChainFilters(CHAINS, ['14']), []);
});

test('开关默认关闭：环境变量未设置时 start 被后端拒绝', async (t) => {
  const root = await project({ env: {} });
  t.after(() => rm(root, { recursive: true, force: true }));
  const control = new ChainCollectionControl({ projectRoot: root, env: {}, clock: () => Date.parse('2026-10-25T00:00:00Z') });
  assert.equal((await control.status()).enabled, false);
  await assert.rejects(
    () => control.start(),
    (error) => error instanceof ChainCollectionError && error.code === 'chain_collection_disabled' && error.status === 400,
    '开关关闭时 start 必须被拒绝',
  );
});

test('开关默认状态来自 CORPUS_CHAIN_COLLECTION（chainCollectionAllowed 首次真正生效）', async (t) => {
  const root = await project({ env: { CORPUS_CHAIN_COLLECTION: '1' } });
  t.after(() => rm(root, { recursive: true, force: true }));
  const control = new ChainCollectionControl({ projectRoot: root, env: { CORPUS_CHAIN_COLLECTION: '1' }, clock: () => Date.parse('2026-10-25T00:00:00Z') });
  const status = await control.status();
  assert.equal(status.enabled, true);
  assert.equal(status.switchDefaulted, true);
  assert.equal(status.defaultSource, 'env');
});

test('环境变量的其它取值不误判为打开', async (t) => {
  const root = await project({ env: { CORPUS_CHAIN_COLLECTION: '0' } });
  t.after(() => rm(root, { recursive: true, force: true }));
  const control = new ChainCollectionControl({ projectRoot: root, env: { CORPUS_CHAIN_COLLECTION: '0' } });
  assert.equal((await control.status()).enabled, false);
});

test('心跳过期或进程已死：不得报成运行中', async (t) => {
  const root = await project({ env: { CORPUS_CHAIN_COLLECTION: '1' }, campaign: RUNNING_CAMPAIGN });
  t.after(() => rm(root, { recursive: true, force: true }));
  // 心跳新鲜但进程已死
  const dead = new ChainCollectionControl({
    projectRoot: root,
    env: { CORPUS_CHAIN_COLLECTION: '1' },
    clock: () => Date.parse('2026-10-25T00:00:30Z'),
    pidAlive: () => false,
  });
  const deadStatus = await dead.status();
  assert.equal(deadStatus.running, false);
  assert.equal(deadStatus.state, 'stale');
  assert.notEqual(deadStatus.stateLabel, '采集中');
  // 心跳过期但进程还在
  const stale = new ChainCollectionControl({
    projectRoot: root,
    env: { CORPUS_CHAIN_COLLECTION: '1' },
    clock: () => Date.parse('2026-10-25T00:05:00Z'),
    pidAlive: () => true,
  });
  const staleStatus = await stale.status();
  assert.equal(staleStatus.running, false);
  assert.equal(staleStatus.state, 'stale');
});

test('开关已打开与正在采集是两个字段，不能混为一谈', async (t) => {
  const root = await project({ env: { CORPUS_CHAIN_COLLECTION: '1' } });
  t.after(() => rm(root, { recursive: true, force: true }));
  const control = new ChainCollectionControl({ projectRoot: root, env: { CORPUS_CHAIN_COLLECTION: '1' }, clock: () => Date.parse('2026-10-25T00:00:00Z') });
  const status = await control.status();
  assert.equal(status.enabled, true);
  assert.equal(status.running, false);
  assert.equal(status.state, 'idle');
});

test('未知链 ID 必须被拒绝，不静默降级为全部链', async (t) => {
  const root = await project({ env: { CORPUS_CHAIN_COLLECTION: '1' } });
  t.after(() => rm(root, { recursive: true, force: true }));
  const { spawnProcess, calls } = fakeSpawn();
  const control = new ChainCollectionControl({ projectRoot: root, env: { CORPUS_CHAIN_COLLECTION: '1' }, spawnProcess, clock: () => Date.parse('2026-10-25T00:00:00Z') });
  await assert.rejects(
    () => control.start({ chainIds: ['999'] }),
    (error) => error instanceof ChainCollectionError && error.code === 'unknown_chain',
    '未知链必须被拒绝',
  );
  assert.equal(calls.length, 0, '未知链时不得真的拉起进程');
});

test('可用链列表为空时拒绝启动空采集', async (t) => {
  const root = await project({ env: { CORPUS_CHAIN_COLLECTION: '1' }, chains: [] });
  t.after(() => rm(root, { recursive: true, force: true }));
  const { spawnProcess, calls } = fakeSpawn();
  const control = new ChainCollectionControl({ projectRoot: root, env: { CORPUS_CHAIN_COLLECTION: '1' }, spawnProcess, clock: () => Date.parse('2026-10-25T00:00:00Z') });
  await assert.rejects(
    () => control.start({ chainIds: ['14'] }),
    (error) => error instanceof ChainCollectionError && error.code === 'no_chains_available',
  );
  assert.equal(calls.length, 0);
});

test('空 chainIds 表示覆盖全部可用链，是合法输入', async (t) => {
  const root = await project({ env: { CORPUS_CHAIN_COLLECTION: '1' } });
  t.after(() => rm(root, { recursive: true, force: true }));
  const { spawnProcess, calls } = fakeSpawn();
  const control = new ChainCollectionControl({ projectRoot: root, env: { CORPUS_CHAIN_COLLECTION: '1' }, spawnProcess, clock: () => Date.parse('2026-10-25T00:00:00Z') });
  await control.start({ chainIds: [], durationSec: 3600 });
  assert.equal(calls.length, 1);
  const args = calls[0].args;
  assert.equal(args.filter((item) => item === '--chain').length, CHAINS.length);
});

test('start 把链 ID 传给采集脚本的 --chain 参数', async (t) => {
  const root = await project({ env: { CORPUS_CHAIN_COLLECTION: '1' } });
  t.after(() => rm(root, { recursive: true, force: true }));
  const { spawnProcess, calls } = fakeSpawn();
  const control = new ChainCollectionControl({ projectRoot: root, env: { CORPUS_CHAIN_COLLECTION: '1' }, spawnProcess, clock: () => Date.parse('2026-10-25T00:00:00Z') });
  await control.start({ chainIds: ['14', '42220'], durationSec: 1800 });
  assert.equal(calls.length, 1);
  const args = calls[0].args;
  assert.ok(args.includes('--chain'));
  assert.equal(args.filter((item) => item === '--chain').length, 2);
  assert.ok(args.includes('14'));
  assert.ok(args.includes('42220'));
  assert.ok(args.includes('1800'));
});

test('spawn 失败时如实报错，不返回看起来成功的状态', async (t) => {
  const root = await project({ env: { CORPUS_CHAIN_COLLECTION: '1' } });
  t.after(() => rm(root, { recursive: true, force: true }));
  const spawnProcess = () => { throw new Error('spawn exploded'); };
  const control = new ChainCollectionControl({ projectRoot: root, env: { CORPUS_CHAIN_COLLECTION: '1' }, spawnProcess, clock: () => Date.parse('2026-10-25T00:00:00Z') });
  await assert.rejects(
    () => control.start({ chainIds: ['14'] }),
    (error) => error instanceof ChainCollectionError && error.code === 'spawn_failed',
  );
});

test('已有采集在跑时不能再启动一个', async (t) => {
  const root = await project({ env: { CORPUS_CHAIN_COLLECTION: '1' }, campaign: RUNNING_CAMPAIGN, lock: { pid: 999 } });
  t.after(() => rm(root, { recursive: true, force: true }));
  const { spawnProcess, calls } = fakeSpawn();
  const control = new ChainCollectionControl({
    projectRoot: root,
    env: { CORPUS_CHAIN_COLLECTION: '1' },
    spawnProcess,
    clock: () => Date.parse('2026-10-25T00:00:30Z'),
    pidAlive: (pid) => pid === 999,
  });
  await assert.rejects(
    () => control.start({ chainIds: ['14'] }),
    (error) => error instanceof ChainCollectionError && error.code === 'collection_already_running',
  );
  assert.equal(calls.length, 0);
});

test('锁文件里的 PID 还活着时拒绝再拉起一个采集', async (t) => {
  const root = await project({ env: { CORPUS_CHAIN_COLLECTION: '1' }, lock: { pid: 777 } });
  t.after(() => rm(root, { recursive: true, force: true }));
  const { spawnProcess, calls } = fakeSpawn();
  const control = new ChainCollectionControl({
    projectRoot: root,
    env: { CORPUS_CHAIN_COLLECTION: '1' },
    spawnProcess,
    clock: () => Date.parse('2026-10-25T00:00:00Z'),
    pidAlive: (pid) => pid === 777,
  });
  await assert.rejects(
    () => control.start({ chainIds: ['14'] }),
    (error) => error instanceof ChainCollectionError && error.code === 'collection_already_running',
  );
  assert.equal(calls.length, 0);
});

test('durationSec 越界必须被拒绝', async (t) => {
  const root = await project({ env: { CORPUS_CHAIN_COLLECTION: '1' } });
  t.after(() => rm(root, { recursive: true, force: true }));
  const { spawnProcess, calls } = fakeSpawn();
  const control = new ChainCollectionControl({ projectRoot: root, env: { CORPUS_CHAIN_COLLECTION: '1' }, spawnProcess, clock: () => Date.parse('2026-10-25T00:00:00Z') });
  for (const durationSec of [0, 29, 86401, 3600.5, 'abc', null]) {
    await assert.rejects(
      () => control.start({ chainIds: ['14'], durationSec }),
      (error) => error instanceof ChainCollectionError && error.code === 'invalid_field',
      `durationSec=${durationSec} 必须被拒绝`,
    );
  }
  assert.equal(calls.length, 0);
});

test('选中的链持久化，页面刷新后仍保持', async (t) => {
  const root = await project({ env: {} });
  t.after(() => rm(root, { recursive: true, force: true }));
  const control = new ChainCollectionControl({ projectRoot: root, env: {}, clock: () => Date.parse('2026-10-25T00:00:00Z') });
  await control.select(['14']);
  const reopened = new ChainCollectionControl({ projectRoot: root, env: {}, clock: () => Date.parse('2026-10-25T00:00:10Z') });
  const status = await reopened.status();
  assert.deepEqual(status.selectedChainIds, ['14']);
  // 只选链不动开关：开关仍处于默认值状态，没有被用户显式操作过。
  assert.equal(status.switchDefaulted, true);
});

test('用户显式操作开关后，不再由默认值决定', async (t) => {
  const root = await project({ env: { CORPUS_CHAIN_COLLECTION: '1' } });
  t.after(() => rm(root, { recursive: true, force: true }));
  const control = new ChainCollectionControl({ projectRoot: root, env: { CORPUS_CHAIN_COLLECTION: '1' }, clock: () => Date.parse('2026-10-25T00:00:00Z') });
  assert.equal((await control.status()).switchDefaulted, true);
  // 关掉：没有采集在跑，不会去发停止信号。
  const off = await control.setEnabled(false);
  assert.equal(off.enabled, false);
  assert.equal(off.switchDefaulted, false);
  // 重新打开：即使环境变量是 1，状态也由用户的选择决定。
  const reopened = new ChainCollectionControl({ projectRoot: root, env: { CORPUS_CHAIN_COLLECTION: '1' }, clock: () => Date.parse('2026-10-25T00:00:10Z') });
  const status = await reopened.status();
  assert.equal(status.enabled, false, '用户关掉后，环境变量不应把它重新打开');
  assert.equal(status.switchDefaulted, false);
});

test('选择未知链或非法参数时 select 必须被拒绝', async (t) => {
  const root = await project({ env: {} });
  t.after(() => rm(root, { recursive: true, force: true }));
  const control = new ChainCollectionControl({ projectRoot: root, env: {} });
  await assert.rejects(
    () => control.select(['999']),
    (error) => error instanceof ChainCollectionError && error.code === 'unknown_chain',
  );
  await assert.rejects(
    () => control.select('14'),
    (error) => error instanceof ChainCollectionError && error.code === 'invalid_field',
  );
});

test('没有进程可停时 stop 如实报 409，不假装已停止', async (t) => {
  const root = await project({ env: { CORPUS_CHAIN_COLLECTION: '1' } });
  t.after(() => rm(root, { recursive: true, force: true }));
  const control = new ChainCollectionControl({ projectRoot: root, env: { CORPUS_CHAIN_COLLECTION: '1' }, clock: () => Date.parse('2026-10-25T00:00:00Z') });
  await assert.rejects(
    () => control.stop(),
    (error) => error instanceof ChainCollectionError && error.code === 'not_running' && error.status === 409,
  );
});

test('停止时只用本控制面记录的 PID，不用采集报告里的旧 PID', async (t) => {
  // 采集报告里的 pid 来自上一轮运行，那台进程早已退出。
  // PID 可能被系统回收给无关进程，拿它发信号会误杀别的程序。
  const root = await project({ env: { CORPUS_CHAIN_COLLECTION: '1' }, campaign: { ...RUNNING_CAMPAIGN, pid: 3092 } });
  t.after(() => rm(root, { recursive: true, force: true }));
  const control = new ChainCollectionControl({
    projectRoot: root,
    env: { CORPUS_CHAIN_COLLECTION: '1' },
    clock: () => Date.parse('2026-10-25T00:00:30Z'),
    pidAlive: (pid) => pid === 3092,
  });
  // 本控制面没有记录过 run.pid，不能拿报告里的 3092 去发信号。
  await assert.rejects(
    () => control.stop(),
    (error) => error instanceof ChainCollectionError && error.code === 'not_running' && error.status === 409,
    '没有自己记录的 PID 时必须拒绝停止',
  );
});

test('用户从未手动操作时，开关跟随当前环境变量，不被文件里的旧值盖住', async (t) => {
  const root = await project({ env: { CORPUS_CHAIN_COLLECTION: '1' } });
  t.after(() => rm(root, { recursive: true, force: true }));
  // 第一次访问：环境变量为 1，开关打开，并写入状态文件。
  const first = new ChainCollectionControl({ projectRoot: root, env: { CORPUS_CHAIN_COLLECTION: '1' } });
  assert.equal((await first.status()).enabled, true);
  // 之后环境变量改成关闭，重启服务：开关应当跟随新值，而不是停留在文件里的 true。
  const second = new ChainCollectionControl({ projectRoot: root, env: { CORPUS_CHAIN_COLLECTION: '0' } });
  const status = await second.status();
  assert.equal(status.enabled, false, '环境变量变化必须生效，不能被状态文件里的旧值盖住');
  assert.equal(status.switchDefaulted, true);
});

test('用户手动操作过之后，环境变量不再改变开关', async (t) => {
  const root = await project({ env: { CORPUS_CHAIN_COLLECTION: '1' } });
  t.after(() => rm(root, { recursive: true, force: true }));
  const control = new ChainCollectionControl({
    projectRoot: root,
    env: { CORPUS_CHAIN_COLLECTION: '1' },
    autoStart: false,
  });
  await control.setEnabled(false);
  const reopened = new ChainCollectionControl({ projectRoot: root, env: { CORPUS_CHAIN_COLLECTION: '1' } });
  const status = await reopened.status();
  assert.equal(status.enabled, false, '用户的选择优先于环境变量');
  assert.equal(status.switchDefaulted, false);
});

test('库调用方保持既有历史行为：守卫一律放行', async (t) => {
  const root = await project({ env: {} });
  t.after(() => rm(root, { recursive: true, force: true }));
  const control = new ChainCollectionControl({
    projectRoot: root,
    env: {},
    guardFollowsSwitch: false,
  });
  assert.equal(await control.guardAllows(), true, '库调用方不应被链上采集守卫拦住');
});

test('命令行服务：开关关闭时守卫拒绝', async (t) => {
  const root = await project({ env: { CORPUS_CHAIN_COLLECTION: '0' } });
  t.after(() => rm(root, { recursive: true, force: true }));
  const control = new ChainCollectionControl({ projectRoot: root, env: { CORPUS_CHAIN_COLLECTION: '0' } });
  assert.equal(await control.guardAllows(), false);
});

test('采集在跑时：开关状态与运行状态分别可见', async (t) => {
  const root = await project({ env: { CORPUS_CHAIN_COLLECTION: '1' }, campaign: RUNNING_CAMPAIGN, lock: { pid: 999 } });
  t.after(() => rm(root, { recursive: true, force: true }));
  const control = new ChainCollectionControl({
    projectRoot: root,
    env: { CORPUS_CHAIN_COLLECTION: '1' },
    clock: () => Date.parse('2026-10-25T00:00:30Z'),
    pidAlive: (pid) => pid === 999,
  });
  const status = await control.status();
  assert.equal(status.running, true);
  assert.equal(status.enabled, true);
  assert.equal(status.state, 'running');
});
