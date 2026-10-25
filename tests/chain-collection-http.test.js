// 链上采集控制面的 HTTP 层行为测试。
//
// 为什么要单独测 HTTP 层：控制面类本身测过字段校验，但 HTTP 路由里
// 曾经出现过「enabled 与 chainIds 同传时只执行其中一个、另一个被静默丢掉」
// 这种问题——类层看不见它，只有真正发请求才暴露。
//
// 诚实性约束（见 .cursor/rules/silent-wrong-value-review.mdc）：
//   - 字段冲突必须报错，不能只执行其中一个；
//   - 未知字段必须报错，不能被忽略；
//   - 读取类请求不得产生副作用（不得启动真实采集、不得写状态文件）。
//
// 隔离：控制面实例指向临时目录，不读写真实项目的 work/ 状态。
// 否则跑一次测试就会改掉用户本机的链上采集开关。
import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startServer } from '../src/web-server.js';
import { ChainCollectionControl } from '../src/chain-collection-control.js';

const CHAINS = [
  { chainId: 14, name: 'Flare', llamaName: 'Flare' },
  { chainId: 100, name: 'Gnosis', llamaName: 'xDai' },
];

async function controlFor(t) {
  const root = await mkdtemp(join(tmpdir(), 'chain-collection-http-'));
  await mkdir(join(root, 'work'), { recursive: true });
  await mkdir(join(root, 'flare-scan'), { recursive: true });
  await writeFile(join(root, 'flare-scan', 'chains.json'), JSON.stringify({ chains: CHAINS }));
  const control = new ChainCollectionControl({
    projectRoot: root,
    enabledDefault: false,
    guardFollowsSwitch: true,
    autoStart: false,
  });
  t.after(() => rm(root, { recursive: true, force: true }));
  return control;
}

async function serverFor(t, overrides = {}) {
  const chainCollectionControl = await controlFor(t);
  const server = startServer({ port: 0, chainCollectionEnabled: false, chainCollectionControl, ...overrides });
  await once(server, 'listening');
  t.after(async () => {
    server.stop();
    server.closeAllConnections();
    if (server.listening) await once(server, 'close');
  });
  return `http://127.0.0.1:${server.address().port}`;
}

const postJson = (base, path, body) => fetch(`${base}${path}`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify(body),
});

test('switch 同时传 enabled 与 chainIds 时必须报错，不得静默丢掉一个', async (t) => {
  const base = await serverFor(t);
  const response = await postJson(base, '/api/v1/chain-collection/switch', { enabled: false, chainIds: ['14'] });
  assert.equal(response.status, 400);
  const body = await response.json();
  assert.equal(body.error.code, 'conflicting_fields');
  assert.deepEqual(body.error.details.fields, ['enabled', 'chainIds']);
});

test('switch 传未知字段必须报错，不能被忽略', async (t) => {
  const base = await serverFor(t);
  const response = await postJson(base, '/api/v1/chain-collection/switch', { enabled: true, nonsense: 1 });
  assert.equal(response.status, 400);
  const body = await response.json();
  assert.equal(body.error.code, 'unknown_field');
  assert.match(body.error.message, /nonsense/);
});

test('switch 缺字段必须报错，不能返回看起来成功的状态', async (t) => {
  const base = await serverFor(t);
  const response = await postJson(base, '/api/v1/chain-collection/switch', {});
  assert.equal(response.status, 400);
  assert.equal((await response.json()).error.code, 'invalid_request');
});

test('status 读取可用，且不返回会误导的运行中状态', async (t) => {
  const base = await serverFor(t);
  const response = await fetch(`${base}/api/v1/chain-collection/status`);
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(typeof body.enabled, 'boolean');
  assert.equal(typeof body.running, 'boolean');
  // 「开关已打开」与「现在正在采集」是两个独立字段，不能合并成一个。
  assert.ok('enabled' in body && 'running' in body);
  // 开关关闭且没有采集在跑：两个字段必须都是 false，不能有一个是 undefined。
  assert.equal(body.enabled, false);
  assert.equal(body.running, false);
  assert.ok(Array.isArray(body.availableChains));
  assert.deepEqual(body.availableChains.map((chain) => chain.chainId), ['14', '100']);
});

test('不存在的链上采集子路径返回 404，不落到别的处理器上', async (t) => {
  const base = await serverFor(t);
  const response = await fetch(`${base}/api/v1/chain-collection/nope`);
  assert.equal(response.status, 404);
  assert.equal((await response.json()).error.code, 'not_found');
});

test('读取状态不产生副作用：不会启动采集，也不写开关状态', async (t) => {
  const control = await controlFor(t);
  const server = startServer({ port: 0, chainCollectionEnabled: false, chainCollectionControl: control });
  await once(server, 'listening');
  t.after(async () => {
    server.stop();
    server.closeAllConnections();
    if (server.listening) await once(server, 'close');
  });
  const base = `http://127.0.0.1:${server.address().port}`;
  const before = await fetch(`${base}/api/v1/chain-collection/status`).then((r) => r.json());
  const after = await fetch(`${base}/api/v1/chain-collection/status`).then((r) => r.json());
  assert.equal(before.running, false, '读取状态不得自己把采集跑起来');
  assert.equal(after.running, false);
  assert.equal(before.enabled, after.enabled);
  // 读操作不该落盘：状态文件仍然不存在。
  await assert.rejects(() => readFile(join(control.projectRoot, 'work', 'chain-collection-control.json')));
});
