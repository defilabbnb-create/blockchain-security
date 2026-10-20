import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { TaskStateStore } from '../src/task-state.js';
import { startServer } from '../src/web-server.js';

async function waitFor(check, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = await check();
    if (value) return value;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error('等待采集 worker 结果超时');
}

function fakeRpc() {
  const address = `0x${'11'.repeat(20)}`;
  const blockHash = `0x${'aa'.repeat(32)}`;
  return async ({ method, params }) => {
    if (method === 'eth_chainId') return { value: '0x1', raw: Buffer.from('{"jsonrpc":"2.0","id":1,"result":"0x1"}') };
    if (method === 'eth_getBlockByNumber') {
      const result = { number: params[0], hash: blockHash, timestamp: '0x64', transactions: [] };
      return { value: result, raw: Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: 1, result })) };
    }
    if (method === 'eth_getCode') return { value: '0x6000', raw: Buffer.from('{"jsonrpc":"2.0","id":1,"result":"0x6000"}') };
    if (method === 'eth_getLogs') return { value: [], raw: Buffer.from('{"jsonrpc":"2.0","id":1,"result":[]}') };
    throw new Error(`unexpected RPC method ${method} for ${address}`);
  };
}

async function fixture(t, startCollectionWorker) {
  const dir = await mkdtemp(join(tmpdir(), 'web-collection-worker-'));
  await mkdir(join(dir, 'artifacts'));
  const store = new TaskStateStore({ path: join(dir, 'tasks.json') });
  const server = startServer({
    port: 0,
    taskStore: store,
    resourceArtifactRoots: [dir],
    evidenceRoot: join(dir, 'evidence'),
    snapshotProvider: async () => ({ generatedAt: new Date().toISOString(), activeTask: null, activeChain: null, queue: [], findings: [], vulnerabilityChains: [] }),
    startCollectionWorker,
    collectionWorkerId: 'web-collection-test',
    collectionWorkerPollIntervalMs: 10,
    collectionWorkerRpcRequest: fakeRpc(),
  });
  await once(server, 'listening');
  t.after(async () => {
    await server.stop();
    await rm(dir, { recursive: true, force: true });
  });
  return { dir, store, server, base: `http://127.0.0.1:${server.address().port}` };
}

test('production collection worker consumes only read-only collection tasks and reports live health', async (t) => {
  const f = await fixture(t, true);
  const collection = await f.store.create({
    taskId: 'collection-task',
    type: 'v1-resource-collection',
    payload: { resource: 'collection', input: { projectId: 'p', chainId: 1, address: `0x${'11'.repeat(20)}`, block: 10, rpcUrl: 'http://127.0.0.1:8545', includeLogs: false } },
  });
  const analysis = await f.store.create({ taskId: 'analysis-task', type: 'local-source-analysis', payload: {} });
  const health = await (await fetch(`${f.base}/api/health`)).json();
  assert.equal(health.workers.collection.running, true);
  assert.equal(health.workers.collection.workerId, 'web-collection-test');
  assert.deepEqual(health.workers.collection.handlerTypes, ['v1-resource-collection']);
  await waitFor(async () => (await f.store.get(collection.taskId)).state === 'succeeded');
  assert.equal((await f.store.get(analysis.taskId)).state, 'queued');
  assert.equal(f.server.collectionWorkerStatus().running, true);
});

test('embedded test servers do not consume tasks unless explicitly enabled', async (t) => {
  const f = await fixture(t, false);
  const task = await f.store.create({ type: 'v1-resource-collection', payload: { resource: 'collection', input: {} } });
  const health = await (await fetch(`${f.base}/api/v1/health`)).json();
  assert.equal(health.workers.collection.enabled, false);
  assert.equal(health.workers.collection.state, 'disabled');
  await new Promise((resolve) => setTimeout(resolve, 80));
  assert.equal((await f.store.get(task.taskId)).state, 'queued');
  assert.equal(f.server.collectionWorker, null);
});

