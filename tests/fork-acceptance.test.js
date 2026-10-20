import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const runner = require('../scripts/fork-acceptance.cjs');

const address = `0x${'12'.repeat(20)}`;
const blockHash = `0x${'ab'.repeat(32)}`;
const runtime = '0x600060005560016000f3';
const blockNumber = 42;
const data = '0x12345678';
const result = '0x01';
const keccak = (value) => {
  const bytes = Buffer.from(value.slice(2), 'hex');
  return `0x${crypto.createHash('sha3-256').update(bytes).digest('hex')}`;
};

function manifest(overrides = {}) {
  return {
    schemaVersion: 1, id: 'fork-baseline',
    deployment: { chainId: 1, blockNumber, blockHash, address, runtimeCodeHash: keccak(runtime) },
    probes: [{ name: 'read-only', data, expectedReturnData: result }],
    ...overrides,
  };
}

test('returns not_performed without fork configuration', async () => {
  assert.deepEqual(await runner.runFromEnvironment({ env: {}, manifestPath: undefined }), {
    schemaVersion: 1, state: 'not_performed', reason: 'fixed_block_fork_not_configured',
    externalTransactions: false, externalSigning: false,
  });
});

test('rejects malformed deployment manifests before RPC access', () => {
  assert.throws(() => runner.validateManifest({ schemaVersion: 1, id: 'x' }), /deployment is required/);
  assert.throws(() => runner.validateManifest({
    ...manifest(), probes: [{ name: 'x', data: '0x', expectedReturnData: '0x' }, { name: 'x', data: '0x', expectedReturnData: '0x' }],
  }), /duplicated/);
});

test('verifies chain, repeated fixed block, code hash, and read-only calls', async () => {
  const calls = [];
  const remote = async (method, params) => {
    calls.push([method, params]);
    if (method === 'eth_chainId') return '0x1';
    if (method === 'eth_getBlockByNumber') return { number: '0x2a', hash: blockHash };
    if (method === 'eth_getCode') return runtime;
    if (method === 'eth_call') return result;
    throw new Error(`unexpected method ${method}`);
  };
  remote.keccak256 = keccak;
  const provider = {
    async send(method, params) {
      if (method === 'eth_chainId') return '0x7a69';
      if (method === 'eth_getBlockByNumber') return { number: '0x2a', hash: blockHash };
      if (method === 'eth_getCode') return runtime;
      if (method === 'eth_call') return result;
      throw new Error(`unexpected provider method ${method}`);
    },
  };
  const report = await runner.runForkAcceptance({ manifest: manifest(), rpcUrl: 'https://rpc.example.test', provider, rpc: remote, keccak256: keccak });
  assert.equal(report.state, 'passed');
  assert.equal(report.executionBoundary.blockHash, blockHash);
  assert.equal(report.executionBoundary.externalTransactions, false);
  assert.equal(report.probes[0].state, 'passed');
  assert.equal(calls.filter(([method]) => method === 'eth_call').length, 1);
});

test('fails closed when fork block or runtime code diverges', async () => {
  const baseRemote = async (method) => ({
    eth_chainId: '0x1',
    eth_getBlockByNumber: { number: '0x2a', hash: `0x${'cd'.repeat(32)}` },
    eth_getCode: runtime,
  }[method]);
  baseRemote.keccak256 = keccak;
  const provider = { send: async (method) => method === 'eth_chainId' ? '0x7a69' : { number: '0x2a', hash: blockHash } };
  await assert.rejects(() => runner.runForkAcceptance({ manifest: manifest(), rpcUrl: 'https://rpc.example.test', provider, rpc: baseRemote, keccak256: keccak }), { code: 'block_hash_mismatch' });
});

test('never permits non-read-only RPC methods', async () => {
  const rpc = runner.createReadOnlyRpc('https://rpc.example.test', { fetchImpl: async () => ({ ok: true, json: async () => ({ id: 1, result: '0x1' }) }) });
  await assert.rejects(() => rpc('eth_sendRawTransaction', ['0xdead']), /not allowed/);
});

test('matches each concurrent RPC response to its own request id', async () => {
  const rpc = runner.createReadOnlyRpc('https://rpc.example.test', {
    fetchImpl: async (_url, options) => {
      const request = JSON.parse(options.body);
      await new Promise((resolve) => setTimeout(resolve, request.id === 1 ? 5 : 0));
      return { ok: true, json: async () => ({ id: request.id, result: request.id === 1 ? '0x1' : '0x2' }) };
    },
  });
  assert.deepEqual(await Promise.all([rpc('eth_chainId', []), rpc('eth_chainId', [])]), ['0x1', '0x2']);
});
