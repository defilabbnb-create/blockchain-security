import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const boundary = require('../scripts/dynamic-execution-boundary.cjs');

test('defaults to an explicit isolated 31337 boundary', () => {
  const config = boundary.parseForkConfig({});
  assert.equal(config.mode, 'isolated_in_process');
  assert.equal(config.requested, false);
  assert.equal(config.valid, true);
  assert.equal(config.configured, false);
  assert.equal(boundary.hardhatNetworkConfig({}).forking, undefined);
  const report = boundary.publicBoundary(config);
  assert.deepEqual(report.forkProbe, { state: 'not_performed', reason: 'fork_not_requested' });
  assert.equal(report.externalTransactions, false);
  assert.equal(report.externalSigning, false);
  assert.equal(report.networkWrites, 'local_only');
});

test('requires an explicit URL and fixed block for fork mode', () => {
  const config = boundary.parseForkConfig({
    DYNAMIC_EXECUTION_MODE: 'fixed_block_fork',
    DYNAMIC_FORK_RPC_URL: 'https://rpc.example.test/private-token',
    DYNAMIC_FORK_BLOCK_NUMBER: '0x2a',
  });
  assert.equal(config.valid, true);
  assert.equal(config.configured, true);
  assert.equal(config.blockNumber, 42);
  assert.equal(config.rpcUrl, 'https://rpc.example.test/private-token');
  const hardhat = boundary.hardhatNetworkConfig({
    DYNAMIC_EXECUTION_MODE: 'fixed_block_fork',
    DYNAMIC_FORK_RPC_URL: config.rpcUrl,
    DYNAMIC_FORK_BLOCK_NUMBER: '42',
  });
  assert.deepEqual(hardhat.forking, { url: config.rpcUrl, blockNumber: 42 });
  const report = boundary.publicBoundary(config, {
    chainId: 31337,
    forkState: 'verified',
    forkProbe: { state: 'verified', readOnly: true, repeatHashMatch: true },
    blockHash: '0xabc',
  });
  assert.equal(report.mode, 'fixed_block_fork');
  assert.equal(report.rpcEndpoint.sha256, boundary.hashRpcUrl(config.rpcUrl));
  assert.equal(report.fixedBlockHash, '0xabc');
  assert.equal(report.rpcEndpoint.url, undefined);
});

test('partial, invalid, and unsafe fork configuration fails closed', () => {
  for (const env of [
    { DYNAMIC_FORK_RPC_URL: 'https://rpc.example.test' },
    { DYNAMIC_FORK_BLOCK_NUMBER: '12' },
    { DYNAMIC_EXECUTION_MODE: 'isolated_in_process', DYNAMIC_FORK_RPC_URL: 'https://rpc.example.test', DYNAMIC_FORK_BLOCK_NUMBER: '12' },
    { DYNAMIC_EXECUTION_MODE: 'fixed_block_fork', DYNAMIC_FORK_RPC_URL: 'file:///tmp/rpc', DYNAMIC_FORK_BLOCK_NUMBER: '12' },
    { DYNAMIC_EXECUTION_MODE: 'fixed_block_fork', DYNAMIC_FORK_RPC_URL: 'https://user:secret@rpc.example.test', DYNAMIC_FORK_BLOCK_NUMBER: '12' },
    { DYNAMIC_EXECUTION_MODE: 'fixed_block_fork', DYNAMIC_FORK_RPC_URL: 'https://rpc.example.test', DYNAMIC_FORK_BLOCK_NUMBER: '9007199254740992' },
  ]) {
    const config = boundary.parseForkConfig(env);
    assert.equal(config.valid, false, JSON.stringify(env));
    assert.equal(boundary.hardhatNetworkConfig(env).forking, undefined);
  }
});
