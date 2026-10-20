import test from 'node:test';
import assert from 'node:assert/strict';
import { createRpc } from '../src/rpc.js';
import { scanContracts } from '../src/scanner.js';
const h = n => '0x' + n.toString(16).padStart(64, '0');
const a = '0x' + '11'.repeat(20);
function mock({ receipts = {}, count = 2, change = false } = {}) {
  const calls = [];
  const rpc = async (method, params = []) => {
    calls.push([method, params]);
    if (method === 'eth_chainId') return '0x1';
    if (method === 'eth_blockNumber') return '0xc';
    if (method === 'eth_getBlockByNumber') return { number: '0xa', hash: change && params[1] === false ? h(999) : h(10), transactions: Array.from({ length: count }, (_, i) => ({ hash: h(i + 1), to: i === 0 ? a : null })) };
    if (method === 'eth_getTransactionReceipt') return Object.hasOwn(receipts, params[0]) ? receipts[params[0]] : { transactionHash: params[0], blockHash: h(10), blockNumber: '0xa', status: '0x1', contractAddress: a };
    if (method === 'eth_getCode') return '0x6000';
    if (method === 'eth_getBalance') return '0x20000000000001';
    throw new Error('Unexpected call');
  };
  return { rpc, calls };
}
test('only creation receipts, pinned state, exact uint balance, all transactions', async () => {
  const { rpc, calls } = mock({ count: 502 });
  const result = await scanContracts(rpc);
  assert.equal(result.contracts.length, 501);
  assert.equal(result.scannedTransactions, 502);
  assert.equal(result.contracts[0].balanceWei, '9007199254740993');
  assert.equal(result.complete, true);
  assert.equal(calls.filter(([m]) => m === 'eth_getTransactionReceipt').length, 501);
  for (const [m, p] of calls) if (['eth_getCode', 'eth_getBalance'].includes(m)) assert.equal(p[1], '0xa');
});
test('null receipt is explicit incomplete result, never crashes or claims success', async () => {
  const { rpc } = mock({ receipts: { [h(2)]: null } });
  const result = await scanContracts(rpc);
  assert.equal(result.complete, false); assert.equal(result.issues.length, 1); assert.equal(result.contracts.length, 0);
});
test('chain mismatch and invalid configuration fail before scanning', async () => {
  await assert.rejects(scanContracts(mock().rpc, { chainId: 14 }), /链不匹配/);
  await assert.rejects(scanContracts(mock().rpc, { concurrency: 0 }), /范围/);
  await assert.rejects(scanContracts(mock().rpc, { minBalanceWei: '-1' }), /非负/);
});
test('reorg invalidates result', async () => {
  await assert.rejects(scanContracts(mock({ change: true }).rpc), /链重组/);
});
test('zero native balance included by default and filter optional', async () => {
  const original = mock().rpc;
  const rpc = (m, p) => m === 'eth_getBalance' ? Promise.resolve('0x0') : original(m, p);
  assert.equal((await scanContracts(rpc)).contracts.length, 1);
  assert.equal((await scanContracts(rpc, { minBalanceWei: '1' })).contracts.length, 0);
});
test('failed creation is not reported', async () => {
  const { rpc } = mock({ receipts: { [h(2)]: { transactionHash: h(2), blockHash: h(10), blockNumber: '0xa', status: '0x0', contractAddress: null } } });
  const result = await scanContracts(rpc); assert.equal(result.complete, true); assert.equal(result.contracts.length, 0);
});
test('RPC retries temporary HTTP errors only and validates response id', async () => {
  let tries = 0;
  const rpc = createRpc('https://example.com/secret-key', { delay: async () => {}, fetchImpl: async (_, opts) => {
    tries++; const request = JSON.parse(opts.body);
    return tries < 3 ? new Response('', { status: 429 }) : Response.json({ jsonrpc: '2.0', id: request.id, result: '0x1' });
  } });
  assert.equal(await rpc('eth_chainId'), '0x1'); assert.equal(tries, 3);
  const broken = createRpc('https://example.com/secret-key', { fetchImpl: async () => Response.json({ jsonrpc: '2.0', id: 999, result: '0x1' }) });
  await assert.rejects(broken('eth_chainId'), /响应不匹配/);
});
test('RPC errors redact server messages and do not retry permanent errors', async () => {
  let tries = 0;
  const rpc = createRpc('https://example.com/SECRET', { fetchImpl: async (_, opts) => {
    tries++; return Response.json({ jsonrpc: '2.0', id: JSON.parse(opts.body).id, error: { code: -32602, message: 'https://example.com/SECRET' } });
  } });
  await assert.rejects(rpc('eth_chainId'), e => !e.message.includes('SECRET') && e.message.includes('-32602'));
  assert.equal(tries, 1);
});
test('invalid JSON and missing result are rejected', async () => {
  const bad = createRpc('http://localhost', { fetchImpl: async () => new Response('<html>') });
  await assert.rejects(bad('eth_chainId'), /不是 JSON/);
  const missing = createRpc('http://localhost', { fetchImpl: async () => Response.json({ jsonrpc: '2.0', id: 1 }) });
  await assert.rejects(missing('eth_chainId'), /缺少 result/);
});
test('receipt RPC concurrency is bounded', async () => {
  const original = mock({ count: 20 }).rpc;
  let active = 0, maximum = 0;
  const rpc = async (m, p) => {
    if (m === 'eth_getTransactionReceipt') {
      active++; maximum = Math.max(maximum, active);
      await new Promise(r => setTimeout(r, 2)); active--;
    }
    return original(m, p);
  };
  await scanContracts(rpc, { concurrency: 3 });
  assert.equal(maximum, 3);
});
test('malformed block and stale receipt cannot produce valid results', async () => {
  const original = mock().rpc;
  const malformed = (m, p) => m === 'eth_getBlockByNumber' ? { number: '0xa', hash: h(10), transactions: [h(2)] } : original(m, p);
  await assert.rejects(scanContracts(malformed), /交易数据无效/);
  const { rpc } = mock({ receipts: { [h(2)]: { transactionHash: h(2), blockHash: h(999), blockNumber: '0xa', status: '0x1', contractAddress: a } } });
  const result = await scanContracts(rpc);
  assert.equal(result.complete, false); assert.match(result.issues[0].error, /不一致/);
});
