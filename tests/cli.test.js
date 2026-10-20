import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
const root = resolve('.');
async function run(file, args, env = {}) {
  const child = spawn(process.execPath, [resolve(root, file), ...args], { cwd: tmpdir(), env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '';
  child.stdout.on('data', d => stdout += d); child.stderr.on('data', d => stderr += d);
  const status = await new Promise((r, reject) => { child.on('close', r); child.on('error', reject); });
  return { status, stdout, stderr };
}
test('all entry points provide help without network/config and fail invalid args', async () => {
  for (const file of ['src/scan.js', 'src/scan.ts', 'etherscan-scan.mjs']) {
    const help = await run(file, ['--help'], { RPC_URL: 'invalid' });
    assert.equal(help.status, 0, help.stderr); assert.match(help.stdout, /用法/);
    const bad = await run(file, ['--blocks', '-1']); assert.equal(bad.status, 1);
  }
});
test('CLI writes valid atomic JSON, exits 2 for missing receipt', async () => {
  const h = '0x' + '12'.repeat(32);
  const server = createServer(async (req, res) => {
    let body = ''; for await (const chunk of req) body += chunk;
    const { method, id } = JSON.parse(body);
    let result;
    if (method === 'eth_chainId') result = '0x1';
    else if (method === 'eth_blockNumber') result = '0x4';
    else if (method === 'eth_getBlockByNumber') result = { number: '0x2', hash: h, transactions: [{ hash: h, to: null }] };
    else if (method === 'eth_getTransactionReceipt') result = null;
    else throw new Error('Unexpected RPC');
    res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ jsonrpc: '2.0', id, result }));
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const dir = await mkdtemp(join(tmpdir(), 'scan-cli-'));
  try {
    const output = join(dir, 'report.json');
    const runResult = await run('src/scan.js', ['--output', output], { RPC_URL: `http://127.0.0.1:${server.address().port}`, NODE_USE_ENV_PROXY: '0' });
    assert.equal(runResult.status, 2, runResult.stderr);
    const report = JSON.parse(await readFile(output, 'utf8'));
    assert.equal(report.complete, false); assert.equal(report.issues.length, 1);
    assert.deepEqual(report, JSON.parse(runResult.stdout));
  } finally { server.closeAllConnections(); await new Promise(r => server.close(r)); await rm(dir, { recursive: true, force: true }); }
});
