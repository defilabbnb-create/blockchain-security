import { parseArgs } from 'node:util';
import { writeFile, rename, unlink } from 'node:fs/promises';
import { resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { createRpc, integer } from './rpc.js';
import { scanContracts } from './scanner.js';

export async function main(args = process.argv.slice(2)) {
  try {
    const { values } = parseArgs({ args, options: {
      help: { type: 'boolean', short: 'h' }, blocks: { type: 'string' },
      confirmations: { type: 'string' }, 'chain-id': { type: 'string' }, concurrency: { type: 'string' },
      'min-balance-wei': { type: 'string' }, output: { type: 'string' }, timeout: { type: 'string' },
    } });
    if (values.help) {
      console.log('用法：bash scan.sh [--blocks 1] [--confirmations 2] [--chain-id 1] [--concurrency 4] [--min-balance-wei 0] [--timeout 15000] [--output report.json]\n通过 RPC_URL 配置节点（默认 https://ethereum-rpc.publicnode.com）；所有操作只读。退出码：0 完整、1 失败、2 部分结果。');
      return;
    }
    const option = (key, env, fallback, min, max) => integer(values[key] ?? process.env[env] ?? fallback, key, min, max);
    const config = {
      blocks: option('blocks', 'SCAN_BLOCKS', 1, 1, 1000),
      confirmations: option('confirmations', 'CONFIRMATIONS', 2, 0, 100000),
      chainId: option('chain-id', 'CHAIN_ID', 1, 1, Number.MAX_SAFE_INTEGER),
      concurrency: option('concurrency', 'SCAN_CONCURRENCY', 4, 1, 16),
      minBalanceWei: values['min-balance-wei'] ?? '0',
    };
    const rpc = createRpc(process.env.RPC_URL || 'https://ethereum-rpc.publicnode.com', { timeout: option('timeout', 'RPC_TIMEOUT_MS', 15000, 1, 120000) });
    const report = await scanContracts(rpc, config);
    const json = `${JSON.stringify(report, null, 2)}\n`;
    if (values.output) {
      const target = resolve(values.output);
      const temp = `${target}.${randomUUID()}.tmp`;
      try { await writeFile(temp, json, { flag: 'wx', mode: 0o600 }); await rename(temp, target); }
      finally { await unlink(temp).catch(() => {}); }
    }
    process.stdout.write(json);
    if (!report.complete) process.exitCode = 2;
  } catch (error) { console.error(`扫描失败：${error.message}`); process.exitCode = 1; }
}
