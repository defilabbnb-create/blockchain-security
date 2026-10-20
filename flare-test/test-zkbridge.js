// Read-only ERC20 balance probe against an explicitly configured local fork.
import { createRpc } from '../src/rpc.js';
try {
  const endpoint = process.env.FORK_RPC_URL || 'http://127.0.0.1:49373';
  const url = new URL(endpoint);
  if (!['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)) throw new Error('FORK_RPC_URL 必须指向本机 fork');
  const address = process.env.CONTRACT_ADDRESS;
  const holder = process.env.HOLDER_ADDRESS || '0x0000000000000000000000000000000000000001';
  if (!/^0x[0-9a-f]{40}$/i.test(address || '') || !/^0x[0-9a-f]{40}$/i.test(holder)) throw new Error('请设置有效 CONTRACT_ADDRESS 和 HOLDER_ADDRESS');
  const rpc = createRpc(endpoint, { retries: 0 });
  const code = await rpc('eth_getCode', [address, 'latest']);
  if (!code || code === '0x') throw new Error('该地址没有合约字节码');
  const result = await rpc('eth_call', [{ to: address, data: `0x70a08231${holder.slice(2).padStart(64, '0')}` }, 'latest']);
  if (!/^0x[0-9a-f]{64}$/i.test(result)) throw new Error('返回值不是 ERC20 uint256');
  console.log(JSON.stringify({ address, holder, balance: BigInt(result).toString() }, null, 2));
} catch (error) { console.error(`本地检查失败：${error.message}`); process.exitCode = 1; }
