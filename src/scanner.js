import { integer, quantity } from './rpc.js';
const hashPattern = /^0x[0-9a-f]{64}$/i;
const addressPattern = /^0x[0-9a-f]{40}$/i;
const hex = n => `0x${n.toString(16)}`;

async function mapLimit(items, concurrency, fn) {
  let cursor = 0;
  const results = new Array(items.length);
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (cursor < items.length) { const index = cursor++; results[index] = await fn(items[index]); }
  }));
  return results;
}

export async function scanContracts(rpc, { blocks = 1, confirmations = 2, chainId = 1, concurrency = 4, minBalanceWei = '0' } = {}) {
  integer(blocks, 'blocks', 1, 1000); integer(confirmations, 'confirmations', 0, 100000);
  integer(chainId, 'chainId', 1, Number.MAX_SAFE_INTEGER); integer(concurrency, 'concurrency', 1, 16);
  if (!/^(0|[1-9][0-9]*)$/.test(String(minBalanceWei))) throw new Error('minBalanceWei 必须是非负十进制整数');
  const minimum = BigInt(minBalanceWei);
  const actualChain = quantity(await rpc('eth_chainId'));
  if (actualChain !== BigInt(chainId)) throw new Error(`链不匹配：预期 ${chainId}，实际 ${actualChain}`);
  const head = quantity(await rpc('eth_blockNumber'));
  if (head < BigInt(confirmations)) throw new Error('区块高度不足以满足 confirmations');
  const end = head - BigInt(confirmations);
  const start = end >= BigInt(blocks - 1) ? end - BigInt(blocks - 1) : 0n;
  const report = {
    schemaVersion: 1, complete: true, chainId: actualChain.toString(),
    fromBlock: start.toString(), toBlock: end.toString(), confirmations,
    scope: 'Top-level contract creations only; balances are native currency at each creation block. No vulnerability verdict.',
    scannedBlocks: 0, scannedTransactions: 0, creationTransactions: 0, contracts: [], issues: [],
  };
  let previousHash;
  for (let number = start; number <= end; number++) {
    const tag = hex(number);
    const block = await rpc('eth_getBlockByNumber', [tag, true]);
    if (!block || quantity(block.number) !== number || !hashPattern.test(block.hash) || !Array.isArray(block.transactions)) throw new Error(`区块 ${number} 数据无效或不可用`);
    if (previousHash && block.parentHash !== previousHash) throw new Error(`区块 ${number} 发生链重组，请重试`);
    previousHash = block.hash;
    const transactions = block.transactions;
    for (const tx of transactions) {
      if (!tx || typeof tx !== 'object' || !hashPattern.test(tx.hash) || !(tx.to === null || addressPattern.test(tx.to))) throw new Error(`区块 ${number} 交易数据无效`);
    }
    const creations = transactions.filter(tx => tx.to === null);
    report.scannedTransactions += transactions.length;
    report.creationTransactions += creations.length;
    const results = await mapLimit(creations, concurrency, async tx => {
      try {
        const receipt = await rpc('eth_getTransactionReceipt', [tx.hash]);
        if (!receipt) throw new Error('交易回执暂不可用');
        if (receipt.transactionHash !== tx.hash || receipt.blockHash !== block.hash || quantity(receipt.blockNumber) !== number) throw new Error('回执与区块不一致，请重试');
        const status = quantity(receipt.status);
        if (status === 0n) return {};
        if (status !== 1n || !addressPattern.test(receipt.contractAddress)) throw new Error('创建回执格式无效');
        const address = receipt.contractAddress;
        const code = await rpc('eth_getCode', [address, tag]);
        if (typeof code !== 'string' || !/^0x(?:[0-9a-f]{2})*$/i.test(code)) throw new Error('字节码格式无效');
        if (code === '0x') return {};
        const balance = quantity(await rpc('eth_getBalance', [address, tag]), 'balance');
        if (balance < minimum) return {};
        return { contract: { address, transactionHash: tx.hash, blockNumber: number.toString(), blockHash: block.hash, balanceWei: balance.toString(), codeBytes: (code.length - 2) / 2 } };
      } catch (error) { return { issue: { transactionHash: tx.hash, blockNumber: number.toString(), error: error.message } }; }
    });
    const check = await rpc('eth_getBlockByNumber', [tag, false]);
    if (!check || check.hash !== block.hash) throw new Error(`区块 ${number} 发生链重组，请重试`);
    for (const result of results) {
      if (result.contract) report.contracts.push(result.contract);
      if (result.issue) report.issues.push(result.issue);
    }
    report.scannedBlocks++;
  }
  // Also recheck the final anchor: earlier ancestors cannot change without changing it.
  const anchor = await rpc('eth_getBlockByNumber', [hex(end), false]);
  if (!anchor || anchor.hash !== previousHash) throw new Error('扫描期间发生链重组，请重试');
  report.complete = report.issues.length === 0;
  return report;
}
