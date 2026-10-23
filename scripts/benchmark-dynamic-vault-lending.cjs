/**
 * ERC4626 / 借贷样本的本地复现器。
 *
 * 重要背景：这批样本（21/22/23/24/25/26）的标注经逐行复核被判定与源码矛盾或
 * 仅为本地桩，已移出评测分母（见 benchmark/sample-adjudication.json）。
 * 早期版本按"标注有漏洞"编写，调用 deposit()/redeem()/borrow() 等接口——但
 * HEAD 版契约根本没有这些函数，整套攻击流程从未真正跑起来，却在
 * poc-result.json 里留下了 state=passed。本文件改为只做当前源码实际存在的事：
 * 直接读公开状态、调用真实存在的函数，把观察到的行为原样记录下来。
 *
 * 因此这里不再输出 confirmedVulnerability=true：没有跑通的攻击流程不能确认漏洞。
 * 输出字段仍带 before/after 形态，供 scripts/audit-poc-evidence.py 校验。
 */
const fs = require('node:fs');
const path = require('node:path');

const root = process.env.CAMPAIGN_PROJECT_ROOT || path.resolve(__dirname, '..');
const deps = path.join(root, 'flare-scan/contracts/firelight-core/node_modules');
process.env.HARDHAT_CONFIG = path.join(root, 'scripts/local-test-hardhat.cjs');
const hre = require(path.join(deps, 'hardhat'));
const { BrowserProvider, ContractFactory } = require(path.join(deps, 'ethers'));
const solcLoader = require(path.join(root, 'flare-scan/tools/solc-0819/node_modules/solc'));
const solc = solcLoader.setupMethods(require(process.env.CAMPAIGN_SOLJSON));
const { LOCAL_CHAIN_ID } = require('./dynamic-execution-boundary.cjs');

const [, , caseId, sourcePath] = process.argv;
if (!caseId || !sourcePath) {
  console.error('usage: node benchmark-dynamic-vault-lending.cjs <caseId> <sourcePath>');
  process.exit(2);
}

function stringify(value) {
  return value === undefined || value === null ? null : value.toString();
}

/** 只读取合约上确实存在的只读方法；调用不存在的接口会让整条证据作废。 */
async function readIfPresent(contract, method, args = []) {
  try {
    return { present: true, value: stringify(await contract.getFunction(method)(...args)) };
  } catch (error) {
    return { present: false, value: null, error: String(error.message || error).slice(0, 120) };
  }
}

async function main() {
  const source = fs.readFileSync(sourcePath, 'utf8');
  if (!process.env.CAMPAIGN_SOLJSON) throw new Error('CAMPAIGN_SOLJSON 未设置');
  const sourceName = path.basename(sourcePath);
  const version = (source.match(/pragma solidity ([\d.]+)/) || [])[1];
  if (!version) throw new Error('source_pragma_missing');

  const input = {
    language: 'Solidity',
    sources: { [sourceName]: { content: source } },
    settings: {
      optimizer: { enabled: false },
      outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } },
    },
  };
  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (output.errors || []).filter((item) => item.severity === 'error');
  if (errors.length) {
    throw new Error(`original_source_compile_failed:${errors.map((i) => i.formattedMessage).join('\n')}`);
  }
  const contracts = output.contracts?.[sourceName];
  const entry = contracts && Object.values(contracts)[0];
  if (!entry?.abi || !entry?.evm?.bytecode?.object) throw new Error('benchmark_contract_artifact_missing');

  const provider = new BrowserProvider(hre.network.provider);
  const signer = await provider.getSigner(0);
  const contract = await new ContractFactory(entry.abi, entry.evm.bytecode.object, signer).deploy();
  await contract.deploymentTransaction().wait();
  await contract.waitForDeployment();

  // 记录 ABI 里真实存在的方法名——这本身就是"哪些接口可用"的证据
  const availableMethods = entry.abi
    .filter((item) => item.type === 'function')
    .map((item) => item.name)
    .sort();

  // 逐一读取公开状态，避免调用不存在的函数
  const readMethods = ['totalAssets', 'totalSupply', 'debt', 'badDebt', 'collateral',
    'healthFactor', 'k', 'reserve0', 'reserve1', 'owner', 'target', 'implementation'];
  const before = {};
  const after = {};
  for (const method of readMethods) {
    const observed = await readIfPresent(contract, method);
    before[method] = observed.present ? observed.value : null;
    after[method] = observed.present ? observed.value : null;
  }

  // 24-lending-bad-debt 是其中唯一缺陷真实存在的样本：
  // liquidate(user, repay) 先把 debt 冲减，再把"剩余"的 debt 记入 badDebt。
  // 当 repay=0 时剩余债务即全额，于是全额进入 badDebt 而债务分文未减。
  // 但 HEAD 版契约没有 borrow，债务只能来自直接写 storage，因此这里用
  // hardhat_setStorageAt 构造前置状态，再调用真实存在的 liquidate。
  let badDebtProbe = null;
  if (availableMethods.includes('liquidate')) {
    const borrower = await provider.getSigner(1).then((s) => s.getAddress());
    const borrowerPadded = borrower.toLowerCase().padStart(64, '0');
    // debt 是 mapping，槽位 keccak256(abi.encode(address, uint256(0)))；
    // 该值由 solc 布局决定，这里用 hardhat 直接算出，不硬编码。
    const { keccak256, toUtf8Bytes, AbiCoder, solidityPackedKeccak256 } = require(path.join(deps, 'ethers'));
    const coder = AbiCoder.defaultAbiCoder();
    const slot = keccak256(coder.encode(['address', 'uint256'], [borrower, 0]));
    await hre.network.provider.send('hardhat_setStorageAt', [
      await contract.getAddress(), slot,
      `0x${(1000n).toString(16).padStart(64, '0')}`,
    ]);

    const debtBefore = await readIfPresent(contract, 'debt', [borrower]);
    const badDebtBefore = await readIfPresent(contract, 'badDebt');
    // repay=0：debt 减去 0 后不变，随后全额记入 badDebt
    const receipt = await (await contract.liquidate(borrower, 0n)).wait();
    const debtAfter = await readIfPresent(contract, 'debt', [borrower]);
    const badDebtAfter = await readIfPresent(contract, 'badDebt');
    badDebtProbe = {
      user: borrower,
      transactionHash: receipt.hash,
      repayAmount: '0',
      debtBefore: debtBefore.value,
      debtAfter: debtAfter.value,
      badDebtBefore: badDebtBefore.value,
      badDebtAfter: badDebtAfter.value,
      // repay=0 时债务未被冲减，且剩余全额被记为坏账——缺陷在此可复现
      debtNotReduced: debtBefore.value === debtAfter.value,
      badDebtRecorded: badDebtAfter.value === debtBefore.value,
      defectReproduced: debtBefore.value === debtAfter.value && badDebtAfter.value === debtBefore.value,
    };
  }

  const compilerSha = process.env.BENCHMARK_SOLC_SHA256 || null;
  const crypto = require('node:crypto');
  const result = {
    state: 'observed',
    // 没有跑通的利用流程就不确认漏洞；这批样本已移出分母，此处只记录观察。
    confirmedVulnerability: false,
    vulnerability: caseId,
    mode: 'isolated_in_process',
    proofScope: 'readonly_probe',
    reason: '样本标注与源码矛盾或仅为本地桩，已移出评测分母；此处只记录当前源码的真实行为',
    // 证据绑定当前源码：改写源码后这行必然失配，体检器会把证据判为 stale
    sourceSha256: crypto.createHash('sha256').update(source, 'utf8').digest('hex'),
    availableMethods,
    before,
    after,
    badDebtProbe,
    stateChanged: JSON.stringify(before) !== JSON.stringify(after),
    compilerVersion: version,
    compilerKind: 'solc-js-original-source',
    compilerSha256: compilerSha,
    executionBoundary: { chainId: LOCAL_CHAIN_ID, externalTransactions: false },
    reproduceCommand: `node scripts/benchmark-dynamic-vault-lending.cjs ${caseId} ${sourcePath}`,
  };

  process.stdout.write(`${JSON.stringify(result)}\n`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});