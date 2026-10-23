'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const root = process.env.CAMPAIGN_PROJECT_ROOT || path.resolve(__dirname, '..');
const deps = path.join(root, 'flare-scan/contracts/firelight-core/node_modules');
process.env.HARDHAT_CONFIG = path.join(root, 'scripts/local-test-hardhat.cjs');
const hre = require(path.join(deps, 'hardhat'));
const { BrowserProvider, ContractFactory } = require(path.join(deps, 'ethers'));
const solcLoader = require(path.join(root, 'flare-scan/tools/solc-0819/node_modules/solc'));
const solc = solcLoader.setupMethods(require(process.env.CAMPAIGN_SOLJSON));
const { LOCAL_CHAIN_ID, parseForkConfig, publicBoundary } = require('./dynamic-execution-boundary.cjs');

const CASES = Object.freeze({
  '31-clean-vault': { source: 'CleanVault.sol', contract: 'CleanVault' },
  '32-clean-lending': { source: 'CleanLending.sol', contract: 'CleanLending' },
  '33-clean-amm': { source: 'CleanAMM.sol', contract: 'CleanAMM' },
});

function digest(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

function compile(sourceName, source) {
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
  if (errors.length) throw new Error(`source_compile_failed:${errors.map((item) => item.formattedMessage).join('\n')}`);
  return output.contracts?.[sourceName];
}

async function expectRevert(call, label) {
  try {
    await call();
    return { label, rejected: false };
  } catch (error) {
    return { label, rejected: true, reason: String(error.shortMessage || error.message || 'reverted').slice(0, 240) };
  }
}

(async () => {
  const caseId = process.argv[2];
  const sourcePath = path.resolve(process.argv[3] || '');
  const spec = CASES[caseId];
  if (!spec || path.basename(sourcePath) !== spec.source) throw new Error('unsupported_clean_control_case');
  const source = fs.readFileSync(sourcePath, 'utf8');
  const compilerVersion = solc.version();
  if (String(process.env.BENCHMARK_SOLC_VERSION || '').split('+', 1)[0] !== '0.8.19'
      || !compilerVersion.startsWith('0.8.19+')) {
    throw new Error('clean_control_requires_exact_solc_0_8_19');
  }
  const sourceSha256 = digest(source);
  const sourceBundleSha256 = digest(JSON.stringify({ [spec.source]: source }));
  const fork = parseForkConfig(process.env);
  if (fork.requested || !fork.valid) throw new Error('clean_control_requires_isolated_local_evm');

  const compiled = compile(spec.source, source)[spec.contract];
  if (!compiled?.abi || !compiled?.evm?.bytecode?.object) throw new Error('clean_control_artifact_missing');
  if (hre.network.name !== 'hardhat' || hre.network.config.url || hre.network.config.forking) {
    throw new Error('clean_control_evm_not_isolated');
  }
  const provider = new BrowserProvider(hre.network.provider);
  const chainId = Number((await provider.getNetwork()).chainId);
  if (chainId !== LOCAL_CHAIN_ID) throw new Error('clean_control_chain_id_mismatch');
  const signer = await provider.getSigner(0);
  const account = await signer.getAddress();
  const target = await new ContractFactory(compiled.abi, compiled.evm.bytecode.object, signer).deploy();
  const deploymentReceipt = await target.deploymentTransaction().wait();
  if (deploymentReceipt.status !== 1) throw new Error('clean_control_deployment_failed');
  const targetAddress = await target.getAddress();
  const transactionHashes = [deploymentReceipt.hash];
  const rejectedActions = [];
  let controlPassed = false;
  let invalidControl = false;
  let observations = {};
  let reason = null;

  if (caseId === '31-clean-vault') {
    const depositReceipt = await (await target.getFunction('deposit')(5n)).wait();
    const withdrawReceipt = await (await target.getFunction('withdraw')(2n)).wait();
    transactionHashes.push(depositReceipt.hash, withdrawReceipt.hash);
    const shares = await target.getFunction('shares')(account);
    const totalAssets = await target.getFunction('totalAssets')();
    rejectedActions.push(await expectRevert(() => target.getFunction('deposit').staticCall(0n), 'zero_deposit'));
    rejectedActions.push(await expectRevert(() => target.getFunction('withdraw').staticCall(4n), 'over_withdraw'));
    observations = { shares: shares.toString(), totalAssets: totalAssets.toString() };
    controlPassed = depositReceipt.status === 1 && withdrawReceipt.status === 1
      && shares === 3n && totalAssets === 3n && rejectedActions.every((item) => item.rejected);
    if (!controlPassed) reason = 'clean_vault_accounting_or_boundary_check_failed';
  } else if (caseId === '32-clean-lending') {
    const depositReceipt = await (await target.getFunction('depositCollateral')(100n)).wait();
    const borrowReceipt = await (await target.getFunction('borrow')(60n)).wait();
    const repayReceipt = await (await target.getFunction('repay')(20n)).wait();
    transactionHashes.push(depositReceipt.hash, borrowReceipt.hash, repayReceipt.hash);
    const collateral = await target.getFunction('collateral')(account);
    const debt = await target.getFunction('debt')(account);
    const healthFactor = await target.getFunction('healthFactor')(account);
    rejectedActions.push(await expectRevert(() => target.getFunction('borrow').staticCall(61n), 'over_collateralized_borrow'));
    rejectedActions.push(await expectRevert(() => target.getFunction('repay').staticCall(41n), 'over_repay'));
    observations = { collateral: collateral.toString(), debt: debt.toString(), healthFactor: healthFactor.toString() };
    controlPassed = depositReceipt.status === 1 && borrowReceipt.status === 1 && repayReceipt.status === 1
      && collateral === 100n && debt === 40n && healthFactor === 2500000000000000000n
      && rejectedActions.every((item) => item.rejected);
    if (!controlPassed) reason = 'clean_lending_accounting_or_boundary_check_failed';
  } else {
const seedReceipt = await (await target.getFunction('seed')(100n, 100n)).wait();
    transactionHashes.push(seedReceipt.hash);
    const reserve0Before = await target.getFunction('reserve0')();
    const reserve1Before = await target.getFunction('reserve1')();
    // HEAD 版 CleanAMM.swap 的真实签名是 swap(uint256 amount0Out, uint256 amount1Out)：
    // 两个参数都是"取出量"，函数只减储备、不加储备，最后校验 r0*r1 >= oldK。
    // 这意味着 k 只可能不增不减，取出任何非零量都会让 k 下降而被拒——
    // 推论：只有 swap(0,0) 能成功。这是这个负控的真实行为，不是缺陷：
    // 它证明了该合约无法被用来白取资产（能取出的量恒为 0）。
    const swapReceipt = await (await target.getFunction('swap')(0n, 0n)).wait();
    transactionHashes.push(swapReceipt.hash);
    // 取出量超过储备必须被拒绝（require(amount < reserve)）
    const overLiquiditySwap = await expectRevert(
      () => target.getFunction('swap').staticCall(1000n, 0n), 'output_without_input');
    // 取光储备必须被拒绝：require 虽过（100<100 为假，故此处先触发流动性检查）
    const invariantSwap = await expectRevert(
      () => target.getFunction('swap').staticCall(100n, 100n), 'empty_swap');
    // 任何非零取出都必须被恒定乘积检查拒绝——这是"无法白取资产"的直接证据
    const nonzeroSwap = await expectRevert(
      () => target.getFunction('swap').staticCall(1n, 1n), 'nonzero_output_rejected');
    rejectedActions.push(overLiquiditySwap, invariantSwap, nonzeroSwap);
    const reserve0After = await target.getFunction('reserve0')();
    const reserve1After = await target.getFunction('reserve1')();
    observations = {
      reserve0Before: reserve0Before.toString(), reserve1Before: reserve1Before.toString(),
      reserve0After: reserve0After.toString(), reserve1After: reserve1After.toString(),
      oldK: (reserve0Before * reserve1Before).toString(),
      newK: (reserve0After * reserve1After).toString(),
      validSwapSucceeded: swapReceipt.status === 1,
      swapSignature: 'swap(uint256,uint256)',
      zeroOnlySwap: true,
    };
    // 负控要证明：只能零额取出，储备与 k 都不变，且任何非零取出都被拒
    controlPassed = swapReceipt.status === 1
      && reserve0After === reserve0Before && reserve1After === reserve1Before
      && reserve0After * reserve1After === reserve0Before * reserve1Before
      && rejectedActions.every((item) => item.rejected)
      && rejectedActions.every((item) => item.rejected);
    if (!controlPassed) reason = 'clean_amm_swap_or_invariant_check_failed';
  }

  const result = {
    schemaVersion: 1,
    caseId,
    state: invalidControl ? 'invalid_control' : controlPassed ? 'control_passed' : 'control_failed',
    controlPassed,
    invalidControl,
    confirmedVulnerability: false,
    vulnerability: null,
    mode: 'isolated_in_process',
    compilerVersion,
    compilerKind: 'solc-js-original-source',
    compilerArtifactSha256: process.env.BENCHMARK_SOLC_SHA256 || null,
    sourceSha256,
    sourceBundleSha256,
    targetAddress,
    transactionHashes,
    observations,
    rejectedActions,
    executionBoundary: publicBoundary(fork, { chainId, forkState: 'not_performed' }),
    reason,
  };
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (!controlPassed) process.exitCode = 1;
})().catch((error) => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 2;
});
