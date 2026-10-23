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
  '06-integer_overflow_minimal': {
    vulnerability: 'arithmetic',
    contract: 'IntegerOverflowMinimal',
    action: 'run',
    args: [2n],
  },
  '07-overflow_simple_add': {
    vulnerability: 'arithmetic',
    contract: 'Overflow_Add',
    action: 'add',
    args: [2n ** 256n - 1n],
  },
  '19-mishandled': {
    vulnerability: 'unchecked_low_level_calls',
    contract: 'ReturnValue',
    action: 'callnotchecked',
    checkedAction: 'callchecked',
    receiver: 'RevertingReceiver',
  },
});

function digest(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
function sortedBundle(sources) {
  return JSON.stringify(Object.fromEntries(Object.entries(sources).sort().map(([name, value]) => [name, value.content])));
}

function compileSources(sources) {
  const input = { language: 'Solidity', sources, settings: { optimizer: { enabled: false }, outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } } } };
  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (output.errors || []).filter((item) => item.severity === 'error');
  if (errors.length) throw new Error(`source_compile_failed:${errors.map((item) => item.formattedMessage).join('\n')}`);
  return output;
}

function entry(output, sourceName, contractName) {
  const row = output.contracts?.[sourceName]?.[contractName];
  if (!row?.abi || !row?.evm?.bytecode?.object) throw new Error(`artifact_missing:${sourceName}:${contractName}`);
  return row;
}

(async () => {
  const caseId = process.argv[2];
  const sourcePath = path.resolve(process.argv[3] || '');
  const spec = CASES[caseId];
  if (!spec) throw new Error(`unsupported_dynamic_case:${caseId}`);
  const sourceName = path.basename(sourcePath);
  const source = fs.readFileSync(sourcePath, 'utf8');
  const sourceSha256 = digest(source);
  const receiverSource = spec.receiver ? `pragma solidity ^0.4.25; contract RevertingReceiver { function() public { revert(); } }` : null;
  const sources = { [sourceName]: { content: source } };
  if (receiverSource) sources['RevertingReceiver.sol'] = { content: receiverSource };
  const sourceBundleSha256 = digest(sortedBundle(sources));
  const fork = parseForkConfig(process.env);
  if (fork.requested || !fork.valid) throw new Error('benchmark_dynamic_requires_isolated_local_evm');
  const compiled = compileSources(sources);
  const targetEntry = entry(compiled, sourceName, spec.contract);
  const receiverEntry = spec.receiver ? entry(compiled, 'RevertingReceiver.sol', spec.receiver) : null;
  if (hre.network.name !== 'hardhat' || hre.network.config.url || hre.network.config.forking) throw new Error('benchmark_evm_not_isolated');
  const provider = new BrowserProvider(hre.network.provider);
  const chainId = Number((await provider.getNetwork()).chainId);
  if (chainId !== LOCAL_CHAIN_ID) throw new Error('benchmark_evm_chain_id_mismatch');
  const signer = await provider.getSigner(0);
  const target = await new ContractFactory(targetEntry.abi, targetEntry.evm.bytecode.object, signer).deploy();
  await target.waitForDeployment();
  const targetAddress = await target.getAddress();
  const boundary = publicBoundary(fork, { chainId, forkState: 'not_performed' });
  let before = null;
  let after = null;
  let transactionHash = null;
  let checkedTransactionHash = null;
  let checkedReverted = false;
  let receiverAddress = null;
  if (caseId === '06-integer_overflow_minimal') {
    before = (await target.getFunction('count')()).toString();
    const receipt = await (await target.getFunction(spec.action)(...spec.args)).wait();
    transactionHash = receipt.hash;
    after = (await target.getFunction('count')()).toString();
  } else if (caseId === '07-overflow_simple_add') {
    before = (await target.getFunction('balance')()).toString();
    const receipt = await (await target.getFunction(spec.action)(...spec.args)).wait();
    transactionHash = receipt.hash;
    after = (await target.getFunction('balance')()).toString();
  } else {
    const receiver = await new ContractFactory(receiverEntry.abi, receiverEntry.evm.bytecode.object, signer).deploy();
    await receiver.waitForDeployment();
    receiverAddress = await receiver.getAddress();
    const uncheckedReceipt = await (await target.getFunction(spec.action)(receiverAddress)).wait();
    transactionHash = uncheckedReceipt.hash;
    try {
      await (await target.getFunction(spec.checkedAction)(receiverAddress)).wait();
    } catch (error) {
      checkedReverted = true;
      checkedTransactionHash = error.receipt?.hash || null;
    }
  }
  const confirmed = caseId === '06-integer_overflow_minimal'
    ? before === '1' && after === (2n ** 256n - 1n).toString()
    : caseId === '07-overflow_simple_add'
      ? before === '1' && after === '0'
      : Boolean(transactionHash) && checkedReverted;
  const result = {
    schemaVersion: 1, caseId, state: confirmed ? 'passed' : 'failed', confirmedVulnerability: confirmed,
    vulnerability: spec.vulnerability, mode: 'isolated_in_process', compilerVersion: solc.version(),
    compilerArtifactSha256: process.env.BENCHMARK_SOLC_SHA256 || null,
    compilerKind: 'solc-js-original-source', sourceSha256, sourceBundleSha256, targetAddress,
    beforeValue: before, afterValue: after, transactionHash, receiverAddress, checkedTransactionHash,
    checkedReverted, executionBoundary: boundary,
    reason: confirmed ? null : 'dynamic_assertion_failed',
    reproduction: caseId === '06-integer_overflow_minimal'
      ? '调用 run(2)，验证 uint 从 1 下溢为 uint256 最大值。'
      : caseId === '07-overflow_simple_add'
        ? '调用 add(uint256.max)，验证余额从 1 溢出为 0。'
        : '向会回滚的接收合约调用 callnotchecked 与 callchecked，验证未检查调用继续成功而检查调用回滚。',
  };
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (!confirmed) process.exitCode = 1;
})().catch((error) => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 1;
});
