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

const EXPECTED_SHA256 = 'f2aca13163e64595c86b30cda54a52b1b970fc75e9b38ccba0218ffc316b6619';
const ACTOR_SOURCE = `pragma solidity ^0.4.19;
contract IThrone {
  function claimThrone(string name) public payable;
}
contract RejectingMonarch {
  function claim(address throne, string name) public payable {
    IThrone(throne).claimThrone.value(msg.value)(name);
  }
  function() payable { revert(); }
}
contract AcceptingMonarch {
  uint public received;
  function claim(address throne, string name) public payable {
    IThrone(throne).claimThrone.value(msg.value)(name);
  }
  function() payable { received += msg.value; }
}`;

function digest(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }

function compile(sourceName, source) {
  const input = { language: 'Solidity', sources: {
    [sourceName]: { content: source }, 'KotetActors.sol': { content: ACTOR_SOURCE },
  }, settings: { optimizer: { enabled: false }, outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } } } };
  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (output.errors || []).filter((item) => item.severity === 'error');
  if (errors.length) throw new Error(`source_compile_failed:${errors.map((item) => item.formattedMessage).join('\n')}`);
  return output.contracts;
}

function artifact(contracts, sourceName, contractName) {
  const item = contracts?.[sourceName]?.[contractName];
  if (!item?.abi || !item?.evm?.bytecode?.object) throw new Error(`artifact_missing:${sourceName}:${contractName}`);
  return item;
}

async function deploy(signer, item, args = []) {
  const contract = await new ContractFactory(item.abi, item.evm.bytecode.object, signer).deploy(...args);
  const receipt = await contract.deploymentTransaction().wait();
  if (receipt.status !== 1) throw new Error('deployment_failed');
  await contract.waitForDeployment();
  return contract;
}

async function runScenario(provider, artifacts, receiverName, receiverArtifact) {
  const wizard = await provider.getSigner(0);
  const claimant = await provider.getSigner(1);
  const claimantAddress = (await claimant.getAddress()).toLowerCase();
  const throne = await deploy(wizard, artifacts.throne);
  const receiver = await deploy(wizard, receiverArtifact);
  const throneAddress = await throne.getAddress();
  const receiverAddress = await receiver.getAddress();
  const firstPrice = 100000000000000000n;
  await (await receiver.getFunction('claim')(throneAddress, 'first', { value: firstPrice, gasLimit: 1000000 })).wait();
  const nextPrice = BigInt(await throne.getFunction('currentClaimPrice')());
  const receiverBalanceBefore = await provider.getBalance(receiverAddress);
  const contractBalanceBefore = await provider.getBalance(throneAddress);
  const claimReceipt = await (await throne.connect(claimant).getFunction('claimThrone')('second', {
    value: nextPrice, gasLimit: 1500000,
  })).wait();
  const receiverBalanceAfter = await provider.getBalance(receiverAddress);
  const contractBalanceAfter = await provider.getBalance(throneAddress);
  const monarch = await throne.getFunction('currentMonarch')();
  const priorMonarch = await throne.getFunction('pastMonarchs')(1);
  const commission = nextPrice / 100n;
  const compensation = nextPrice - commission;
  const expectedReceiverIncrease = receiverName === 'accepting' ? compensation : 0n;
  return {
    receiverName, receiverAddress: receiverAddress.toLowerCase(), claimantAddress,
    nextPriceWei: nextPrice.toString(), compensationWei: compensation.toString(),
    contractBalanceBeforeWei: contractBalanceBefore.toString(),
    contractBalanceAfterWei: contractBalanceAfter.toString(),
    receiverBalanceBeforeWei: receiverBalanceBefore.toString(),
    receiverBalanceAfterWei: receiverBalanceAfter.toString(),
    receiverIncreaseWei: (receiverBalanceAfter - receiverBalanceBefore).toString(),
    currentMonarchAddress: String(monarch.etherAddress).toLowerCase(),
    priorMonarchAddress: String(priorMonarch.etherAddress).toLowerCase(),
    claimTransactionStatus: Number(claimReceipt.status),
    assertions: {
      claimTransactionSucceeded: Number(claimReceipt.status) === 1,
      throneAdvancedDespitePayoutOutcome: String(monarch.etherAddress).toLowerCase() === claimantAddress
        && String(priorMonarch.etherAddress).toLowerCase() === receiverAddress.toLowerCase(),
      receiverPaidAsExpected: receiverBalanceAfter - receiverBalanceBefore === expectedReceiverIncrease,
      contractRetainedFailedCompensation: receiverName === 'rejecting'
        ? contractBalanceAfter - contractBalanceBefore === nextPrice
        : contractBalanceAfter - contractBalanceBefore === commission,
    },
  };
}

(async () => {
  const sourcePath = path.resolve(process.argv[2] || '');
  const sourceBytes = fs.readFileSync(sourcePath);
  const source = sourceBytes.toString('utf8');
  const sourceSha256 = digest(sourceBytes);
  if (sourceSha256 !== EXPECTED_SHA256 || process.env.TRAINING_SOURCE_SHA256 !== EXPECTED_SHA256) {
    throw new Error('training_kotet_source_hash_mismatch');
  }
  if (String(process.env.BENCHMARK_SOLC_VERSION || '').split('+', 1)[0] !== '0.4.26'
      || !String(solc.version()).startsWith('0.4.26+')) throw new Error('training_kotet_requires_exact_solc_0.4.26');
  const compilerArtifactSha256 = String(process.env.BENCHMARK_SOLC_SHA256 || '').replace(/^0x/, '');
  if (!/^[a-f0-9]{64}$/i.test(compilerArtifactSha256)) throw new Error('training_kotet_compiler_hash_missing');
  const claimDeclaration = source.match(/function\s+claimThrone\s*\([^)]*\)\s*([^{}]*)\{/);
  const fallbackDeclaration = source.match(/function\s*\(\s*\)\s*([^{}]*)\{/);
  if (!claimDeclaration || !/\bpayable\b/.test(claimDeclaration[1])
      || !fallbackDeclaration || !/\bpayable\b/.test(fallbackDeclaration[1])) {
    const result = {
      schemaVersion: 1, sampleId: 'crytic-kotet-unchecked-compensation',
      state: 'harness_not_feasible', confirmedVulnerability: false,
      vulnerability: 'unchecked_compensation_send_with_state_advance',
      sourceSha256, compilerVersion: solc.version(), compilerArtifactSha256,
      reason: 'collected_claim_and_fallback_entrypoints_are_nonpayable',
      proofScope: 'The exact source does not expose a payable claimThrone function or payable fallback, so it cannot accept the minimum claim price required to reach the unchecked compensation send. No repaired source or asset-impact claim is substituted.',
      assertions: [{ name: 'claim_path_accepts_required_eth', passed: false },
        { name: 'fallback_accepts_required_eth', passed: false }],
    };
    process.stdout.write(`${JSON.stringify(result)}\n`);
    return;
  }
  const fork = parseForkConfig(process.env);
  if (fork.requested || !fork.valid || hre.network.name !== 'hardhat' || hre.network.config.url || hre.network.config.forking) {
    throw new Error('training_kotet_requires_isolated_local_evm');
  }
  const sourceName = path.basename(sourcePath);
  const compiled = compile(sourceName, sourceBytes.toString('utf8'));
  const artifacts = {
    throne: artifact(compiled, sourceName, 'KingOfTheEtherThrone'),
    rejecting: artifact(compiled, 'KotetActors.sol', 'RejectingMonarch'),
    accepting: artifact(compiled, 'KotetActors.sol', 'AcceptingMonarch'),
  };
  const provider = new BrowserProvider(hre.network.provider);
  const chainId = Number((await provider.getNetwork()).chainId);
  if (chainId !== LOCAL_CHAIN_ID) throw new Error('training_kotet_chain_id_mismatch');
  const rejecting = await runScenario(provider, artifacts, 'rejecting', artifacts.rejecting);
  const accepting = await runScenario(provider, artifacts, 'accepting', artifacts.accepting);
  const rejectedCompensation = BigInt(rejecting.contractBalanceAfterWei) - BigInt(rejecting.contractBalanceBeforeWei);
  const acceptedCompensation = BigInt(accepting.contractBalanceAfterWei) - BigInt(accepting.contractBalanceBeforeWei);
  const confirmed = Object.values(rejecting.assertions).every(Boolean)
    && Object.values(accepting.assertions).every(Boolean)
    && rejectedCompensation - acceptedCompensation === BigInt(rejecting.compensationWei);
  const assertions = [
    { name: 'ignored_failed_send_does_not_rollback_monarch_state', passed: rejecting.assertions.throneAdvancedDespitePayoutOutcome },
    { name: 'rejecting_prior_monarch_receives_no_compensation', passed: rejecting.assertions.receiverPaidAsExpected },
    { name: 'failed_compensation_remains_in_contract_balance', passed: rejecting.assertions.contractRetainedFailedCompensation },
    { name: 'accepting_control_receives_compensation', passed: accepting.assertions.receiverPaidAsExpected },
    { name: 'contract_balance_delta_matches_unpaid_compensation', passed: rejectedCompensation - acceptedCompensation === BigInt(rejecting.compensationWei) },
  ];
  const result = {
    schemaVersion: 1, sampleId: 'crytic-kotet-unchecked-compensation',
    state: confirmed ? 'confirmed' : 'unconfirmed', confirmedVulnerability: confirmed,
    vulnerability: 'unchecked_compensation_send_with_state_advance',
    proofScope: 'On the pinned local source, the same throne transition advances to the new monarch when the prior monarch rejects its compensation; the previous monarch receives zero while the contract retains the unpaid amount. An accepting prior monarch receives that compensation and leaves only the commission in contract balance. This is a local source-specific payout/state result, not evidence about any live deployment.',
    mode: 'isolated_in_process', compilerVersion: solc.version(), compilerArtifactSha256,
    compilerKind: 'solc-js-original-source', sourceSha256,
    scenarios: { rejecting, accepting }, assertions,
    executionBoundary: publicBoundary(fork, { chainId, forkState: 'not_performed' }),
    reason: confirmed ? null : 'uncheckedsend_state_or_asset_assertion_failed',
  };
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (!confirmed) process.exitCode = 1;
})().catch((error) => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 2;
});
