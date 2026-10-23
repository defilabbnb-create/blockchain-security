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

const SPECS = Object.freeze({
  '10-dos_address': { contract: 'DosGas', vulnerability: 'denial_of_service' },
  '11-dos_simple': { contract: 'DosOneFunc', vulnerability: 'denial_of_service' },
  '12-eth_tx_order_dependence_minimal': { contract: 'EthTxOrderDependenceMinimal', vulnerability: 'front_running' },
  '17-timed_crowdsale': { contract: 'TimedCrowdsale', vulnerability: 'time_manipulation' },
  '18-lotto': { contract: 'Lotto', vulnerability: 'unchecked_low_level_calls' },
});

function digest(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

function compile(sourceName, source) {
  const input = {
    language: 'Solidity',
    sources: { [sourceName]: { content: source } },
    settings: { optimizer: { enabled: false }, outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } } },
  };
  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (output.errors || []).filter((item) => item.severity === 'error');
  if (errors.length) throw new Error(`source_compile_failed:${errors.map((item) => item.formattedMessage).join('\n')}`);
  const entry = output.contracts?.[sourceName]?.[Object.keys(output.contracts?.[sourceName] || {})[0]];
  if (!entry?.abi || !entry?.evm?.bytecode?.object) throw new Error('benchmark_contract_artifact_missing');
  return entry;
}

async function deploy(entry, signer) {
  const contract = await new ContractFactory(entry.abi, entry.evm.bytecode.object, signer).deploy();
  const receipt = await contract.deploymentTransaction().wait();
  await contract.waitForDeployment();
  return { contract, transactionHash: receipt.hash };
}

async function execute(caseId, target, provider) {
  const txHashes = [];
  if (caseId === '10-dos_address') {
    for (let index = 0; index < 5; index += 1) {
      txHashes.push((await (await target.addCreditors()).wait()).hash);
    }
    const before = (await target.numberCreditors()).toString();
    const cleared = await (await target.emptyCreditors()).wait();
    const after = (await target.numberCreditors()).toString();
    return {
      observation: { creditorsBefore: before, creditorsAfter: after, win: await target.iWin() },
      transactionHashes: [...txHashes, cleared.hash],
      reason: 'array_state_changed_without_external_call_or_asset_impact',
      findingScope: 'Only the creditor-array state transition was observed. No external call, user asset, or gas-limit denial was demonstrated.',
    };
  }
  if (caseId === '11-dos_simple') {
    const failedCalls = [];
    for (let index = 0; index < 6; index += 1) {
      try {
        const tx = await target.ifillArray();
        txHashes.push((await tx.wait()).hash);
      } catch (error) {
        const receipt = error?.receipt;
        failedCalls.push({
          call: index + 1,
          reason: 'array_reset_branch_exceeded_local_block_gas_limit',
          transactionHash: receipt?.hash || error?.transactionHash || null,
          status: receipt?.status ?? 0,
        });
        break;
      }
    }
    const failed = failedCalls.length > 0;
    return {
      observation: {
        calls: txHashes.length,
        finalState: failed ? 'array_reset_branch_reverted' : 'array_reset_after_threshold',
        failedCalls,
      },
      transactionHashes: txHashes,
      reason: failed
        ? 'array_reset_branch_hit_local_gas_limit_without_victim_lockout_or_asset_impact'
        : 'array_fill_and_reset_observed_without_external_call_or_asset_impact',
      findingScope: failed
        ? 'The repeated-write path reached a gas-limited reset attempt. No victim-facing lockout or asset impact was demonstrated.'
        : 'Only repeated array writes and the reset branch were observed. No victim-facing lockout or asset impact was demonstrated.',
    };
  }
  if (caseId === '12-eth_tx_order_dependence_minimal') {
    const owner = target.runner;
    const attacker = await provider.getSigner(1);
    const setReward = await (await target.connect(owner).setReward({ value: 10n ** 18n })).wait();
    const claim = await (await target.connect(attacker).claimReward(1n)).wait();
    txHashes.push(setReward.hash, claim.hash);
    return {
      observation: { attackerClaimed: claim.status === 1, claimed: await target.claimed(), rewardAfter: (await target.reward()).toString() },
      transactionHashes: txHashes,
      reason: 'reward_claim_path_reproduced_but_pending_transaction_ordering_was_not_modeled',
      findingScope: 'An unauthorized address could claim after reward setup, but this isolated run does not prove a mempool ordering race.',
    };
  }
  if (caseId === '17-timed_crowdsale') {
    const finished = await target.isSaleFinished();
    return {
      observation: { saleFinishedAtCurrentChainTime: finished, cutoffUnix: '1546300800' },
      transactionHashes: [],
      reason: 'timestamp_boundary_observed_without_state_or_asset_impact',
      findingScope: 'Only the current timestamp comparison was observed. No dependent settlement, payout, or asset impact exists in this source.',
    };
  }
  const sendToWinner = await (await target.sendToWinner()).wait();
  const withdrawLeftOver = await (await target.withdrawLeftOver()).wait();
  txHashes.push(sendToWinner.hash, withdrawLeftOver.hash);
  return {
    observation: { payedOut: await target.payedOut(), winner: await target.winner(), winAmount: (await target.winAmount()).toString() },
    transactionHashes: txHashes,
    reason: 'unchecked_send_observed_without_reachable_value_or_failure_impact',
    findingScope: 'The unchecked send path was called with zero-valued, unreachable winner state; no failed transfer or asset loss was demonstrated.',
  };
}

(async () => {
  const caseId = process.argv[2];
  const sourcePath = path.resolve(process.argv[3] || '');
  const spec = SPECS[caseId];
  if (!spec) throw new Error(`unsupported_dynamic_case:${caseId}`);
  const sourceName = path.basename(sourcePath);
  const source = fs.readFileSync(sourcePath, 'utf8');
  const sourceSha256 = digest(source);
  const compilerRelease = String(process.env.BENCHMARK_SOLC_VERSION || '').split('+', 1)[0];
  if (!/^0\.\d+\.\d+$/.test(compilerRelease) || solc.version().split('+', 1)[0] !== compilerRelease) {
    throw new Error('benchmark_compiler_version_mismatch');
  }
  const fork = parseForkConfig(process.env);
  if (fork.requested || !fork.valid) throw new Error('benchmark_dynamic_requires_isolated_local_evm');
  if (hre.network.name !== 'hardhat' || hre.network.config.url || hre.network.config.forking) throw new Error('benchmark_evm_not_isolated');
  const provider = new BrowserProvider(hre.network.provider);
  const chainId = Number((await provider.getNetwork()).chainId);
  if (chainId !== LOCAL_CHAIN_ID) throw new Error('benchmark_evm_chain_id_mismatch');
  const signer = await provider.getSigner(0);
  const entry = compile(sourceName, source);
  const deployed = await deploy(entry, signer);
  const evidence = await execute(caseId, deployed.contract, provider);
  const result = {
    schemaVersion: 1, caseId, state: 'unconfirmed', confirmedVulnerability: false,
    vulnerability: spec.vulnerability, mode: 'isolated_in_process',
    compilerVersion: solc.version(), compilerKind: 'solc-js-original-source',
    compilerArtifactSha256: process.env.BENCHMARK_SOLC_SHA256 || null,
    sourceSha256, sourceFile: sourceName, targetAddress: await deployed.contract.getAddress(),
    deploymentTransactionHash: deployed.transactionHash, ...evidence,
    executionBoundary: publicBoundary(fork, { chainId, forkState: 'not_performed' }),
    reproduction: '在隔离本地 EVM 中执行可达观察路径；结果仅记录状态观察，不把影响未确认升级为漏洞确认。',
  };
  process.stdout.write(`${JSON.stringify(result)}\n`);
})().catch((error) => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 1;
});
