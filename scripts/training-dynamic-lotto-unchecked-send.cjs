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

const EXPECTED_SOURCE_SHA256 = '42df68b79df9483a424dc0ce1aba6fd2382b20339ca23a62e881c52a52575b2f';
const EXPECTED_COMPILER = '0.4.26';
const ETHER = 1000000000000000000n;
const PRIZE_POOL = 160n * ETHER;
const SUBPOTS = 32n;
const PARTICIPANTS = `pragma solidity ^0.4.0;
contract RejectingLotteryWinner {
    function buy(address lotto) public payable { require(lotto.call.value(msg.value)()); }
    function() public payable { revert(); }
}
contract AcceptingLotteryWinner {
    uint public received;
    function buy(address lotto) public payable { require(lotto.call.value(msg.value)()); }
    function() public payable { received += msg.value; }
}`;

function digest(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }

function compile(sourceName, source) {
  const input = { language: 'Solidity', sources: {
    [sourceName]: { content: source }, 'LotteryParticipants.sol': { content: PARTICIPANTS },
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

async function deploy(signer, item) {
  const contract = await new ContractFactory(item.abi, item.evm.bytecode.object, signer).deploy();
  const receipt = await contract.deploymentTransaction().wait();
  if (receipt.status !== 1) throw new Error('deployment_failed');
  await contract.waitForDeployment();
  return { contract, receipt };
}

async function setupLottery(signer, lottoArtifact, participantArtifact, participantName) {
  const lotto = (await deploy(signer, lottoArtifact)).contract;
  const participant = (await deploy(signer, participantArtifact)).contract;
  const lottoAddress = await lotto.getAddress();
  const participantAddress = await participant.getAddress();
  const buyReceipt = await (await participant.getFunction('buy')(lottoAddress, {
    value: PRIZE_POOL, gasLimit: 1000000,
  })).wait();
  const roundIndex = BigInt(await lotto.getFunction('getRoundIndex')());
  const potBefore = BigInt(await lotto.getFunction('getPot')(roundIndex));
  const balanceBefore = BigInt(await signer.provider.getBalance(lottoAddress));
  return { lotto, participant, lottoAddress, participantAddress, participantName, roundIndex,
    buyReceipt, potBefore, balanceBefore };
}

(async () => {
  const sourcePath = path.resolve(process.argv[2] || '');
  const sourceBytes = fs.readFileSync(sourcePath);
  const source = sourceBytes.toString('utf8');
  const sourceSha256 = digest(sourceBytes);
  if (sourceSha256 !== EXPECTED_SOURCE_SHA256 || process.env.TRAINING_SOURCE_SHA256 !== EXPECTED_SOURCE_SHA256) {
    throw new Error('lotto_source_hash_mismatch');
  }
  if (String(process.env.BENCHMARK_SOLC_VERSION || '').split('+', 1)[0] !== EXPECTED_COMPILER
      || !String(solc.version()).startsWith(`${EXPECTED_COMPILER}+`)) {
    throw new Error('lotto_requires_exact_solc_0.4.26');
  }
  const compilerArtifactSha256 = String(process.env.BENCHMARK_SOLC_SHA256 || '').replace(/^0x/, '');
  if (!/^[a-f0-9]{64}$/i.test(compilerArtifactSha256)) throw new Error('lotto_compiler_hash_missing');
  const fork = parseForkConfig(process.env);
  if (fork.requested || !fork.valid) throw new Error('lotto_requires_isolated_local_evm');
  if (hre.network.name !== 'hardhat' || hre.network.config.url || hre.network.config.forking) {
    throw new Error('lotto_evm_not_isolated');
  }

  const sourceName = path.basename(sourcePath);
  const contracts = compile(sourceName, source);
  const lottoArtifact = artifact(contracts, sourceName, 'Lotto');
  const rejectingArtifact = artifact(contracts, 'LotteryParticipants.sol', 'RejectingLotteryWinner');
  const acceptingArtifact = artifact(contracts, 'LotteryParticipants.sol', 'AcceptingLotteryWinner');
  const fallbackEntry = lottoArtifact.abi.find((entry) => entry.type.toLowerCase() === 'fallback');
  const fallbackPayable = fallbackEntry?.payable === true || fallbackEntry?.stateMutability === 'payable';
  if (!fallbackPayable) {
    process.stdout.write(`${JSON.stringify({
      schemaVersion: 1, sampleId: 'etherpot-lotto-unchecked-winner-send',
      state: 'harness_not_feasible', confirmedVulnerability: false,
      vulnerability: 'unchecked_winner_payout_permanently_marks_subpot_cashed',
      reason: 'source_fallback_is_nonpayable_so_no_ticket_or_pot_can_be_created_through_public_entrypoint',
      sourceSha256, compilerVersion: solc.version(), compilerArtifactSha256,
      proofScope: 'The exact source compiles with a nonpayable fallback, and has no other public path to create tickets or populate a round pot. The `cash` unchecked-send path therefore cannot be reached with a valid source-level lottery state; no vulnerability claim is made.',
      assertions: [{ name: 'original_fallback_accepts_ticket_payment', passed: false }],
      executionBoundary: publicBoundary(fork, { chainId: LOCAL_CHAIN_ID, forkState: 'not_performed' }),
    })}\n`);
    return;
  }
  const provider = new BrowserProvider(hre.network.provider);
  const chainId = Number((await provider.getNetwork()).chainId);
  if (chainId !== LOCAL_CHAIN_ID) throw new Error('lotto_chain_id_mismatch');
  const signer = await provider.getSigner(0);
  const rejecting = await setupLottery(signer, lottoArtifact, rejectingArtifact, 'rejecting');
  const accepting = await setupLottery(signer, lottoArtifact, acceptingArtifact, 'accepting');
  if (rejecting.roundIndex !== accepting.roundIndex || rejecting.roundIndex !== 0n
      || rejecting.potBefore !== PRIZE_POOL || accepting.potBefore !== PRIZE_POOL
      || rejecting.balanceBefore !== PRIZE_POOL || accepting.balanceBefore !== PRIZE_POOL) {
    throw new Error('lotto_round_or_prize_setup_mismatch');
  }

  const lastDecisionBlock = Number(await rejecting.lotto.getFunction('getDecisionBlockNumber')(
    rejecting.roundIndex, SUBPOTS - 1n));
  const currentBlock = Number(await provider.send('eth_blockNumber', []));
  if (currentBlock <= lastDecisionBlock) {
    await provider.send('hardhat_mine', [`0x${(lastDecisionBlock + 1 - currentBlock).toString(16)}`]);
  }

  let selectedSubpot = null;
  let selectedWinner = null;
  for (let index = 0n; index < SUBPOTS; index += 1n) {
    const winner = String(await rejecting.lotto.getFunction('calculateWinner')(rejecting.roundIndex, index)).toLowerCase();
    if (winner === rejecting.participantAddress.toLowerCase()) {
      selectedSubpot = index;
      selectedWinner = winner;
      break;
    }
  }
  if (selectedSubpot === null) {
    const result = {
      schemaVersion: 1, sampleId: 'etherpot-lotto-unchecked-winner-send',
      state: 'unconfirmed', confirmedVulnerability: false,
      vulnerability: 'unchecked_winner_payout_permanently_marks_subpot_cashed',
      reason: 'no_nonzero_winner_found_in_source_defined_subpots', sourceSha256,
      inspectedSubpots: SUBPOTS.toString(), compilerVersion: solc.version(), compilerArtifactSha256,
      mode: 'isolated_in_process',
      executionBoundary: publicBoundary(fork, { chainId, forkState: 'not_performed' }),
    };
    process.stdout.write(`${JSON.stringify(result)}\n`);
    process.exitCode = 0;
    return;
  }
  const controlWinner = String(await accepting.lotto.getFunction('calculateWinner')(
    accepting.roundIndex, selectedSubpot)).toLowerCase();
  if (controlWinner !== accepting.participantAddress.toLowerCase()) throw new Error('lotto_control_winner_mismatch');

  const prizeWei = BigInt(await rejecting.lotto.getFunction('getSubpot')(rejecting.roundIndex)).toString();
  const rejectCash = await (await rejecting.lotto.getFunction('cash')(rejecting.roundIndex, selectedSubpot, {
    gasLimit: 1000000,
  })).wait();
  const rejectCashed = await rejecting.lotto.getFunction('getIsCashed')(rejecting.roundIndex, selectedSubpot);
  const rejectBalanceAfter = BigInt(await provider.getBalance(rejecting.lottoAddress));
  const rejectRecipientAfter = BigInt(await provider.getBalance(rejecting.participantAddress));
  const acceptCash = await (await accepting.lotto.getFunction('cash')(accepting.roundIndex, selectedSubpot, {
    gasLimit: 1000000,
  })).wait();
  const acceptCashed = await accepting.lotto.getFunction('getIsCashed')(accepting.roundIndex, selectedSubpot);
  const acceptBalanceAfter = BigInt(await provider.getBalance(accepting.lottoAddress));
  const acceptRecipientAfter = BigInt(await provider.getBalance(accepting.participantAddress));
  const acceptingReceived = BigInt(await accepting.participant.getFunction('received')());
  const repeatReceipt = await (await rejecting.lotto.getFunction('cash')(rejecting.roundIndex, selectedSubpot, {
    gasLimit: 1000000,
  })).wait();
  const rejectBalanceAfterRetry = BigInt(await provider.getBalance(rejecting.lottoAddress));

  const failedPayoutLocksClaim = rejectCash.status === 1 && repeatReceipt.status === 1
    && rejectCashed === true && rejectBalanceAfter === rejecting.balanceBefore
    && rejectRecipientAfter === 0n && rejectBalanceAfterRetry === rejecting.balanceBefore;
  const successfulControlPaysWinner = acceptCash.status === 1 && acceptCashed === true
    && acceptBalanceAfter === accepting.balanceBefore - BigInt(prizeWei)
    && acceptingReceived === BigInt(prizeWei)
    && acceptRecipientAfter === BigInt(prizeWei);
  const assertions = [
    { name: 'failed_winner_send_still_marks_subpot_cashed_and_retains_prize', passed: failedPayoutLocksClaim },
    { name: 'accepting_winner_control_receives_same_prize', passed: successfulControlPaysWinner },
    { name: 'cash_retry_cannot_recover_failed_payout', passed: repeatReceipt.status === 1
      && rejectBalanceAfterRetry === rejecting.balanceBefore },
  ];
  const confirmed = assertions.every((assertion) => assertion.passed);
  const result = {
    schemaVersion: 1, sampleId: 'etherpot-lotto-unchecked-winner-send',
    state: confirmed ? 'confirmed' : 'unconfirmed', confirmedVulnerability: confirmed,
    vulnerability: 'unchecked_winner_payout_permanently_marks_subpot_cashed',
    proofScope: confirmed
      ? 'In this source-bound isolated EVM run, the selected winning contract reverts on the unchecked send. Lotto.cash still marks the subpot cashed and retains the prize; a repeat cash call cannot recover it. An otherwise identical accepting winner receives that same prize. This confirms a local lost payout claim, not an external deployment or market impact.'
      : 'The failed-payout or accepting-winner assertions did not all hold.',
    mode: 'isolated_in_process', compilerVersion: solc.version(), compilerArtifactSha256,
    compilerKind: 'solc-js-original-source', sourceSha256, prizeWei,
    selectedSubpot: selectedSubpot.toString(), selectedWinner,
    rejectingWinner: { address: rejecting.participantAddress, sendStatus: rejectCash.status,
      isCashed: rejectCashed, potBeforeWei: rejecting.potBefore.toString(),
      balanceBeforeWei: rejecting.balanceBefore.toString(), balanceAfterWei: rejectBalanceAfter.toString(),
      recipientBalanceAfterWei: rejectRecipientAfter.toString(), balanceAfterRetryWei: rejectBalanceAfterRetry.toString() },
    acceptingControl: { address: accepting.participantAddress, sendStatus: acceptCash.status,
      isCashed: acceptCashed, potBeforeWei: accepting.potBefore.toString(),
      balanceBeforeWei: accepting.balanceBefore.toString(), balanceAfterWei: acceptBalanceAfter.toString(),
      recipientBalanceAfterWei: acceptRecipientAfter.toString(), receivedWei: acceptingReceived.toString() },
    transactions: [rejecting.buyReceipt, accepting.buyReceipt, rejectCash, acceptCash, repeatReceipt]
      .map((receipt) => ({ status: receipt.status, hash: receipt.hash })),
    assertions,
    executionBoundary: publicBoundary(fork, { chainId, forkState: 'not_performed' }),
    reason: confirmed ? null : 'unchecked_winner_send_or_control_assertion_failed',
  };
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (!confirmed) process.exitCode = 1;
})().catch((error) => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 2;
});
