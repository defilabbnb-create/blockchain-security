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

const RECEIVERS = `pragma solidity ^0.4.18;
contract RejectingHolder {
    uint public rejectedPayoutAttempts;
    function contribute(address bank) public payable { require(bank.call.value(msg.value)()); }
    function() public payable { rejectedPayoutAttempts += 1; revert(); }
}
contract AcceptingHolder {
    uint public received;
    function contribute(address bank) public payable { require(bank.call.value(msg.value)()); }
    function() public payable { received += msg.value; }
}`;

const EXPECTED_SOURCE_SHA256 = '580b0f56fdf071e7d6831315c17498eb1a0e7b1d9857ebb964dcc9f9e37f3996';
const EXPECTED_COMPILER = '0.4.26';
const ETHER = 1000000000000000000n;

function digest(value) { return crypto.createHash('sha256').update(value).digest('hex'); }

function compile(sourceName, source) {
  const input = {
    language: 'Solidity',
    sources: { [sourceName]: { content: source }, 'TokenBankReceivers.sol': { content: RECEIVERS } },
    settings: { optimizer: { enabled: false }, outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } } },
  };
  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (output.errors || []).filter((entry) => entry.severity === 'error');
  if (errors.length) throw new Error(`source_compile_failed:${errors.map((entry) => entry.formattedMessage).join('\n')}`);
  return output.contracts;
}

function artifact(contracts, sourceName, contractName) {
  const result = contracts?.[sourceName]?.[contractName];
  if (!result?.abi || !result?.evm?.bytecode?.object) throw new Error(`artifact_missing:${sourceName}:${contractName}`);
  return result;
}

async function deploy(signer, item) {
  const contract = await new ContractFactory(item.abi, item.evm.bytecode.object, signer).deploy();
  const receipt = await contract.deploymentTransaction().wait();
  if (receipt.status !== 1) throw new Error('deployment_failed');
  await contract.waitForDeployment();
  return { contract, receipt };
}

async function balance(provider, address) {
  return BigInt(await provider.send('eth_getBalance', [address, 'latest']));
}

(async () => {
  const sourcePath = path.resolve(process.argv[2] || '');
  const sourceBytes = fs.readFileSync(sourcePath);
  const source = sourceBytes.toString('utf8');
  const sourceSha256 = digest(sourceBytes);
  if (sourceSha256 !== EXPECTED_SOURCE_SHA256 || process.env.TRAINING_SOURCE_SHA256 !== EXPECTED_SOURCE_SHA256) {
    throw new Error('tokenbank_source_hash_mismatch');
  }
  const compilerRelease = String(process.env.BENCHMARK_SOLC_VERSION || '').split('+', 1)[0];
  if (compilerRelease !== EXPECTED_COMPILER || !String(solc.version()).startsWith(`${EXPECTED_COMPILER}+`)) {
    throw new Error('tokenbank_requires_exact_solc_0.4.26');
  }
  const compilerArtifactSha256 = String(process.env.BENCHMARK_SOLC_SHA256 || '').replace(/^0x/, '');
  if (!/^[a-f0-9]{64}$/i.test(compilerArtifactSha256)) throw new Error('tokenbank_compiler_hash_missing');
  const fork = parseForkConfig(process.env);
  if (fork.requested || !fork.valid) throw new Error('tokenbank_requires_isolated_local_evm');
  if (hre.network.name !== 'hardhat' || hre.network.config.url || hre.network.config.forking) {
    throw new Error('tokenbank_evm_not_isolated');
  }

  const sourceName = path.basename(sourcePath);
  const contracts = compile(sourceName, source);
  const bankArtifact = artifact(contracts, sourceName, 'TokenBank');
  const rejectingArtifact = artifact(contracts, 'TokenBankReceivers.sol', 'RejectingHolder');
  const acceptingArtifact = artifact(contracts, 'TokenBankReceivers.sol', 'AcceptingHolder');
  const provider = new BrowserProvider(hre.network.provider);
  const chainId = Number((await provider.getNetwork()).chainId);
  if (chainId !== LOCAL_CHAIN_ID) throw new Error('tokenbank_chain_id_mismatch');
  const owner = await provider.getSigner(0);

  const { contract: bank, receipt: bankDeploy } = await deploy(owner, bankArtifact);
  const { contract: rejecting, receipt: rejectingDeploy } = await deploy(owner, rejectingArtifact);
  const { contract: accepting, receipt: acceptingDeploy } = await deploy(owner, acceptingArtifact);
  const bankAddress = await bank.getAddress();
  const rejectingAddress = await rejecting.getAddress();
  const acceptingAddress = await accepting.getAddress();
  const transactions = [bankDeploy, rejectingDeploy, acceptingDeploy].map((receipt) => ({
    name: 'deployment', status: receipt.status, hash: receipt.hash,
  }));

  const initReceipt = await (await bank.getFunction('initTokenBank')()).wait();
  const ownerDepositReceipt = await (await bank.getFunction('Deposit')({ value: 2n * ETHER })).wait();
  const rejectingDepositReceipt = await (await rejecting.getFunction('contribute')(bankAddress, { value: 2n * ETHER })).wait();
  const acceptingDepositReceipt = await (await accepting.getFunction('contribute')(bankAddress, { value: 2n * ETHER })).wait();
  transactions.push(...[
    ['initialize', initReceipt], ['owner_deposit', ownerDepositReceipt],
    ['rejecting_holder_deposit', rejectingDepositReceipt], ['accepting_holder_deposit', acceptingDepositReceipt],
  ].map(([name, receipt]) => ({ name, status: receipt.status, hash: receipt.hash })));

  const rejectionBefore = {
    holderCredit: await bank.getFunction('Holders')(rejectingAddress),
    bankBalance: await balance(provider, bankAddress),
    recipientBalance: await balance(provider, rejectingAddress),
  };
  const rejectedPayout1 = await (await bank.getFunction('WithdrawToHolder')(rejectingAddress, ETHER, {
    gasLimit: 500000,
  })).wait();
  const rejectionAfter = {
    holderCredit: await bank.getFunction('Holders')(rejectingAddress),
    bankBalance: await balance(provider, bankAddress),
    recipientBalance: await balance(provider, rejectingAddress),
  };
  const rejectedPayout2 = await (await bank.getFunction('WithdrawToHolder')(rejectingAddress, ETHER, {
    gasLimit: 500000,
  })).wait();
  const rejectionFinal = {
    holderCredit: await bank.getFunction('Holders')(rejectingAddress),
    bankBalance: await balance(provider, bankAddress),
    recipientBalance: await balance(provider, rejectingAddress),
    fallbackAttempts: await rejecting.getFunction('rejectedPayoutAttempts')(),
  };
  transactions.push({ name: 'uninvoked_rejecting_payout_1', status: rejectedPayout1.status, hash: rejectedPayout1.hash });
  transactions.push({ name: 'uninvoked_rejecting_payout_2', status: rejectedPayout2.status, hash: rejectedPayout2.hash });

  const controlBefore = {
    holderCredit: await bank.getFunction('Holders')(acceptingAddress),
    bankBalance: await balance(provider, bankAddress),
    recipientBalance: await balance(provider, acceptingAddress),
  };
  const successfulPayout = await (await bank.getFunction('WithdrawToHolder')(acceptingAddress, ETHER, {
    gasLimit: 500000,
  })).wait();
  const acceptingRecordedReceived = await accepting.getFunction('received')();
  const controlAfter = {
    holderCredit: await bank.getFunction('Holders')(acceptingAddress),
    bankBalance: await balance(provider, bankAddress),
    recipientBalance: await balance(provider, acceptingAddress),
  };
  transactions.push({ name: 'successful_payout_control', status: successfulPayout.status, hash: successfulPayout.hash });

  const callExpressionLostClaim = rejectedPayout1.status === 1 && rejectedPayout2.status === 1
    && rejectionBefore.holderCredit === 2n * ETHER
    && rejectionAfter.holderCredit === ETHER
    && rejectionFinal.holderCredit === 0n
    && rejectionFinal.bankBalance === rejectionBefore.bankBalance
    && rejectionFinal.recipientBalance === rejectionBefore.recipientBalance
    && rejectionFinal.fallbackAttempts === 0n;
  const acceptingRecipientObservation = successfulPayout.status === 1
    && controlBefore.holderCredit === 2n * ETHER
    && controlAfter.holderCredit === ETHER
    && controlAfter.bankBalance === controlBefore.bankBalance
    && controlAfter.recipientBalance === controlBefore.recipientBalance
    && acceptingRecordedReceived === 0n;
  const confirmed = callExpressionLostClaim && acceptingRecipientObservation
    && transactions.every((transaction) => transaction.status === 1);
  const assertions = [
    { name: 'two_withdrawals_clear_holder_credit_without_asset_transfer_or_fallback', passed: callExpressionLostClaim },
    { name: 'accepting_recipient_also_receives_no_call_while_credit_is_decremented', passed: acceptingRecipientObservation },
  ];
  const serialize = (record) => Object.fromEntries(Object.entries(record).map(([key, value]) => [key,
    typeof value === 'bigint' ? value.toString() : value]));
  const result = {
    schemaVersion: 1,
    sampleId: 'smartbugs-unchecked-tokenbank-withdraw',
    state: confirmed ? 'confirmed' : 'unconfirmed',
    confirmedVulnerability: confirmed,
    vulnerability: 'uninvoked_payout_expression_with_asset_credit_decrement',
    proofScope: confirmed
      ? 'The source expression `_addr.call.value(_wei);` does not invoke either rejecting or accepting recipient fallback in the isolated EVM. Two successful owner withdrawal transactions reduce the rejecting holder credit from 2 ETH to zero, while the bank still holds all deposited ETH, the holder balance is unchanged, and the rejecting fallback counter remains zero. This confirms loss of the recorded withdrawal claim in this local source harness; it does not show an external asset transfer or theft.'
      : 'The local recipient-credit, no-fallback, or unchanged-bank-asset assertions did not all hold.',
    mode: 'isolated_in_process',
    compilerVersion: solc.version(),
    compilerKind: 'solc-js-original-source',
    compilerArtifactSha256,
    sourceSha256,
    targetAddress: bankAddress,
    rejectingHolderAddress: rejectingAddress,
    acceptingHolderAddress: acceptingAddress,
    payoutWei: ETHER.toString(),
    rejectingRecipient: { before: serialize(rejectionBefore), afterFirstWithdrawal: serialize(rejectionAfter),
      afterSecondWithdrawal: serialize(rejectionFinal) },
    successfulControl: { before: serialize(controlBefore), after: serialize(controlAfter),
      recipientRecordedReceivedWei: acceptingRecordedReceived.toString() },
    transactions,
    assertions,
    executionBoundary: publicBoundary(fork, { chainId, forkState: 'not_performed' }),
    reason: confirmed ? null : 'tokenbank_noop_call_or_asset_credit_assertion_failed',
  };
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (!confirmed) process.exitCode = 1;
})().catch((error) => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 2;
});
