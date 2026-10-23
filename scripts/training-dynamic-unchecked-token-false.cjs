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

const FALSE_RETURNING_TOKEN = `pragma solidity ^0.4.11;
contract FalseReturningERC20 {
    mapping(address => uint256) public balanceOf;
    uint256 public transferCalls;
    bool public lastTransferReturn;

    function seed(address account, uint256 amount) public {
        balanceOf[account] = amount;
    }

    function transfer(address, uint256) public returns (bool) {
        transferCalls += 1;
        lastTransferReturn = false;
        return false;
    }
}`;

const NUM_TRANSFERS_SLOT = 14n;

function digest(value) { return crypto.createHash('sha256').update(value).digest('hex'); }

function compile(sourceName, source) {
  const input = {
    language: 'Solidity',
    sources: { [sourceName]: { content: source }, 'FalseReturningERC20.sol': { content: FALSE_RETURNING_TOKEN } },
    settings: { optimizer: { enabled: false }, outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } } },
  };
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

async function storageWord(provider, address, slot) {
  return BigInt(await provider.send('eth_getStorageAt', [address, `0x${slot.toString(16)}`, 'latest']));
}

(async () => {
  const sourcePath = path.resolve(process.argv[2] || '');
  const sourceBytes = fs.readFileSync(sourcePath);
  const source = sourceBytes.toString('utf8');
  const sourceSha256 = digest(sourceBytes);
  const expectedSha256 = process.env.TRAINING_SOURCE_SHA256 || '';
  if (!/^[a-f0-9]{64}$/.test(expectedSha256) || sourceSha256 !== expectedSha256) {
    throw new Error('training_unchecked_token_source_hash_mismatch');
  }
  if (process.env.CORPUS_DEFER_MERGE !== '1') throw new Error('corpus_defer_merge_required');
  if (String(process.env.BENCHMARK_SOLC_VERSION || '').split('+', 1)[0] !== '0.4.26'
      || !String(solc.version()).startsWith('0.4.26+')) {
    throw new Error('training_unchecked_token_requires_exact_solc_0_4_26');
  }
  const compilerArtifactSha256 = String(process.env.BENCHMARK_SOLC_SHA256 || '').replace(/^0x/, '');
  if (!/^[a-f0-9]{64}$/i.test(compilerArtifactSha256)) throw new Error('training_unchecked_token_compiler_hash_missing');
  const fork = parseForkConfig(process.env);
  if (fork.requested || !fork.valid) throw new Error('training_unchecked_token_requires_isolated_local_evm');

  const sourceName = path.basename(sourcePath);
  const contracts = compile(sourceName, source);
  const daoArtifact = artifact(contracts, sourceName, 'daoPOLSKAtokens');
  const tokenArtifact = artifact(contracts, 'FalseReturningERC20.sol', 'FalseReturningERC20');
  if (hre.network.name !== 'hardhat' || hre.network.config.url || hre.network.config.forking) {
    throw new Error('training_unchecked_token_evm_not_isolated');
  }
  const provider = new BrowserProvider(hre.network.provider);
  const chainId = Number((await provider.getNetwork()).chainId);
  if (chainId !== LOCAL_CHAIN_ID) throw new Error('training_unchecked_token_chain_id_mismatch');
  const owner = await provider.getSigner(0);
  const recipient = await provider.getSigner(1);
  const [daoDeployment, tokenDeployment] = await Promise.all([
    deploy(owner, daoArtifact), deploy(owner, tokenArtifact),
  ]);
  const dao = daoDeployment.contract;
  const token = tokenDeployment.contract;
  const daoAddress = await dao.getAddress();
  const tokenAddress = await token.getAddress();
  const ownerAddress = (await owner.getAddress()).toLowerCase();
  const recipientAddress = (await recipient.getAddress()).toLowerCase();

  const seeded = await (await token.getFunction('seed')(daoAddress, 100n)).wait();
  if (seeded.status !== 1) throw new Error('mock_token_seed_failed');
  const countBefore = await storageWord(provider, daoAddress, NUM_TRANSFERS_SLOT);
  const sourceBalanceBefore = await token.getFunction('balanceOf')(daoAddress);
  const recipientBalanceBefore = await token.getFunction('balanceOf')(recipientAddress);
  const attemptReceipt = await (await dao.getFunction('sendTokenAw')(tokenAddress, recipientAddress, 40n,
    { gasLimit: 1_500_000 })).wait();
  const countAfter = await storageWord(provider, daoAddress, NUM_TRANSFERS_SLOT);
  const sourceBalanceAfter = await token.getFunction('balanceOf')(daoAddress);
  const recipientBalanceAfter = await token.getFunction('balanceOf')(recipientAddress);
  const transferCalls = await token.getFunction('transferCalls')();
  const transferReturn = await token.getFunction('lastTransferReturn')();

  const tokenReturnedFalse = transferCalls === 1n && transferReturn === false;
  const balancesUnchanged = sourceBalanceBefore === 100n && sourceBalanceAfter === 100n
    && recipientBalanceBefore === 0n && recipientBalanceAfter === 0n;
  const bookkeepingAdvanced = countBefore === 0n && countAfter === 1n;
  const impactDemonstrated = attemptReceipt.status === 1 && tokenReturnedFalse && balancesUnchanged && bookkeepingAdvanced;
  const assertions = [
    { name: 'mock_erc20_transfer_was_called_and_returned_false', passed: tokenReturnedFalse },
    { name: 'transfer_receipt_succeeded_despite_false_token_result', passed: attemptReceipt.status === 1 },
    { name: 'caller_transfer_counter_advanced', passed: bookkeepingAdvanced },
    { name: 'failed_mock_transfer_moved_no_tokens', passed: balancesUnchanged },
  ];
  const result = {
    schemaVersion: 1,
    sampleId: 'smartbugs-unchecked-token-transfer-bookkeeping',
    state: impactDemonstrated ? 'confirmed' : 'unconfirmed',
    confirmedVulnerability: impactDemonstrated,
    impactDemonstrated,
    vulnerability: 'unchecked_erc20_false_return_advances_transfer_bookkeeping',
    proofScope: 'In the exact DAO Polska source, owner-only sendTokenAw records a transfer entry and increments numTransfers without checking ERC20.transfer return. A false-returning local mock leaves token balances unchanged while the caller transaction succeeds and advances its transfer counter. This demonstrates failed-transfer bookkeeping only; no asset loss or live deployment behavior is claimed.',
    mode: 'isolated_in_process',
    compilerVersion: solc.version(),
    compilerArtifactSha256,
    sourceSha256,
    targetAddresses: { dao: daoAddress, mockToken: tokenAddress, owner: ownerAddress, recipient: recipientAddress },
    storageObservation: { numTransfersSlot: NUM_TRANSFERS_SLOT.toString(), before: countBefore.toString(), after: countAfter.toString() },
    tokenObservation: {
      transferCalls: transferCalls.toString(), returnedFalse: transferReturn,
      daoBalanceBefore: sourceBalanceBefore.toString(), daoBalanceAfter: sourceBalanceAfter.toString(),
      recipientBalanceBefore: recipientBalanceBefore.toString(), recipientBalanceAfter: recipientBalanceAfter.toString(),
    },
    transaction: { status: Number(attemptReceipt.status), hash: attemptReceipt.hash,
      gasUsed: attemptReceipt.gasUsed.toString() },
    assertions,
    executionBoundary: publicBoundary(fork, { chainId, forkState: 'not_performed' }),
    reason: impactDemonstrated ? null : 'false_return_or_bookkeeping_impact_assertion_failed',
  };
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (!impactDemonstrated) process.exitCode = 1;
})().catch((error) => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 2;
});
