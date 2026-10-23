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
  const input = { language: 'Solidity', sources: { [sourceName]: { content: source } },
    settings: { optimizer: { enabled: false }, outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } } } };
  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (output.errors || []).filter((item) => item.severity === 'error');
  if (errors.length) throw new Error(`source_compile_failed:${errors.map((item) => item.formattedMessage).join('\n')}`);
  const item = output.contracts?.[sourceName]?.ERC20;
  if (!item?.abi || !item?.evm?.bytecode?.object) throw new Error('artifact_missing:ERC20');
  return item;
}

async function deploy(signer, artifact, args) {
  const contract = await new ContractFactory(artifact.abi, artifact.evm.bytecode.object, signer).deploy(...args);
  const receipt = await contract.deploymentTransaction().wait();
  if (receipt.status !== 1) throw new Error('deployment_failed');
  await contract.waitForDeployment();
  return contract;
}

async function transactionStatus(action) {
  try {
    const receipt = await (await action).wait();
    return Number(receipt.status);
  } catch (error) {
    return Number(error.receipt?.status ?? error.info?.receipt?.status ?? 0);
  }
}

async function scenario(provider, artifact, holder, spender, receiver, order) {
  const held = 1000n;
  const oldAllowance = 100n;
  const newAllowance = 50n;
  const token = await deploy(holder, artifact, [held]);
  const tokenAddress = await token.getAddress();
  const holderAddress = (await holder.getAddress()).toLowerCase();
  const spenderAddress = (await spender.getAddress()).toLowerCase();
  const receiverAddress = (await receiver.getAddress()).toLowerCase();
  const initialHolder = BigInt(await token.getFunction('balanceOf')(holderAddress));
  const initialReceiver = BigInt(await token.getFunction('balanceOf')(receiverAddress));
  await (await token.connect(holder).getFunction('approve')(spenderAddress, oldAllowance)).wait();

  let oldAllowanceSpendStatus = null;
  let newAllowanceApprovalStatus = null;
  let remainingAllowanceSpendStatus = null;
  if (order === 'spend_old_then_approve_new') {
    oldAllowanceSpendStatus = await transactionStatus(token.connect(spender).getFunction('transferFrom')(
      holderAddress, receiverAddress, oldAllowance, { gasLimit: 300000 },
    ));
    newAllowanceApprovalStatus = await transactionStatus(token.connect(holder).getFunction('approve')(
      spenderAddress, newAllowance, { gasLimit: 200000 },
    ));
    remainingAllowanceSpendStatus = await transactionStatus(token.connect(spender).getFunction('transferFrom')(
      holderAddress, receiverAddress, newAllowance, { gasLimit: 300000 },
    ));
  } else {
    newAllowanceApprovalStatus = await transactionStatus(token.connect(holder).getFunction('approve')(
      spenderAddress, newAllowance, { gasLimit: 200000 },
    ));
    oldAllowanceSpendStatus = await transactionStatus(token.connect(spender).getFunction('transferFrom')(
      holderAddress, receiverAddress, oldAllowance, { gasLimit: 300000 },
    ));
    remainingAllowanceSpendStatus = await transactionStatus(token.connect(spender).getFunction('transferFrom')(
      holderAddress, receiverAddress, newAllowance, { gasLimit: 300000 },
    ));
  }

  return {
    order, oldAllowance: oldAllowance.toString(), newAllowance: newAllowance.toString(),
    holderBalanceBefore: initialHolder.toString(),
    holderBalanceAfter: String(await token.getFunction('balanceOf')(holderAddress)),
    receiverBalanceBefore: initialReceiver.toString(),
    receiverBalanceAfter: String(await token.getFunction('balanceOf')(receiverAddress)),
    receiverBalanceGain: (BigInt(await token.getFunction('balanceOf')(receiverAddress)) - initialReceiver).toString(),
    totalSpent: (initialHolder - BigInt(await token.getFunction('balanceOf')(holderAddress))).toString(),
    allowanceAfter: String(await token.getFunction('allowance')(holderAddress, spenderAddress)),
    oldAllowanceSpendStatus, newAllowanceApprovalStatus, remainingAllowanceSpendStatus,
    transactions: [oldAllowanceSpendStatus, newAllowanceApprovalStatus, remainingAllowanceSpendStatus],
    tokenAddress,
  };
}

(async () => {
  const sourcePath = path.resolve(process.argv[2] || '');
  const sourceBytes = fs.readFileSync(sourcePath);
  const source = sourceBytes.toString('utf8');
  const sourceSha256 = digest(sourceBytes);
  const expectedSha256 = process.env.TRAINING_SOURCE_SHA256 || '';
  if (!/^[a-f0-9]{64}$/.test(expectedSha256) || sourceSha256 !== expectedSha256) {
    throw new Error('training_erc20_race_source_hash_mismatch');
  }
  if (String(process.env.BENCHMARK_SOLC_VERSION || '').split('+', 1)[0] !== '0.4.26'
      || !String(solc.version()).startsWith('0.4.26+')) {
    throw new Error('training_erc20_race_requires_exact_solc_0.4.26');
  }
  const compilerArtifactSha256 = String(process.env.BENCHMARK_SOLC_SHA256 || '').replace(/^0x/, '');
  if (!/^[a-f0-9]{64}$/i.test(compilerArtifactSha256)) throw new Error('training_erc20_race_compiler_hash_missing');
  const fork = parseForkConfig(process.env);
  if (fork.requested || !fork.valid) throw new Error('training_erc20_race_requires_isolated_local_evm');
  if (hre.network.name !== 'hardhat' || hre.network.config.url || hre.network.config.forking) {
    throw new Error('training_erc20_race_evm_not_isolated');
  }

  const artifact = compile(path.basename(sourcePath), source);
  const provider = new BrowserProvider(hre.network.provider);
  const chainId = Number((await provider.getNetwork()).chainId);
  if (chainId !== LOCAL_CHAIN_ID) throw new Error('training_erc20_race_chain_id_mismatch');
  const holder = await provider.getSigner(0);
  const spender = await provider.getSigner(1);
  const receiver = await provider.getSigner(2);
  const raced = await scenario(provider, artifact, holder, spender, receiver, 'spend_old_then_approve_new');
  const safeOrder = await scenario(provider, artifact, holder, spender, receiver, 'approve_new_then_spend');
  const confirmed = raced.transactions.every((status) => status === 1)
    && safeOrder.newAllowanceApprovalStatus === 1
    && safeOrder.oldAllowanceSpendStatus === 0
    && safeOrder.remainingAllowanceSpendStatus === 1
    && raced.totalSpent === '150' && safeOrder.totalSpent === '50'
    && raced.receiverBalanceGain === '150' && safeOrder.receiverBalanceGain === '50'
    && raced.allowanceAfter === '0' && safeOrder.allowanceAfter === '0'
    && raced.oldAllowanceSpendStatus === 1 && raced.newAllowanceApprovalStatus === 1
    && raced.remainingAllowanceSpendStatus === 1;
  const result = {
    schemaVersion: 1, sampleId: 'smartbugs-erc20-approve-race',
    state: confirmed ? 'confirmed' : 'unconfirmed', confirmedVulnerability: confirmed,
    vulnerability: 'erc20_approve_allowance_transaction_ordering',
    proofScope: 'The exact source ERC20 is deployed unchanged to an isolated local EVM. With old allowance 100 and holder intent to reduce allowance to 50, spender consumes 100 before approve(50) then spends another 50; the holder loses 150. In the control, approve(50) is mined first, a 100-token spend reverts, and only 50 is transferred. This establishes the ordering-dependent allowance race and asset delta locally; it does not model public mempool probability or a live deployment.',
    mode: 'isolated_in_process', compilerVersion: solc.version(), compilerArtifactSha256,
    compilerKind: 'solc-js-original-source', sourceSha256,
    raced, safeOrder, additionalHolderTokenLoss: (BigInt(raced.totalSpent) - BigInt(safeOrder.totalSpent)).toString(),
    assertions: [
      { name: 'old_allowance_is_spent_before_replacement_then_new_allowance_is_spent',
        passed: raced.oldAllowanceSpendStatus === 1 && raced.newAllowanceApprovalStatus === 1
          && raced.remainingAllowanceSpendStatus === 1 && raced.totalSpent === '150' },
      { name: 'replacement_first_blocks_old_allowance_spend_then_allows_new_limit',
        passed: safeOrder.newAllowanceApprovalStatus === 1 && safeOrder.oldAllowanceSpendStatus === 0
          && safeOrder.remainingAllowanceSpendStatus === 1 && safeOrder.totalSpent === '50' },
      { name: 'holder_loss_and_receiver_gain_match_ordering_delta',
        passed: raced.receiverBalanceGain === '150' && safeOrder.receiverBalanceGain === '50'
          && raced.allowanceAfter === '0' && safeOrder.allowanceAfter === '0' },
    ],
    executionBoundary: publicBoundary(fork, { chainId, forkState: 'not_performed' }),
    reason: confirmed ? null : 'allowance_ordering_asset_assertion_failed',
  };
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (!confirmed) process.exitCode = 1;
})().catch((error) => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 2;
});
