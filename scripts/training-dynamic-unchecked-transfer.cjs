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

const EXPECTED_SOURCE_SHA256 = 'b9c32c34e06c5b84561b827738b0f4d4fe60d4292516714f6a08cbc8925ccac0';
const EXPECTED_COMPILER = '0.4.26';
const MOCKS = `pragma solidity ^0.4.25;
contract FalseReturnToken {
    mapping(address => uint) public balanceOf;
    function seed(address holder, uint amount) public { balanceOf[holder] = amount; }
    function transferFrom(address, address, uint) public returns (bool) { return false; }
}
contract SuccessfulToken {
    mapping(address => uint) public balanceOf;
    function seed(address holder, uint amount) public { balanceOf[holder] = amount; }
    function transferFrom(address from, address to, uint amount) public returns (bool) {
        require(balanceOf[from] >= amount);
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}`;

function digest(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }

function compile(sourceName, source) {
  const input = {
    language: 'Solidity',
    sources: { [sourceName]: { content: source }, 'UncheckedTransferMocks.sol': { content: MOCKS } },
    settings: { optimizer: { enabled: false }, outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } } },
  };
  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (output.errors || []).filter((entry) => entry.severity === 'error');
  if (errors.length) throw new Error(`source_compile_failed:${errors.map((entry) => entry.formattedMessage).join('\n')}`);
  return output.contracts;
}

function artifact(contracts, sourceName, name) {
  const result = contracts?.[sourceName]?.[name];
  if (!result?.abi || !result?.evm?.bytecode?.object) throw new Error(`artifact_missing:${sourceName}:${name}`);
  return result;
}

async function deploy(signer, item) {
  const contract = await new ContractFactory(item.abi, item.evm.bytecode.object, signer).deploy();
  const receipt = await contract.deploymentTransaction().wait();
  if (receipt.status !== 1) throw new Error('deployment_failed');
  await contract.waitForDeployment();
  return { contract, receipt };
}

(async () => {
  const sourcePath = path.resolve(process.argv[2] || '');
  const sourceBytes = fs.readFileSync(sourcePath);
  const source = sourceBytes.toString('utf8');
  const sourceSha256 = digest(sourceBytes);
  if (sourceSha256 !== EXPECTED_SOURCE_SHA256 || process.env.TRAINING_SOURCE_SHA256 !== EXPECTED_SOURCE_SHA256) {
    throw new Error('unchecked_transfer_source_hash_mismatch');
  }
  if (String(process.env.BENCHMARK_SOLC_VERSION || '').split('+', 1)[0] !== EXPECTED_COMPILER
      || !String(solc.version()).startsWith(`${EXPECTED_COMPILER}+`)) {
    throw new Error('unchecked_transfer_requires_exact_solc_0.4.26');
  }
  const compilerArtifactSha256 = String(process.env.BENCHMARK_SOLC_SHA256 || '').replace(/^0x/, '');
  if (!/^[a-f0-9]{64}$/i.test(compilerArtifactSha256)) throw new Error('unchecked_transfer_compiler_hash_missing');
  const fork = parseForkConfig(process.env);
  if (fork.requested || !fork.valid) throw new Error('unchecked_transfer_requires_isolated_local_evm');
  if (hre.network.name !== 'hardhat' || hre.network.config.url || hre.network.config.forking) {
    throw new Error('unchecked_transfer_evm_not_isolated');
  }

  const sourceName = path.basename(sourcePath);
  const contracts = compile(sourceName, source);
  const demoArtifact = artifact(contracts, sourceName, 'demo');
  const falseTokenArtifact = artifact(contracts, 'UncheckedTransferMocks.sol', 'FalseReturnToken');
  const trueTokenArtifact = artifact(contracts, 'UncheckedTransferMocks.sol', 'SuccessfulToken');
  const provider = new BrowserProvider(hre.network.provider);
  const chainId = Number((await provider.getNetwork()).chainId);
  if (chainId !== LOCAL_CHAIN_ID) throw new Error('unchecked_transfer_chain_id_mismatch');
  const signer = await provider.getSigner(0);
  const from = await (await provider.getSigner(1)).getAddress();
  const to = await (await provider.getSigner(2)).getAddress();
  const amount = 17n;

  const [{ contract: demo, receipt: demoDeployment }, { contract: falseToken, receipt: falseDeployment },
    { contract: trueToken, receipt: trueDeployment }] = await Promise.all([
    deploy(signer, demoArtifact), deploy(signer, falseTokenArtifact), deploy(signer, trueTokenArtifact),
  ]);
  const demoAddress = await demo.getAddress();
  const falseTokenAddress = await falseToken.getAddress();
  const trueTokenAddress = await trueToken.getAddress();
  const transactions = [demoDeployment, falseDeployment, trueDeployment].map((receipt) => ({
    name: 'deployment', status: receipt.status, hash: receipt.hash,
  }));

  const falseSeedReceipt = await (await falseToken.getFunction('seed')(from, amount)).wait();
  const trueSeedReceipt = await (await trueToken.getFunction('seed')(from, amount)).wait();
  transactions.push({ name: 'seed_false_return_token', status: falseSeedReceipt.status, hash: falseSeedReceipt.hash });
  transactions.push({ name: 'seed_successful_token', status: trueSeedReceipt.status, hash: trueSeedReceipt.hash });

  const recipients = [to];
  const values = [amount];
  const falseReturn = await demo.getFunction('transfer').staticCall(from, falseTokenAddress, recipients, values);
  const falseBefore = {
    from: await falseToken.getFunction('balanceOf')(from),
    to: await falseToken.getFunction('balanceOf')(to),
  };
  const falseReceipt = await (await demo.getFunction('transfer')(from, falseTokenAddress, recipients, values, {
    gasLimit: 500000,
  })).wait();
  const falseAfter = {
    from: await falseToken.getFunction('balanceOf')(from),
    to: await falseToken.getFunction('balanceOf')(to),
  };
  transactions.push({ name: 'demo_transfer_false_token_return', status: falseReceipt.status, hash: falseReceipt.hash });

  const trueBefore = {
    from: await trueToken.getFunction('balanceOf')(from),
    to: await trueToken.getFunction('balanceOf')(to),
  };
  const trueReturn = await demo.getFunction('transfer').staticCall(from, trueTokenAddress, recipients, values);
  const trueReceipt = await (await demo.getFunction('transfer')(from, trueTokenAddress, recipients, values, {
    gasLimit: 500000,
  })).wait();
  const trueAfter = {
    from: await trueToken.getFunction('balanceOf')(from),
    to: await trueToken.getFunction('balanceOf')(to),
  };
  transactions.push({ name: 'demo_transfer_successful_token_return', status: trueReceipt.status, hash: trueReceipt.hash });

  const falseReturnIgnored = falseReturn === true && falseReceipt.status === 1
    && falseBefore.from === amount && falseBefore.to === 0n
    && falseAfter.from === amount && falseAfter.to === 0n;
  const successfulControlWorks = trueReturn === true && trueReceipt.status === 1
    && trueBefore.from === amount && trueBefore.to === 0n
    && trueAfter.from === 0n && trueAfter.to === amount;
  const confirmed = falseReturnIgnored && successfulControlWorks
    && transactions.every((transaction) => transaction.status === 1);
  const serializeBalances = (balances) => ({ from: balances.from.toString(), to: balances.to.toString() });
  const assertions = [
    { name: 'false_return_is_ignored_and_demo_returns_true_without_token_transfer', passed: falseReturnIgnored },
    { name: 'true_return_control_moves_token_balances', passed: successfulControlWorks },
  ];
  process.stdout.write(`${JSON.stringify({
    schemaVersion: 1,
    sampleId: 'smartbugs-unchecked-transfer-demo',
    state: confirmed ? 'confirmed' : 'unconfirmed',
    confirmedVulnerability: confirmed,
    vulnerability: 'unchecked_transfer_from_boolean_result',
    proofScope: confirmed
      ? 'With a mock transferFrom that returns false and leaves balances unchanged, the original demo.transfer static call returns true and the transaction succeeds. A true-return control moves the same 17 token units. This confirms the wrapper reports success despite an explicit false token return in the local harness.'
      : 'The explicit false-return token path or its successful token control did not satisfy all return-value and balance assertions.',
    mode: 'isolated_in_process', compilerVersion: solc.version(), compilerKind: 'solc-js-original-source',
    compilerArtifactSha256, sourceSha256, demoAddress, falseTokenAddress, trueTokenAddress,
    from, to, amount: amount.toString(),
    falseReturn: { demoReturn: falseReturn, transactionStatus: falseReceipt.status,
      balancesBefore: serializeBalances(falseBefore), balancesAfter: serializeBalances(falseAfter) },
    successfulControl: { demoReturn: trueReturn, transactionStatus: trueReceipt.status,
      balancesBefore: serializeBalances(trueBefore), balancesAfter: serializeBalances(trueAfter) },
    assertions, transactions,
    executionBoundary: publicBoundary(fork, { chainId, forkState: 'not_performed' }),
    reason: confirmed ? null : 'unchecked_transfer_return_or_balance_assertion_failed',
  })}\n`);
  if (!confirmed) process.exitCode = 1;
})().catch((error) => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 2;
});
