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
  const sources = { [sourceName]: { content: source } };
  const input = { language: 'Solidity', sources,
    settings: { optimizer: { enabled: false }, outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } } } };
  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (output.errors || []).filter((item) => item.severity === 'error');
  if (errors.length) throw new Error(`source_compile_failed:${errors.map((item) => item.formattedMessage).join('\n')}`);
  return {
    target: output.contracts?.[sourceName]?.KingOfTheEtherThrone,
  };
}

async function deploy(artifact, signer, overrides = {}) {
  const contract = await new ContractFactory(artifact.abi, artifact.evm.bytecode.object, signer).deploy(overrides);
  await contract.deploymentTransaction().wait();
  await contract.waitForDeployment();
  return contract;
}

(async () => {
  const sourcePath = path.resolve(process.argv[2] || '');
  const source = fs.readFileSync(sourcePath);
  const sourceSha256 = digest(source);
  const compilerRelease = String(process.env.BENCHMARK_SOLC_VERSION || '').split('+', 1)[0];
  if (compilerRelease !== '0.4.26' || !String(solc.version()).startsWith('0.4.26+')) {
    throw new Error('training_harness_requires_exact_solc_0.4.26');
  }
  const fork = parseForkConfig(process.env);
  if (fork.requested || !fork.valid) throw new Error('training_harness_requires_isolated_local_evm');
  if (hre.network.name !== 'hardhat' || hre.network.config.url || hre.network.config.forking) {
    throw new Error('training_harness_evm_not_isolated');
  }
  const provider = new BrowserProvider(hre.network.provider);
  const chainId = Number((await provider.getNetwork()).chainId);
  if (chainId !== LOCAL_CHAIN_ID) throw new Error('training_harness_chain_id_mismatch');
  const wizard = await provider.getSigner(0);
  const nextMonarch = await provider.getSigner(1);
  const { target: targetArtifact } = compile(path.basename(sourcePath), source.toString('utf8'));
  if (!targetArtifact) throw new Error('training_harness_artifact_missing');
  const target = await deploy(targetArtifact, wizard);
  const targetAddress = await target.getAddress();
  const rejectingAddress = await wizard.getAddress();
  const initialPrice = await target.currentClaimPrice();
  const firstClaimPrice = initialPrice * 3n / 2n;
  const secondClaimPrice = firstClaimPrice * 3n / 2n;
  await provider.send('hardhat_setCode', [rejectingAddress, '0x60006000fd']);
  const rejectingBalanceBefore = await provider.getBalance(rejectingAddress);
  const targetBalanceBefore = await provider.getBalance(targetAddress);
  const secondClaimData = target.interface.encodeFunctionData('claimThrone(string)', ['next monarch']);
  const secondClaim = await (await nextMonarch.sendTransaction({
    to: targetAddress, data: secondClaimData, value: secondClaimPrice,
  })).wait();
  const rejectingBalanceAfter = await provider.getBalance(rejectingAddress);
  const targetBalanceAfter = await provider.getBalance(targetAddress);
  const state = await target.currentMonarch();
  const monarchCount = await target.numberOfMonarchs();
  const expectedCompensation = firstClaimPrice - firstClaimPrice / 100n;
  const confirmed = rejectingBalanceBefore === 0n && rejectingBalanceAfter === 0n
    && targetBalanceAfter === targetBalanceBefore + secondClaimPrice
    && state.etherAddress.toLowerCase() === (await nextMonarch.getAddress()).toLowerCase()
    && monarchCount === 1n;
  process.stdout.write(`${JSON.stringify({
    schemaVersion: 1, sampleId: 'smartbugs-king-of-the-ether-throne', state: confirmed ? 'confirmed' : 'unconfirmed',
    confirmedVulnerability: confirmed, vulnerability: 'unchecked_external_call_state_advance',
    mode: 'isolated_in_process', compilerVersion: solc.version(), compilerKind: 'solc-js-original-source',
    sourceSha256, rejectingCodeSha256: digest(Buffer.from('0x60006000fd')),
    targetAddress, rejectingMonarchAddress: rejectingAddress,
    deploymentValueWei: '0', initialClaimPriceWei: initialPrice.toString(),
    failedCompensationWei: expectedCompensation.toString(), rejectingMonarchBalanceBeforeWei: rejectingBalanceBefore.toString(),
    rejectingMonarchBalanceAfterWei: rejectingBalanceAfter.toString(), targetBalanceBeforeWei: targetBalanceBefore.toString(),
    targetBalanceAfterWei: targetBalanceAfter.toString(), currentMonarchAfter: state.etherAddress,
    pastMonarchCountAfter: monarchCount.toString(), transactionHashes: [secondClaim.hash],
    executionBoundary: publicBoundary(fork, { chainId, forkState: 'not_performed' }),
    proofScope: confirmed
      ? 'A rejecting prior monarch receives no compensation, but the next public claim advances the monarch state and increases the contract balance by the full new claim price. This demonstrates an unpaid reachable compensation and state progression, not a general insolvency claim.'
      : 'The expected rejected compensation and continued monarch state progression were not both observed.',
  })}\n`);
  if (!confirmed) process.exitCode = 1;
})().catch((error) => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 1;
});
