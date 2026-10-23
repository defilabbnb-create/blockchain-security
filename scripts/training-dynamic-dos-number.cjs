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

function digest(value) { return crypto.createHash('sha256').update(value).digest('hex'); }

function compile(sourceName, source) {
  const input = { language: 'Solidity', sources: { [sourceName]: { content: source } },
    settings: { optimizer: { enabled: false }, outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } } } };
  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (output.errors || []).filter((item) => item.severity === 'error');
  if (errors.length) throw new Error(`source_compile_failed:${errors.map((item) => item.formattedMessage).join('\n')}`);
  const item = output.contracts?.[sourceName]?.DosNumber;
  if (!item?.abi || !item?.evm?.bytecode?.object) throw new Error('dos_number_artifact_missing');
  return item;
}

async function waitFor(contract, call, args, overrides) {
  try {
    const tx = await contract.getFunction(call)(...args, overrides);
    const receipt = await tx.wait();
    return { status: Number(receipt.status), hash: receipt.hash, gasUsed: receipt.gasUsed.toString() };
  } catch (error) {
    const receipt = error.receipt || error.info?.receipt || null;
    return { status: Number(receipt?.status ?? 0), hash: receipt?.hash || error.transactionHash || null,
      gasUsed: receipt?.gasUsed?.toString?.() || null, error: String(error.shortMessage || error.message || error).slice(0, 300) };
  }
}

(async () => {
  const sourcePath = path.resolve(process.argv[2] || '');
  const sourceBytes = fs.readFileSync(sourcePath);
  const source = sourceBytes.toString('utf8');
  const sourceSha256 = digest(sourceBytes);
  const expectedSha256 = process.env.TRAINING_SOURCE_SHA256 || '';
  if (!/^[a-f0-9]{64}$/.test(expectedSha256) || sourceSha256 !== expectedSha256) {
    throw new Error('training_dos_number_source_hash_mismatch');
  }
  if (String(process.env.BENCHMARK_SOLC_VERSION || '').split('+', 1)[0] !== '0.4.25'
      || !String(solc.version()).startsWith('0.4.25+')) {
    throw new Error('training_dos_number_requires_exact_solc_0.4.25');
  }
  const compilerArtifactSha256 = String(process.env.BENCHMARK_SOLC_SHA256 || '').replace(/^0x/, '');
  if (!/^[a-f0-9]{64}$/i.test(compilerArtifactSha256)) throw new Error('training_dos_number_compiler_hash_missing');
  const fork = parseForkConfig(process.env);
  if (fork.requested || !fork.valid || hre.network.name !== 'hardhat' || hre.network.config.url || hre.network.config.forking) {
    throw new Error('training_dos_number_requires_isolated_local_evm');
  }

  const contractArtifact = compile(path.basename(sourcePath), source);
  const provider = new BrowserProvider(hre.network.provider);
  const chainId = Number((await provider.getNetwork()).chainId);
  if (chainId !== LOCAL_CHAIN_ID) throw new Error('training_dos_number_chain_id_mismatch');
  const signer = await provider.getSigner(0);
  const deployed = await new ContractFactory(contractArtifact.abi, contractArtifact.evm.bytecode.object, signer).deploy();
  const deployReceipt = await deployed.deploymentTransaction().wait();
  if (deployReceipt.status !== 1) throw new Error('dos_number_deployment_failed');
  await deployed.waitForDeployment();

  const count = 7000;
  const batchSize = 100;
  const batches = [];
  for (let inserted = 0; inserted < count; inserted += batchSize) {
    const size = Math.min(batchSize, count - inserted);
    const receipt = await waitFor(deployed, 'insertNnumbers', [77, size], { gasLimit: 4_000_000 });
    batches.push(receipt);
    if (receipt.status !== 1) throw new Error(`dos_number_population_failed_at_${inserted}:${JSON.stringify(receipt)}`);
  }

  const block = await provider.getBlock('latest');
  const blockGasLimit = BigInt(block.gasLimit);
  const lengthBefore = await deployed.getFunction('getLengthArray')();
  const realLengthBefore = await deployed.getFunction('getRealLengthArray')();
  const clearDos = await waitFor(deployed, 'clearDOS', [], { gasLimit: blockGasLimit });
  const lengthAfterClearDos = await deployed.getFunction('getLengthArray')();
  const realLengthAfterClearDos = await deployed.getFunction('getRealLengthArray')();

  const clear = await waitFor(deployed, 'clear', [], { gasLimit: 500_000 });
  const lengthAfterClear = await deployed.getFunction('getLengthArray')();
  const realLengthAfterClear = await deployed.getFunction('getRealLengthArray')();
  const insertAfterClear = await waitFor(deployed, 'insertNnumbers', [99, 1], { gasLimit: 500_000 });
  const lengthAfterFollowup = await deployed.getFunction('getLengthArray')();
  const signerAddress = (await signer.getAddress()).toLowerCase();
  const contractAddress = (await deployed.getAddress()).toLowerCase();

  const clearDosFailedAtBlockLimit = clearDos.status === 0 && lengthAfterClearDos === BigInt(count)
    && realLengthAfterClearDos === BigInt(count);
  const alternativePathAvailable = clear.status === 1 && lengthAfterClear === 0n
    && realLengthAfterClear === BigInt(count) && insertAfterClear.status === 1 && lengthAfterFollowup === 1n;
  const impactDemonstrated = clearDosFailedAtBlockLimit && !alternativePathAvailable;
  const confirmed = impactDemonstrated;
  const assertions = [
    { name: 'large_array_population_completed', passed: lengthBefore === BigInt(count) && realLengthBefore === BigInt(count) },
    { name: 'clear_dos_exceeds_local_block_gas_and_reverts_atomically', passed: clearDosFailedAtBlockLimit },
    { name: 'logical_clear_and_followup_insert_remain_available', passed: alternativePathAvailable },
  ];
  const result = {
    schemaVersion: 1, sampleId: 'smartbugs-dos-number',
    state: confirmed ? 'confirmed' : 'unconfirmed', confirmedVulnerability: confirmed,
    vulnerability: 'denial_of_service_array_cleanup_gas',
    impactDemonstrated,
    proofScope: 'Local isolation checks whether clearDOS exceeds the local block gas limit after public array growth, and whether clear plus a subsequent insert still work. This does not represent a deployed contract or chain-wide outage.',
    mode: 'isolated_in_process', compilerVersion: solc.version(), compilerArtifactSha256, sourceSha256,
    target: { contract: contractAddress, actor: signerAddress },
    population: { count, batchSize, successfulBatches: batches.length, failedBatches: batches.filter((row) => row.status !== 1).length },
    blockGasLimit: blockGasLimit.toString(),
    observations: {
      logicalLengthBefore: lengthBefore.toString(), realLengthBefore: realLengthBefore.toString(),
      clearDOS: clearDos, logicalLengthAfterClearDOS: lengthAfterClearDos.toString(),
      realLengthAfterClearDOS: realLengthAfterClearDos.toString(), clear,
      logicalLengthAfterClear: lengthAfterClear.toString(), realLengthAfterClear: realLengthAfterClear.toString(),
      insertAfterClear, logicalLengthAfterFollowupInsert: lengthAfterFollowup.toString(),
    },
    assertions, executionBoundary: publicBoundary(fork, { chainId, forkState: 'not_performed' }),
    reason: confirmed ? null : (clearDosFailedAtBlockLimit && alternativePathAvailable
      ? 'clearDOS_reverts_at_block_limit_but_public_constant_cost_clear_and_followup_insert_succeed'
      : 'dos_number_impact_assertions_not_fully_reproduced'),
  };
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (!assertions.every((assertion) => assertion.passed)) process.exitCode = 1;
})().catch((error) => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 2;
});
