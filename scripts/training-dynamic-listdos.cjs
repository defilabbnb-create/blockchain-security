'use strict';

// Feasibility check for the pinned upstream sample. The sample is compiled as
// collected; it is never rewritten to make a PoC appear executable.
const fs = require('node:fs');
const crypto = require('node:crypto');

function digest(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }

try {
  const sourcePath = process.argv[2];
  if (!sourcePath) throw new Error('training_listdos_source_path_missing');
  const bytes = fs.readFileSync(sourcePath);
  const sourceSha256 = digest(bytes);
  const expected = process.env.TRAINING_SOURCE_SHA256 || '';
  if (!/^[a-f0-9]{64}$/.test(expected) || sourceSha256 !== expected) {
    throw new Error('training_listdos_source_hash_mismatch');
  }
  const solcLoader = require(process.env.TRAINING_SOLC_LOADER);
  const solc = solcLoader.setupMethods(require(process.env.CAMPAIGN_SOLJSON));
  const release = String(process.env.BENCHMARK_SOLC_VERSION || '').split('+', 1)[0];
  if (release !== '0.4.15' || !String(solc.version()).startsWith('0.4.15+')) {
    throw new Error('training_listdos_requires_exact_solc_0.4.15');
  }
  const compilerArtifactSha256 = String(process.env.BENCHMARK_SOLC_SHA256 || '').replace(/^0x/, '');
  if (!/^[a-f0-9]{64}$/i.test(compilerArtifactSha256)) {
    throw new Error('training_listdos_compiler_hash_missing');
  }
  const sourceName = 'list_dos.sol';
  const input = { language: 'Solidity', sources: { [sourceName]: { content: bytes.toString('utf8') } },
    settings: { optimizer: { enabled: false }, outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } } } };
  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (output.errors || []).filter((item) => item.severity === 'error');
  const diagnostics = errors.map((item) => item.formattedMessage || item.message);
  const feasible = errors.length === 0;
  const result = {
    schemaVersion: 1,
    sampleId: 'crytic-dos-list',
    state: feasible ? 'unconfirmed' : 'harness_not_feasible',
    confirmedVulnerability: false,
    vulnerability: 'denial_of_service_batch_refund',
    reason: feasible ? 'original_source_compiles_but_no_evm_poc_was_run' : 'original_source_does_not_compile_as_collected',
    proofScope: 'Compile feasibility check of the exact hash-pinned upstream source only; no source transformation and no EVM state or asset claim.',
    sourceSha256,
    compilerVersion: solc.version(),
    compilerArtifactSha256,
    diagnostics,
    compileErrorCount: errors.length,
    sourceLines: {
      pushTransferRequire: 'refundAddresses[i].transfer(refundAmount[refundAddresses[i]]) is used as a require(bool) argument although address.transfer returns no value.',
      safeRefundMappingIndex: 'refundAmount[i] indexes mapping(address => uint) with uint i instead of an address key.',
    },
  };
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (feasible) process.exitCode = 1;
} catch (error) {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 2;
}
