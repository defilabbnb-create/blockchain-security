#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { LOCAL_CHAIN_ID, parseForkConfig } = require('./dynamic-execution-boundary.cjs');

const MAX_MANIFEST_BYTES = 1024 * 1024;
const MAX_CALLDATA_BYTES = 16 * 1024;
const HASH_RE = /^0x[0-9a-f]{64}$/i;
const ADDRESS_RE = /^0x[0-9a-f]{40}$/i;
const HEX_RE = /^0x(?:[0-9a-f]{2})*$/i;

function fail(message, code = 'invalid_manifest') {
  const error = new Error(message);
  error.code = code;
  throw error;
}

function digest(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function validateManifest(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('manifest must be an object');
  if (value.schemaVersion !== 1) fail('manifest schemaVersion must be 1');
  if (typeof value.id !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,99}$/.test(value.id)) fail('manifest id is invalid');
  const deployment = value.deployment;
  if (!deployment || typeof deployment !== 'object' || Array.isArray(deployment)) fail('deployment is required');
  if (!Number.isSafeInteger(deployment.chainId) || deployment.chainId < 1) fail('deployment.chainId must be a positive safe integer');
  if (!Number.isSafeInteger(deployment.blockNumber) || deployment.blockNumber < 0) fail('deployment.blockNumber must be a non-negative safe integer');
  if (typeof deployment.blockHash !== 'string' || !HASH_RE.test(deployment.blockHash)) fail('deployment.blockHash must be a 32-byte hash');
  if (typeof deployment.address !== 'string' || !ADDRESS_RE.test(deployment.address)) fail('deployment.address must be a 20-byte address');
  if (typeof deployment.runtimeCodeHash !== 'string' || !HASH_RE.test(deployment.runtimeCodeHash)) fail('deployment.runtimeCodeHash must be a 32-byte hash');
  if (!Array.isArray(value.probes) || value.probes.length > 64) fail('probes must be an array with at most 64 entries');
  const names = new Set();
  for (const [index, probe] of value.probes.entries()) {
    if (!probe || typeof probe !== 'object' || Array.isArray(probe)) fail(`probes[${index}] must be an object`);
    if (typeof probe.name !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,99}$/.test(probe.name) || names.has(probe.name)) fail(`probes[${index}].name is invalid or duplicated`);
    names.add(probe.name);
    if (typeof probe.data !== 'string' || !HEX_RE.test(probe.data) || (probe.data.length - 2) / 2 > MAX_CALLDATA_BYTES) fail(`probes[${index}].data must be bounded hex calldata`);
    if (typeof probe.expectedReturnData !== 'string' || !HEX_RE.test(probe.expectedReturnData)) fail(`probes[${index}].expectedReturnData must be hex data`);
  }
  if (!value.probes.length) fail('at least one read-only call probe is required');
  return value;
}

async function readManifest(file) {
  const stat = await fs.promises.stat(file);
  if (!stat.isFile() || stat.size > MAX_MANIFEST_BYTES) fail('manifest must be a regular file no larger than 1 MiB');
  return validateManifest(JSON.parse(await fs.promises.readFile(file, 'utf8')));
}

function normalizeQuantity(value, label) {
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return value;
  if (typeof value === 'string' && /^(?:0x[0-9a-f]+|[0-9]+)$/i.test(value)) {
    const parsed = Number(value);
    if (Number.isSafeInteger(parsed) && parsed >= 0) return parsed;
  }
  fail(`${label} is not a safe non-negative quantity`, 'deployment_mismatch');
}

function normalizeHash(value, label) {
  if (typeof value !== 'string' || !HASH_RE.test(value)) fail(`${label} is not a 32-byte hash`, 'deployment_mismatch');
  return value.toLowerCase();
}

function normalizeCode(value, label) {
  if (typeof value !== 'string' || !HEX_RE.test(value)) fail(`${label} is not hex bytecode`, 'deployment_mismatch');
  return value.toLowerCase();
}

function normalizeRpcUrl(value) {
  let url;
  try { url = new URL(value); } catch { fail('fork RPC URL must be HTTP or HTTPS', 'fork_configuration_invalid'); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) fail('fork RPC URL must be HTTP or HTTPS without embedded credentials', 'fork_configuration_invalid');
  return url;
}

function createReadOnlyRpc(url, { timeoutMs = 10_000, fetchImpl = fetch } = {}) {
  const endpoint = normalizeRpcUrl(url).toString();
  let requestId = 0;
  return async (method, params) => {
    if (!['eth_chainId', 'eth_getBlockByNumber', 'eth_getCode', 'eth_call'].includes(method)) fail(`RPC method is not allowed: ${method}`, 'rpc_method_forbidden');
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const id = ++requestId;
      const response = await fetchImpl(endpoint, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
        signal: controller.signal,
      });
      if (!response.ok) fail(`RPC returned HTTP ${response.status}`, 'rpc_error');
      const body = await response.json();
      if (body.id !== id || body.error || !Object.hasOwn(body, 'result')) fail(`RPC ${method} failed`, 'rpc_error');
      return body.result;
    } finally { clearTimeout(timer); }
  };
}

async function verifyRemoteDeployment(rpc, manifest, { keccak256 } = {}) {
  const deployment = manifest.deployment;
  const chainId = normalizeQuantity(await rpc('eth_chainId', []), 'RPC chainId');
  if (chainId !== deployment.chainId) fail(`RPC chainId ${chainId} does not match manifest chainId ${deployment.chainId}`, 'chain_id_mismatch');
  const blockTag = `0x${deployment.blockNumber.toString(16)}`;
  const [block, repeatedBlock, code] = await Promise.all([
    rpc('eth_getBlockByNumber', [blockTag, false]),
    rpc('eth_getBlockByNumber', [blockTag, false]),
    rpc('eth_getCode', [deployment.address, blockTag]),
  ]);
  if (!block || !repeatedBlock) fail('fixed block is unavailable from RPC', 'fixed_block_unavailable');
  const blockHash = normalizeHash(block.hash, 'RPC block hash');
  if (normalizeQuantity(block.number, 'RPC block number') !== deployment.blockNumber) fail('RPC returned a different block number', 'block_number_mismatch');
  if (normalizeHash(repeatedBlock.hash, 'repeated RPC block hash') !== blockHash) fail('fixed block hash changed between reads', 'block_hash_unstable');
  if (blockHash !== deployment.blockHash.toLowerCase()) fail('fixed block hash does not match manifest', 'block_hash_mismatch');
  const runtimeCode = normalizeCode(code, 'deployed runtime code');
  if (runtimeCode === '0x') fail('deployment has no runtime code at the pinned block', 'deployment_code_missing');
  if (typeof keccak256 !== 'function') fail('canonical Keccak-256 function is required for runtime binding', 'keccak_unavailable');
  const codeHash = await keccak256(runtimeCode);
  if (codeHash.toLowerCase() !== deployment.runtimeCodeHash.toLowerCase()) fail('runtime code hash does not match deployment manifest', 'runtime_code_hash_mismatch');
  return { chainId, blockNumber: deployment.blockNumber, blockHash, address: deployment.address.toLowerCase(), runtimeCodeHash: codeHash.toLowerCase(), runtimeCodeBytes: (runtimeCode.length - 2) / 2 };
}

async function runForkAcceptance({ manifest, rpcUrl, provider, rpc, keccak256, localChainId = LOCAL_CHAIN_ID }) {
  validateManifest(manifest);
  const remote = rpc || createReadOnlyRpc(rpcUrl);
  const deployment = await verifyRemoteDeployment(remote, manifest, { keccak256 });
  const localNetwork = await provider.send('eth_chainId', []);
  if (normalizeQuantity(localNetwork, 'Hardhat local chainId') !== localChainId) fail('Hardhat provider is not the expected local chain', 'local_chain_id_mismatch');
  const blockTag = `0x${manifest.deployment.blockNumber.toString(16)}`;
  const localBlock = await provider.send('eth_getBlockByNumber', [blockTag, false]);
  if (!localBlock || normalizeHash(localBlock.hash, 'Hardhat fork block hash') !== deployment.blockHash || normalizeQuantity(localBlock.number, 'Hardhat fork block number') !== deployment.blockNumber) fail('Hardhat fork block does not match verified upstream block', 'fork_block_mismatch');
  const localCode = normalizeCode(await provider.send('eth_getCode', [deployment.address, blockTag]), 'Hardhat fork runtime code');
  const localCodeHash = (await keccak256(localCode)).toLowerCase();
  if (localCodeHash !== deployment.runtimeCodeHash) fail('Hardhat fork code does not match verified deployment code', 'fork_code_mismatch');
  const probes = [];
  for (const probe of manifest.probes) {
    const [upstreamResult, forkResult] = await Promise.all([
      remote('eth_call', [{ to: deployment.address, data: probe.data }, blockTag]),
      provider.send('eth_call', [{ to: deployment.address, data: probe.data }, blockTag]),
    ]);
    const expected = probe.expectedReturnData.toLowerCase();
    const upstream = normalizeCode(upstreamResult, `probe ${probe.name} upstream result`);
    const fork = normalizeCode(forkResult, `probe ${probe.name} fork result`);
    if (upstream !== expected || fork !== expected || upstream !== fork) fail(`read-only probe ${probe.name} did not match expected output on both endpoints`, 'read_only_probe_mismatch');
    probes.push({ name: probe.name, state: 'passed', dataBytes: (probe.data.length - 2) / 2, returnData: fork });
  }
  return {
    schemaVersion: 1,
    id: manifest.id,
    state: 'passed',
    mode: 'fixed_block_fork',
    executionBoundary: {
      chainId: localChainId, upstreamChainId: deployment.chainId,
      blockNumber: deployment.blockNumber, blockHash: deployment.blockHash.toLowerCase(),
      address: deployment.address, runtimeCodeHash: deployment.runtimeCodeHash,
      rpcEndpointHash: digest(String(rpcUrl)),
      remoteMethods: ['eth_chainId', 'eth_getBlockByNumber', 'eth_getCode', 'eth_call'],
      externalTransactions: false, externalSigning: false, networkWrites: 'local_only',
      readOnly: true,
    },
    probes,
    manifestSha256: digest(Buffer.from(JSON.stringify(manifest))),
    interpretation: '只读 fork 基线验证了链、区块、运行时代码和声明的 eth_call；没有发送交易，也不构成漏洞结论。',
  };
}

async function runFromEnvironment({ env = process.env, manifestPath } = {}) {
  const config = parseForkConfig(env);
  if (!config.requested && !config.configured) return { schemaVersion: 1, state: 'not_performed', reason: 'fixed_block_fork_not_configured', externalTransactions: false, externalSigning: false };
  if (!config.valid || !config.configured) return { schemaVersion: 1, state: 'unavailable', reason: config.reason || 'fixed_block_fork_configuration_invalid', externalTransactions: false, externalSigning: false };
  if (!manifestPath) fail('manifest path is required when a fixed-block fork is configured');
  normalizeRpcUrl(config.rpcUrl);
  const root = env.CAMPAIGN_PROJECT_ROOT || path.resolve(__dirname, '..');
  process.env.HARDHAT_CONFIG = path.join(root, 'scripts/local-test-hardhat.cjs');
  const deps = path.join(root, 'flare-scan/contracts/firelight-core/node_modules');
  const hre = require(path.join(deps, 'hardhat'));
  const { keccak256 } = require(path.join(deps, 'ethers'));
  const manifest = await readManifest(manifestPath);
  const providerConfig = hre.network.config;
  if (hre.network.name !== 'hardhat' || providerConfig.url || !providerConfig.forking || providerConfig.forking.blockNumber !== manifest.deployment.blockNumber) fail('Hardhat did not apply the declared fixed-block fork', 'fork_configuration_mismatch');
  return runForkAcceptance({ manifest, rpcUrl: config.rpcUrl, provider: hre.network.provider, keccak256, rpc: createReadOnlyRpc(config.rpcUrl) });
}

module.exports = { MAX_MANIFEST_BYTES, validateManifest, readManifest, createReadOnlyRpc, verifyRemoteDeployment, runForkAcceptance, runFromEnvironment };

if (require.main === module) {
  runFromEnvironment({ manifestPath: process.argv[2] }).then((result) => {
    process.stdout.write(`${JSON.stringify(result)}\n`);
    if (result.state === 'unavailable') process.exitCode = 2;
  }).catch((error) => {
    process.stdout.write(`${JSON.stringify({ schemaVersion: 1, state: 'failed', code: error.code || 'fork_acceptance_failed', error: error.message, externalTransactions: false, externalSigning: false })}\n`);
    process.exitCode = 1;
  });
}
