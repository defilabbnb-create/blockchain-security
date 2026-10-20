'use strict';

const crypto = require('node:crypto');

const LOCAL_CHAIN_ID = 31337;

function hashRpcUrl(url) {
  return crypto.createHash('sha256').update(String(url), 'utf8').digest('hex');
}

function parseBlockNumber(value) {
  if (typeof value !== 'string' || !value.trim()) return null;
  const text = value.trim();
  if (!/^(?:0x[0-9a-f]+|[0-9]+)$/i.test(text)) return null;
  const number = Number(text);
  if (!Number.isSafeInteger(number) || number < 0) return null;
  return number;
}

function parseForkConfig(env = process.env) {
  const rawMode = String(env.DYNAMIC_EXECUTION_MODE || '').trim();
  const rpcUrl = String(env.DYNAMIC_FORK_RPC_URL || '').trim();
  const blockText = String(env.DYNAMIC_FORK_BLOCK_NUMBER || '').trim();
  const hasForkInput = Boolean(rpcUrl || blockText || rawMode === 'fixed_block_fork');
  const mode = hasForkInput ? (rawMode || 'fixed_block_fork') : 'isolated_in_process';
  const base = {
    mode,
    requested: hasForkInput,
    rpcUrlHash: rpcUrl ? hashRpcUrl(rpcUrl) : null,
    blockNumber: parseBlockNumber(blockText),
    configured: false,
    valid: true,
    reason: null,
  };
  if (mode !== 'isolated_in_process' && mode !== 'fixed_block_fork') {
    return { ...base, valid: false, reason: 'unsupported_execution_mode' };
  }
  if (!hasForkInput) return base;
  let parsedUrl;
  try { parsedUrl = new URL(rpcUrl); } catch { parsedUrl = null; }
  if (!parsedUrl || !['http:', 'https:'].includes(parsedUrl.protocol) || parsedUrl.username || parsedUrl.password) {
    return { ...base, valid: false, reason: 'fork_rpc_url_must_be_http_or_https' };
  }
  if (mode !== 'fixed_block_fork') {
    return { ...base, valid: false, reason: 'fork_requires_fixed_block_fork_mode' };
  }
  if (base.blockNumber === null) {
    return { ...base, valid: false, reason: 'fork_block_number_required_and_must_be_safe_integer' };
  }
  return { ...base, configured: true, rpcUrl };
}

function hardhatNetworkConfig(env = process.env) {
  const fork = parseForkConfig(env);
  const network = {
    chainId: LOCAL_CHAIN_ID,
    hardfork: 'cancun',
    throwOnTransactionFailures: false,
  };
  // Invalid input deliberately stays unforked; the harness fails closed after
  // loading the config and emits a structured boundary error. This avoids
  // passing malformed or partial options into Hardhat's network constructor.
  if (fork.valid && fork.configured) network.forking = {
    url: fork.rpcUrl,
    blockNumber: fork.blockNumber,
  };
  return network;
}

function publicBoundary(fork, { chainId = LOCAL_CHAIN_ID, forkState = null,
  forkProbe = null, blockHash = null } = {}) {
  const isFork = fork.mode === 'fixed_block_fork' && fork.configured;
  return {
    mode: isFork ? 'fixed_block_fork' : 'isolated_in_process',
    chainId: Number(chainId),
    forkState: forkState || (isFork ? 'configured' : 'not_performed'),
    forkProbe: forkProbe || (isFork ? { state: 'not_performed', reason: 'fork_probe_not_run' } : { state: 'not_performed', reason: 'fork_not_requested' }),
    requestedMode: fork.mode,
    requestedFork: fork.requested,
    fixedBlockNumber: isFork ? fork.blockNumber : null,
    fixedBlockHash: blockHash,
    rpcEndpoint: isFork ? { state: 'configured', sha256: fork.rpcUrlHash } : { state: 'not_configured' },
    externalTransactions: false,
    externalSigning: false,
    networkWrites: 'local_only',
  };
}

module.exports = { LOCAL_CHAIN_ID, hashRpcUrl, parseBlockNumber, parseForkConfig,
  hardhatNetworkConfig, publicBoundary };
