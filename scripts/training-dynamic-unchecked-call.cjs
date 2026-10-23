'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const root = process.env.CAMPAIGN_PROJECT_ROOT || path.resolve(__dirname, '..');
const deps = path.join(root, 'flare-scan/contracts/firelight-core/node_modules');
process.env.HARDHAT_CONFIG = path.join(root, 'scripts/local-test-hardhat.cjs');
const hre = require(path.join(deps, 'hardhat'));
const { BrowserProvider, ContractFactory, concat, keccak256, zeroPadValue } = require(path.join(deps, 'ethers'));
const solcLoader = require(path.join(root, 'flare-scan/tools/solc-0819/node_modules/solc'));
const solc = solcLoader.setupMethods(require(process.env.CAMPAIGN_SOLJSON));
const { LOCAL_CHAIN_ID, parseForkConfig, publicBoundary } = require('./dynamic-execution-boundary.cjs');

const SAMPLE_ID = 'smartbugs-keepmyether-unchecked-call';
const COMPILER_RELEASE = '0.4.26';

function digest(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function compile(sourceName, source) {
  const helperName = 'D3RejectingWallet.sol';
  const helper = `pragma solidity ^0.4.23;
contract D3RejectingWallet {
    function() public payable { revert(); }
    function deposit(address target) public payable returns (bool) {
        return target.call.value(msg.value)();
    }
    function withdrawFrom(address target) public returns (bool) {
        return target.call(bytes4(keccak256("withdraw()")));
    }
}`;
  const input = {
    language: 'Solidity',
    sources: { [sourceName]: { content: source }, [helperName]: { content: helper } },
    settings: {
      optimizer: { enabled: false },
      outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } },
    },
  };
  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (output.errors || []).filter((item) => item.severity === 'error');
  if (errors.length) throw new Error(`source_compile_failed:${errors.map((item) => item.formattedMessage).join('\n')}`);
  const target = output.contracts?.[sourceName]?.keepMyEther;
  const rejectingWallet = output.contracts?.[helperName]?.D3RejectingWallet;
  if (!target?.abi || !target?.evm?.bytecode?.object || !rejectingWallet?.abi || !rejectingWallet?.evm?.bytecode?.object) {
    throw new Error('training_unchecked_call_artifact_missing');
  }
  return { target, rejectingWallet, helperSource: helper };
}

async function deploy(artifact, signer) {
  const contract = await new ContractFactory(artifact.abi, artifact.evm.bytecode.object, signer).deploy();
  const receipt = await contract.deploymentTransaction().wait();
  await contract.waitForDeployment();
  return { contract, transactionHash: receipt.hash };
}

(async () => {
  const sourcePath = path.resolve(process.argv[2] || '');
  const sourceBytes = fs.readFileSync(sourcePath);
  const sourceSha256 = digest(sourceBytes);
  const compilerRelease = String(process.env.BENCHMARK_SOLC_VERSION || '').split('+', 1)[0];
  if (compilerRelease !== COMPILER_RELEASE || !String(solc.version()).startsWith(`${COMPILER_RELEASE}+`)) {
    throw new Error('training_unchecked_call_compiler_version_mismatch');
  }
  const compilerArtifactSha256 = digest(fs.readFileSync(process.env.CAMPAIGN_SOLJSON));
  if (compilerArtifactSha256 !== String(process.env.BENCHMARK_SOLC_SHA256 || '').replace(/^0x/, '').toLowerCase()) {
    throw new Error('training_unchecked_call_compiler_hash_mismatch');
  }
  const fork = parseForkConfig(process.env);
  if (fork.requested || !fork.valid) throw new Error('training_unchecked_call_requires_isolated_local_evm');
  if (hre.network.name !== 'hardhat' || hre.network.config.url || hre.network.config.forking) {
    throw new Error('training_unchecked_call_evm_not_isolated');
  }
  const provider = new BrowserProvider(hre.network.provider);
  const chainId = Number((await provider.getNetwork()).chainId);
  if (chainId !== LOCAL_CHAIN_ID) throw new Error('training_unchecked_call_chain_id_mismatch');
  const signer = await provider.getSigner(0);
  const { target: targetArtifact, rejectingWallet: walletArtifact, helperSource } = compile(path.basename(sourcePath), sourceBytes.toString('utf8'));
  const targetDeployment = await deploy(targetArtifact, signer);
  const walletDeployment = await deploy(walletArtifact, signer);
  const target = targetDeployment.contract;
  const wallet = walletDeployment.contract;
  const targetAddress = await target.getAddress();
  const walletAddress = await wallet.getAddress();
  const amount = 10n ** 18n;
  const mappingSlot = keccak256(concat([zeroPadValue(walletAddress, 32), zeroPadValue('0x00', 32)]));

  const depositForwarded = await wallet.deposit.staticCall(targetAddress, { value: amount });
  const deposit = await (await wallet.deposit(targetAddress, { value: amount })).wait();
  const depositTrace = await provider.send('debug_traceTransaction', [deposit.hash, {}]).catch((error) => ({ error: String(error.message || error) }));
  const userCreditBefore = await target.balances(walletAddress, { blockTag: deposit.blockNumber });
  const targetBalanceBefore = await provider.getBalance(targetAddress, deposit.blockNumber);
  const walletBalanceBefore = await provider.getBalance(walletAddress, deposit.blockNumber);
  const withdrawal = await (await wallet.withdrawFrom(targetAddress)).wait();
  const userCreditAfter = await target.balances(walletAddress);
  const targetBalanceAfter = await provider.getBalance(targetAddress);
  const walletBalanceAfter = await provider.getBalance(walletAddress);

  const confirmed = depositForwarded === true && deposit.status === 1 && withdrawal.status === 1
    && userCreditBefore === amount && targetBalanceBefore === amount
    && walletBalanceBefore === 0n && userCreditAfter === 0n
    && targetBalanceAfter === amount && walletBalanceAfter === 0n;
  const result = {
    schemaVersion: 1,
    sampleId: SAMPLE_ID,
    state: confirmed ? 'confirmed' : 'unconfirmed',
    confirmedVulnerability: confirmed,
    vulnerability: 'unchecked_call_failed_withdrawal_credit_cleared',
    mode: 'isolated_in_process',
    compilerVersion: solc.version(),
    compilerKind: 'solc-js-original-source',
    compilerArtifactSha256,
    sourceSha256,
    harnessSourceSha256: digest(Buffer.from(helperSource)),
    targetAddress,
    rejectingWalletAddress: walletAddress,
    depositAmountWei: amount.toString(),
    depositForwarded,
    depositGasUsed: deposit.gasUsed.toString(),
    depositBlockNumber: deposit.blockNumber,
    targetRawBalanceAtDepositBlock: await provider.send('eth_getBalance', [targetAddress, `0x${deposit.blockNumber.toString(16)}`]),
    mappingSlot,
    mappingStorageAtDepositBlock: await provider.send('eth_getStorageAt', [targetAddress, mappingSlot, `0x${deposit.blockNumber.toString(16)}`]),
    targetCodeLength: (await provider.getCode(targetAddress)).length,
    walletCodeLength: (await provider.getCode(walletAddress)).length,
    depositTraceCalls: (depositTrace.structLogs || []).filter((step) => step.op === 'CALL').map((step) => ({ depth: step.depth, stackTail: step.stack.slice(-7) })),
    depositTraceDepths: [...new Set((depositTrace.structLogs || []).map((step) => step.depth))],
    depositTraceFailureOps: (depositTrace.structLogs || []).filter((step) => ['REVERT', 'INVALID', 'SELFDESTRUCT'].includes(step.op)).map((step) => ({ depth: step.depth, op: step.op })),
    depositTraceFailed: depositTrace.failed ?? null,
    depositTraceReturnValue: depositTrace.returnValue ?? null,
    depositTraceError: depositTrace.error ?? null,
    depositTraceDepth2: (depositTrace.structLogs || []).filter((step) => step.depth === 2).map((step) => ({ op: step.op, stackTail: step.stack.slice(-5) })).slice(0, 60),
    userCreditBeforeWei: userCreditBefore.toString(),
    userCreditAfterWei: userCreditAfter.toString(),
    targetBalanceBeforeWei: targetBalanceBefore.toString(),
    targetBalanceAfterWei: targetBalanceAfter.toString(),
    rejectingWalletBalanceBeforeWei: walletBalanceBefore.toString(),
    rejectingWalletBalanceAfterWei: walletBalanceAfter.toString(),
    transactionHashes: [deposit.hash, withdrawal.hash],
    executionBoundary: publicBoundary(fork, { chainId, forkState: 'not_performed' }),
    proofScope: confirmed
      ? 'The source fallback credits the rejecting wallet. Its withdraw call succeeds, the source low-level payout fails because the wallet reverts, and the source then clears the wallet credit while retaining the ETH. This proves loss of the reachable withdrawal entitlement and funds remaining in the source contract in this local scenario.'
      : 'The expected rejected payout, cleared user credit, and retained source balance were not all observed.',
  };
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (!confirmed) process.exitCode = 1;
})().catch((error) => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 1;
});
