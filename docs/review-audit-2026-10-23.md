# 外部评审意见核对结果

对象:一份基于 README 的架构评审(2026-10-23)
核对方式:逐条比对仓库实际代码

## 结论摘要

评审的技术判断**方向大体正确**,但有 **3 条"完全空白/没看到"的结论与代码不符**。
评审明确承认"代码本身还没细看",这 3 条是纯文档推断失误,不应据此派活。

---

## 逐条核对

### ① 工厂 CREATE2 + 代理实现覆盖 —— 部分成立

评审称"仅顶层部署,不覆盖工厂内部 CREATE/CREATE2 或代理实现漏洞"。

**代码事实**:EIP-1967 代理解析已实现。

- `scripts/proxy_history.py` —— 只读代理解析
  - 三个 storage slot:`IMPL_SLOT`(0x360894…)、`BEACON_SLOT`(0xa3f0ad…)、`ADMIN_SLOT`(0xb53127…)
  - 三种升级事件 topic:`UPGRADED_TOPIC`、`BEACON_UPGRADED_TOPIC`、`ADMIN_CHANGED_TOPIC`
  - 支持 beacon 模式(`BEACON_IMPLEMENTATION_SELECTOR = 0x5c60da1b`)
  - 明确不做推断:历史缺失/畸形时返回 `partial`/`unsupported`,**从不推断 implementation**
  - 声明只读,不发交易
- `scripts/recon.py` 第 19 行 `from proxy_history import proxy_history`

**判定**:README 的免责声明滞后于代码。**ERC-1967 代理已覆盖,评审说的"代理实现漏洞看不到"不准确。**
CREATE2 工厂内部发现是否已实现需进一步确认(未在本轮核实)。

### ② 工程成熟度超前于检测能力 —— 成立,认同

评审认为可靠性工程(状态机/fencing/lease/soak)投入过多,而"准不准"未验证。

**判定**:这是价值判断,不是事实错误。是否调整投入顺序属项目决策。认同其"现阶段基础设施够用"的分寸建议。

### ③ 无自研 detector,LLM 仅在问答层 —— 需修正

评审称"没有针对未保护初始化/可控 target delegatecall/签名重放的专门判定逻辑,只有记录 delegatecall 位置"。

**代码事实**:存在大量针对具体漏洞类的动态夹具与判定脚本,远超"仅记录位置":

- `scripts/invariant_templates_vuln.py`、`scripts/invariant_assertions/`(含 `vuln.py`/`cross.py`/`erc4626.py`/`lending.py`/`amm.py`)
- 专项 runner:`reentrancy`、`unchecked-call`、`unchecked-transfer`、`unchecked-token-false`、`erc20-race`、`listdos`、`dos-number`、`predictable-randomness`、`old-blockhash`、`storage-write`、`access-control`、`delegatecall`、`cross-call`、`bec-token-overflow`
- `scripts/unified_ir.py`、`scripts/decompiler_adapter.py`、`scripts/harness_gen.py`
- 新增未跟踪:`scripts/source_vuln_evidence.py`、`scripts/severity-model.json`、`src/severity-resolver.js`

**判定**:评审"仅记录位置"的描述**不准确**。但评审的**核心担忧仍成立**:LLM 确实未接入 true/false positive 分类环节
(文档已自述 LLM 仅用于问答解释),从线索到判断的人工距离尚未自动化。**担忧有效,举证失实。**

### ④ 反编译前缺 bytecode hash 交叉引用 —— 成立(需确认细节)

评审称未先用 bytecode hash 查 Sourcify。

**代码事实**:`scripts/decompiler_crosscheck.py` 存在,`defi-campaign.py` 第 33 行
`from decompiler_crosscheck import attach_opcode_cross_validation`。
该模块名为 **crosscheck**(交叉校验),与评审描述的"交叉引用"方向一致,但是否即 Sourcify 源码查找需读码确认。

**判定**:评审可能与 `decompiler_crosscheck.py` 混淆。若该模块只做 opcode 交叉验证而不查已验证源码,则 ④ 成立。

### ⑤ 动态验证未泛化 —— 成立,认同

手写夹具(VaultV2/Firelight/EngineChip/AMT*)无法自动套用到新协议。

**判定**:与代码现状一致。`invariant_gen.py` + `harness_gen.py` 是泛化尝试但尚未覆盖任意新目标。认同。

### ⑥ 代理升级监控 / fork-diff —— **评审错误**

评审称"目前文档里完全没提到,升级事件监听和 AST diff 都是空白"。

**代码事实**:`scripts/proxy_history.py` 已实现 `Upgraded`/`BeaconUpgraded`/`AdminChanged`
三事件监控 + EIP-1967 slot 解析 + beacon 模式。`scripts/recon.py` 已集成。

**判定**:**"升级事件监听空白"是错的,已实现。**fork-diff(AST 模板对比)未发现,这一半可能成立。

### ⑦ 干净代码误报率测试 —— **评审错误**

评审称"没看到对干净代码的误报测试"。

**代码事实**:
- `scripts/benchmark-dynamic-clean-controls.cjs`(9770 字节)
- `tests/test_benchmark_clean_controls.py`(4594 字节)
- `benchmark/contracts/21-erc4626-donation` 等 ground-truth.json 已修改

**判定**:**"没有干净代码误报测试"是错的,该测试已存在。**

### ⑧ RPC 不统一 —— **评审错误**

评审称核心扫描用单节点 `publicnode.com` 无故障转移。

**代码事实**:
- `scripts/rpc_pool.py` —— `RpcPool` 类,含 `failovers`、`host_cooldown`、`host_next`、`stats`,只读策略
- `scripts/defi-campaign.py` 第 30 行 `from rpc_pool import RpcPool`,第 645-648 行加载
  `work/rpc-pool.json` 并**强制 30 分钟新鲜度校验**(超期抛错)
- 第 316 行策略:`publicHttpsOnly`、`maxPerChain`、`probeConcurrency`、`maxHeightDeviation`、`readOnly`
- `scripts/recon.py` 第 20 行同样接入

**判定**:**"核心扫描路径未接 RPC 池"是错的,已接入且带新鲜度硬校验。**
评审可能只看了 `scan.sh` 这个 shell 包装脚本。

---

## 给云端排查的修正建议

不要按评审的 P0 优先级原样派活。修正后:

| 评审原优先级 | 修正后 | 理由 |
|---|---|---|
| P0 代理实现覆盖 | **降级,已基本完成** | `proxy_history.py` 已实现 ERC-1967 |
| P0 干净代码误报测试 | **降级,已存在** | `benchmark-dynamic-clean-controls.cjs` |
| P1 核心路径接 RPC 池 | **降级,已接入** | `defi-campaign.py` 已用 `RpcPool` |
| P1 bytecode hash 交叉引用 | **升为 P0** | 若 `decompiler_crosscheck.py` 不含 Sourcify 查询,这是真空白 |
| P2 升级事件监听 | **降级,已实现** | 三 topic + beacon 已覆盖 |
| P2 动态验证模板化 | **保留 P1** | ⑤ 成立,泛化不足是真瓶颈 |
| 新增:LLM 接入 FP 分类 | **P0** | ③ 核心担忧成立,人工距离未自动化 |

**仍需云端深挖的真实问题**:
1. `decompiler_crosscheck.py` 是否查已验证源码(决定 ④ 真伪)
2. CREATE2 工厂内部合约发现是否有实现(决定 ① 剩余部分)
3. `discovery-plan` 生成的"待验证假设"是否真能过滤掉大部分噪声
4. FP 分类环节的 LLM 接入设计