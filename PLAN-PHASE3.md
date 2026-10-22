# 区块链安全 · 源码采集与审查 续跑优化方案（Phase 3）

面向执行者（GPT / DSH / DHLsh）。本文件是**方案**，不是执行记录。所有数字都标注来源文件与时间。

- 证据基准：`work/defi-campaign/930f4b6d-760a-40b2-8d9f-c4744bc4fd7d/`（runId `930f4b6d-760a-40b2-8d9f-c4744bc4fd7d`）
- 采集状态文件：`work/defi-campaign.json`
- 采集入口：`scripts/defi-campaign.py`（`npm run research:hour`）
- Web 状态接口：`http://127.0.0.1:8788/api/health`、`/api/campaign`、`/api/rpc-pool`、`/api/sync`

---

## 0. 必须先接受的三个事实（否则会得出错误结论）

1. **上一次采集已中断，不在运行。** `work/defi-campaign.json` 的 `state=interrupted`，最后心跳 `2026-10-17T03:10:11Z`，PID 14683；`kill -0 14683` 返回 no such process。采集窗口 28.9 分钟 / 目标 60 分钟（48.2%），`validation.targetWindowReached=false`。
2. **旧结论不代表当前代码。** 那次采集的 `sourceFingerprint=54b1d6904c7690aeb0b19a69f837e370573a2f636bc9d5bb84d7dad3eaa0f9d4`，当前运行时指纹为 `230f9a2a0a0fdea246b982cd5b150ddbf37b5f46f6742bee8de939db525c226b`。**续跑必须产生新 runId 与新证据目录**，旧目录只作历史对照，不得与新结果混合统计。
3. **`review`（云端审查）阶段全程没有证据。** `/api/health` 显示 `cloudAI.configured=false`、`dsh.available=false`；`DEFI_CLOUD_AI_BASE_URL/API_KEY/MODEL` 未设置。10-17 那批 77 份审查是**旧版来源审查**（`historicalLocalReviews=77`），不是模型审查证据，不得计入云端审查指标。

---

## 1. 现状基线（10-17 那一轮，来自 `summary.json` 与 218 份 `contracts/*/evidence.json`）

| 环节 | 数量 | 分母 | 备注 |
|---|---|---|---|
| 协议-链初筛合格 | 253 | — | 口径：协议在目标链 TVL ≥ $10,000，**不是单合约余额** |
| 已尝试协议-链 | 169 | 253 | 66.8% |
| 发现阶段阻塞 | 63 | 253 | adapter 缺失 / provider 冷却 / HTTP 错误 |
| 合约候选 | 218 | — | 去重地址 6 |
| 部署已核实 | 204 | 218 | |
| 运行时代码读取 | 204 | 204 | 确定性 EVM 反汇编，**不是**高层反编译 |
| 验证源码获取 | 85 | 204 | 41.7% |
| 旧版来源审查 | 77 | 85 | 非云端审查 |
| 静态检查完成 | 68 | 85 | 80% |
| 静态检查失败 | 9 | 85 | solc 缺失 / 导入解析失败，见 §4 |
| 隔离动态检查 | 10 项 / 2 套件 | 204 | 失败 0；**216 项 not_performed** |
| 合约阶段阻塞 | 133 | 218 | 见 §2 错误分布 |
| **已确认漏洞** | **0** | — | 无任何经确认可利用漏洞 |

### 阻塞根因（218 份 evidence.json 逐份统计）

| 错误 | 次数 | 归类 |
|---|---|---|
| `HTTPError: HTTP Error 404: Not Found` | 116 | **源码源单一**：`scripts/defi-campaign.py:768` 只打 Sourcify 一个端点，404 直接判 blocked，无回退 |
| `ValueError: address has no valid deployed code at pinned block` | 8 | 代理/自毁/未部署，非缺陷 |
| `ValueError: RPC disagreement or reorg at pinned block` | 3 | 需多端点一致性重试 |
| `HTTPError: 400 Bad Request` | 2 | 参数问题 |
| `No usable verified RPC` / SSL 超时 / `campaign stopping` / `NoneType` | 4 | 运行期环境问题 |

404 的链分布高度集中：Flare(14) 15/30、Cronos(25) 19/25、Fantom(250) 16/22、Aurora 13/22、Astar(592) 13/16、Kava(2222) 7/7。→ **这不是随机故障，是 Sourcify 对这些长尾链覆盖不足**，加端点数量解决不了，必须加**第二数据源**。

### 审查质量与其它缺口

- `reviewObservations=78`，其中 `unsupportedModelObservations=54`（约 69% 无源码支撑）→ 现有审查没有强制"引用文件+行"约束。
- `reviewHypotheses=35`，`confirmedVulnerability=0`。
- `cloudReviewUnavailable=1`（配置缺失导致的失败）。
- 反编译（Heimdall）`decompilation.state=not_recorded` → 上一轮**没有启用** `--decompiler`。

---

## 2. 优化目标（可验收，按优先级）

| 编号 | 目标 | 验收标准（可自动判定） |
|---|---|---|
| G1 | 采集跑得起来且跑满窗口 | 新 runId `state=completed`，`validation.targetWindowReached=true`，`sourceUnchanged=true`，`continuousSampling=true`，`durationMs ≥ 3600000` |
| G2 | 源码获取覆盖率翻倍 | `verifiedSourceBundles / deployedContracts` 从 41.7% 提升到 **≥ 70%** |
| G3 | 404 不再是主要阻塞 | 404 计数从 116 降到 **≤ 30**，且每条 404 都带**已尝试过的数据源列表** |
| G4 | 静态分析不再大面积失败 | 静态检查失败率从 9/85 降到 **≤ 3%**，且每条失败都能归因到具体原因（solc 版本 / 导入重映射 / 文件名安全） |
| G5 | 有真实模型审查证据 | `analysisMode.cloudAI.completedCalls > 0`，每份审查目录存在 `cloud-review-evidence.json`，且 `unsupportedModelObservations` 占比降到 **≤ 30%** |
| G6 | 动态验证有规模化路径 | `dynamicTestsPerformed` 从 10 提升到 **≥ 50**，且每条有明确 harness 与被测函数 |
| G7 | 报告口径不被误读 | 采集/模型审查/Slither/本地复现**四类计数分列**，`已确认漏洞` 与 `风险假设` 在 UI 与 JSON 中分开呈现 |

---

## 3. 阶段 A —— 让采集跑得起来（前置，最高优先）

**A1. 刷新 RPC 池（硬前置）**
`scripts/defi-campaign.py:607` 要求 `work/rpc-pool.json` 的 `generatedAt` 在 **30 分钟内**，否则启动即失败。当前池子 `generatedAt=2026-10-17T04:13:38Z`，已过期 5 天。
```
npm run rpc:refresh
```
必须紧接启动采集执行，且中途不要让池子过期。

**A2. 清理陈旧锁**
`work/defi-campaign.lock` 仍写着 pid 14683（该进程已不存在）。采集实际用 `fcntl.flock`（`scripts/defi-campaign.py:983`），进程退出即释放，**不会**阻塞。但建议在启动前删除该文件，避免外部工具误判"正在运行"。

**A3. 起进程并按心跳判定存活**
```
npm run research:hour          # 等价 python3 scripts/defi-campaign.py --duration 3600
```
判定"仍在运行"的唯一标准：`work/defi-campaign.json` 的 `heartbeatAt` 新鲜（< 60 秒）+ `lease.pid` 存活 + `heartbeatSeq` 递增。**"优先队列非空"不等于进程在跑。**

**A4. 禁止事项**
- 采集期间**不修改** `src/`、`scripts/` 下被测源码（会触发 `fingerprint_check` 记 `validationErrors`，状态变 `invalidated`）。
- **不重启** Web 服务、不改动其他项目的稳定性测试；本项目当前无 `work/soak.lock`。
- 不执行任何资产授权、签名、广播（采集本身是只读）。

---

## 4. 阶段 B —— 源码获取覆盖率翻倍（对 G2/G3 贡献最大）

这是唯一能实质抬高覆盖率的改动，其余都是边角。

**B1. 多数据源回退链（核心改造）**
当前只有 Sourcify 一个源（`scripts/defi-campaign.py:768`）：
```
https://sourcify.dev/server/v2/contract/{chainId}/{address}?fields=all
```
建议改造为**有序回退链**，每个源都独立记录尝试结果：

1. **Sourcify**（现有）
2. **Etherscan V2 多链 API**（`https://api.etherscan.io/v2/api?chainid={chainId}&module=contract&action=getsourcecode&address={addr}`）—— 覆盖长尾链能力显著强于 Sourcify。需 `ETHERSCAN_API_KEY`（多链一把 key 通吃）。项目里 `scripts/proxy_graph.py:89` 已经把 `etherscan_v2` 当作一等 provider，但 `defi-campaign.py` 完全没用上 —— **代码已存在，只需接线**。
3. **Blockscout 类实例**（部分长尾链自带官方 explorer，如 Flare/Cronos/Fantom 系；需按链维护 explorer 域名表）
4. **GitHub 官方仓库核验**（项目已有该能力：仓库内已有按官方仓库路径拉取核验的 adapter 机制，见 `scripts/defi-campaign.py:621-628` 的历史修订回溯逻辑）

**B2. 身份与字节码核验必须保留**
现有两条硬校验不能因为换源而放松（`scripts/defi-campaign.py:770-773`）：
- 返回的 `chainId` + `address` 必须与目标一致（防串链）；
- 源提供的 `onchainBytecode` 必须与**在固定区块上**用 `eth_getCode` 取到的运行时字节码一致，且 `runtimeMatch ∈ {exact_match, match}`。
任何放宽都会让"源码"变成"同名但不同物"，这是本项目最不能退化的红线。

**B3. 代理合约的实现合约也要取源码**
统计显示 `reviewCompleteness` 里 `proxy_only_implementation_unavailable` 有 21 份。应对 EIP-1967 / beacon 实现的实现合约**单独走一遍 B1 源**，并把代理解析链（proxy → implementation → 关联库）一起纳入审查。

**B4. 失败必须可归因**
每个未取到源码的合约，`evidence.json` 要落一份 `source-attempts.json`：尝试了哪些源、每个源的 HTTP 状态与错误、链上是否有部署代码。这样 404、RPC 问题、源覆盖问题三类能分开统计，不再混在 `blocked` 里。

**B5. 预期收益**
116 条 404 中，若 Etherscan V2 能覆盖 Flare/Cronos/Fantom/Aurora/Astar/Kava 的多数，源码获取率可从 41.7% 提升到 65%~75%，直接达成 G2。

---

## 5. 阶段 C —— 修静态分析的 9 条失败（对 G4）

失败分类（来自 `evidence.json` 的 `staticAnalysis.error`）：
- `Solidity version not found` ×3 → 需要预取 solc 二进制。项目已有 `npm run solc:prefetch` 与 `toolchain.lock.json`，走这条通道即可。
- `Command '['/Library/Developer/CommandLineTools/usr/bin/python3', ...` ×3 → **调用了系统 Python 而非项目虚拟环境**，且**源码指纹一致性依赖固定解释器**。应固定为项目 venv 内的 python 绝对路径。
- `unsafe source filename` ×2 → 文件名安全校验太严（编译器产物路径含 `../` 等），需在**不放松安全边界**的前提下规范化到受控临时目录再分析。
- `ParserError: Source "lib/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Utils.so…` ×1 → OpenZeppelin 导入路径解析失败。Sourcify bundle 的 `sources` 键是编译期路径，需做**导入重映射**（把 `lib/openzeppelin-contracts/...` 映射到 bundle 内实际存在的键），并对解析失败的 import 显式降级为"未能解析的外部依赖"，而不是整个分析失败。

配套要求：静态分析结论一律标为**线索**，不得写成"确认漏洞"；须记录源码指纹、编译器版本、覆盖文件数。

---

## 6. 阶段 D —— 接入真实模型审查（对 G5）

**D1. 配置凭据（需用户授权，本方案不代做）**
```
DEFI_CLOUD_AI_BASE_URL=...
DEFI_CLOUD_AI_API_KEY=...
DEFI_CLOUD_AI_MODEL=...
```
三者齐备时 `config.cloudReviewConfiguration` 才为 `configured`（`scripts/defi-campaign.py:366`）。注意项目红线"不修改模型配置"——新增环境变量属于用户提供凭据，**必须由用户显式授权并提供**，执行者不得自行改写模型配置文件或既有模型参数。

**D2. 审查提示词必须带可验证约束**
现模型审查无约束导致 54/78 观察无源码支撑。建议每份审查强制输出结构：
- 每条观察必须引用 `文件路径:行号` 或标注 `unverifiable`；
- 每条风险假设必须给出 `攻击前提 / 触发调用路径 / 影响面 / 缺失的证据`；
- 明确区分 `risk_hypothesis`（假设）与 `confirmed_vulnerability`（已复现确认）——**本项目已确认漏洞目前为 0**，不要用假设数量冒充成果。

**D3. 证据落盘**
每份审查必须写 `cloud-review-evidence.json`（含 provider、model、manifestSha256、responseSha256、providerRequestId）。缺文件的审查**不计入**云端审查指标。

**D4. 预算与并发**
`--review-budget-usd` 控制单份预算；`--workers` 上限为 3（`scripts/defi-campaign.py:978` 硬校验），`--review-budget-usd` 不为负。

---

## 7. 阶段 E —— 动态验证规模化（对 G6）

现状 `dynamicTestsPerformed=10`、`dynamicTestsNotPerformed=216`，原因写得很直白：*"No target-specific local EVM harness is defined for this contract."*

- 仓库已有 `scripts/harness_gen.py`、`scripts/dynamic_runner.py`、`scripts/poc_generator.py`、`scripts/poc_runner.py`，以及多套 benchmark 动态脚本（reentrancy、access control、overflow、AMM 等）。
- 建议：用 `harness_gen.py` 对**静态分析给出高置信线索**的合约**自动生成最小 harness**，而不是对全部 204 个都生成（成本与噪声都不划算）。
- 只有真正跑起来的项才计入 `dynamicTestsPerformed`；每条保留：harness 文件、被测函数、调用序列、断言、结果。
- **本地测试通过 ≠ 部署合约存在漏洞**。报告中必须保留这一句限定。

---

## 8. 阶段 F —— 报告与口径（对 G7，防止误读）

必须分开呈现、不得相加或互相替代的**四类计数**：
1. **采集**（协议-链初筛 / 合约 / 运行时代码）
2. **模型源码审查**（有 `cloud-review-evidence.json` 才算）
3. **静态分析（Slither 等）** —— 只是线索
4. **本地复现（Hardhat/Foundry）** —— 只是复现，不代表部署合约安全

其它口径纪律：
- TVL ≥ $10,000 是**协议在目标链**的初筛口径，**不是单合约余额**、不是当前可转移资产。
- 优先队列非空 ≠ 扫描进程在跑；以心跳 + PID 存活为准。
- `completed` 只表示**采集窗口结束**，不等于审计通过。
- 引用数字必须带 `generatedAt` / `lastReportAt`；`work/dsh-status.json` 与 `work/dsh-sync.json` 的 `syncVersion` 不一致时，先重读，仍不一致则声明"尚未同步"。
- 共享文件不证明 DSH/DHLsh 客户端已消费；未完成对话验收前，不得声称两个客户端端到端通过。

---

## 9. 阶段 G —— 可选增强

- **G-1 启用反编译**：上一轮 `decompilation.state=not_recorded`，即没开 `--decompiler`。加 `--decompiler heimdall` 可为**没有验证源码**的合约产出启发式伪码。注意这是**启发式推断，不是已验证源码**，报告口径必须写清。代价：每合约最多 30 秒墙钟，会挤占 60 分钟窗口的合约吞吐 → 建议**先跑不带反编译的一轮拿覆盖率，再跑一轮带反编译的补伪码**，不要一次混做。
- **G-2 提高并发**：`--workers` 当前被限制在 1..3。若 RPC 池每链健康端点够（`maxPerChain=8`），放宽上限并同步调高 `remoteHostIntervalSec`（现 0.5 秒/host）可显著提速；但**必须先确认各 provider 的 403/429 冷却不会被打爆**（当前 12 条错误里已有 6 条 provider 冷却）。
- **G-3 协议-链深挖**：每个协议-链每轮只取 3 个地址（`scripts/defi-campaign.py:912`）。覆盖率补齐后，可提高每协议链的地址批次，优先吃 63 条发现阶段阻塞（其中 4 个协议缺 adapter：Reaper Farm、Beefy、Kava Swap、vfat.io）——为它们补 adapter 或手工地址可直接提高初筛达成率。

---

## 10. 推荐执行顺序与门禁

| 顺序 | 动作 | 门禁（不满足则停） |
|---|---|---|
| 0 | 用户授权并提供 `DEFI_CLOUD_AI_*`（如需 D）与 `ETHERSCAN_API_KEY`（如需 B） | 未提供则对应阶段跳过，其余照跑 |
| 1 | `npm run rpc:refresh` | 池子 `generatedAt` 新鲜 |
| 2 | 清理 `work/defi-campaign.lock` | 无残留 pid |
| 3 | **B1 多源回退改造 + B2/B3 核验保留 + B4 失败归因** | 单测：任一源返回错链/错字节码必须被拒 |
| 4 | C 静态分析 4 类失败修复 | 固件编译与 Slither 在固定解释器下可复现 |
| 5 | 起一轮 3600 秒采集 | 结束时 `state=completed` 且 `validation` 四项全绿 |
| 6 | 读取 `/api/campaign` 与 `work/defi-campaign.json` 汇总 G2~G7 | 不达标则在 §11 记录**差距原因**，不粉饰 |
| 7 | 按需跑第二轮（`--decompiler heimdall` 或更高并发） | 与第一轮分目录、分 runId，不混合统计 |

---

## 11. 交付物清单（执行者必须产出）

1. 新 runId 的 `work/defi-campaign.json` + `work/defi-campaign/<新runId>/`（含 `summary.json`、`events.jsonl`、`rpc-usage.json`、`contracts/*/evidence.json`、`contracts/*/source-attempts.json`）。
2. 一份阶段对照表：G1~G7 逐项 **达标 / 未达标 + 差距数值 + 原因**。
3. 四类计数分列的汇总（采集 / 模型审查 / 静态 / 复现），每项带分母与来源文件路径。
4. `unsupportedModelObservations` 占比、`404` 分类计数、静态失败归因表。
5. **明确的负面结论**：确认漏洞数量（若仍为 0，写 0，不折算）、未完成项、被跳过的阶段及原因。
6. 若阶段 D 未获授权：明确写"云端审查未配置，本轮无模型审查证据"，不得用旧版来源审查顶替。

---

## 阶段 H —— 离线语料控制面（LaneW，已实现，边界见下）

链上采集在离线阶段不开放，语料工作改由本地控制面承接。实现位置：后端 `src/corpus-control.js`，前端 `web/views/corpus.js`（侧边栏第 15 项「离线语料控制台」），测试 `tests/corpus-control.test.js`。

| 编号 | 目标 | 验收标准（可自动判定） |
|---|---|---|
| H1 | 五条离线泳道可独立调度 | `GET /api/v1/corpus/tasks` 返回 static/dynamic/decompiler/fetch/eval 五条泳道的状态、进度与心跳 |
| H2 | 暂停只在样本边界生效 | 暂停请求后当前样本跑完才进入 `paused`；正在运行的 compiler/forge/node 子进程不被杀 |
| H3 | 停止可终止子进程 | 先向进程组发 SIGTERM，宽限 5 秒未退出再 SIGKILL |
| H4 | 心跳与 PID 双校验 | 心跳超过 120 秒或 PID 已死时不再显示 `running`；恢复时把死任务标为 `interrupted` 并落盘 |
| H5 | 链上采集一律后端拒绝 | `POST /api/v1/corpus/chain-collection/start`、`POST /api/v1/collection`、`POST /api/v1/tasks`（采集语义类型）全部返回 HTTP 400 且 `error.code=chain_collection_disabled`，且不创建任务 |
| H6 | 语料统计口径明确 | 概览带 manifest SHA-256 与 `generatedAt`；统计来自本地已保存内容，不表述为实时任务 |

H5 的执行记录与已知缺口见 `PROGRESS-PHASE2.md` 的「2026-10-22 离线语料任务控制面（LaneW）」一节；证据文件为 `work/lane-W-report.json` 与 `work/corpus-control/tasks.json`。

**边界（不得放宽）**：静态泳道只使用 `work/compiler-cache` 已缓存的 soljson，缺失即记 `failed`，不联网下载；评测泳道以 `--layers slither` 运行，输出是静态告警线索，不是漏洞确认；四泳道目前只做过单样本级验证，未跑完整批次。

---

## 12. 红线（继承 AGENTS.md，不可放宽）

- 不执行资产授权、签名、广播。
- 不修改模型配置（新增环境变量须用户显式提供与授权）。
- 采集期间不修改被测源码、不重启 Web 服务；变更后必须**新运行**，不得把两次运行的数字混在一起。
- 不干扰其他项目的稳定性测试；本项目 `work/soak.lock` 当前不存在，无需处理。
- 用户已取消三小时报告、改为一小时持续采集：不得重启旧 soak；离线阶段不得启动任何链上采集。
- 离线语料控制面不得为放行链上采集而修改守卫；链上采集的放开只能由用户显式设置 `CORPUS_CHAIN_COLLECTION=1`。
- 保留失败与中断报告，不删除历史证据目录。
- 共享文件不构成客户端已消费的证据；未经对话验收，不声称 DSH/DHLsh 端到端通过。

---

## 附：本方案引用的证据位置

| 结论 | 来源 |
|---|---|
| 采集中断、窗口 48.2% | `work/defi-campaign.json`（`state=interrupted`，`updatedAt=2026-10-17T03:10:11.731781Z`） |
| PID 14683 已不存在 | `kill -0 14683` → no such process |
| 计数与校验 | `work/defi-campaign/930f4b6d.../summary.json`（`counts`、`validation`、`analysisMode`） |
| 218 份合约状态分布 | `work/defi-campaign/930f4b6d.../contracts/*/evidence.json` 逐份统计 |
| 阻塞错误分布 | 同上，`error` 字段聚合（404×116 等） |
| 源码单源 | `scripts/defi-campaign.py:768` |
| 已存在但未接线的 etherscan_v2 provider | `scripts/proxy_graph.py:89` |
| RPC 池 30 分钟新鲜度门禁 | `scripts/defi-campaign.py:607` |
| workers 上限 1..3 | `scripts/defi-campaign.py:978` |
| 每协议链每轮 3 地址 | `scripts/defi-campaign.py:912` |
| 云端审查配置判定 | `scripts/defi-campaign.py:366` |
| 字节码/身份双校验 | `scripts/defi-campaign.py:770-773` |
| 当前运行时指纹 | `node -e "import {runtimeFingerprint} from './src/runtime-fingerprint.js'..."` → `230f9a2a...` |
