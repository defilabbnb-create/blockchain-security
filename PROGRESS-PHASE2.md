# 阶段二进度

| 波次 | 单元 | 状态 | 完成时间 | 反空壳证据 | 备注 |
|---|---|---|---|---|---|
| W0 | Git 安全网 | DONE | 2026-10-21 |  | 基线 commit 与 phase1-baseline 标签已建立 |
| W0 | 反向 fixture 库 | DONE | 2026-10-21 | 14/14 fixture `forge build` 通过 | Foundry 1.8.5 |
| W0 | 断言注册表契约 | DONE |  |  | 仅定义注册表和加载规则 |
| W0 | 快速测试脚本 | DONE | 2026-10-21 | `fast-test.sh`/`full-test.sh` 语法与 W0 专测通过 | 关键词无匹配时显式跳过 |
| P1-1 | ERC4626 断言渲染 | DONE | 2026-10-21 | 5 模板、Solidity 片段 `forge build`、专测通过 | 参数化字段与容差 |
| P1-2 | 借贷断言渲染 | DONE | 2026-10-21 | 3 模板、专测通过 | 缺字段返回 adapter_required |
| P1-3 | AMM/跨合约断言 | DONE | 2026-10-21 | 4 模板、专测通过 | 缺依赖地址返回 adapter_required |
| P1-4 | 角色识别 | DONE | 2026-10-21 | 8 项专测通过 | confidence 阈值 0.7，新增 AMM/质押 |
| P1-5 | IR 函数粒度对账 | DONE | 2026-10-21 | 6 项专测通过 | PC/CFG 归属与 contract fallback |
| P1-6 | 分层评测 | DONE | 2026-10-21 | 33 个样本（含 3 个 clean 对照）；`--layers all` 输出四层指标 | IR/不变量/PoC 缺证据时记录 unavailable，不误算为零发现 |
| P1-7 | 部署适配器 | DONE | 2026-10-21 | 3 项专测通过 | 参数缺失和 forge 原文错误显式保留 |
| P1-8 | Web 审计界面 | DONE | 2026-10-21 | `npm run test:ui` passed；无错误请求 | 四视图、三态、移动端 |
| P2-1 | harness 真实断言生成 | DONE | 2026-10-21 | harness 专测与 `forge build` 通过 | smoke test 已删除；缺渲染器不进 forge |
| P2-2 | PoC 真实生成与执行 | DONE | 2026-10-21 | 9 项 PoC/runner 专测；真实 forge PASS 才 confirmed | 本地模板、cloud 通道、失败分类与 3 次尝试 |
| P2-3 | pipeline 部署阶段 | DONE | 2026-10-21 | 20 项 pipeline 专测通过 | deploy 阶段记录 deployedTarget/adapterRequiredCount |
| P3-1 | 真实合约离线重放 | DONE | 2026-10-21 | `e2e_real_run.py` 使用已有 campaign verified-source；输出 `network=offline_replay` | 无网络时重跑本地分析，保留 partial/unavailable，不用 fixture 冒充真实合约 |
| P3-2 | 报告四章升级 | DONE | 2026-10-21 | 报告专测通过；Markdown/HTML/SARIF 含四章与 `codeFlows` | 不变量、源码可信度、PoC、覆盖缺口独立保留状态 |
| P3-3 | Web 样式与交互打磨 | DONE | 2026-10-21 | `npm run test:ui` passed；390/768/1440 视口 | 语义色、三态、移动端和键盘焦点 |
| P4 | 全量验收 | DONE | 2026-10-22 | Node 337、Python 627、security 4/4、UI passed | `forge` 使用仓库绑定 `work/tools/forge`；`git diff --check` 通过 |

## 阶段二收尾增强

- 流水线目标级有界并行：默认 4 路，可通过 `PIPELINE_TARGET_CONCURRENCY` 或 `--target-concurrency 1..8` 调整；聚合结果保持输入顺序。
- 快速测试入口支持多个关键词并行执行，`TEST_MAX_PARALLEL` 限制进程并发，失败状态正确汇总且无匹配时显式提示。
- 四个审计视图增加“下一步”导航，移动端自动纵向排列；未改变 `/api/v1/*` 语义和只读边界。
- 收尾验证：`npm run test:parallel`、pipeline 专测、`npm run test:security`、`npm run test:ui`、语法检查与 `git diff --check` 均通过。

## 后续闭环执行记录

- 反向 fixture 真实闸门已补齐：`bash scripts/verify-reverse-fixtures.sh` 验证 7 个 fixture，correct 全部通过、violating 全部断言失败，且两变体 assertion SHA-256 一致；缺 Forge 时 fail-closed。
- 分层评测已修正：33 个样本含 3 个 clean 对照；IR 对账、不变量和 PoC 缺少证据时记录 `unavailableSampleCount` 与原因，不再当作零发现参与 precision/recall；`npm run eval -- --layers all` 当前 33/33 Slither 样本可评分，其余三层 33/33 明确 unavailable。最新报告为 `benchmark/results/20261021T050009.095195Z.json`。
- 并发资源上限统一为 8 路；默认仍为 4 路，`TEST_MAX_PARALLEL` 与 `PIPELINE_TARGET_CONCURRENCY` 超过 8 会拒绝。
- E2E 入口同步暴露 `--target-concurrency 1..8`，三合约离线重放和后续 fixed-block 重跑可直接复用同一并行限制。
- 后续阶段内并行：完整流程中独立阶段按证据依赖并发调度；`PIPELINE_STAGE_CONCURRENCY` / `--stage-concurrency` 默认 2、范围 1..4，并与目标并发共享 8 路总预算。非零预算时阶段串行，避免并行超支。阶段线程池按整次运行复用，避免每个目标/波次重复创建；Foundry invariant harness 的 `PIPELINE_FORGE_THREADS` / `--forge-threads` 默认 2，并按 CPU 自动收缩。专测与完整回归已通过。
- 性能证据已持久化：`run.json.performance` 记录墙钟、CPU、进程峰值 RSS、阶段累计耗时和 worker 利用率；目标 `state.json` 的各阶段记录 `pipelineWallMs`。完整离线 fixture 串行 217.4 ms、阶段并行 195.5 ms，提速约 11.2%，进程峰值 RSS 约 25.6/26.1 MiB；两次动态结果均 `passed`，不能外推为真实 fixed-block 链上收益。
- Web 控制台已复验：`npm run test:ui` 在 390/768/1440 视口通过，页面错误和失败请求均为 0。服务 `/api/health` 为 `ok`，但 `dataFreshness.state=interrupted`，当前展示的是已保存快照而非正在刷新中的链上数据；需运行新的采集/固定区块任务后再宣称数据更新。
- 真实合约离线 E2E 已执行 3 个已保存 verified-source 目标：`work/e2e/run-20261021-v6/summary.json`，并以 `--target-concurrency 3` 验证并行参数已透传。三者均完成 collect、repr、static、report；recon、deploy、dynamic、decompile、review、poc 按缺失证据或配置显式记录 unavailable。该产物不是 fixed-block RPC 全链通过证明。
- 仍待外部条件：提供安全的 fixed-block RPC 与部署参数后，重跑 3 个目标的 recon/deploy/dynamic；配置云审查后再启用 review。当前 3 个 clean 对照可开始估计静态检测误报，但样本量仍不足以代表真实合约总体。

## 2026-10-22 动态样本与最终回归

- 动态 benchmark 全量执行 33/33：15 个固定 SmartBugs 样本和 9 个本地合成漏洞样本的 PoC 确认；6 个样本保持 `unconfirmed`；3 个 clean control 通过；失败与无效 control 均为 0。确认数是本地隔离 EVM PoC 结果，不是扫描器 precision/recall，也不代表线上部署合约已验证。
- 五个新增观察样本 10/11/12/17/18 均由独立观察 runner 编译并执行，结果明确保持 `unconfirmed`。11 号样本的第六次数组清空交易受本地块 gas 限制回滚，证据记录了调用序号、回滚状态与交易哈希，不宣称已证明受害者锁定或资产损失。
- 修复 33-clean-amm 负对照：旧夹具没有任何输入量却允许输出量，导致所有正向 swap 都必然违反恒定乘积。新夹具执行 `100/100 → 110/91` 的有效交换，`K` 从 10000 增至 10010，并验证无输入输出与空交换均回滚；最终列为 `control_passed`。
- 修复动态 benchmark 单样本 CLI 退出码：`confirmed`、`control_passed`、`unconfirmed`、`invalid_control` 都表示 runner 正常完成并返回 0；编译/runner 错误仍返回非零。此前单样本入口把所有非漏洞 PoC 状态误当作进程失败。
- 来源核验：33/33 文件通过哈希核验，其中 20 个固定 SmartBugs 源码远端内容一致、13 个本地合成 fixture、mismatch 0。逐条核对了 33 个动态结果的 source SHA-256，并核实训练 manifest 引用的动态证据哈希均匹配。
- 训练语料：`training:analyze` 处理 168 条，静态 156 passed / 7 partial / 5 failed；动态 16 confirmed / 5 unconfirmed / 147 not run（其余样本没有目标专用 harness）；反编译 162 completed / 1 failed / 5 not run。`training:export` 输出 176 行，跳过 0。动态未运行仍是主要覆盖缺口。
- 最终验证：`npm test` Node 337/337、Python 627/627；`npm run test:security` 4/4；`npm run test:ui` 通过 390/768/1440 视口及各页面 API 检查；`git diff --check` 通过。
- Web 服务仍可访问 `http://127.0.0.1:8788`，health 为 `ok`；其 `dataFreshness.state=interrupted`、最近源码报告时间为 2026-10-16。服务健康不代表链上采集正在运行或显示的是新鲜数据。
- 下一轮建议：优先为训练语料中高置信静态线索补最小、source-bound 的目标 harness，并逐个验证 147 个 `not_run` 中哪些值得执行；先补 DoS 的受害者影响、前跑交易排序模型和未检查调用失败/记账影响所需的真实状态与资产断言。保留 3 个通过的 clean controls 作为回归闸门，再重新测静态识别率；不可把 PoC 通过数写成扫描器召回率。

## 2026-10-22 训练样本动态深挖续记

- 继续沿用现有 168 条训练语料与分片合并流程；没有重建语料、修改 benchmark ground truth 或覆盖无关工作区改动。新增 harness 均先核对固定提交样本与源码 SHA-256，再记录编译器、harness、证据哈希；PoC 结果和静态扫描指标继续分开统计。
- 高置信交易排序候选 `race_condition/RaceCondition.sol` 以三次隔离本地 EVM 重放确认：在固定买方预算下，`buy_first` 向原 owner 转 100 个测试代币；owner 先将价格设为 200 后，买方转出 200 个代币，多损失 100。买入后原 owner 的价格修改回滚。该模型证明样本源码存在排序依赖的资产变化，不模拟 mempool 概率或线上部署。
- 高置信未检查调用候选 TokenBank 以三次本地重放确认账面提款权损失：源码表达式 `_addr.call.value(_wei);` 没有调用语法，两种收款账户均未触发 fallback；两次成功提款把 2 ETH 记录额度降为 0，而合约仍持有 6 ETH。结论限于记录额度被消除，不表示 ETH 已转出或被盗。
- DoS 竞拍样本 `denial_of_service/auction.sol` 已 source-bound 三次确认：拒收退款的领先者可使受害者更高出价回滚，状态不变；同文件 pull-refund 对照接受相同出价并记入退款。另一 DoS 样本 `denial_of_service/list_dos.sol` 在声明兼容的 Solidity 0.4.15 下原样编译失败（`transfer` 无返回值却传入 `require(bool)`，且 `mapping(address => uint)` 被 `uint` 索引）；记录为 `harness_not_feasible`，没有修补后冒充原样本验证。
- 未检查补偿候选 King of the Ether Throne 经精确源码可行性检查后保留 `harness_not_feasible`：claim 与 fallback 均为 nonpayable，不能提供进入最低 claim 价格和补偿发送路径所需的 ETH；未用修改版源码作动态确认。
- 本轮动态训练语料最新状态：168 条中 `19 passed/confirmed`、`5 unconfirmed`、`2 harness_not_feasible`、`142 not_run`。相对此前基线新增 3 个本地动态确认（竞拍 DoS、交易排序、TokenBank）；2 个样本因收集源码问题而不可执行。该状态不是扫描器召回率，也不代表线上合约已验证。
- 三个 clean control 仍作为 benchmark 回归闸门：`31-clean-vault`、`32-clean-lending`、`33-clean-amm`；训练动态确认数未计入扫描器 precision/recall。动态 JSONL 导出和完整 33 样本 benchmark 回归随后执行并记录结果。
- Web 采集状态的限制不变：服务在线不代表数据新鲜；链上采集仍为 interrupted，最近源码报告时间仍为 2026-10-16。

## 2026-10-22 高置信训练样本续查

- 在不改动 ground truth 的前提下继续筛查 `not_run` 样本，新增的最小 harness 均绑定原始源码 SHA-256，并在隔离本地 EVM 重放 3 次；动态 PoC 与静态扫描指标分开统计。
- `front_running/odds_and_evens.sol` 三次确认固定交易排序模型中的资产转移：攻击者复制待处理的 `play(0)` 并先进入玩家槽，获得 1.8 ETH；盲猜 `play(1)` 对照中受害者获得 1.8 ETH。该模型没有模拟公共 mempool 传播或线上部署。
- `unchecked_low_level_calls/0x2972d548...sol` 三次确认：mock token 的 `transferFrom` 返回 `false` 且不转账时，目标 wrapper 仍成功返回 `true`；接受调用的 token 对照成功转移 17 个测试 token。TokenBank 证据仍限于错误提款表达式导致 2 ETH 账面提款权被清零，银行仍持有 6 ETH，不能称为资产已转出或被盗。
- DoS 影响边界：`dos_number.sol` 中为数组清理而设计的 `clearDOS()` 在 7,000 项下触及本地 30M gas 上限并回滚，但公开 `clear()` 仍以 21,484 gas 完成逻辑清空，后续插入也成功（51,248 gas），所以保留 `unconfirmed`。`send_loop.sol` 的硬编码收款人没有可达的退款记账/入金入口，不能靠改写状态制造受害者 DoS；`list_dos.sol` 原样编译失败，仍为 `harness_not_feasible`。
- `unchecked_low_level_calls/etherpot_lotto.sol` 的 source-bound 可行性检查三次一致发现原始 fallback 为 nonpayable，且没有其他公开入口能创建票数或奖池。购票回滚，无法建立进入未检查中奖转账的有效状态；标记 `harness_not_feasible`，没有改源或声称确认漏洞。FindThisHash 仍为 `not_run`，本地样本没有固定 hash 的前像。
- 当前 168 条训练语料动态状态：`21 passed/confirmed`、`6 unconfirmed`、`3 harness_not_feasible`、`138 not_run`。其中 `dos_number` 的清理回滚不等于用户功能被阻断。此计数不是静态扫描召回率，也不代表线上合约已验证。
- 保留 `31-clean-vault`、`32-clean-lending`、`33-clean-amm` 三个 clean control 为回归闸门；最近 33-case benchmark 仍为 24 个漏洞 PoC 本地确认、6 个 unconfirmed、3 个 clean control 通过。观察样本 10/11/12/17/18/28 均未提升为确认。
- 最新 `training:export` 输出为 176 行、跳过 0；20 条动态证据通过导出器的源码、证据、断言、交易状态与隔离边界校验并标记 `confirmedVulnerability=true`，另有旧 benchmark 证据因缺少规范化成功收据仍保守导出为 `unverified`。race 与 odds harness 已补全成功 receipt 记录并重新三跑，二者均通过该确认门槛。针对性回归：训练动态 harness 测试 28/28，训练证据导出测试 5/5，新增 Lotto runner 的 Python/Node 语法检查通过，`git diff --check` 通过。未因此重跑全套 Node/Python、安全或 UI 套件。
- Web/链上数据新鲜度限制未变：本地服务在线，但采集状态仍为 `interrupted`，最近源码报告仍是 2026-10-16；不可把服务健康当作新鲜扫描数据。

## 2026-10-22 离线语料任务控制面（LaneW）

- 新增离线语料控制面：后端 `src/corpus-control.js`、前端 `web/views/corpus.js`、测试 `tests/corpus-control.test.js`；修改 `src/web-server.js`、`web/app.js`、`web/index.html`、`web/styles.css`。控制面只管理本地离线泳道（`static` / `dynamic` / `decompiler` / `fetch` / `eval`），只读本地语料目录、`benchmark/contracts` 与 `work/`，只允许调用白名单内的本地脚本。证据产物为 `work/lane-W-report.json` 与 `work/corpus-control/tasks.json`。
- **链上采集守卫仍是后端硬拒绝，不依赖前端置灰。** 双层守卫：`CorpusControlPlane.handle` / `#assertOfflineLane` 对链上语义路径与泳道名直接抛 `chain_collection_disabled`；`src/web-server.js` 的 `/api/v1/collection` 系列与 `/api/v1/tasks` 路由入口在 `chainCollectionEnabled=false` 时命中 `isChainCollectionStart` 即返回 HTTP 400。命令行服务默认关闭，只有显式设置 `CORPUS_CHAIN_COLLECTION=1` 才放开。复验（本地另起端口 8799 的新实例，验证后已关闭）结果：`POST /api/v1/corpus/chain-collection/start`、`POST /api/v1/collection`、`POST /api/v1/tasks`（`type=v1-resource-collection`）以及 `/api/v1/corpus/tasks/{campaign,chain-scan,defi-campaign,collection}/start` 全部返回 HTTP 400 且 `error.code=chain_collection_disabled`；被拒请求不会创建任务（`/api/v1/tasks` 列表条数不变）。库调用方式下 `chainCollectionEnabled` 缺省视为放行，属既有历史行为，未在本轮改动。
- **验收复跑结果**：`node --test tests/corpus-control.test.js` 8/8 通过；`node --test tests/web-runtime.test.js` 22/22 通过；`python3 -m unittest discover -s tests` 共 676 项全部通过（OK，failures=0，约 39 秒）。四个改动文件 `node --check` 语法检查通过。`work/lane-W-report.json` 中记录的用例名与实测一致；其 `knownGaps` 里提到的 “Python 既有测试 1 项失败（notRunSampleCount 46 与 47）” 在本次复跑中未复现——`tests/test_training_dynamic_unchecked_token_false.py` 单独 4/4 通过，断言 `notRunSampleCount <= 47` 当前成立。
- **证据产物与实现一致**：`work/corpus-control/tasks.json` 顶层为 `schemaVersion=1` / `laneId="W"` / `generatedAt` / `persistenceFile` / `pauseSemantics="sample_boundary"`，`tasks` 数组含 `fetch` 一条已完成任务（9/9 通过，原因均为 `offline_cache_sha256_match`，`lastHeartbeatAt=2026-10-22T09:03:43.215Z`），与实现的原子写入、持久化字段一致。`/api/v1/corpus/tasks` 实测返回 5 个泳道（static/dynamic/decompiler/fetch/eval），fetch 为 `completed`，其余为 `idle`，与 `CORPUS_LANES` 注册表一致；`/api/v1/corpus/filters` 实测 16 个类别、5 个层、48 条 categoryLayerStates、17 条 benchmarkIssueCategories，与报告一致。
- **四泳道只做了单样本级验证，未跑完整批次。** 本轮独立复跑中，`static` 泳道以 `category=bad_randomness` 跑了 9 个样本（临时 state/shard 目录，不写 `work/` 既有证据）：8 项 `passed`（分析器 `completed`），1 项 `failed`（`ValueError: empty Slither compilation`，与 `work/static-compiler-feasibility.json` 中 `bad_randomness/theRun_source_code/theRun.sol` 的 `partial` 记录一致）。这是单类别、单批次的样本级结果，不是全量覆盖率，也不是审计通过。
- **静态泳道依赖本地已缓存 soljson，不联网下载。** `src/corpus-control.js` 的 `#resolveCachedCompiler` 只读 `work/compiler-cache/list.json` 与已缓存的 `soljson-v*.cjs`，并按官方发布清单的 SHA-256 复核；缓存缺失或哈希不符时该样本记为 `failed`（`compiler_not_cached_offline`），不触发下载。当前缓存覆盖 48 个版本，manifest 中记录的实际编译器版本为 0.4.x（0.4.26 共 135 条）至 0.8.28，均在缓存范围内。
- **评测泳道输出是 Slither 静态告警线索，不是漏洞确认。** `#runEvalItem` 以 `--layers slither` 调用 `scripts/eval_pipeline.py`，产出 precision/recall 与 Slither 告警明细。告警只是线索；本地测试通过不等于确认漏洞，不等于部署合约安全，也不等于实际可利用。
- **探针结论（补充记录）**：`work/static-compiler-feasibility.json` 给出 12 个样本的逐样本编译器候选矩阵——`recordedCompiler` 与 `recordedCandidates` 未必是唯一可行版本，7 个样本 `partial`、5 个 `failed`；其中 `denial_of_service/list_dos.sol` 在 0.4.19~0.4.26 全部候选下都无可用编译器（0 个 workable），属于源码本身不适配，不能靠换版本解决。`work/solc-json-contract-compat.json` 逐版本实测 solc 标准 JSON 契约差异：`settings.compilationTarget` 在 0.4.22~0.4.26 可用，0.5.8 及以后直接报错 `Unknown key "compilationTarget"`；`sources[file].ast` 键自 0.4.13 起出现，`legacyAST` 节点在所有版本都没有被填充（0.4.18 及以后连 `legacyAST` 键都不再返回）。需注意当前实现的用法：`src/corpus-control.js` 的静态泳道把 `compilationTarget` 写在 bundle 的 `metadata.settings` 里，而 `scripts/review-static.py` 只从该处读取编译目标名用于动态 harness 选靶，并不把它写进 solc 的标准 JSON `settings`；因此该探针结论目前是后续改动（若要把 `compilationTarget` 直接下发给 solc）的约束条件，而不是当前已触发的故障。这些结论只能作为修复线索，不构成漏洞判断。
- **口径纪律不变**：本地测试通过 ≠ 漏洞确认；Slither 是线索；语料统计来自本地 manifest 与分片目录的已保存内容，不是实时任务；链上采集状态仍为 `interrupted`（最近源码报告仍为 2026-10-16），本轮未启动、未恢复、未重启任何 campaign / defi-campaign / soak，未执行资产授权、签名或广播，未修改模型配置，未干扰其他稳定性测试，`work/` 下既有报告未删除或覆盖。
