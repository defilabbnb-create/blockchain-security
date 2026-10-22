# 区块链安全工具

本地源码静态分析 + EVM 新建合约只读扫描。无需钱包或私钥。

## 最快使用

- 双击 `开始扫描.command`：扫描 Ethereum 最近一个已等待 2 个区块的区块，保存到 `reports/latest-chain-scan.json`。
- 双击 `静态分析.command`：编译并分析 `flare-scan/targets.json` 的 10 个目标，报告在 `flare-scan/reports/`。
- 终端运行 `npm run doctor` 检查环境；`npm run test:parallel` 运行受控并行回归测试；改代码时用 `npm run test:fast -- pipeline invariant_gen` 只跑相关测试。
- 运行 `npm run screen`：按历史 TVL、当前 TVL、跨链 connection 和 RPC 健康度筛选候选链；结果在 `flare-scan/reports/chain-screen.json`。

要求 Node.js >=24.5.0、Python >=3.9。链上扫描没有 npm 第三方依赖。静态分析使用本目录现有 Slither 0.11.4 与独立安装的 solc-js 0.8.19 / 0.8.23 / 0.8.28。

## 链上扫描

```bash
bash scan.sh --help
bash scan.sh --blocks 10 --confirmations 12 --output reports/scan.json
RPC_URL=https://your-node CHAIN_ID=14 bash scan.sh --blocks 2
```

`--output` 的父目录需要先创建。也可以复制 `.env.example` 为 `.env`；`bash scan.sh` 和 `npm run scan` 会加载它，环境变量优先。密钥只保存在本地 `.env`。

默认 RPC 为 `https://ethereum-rpc.publicnode.com`，不会自动切换节点或链。macOS 启动脚本会使用系统 HTTPS 代理；已有 HTTP(S)_PROXY 优先，`USE_SYSTEM_PROXY=0` 可关闭系统代理读取。支持普通 HTTP 代理，不支持 PAC/SOCKS 自动转换。直接执行 `node src/scan.js` 时，若需要代理，请设置 `NODE_USE_ENV_PROXY=1 HTTPS_PROXY=...`。

扫描读取完整交易列表，只为顶层创建交易查询回执，最多 4 路并发；不会截断 500 笔。余额使用 BigInt 十进制字符串，单位为原生币最小单位（Ethereum 为 wei）；读取创建区块的代码与余额，不是当前余额。零余额合约默认包含，可用 `--min-balance-wei` 过滤。每个区块及最终锚点会检查 hash 一致性。

范围：仅顶层部署，不覆盖工厂内部 CREATE/CREATE2、历史全部合约、ERC20 持仓或代理实现漏洞。发现合约和余额不代表发现漏洞。confirmations 是等待区块数，不是最终性保证。

退出码：0 完整；1 参数、网络或区块一致性失败；2 部分结果（如回执缺失）。请同时检查 JSON 的 `complete` 与 `issues`。彻底失败时不覆盖旧输出文件，所以不能仅凭文件存在判断本轮成功。

历史入口 `etherscan-scan.mjs`、`src/scan.js`、`src/scan.ts` 共用一套实现。

## 冷门链价值与跨链筛选

`npm run screen` 使用 `scripts/chain-screener.py`，把“以前有热度”和“现在还有价值/可转移性”拆成独立证据：

1. 从 DefiLlama 拉当前链 TVL 和历史 TVL 峰值；历史峰值是热度线索，当前 TVL 是资金价值代理，两者都不等于可取回资产。
2. 只对通过历史/当前门槛的链查询 LI.FI connections 和候选 RPC；低于双门槛的链会记录 `prefilterSkipped`，不会浪费跨链 API 或节点请求。需要强制检查某条链时使用 `--chain`。
3. `connection_only` 只代表存在兼容链/代币连接；加入 `--from-token`、`--to-token`、`--amount` 后才请求真实报价，`quote_verified` 只证明采集时取得报价，当前可执行性须重新报价。报价请求需要 `fromAddress`/`toAddress`，默认是不可持币的零权限测试地址，绝不签名、授权或广播。
4. `readyForDeepDive` 要求历史价值、跨链 connection 和 RPC chain ID/区块高度同时通过；`candidateForDeepDive` 允许节点暂时不可用，方便进入待修复节点队列。`selected` 与 `ready` 两个数组分别对应这两个状态。

常用命令：

```bash
npm run screen
python3 scripts/chain-screener.py --chain Flare --destination 1 \
  --from-token 0xe7cd86e13AC4309349F30B3435a9d337750fC82D \
  --to-token 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 \
  --amount 1000000
python3 scripts/chain-screener.py --all --workers 8 --cache-ttl 21600
```

筛选报告还会保存 API 来源、评分拆分、历史峰值日期、节点观察到的 chain ID/区块高度、跨链连接数量和错误。`work/chain-cache` 是 6 小时短缓存；报价不进入缓存，避免把流动性和 gas 估算当成长期事实。历史报告曾取得 Flare 的 USDT0 到 Ethereum USDC 报价，但这不证明桥接协议偿付能力，也不等于对任何代币或合约安全背书。

## DSH 安全作战台

启动本地中文可视化控制台：

```bash
bash start-web.sh
# 浏览器打开 http://127.0.0.1:8788
```

控制台直接读取筛选报告、专项 quote 报告和静态分析报告；`/api/status` 是统一状态快照，`/api/events` 提供 15 秒一次的 SSE 更新，`/api/ask` 默认返回结构化问答。只有请求显式设置 `useModel: true` 且 `DEFI_CLOUD_AI_*` 配置通过 HTTPS 与无凭据校验时，才会调用 OpenAI 兼容云端接口补充解释；返回内容附带模型名与请求/响应 SHA-256。结构化答案始终保留为权威内容。模型不能执行授权、签名、广播或修改报告。

DSH 与 DHLsh 共享 `work/dsh-sync.json`，完整快照保存在 `work/dsh-status.json`。文件包含活动链、任务队列、报告时间、云端审查配置摘要、quote 计数和只读 API 合约，两个入口应比对 `syncVersion`，并分别读取快照 `generatedAt` 与索引 `updatedAt`。快照与索引逐个原子替换，跨文件读取时若版本不一致需重读；共享文件不代表客户端已确认消费。命令行也可以直接询问：

```bash
npm run ask -- "当前正在分析什么？"
npm run ask -- "哪些链可以真实跨链？"
```

`npm run doctor` 会检查云端审查所需环境变量是否齐全、base URL 是否为无凭据的 HTTPS 地址；不发起网络请求，不读取或输出 API key，只显示安全的主机名与模型名。

页面把 `quote_verified`、`connection_only` 和 `unavailable` 分开显示；connection 只证明兼容性，真实报价仍是只读证据，未执行任何交易动作。

首屏作战地图只保留四个审计入口：地图、协议、发现、执行。每个页面底部都有“下一步”入口，移动端会自动改为纵向排列；运维页仍可从侧栏展开。页面只读，不会签名、授权或广播。

任务状态机保存在 `work/task-state.json`，服务启动时自动启用。`GET /api/tasks` 列出持久化任务，`POST /api/tasks` 创建任务；单任务支持读取、定向 claim、heartbeat、checkpoint、状态转换、暂停、恢复、失败和取消。每次 claim 都生成新的 `fencingToken`；heartbeat、checkpoint、失败和 worker-owned 状态转换必须携带当前 token，防止旧 worker 与新租约复用同一 `workerId` 时继续写入。通用状态转换不能绕过 claim 直接创建无 lease 的 active 任务。租约 45 秒无心跳后才允许恢复；写入采用临时文件原子替换，状态记录损坏或任务字典键与 `taskId` 不一致时拒绝读取。任务 payload 只作为 JSON 数据保存，服务不会执行 payload。

稳定任务 API 位于 `/api/v1/tasks`：集合 GET 支持 `state`、`limit` 和稳定 cursor 分页，POST 创建返回 `201`；单任务响应带 `consistency.revision`。operator 的 `transition`、`cancel`、`resume` 需要 `If-Match` 或 body `expectedRevision`；revision 冲突统一返回 HTTP 412。worker 操作仍依靠 fencing token。旧 `/api/tasks` 保持兼容。开发审查可用 `npm run review:manifest -- --base <git-revision> --model <模型名>` 生成脱敏、哈希绑定的 review manifest；该参数只记录审查模型元数据，不发起模型请求。`src/review-manifest.js` 校验云端结构化审查并以确定性规则阻断 P0/P1、失败必需测试、证据缺失和未解释依赖变更。该门禁目前是可调用库，尚未自动合并，也不把云端允许意见当作漏洞或安全结论。

v1 资源 API 还提供 `/api/v1/projects`、`contracts`、`collection`、`bytecode`、`decompile`、`analysis`、`scans`、`findings`、`evidence`、`replay`、`reports`、`workers`、`rules` 和 `invariants`。读取接口只返回已持久化的任务、快照或带 SHA-256 checkpoint 的证据；项目类 POST 只创建持久化任务，不伪造分析结果。资源列表统一使用 allowlist 查询参数、稳定 cursor 和 revision；worker lease 使用 fencing token，规则和不变量按版本保存。报告、artifact 和符号链接路径都会在读取前做根目录、普通文件、大小和哈希校验；缺失或部分结果保持显式状态。

提交结构化审查结果到 `POST /api/v1/reviews/evaluate`，请求包含 `manifest`、匹配其 `manifestSha256` 的 `review` 和可选 `checks`。API 返回确定性门禁结果，并向 `work/review-audit.jsonl` 追加不包含 diff、源码或模型意见文本的审计摘要。此端点不调用云端模型；云端审查仍由外部审查者执行，结果必须再经哈希校验和本地门禁。

真实 worker runner 在 `src/task-worker.js`。通过 `TaskWorker` 注册任务类型 handler，runner 负责有限并发、claim、运行态转换、定时 heartbeat、checkpoint、成功/partial/blocked/失败与有限重试；默认 handler 最长运行 30 分钟，可通过 `maxHandlerRuntimeMs` 配置（1 ms 至 24 小时）。到时会 abort handler；超时结果只会在 handler 实际退出后记录。仍在运行的 worker 会让忽略 abort 的 handler 继续持有 lease 和执行槽，避免同一任务并发重试。`stop({ wait: true })` 会中止 handler 并保留未完成 lease，让其他 worker 在过期后恢复。handler 只能通过 context 使用当前 token，事件回调失败不会中断任务执行。

本地源码分析任务由 `src/analysis-task-handler.js` 提供：入队时冻结已验证源码 bundle 和哈希，执行时只使用本地路径、离线编译器和无 shell 的固定 argv；静态/动态结果、stdout/stderr、checkpoint 和输入绑定会写入独立证据目录。任务状态只表示分析流程结果，不表示漏洞确认或合约安全结论。命令入口为：

```bash
node scripts/run-analysis-tasks.mjs enqueue --source /absolute/verified-bundle.json
node scripts/run-analysis-tasks.mjs drain --concurrency 2
```

## 离线语料控制台

链上采集在离线阶段不开放，语料工作由本地控制面承接。侧边栏第 15 项「离线语料控制台」对应后端 `src/corpus-control.js` 的五条离线泳道：

- `static` 静态分析（`scripts/review-static.py`）、`dynamic` 动态复现（`scripts/benchmark-dynamic-*.cjs`）、`decompiler` 反编译（`scripts/bytecode_analysis.py` + heimdall）、`fetch` 离线抓取校验（`work/corpus-fetch-cache`）、`eval` 本地评测（`scripts/eval_pipeline.py`）。
- 控制面只读本地语料目录、`benchmark/contracts` 与 `work/`，只允许调用白名单内的本地脚本；任务状态原子写入 `work/corpus-control/tasks.json`，整体证据见 `work/lane-W-report.json`。
- 暂停只在样本边界生效：暂停请求后当前样本跑完才挂起，正在运行的 compiler/forge/node 子进程不会被杀；停止才会终止进程组（先 SIGTERM，5 秒宽限后 SIGKILL）。
- 心跳超过 120 秒或进程 PID 已死的任务不再显示为「运行中」，恢复时标为「已中断」并落盘。界面上的语料统计来自本地已保存内容，不是实时任务。
- 链上采集启动按钮置灰只是提示，真正的拒绝在后端：`POST /api/v1/corpus/chain-collection/start`、`POST /api/v1/collection`、`POST /api/v1/tasks`（采集语义类型）一律返回 HTTP 400 与 `chain_collection_disabled`，不会创建任务。只有显式设置 `CORPUS_CHAIN_COLLECTION=1` 才放开。

```bash
curl http://127.0.0.1:8788/api/v1/corpus/overview
curl http://127.0.0.1:8788/api/v1/corpus/tasks
```

静态泳道只使用 `work/compiler-cache` 已缓存的 soljson，缺失即记为失败，不联网下载；评测泳道以 `--layers slither` 运行，输出是静态告警线索，不是漏洞确认。本地测试通过不等于确认漏洞，也不等于部署合约安全。

## Etherscan 地址交易历史

```bash
ETHERSCAN_API_KEY=your_key python3 scanner.py --address 0x完整40位地址 --page 1 --limit 100
```

这是指定地址的普通交易历史，不是全网新合约发现。按 `--page` 翻页；支持 `--chain-id`、`--startblock`、`--endblock`。Python 入口读取进程环境变量，不自动加载 `.env`。不再依赖 requests；密钥缺失、无效地址、API 业务错误、HTTP 错误均明确失败。

## 本地项目导入与原始归档

导入本地 Solidity/Vyper 项目时，使用只读入口生成可审计清单，并把纳入的原始文件写入内容寻址归档：

```bash
npm run import:project -- /absolute/project \
  --project-id protocol-main \
  --output work/protocol-main-import.json
```

导入会记录 Git 分支、提交（若存在）和工作区状态，以及每个文件的相对路径、类别、大小、编码和 SHA-256；原始文件引用可由清单中的 `archive` 通过 `scripts/data_provenance.py` 校验。默认跳过 `.git`、`node_modules`、构建/缓存目录和疑似凭据文件，并限制单文件、总字节数和文件数。不会执行项目构建、测试、安装脚本或依赖。退出码 `0` 表示没有跳过或归档错误，`2` 表示生成了部分清单并在 `errors`/`limits` 中记录原因，`1` 表示参数或输入目录错误。

`--output` 必须使用尚不存在的路径；不会覆盖源码或已有清单，重复导入请使用新的输出文件名。`--max-files` 限制检查的非忽略目录条目数，跳过的凭据、链接和特殊文件也消耗该预算；触顶后显式标记剩余条目未遍历。读取只接受普通文件，逐级拒绝符号链接，并按实际读取字节限制预算；每个原始归档在纳入前实际校验。`.env.*`（保留 `.env.example`）、`credentials.*`、`secrets.*` 等默认跳过。凭据过滤依据文件名，不能保证任意源码或示例文件不含敏感内容。默认输出写入输入项目的 `work/`；若要让输入目录完全无新增文件，请将 `--output` 和 `--archive-root` 都指定到项目目录外。

## Solidity 静态分析

```bash
bash flare-scan/scan.sh --list
bash flare-scan/scan.sh --target morpho-blue
bash flare-scan/scan.sh --target firelight-vault --timeout 180
python3 flare-scan/tools/collect.py
```

每个目标独立进程、超时控制；一个目标失败仍继续其他目标，并在最终 summary 标记 `complete=false`，退出 1。`--output-dir` 可指定报告目录；不传 `--target` 分析全部。所有编译与分析只针对本地源码，不下载或执行合约项目的安装脚本。

报告包含真实分析合约数量、100 个检测器、源码 SHA-256、编译器及配置、发现和错误。告警是线索，不等于已确认漏洞；不同入口导入相同代码时会有重复告警。自动分析成功也不证明合约安全。

### SmartBugs 与历史 Solidity 版本

历史 Solidity 源码不依赖 Foundry 当前安装的单一 `solc`。静态分析和字节码生成通过项目的 `solc-js` 适配器按需加载 `work/compiler-cache/` 中按版本保存的官方 `soljson`，下载时按 solc-bin 发布清单的 SHA-256 校验，并在后续使用时复核缓存文件。发布目录只在首次缺失或损坏时获取；每个版本有独立下载锁和原子缓存写入，损坏编译器会隔离后自动重取，便于多版本首次并行准备。分析证据记录编译器精确版本、构建标识、soljson SHA-256 与发布目录 SHA-256。当前缓存包含 Solidity `0.4.18+commit.9cf6e910`，因此 SmartBugs 固定 `0.4.18` 的样本可直接编译，无需改写源码或更换 Foundry。

版本选择遵循源码 pragma：基准样本若有明确 `solcVersion`，优先使用该固定版本并验证其满足 pragma；其他精确版本只用该版本，范围约束先取可用的最高兼容缓存版本，并保留最高官方兼容版本作回退；多个 pragma 取交集。没有 pragma 时才使用有界历史版本矩阵，结果会标为推断选择，不能当作源码原始编译器版本。所有尝试及退出码、stdout/stderr 哈希和诊断都进入 evidence；非零退出不能被分析器输出的 JSON 状态覆盖。

```bash
CAMPAIGN_SOLJSON="$PWD/work/compiler-cache/soljson-v0.4.18+commit.9cf6e910.cjs" \
  node scripts/campaign-solc.cjs --version
npm run training:analyze -- --workers 4
npm run training:artifacts -- --workers 4
```

大批量首次扫描前，可并行预热 manifest 中已经选择的精确编译器版本；也可传入版本列表。版本会去重，下载由缓存层按版本加锁并做哈希校验，某个版本失败会单独报告：

```bash
npm run solc:prefetch -- --manifest training-data/github-vulnerabilities/manifest.json --workers 8
npm run solc:prefetch -- --version 0.4.18,0.4.25,0.8.28 --workers 3
# 一次预热全部训练语料与 benchmark 的精确 pin；范围 pragma 只解析为每条样本的一个首选版本
npm run solc:prefetch -- --all-manifests --include-benchmarks --workers 8
```

`--version` 和 manifest 也接受带 `+commit...` 的完整版本号，预热时会归一化到对应的官方发布版本并保留完整构建号在分析证据中。

`--manifest` 可重复传入多个文件；`--all-manifests` 会扫描 `training-data/*/manifest.json`，并按同一套 pragma 选择器解析 `compilerPragmas`。`--include-benchmarks` 会加入 `benchmark/contracts/*/ground-truth.json` 的精确 `solcVersion`。预热只下载每条范围约束的首选版本，实际扫描仍保留自己的失败回退候选，避免一次性下载全部历史编译器。

正常扫描仍按需加载，预热只是减少大批任务中的首次下载等待；不会切换机器全局 `solc`，也不会改写历史源码。

Foundry 仍用于执行本地测试 harness；它不是历史 Solidity 编译器的分发或版本选择层。若某条 PoC 必须用旧版 Solidity 编译攻击合约，应通过 `solc-js` 先生成该版本的字节码，再由隔离 EVM 执行，并把源码与编译器哈希一并保存在证据中。动态 harness 不可用时保留 `not_run`，不以静态结果替代动态验证。

需要直接运行 Foundry 测试时，可用项目入口把同一份已校验的 `soljson` 暴露给 Forge：

```bash
mkdir -p work/smartbugs-14/src
cp benchmark/contracts/14-reentrance/reentrance.sol work/smartbugs-14/src/Reentrance.sol
npm run forge:solc -- --compiler-version 0.4.18 -- \
  build --root work/smartbugs-14 --offline
```

入口会拒绝命令中的第二个 `--use`，自动追加 `--offline`，并把版本、构建号、soljson SHA-256 和 solc-bin 清单 SHA-256 打到 stderr。这样 Foundry 不会从 SVM 下载或误选其它版本；每次调用固定一个编译器版本，切换到 `0.4.25` 等版本只需改变 `--compiler-version`，每个版本仍使用独立的缓存和校验锁。混合版本的工程应按 pragma/构建目标分组调用；需要跨编译器运行的 PoC 继续使用单独编译目标的本地 EVM runner。

桥接器按当前 Foundry profile 的 `src`、`test`、`script`、`libs` 配置和 `--contracts` 路径确定自动选版范围，不扫描仓库中无关目录。Foundry-only 输出兼容层会规范化 Solidity `0.4.10` 的字符串源码 ID，并在旧版缺少 `gasEstimates.creation.totalCost` 时从两项分量计算；未启用 Foundry 兼容模式时，solc-js 标准 JSON 输出不变。SmartBugs 有精确 `solcVersion` ground truth 的案例应传该版本（例如 `0.4.18`）；`auto` 对 `^0.4.18` 可能选择缓存中更高的兼容版本，适用于遵循 pragma 的构建，不适用于复现固定编译器基准。

如果不想手工判断版本，可使用 `--compiler-version auto`。它读取 `--root` 项目中 `src/`、`test/` 等目录的 Solidity pragma，求所有源码约束的交集，优先选择本地已校验缓存中的最高兼容版本，再从官方目录补齐缺失版本，并把选择原因写入 stderr。源码约束没有交集时会在运行 Forge 前失败；这比让 Foundry 自动挑一个版本更安全。一个项目若同时包含 `0.4.18` 源码和 `^0.8.19` 测试，应该拆成两个编译目标，旧源码的 PoC 使用下面的 solc-js 隔离 EVM runner。

```bash
npm run forge:solc -- --compiler-version auto -- \
  build --root work/smartbugs-14 --offline
```

由 `poc_generator.py` 从验证源码 bundle 生成的 PoC 会保存 bundle 中的精确 `compilerVersion`；`poc_runner.py` 用该版本调用同一桥接器，并在运行前检查 `src/` 与 `test/` 的 pragma。若目标源码是 `0.4.x`、模板测试要求 `>=0.8.19`，执行会明确返回 `compiler_version_conflict_use_solcjs_runner`，不会启动错误版本的 Foundry 编译。此类跨版本验证应使用按原始编译器编译源码、再在隔离 EVM 部署执行的 runner；SmartBugs benchmark 已按此路径运行。

流水线的 `poc` 阶段也执行同一检查：带精确旧版本的 bundle 会通过 `forge-with-solc.py` 运行，旧源码与现代测试模板混用时直接保存冲突原因并保持 `unconfirmed`，不会把编译失败当成漏洞证据。

编译适配器支持 standard-json、combined-json、remappings、优化器、EVM 与 viaIR，保留 AST、字节码和 source map。未知参数或编译失败明确报错。它是本地分析用适配器，不是完整的原生 solc 替代品；请勿对不可信源码目录当作隔离沙箱使用。

Slither 0.11.4 的同名库结构体解析兼容代码在 `flare-scan/tools/slither_compat.py`，按 AST referencedDeclaration 和源码位置绑定，未修改合约源码或 AST。测试验证了两个同名库、同名结构体但不同字段的解析结果。其他 Slither 版本不启用此补丁。

本地调用效果图会把 inline Yul 的 `sstore` / `tstore` 与 `call` / `delegatecall` / `callcode` / `staticcall` 记作带源码位置的候选效果；slot、目标、值或可行性没有被证明。未识别的 Yul builtin 和无法解码的旧式 assembly block 会记为 unresolved 并将图标为 `partial`，避免把缺失路径误报成完整覆盖。

## 动态分析与字节码分析

动态执行使用本地隔离 Hardhat EVM（chain ID 31337）；已有 Foundry fuzz/invariant 回归与专用合约测试。采集流水线目前自动支持 EngineChip 的资金守恒、权限、暂停、回滚和回调场景，VaultV2 的 ERC-4626 记账/舍入/授权/回滚与多种子状态序列，以及取得验证依赖源码后的 AMTDepositPool / AMTRewardPool 集成场景。测试使用本地部署和模拟配置；没有连接链上 fork、重放线上交易或验证所有部署状态。其它合约明确标记未运行专用动态测试，不将源码审查计作动态分析。

动态 harness 默认明确拒绝外部 RPC 和 fork。需要固定区块 fork 时，必须同时设置 `DYNAMIC_EXECUTION_MODE=fixed_block_fork`、`DYNAMIC_FORK_RPC_URL` 和 `DYNAMIC_FORK_BLOCK_NUMBER`；运行前后会只读两次指定区块并核对哈希，报告只保存 RPC 的 SHA-256，不保存 URL。配置缺失、区块不稳定或边界校验失败会记录为 `unavailable`，不会把失败提升为漏洞确认，也不会签名或广播交易。

VaultV2 的变异验证可检查本地测试是否能发现份额记账、赎回授权和舍入方向错误。先对 VaultV2 运行静态分析，再把其 `static-work/local-test-input.json` 作为输入；输出目录须不存在：

```bash
npm run validate:vault-detector -- \
  --input work/<run>/<contract>/static-work/local-test-input.json \
  --output work/vault-detector-controls-<run-id>
```

此检查以最多两路并发运行未修改基线和六份彼此隔离的故障注入副本，包括份额记账、赎回授权、舍入、接收者错付、错付调用者与捐赠利率上限绕过；不连接 RPC、不发送外部交易。基线包含付款人/份额持有人/调用者/接收者分离、授权撤销恢复、默认零 maxRate 捐赠核算与依赖失败恢复。通过只证明这些特定变异能被当前夹具检出，不等同于确认线上漏洞或证明未发现其他缺陷。

## 四层漏洞发现与加速

流水线使用共享的 8 路总并发预算：默认最多 4 个目标、每目标最多 2 个独立阶段并行；可用 `PIPELINE_TARGET_CONCURRENCY` / `--target-concurrency 1..8` 和 `PIPELINE_STAGE_CONCURRENCY` / `--stage-concurrency 1..4` 调整。实际阶段并发会按目标并发自动收缩，保证两者乘积不超过 8。完整流程中 recon/collect 可并行；collect 后表示、反编译和部署准备可并行，静态分析等待表示缓存完成；dynamic、review、PoC、report 按证据依赖等待。Foundry invariant harness 默认 2 线程，可用 `PIPELINE_FORGE_THREADS` 或 `--forge-threads 1..8` 调整，并按 CPU 自动收缩。失败只阻断依赖它的后续阶段；指定非零预算时阶段串行执行，防止并行超支。

```bash
python3 scripts/pipeline.py run --targets targets.json \
  --stages recon,collect,repr,static,deploy,dynamic,decompile,review,poc,report \
  --target-concurrency 4 --stage-concurrency 2 --forge-threads 2 --output work/pipeline-run
```

并发硬上限为 8 路，超过上限会直接拒绝，避免同时抢占 Forge、CPU、内存和 RPC 配额。反向断言 fixture 可用真实 Forge 闸门验证：`bash scripts/verify-reverse-fixtures.sh --output work/reverse-fixtures-report.json`。评测使用 `npm run eval -- --layers all`；没有真实层证据的样本会标为 `unavailable`，不会被统计成“零发现”。

每次流水线运行的 `run.json` 还会保存 `performance`：总墙钟时间、用户/系统 CPU 时间、进程峰值 RSS、阶段累计墙钟时间和阶段 worker 利用率；每个目标的 `state.json` 会保存对应阶段的 `pipelineWallMs`。这些指标只用于定位瓶颈，不参与漏洞状态或证据哈希判断。

1. **静态线索与业务性质**：每个源码分析 bundle 自动生成 `discovery-plan.json` 和可交互 `discovery-plan.html`，从调用效果和入口提示生成带源码位置、现有 modifiers、独立 oracle 的验证计划。函数名只用于选择待验证假设，不判断漏洞或权限缺失。
2. **动态状态序列**：VaultV2 夹具用独立账本、整数舍入参考模型和多个角色逐步验证业务性质，记录真实动作与相邻转换；测试只有全部断言通过才列出 `propertyIds`，失败记录 `targetPropertyIds` 供定位，不把该场景所有性质都判为失败。
3. **证据与可视化**：计划将源代码/编译设置、输入图、动态夹具指纹与性质结果关联。夹具通过、单条候选路径验证、图截断及未验证性质分别显示；位置重合不算路径或分支覆盖。已有报告也可通过 `npm run plan:discovery -- --report <static-analysis.json> --graph <call-graph.json> --dynamic <local-tests.json> --output <新目录>` 生成视图。
4. **执行与资源调度**：`FLARE_ANALYSIS_PARALLEL=auto` 根据 CPU/内存和机器 overlap 锁决定是否并行静态/动态阶段；`off` 串行、`on` 尝试并行。异常也等待子任务结束再释放 slot。持久 TaskWorker 提供有限并发、分页调度、防重入、心跳、取消和 token fencing。

显式本地任务入口已经接通固定的 `review-static.py`、项目导入、确定性字节码分析和固定 Heimdall 反编译，只接受 allowlist 输入；不从 payload 执行任意脚本。入队冻结输入与 SHA-256，每次尝试使用独立目录；超时或停止会终止本次自建进程组，恢复时重新校验输入。默认任务状态保存在 `work/task-state.json`，与 Web 使用同一持久化任务字典。`drain` 默认一路、最多两路；它消费当前可领任务后退出，不是后台常驻采集任务。未接入的合约映射与链上采集任务保持 queued/blocked，并在 `pending` 或任务历史中明确显示。

```bash
npm run tasks:analysis -- enqueue --source /absolute/verified-source.json
npm run tasks:analysis -- drain --concurrency 2 --timeout-ms 120000
```

`partial` 明确表示覆盖不完整，动态未运行/不可用、调用图截断或验证计划缺失不能视为完整成功；`succeeded` 也只指本次本地阶段完成，不代表合约安全。只有本地编译器可用时才执行，不由这个入口自动下载工具。输入的验证记录仍是已有来源证据，未重新证明线上部署等价。

提速必须在同一输入与工具代码上复验静态语义、调用图、动态轨迹、源码采样和关联证据一致性，同时记录耗时与进程组 RSS。有限样本的加速与变异检出不能外推到所有协议；当前图仍可能 partial，部署状态、跨合约配置和完整路径可行性仍需专用验证。

Firelight Vault 另有成熟提款活性回归：有效请求必须能在成熟后领取，金额须精确到达请求人且 pending 负债归零。变异验证把源码复制到临时隔离项目中，确认恒 revert 和错付两类错误均会使定向测试与 invariant 失败；临时 Solidity 副本在运行后删除，持久输出只包含报告和日志：

```bash
npm run validate:firelight-claim -- --output work/firelight-claim-mutation-<run-id>
```

每份已核验运行时代码都会产生 `runtime-bytecode-analysis.json`，即使源码提供方不可用也保留字节码分析。它包含原始字节码、SHA-256、区块锚点、opcode、选择器候选、调用/存储位置和代理槽常量。PUSH 参数单独解码；可能的元数据仅作标记，不丢弃原始字节。链和区块决定 opcode 是否已启用，嵌入数据可能看起来像指令，选择器/基本块只是待核验线索。

```bash
npm run analyze:bytecode -- path/to/verified-source.json --output work/runtime-analysis.json
# 或输入只包含 0x 运行时代码的文本文件；不要传创建字节码。
```

需要高层伪码时，可选择本机 Heimdall 适配器；输出目录必须是新目录：

```bash
npm run analyze:bytecode -- path/to/verified-source.json \
  --decompiler heimdall \
  --decompiler-output-dir work/decompilation-<run-id> \
  --decompiler-timeout 120 \
  --output work/runtime-analysis.json
```

适配器不访问 RPC、不启用 LLM 后处理；JSON 会保存输入 bytecode SHA-256、实际工具版本、运行时二进制 SHA-256、退出状态、日志及每个产物的 SHA-256。执行前后工具哈希不一致、产物清单溢出、产物不可读或没有可识别伪码时不会报告完整成功；`artifactInventoryComplete` 和 `artifactOverflowCount` 必须一并检查。`completed` 仅表示命令成功生成 `.sol`/`.yul` 文件；伪码可能不完整或不可编译，变量名和业务语义均属推断，`sourceVerified` 始终为 false。当前 Heimdall 下载自官方 0.9.3 release asset，二进制自报版本为 0.9.2；此差异和 asset 哈希记录在 `toolchain.lock.json`。静态反汇编/反编译不自动确认线上漏洞。

campaign 可显式为每个已采集运行时代码运行本地 Heimdall；每份结果保存在对应合约证据目录，超时或工具错误只将反编译标为不完整，不抹去已完成的反汇编。默认关闭以保留采集预算；每份合约受超时限制，最大并发仍由 campaign worker 上限约束：

```bash
npm run research:hour -- --decompiler heimdall --decompiler-timeout 30 --decompiler-hardfork cancun
```

`decompilationState` 及工具产物哈希会出现在 `runtime-bytecode-analysis.json` 和合约证据中。动态夹具会绑定源代码、harness 和 source-map 支持文件哈希；缺失或不匹配时证据为 `unavailable`。trace 响应字段不完整、部分 trace 无效或 effects 超过报告上限时，关联状态分别为 `not_performed` 或 `partial`，并保留 `traceEvidence` 计数，不将截断结果当作完整覆盖。`latest` 是 CLI 默认 hardfork 提示；应按目标链和区块选择实际 EVM 语义版本。

Heimdall 的版本检查会向 GitHub 查询 release/commit 信息，因此启用反编译的 campaign 不能保证完全离线，隔离网络可能导致检查失败。报告会保存命令结果、日志与产物哈希；这不表示已禁用远端访问。参见 [Heimdall version checker](https://raw.githubusercontent.com/Jon-Becker/heimdall-rs/main/crates/common/src/utils/version.rs)。

字节码 CLI 可额外写出统一 IR：

```bash
python3 scripts/bytecode_analysis.py path/to/verified-source.json \
  --ir-output work/unified-ir-<run-id>.json
```

IR 使用稳定的实体 ID 连接合约、selector、基本块、指令、存储/外部调用候选、静态路径和证据。源码调用图会在每个静态分析 bundle 中生成 `unified-ir.json`，采集的运行时代码会生成 `unified-ir-bytecode.json`。所有候选操作保留 `semanticsProven=false`；静态路径的 `pathFeasibility` 仍为 `not_proven`，动态轨迹与源码位置的重合不会自动升级为漏洞确认。

`flare-scan/contracts/sceptre` 当前是 Python/CloudFormation 工程，没有 Solidity 源码，清单明确标记 `no_solidity_sources`，不将其计为已完成的链上协议审计。

## 本机依赖与恢复

第三方源码、缓存和工具依赖没有纳入根 Git；复制/备份整个目录时需保留这些资源。环境可用性由 `npm run doctor` 实际探测。

需要重装工具时（需要网络）：

```bash
python3 -m pip install --target flare-scan/tools/pylibs slither-analyzer==0.11.4
npm install --prefix flare-scan/tools/solc-0819 --ignore-scripts --save-exact solc@0.8.19
npm install --prefix flare-scan/tools/solc-0823 --ignore-scripts --save-exact solc@0.8.23
npm install --prefix flare-scan/tools/solc-0828 --ignore-scripts --save-exact solc@0.8.28
```

Firelight 仍需要自身已有的 node_modules 依赖。当前系统 Python 使用 LibreSSL，Slither 导入 urllib3 时可能给出 TLS 警告；本地静态分析不使用它访问网络。

`safe-deploy.sh` 明确返回“部署未配置”和非零退出码；项目没有经过验证的部署流程。`flare-test/TestContracts.sol` 是历史空占位合约，不是有效测试。`flare-test/test-zkbridge.js` 仅用于配置了合约地址的本机 fork 只读 balanceOf 检查。

## 接口依据

- https://ethereum.org/developers/docs/apis/json-rpc/
- https://docs.etherscan.io/api-reference/endpoint/txlist
- https://docs.soliditylang.org/en/latest/using-the-compiler.html


## 风险链路与本地回归

网页展示 Firelight 三条本地分析路径：事故评估到资金出账、Merkle allocation 到保费扣款、预言机/FLB 到容量承诺。每条关联源码位置、权限与状态门槛、Slither 线索、测试命令和结果。新增批量回滚、撤销授权恢复后守恒、重放不得重复扣款/铸造的三个场景。全部使用本地 fixture/mock，没有资产操作。

```bash
npm test
npm run test:security
# 仅快速跑前两组 Hardhat；报告仍明确全套未完成
npm run test:security -- --quick
```

完整安全回归要求三组 Hardhat 和 Foundry 全部通过，否则退出非零。报告 `work/security-test-report.json` 包含测试前后源码 SHA-256；指纹覆盖 contracts、test、Hardhat/Foundry 配置和依赖锁。源码改变会使网页上的旧结果过期。

项目本地 Foundry 为 `work/tools/forge`，版本 v1.8.5（Darwin arm64）；下载归档 SHA-256 为 `56049728e25e44a61c7f2e49438023b0890cb45850ffcb7c882f90cd998baf83`。Hardhat 三组测试有重叠，不应相加宣称独立覆盖数量。未做部署字节码比对或主网 fork 全路径验证。

## 浏览器与连续三小时验收

```bash
npm run web
# 在另一个终端运行；保持终端与服务运行
npm run test:ui
npm run test:soak
# 短测使用独立输出，不能代替三小时验收
npm run test:soak -- --duration-ms 60000 --interval-ms 15000 --output work/soak-short.json
```

UI 验收使用 Playwright 与本机 Google Chrome。可用 `PLAYWRIGHT_MODULE` 指定 Playwright 模块路径；未安装时可使用 Codex 已配置的本地运行库。`UI_OUTPUT_DIR` 指定截图/报告目录。页面超时或断言失败仍会关闭测试浏览器。

soak 每 30 秒检查 HTTP、状态与同步版本、服务实例、运行源码指纹，并持续读取 SSE；问答探针只请求结构化状态，不调用云端模型。报告包含单调时钟时长、墙上时钟漂移、采样间隔、SSE 最大间隔和失败明细。`work/soak.lock` 阻止重复运行；旧报告自动保留为 `.previous.json`。中断只会记为 interrupted，失败不会被改为通过。

三小时验收要求 `state=completed`、`durationMs>=10800000`、`failures=0`，且结构化问答/SSE/源码检查启用。服务重启、源码变更、超过允许间隔的采样或 SSE 中断、时钟异常、结构化问答回退均使验收失败。服务 PID 存活或 health 单点正常不等于验收完成。保持电脑唤醒；权限提示需由用户在 macOS 系统设置处理。

### 高速稳定性诊断

高速诊断用于快速暴露并发、快照一致性、SSE 和结构化问答回退问题，不把墙上时间压缩成三小时，也不替代三小时验收：

```bash
npm run test:high-speed -- --duration-ms 180000 --concurrency 8 --interval-ms 250 --model-every-ms 10000 --output work/high-speed-stability.json
```

诊断器每轮有明确间隔并限制并发；记录每个 API 的请求量和 HTTP 状态、p50/p95/p99/最大延迟、真实模型调用与回退、DSH/DHLsh 同步版本一致性、SSE 帧与最大间隔、服务实例/源码指纹连续性，以及负载前后 RSS/heap。`SIGINT`/`SIGTERM` 会优雅落盘并标为 `interrupted`。无节流的洪峰负载必须单独标记为无效负载配置，不能作为稳定性通过证据。

`AGENTS.md` 供 DSH/DHLsh 读取本项目最新状态。`npm run ask` 优先查询实时 API；服务不可用时只读本地报告并标为离线，不覆盖同步文件。此测试范围是本机服务与模型 API，并不等于已测试 DSH 桌面 UI 的全部流程。

## 一小时合约采集与多 RPC

初筛口径：协议在目标链的 TVL ≥ 10,000 美元。不以跨链总 TVL 替代，不表示单个合约持有此金额。

运行 `npm run rpc:refresh` 验证节点，再运行 `npm run research:hour` 开始一小时采集。使用 `npm run ask -- "一小时合约采集分析情况？"` 或 `npm run ask -- "RPC 备用节点情况？"` 查看真实状态。

RPC 来自公开目录与官方文档，验证链 ID、最新区块时间、区块高度及多节点共同区块。按负载轮换、故障切换，403/429 按主机冷却；使用中每五分钟重验。单节点与无可用节点明确区分。不同主机名不保证不同运营商。

`work/rpc-pool.json` 保存节点验证；`work/defi-campaign.json` 保存当前状态。独立 `work/defi-campaign/<runId>/` 保存 TVL 快照、固定版本官方 adapter、地址出处、固定区块代码、Sourcify 源码、模型原文与行号核对、静态分析和事件日志。下载的 adapter 仅解析，不执行。

采集 checkpoint 会同时写入 `heartbeatAt`、递增的 `heartbeatSeq` 和 45 秒 TTL 的 `lease`，并在对应运行目录保存 `lease.json`。控制台只有在心跳未过期且 PID 仍存活时才显示活动任务；旧报告没有 lease 时兼容使用 `updatedAt`，过期或已退出的进程会标为 `stale`，不会被称为仍在运行。

三个采集 worker、一个模型审查 worker，外部请求限速。现有模型配置不变、无自动回退。源码审查可能仅覆盖明确记录的摘录；Slither 必须真实完成才计数。新增合约本地复现独立计数，不用旧 Firelight 回归充数。

旧三小时报告已取消并保留。completed 仅表示采集窗口结束，不代表所有对象已审计、漏洞已确认或 DSH 桌面端到端验收通过。改分析器后应保存旧窗口并新开运行，不拼接不同版本的统计。

## 静态／动态并行基准

使用同一份已验证源码、固定输入和随机交错的轮次，比较串行、强制并行与自动策略。输入必须有已审查的目标动态夹具；动态测试失败或未执行时，基准会记为失败。

```bash
npm run benchmark:static -- --source /absolute/verified-source.json --output work/benchmark-new --rounds 2
```

可选 `--dependency`、`--timeout 120`、`--seed 72531` 和 `--modes serial parallel auto`。串行与并行模式必须同时包含。输出目录须为新目录。每轮保留标准输出、错误日志、指标、完整调用图及本地测试证据；总报告记录执行顺序、稳定结果比较、提速和进程组 RSS。

`auto` 要求至少 4 个逻辑 CPU 和估算可用内存不少于 4 GiB；同一项目的静态／动态重叠锁繁忙时会串行回退。强制并行会跳过 CPU／内存门槛，但仍遵守互斥锁。RSS 是进程组周期采样值，不是硬件或统一内存峰值。单一源码的基准只说明该样本和当前机器，不能证明其他负载更快或分析结果安全。
