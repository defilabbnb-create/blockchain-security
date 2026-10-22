# 区块链安全：项目状态与证据

适用于本项目的 DSH、DHLsh 和其他助手；回答使用中文。

项目名称是“区块链安全”，根目录是 `/Users/d288/Desktop/区块链安全`。DSH 指本机 DeepSeek Harness 模型工具，不能当作项目名称；Web 是本项目的可视化界面。

- 用户问当前进度、链筛选、跨链、风险链路、测试或同步时，先执行 `npm run ask -- "用户的问题"`。不要凭旧聊天或本文件给出动态数字。
- Web 默认启动于 `http://127.0.0.1:8788`；`/api/health` 查看健康、实例与快照更新时间，`/api/status` 查看完整状态，`/api/sync` 查看同步索引。读取失败时明确报告失败，不把缓存说成实时。可用 `PORT` 覆盖监听端口。
- 离线证据是 `work/dsh-status.json` 和 `work/dsh-sync.json`；读取两份时检查 `syncVersion` 相同，同时引用 `generatedAt` 与 `lastReportAt`。不一致时重读，仍不一致则说明尚未同步。
- 共享文件不证明 DSH/DHLsh 客户端已消费；未经对话验收，不声称两个客户端端到端通过。
- 优先队列不代表扫描进程正在运行。当前 TVL 是报告时刻的代理指标，历史峰值只是热度线索。
- `connection_only` 只表示兼容性，`quote_verified` 只表示采集时取得报价；引用报价时间与代币最小单位，当前可转移性需要重新报价。
- Slither 是线索；本地测试通过不代表确认漏洞、部署合约安全或实际可利用。检查源码指纹、套件状态与覆盖范围。
- `work/security-test-report.json` 是本地回归证据；`npm run test:security` 运行 Hardhat 和 Foundry，可能耗时数分钟。
- `work/soak-3h.json` 是稳定性证据。只有 completed、durationMs ≥ 10800000、failures = 0、连续采样/SSE、同一服务实例、源码指纹一致、真实模型调用无回退才可称三小时观察通过。
- 三小时运行期间先检查 `work/soak.lock` 和 PID，禁止重复启动或修改被测源码/重启服务。变更后必须新运行；保留失败和中断报告。
- 不执行资产授权、签名、广播；不修改模型配置，也不干扰其他项目的稳定性测试。

## 当前采集任务（优先于历史三小时约定）

- 用户已取消三小时报告，改为一小时持续采集分析；不得重启旧 soak。
- 优先读取 `/api/campaign`、`/api/rpc-pool` 或 `npm run ask -- "一小时合约采集分析情况？"`。
- 金额口径为协议在目标链 TVL ≥ $10,000 初筛，不代表单合约余额。
- 采集、模型源码审查、Slither、本地复现分别计数；接口请求量不代表分析量。
- 当前任务以 `work/defi-campaign.json` 及独立原始证据目录为准；心跳新鲜且 PID 存活才能称仍在运行。
- 模型源码审查可能仅覆盖明确记录的摘录；completed 仅表示采集窗口结束，不能当作完整审计通过。

## 离线语料控制面（LaneW）

- 离线语料任务由 `src/corpus-control.js` 管理，五条泳道：static / dynamic / decompiler / fetch / eval；接口前缀 `/api/v1/corpus`，前端为侧边栏「离线语料控制台」。状态持久化在 `work/corpus-control/tasks.json`（原子写入），证据报告为 `work/lane-W-report.json`。
- 链上采集在离线阶段一律后端拒绝（`chain_collection_disabled`）；`POST /api/v1/corpus/chain-collection/start`、`POST /api/v1/collection`、`POST /api/v1/tasks`（采集语义类型）都返回 HTTP 400。放开只能由用户显式设置 `CORPUS_CHAIN_COLLECTION=1`。
- 暂停只在样本边界生效（`pauseSemantics=sample_boundary`），当前样本跑完才挂起；只有停止才会终止子进程（先进程组 SIGTERM，5 秒后 SIGKILL）。
- 心跳阈值 120 秒；心跳过期或 PID 已死的任务不显示为 running，恢复时标为 interrupted。语料统计来自本地已保存内容，不是实时任务。
- 静态泳道只用 `work/compiler-cache` 已缓存的 soljson，缺失记 `failed` 且不联网下载；评测泳道以 `--layers slither` 运行，输出是静态告警线索，不是漏洞确认。
- 四泳道目前只做过单样本级验证，未跑完整批次；引用计数时必须说明这一点。
