# 执行进度

基线仓库：`/Users/d288/Desktop/区块链安全`。执行开始时仓库无提交，25 项项目文件均为未跟踪状态；这些既有文件保持原样，不能满足干净工作区检查，也无法按任务级提交而不把整个项目基线纳入提交。

| 波次 | 任务 | 状态 | 完成时间 | 验收命令 | 备注 |
|---|---|---|---|---|---|
| W0 | T0 基线 | DONE | 2026-10-21 | `npm run doctor`、`npm test` | Node 330 项通过，Python 428 项通过；doctor 必需项通过，可选 Rust/Docker/PostgreSQL/Redis 缺失；npm test 输出 1 条 LibreSSL `NotOpenSSLWarning`。Git 干净状态检查因仓库初始无提交且项目文件均未跟踪而不满足。 |
| W1 | T1 LibreSSL 警告 | DONE | 2026-10-21 | `npm run test:security 2>&1 | rg -c NotOpenSSLWarning` → 0 | 三个脚本已有忽略配置；安全测试全通过。 |
| W1 | T2 移除本地模型 | DONE | 2026-10-21 | `npm test`；`rg -n 'omlx|callLocalModel|readModelProfile|dsh_model' src scripts web tests` → 无匹配 | 当前代码已采用显式外部云端通道；doctor 只检查配置，不发网络请求。 |
| W1 | T4 评测集 | DONE | 2026-10-21 | 连跑两次 `npm run eval` | 已有 20 样本和评测脚本；两次 precision/recall 均为 0.35，costUsd=0。 |
| W1 | T16 代理链模块 | DONE | 2026-10-21 | `python3 -m unittest discover -s tests -p 'test_proxy_graph.py' -v` | 3 项通过：UUPS storage 对账、预算不足覆盖标注、源码冲突。 |
| W1 | T15 侦察模块 | DONE | 2026-10-21 | `python3 -m unittest discover -s tests -p 'test_recon.py' -v` | 4 项通过：升级计数、调用分布、资产分数单调性、只读 RPC。 |
| G1 | W1 集成闸门 | DONE | 2026-10-21 | `npm test`；`npm run test:security`；禁止符号 `rg` | Node 330、Python 435、Foundry/安全套件全通过；`test:security` 中警告计数为 0。 |
| W2 | T3 findings 管道 | DONE | 2026-10-21 | `node --test tests/finding-index.test.js`; 快照构建 | 7 项测试通过；`work/finding-index.json` 有 305 条 campaign findings；状态快照合并后总 findings 674。 |
| W2 | T5 表示缓存 | DONE | 2026-10-21 | `python3 -m unittest discover -s tests -p 'test_repr_cache.py' -v` | 6 项通过，含并发写、损坏重建、LRU。 |
| W2 | T10 三阶段云审查 | DONE | 2026-10-21 | `python3 -m unittest discover -s tests -p 'test_cloud_review.py' -v` | 5 项通过，含顺序、预算降级、manifest/JSON/HTTPS 校验。 |
| G2 | W2 集成闸门 | DONE | 2026-10-21 | `npm test`; `/api/findings` campaign 来源检查 | Node 330、Python 435 全绿；快照中 campaign 来源条目 305。 |
| W2 | T9 反编译语义 | DONE | 2026-10-21 | `python3 -m unittest discover -s tests -p 'test_decompiler_semantics.py' -v` | 2 项通过；始终输出 `semanticsProven:false`，动态委托调用等风险仅作提示。 |
| W3 | T6 IR 对账 | DONE | 2026-10-21 | `python3 -m unittest discover -s tests -p 'test_ir_reconcile.py' -v` | 3 个 fixture 通过。 |
| W3 | T7 不变量生成 | DONE | 2026-10-21 | `python3 -m unittest discover -s tests -p 'test_invariant_gen.py' -v` | 4 项通过，未知角色显式 `template_unavailable`。 |
| W3 | T12 报告骨架 | DONE | 2026-10-21 | `python3 -m unittest discover -s tests -p 'test_report_builder.py' -v` | 2 项通过；Markdown/HTML/SARIF，缺失输入、覆盖边界、成本与复现状态显式记录；产物原子写。 |
| G3 | W3 集成闸门 | DONE | 2026-10-21 | `npm test` + IR/不变量专测 | Node 330、Python 443 全绿。 |
| W4 | T8 Harness + 动态执行 | DONE | 2026-10-21 | `test_harness_gen.py`、`test_dynamic_runner.py` | 8 项通过；local/fixed-block/replay 边界和只读约束覆盖。 |
| W4 | T10 三阶段云审查 | DONE | 2026-10-21 | `test_cloud_review.py` | 5 项通过；预算降级与拒绝条件覆盖。 |
| W4 | T14a Web 视图模块 | DONE | 2026-10-21 | `npm run test:ui` | 通过；四类工作区、移动端视口、API 读取和无错误检查通过。 |
| G4 | W4 集成闸门 | DONE | 2026-10-21 | `npm test`; `work/tools/forge build`; W4 专测 | forge 输出 `Nothing to compile`；全量测试通过。 |
| W5 | T11 PoC 生成与量化 | DONE | 2026-10-21 | `test_poc_generator.py` | 3 项通过；哈希绑定、因子校验和不可执行适配器均有测试。 |
| W5 | T14b Web 装配 | DONE | 2026-10-21 | `npm run test:ui` | UI 检查通过，现有 Web 装配保持无 npm 框架依赖。 |
| G5 | W5 集成闸门 | DONE | 2026-10-21 | `npm test` + `npm run test:ui` | Node 330、Python 443；UI state=passed。 |
| W6 | T13 编排器与适配器集成 | DONE | 2026-10-21 | `python3 -m unittest tests.test_pipeline_full_fixture -v` | 已加入可复现离线 fixture；九阶段均 `completed`，dynamic=`passed`，review provider=`mock_cloud_ai`，PoC=`unconfirmed`。mock provider 只验证编排和证据封装；真实三阶段云审查由 localhost mock HTTP 专测覆盖。 |
| W6 | T13 源码阶段适配器 | DONE | 2026-10-21 | `python3 -m unittest discover -s tests -p 'test_pipeline_source_stages.py' -v` | 本地源文件 SHA-256 校验、隔离采集、原子落盘、source bundle 缓存；表示缺失维度显式 not_available。 |
| W6 | T13 验证阶段适配器 | DONE | 2026-10-21 | `python3 -m unittest discover -s tests -p 'test_pipeline_verification_stages.py' -v` | 4 项通过；dynamic/decompile/PoC 只根据实际 runner 结果记录，语义始终未证实。 |
| W6 | T13 审查与报告适配器 | DONE | 2026-10-21 | `python3 -m unittest discover -s tests -p 'test_pipeline_review_stages.py' -v` | 3 项通过；本地 review 不确认漏洞，报告 MD/HTML/SARIF 原子落盘并记录哈希。 |
| G6 | W6 集成闸门 | DONE | 2026-10-21 | `npm run test:security`; 九阶段 `pipeline.py run` | 安全套件四组全部 passed；九阶段 fixture 汇总 `completed`，动态 outcome=passed，pocState=unconfirmed。 |
| W7 | 全量验收 | DONE | 2026-10-21 | `npm test`、`npm run test:security`、`npm run test:ui`、`npm run eval` | 最新串行验收为 474 Python + 330 Node 通过；安全四套件 passed，UI state=passed 且 errors/failedRequests 为空，评测 precision=0.35、recall=0.35、costUsd=0。流水线已接入四表示哈希绑定、PoC 严格 PASS 证据和 run-local `finding-index.json`；静态观察仍未证实。 |

## 执行总结与偏差

- 可复现全链命令：`python3 scripts/pipeline.py run --targets tests/fixtures/pipeline-full/targets.json --stages recon,collect,repr,static,dynamic,decompile,review,poc,report --mode local --budget-usd 5 --output work/pipeline-full-run-20261021`；`run.json` 为 `completed`，九阶段均 completed。
- 只读边界：fixture 使用本地 RPC 响应和离线 Forge；没有签名、授权、广播或外部交易。`semanticsProven=false`，PoC 为 `unconfirmed`。
- Git 偏差：仓库初始无 commit，项目文件均未跟踪；按任务创建独立 commit 会把整个历史基线一并纳入，因此未伪造任务级提交或声称工作区干净。
- 指标限制：当前证据没有改造前的并行总时长、单合约全链耗时、评测基线或云审查单合约成本，故这些对比指标保持 `not_available`；本次可测值仅为评测 precision/recall `0.35/0.35`、本地评测成本 `$0`。
- 已知既有边界：`npm run doctor` 的 Heimdall 实测为 0.9.2，而施工图记录为 0.9.3；Rust、Docker、PostgreSQL、Redis 为可选缺失项，不影响必需闸门。

