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
| P1-6 | 分层评测 | DONE | 2026-10-21 | 30 个样本；`--layers all` 输出四层指标 | IR/不变量/PoC 无增量价值时显式记录 `no_incremental_value_detected` |
| P1-7 | 部署适配器 | DONE | 2026-10-21 | 3 项专测通过 | 参数缺失和 forge 原文错误显式保留 |
| P1-8 | Web 审计界面 | DONE | 2026-10-21 | `npm run test:ui` passed；无错误请求 | 四视图、三态、移动端 |
| P2-1 | harness 真实断言生成 | DONE | 2026-10-21 | harness 专测与 `forge build` 通过 | smoke test 已删除；缺渲染器不进 forge |
| P2-2 | PoC 真实生成与执行 | DONE | 2026-10-21 | 9 项 PoC/runner 专测；真实 forge PASS 才 confirmed | 本地模板、cloud 通道、失败分类与 3 次尝试 |
| P2-3 | pipeline 部署阶段 | DONE | 2026-10-21 | 20 项 pipeline 专测通过 | deploy 阶段记录 deployedTarget/adapterRequiredCount |
| P3-1 | 真实合约离线重放 | DONE | 2026-10-21 | `e2e_real_run.py` 使用已有 campaign verified-source；输出 `network=offline_replay` | 无网络时重跑本地分析，保留 partial/unavailable，不用 fixture 冒充真实合约 |
| P3-2 | 报告四章升级 | DONE | 2026-10-21 | 报告专测通过；Markdown/HTML/SARIF 含四章与 `codeFlows` | 不变量、源码可信度、PoC、覆盖缺口独立保留状态 |
| P3-3 | Web 样式与交互打磨 | DONE | 2026-10-21 | `npm run test:ui` passed；390/768/1440 视口 | 语义色、三态、移动端和键盘焦点 |
| P4 | 全量验收 | DONE | 2026-10-21 | Node 331、Python 501、security 4/4、UI passed | `forge` 使用仓库绑定 `work/tools/forge`；`git diff --check` 通过 |

## 阶段二收尾增强

- 流水线目标级有界并行：默认 4 路，可通过 `PIPELINE_TARGET_CONCURRENCY` 或 `--target-concurrency 1..32` 调整；单目标阶段保持顺序，聚合结果保持输入顺序。
- 快速测试入口支持多个关键词并行执行，`TEST_MAX_PARALLEL` 限制进程并发，失败状态正确汇总且无匹配时显式提示。
- 四个审计视图增加“下一步”导航，移动端自动纵向排列；未改变 `/api/v1/*` 语义和只读边界。
- 收尾验证：`npm run test:parallel`、pipeline 专测、`npm run test:security`、`npm run test:ui`、语法检查与 `git diff --check` 均通过。

## 后续闭环执行记录

- 反向 fixture 真实闸门已补齐：`bash scripts/verify-reverse-fixtures.sh` 验证 7 个 fixture，correct 全部通过、violating 全部断言失败，且两变体 assertion SHA-256 一致；缺 Forge 时 fail-closed。
- 分层评测已修正：IR 对账、不变量和 PoC 缺少证据时记录 `unavailableSampleCount` 与原因，不再当作零发现参与 precision/recall；`npm run eval -- --layers all` 当前 30/30 Slither 样本可评分，其余三层 30/30 明确 unavailable。
- 并发资源上限统一为 8 路；默认仍为 4 路，`TEST_MAX_PARALLEL` 与 `PIPELINE_TARGET_CONCURRENCY` 超过 8 会拒绝。
- 真实合约离线 E2E 已执行 3 个已保存 verified-source 目标：`work/e2e/run-20261021-v5/summary.json`。三者均完成 collect、repr、static、report；recon、deploy、dynamic、decompile、review、poc 按缺失证据或配置显式记录 unavailable。该产物不是 fixed-block RPC 全链通过证明。
- 仍待外部条件：提供安全的 fixed-block RPC 与部署参数后，重跑 3 个目标的 recon/deploy/dynamic；配置云审查后再启用 review；为 benchmark 增加 clean 样本后再评估误报率。
