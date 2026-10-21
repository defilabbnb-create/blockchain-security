# 静态分析评测集

`contracts/` 中包含 30 个源绑定样本：前 20 个单文件样本取自 SmartBugs Curated，后 10 个为阶段二新增的 ERC4626、借贷、AMM、预言机和跨合约样本。各样本的 `ground-truth.json` 保留漏洞类别和来源链接；`clean` 均为 `false`，因为本批只包含标注的脆弱样本，未把未审查源码标成干净。

评测目标是单合约源码上的 Slither detector 类别覆盖情况。Slither 检测结果是静态信号，类别匹配用于基准统计，不构成漏洞确认。未能编译或运行分析的样本单独记为 unscored，不按无发现计分。当前评测不调用云端 AI，`costUsd` 只表示模型调用成本为零，不包含本机计算成本。

使用 `--layers all` 时，只有分析器明确返回某层的观察列表，该层样本才进入该层的 precision/recall。缺少 IR 对账、不变量或 PoC 证据会记录为 `unavailableSampleCount` 和原因，不会被当成“该层没有发现”。显式返回空列表才表示该层确实测得零项。
