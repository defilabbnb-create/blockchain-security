# 静态分析评测集

`contracts/` 中 20 个单文件样本取自 SmartBugs Curated，仓库快照固定为 commit `230e649123477eff332742a59a1c7cc6dc286cab`。各样本的 `ground-truth.json` 保留上游记录的漏洞类别、脆弱行号和来源链接；`clean` 均为 `false`，因为本批只包含上游标注的脆弱样本，未把未审查源码标成干净。

评测目标是单合约源码上的 Slither detector 类别覆盖情况。Slither 检测结果是静态信号，类别匹配用于基准统计，不构成漏洞确认。未能编译或运行分析的样本单独记为 unscored，不按无发现计分。当前评测不调用云端 AI，`costUsd` 只表示模型调用成本为零，不包含本机计算成本。
