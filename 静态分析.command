#!/usr/bin/env bash
set -uo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
bash "$ROOT/flare-scan/scan.sh" "$@"
result=$?
printf '\n分析退出码：%s，报告位于 flare-scan/reports/\n' "$result"
if [[ -t 0 ]]; then read -r -p '按回车关闭窗口…' _; fi
exit "$result"
