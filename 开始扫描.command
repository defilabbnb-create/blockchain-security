#!/usr/bin/env bash
set -uo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$ROOT/reports"
bash "$ROOT/scan.sh" --output "$ROOT/reports/latest-chain-scan.json" "$@"
result=$?
printf '\n扫描退出码：%s（0 完整，1 失败，2 部分结果）\n' "$result"
if [[ -t 0 ]]; then read -r -p '按回车关闭窗口…' _; fi
exit "$result"
