#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' '部署未配置：项目没有部署目标、构造参数或网络验证流程。本命令未发送交易。' >&2
exit 1
