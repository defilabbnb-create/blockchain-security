#!/usr/bin/env bash
# 波内只跑受影响测试。用法: bash scripts/fast-test.sh <关键词...>
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m unittest discover -s tests -p "test_${1:-*}.py" -v &
NODE_PATTERN="${1:-*}"
node --test --test-concurrency=8 tests/${NODE_PATTERN}.test.js &
wait
