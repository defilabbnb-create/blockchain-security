#!/usr/bin/env bash
# 波内只跑受影响测试。用法: bash scripts/fast-test.sh <关键词...>
set -euo pipefail
cd "$(dirname "$0")/.."
KEYWORD="${1:-}"
if [[ -n "$KEYWORD" ]]; then
  if [[ "$KEYWORD" == "invariant_assertions" ]]; then
    python_files=(tests/test_assertions_*.py)
    node_files=(tests/assertions*.test.js)
  else
    python_files=(tests/test_${KEYWORD}.py)
    node_files=(tests/${KEYWORD}.test.js)
  fi
else
  python_files=(tests/test_*.py)
  node_files=(tests/*.test.js)
fi

python_started=0
node_started=0
if [[ -e "${python_files[0]}" ]]; then
  if [[ "$KEYWORD" == "invariant_assertions" ]]; then
    python3 -m unittest tests.test_assertions_erc4626 tests.test_assertions_lending tests.test_assertions_amm tests.test_assertions_cross -v &
  else
    python3 -m unittest discover -s tests -p "test_${KEYWORD:-*}.py" -v &
  fi
  python_started=1
fi
if [[ -e "${node_files[0]}" ]]; then
  node --test --test-concurrency=8 "${node_files[@]}" &
  node_started=1
fi
if (( python_started == 0 && node_started == 0 )); then
  echo "No tests matched keyword: ${KEYWORD:-<all>}"
  exit 0
fi
wait
