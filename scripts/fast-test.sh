#!/usr/bin/env bash
# 波内只跑受影响测试。用法: bash scripts/fast-test.sh <关键词...>
# 多个关键词会并行执行；TEST_MAX_PARALLEL 控制同时运行的测试进程数。
set -euo pipefail
cd "$(dirname "$0")/.."
MAX_PARALLEL="${TEST_MAX_PARALLEL:-4}"
if ! [[ "$MAX_PARALLEL" =~ ^[1-9][0-9]*$ ]] || (( MAX_PARALLEL > 32 )); then
  echo "TEST_MAX_PARALLEL must be an integer from 1 to 32" >&2
  exit 2
fi

declare -a commands=()
declare -a labels=()
add_command() {
  commands+=("$1")
  labels+=("$2")
}

if (( $# == 0 )); then
  add_command "python3 -m unittest discover -s tests -p 'test_*.py' -v" "python:all"
  add_command "node --test --test-concurrency=8 tests/*.test.js" "node:all"
else
  for keyword in "$@"; do
    if ! [[ "$keyword" =~ ^[A-Za-z0-9_.-]+$ ]]; then
      echo "Invalid test keyword: $keyword" >&2
      exit 2
    fi
    if [[ "$keyword" == "invariant_assertions" ]]; then
      python_matches=(tests/test_assertions_*.py)
      node_matches=(tests/assertions*.test.js)
      if [[ -e "${python_matches[0]}" ]]; then
        add_command "python3 -m unittest tests.test_assertions_erc4626 tests.test_assertions_lending tests.test_assertions_amm tests.test_assertions_cross -v" "python:$keyword"
      fi
    else
      python_matches=(tests/test_${keyword}.py)
      node_matches=(tests/${keyword}.test.js)
      if [[ -e "${python_matches[0]}" ]]; then
        add_command "python3 -m unittest discover -s tests -p 'test_${keyword}.py' -v" "python:$keyword"
      fi
    fi
    if [[ -e "${node_matches[0]}" ]]; then
      add_command "node --test --test-concurrency=8 ${node_matches[*]}" "node:$keyword"
    fi
  done
fi

if (( ${#commands[@]} == 0 )); then
  echo "No tests matched keywords: ${*:-<all>}"
  exit 0
fi

overall_status=0
batch_start=0
while (( batch_start < ${#commands[@]} )); do
  pids=()
  batch_end=$((batch_start + MAX_PARALLEL))
  if (( batch_end > ${#commands[@]} )); then batch_end=${#commands[@]}; fi
  for (( index=batch_start; index<batch_end; index++ )); do
    echo "[parallel] start ${labels[$index]}"
    bash -lc "${commands[$index]}" &
    pids+=("$!")
  done
  for (( index=0; index<${#pids[@]}; index++ )); do
    if wait "${pids[$index]}"; then
      echo "[parallel] pass ${labels[$((batch_start + index))]}"
    else
      echo "[parallel] fail ${labels[$((batch_start + index))]}" >&2
      overall_status=1
    fi
  done
  batch_start=$batch_end
done
exit "$overall_status"
