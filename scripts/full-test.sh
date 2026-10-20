#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
TEST_MAX_PARALLEL="${TEST_MAX_PARALLEL:-2}" bash scripts/fast-test.sh
