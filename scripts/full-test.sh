#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
node --test --test-concurrency=8 tests/*.test.js &
python3 -m unittest discover -s tests -p 'test_*.py' &
wait
