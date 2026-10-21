#!/usr/bin/env bash
# Execute every correct/violating assertion fixture with the real Forge binary.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 scripts/verify_reverse_fixtures.py "$@"
