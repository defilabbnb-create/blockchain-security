#!/usr/bin/env bash
set -euo pipefail
SOURCE="${BASH_SOURCE[0]}"
while [[ -h "$SOURCE" ]]; do
  DIR="$(cd -P -- "$(dirname -- "$SOURCE")" >/dev/null 2>&1 && pwd)"
  TARGET="$(readlink -- "$SOURCE")"
  if [[ "$TARGET" = /* ]]; then SOURCE="$TARGET"; else SOURCE="$DIR/$TARGET"; fi
done
TOOLS="$(cd -P -- "$(dirname -- "$SOURCE")" >/dev/null 2>&1 && pwd)"
exec node "$TOOLS/solc-wrapper.js" "$@"
