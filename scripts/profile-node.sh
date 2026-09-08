#!/bin/bash
set -e
PID="${1:?usage: sudo ./scripts/profile-node.sh <pid> [seconds]}"
DURATION="${2:-10}"
OUT="$(pwd)/testbed/profile-${PID}.json"
.venv/bin/py-spy record -p "$PID" -d "$DURATION" -f speedscope -o "$OUT"
echo "wrote $OUT"
