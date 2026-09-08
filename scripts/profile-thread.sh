#!/bin/bash
set -e
PID="${1:?usage: sudo ./scripts/profile-thread.sh <pid> [seconds] [rate]}"
DURATION="${2:-10}"
RATE="${3:-1000}"
OUT="$(pwd)/testbed/profile-${PID}-${RATE}hz.json"
.venv/bin/py-spy record -p "$PID" -d "$DURATION" -r "$RATE" -f speedscope -o "$OUT"
echo "wrote $OUT"
