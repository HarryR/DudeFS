#!/bin/bash
set -e
PID="${1:?usage: sudo ./scripts/thread-dump.sh <pid>}"
.venv/bin/py-spy dump -p "$PID"
