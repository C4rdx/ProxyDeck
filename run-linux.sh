#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"

python3 core.py --ui &
server_pid=$!
trap 'kill "$server_pid" 2>/dev/null || true' INT TERM EXIT

sleep 1
if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "http://127.0.0.1:8765" >/dev/null 2>&1 &
fi

wait "$server_pid"
