#!/usr/bin/env bash
set -e
source "$(dirname "$0")/env.sh"

echo "[+] Starting Analyzer..."
exec "$BIN/sov-analyzer" -c "$CFG/analyzer.yaml"
