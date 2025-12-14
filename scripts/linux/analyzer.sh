#!/usr/bin/env bash
set -e

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

export RUST_LOG=info

echo "[+] Starting SOV Analyzer"
echo "[+] Root: $ROOT_DIR"

exec "$ROOT_DIR/target/release/sov-analyzer" \
    -c "$ROOT_DIR/config/analyzer.yaml"
