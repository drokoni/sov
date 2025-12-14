#!/usr/bin/env bash
set -e

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

export RUST_LOG=info

echo "[+] Starting SOV Node Sensor (Linux)"
echo "[!] Requires sudo for log access"

exec sudo "$ROOT_DIR/target/release/sov-sensor-node" \
    -c "$ROOT_DIR/config/node-sensor.yaml"
