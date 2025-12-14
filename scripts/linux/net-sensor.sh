#!/usr/bin/env bash
set -e

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

export RUST_LOG=info

echo "[+] Starting SOV Network Sensor"
echo "[!] Requires sudo for pcap access"

exec sudo "$ROOT_DIR/target/release/sov-sensor-net" \
    -c "$ROOT_DIR/config/net-sensor.yaml"
