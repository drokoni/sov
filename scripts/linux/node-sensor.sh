#!/usr/bin/env bash
set -e
source "$(dirname "$0")/env.sh"

echo "[+] Starting Node Sensor (Linux)..."
echo "[!] Requires sudo for /var/log/* access"
exec sudo -E "$BIN/sov-sensor-node" -c "$CFG/node-sensor.yaml"
