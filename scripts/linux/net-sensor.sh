#!/usr/bin/env bash
set -e
source "$(dirname "$0")/env.sh"

echo "[+] Starting Net Sensor (Linux)..."
echo "[!] Requires sudo for pcap access"
exec sudo -E "$BIN/sov-sensor-net" -c "$CFG/net-sensor.yaml"
