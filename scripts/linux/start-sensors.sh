#!/usr/bin/env bash
set -e
source "$(dirname "$0")/env.sh"

echo "[+] Starting sensors (node + net) in background..."

sudo -E "$BIN/sov-sensor-node" -c "$CFG/node-sensor.yaml" &
NODE_PID=$!

sudo -E "$BIN/sov-sensor-net" -c "$CFG/net-sensor.yaml" &
NET_PID=$!

echo "[+] Node PID=$NODE_PID"
echo "[+] Net  PID=$NET_PID"
echo "[i] Press Ctrl+C to stop"

trap 'echo "[!] Stopping..."; sudo kill $NODE_PID $NET_PID 2>/dev/null || true; exit 0' INT TERM

wait
