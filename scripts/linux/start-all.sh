#!/usr/bin/env bash
set -e

echo "[+] Starting full SOV stack (test mode)"

./analyzer.sh &
sleep 2

./node-sensor.sh &
sleep 1

./net-sensor.sh &

wait
