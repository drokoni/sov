#!/usr/bin/env bash
set -e

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export SOV_ROOT="$ROOT"
export RUST_LOG="${RUST_LOG:-info}"

BIN="$SOV_ROOT/bin"
CFG="$SOV_ROOT/config"

mkdir -p "$SOV_ROOT/logs"

echo "[i] SOV_ROOT=$SOV_ROOT"
echo "[i] RUST_LOG=$RUST_LOG"
