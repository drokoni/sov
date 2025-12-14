#!/usr/bin/env bash
set -e
source "$(dirname "$0")/env.sh"

exec "$BIN/sov-operator-cli" -c "$CFG/operator-cli.yaml" "$@"
