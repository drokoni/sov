#!/usr/bin/env bash
set -e
source "$(dirname "$0")/env.sh"

exec "$BIN/sov-admin-cli" -c "$CFG/admin-cli.yaml" "$@"
