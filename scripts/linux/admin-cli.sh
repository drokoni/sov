#!/usr/bin/env bash
set -e

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

exec "$ROOT_DIR/target/release/sov-admin-cli" \
    -c "$ROOT_DIR/config/admin-cli.yaml" \
    "$@"
