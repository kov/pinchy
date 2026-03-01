#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$SCRIPT_DIR/migrate-ebpf-inplace.rs"
BIN="/tmp/migrate-ebpf-inplace"

rustc "$SRC" -O -o "$BIN"
exec "$BIN" "$@"
