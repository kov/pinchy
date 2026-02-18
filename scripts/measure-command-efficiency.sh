#!/usr/bin/env bash
set -euo pipefail

RUNS="${RUNS:-15}"
THROUGHPUT_RUNS="${THROUGHPUT_RUNS:-3}"
EVENTS="${EVENTS:-}"
FIND_PATH="${FIND_PATH:-$HOME/.local}"
BENCH_COMMAND="${BENCH_COMMAND:-find \"$FIND_PATH\"}"
CLIENT_QUEUE_CAPACITY="${CLIENT_QUEUE_CAPACITY:-512}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if ! command -v awk >/dev/null 2>&1; then
    echo "awk is required"
    exit 1
fi

if ! command -v base64 >/dev/null 2>&1; then
    echo "base64 is required"
    exit 1
fi

echo "Building release binaries with efficiency metrics..."
cargo build -p pinchy --release --features efficiency-metrics --bin pinchyd --bin pinchy --bin test-helper

arch="$(uname -m)"
case "$arch" in
    x86_64|amd64)
        arch="x86_64"
        ;;
    aarch64|arm64)
        arch="aarch64"
        ;;
    *)
        echo "Unsupported host arch for UML benchmark: $arch"
        exit 1
        ;;
esac

uml_kernel="$ROOT_DIR/uml-kernel/cache/linux-$arch"
uml_init="$ROOT_DIR/uml-kernel/uml-test-runner.sh"
bindir="$ROOT_DIR/target/release"

if [[ ! -x "$uml_kernel" ]]; then
    echo "UML kernel not found at $uml_kernel"
    echo "Build it first with: ./uml-kernel/build-kernel.sh $arch"
    exit 1
fi

if [[ ! -x "$uml_init" ]]; then
    echo "UML init script not executable: $uml_init"
    exit 1
fi

tmp_dir="$(mktemp -d /tmp/pinchy-eff-cmd-XXXXXX)"
keep_tmp="${KEEP_TMP:-1}"

if [[ "$keep_tmp" != "1" ]]; then
    trap 'rm -rf "$tmp_dir"' EXIT
fi

echo "Running command benchmark inside UML..."
bench_command_b64="$(printf '%s' "$BENCH_COMMAND" | base64 | tr -d '\n')"

"$uml_kernel" \
    mem=64M \
    root=/dev/root \
    rootfstype=hostfs \
    hostfs=/ \
    "init=$uml_init" \
    con0=fd:1,fd:1 \
    con=null \
    "PINCHY_TEST_EVENTS=$EVENTS" \
    "PINCHY_FIND_PATH=$FIND_PATH" \
    "PINCHY_BENCH_COMMAND_B64=$bench_command_b64" \
    "PINCHY_TEST_OUTDIR=$tmp_dir" \
    "PINCHY_TEST_BINDIR=$bindir" \
    "PINCHY_TEST_PROJDIR=$ROOT_DIR" \
    "PINCHY_TEST_MODE=benchmark_command" \
    "PINCHY_TEST_NAME=efficiency_command_benchmark" \
    "PINCHY_BENCH_LOOPS=$THROUGHPUT_RUNS" \
    "PINCHY_BENCH_RUNS=$RUNS" \
    "PINCHY_CLIENT_QUEUE_CAPACITY=$CLIENT_QUEUE_CAPACITY" \
    >"$tmp_dir/uml-console.log" 2>&1

if [[ ! -f "$tmp_dir/done" ]]; then
    echo "UML benchmark did not complete successfully."
    echo "Console log: $tmp_dir/uml-console.log"
    exit 1
fi

stats_log="$tmp_dir/pinchyd-throughput.out"
latency_file="$tmp_dir/latency-ms.txt"
throughput_file="$tmp_dir/throughput-ms.txt"

if [[ ! -f "$stats_log" ]]; then
    echo "Missing throughput stats log: $stats_log"
    exit 1
fi

if [[ ! -f "$throughput_file" ]]; then
    echo "Missing throughput file: $throughput_file"
    exit 1
fi

if [[ ! -f "$latency_file" ]]; then
    echo "Missing latency file: $latency_file"
    exit 1
fi

throughput_ms="$(cat "$throughput_file" | tr -d '\n')"

if ! grep -q '^EFF userspace' "$stats_log"; then
    echo "No efficiency stats were emitted. Ensure pinchyd ran long enough."
    echo "Raw log: $stats_log"
    exit 1
fi

last_stats_line="$(grep '^EFF userspace' "$stats_log" | tail -n 1)"

extract_value() {
    local key="$1"
    echo "$last_stats_line" | sed -n "s/.*$key=\([0-9]\+\).*/\1/p"
}

ebpf_submitted="$(extract_value ebpf_submitted)"
ebpf_bytes="$(extract_value ebpf_bytes)"
ebpf_reserve_fail="$(extract_value ebpf_reserve_fail)"
dispatch_send_fail="$(extract_value send_fail)"
dispatch_send_queue_full="$(extract_value send_queue_full)"

if [[ -z "${ebpf_submitted:-}" || -z "${ebpf_bytes:-}" ]]; then
    echo "Failed to parse eBPF counters from: $last_stats_line"
    exit 1
fi

throughput_seconds="$(awk -v ms="$throughput_ms" 'BEGIN { printf "%.6f", ms / 1000.0 }')"
events_per_second="$(awk -v ev="$ebpf_submitted" -v sec="$throughput_seconds" 'BEGIN { if (sec > 0) printf "%.2f", ev / sec; else print "0.00" }')"
bytes_per_event="$(awk -v bytes="$ebpf_bytes" -v ev="$ebpf_submitted" 'BEGIN { if (ev > 0) printf "%.2f", bytes / ev; else print "0.00" }')"
micros_per_event="$(awk -v ms="$throughput_ms" -v ev="$ebpf_submitted" 'BEGIN { if (ev > 0) printf "%.2f", (ms * 1000.0) / ev; else print "0.00" }')"

lat_count="$(wc -l <"$latency_file")"
lat_min="$(sort -n "$latency_file" | head -n 1)"
lat_p50="$(sort -n "$latency_file" | awk -v n="$lat_count" 'NR == int((n + 1) / 2) { print; exit }')"
lat_p95_idx="$(awk -v n="$lat_count" 'BEGIN { idx = int((n * 95 + 99) / 100); if (idx < 1) idx = 1; print idx }')"
lat_p95="$(sort -n "$latency_file" | awk -v idx="$lat_p95_idx" 'NR == idx { print; exit }')"

echo
echo "=== Pinchy Command Efficiency Measurement ==="
echo "events filter: $EVENTS"
echo "command: $BENCH_COMMAND"
echo "default find path: $FIND_PATH"
echo "throughput runs: $THROUGHPUT_RUNS"
echo "latency runs: $RUNS"
echo "client queue capacity: $CLIENT_QUEUE_CAPACITY"
echo
echo "throughput wall time (ms): $throughput_ms"
echo "throughput wall time (s):  $throughput_seconds"
echo "eBPF submitted events:     $ebpf_submitted"
echo "eBPF submitted bytes:      $ebpf_bytes"
echo "events/sec:               $events_per_second"
echo "bytes/event:              $bytes_per_event"
echo "avg us/event:             $micros_per_event"
echo
echo "latency min (ms):         $lat_min"
echo "latency p50 (ms):         $lat_p50"
echo "latency p95 (ms):         $lat_p95"
echo
echo "dispatch send fail:        ${dispatch_send_fail:-0}"
echo "dispatch send queue full:  ${dispatch_send_queue_full:-0}"
echo "eBPF reserve fail:         ${ebpf_reserve_fail:-0}"
echo
echo "Last stats line:"
echo "$last_stats_line"
echo
echo "Full stats log: $stats_log"
echo "UML console log: $tmp_dir/uml-console.log"
