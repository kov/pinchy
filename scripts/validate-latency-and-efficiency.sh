#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

LATENCY_TEST="${LATENCY_TEST:-latency_open_printed_before_exit}"
BENCH_COMMAND="${BENCH_COMMAND:-find /home/kov/.local}"
EVENTS="${EVENTS:-}"
RUNS="${RUNS:-3}"
THROUGHPUT_RUNS="${THROUGHPUT_RUNS:-1}"
BASELINE_FILE="${BASELINE_FILE:-}"
METRICS_OUT="${METRICS_OUT:-/tmp/pinchy-latency-efficiency-current.txt}"

extract_metric() {
    local label="$1"
    local text="$2"

    echo "$text" \
        | awk -F: -v key="$label" '$1 == key { gsub(/ /, "", $2); print $2; exit }'
}

baseline_value() {
    local key="$1"

    if [[ -z "$BASELINE_FILE" || ! -f "$BASELINE_FILE" ]]; then
        return 1
    fi

    grep -E "^${key}=" "$BASELINE_FILE" | head -n 1 | cut -d= -f2-
}

is_uint() {
    local value="$1"
    [[ "$value" =~ ^[0-9]+$ ]]
}

require_uint() {
    local label="$1"
    local value="$2"

    if ! is_uint "$value"; then
        echo "Invalid numeric value for $label: $value"
        exit 1
    fi
}

echo "Running latency integration test ($LATENCY_TEST)..."
cargo test --test integration -- "$LATENCY_TEST"

echo
echo "Running command efficiency benchmark..."
bench_output="$(
    RUNS="$RUNS" \
    THROUGHPUT_RUNS="$THROUGHPUT_RUNS" \
    EVENTS="$EVENTS" \
    BENCH_COMMAND="$BENCH_COMMAND" \
    ./scripts/measure-command-efficiency.sh
)"

echo "$bench_output"

events_per_second="$(extract_metric "events/sec" "$bench_output")"
latency_p95_ms="$(extract_metric "latency p95 (ms)" "$bench_output")"
dispatch_send_fail="$(extract_metric "dispatch send fail" "$bench_output")"
dispatch_send_queue_full="$(extract_metric "dispatch send queue full" "$bench_output")"
ebpf_reserve_fail="$(extract_metric "eBPF reserve fail" "$bench_output")"

cat >"$METRICS_OUT" <<EOF
events_per_second=$events_per_second
latency_p95_ms=$latency_p95_ms
dispatch_send_fail=$dispatch_send_fail
dispatch_send_queue_full=$dispatch_send_queue_full
ebpf_reserve_fail=$ebpf_reserve_fail
EOF

echo
echo "Current metrics written to: $METRICS_OUT"

if [[ -z "$BASELINE_FILE" ]]; then
    echo "No baseline file provided, skipping regression checks."
    exit 0
fi

if [[ ! -f "$BASELINE_FILE" ]]; then
    echo "Baseline file does not exist: $BASELINE_FILE"
    exit 1
fi

baseline_events_per_second="$(baseline_value "events_per_second" || true)"
baseline_dispatch_send_fail="$(baseline_value "dispatch_send_fail" || true)"
baseline_dispatch_send_queue_full="$(baseline_value "dispatch_send_queue_full" || true)"
baseline_ebpf_reserve_fail="$(baseline_value "ebpf_reserve_fail" || true)"

if [[ -z "$baseline_events_per_second" ]]; then
    echo "Missing events_per_second in baseline file: $BASELINE_FILE"
    exit 1
fi

allowed_min_eps="$(
    awk -v baseline="$baseline_events_per_second" \
        'BEGIN { printf "%.6f", baseline * 0.95 }'
)"

eps_ok="$(
    awk -v current="$events_per_second" -v minimum="$allowed_min_eps" \
        'BEGIN { print (current + 0 >= minimum + 0) ? "1" : "0" }'
)"

if [[ "$eps_ok" != "1" ]]; then
    echo "Throughput regression too high:"
    echo "  baseline events/sec: $baseline_events_per_second"
    echo "  current  events/sec: $events_per_second"
    echo "  minimum allowed:     $allowed_min_eps (95% of baseline)"
    exit 1
fi

if [[ -n "$baseline_dispatch_send_fail" ]]; then
    require_uint "baseline dispatch_send_fail" "$baseline_dispatch_send_fail"
    require_uint "current dispatch_send_fail" "$dispatch_send_fail"

    if [[ "$dispatch_send_fail" -gt "$baseline_dispatch_send_fail" ]]; then
        echo "dispatch send fail regressed:"
        echo "  baseline: $baseline_dispatch_send_fail"
        echo "  current:  $dispatch_send_fail"
        exit 1
    fi
fi

if [[ -n "$baseline_dispatch_send_queue_full" ]]; then
    require_uint \
        "baseline dispatch_send_queue_full" \
        "$baseline_dispatch_send_queue_full"
    require_uint "current dispatch_send_queue_full" "$dispatch_send_queue_full"

    if [[ "$dispatch_send_queue_full" -gt "$baseline_dispatch_send_queue_full" ]]; then
        echo "dispatch send queue full regressed:"
        echo "  baseline: $baseline_dispatch_send_queue_full"
        echo "  current:  $dispatch_send_queue_full"
        exit 1
    fi
fi

if [[ -n "$baseline_ebpf_reserve_fail" ]]; then
    require_uint "baseline ebpf_reserve_fail" "$baseline_ebpf_reserve_fail"
    require_uint "current ebpf_reserve_fail" "$ebpf_reserve_fail"

    if [[ "$ebpf_reserve_fail" -gt "$baseline_ebpf_reserve_fail" ]]; then
        echo "eBPF reserve fail regressed:"
        echo "  baseline: $baseline_ebpf_reserve_fail"
        echo "  current:  $ebpf_reserve_fail"
        exit 1
    fi
fi

echo "Regression checks passed against baseline: $BASELINE_FILE"
