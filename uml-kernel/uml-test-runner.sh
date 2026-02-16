#!/bin/sh
# Init script for UML test instances.
# Receives test parameters via kernel command line (/proc/cmdline).
# Runs as PID 1 inside UML; actual test workload runs under setsid.
#
# The root filesystem (hostfs) is read-only by default. We mount a
# tmpfs on /tmp and a separate writable hostfs for the output
# directory. The hostfs mount syntax depends on the mount tool:
# fd-based-mount capable mount uses -o "hostfs=/path", while legacy
# mount(2) needs -o "/path" (without the hostfs= prefix).

set -e

# Mount proc first so we can parse kernel command line parameters
mount -t proc proc /proc

# Parse kernel command line parameters.
for param in $(cat /proc/cmdline); do
    case "$param" in
        PINCHY_TEST_EVENTS=*)
            PINCHY_TEST_EVENTS="${param#PINCHY_TEST_EVENTS=}"
            ;;
        PINCHY_TEST_WORKLOAD=*)
            PINCHY_TEST_WORKLOAD="${param#PINCHY_TEST_WORKLOAD=}"
            ;;
        PINCHY_TEST_OUTDIR=*)
            PINCHY_TEST_OUTDIR="${param#PINCHY_TEST_OUTDIR=}"
            ;;
        PINCHY_TEST_BINDIR=*)
            PINCHY_TEST_BINDIR="${param#PINCHY_TEST_BINDIR=}"
            ;;
        PINCHY_TEST_PROJDIR=*)
            PINCHY_TEST_PROJDIR="${param#PINCHY_TEST_PROJDIR=}"
            ;;
        PINCHY_TEST_MODE=*)
            PINCHY_TEST_MODE="${param#PINCHY_TEST_MODE=}"
            ;;
        PINCHY_TEST_NAME=*)
            PINCHY_TEST_NAME="${param#PINCHY_TEST_NAME=}"
            ;;
        PINCHY_BENCH_LOOPS=*)
            PINCHY_BENCH_LOOPS="${param#PINCHY_BENCH_LOOPS=}"
            ;;
        PINCHY_BENCH_RUNS=*)
            PINCHY_BENCH_RUNS="${param#PINCHY_BENCH_RUNS=}"
            ;;
        PINCHY_CLIENT_QUEUE_CAPACITY=*)
            PINCHY_CLIENT_QUEUE_CAPACITY="${param#PINCHY_CLIENT_QUEUE_CAPACITY=}"
            ;;
    esac
done

# Remaining system mounts
mount -t sysfs sysfs /sys
mount -t tmpfs tmpfs /dev
mknod /dev/null c 1 3
mount -t tmpfs tmpfs /run

# Mount a tmpfs on /tmp and a separate writable hostfs for the output
# directory. Legacy mount(2) passes -o data as a raw path to hostfs's
# parse_monolithic handler, so "hostfs=/path" becomes "/hostfs=/path"
# which fails. Detect which syntax the mount tool needs.
mount -t tmpfs tmpfs /tmp
mkdir -p /tmp/outdir

if mount --version 2>&1 | grep -q "fd-based-mount"; then
    mount -t hostfs none /tmp/outdir -o "hostfs=$PINCHY_TEST_OUTDIR"
else
    mount -t hostfs none /tmp/outdir -o "$PINCHY_TEST_OUTDIR"
fi

OUTDIR="/tmp/outdir"

# Validate hostfs mount succeeded
if ! mountpoint -q "$OUTDIR"; then
    echo "FATAL: hostfs mount on $OUTDIR failed" >"$PINCHY_TEST_OUTDIR/pinchy.stderr" 2>/dev/null || true
    echo "FATAL: hostfs mount on $OUTDIR failed" >&2
    poweroff -f
fi

mount -t bpf bpf /sys/fs/bpf
mount -t tracefs tracefs /sys/kernel/tracing
ip link set lo up

if [ -n "$PINCHY_TEST_NAME" ]; then
    echo "=== UML test: $PINCHY_TEST_NAME (mode=$PINCHY_TEST_MODE) ==="
fi

PINCHYD="$PINCHY_TEST_BINDIR/pinchyd"
PINCHY="$PINCHY_TEST_BINDIR/pinchy"
TEST_HELPER="$PINCHY_TEST_BINDIR/test-helper"
PINCHY_CLIENT_QUEUE_CAPACITY="${PINCHY_CLIENT_QUEUE_CAPACITY:-128}"

# Start system D-Bus daemon with pinchy policy installed.
# We copy the policy to a tmpfs-backed directory so tests work without
# requiring the policy to be installed system-wide on the host.
mkdir -p /run/dbus /run/dbus-policy
cp "$PINCHY_TEST_PROJDIR/org.pinchy.Service.conf" /run/dbus-policy/
cat > /run/dbus-system.conf << 'DBUS_EOF'
<!DOCTYPE busconfig PUBLIC
  "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
  "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>system</type>
  <fork/>
  <listen>unix:path=/run/dbus/system_bus_socket</listen>
  <auth>EXTERNAL</auth>
  <pidfile>/run/dbus/pid</pidfile>

  <policy context="default">
    <allow user="*"/>
    <deny own="*"/>
    <deny send_type="method_call"/>
    <allow send_type="signal"/>
    <allow send_requested_reply="true" send_type="method_return"/>
    <allow send_requested_reply="true" send_type="error"/>
    <allow receive_type="method_call"/>
    <allow receive_type="method_return"/>
    <allow receive_type="error"/>
    <allow receive_type="signal"/>
    <allow send_destination="org.freedesktop.DBus"
           send_interface="org.freedesktop.DBus"/>
    <allow send_destination="org.freedesktop.DBus"
           send_interface="org.freedesktop.DBus.Introspectable"/>
    <allow send_destination="org.freedesktop.DBus"
           send_interface="org.freedesktop.DBus.Properties"/>
  </policy>

  <includedir>/run/dbus-policy</includedir>
</busconfig>
DBUS_EOF
dbus-daemon --config-file=/run/dbus-system.conf

# Validate dbus-daemon started
if [ ! -f /run/dbus/pid ]; then
    echo "FATAL: dbus-daemon failed to start (no PID file)" >"$OUTDIR/pinchy.stderr"
    echo "1" >"$OUTDIR/pinchyd.exit"
    echo "1" >"$OUTDIR/pinchy.exit"
    touch "$OUTDIR/done"
    poweroff -f
fi

cd "$PINCHY_TEST_PROJDIR"

# Use a smaller ring buffer for tests to reduce memory usage
export PINCHY_RINGBUF_SIZE=2097152

PINCHYD_OUT="$OUTDIR/pinchyd.out"

wait_for_pinchyd() {
    for i in $(seq 1 60); do
        if grep -q "Waiting for Ctrl-C..." "$PINCHYD_OUT" 2>/dev/null; then
            return 0
        fi

        if ! kill -0 $PINCHYD_PID 2>/dev/null; then
            echo "pinchyd exited prematurely" >"$OUTDIR/pinchy.stderr"
            echo "1" >"$OUTDIR/pinchyd.exit"
            echo "1" >"$OUTDIR/pinchy.exit"
            touch "$OUTDIR/done"
            poweroff -f
        fi

        sleep 0.1
    done

    echo "wait_for_pinchyd timed out" >"$OUTDIR/pinchy.stderr"
    echo "1" >"$OUTDIR/pinchyd.exit"
    echo "1" >"$OUTDIR/pinchy.exit"
    touch "$OUTDIR/done"
    poweroff -f
}

build_event_args() {
    EVENT_ARGS=""
    OLD_IFS="$IFS"
    IFS=","
    for event in $PINCHY_TEST_EVENTS; do
        EVENT_ARGS="$EVENT_ARGS -e $event"
    done
    IFS="$OLD_IFS"
}

run_standard() {
    PINCHYD_OUT="$OUTDIR/pinchyd.out"
    $PINCHYD >"$PINCHYD_OUT" 2>&1 &
    PINCHYD_PID=$!
    wait_for_pinchyd

    build_event_args

    # Run pinchy client with test-helper workload under setsid
    setsid sh -c "$PINCHY $EVENT_ARGS -- $TEST_HELPER $PINCHY_TEST_WORKLOAD \
        >\"$OUTDIR/pinchy.stdout\" 2>\"$OUTDIR/pinchy.stderr\"; \
        echo \$? >\"$OUTDIR/pinchy.exit\""

    # Stop pinchyd
    kill -INT $PINCHYD_PID 2>/dev/null || true
    wait $PINCHYD_PID 2>/dev/null
    echo $? >"$OUTDIR/pinchyd.exit"
}

run_benchmark() {
    BENCH_LOOPS="${PINCHY_BENCH_LOOPS:-250}"
    BENCH_RUNS="${PINCHY_BENCH_RUNS:-15}"
    BENCH_LATENCY_LOOPS="${PINCHY_BENCH_LATENCY_LOOPS:-1}"

    build_event_args

    : >"$OUTDIR/pinchy.stderr"
    rm -f "$OUTDIR/latency-ms.txt"

    # Throughput phase
    PINCHYD_OUT="$OUTDIR/pinchyd-throughput.out"
    PINCHY_CLIENT_QUEUE_CAPACITY="$PINCHY_CLIENT_QUEUE_CAPACITY" PINCHY_EFF_STATS=1 $PINCHYD >"$PINCHYD_OUT" 2>&1 &
    PINCHYD_PID=$!
    wait_for_pinchyd

    start_ns=$(date +%s%N)
    PINCHY_BENCH_LOOPS="$BENCH_LOOPS" setsid sh -c "$PINCHY $EVENT_ARGS -- $TEST_HELPER $PINCHY_TEST_WORKLOAD \
        >/dev/null 2>>\"$OUTDIR/pinchy.stderr\""
    end_ns=$(date +%s%N)

    echo $(( (end_ns - start_ns) / 1000000 )) >"$OUTDIR/throughput-ms.txt"

    sleep 2

    kill -INT $PINCHYD_PID 2>/dev/null || true
    wait $PINCHYD_PID 2>/dev/null
    THROUGHPUT_PINCHYD_EXIT=$?

    # Latency phase
    PINCHYD_OUT="$OUTDIR/pinchyd-latency.out"
    PINCHY_CLIENT_QUEUE_CAPACITY="$PINCHY_CLIENT_QUEUE_CAPACITY" PINCHY_EFF_STATS=1 $PINCHYD >"$PINCHYD_OUT" 2>&1 &
    PINCHYD_PID=$!
    wait_for_pinchyd

    for _ in $(seq 1 "$BENCH_RUNS"); do
        start_ns=$(date +%s%N)
        PINCHY_BENCH_LOOPS="$BENCH_LATENCY_LOOPS" setsid sh -c "$PINCHY $EVENT_ARGS -- $TEST_HELPER $PINCHY_TEST_WORKLOAD \
            >/dev/null 2>>\"$OUTDIR/pinchy.stderr\""
        end_ns=$(date +%s%N)
        echo $(( (end_ns - start_ns) / 1000000 )) >>"$OUTDIR/latency-ms.txt"
    done

    sleep 1

    kill -INT $PINCHYD_PID 2>/dev/null || true
    wait $PINCHYD_PID 2>/dev/null
    LATENCY_PINCHYD_EXIT=$?

    cat "$OUTDIR/pinchyd-throughput.out" "$OUTDIR/pinchyd-latency.out" >"$OUTDIR/pinchyd.out"

    if [ "$THROUGHPUT_PINCHYD_EXIT" -eq 0 ] && [ "$LATENCY_PINCHYD_EXIT" -eq 0 ]; then
        echo "0" >"$OUTDIR/pinchyd.exit"
    else
        echo "1" >"$OUTDIR/pinchyd.exit"
    fi

    echo "0" >"$OUTDIR/pinchy.exit"
}

run_server_only() {
    PINCHYD_OUT="$OUTDIR/pinchyd.out"
    $PINCHYD >"$PINCHYD_OUT" 2>&1 &
    PINCHYD_PID=$!
    wait_for_pinchyd

    kill -INT $PINCHYD_PID 2>/dev/null || true
    wait $PINCHYD_PID 2>/dev/null
    echo $? >"$OUTDIR/pinchyd.exit"
}

run_check_caps() {
    PINCHYD_OUT="$OUTDIR/pinchyd.out"
    $PINCHYD >"$PINCHYD_OUT" 2>&1 &
    PINCHYD_PID=$!
    wait_for_pinchyd

    cat /proc/$PINCHYD_PID/status >"$OUTDIR/proc_status"

    kill -INT $PINCHYD_PID 2>/dev/null || true
    wait $PINCHYD_PID 2>/dev/null
    echo $? >"$OUTDIR/pinchyd.exit"
}

run_auto_quit() {
    date +%s >"$OUTDIR/pinchyd.start_time"

    PINCHYD_OUT="$OUTDIR/pinchyd.out"
    $PINCHYD >"$PINCHYD_OUT" 2>&1 &
    PINCHYD_PID=$!

    wait $PINCHYD_PID 2>/dev/null
    echo $? >"$OUTDIR/pinchyd.exit"

    date +%s >"$OUTDIR/pinchyd.end_time"
}

run_auto_quit_after_client() {
    PINCHYD_OUT="$OUTDIR/pinchyd.out"
    $PINCHYD >"$PINCHYD_OUT" 2>&1 &
    PINCHYD_PID=$!
    wait_for_pinchyd

    setsid sh -c "$PINCHY -- $TEST_HELPER pinchy_reads \
        >\"$OUTDIR/pinchy.stdout\" 2>\"$OUTDIR/pinchy.stderr\"" &
    CLIENT_PID=$!

    sleep 1

    kill $CLIENT_PID 2>/dev/null || true
    wait $CLIENT_PID 2>/dev/null
    echo $? >"$OUTDIR/pinchy.exit"

    date +%s >"$OUTDIR/client.kill_time"

    wait $PINCHYD_PID 2>/dev/null
    echo $? >"$OUTDIR/pinchyd.exit"

    date +%s >"$OUTDIR/pinchyd.end_time"
}

case "$PINCHY_TEST_MODE" in
    standard)
        run_standard
        ;;
    server_only)
        run_server_only
        ;;
    check_caps)
        run_check_caps
        ;;
    auto_quit)
        run_auto_quit
        ;;
    auto_quit_after_client)
        run_auto_quit_after_client
        ;;
    benchmark)
        run_benchmark
        ;;
    *)
        echo "FATAL: Unknown test mode: $PINCHY_TEST_MODE" >"$OUTDIR/pinchy.stderr"
        echo "1" >"$OUTDIR/pinchyd.exit"
        echo "1" >"$OUTDIR/pinchy.exit"
        ;;
esac

touch "$OUTDIR/done"

poweroff -f
