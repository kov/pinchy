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

wait_for_pinchyd() {
    for i in $(seq 1 60); do
        if grep -q "Waiting for Ctrl-C..." "$OUTDIR/pinchyd.out" 2>/dev/null; then
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

run_standard() {
    $PINCHYD >"$OUTDIR/pinchyd.out" 2>&1 &
    PINCHYD_PID=$!
    wait_for_pinchyd

    # Build event filter arguments
    EVENT_ARGS=""
    OLD_IFS="$IFS"
    IFS=","
    for event in $PINCHY_TEST_EVENTS; do
        EVENT_ARGS="$EVENT_ARGS -e $event"
    done
    IFS="$OLD_IFS"

    # Run pinchy client with test-helper workload under setsid
    setsid sh -c "$PINCHY $EVENT_ARGS -- $TEST_HELPER $PINCHY_TEST_WORKLOAD \
        >\"$OUTDIR/pinchy.stdout\" 2>\"$OUTDIR/pinchy.stderr\"; \
        echo \$? >\"$OUTDIR/pinchy.exit\""

    # Stop pinchyd
    kill -INT $PINCHYD_PID 2>/dev/null || true
    wait $PINCHYD_PID 2>/dev/null
    echo $? >"$OUTDIR/pinchyd.exit"
}

run_server_only() {
    $PINCHYD >"$OUTDIR/pinchyd.out" 2>&1 &
    PINCHYD_PID=$!
    wait_for_pinchyd

    kill -INT $PINCHYD_PID 2>/dev/null || true
    wait $PINCHYD_PID 2>/dev/null
    echo $? >"$OUTDIR/pinchyd.exit"
}

run_check_caps() {
    $PINCHYD >"$OUTDIR/pinchyd.out" 2>&1 &
    PINCHYD_PID=$!
    wait_for_pinchyd

    cat /proc/$PINCHYD_PID/status >"$OUTDIR/proc_status"

    kill -INT $PINCHYD_PID 2>/dev/null || true
    wait $PINCHYD_PID 2>/dev/null
    echo $? >"$OUTDIR/pinchyd.exit"
}

run_auto_quit() {
    date +%s >"$OUTDIR/pinchyd.start_time"

    $PINCHYD >"$OUTDIR/pinchyd.out" 2>&1 &
    PINCHYD_PID=$!

    wait $PINCHYD_PID 2>/dev/null
    echo $? >"$OUTDIR/pinchyd.exit"

    date +%s >"$OUTDIR/pinchyd.end_time"
}

run_auto_quit_after_client() {
    $PINCHYD >"$OUTDIR/pinchyd.out" 2>&1 &
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
    *)
        echo "FATAL: Unknown test mode: $PINCHY_TEST_MODE" >"$OUTDIR/pinchy.stderr"
        echo "1" >"$OUTDIR/pinchyd.exit"
        echo "1" >"$OUTDIR/pinchy.exit"
        ;;
esac

touch "$OUTDIR/done"

poweroff -f
