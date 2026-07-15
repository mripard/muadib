#!/bin/bash
set -euo pipefail

fail() {
    echo "FAIL: $1" >&2
    journalctl -u adibi.service --no-pager -n 30 >&2 || true
    exit 1
}

cleanup() {
    adb forward --remove-all 2>/dev/null || true
    kill "${TCP_PID:-}" 2>/dev/null || true
    kill "${UNIX_PID:-}" 2>/dev/null || true
    kill "${ABSTRACT_PID:-}" 2>/dev/null || true
    rm -f /tmp/test-fwd.sock
}
trap cleanup EXIT

# Helper: send a string through a forwarded port and capture the echo.
# Keeps stdin open for 2 s so the host ADB daemon has time to relay
# the data before seeing EOF on the client socket.
fwd_echo() {
    { echo "$1"; sleep 2; } | socat -t 5 - TCP:127.0.0.1:"$2"
}

echo "=== Forward: tcp echo ==="
socat TCP-LISTEN:9876,reuseaddr,fork EXEC:cat &
TCP_PID=$!
sleep 1

adb forward tcp:9877 tcp:9876

output=$(fwd_echo "hello-tcp-forward" 9877)
[[ "$output" == "hello-tcp-forward" ]] \
    || fail "tcp echo: expected 'hello-tcp-forward', got '$output'"

echo "=== Forward: tcp second connection ==="
output=$(fwd_echo "second-connection" 9877)
[[ "$output" == "second-connection" ]] \
    || fail "tcp second: expected 'second-connection', got '$output'"

echo "=== Forward: tcp large payload ==="
payload=$(head -c 65536 /dev/urandom | base64 -w0)
output=$({ echo "$payload"; sleep 2; } | socat -t 5 - TCP:127.0.0.1:9877)
[[ "$output" == "$payload" ]] \
    || fail "tcp large payload mismatch"

echo "=== Forward: localfilesystem echo ==="
rm -f /tmp/test-fwd.sock
socat UNIX-LISTEN:/tmp/test-fwd.sock,fork EXEC:cat &
UNIX_PID=$!
sleep 1

adb forward tcp:9878 localfilesystem:/tmp/test-fwd.sock
output=$(fwd_echo "hello-unix-forward" 9878)
[[ "$output" == "hello-unix-forward" ]] \
    || fail "unix echo: expected 'hello-unix-forward', got '$output'"

echo "=== Forward: localabstract echo ==="
socat ABSTRACT-LISTEN:test-fwd,fork EXEC:cat &
ABSTRACT_PID=$!
sleep 1

adb forward tcp:9879 localabstract:test-fwd
output=$(fwd_echo "hello-abstract-forward" 9879)
[[ "$output" == "hello-abstract-forward" ]] \
    || fail "abstract echo: expected 'hello-abstract-forward', got '$output'"

echo "=== Forward: removal ==="
adb forward --remove tcp:9877
if echo "should-fail" | socat -t 1 - TCP:127.0.0.1:9877 2>/dev/null; then
    fail "connection should have failed after forward removal"
fi

echo "All forward tests passed"
