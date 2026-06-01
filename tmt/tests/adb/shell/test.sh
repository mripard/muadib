#!/bin/bash
set -euo pipefail

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

strip_cr() {
    tr -d '\r'
}

echo "=== Shell: simple echo ==="
output=$(adb shell echo hello | strip_cr)
[[ "$output" == *"hello"* ]] || fail "expected 'hello', got '$output'"

echo "=== Shell: command with arguments ==="
output=$(adb shell ls / | strip_cr)
[[ "$output" == *"bin"* ]] || fail "expected 'bin' in root listing, got '$output'"

echo "=== Shell: pipeline ==="
output=$(adb shell "echo hello world | wc -w" | strip_cr)
[[ "$output" == *"2"* ]] || fail "expected '2' from wc -w, got '$output'"

echo "=== Shell: environment variable ==="
output=$(adb shell "FOO=bar sh -c 'echo \$FOO'" | strip_cr)
[[ "$output" == *"bar"* ]] || fail "expected 'bar', got '$output'"

echo "=== Shell: working directory ==="
output=$(adb shell pwd | strip_cr)
[[ -n "$output" ]] || fail "pwd returned empty"

echo "=== Shell: multi-line output ==="
output=$(adb shell "seq 1 5" | strip_cr)
for n in 1 2 3 4 5; do
    [[ "$output" == *"$n"* ]] || fail "expected '$n' in seq output"
done

echo "=== Shell: large output ==="
count=$(adb shell "seq 1 10000" | wc -l)
[ "$count" -ge 10000 ] || fail "expected >= 10000 lines, got $count"

echo "=== Shell: file creation round-trip ==="
TESTFILE=$(mktemp)
trap "rm -f $TESTFILE" EXIT
adb shell "echo round-trip-test > $TESTFILE"
output=$(cat "$TESTFILE" | strip_cr)
[[ "$output" == *"round-trip-test"* ]] \
    || fail "expected 'round-trip-test' in file, got '$output'"

echo "All shell tests passed"
