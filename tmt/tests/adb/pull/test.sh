#!/bin/bash
set -euo pipefail

SRCDIR=$(mktemp -d)
DSTDIR=$(mktemp -d)
trap "rm -rf $SRCDIR $DSTDIR" EXIT

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

echo "=== Pull: small text file ==="
echo "hello world" > "$SRCDIR/small.txt"
adb pull "$SRCDIR/small.txt" "$DSTDIR/small.txt"
diff "$SRCDIR/small.txt" "$DSTDIR/small.txt" || fail "small text file content mismatch"

echo "=== Pull: binary file ==="
dd if=/dev/urandom of="$SRCDIR/binary.bin" bs=1024 count=10 2>/dev/null
adb pull "$SRCDIR/binary.bin" "$DSTDIR/binary.bin"
diff "$SRCDIR/binary.bin" "$DSTDIR/binary.bin" || fail "binary file content mismatch"

echo "=== Pull: large file (512 KB, multi-chunk) ==="
dd if=/dev/urandom of="$SRCDIR/large.bin" bs=1024 count=512 2>/dev/null
adb pull "$SRCDIR/large.bin" "$DSTDIR/large.bin"
diff "$SRCDIR/large.bin" "$DSTDIR/large.bin" || fail "large file content mismatch"

echo "=== Pull: empty file ==="
touch "$SRCDIR/empty.txt"
adb pull "$SRCDIR/empty.txt" "$DSTDIR/empty.txt"
[ -f "$DSTDIR/empty.txt" ] || fail "empty file not created"
[ ! -s "$DSTDIR/empty.txt" ] || fail "empty file should have zero size"

echo "=== Pull: non-existent file (expect failure) ==="
if adb pull "$SRCDIR/nonexistent.txt" "$DSTDIR/nonexistent.txt" 2>/dev/null; then
    fail "pulling non-existent file should have failed"
fi

echo "=== Pull: file with spaces in name ==="
echo "spaces content" > "$SRCDIR/file with spaces.txt"
adb pull "$SRCDIR/file with spaces.txt" "$DSTDIR/file with spaces.txt"
diff "$SRCDIR/file with spaces.txt" "$DSTDIR/file with spaces.txt" \
    || fail "file with spaces content mismatch"

echo "All pull tests passed"
