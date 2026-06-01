#!/bin/bash
set -euo pipefail

SRCDIR=$(mktemp -d)
DSTDIR=$(mktemp -d)
trap "rm -rf $SRCDIR $DSTDIR" EXIT

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

echo "=== Push: small text file ==="
echo "push test content" > "$SRCDIR/small.txt"
adb push "$SRCDIR/small.txt" "$DSTDIR/small.txt"
diff "$SRCDIR/small.txt" "$DSTDIR/small.txt" || fail "small text file content mismatch"

echo "=== Push: binary file ==="
dd if=/dev/urandom of="$SRCDIR/binary.bin" bs=1024 count=10 2>/dev/null
adb push "$SRCDIR/binary.bin" "$DSTDIR/binary.bin"
diff "$SRCDIR/binary.bin" "$DSTDIR/binary.bin" || fail "binary file content mismatch"

echo "=== Push: large file (512 KB, multi-chunk) ==="
dd if=/dev/urandom of="$SRCDIR/large.bin" bs=1024 count=512 2>/dev/null
adb push "$SRCDIR/large.bin" "$DSTDIR/large.bin"
diff "$SRCDIR/large.bin" "$DSTDIR/large.bin" || fail "large file content mismatch"

echo "=== Push: empty file ==="
touch "$SRCDIR/empty.txt"
adb push "$SRCDIR/empty.txt" "$DSTDIR/empty.txt"
[ -f "$DSTDIR/empty.txt" ] || fail "empty file not created"
[ ! -s "$DSTDIR/empty.txt" ] || fail "empty file should have zero size"

echo "=== Push: overwrite existing file ==="
echo "original" > "$DSTDIR/overwrite.txt"
echo "replacement" > "$SRCDIR/overwrite.txt"
adb push "$SRCDIR/overwrite.txt" "$DSTDIR/overwrite.txt"
diff "$SRCDIR/overwrite.txt" "$DSTDIR/overwrite.txt" || fail "overwrite content mismatch"

echo "=== Push: file with spaces in name ==="
echo "spaces content" > "$SRCDIR/file with spaces.txt"
adb push "$SRCDIR/file with spaces.txt" "$DSTDIR/file with spaces.txt"
diff "$SRCDIR/file with spaces.txt" "$DSTDIR/file with spaces.txt" \
    || fail "file with spaces content mismatch"

echo "=== Push: file mode is preserved ==="
echo "mode test" > "$SRCDIR/mode.sh"
chmod 0750 "$SRCDIR/mode.sh"
adb push "$SRCDIR/mode.sh" "$DSTDIR/mode.sh"
src_mode=$(stat -c '%a' "$SRCDIR/mode.sh")
dst_mode=$(stat -c '%a' "$DSTDIR/mode.sh")
[ "$src_mode" = "$dst_mode" ] || fail "mode mismatch: source=$src_mode dest=$dst_mode"

echo "=== Push: modification time is preserved ==="
echo "mtime test" > "$SRCDIR/mtime.txt"
touch -t 199303261200.00 "$SRCDIR/mtime.txt"
adb push "$SRCDIR/mtime.txt" "$DSTDIR/mtime.txt"
src_mtime=$(stat -c '%Y' "$SRCDIR/mtime.txt")
dst_mtime=$(stat -c '%Y' "$DSTDIR/mtime.txt")
[ "$src_mtime" = "$dst_mtime" ] || fail "mtime mismatch: source=$src_mtime dest=$dst_mtime"

echo "=== Push: non-existent destination directory (expect failure) ==="
if adb push "$SRCDIR/small.txt" "/nonexistent/dir/file.txt" 2>/dev/null; then
    fail "pushing to non-existent directory should have failed"
fi

echo "All push tests passed"
