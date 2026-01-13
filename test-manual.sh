#!/bin/bash
# Raikage Manual Testing Script
# This script tests encryption/decryption with various file sizes and scenarios

set -e

echo "========================================"
echo "Raikage Manual Testing Script"
echo "========================================"
echo ""

# Build the project first
echo "[1/7] Building Raikage..."
zig build
echo "Build successful!"
echo ""

# Create test directory
TEST_DIR="test-output"
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"

# Test 1: Small text file
echo "[2/7] Test 1: Small text file (100 bytes)"
SMALL_CONTENT=$(printf 'This is a small test file for encryption testing. %.0s' {1..2})
echo -n "$SMALL_CONTENT" > "$TEST_DIR/small.txt"
echo "Created: $TEST_DIR/small.txt ($(stat -f%z "$TEST_DIR/small.txt" 2>/dev/null || stat -c%s "$TEST_DIR/small.txt") bytes)"
echo ""

# Test 2: Medium text file (10 KB)
echo "[3/7] Test 2: Medium text file (10 KB)"
dd if=/dev/zero bs=1024 count=10 2>/dev/null | tr '\0' 'A' > "$TEST_DIR/medium.txt"
echo "Created: $TEST_DIR/medium.txt ($(stat -f%z "$TEST_DIR/medium.txt" 2>/dev/null || stat -c%s "$TEST_DIR/medium.txt") bytes)"
echo ""

# Test 3: Large text file (1 MB)
echo "[4/7] Test 3: Large text file (1 MB)"
dd if=/dev/zero bs=1024 count=1024 2>/dev/null | tr '\0' 'B' > "$TEST_DIR/large.txt"
echo "Created: $TEST_DIR/large.txt ($(stat -f%z "$TEST_DIR/large.txt" 2>/dev/null || stat -c%s "$TEST_DIR/large.txt") bytes)"
echo ""

# Test 4: Very large file (10 MB)
echo "[5/7] Test 4: Very large file (10 MB)"
dd if=/dev/zero bs=1M count=10 2>/dev/null | tr '\0' 'C' > "$TEST_DIR/verylarge.txt"
echo "Created: $TEST_DIR/verylarge.txt ($(stat -f%z "$TEST_DIR/verylarge.txt" 2>/dev/null || stat -c%s "$TEST_DIR/verylarge.txt") bytes)"
echo ""

# Test 5: Binary file
echo "[6/7] Test 5: Binary file (random data)"
dd if=/dev/urandom of="$TEST_DIR/binary.dat" bs=1024 count=5 2>/dev/null
echo "Created: $TEST_DIR/binary.dat ($(stat -f%z "$TEST_DIR/binary.dat" 2>/dev/null || stat -c%s "$TEST_DIR/binary.dat") bytes)"
echo ""

# Test 6: Empty file
echo "[7/7] Test 6: Empty file"
touch "$TEST_DIR/empty.txt"
echo "Created: $TEST_DIR/empty.txt (0 bytes)"
echo ""

echo "========================================"
echo "Test files created successfully!"
echo "========================================"
echo ""
echo "Manual Testing Instructions:"
echo ""
echo "1. Encrypt a file:"
echo "   ./zig-out/bin/raikage encrypt $TEST_DIR/small.txt"
echo "   - Enter password (at least 8 characters)"
echo "   - Confirm password"
echo "   - Should create: $TEST_DIR/small.txt.rkg"
echo ""
echo "2. Decrypt a file:"
echo "   ./zig-out/bin/raikage decrypt $TEST_DIR/small.txt.rkg"
echo "   - Enter the same password"
echo "   - Should restore: $TEST_DIR/small.txt"
echo ""
echo "3. Verify contents match:"
echo "   diff $TEST_DIR/small.txt $TEST_DIR/small.txt.decrypted"
echo ""
echo "4. Test wrong password:"
echo "   Try decrypting with incorrect password - should fail"
echo ""
echo "5. Test file overwrite protection:"
echo "   Try encrypting same file twice - should prompt"
echo ""
echo "6. Test password hiding:"
echo "   Verify password is not visible when typing"
echo ""
echo "Test files are in: $TEST_DIR"
