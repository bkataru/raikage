# Raikage Manual Testing Script
# This script tests encryption/decryption with various file sizes and scenarios

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Raikage Manual Testing Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Build the project first
Write-Host "[1/7] Building Raikage..." -ForegroundColor Yellow
zig build
if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed!" -ForegroundColor Red
    exit 1
}
Write-Host "Build successful!" -ForegroundColor Green
Write-Host ""

# Create test directory
$testDir = "test-output"
if (Test-Path $testDir) {
    Remove-Item -Recurse -Force $testDir
}
New-Item -ItemType Directory -Path $testDir | Out-Null

# Test 1: Small text file
Write-Host "[2/7] Test 1: Small text file (100 bytes)" -ForegroundColor Yellow
$smallContent = "This is a small test file for encryption testing. " * 2
Set-Content -Path "$testDir\small.txt" -Value $smallContent -NoNewline
Write-Host "Created: $testDir\small.txt ($(Get-Item $testDir\small.txt).Length bytes)"
Write-Host ""

# Test 2: Medium text file
Write-Host "[3/7] Test 2: Medium text file (10 KB)" -ForegroundColor Yellow
$mediumContent = ("A" * 1024) * 10
Set-Content -Path "$testDir\medium.txt" -Value $mediumContent -NoNewline
Write-Host "Created: $testDir\medium.txt ($((Get-Item $testDir\medium.txt).Length) bytes)"
Write-Host ""

# Test 3: Large text file
Write-Host "[4/7] Test 3: Large text file (1 MB)" -ForegroundColor Yellow
$largeContent = ("B" * 1024) * 1024
Set-Content -Path "$testDir\large.txt" -Value $largeContent -NoNewline
Write-Host "Created: $testDir\large.txt ($((Get-Item $testDir\large.txt).Length) bytes)"
Write-Host ""

# Test 4: Very large file (10 MB)
Write-Host "[5/7] Test 4: Very large file (10 MB)" -ForegroundColor Yellow
$veryLargeContent = ("C" * 1024 * 1024) * 10
Set-Content -Path "$testDir\verylarge.txt" -Value $veryLargeContent -NoNewline
Write-Host "Created: $testDir\verylarge.txt ($((Get-Item $testDir\verylarge.txt).Length) bytes)"
Write-Host ""

# Test 5: Binary file
Write-Host "[6/7] Test 5: Binary file (random data)" -ForegroundColor Yellow
$randomBytes = New-Object byte[] 5000
(New-Object Random).NextBytes($randomBytes)
[System.IO.File]::WriteAllBytes("$testDir\binary.dat", $randomBytes)
Write-Host "Created: $testDir\binary.dat ($((Get-Item $testDir\binary.dat).Length) bytes)"
Write-Host ""

# Test 6: Empty file
Write-Host "[7/7] Test 6: Empty file" -ForegroundColor Yellow
New-Item -ItemType File -Path "$testDir\empty.txt" -Force | Out-Null
Write-Host "Created: $testDir\empty.txt (0 bytes)"
Write-Host ""

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test files created successfully!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Manual Testing Instructions:" -ForegroundColor Yellow
Write-Host ""
Write-Host "1. Encrypt a file:" -ForegroundColor White
Write-Host "   .\zig-out\bin\raikage.exe encrypt $testDir\small.txt" -ForegroundColor Gray
Write-Host "   - Enter password (at least 8 characters)"
Write-Host "   - Confirm password"
Write-Host "   - Should create: $testDir\small.txt.rkg"
Write-Host ""
Write-Host "2. Decrypt a file:" -ForegroundColor White
Write-Host "   .\zig-out\bin\raikage.exe decrypt $testDir\small.txt.rkg" -ForegroundColor Gray
Write-Host "   - Enter the same password"
Write-Host "   - Should restore: $testDir\small.txt"
Write-Host ""
Write-Host "3. Verify contents match:" -ForegroundColor White
Write-Host "   Compare original and decrypted files" -ForegroundColor Gray
Write-Host ""
Write-Host "4. Test wrong password:" -ForegroundColor White
Write-Host "   Try decrypting with incorrect password - should fail" -ForegroundColor Gray
Write-Host ""
Write-Host "5. Test file overwrite protection:" -ForegroundColor White
Write-Host "   Try encrypting same file twice - should prompt" -ForegroundColor Gray
Write-Host ""
Write-Host "6. Test password hiding:" -ForegroundColor White
Write-Host "   Verify password is not visible when typing" -ForegroundColor Gray
Write-Host ""
Write-Host "Test files are in: $testDir" -ForegroundColor Cyan
