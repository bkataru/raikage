# Raikage - Secure File Encryption Tool

A high-performance, secure file encryption CLI tool written in Zig 0.15.2, using modern cryptographic algorithms including ChaCha20-Poly1305 AEAD encryption, Argon2id key derivation, and Blake3 hashing.

## Features

- **Strong Encryption**: ChaCha20-Poly1305 authenticated encryption (AEAD)
- **Secure Key Derivation**: Argon2id with customizable parameters
- **Data Integrity**: Blake3 hashing for additional integrity verification
- **Large File Support**: Streaming mode for files >100MB
- **Password Protection**: Hidden password input with confirmation on encryption
- **File Overwrite Protection**: Prompts before overwriting existing files
- **Memory Safety**: Built-in leak detection and secure memory zeroing
- **Cross-Platform**: Works on Windows, Linux, and macOS

## Security Overview

### Cryptographic Algorithms

- **Encryption**: ChaCha20-Poly1305 (RFC 7539)
  - 256-bit keys
  - 96-bit nonces (randomly generated)
  - 128-bit authentication tags
  - Authenticated Encryption with Associated Data (AEAD)

- **Key Derivation**: Argon2id (RFC 9106)
  - Parameters: t=3, m=32MB (2^15), p=4
  - 16-byte random salt (cryptographically secure)
  - Resistant to GPU/ASIC attacks

- **Hashing**: Blake3
  - 256-bit output
  - Used for additional integrity verification
  - Computed on plaintext before encryption

### Security Features

- Cryptographically secure random number generation for salts and nonces
- Constant-time authentication tag verification (via Poly1305)
- Secure memory zeroing for passwords and keys
- No password logging or debug output
- Minimum password length enforcement (8 characters)
- Password confirmation on encryption
- File format versioning for future compatibility

## Installation

### Prerequisites

- Zig 0.15.2 or later ([download here](https://ziglang.org/download/))

### Building from Source

```bash
# Clone the repository
git clone https://github.com/bkataru/raikage.git
cd raikage

# Build the project
zig build

# The binary will be in zig-out/bin/raikage (or raikage.exe on Windows)
```

### Running Tests

```bash
# Run all unit and integration tests
zig build test

# Run with detailed output
zig build test --summary all
```

### Using as a Library

Raikage can also be used as a cryptographic library in your Zig projects.

#### Option 1: Using `zig fetch` (Recommended)

The `zig fetch` command downloads the package and automatically adds it to your `build.zig.zon`:

```bash
zig fetch --save git+https://github.com/bkataru/raikage.git
```

For a specific version (recommended for production):
```bash
zig fetch --save git+https://github.com/bkataru/raikage.git#v1.1.0
```

This will automatically update your `build.zig.zon` file with the correct dependency entry and hash.

#### Option 2: Manual Configuration

If you prefer to manually configure dependencies, add to your `build.zig.zon`:

```zig
.dependencies = .{
    .raikage = .{
        .url = "git+https://github.com/bkataru/raikage.git#v1.1.0",
        .hash = "12209a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f", // Content hash for integrity verification
    },
},
```

**Note:** The `.hash` field is a cryptographic fingerprint that ensures package integrity. When you first add the dependency, use a placeholder like `"1220..."` and run `zig build`. Zig will tell you the correct hash to use. For example:

```
$ zig build
error: hash mismatch:
  expected: 1220...
  actual:   12209a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f

note: to update the hash, use:
  .hash = "12209a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f",
```

#### Option 3: Local Path Dependency

For local development or testing changes:

```zig
.dependencies = .{
    .raikage = .{
        .path = "../raikage",
    },
},
```

This is useful when you're developing both projects simultaneously or want to test local modifications.

#### Configuring build.zig

After adding the dependency to `build.zig.zon`, configure your `build.zig` to use the raikage module:

```zig
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Fetch the raikage dependency
    const raikage_dep = b.dependency("raikage", .{
        .target = target,
        .optimize = optimize,
    });

    // Get the module from the dependency
    const raikage_mod = raikage_dep.module("raikage");

    // Create your executable
    const exe = b.addExecutable(.{
        .name = "my_app",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Add the raikage import to your executable
    exe.root_module.addImport("raikage", raikage_mod);

    b.installArtifact(exe);
}
```

**Complete Workflow Example:**

```bash
# 1. Initialize your project (if not already done)
zig init

# 2. Add raikage as a dependency
zig fetch --save git+https://github.com/bkataru/raikage.git#v1.1.0

# 3. Update your build.zig (see code example above)

# 4. Build your project
zig build

# 5. Use raikage in your code (src/main.zig):
# const raikage = @import("raikage");
```

## Usage

### Encrypting a File

```bash
raikage encrypt <file>
```

Example:
```bash
raikage encrypt document.pdf
# Enter password: ********
# Confirm password: ********
# Successfully encrypted to: document.pdf.rkg
```

The encrypted file will have a `.rkg` extension added.

### Decrypting a File

```bash
raikage decrypt <file.rkg>
```

Example:
```bash
raikage decrypt document.pdf.rkg
# Password: ********
# Successfully decrypted to: document.pdf
```

The decrypted file will have the `.rkg` extension removed.

### Password Requirements

- Minimum length: 8 characters
- Case-sensitive
- Can include any characters (letters, numbers, symbols, spaces)
- Hidden input (not displayed while typing)
- Confirmation required when encrypting

## Library API

When using Raikage as a library, import it in your Zig code:

```zig
const raikage = @import("raikage");
```

### Core Functions

| Function | Signature | Description |
|----------|-----------|-------------|
| `deriveKey` | `fn(allocator: Allocator, password: []const u8, salt: [16]u8) ![32]u8` | Derive encryption key using Argon2id with t=3, m=32MB, p=4 |
| `hashData` | `fn(data: []const u8) [32]u8` | Compute Blake3 hash (32 bytes) of data |
| `generateRandom` | `fn(buffer: []u8) !void` | Fill buffer with cryptographically secure random bytes |
| `secureZeroKey` | `fn(key: *[32]u8) void` | Securely zero key from memory using volatile writes |
| `encryptFileStreaming` | `fn(input_file: File, output_file: File, password: []const u8, allocator: Allocator) !void` | Encrypt file with automatic streaming for large files |
| `decryptFileStreaming` | `fn(input_file: File, output_file: File, password: []const u8, allocator: Allocator) !void` | Decrypt file with automatic streaming for large files |

### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `KEY_LEN` | 32 | ChaCha20-Poly1305 key size (bytes) |
| `SALT_LEN` | 16 | Argon2id salt size (bytes) |
| `NONCE_LEN` | 12 | ChaCha20-Poly1305 nonce size (bytes) |
| `TAG_LEN` | 16 | Poly1305 authentication tag size (bytes) |
| `HASH_LEN` | 32 | Blake3 hash output size (bytes) |
| `HEADER_SIZE` | 86 | `.rkg` encrypted file header size (bytes) |
| `CHUNK_SIZE` | 65536 | Streaming chunk size - 64KB |
| `STREAMING_THRESHOLD` | 104857600 | File size threshold for streaming mode - 100MB |
| `MAX_FILE_SIZE` | 1073741824 | Maximum supported file size - 1GB |

### Example: Key Derivation

```zig
const std = @import("std");
const raikage = @import("raikage");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Generate random salt
    var salt: [raikage.SALT_LEN]u8 = undefined;
    try raikage.generateRandom(&salt);

    // Derive key from password
    const password = "my_secure_password";
    const key = try raikage.deriveKey(allocator, password, salt);
    defer {
        var mutable_key = key;
        raikage.secureZeroKey(&mutable_key);
    }

    std.debug.print("Key derived successfully!\n", .{});
}
```

### Example: File Hashing

```zig
const std = @import("std");
const raikage = @import("raikage");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const file = try std.fs.cwd().openFile("document.pdf", .{});
    defer file.close();

    const data = try file.readToEndAlloc(allocator, raikage.MAX_FILE_SIZE);
    defer allocator.free(data);

    const hash = raikage.hashData(data);
    std.debug.print("Blake3 hash: {s}\n", .{std.fmt.fmtSliceHexLower(&hash)});
}
```

### Example: Custom Encryption Workflow

```zig
const std = @import("std");
const raikage = @import("raikage");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const input_file = try std.fs.cwd().openFile("sensitive.txt", .{});
    defer input_file.close();

    const output_file = try std.fs.cwd().createFile("sensitive.txt.encrypted", .{});
    defer output_file.close();

    const password = "strong_password_here";

    // Encrypt file using streaming mode
    try raikage.encryptFileStreaming(input_file, output_file, password, allocator);

    std.debug.print("File encrypted successfully!\n", .{});
}
```

## File Format Specification

Encrypted files (`.rkg`) use the following format:

### Header (86 bytes)

| Field          | Size    | Description                              |
|----------------|---------|------------------------------------------|
| version        | 1 byte  | File format version (currently 0x01)     |
| flags          | 1 byte  | Reserved for future use (0x00)           |
| salt           | 16 bytes| Argon2id salt (random)                   |
| nonce          | 12 bytes| ChaCha20-Poly1305 nonce (random)         |
| tag            | 16 bytes| ChaCha20-Poly1305 authentication tag     |
| data_hash      | 32 bytes| Blake3 hash of plaintext                 |
| original_len   | 8 bytes | Original file size (u64, little-endian)  |

### Encrypted Data

The ciphertext follows immediately after the header. The size of the ciphertext is equal to the original file size (ChaCha20 is a stream cipher).

### Total File Size

```
encrypted_file_size = 86 + original_file_size
```

## Performance

### File Size Limits

- Maximum file size: 1GB (1,073,741,824 bytes)
- Files <100MB: In-memory encryption (faster)
- Files ≥100MB: Streaming encryption (memory-efficient)

### Benchmarks

Performance depends on hardware, but typical speeds on modern CPUs:

- Small files (<1MB): ~100-500 MB/s
- Medium files (1-100MB): ~200-800 MB/s
- Large files (100MB-1GB): ~150-600 MB/s (streaming mode)

Key derivation (Argon2id) takes approximately 0.5-1.5 seconds per operation, which is intentional to resist brute-force attacks.

## Technical Details

### Encryption Process

1. Validate file size (max 1GB)
2. Generate random 16-byte salt
3. Generate random 12-byte nonce
4. Prompt for password with confirmation
5. Derive 32-byte key using Argon2id(password, salt)
6. Compute Blake3 hash of plaintext
7. Encrypt plaintext with ChaCha20-Poly1305(key, nonce) → ciphertext + tag
8. Write header + ciphertext to `.rkg` file
9. Securely zero password and key from memory

### Decryption Process

1. Read and parse file header
2. Validate file format version
3. Prompt for password (no confirmation)
4. Derive key using Argon2id(password, salt from header)
5. Decrypt ciphertext with ChaCha20-Poly1305(key, nonce, tag)
   - If authentication fails → wrong password or corrupted file
6. Verify Blake3 hash matches plaintext
7. Write plaintext to output file
8. Securely zero password and key from memory

### Memory Management

- Uses `GeneralPurposeAllocator` with leak detection
- All allocations are properly freed
- Sensitive data (passwords, keys) is securely zeroed before deallocation
- No memory leaks (verified by allocator)

## Testing

### Automated Tests

The project includes comprehensive test coverage:

- **Unit Tests** (src/shared.zig):
  - Key derivation consistency and uniqueness
  - Blake3 hashing
  - ChaCha20-Poly1305 round-trip encryption/decryption
  - Authentication failure detection
  - Header serialization/deserialization
  - Random number generation
  - Secure memory zeroing

- **Integration Tests** (src/main.zig):
  - File size validation
  - Header size calculation
  - End-to-end encryption workflows

Run tests with:
```bash
zig build test
```

### Manual Testing

A comprehensive manual testing script is provided:

**Windows:**
```powershell
.\test-manual.ps1
```

**Unix/Linux/macOS:**
```bash
chmod +x test-manual.sh
./test-manual.sh
```

These scripts create test files of various sizes and provide step-by-step instructions for manual testing.

## Security Considerations

### Threat Model

Raikage protects against:

- Unauthorized file access (encryption at rest)
- Brute-force password attacks (Argon2id with memory-hard parameters)
- Ciphertext tampering (Poly1305 authentication)
- Chosen-ciphertext attacks (AEAD construction)

Raikage does NOT protect against:

- Keyloggers or malware on the host system
- Physical access to unlocked systems
- Side-channel attacks (timing, power analysis) on the hardware
- Quantum computer attacks (ChaCha20 is not post-quantum secure)
- Weak passwords (always use strong, unique passwords)

### Best Practices

1. **Use Strong Passwords**: At least 12+ characters with mixed case, numbers, and symbols
2. **Don't Reuse Passwords**: Each file should have a unique password
3. **Secure Storage**: Store encrypted files on secure media
4. **Backup**: Keep backups of both encrypted files and passwords (separately)
5. **Verify Integrity**: Test decryption after encryption to ensure files are recoverable
6. **Secure Deletion**: Securely wipe original files after encryption if needed

### Known Limitations

- Passwords must be manually remembered or stored in a secure password manager
- No key file support (password-only authentication)
- No file compression (encrypt compressed files for better efficiency)
- No progress indication for large file operations
- Single-threaded operation (no parallel processing)

## Contributing

Contributions are welcome! Please ensure:

1. All tests pass (`zig build test`)
2. Code follows Zig style guidelines
3. Security-sensitive changes are reviewed carefully
4. New features include appropriate tests

## Changelog

### v1.0.0 - Initial Release

- ChaCha20-Poly1305 authenticated encryption
- Argon2id key derivation
- Blake3 integrity hashing
- Streaming support for files >100MB
- Cross-platform support (Windows, Linux, macOS)
- Comprehensive test suite (17 tests)
- Memory leak detection and secure zeroing

## License

MIT License - See [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [Zig](https://ziglang.org/) programming language
- Uses algorithms from:
  - RFC 7539 (ChaCha20 and Poly1305)
  - RFC 9106 (Argon2)
  - [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) specification

## Links

- GitHub Repository: [https://github.com/bkataru/raikage](https://github.com/bkataru/raikage)
- Issues & Bug Reports: [https://github.com/bkataru/raikage/issues](https://github.com/bkataru/raikage/issues)

---

**Note**: This tool is provided as-is for educational and practical use. While it uses industry-standard cryptographic algorithms, it has not undergone formal security audit. Use at your own risk for sensitive data.
