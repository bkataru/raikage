# Raikage Examples

This directory contains working examples demonstrating how to use Raikage as a library in your Zig projects.

## Available Examples

### 1. Key Derivation (`key_derivation.zig`)

Demonstrates Argon2id key derivation from passwords:
- Generating cryptographically secure random salts
- Deriving encryption keys from passwords
- Key consistency verification
- Secure memory zeroing

**Run:**
```bash
zig build run-key-derivation
```

### 2. File Hashing (`file_hashing.zig`)

Demonstrates Blake3 hashing for file integrity:
- Computing cryptographic hashes of file content
- Hash consistency verification
- Base64 encoding of hashes
- Content change detection

**Run:**
```bash
zig build run-file-hashing
```

### 3. Custom Encryption Workflow (`custom_encryption.zig`)

Demonstrates end-to-end encryption workflow:
- File creation and management
- Streaming encryption for large files
- Streaming decryption
- Content integrity verification
- Performance measurement

**Run:**
```bash
zig build run-custom-encryption
```

## Building Examples

To build all examples:
```bash
zig build examples
```

To run a specific example:
```bash
zig build run-<example-name>
```

## Using Raikage in Your Project

To use Raikage as a library dependency, see the main [README](../README.md) for installation instructions.

Basic import:
```zig
const raikage = @import("raikage");
```

## Example Output

Each example includes detailed output showing:
- Step-by-step execution progress
- Generated values (salts, hashes, keys)
- Performance metrics (timing)
- Verification results
- Success/failure indicators

## Notes

- All examples use `GeneralPurposeAllocator` for memory management
- Temporary test files are automatically cleaned up
- Keys and sensitive data are securely zeroed after use
- Examples demonstrate proper error handling with Zig's `try` syntax
