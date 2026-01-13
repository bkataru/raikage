# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-01-14

### Added
- ChaCha20-Poly1305 authenticated encryption (AEAD)
- Argon2id key derivation with configurable parameters (t=3, m=32MB, p=4)
- Blake3 integrity hashing for additional data verification
- Streaming support for large files (>100MB)
- Cross-platform support (Windows, Linux, macOS)
- Comprehensive test suite with 17 unit and integration tests
- Memory leak detection and secure memory zeroing
- File format versioning for future compatibility
- Command-line interface for file encryption and decryption
- Password confirmation on encryption
- File overwrite protection with user prompts
- Minimum password length enforcement (8 characters)
- Hidden password input for security
- Library API for use in other Zig projects
- Comprehensive documentation with usage examples
- `build.zig.zon` for package distribution
- Support for `zig fetch` package management

### Security
- Cryptographically secure random number generation for salts and nonces
- Constant-time authentication tag verification via Poly1305
- Secure memory zeroing for passwords and keys
- No password logging or debug output
- Maximum file size limit (1GB) to prevent resource exhaustion

### Documentation
- Complete README with installation, usage, and API documentation
- Security overview and threat model
- File format specification
- Performance benchmarks and guidelines
- Manual and automated testing instructions
- Library usage examples for key derivation, hashing, and encryption

## [1.0.1] - 2026-01-14

### Added
- Examples directory with three working code samples:
  - `key_derivation.zig`: Demonstrates Argon2id password-based key derivation
  - `file_hashing.zig`: Demonstrates Blake3 file hashing for integrity verification
  - `custom_encryption.zig`: Complete encryption/decryption workflow example
- Build system support for examples (`zig build examples`)
- Individual run steps for each example (e.g., `zig build run-key_derivation`)
- Organized documentation under `docs/` directory
- API documentation in `docs/API.md`
- Comprehensive GitHub Actions CI/CD workflows:
  - Main CI workflow with multi-OS testing (Ubuntu, Windows, macOS)
  - Automated release workflow for tag-based binary builds
  - Code quality checks (formatting, metrics, documentation completeness)
  - Security scanning (daily scheduled, hardcoded secrets detection)
  - Cross-compilation support for x86_64 and aarch64 architectures
  - Memory leak detection in automated tests
- CI status badge in README.md

### Changed
- Improved library usage documentation with comprehensive examples
- Added badges for Zig version, license, and version
- Enhanced installation instructions with `zig fetch` workflow
- Better explanation of hash/fingerprint for package integrity
- Fixed `encryptFileStreaming()` and `decryptFileStreaming()` to use unbuffered I/O for proper library usage
- Reorganized internal documentation into `docs/` folder
- Updated README.md with accurate API signatures

### Fixed
- Buffered I/O issue in streaming functions that caused 0-byte encrypted files when used as library
- Incorrect API documentation for `generateRandom()` (returns `void`, not `!void`)
- Incorrect example code showing outdated hex formatting methods
- Fixed Zig 0.15.2 compatibility issues in `src/shared.zig`:
  - Updated posix import from `std.os` to `std.posix` (line 114)
  - Corrected `tcgetattr()` API usage to match new return-value signature (lines 118-122)
- Resolved CI security scan false positives by excluding test code from hardcoded password detection

## [Unreleased]

### Added
- None

### Changed
- None

### Fixed
- None

[1.0.1]: https://github.com/bkataru/raikage/releases/tag/v1.0.1
[1.0.0]: https://github.com/bkataru/raikage/releases/tag/v1.0.0
