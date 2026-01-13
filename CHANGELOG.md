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

## [Unreleased]

### Changed
- Improved library usage documentation with comprehensive examples
- Added badges for Zig version, license, and version
- Enhanced installation instructions with `zig fetch` workflow
- Better explanation of hash/fingerprint for package integrity

[1.0.0]: https://github.com/bkataru/raikage/releases/tag/v1.0.0
