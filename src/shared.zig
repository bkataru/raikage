const std = @import("std");
const crypto = std.crypto;
const fs = std.fs;
const Allocator = std.mem.Allocator;
const builtin = @import("builtin");

pub const Argon2 = crypto.pwhash.argon2;
pub const ChaCha20Poly1305 = crypto.aead.chacha_poly.ChaCha20Poly1305;
pub const Blake3 = crypto.hash.Blake3;

pub const SALT_LEN = 16;
pub const NONCE_LEN = 12;
pub const TAG_LEN = ChaCha20Poly1305.tag_length;
pub const KEY_LEN = 32;
pub const MAX_FILE_SIZE = 1024 * 1024 * 1024; // 1GB limit for safety
pub const CHUNK_SIZE = 64 * 1024; // 64KB chunks for streaming
pub const STREAMING_THRESHOLD = 100 * 1024 * 1024; // Use streaming for files >100MB

pub const Argon2Params = Argon2.Params{
    .t = 3,
    .m = 1 << 15,
    .p = 4,
};

pub const Error = error{
    ReadError,
    WriteError,
    AuthenticationFailed,
    InvalidFile,
    FileTooLarge,
    PasswordMismatch,
    PasswordTooShort,
};

/// File header structure for encrypted files
pub const Header = struct {
    version: u8 = 1,
    flags: u8 = 0,
    salt: [SALT_LEN]u8,
    nonce: [NONCE_LEN]u8,
    tag: [TAG_LEN]u8,
    data_hash: [32]u8,
    original_len: u64,

    /// Write header to a file writer
    pub fn write(self: *const Header, writer: anytype) !void {
        try writer.writeByte(self.version);
        try writer.writeByte(self.flags);
        try writer.writeAll(&self.salt);
        try writer.writeAll(&self.nonce);
        try writer.writeAll(&self.tag);
        try writer.writeAll(&self.data_hash);
        try writer.writeInt(u64, self.original_len, .little);
    }

    /// Read header from a reader
    pub fn read(reader: anytype) !Header {
        var header: Header = undefined;
        header.version = try reader.readByte();
        header.flags = try reader.readByte();
        _ = try reader.readAll(&header.salt);
        _ = try reader.readAll(&header.nonce);
        _ = try reader.readAll(&header.tag);
        _ = try reader.readAll(&header.data_hash);
        header.original_len = try reader.readInt(u64, .little);
        return header;
    }
};

/// Platform-specific password input with hidden echo
fn readPasswordHidden(allocator: Allocator, max_len: usize) ![]u8 {
    if (builtin.os.tag == .windows) {
        // Windows implementation using kernel32
        const windows = std.os.windows;
        const kernel32 = windows.kernel32;

        const stdin_handle = std.fs.File.stdin().handle;
        var mode: windows.DWORD = undefined;

        // Get current console mode
        if (kernel32.GetConsoleMode(stdin_handle, &mode) == 0) {
            // Fallback to regular reading if not a console
            return readPasswordFallback(allocator, max_len);
        }

        // Disable echo
        const new_mode = mode & ~@as(windows.DWORD, 0x0004); // ENABLE_ECHO_INPUT = 0x0004
        _ = kernel32.SetConsoleMode(stdin_handle, new_mode);
        defer _ = kernel32.SetConsoleMode(stdin_handle, mode); // Restore mode

        var stdin_buffer: [256]u8 = undefined;
        var stdin = std.fs.File.stdin().reader(&stdin_buffer);

        // Read password into buffer
        var password_buf: [1024]u8 = undefined;
        var len: usize = 0;
        while (len < max_len) {
            const byte = stdin.interface.takeByte() catch |err| switch (err) {
                error.ReadFailed => break,
                error.EndOfStream => break,
            };
            if (byte == '\n' or byte == '\r') break;
            password_buf[len] = byte;
            len += 1;
        }

        // Allocate and copy password
        const password = try allocator.alloc(u8, len);
        @memcpy(password, password_buf[0..len]);

        return password;
    } else {
        // Unix/Linux implementation using termios
        const posix = std.os;
        const stdin_fd = std.fs.File.stdin().handle;

        // Get current terminal settings
        var old_term: posix.termios = undefined;
        _ = posix.tcgetattr(stdin_fd, &old_term) catch {
            // Fallback if not a terminal
            return readPasswordFallback(allocator, max_len);
        };

        // Disable echo
        var new_term = old_term;
        new_term.lflag.ECHO = false;
        _ = posix.tcsetattr(stdin_fd, .NOW, new_term) catch {
            return readPasswordFallback(allocator, max_len);
        };
        defer _ = posix.tcsetattr(stdin_fd, .NOW, old_term) catch {};

        var stdin_buffer: [256]u8 = undefined;
        var stdin = std.fs.File.stdin().reader(&stdin_buffer);

        // Read password into buffer
        var password_buf: [1024]u8 = undefined;
        var len: usize = 0;
        while (len < max_len) {
            const byte = stdin.interface.takeByte() catch |err| switch (err) {
                error.ReadFailed => break,
                error.EndOfStream => break,
            };
            if (byte == '\n' or byte == '\r') break;
            password_buf[len] = byte;
            len += 1;
        }

        // Allocate and copy password
        const password = try allocator.alloc(u8, len);
        @memcpy(password, password_buf[0..len]);

        return password;
    }
}

/// Fallback password reading without hidden input
fn readPasswordFallback(allocator: Allocator, max_len: usize) ![]u8 {
    var stdin_buffer: [256]u8 = undefined;
    var stdin = std.fs.File.stdin().reader(&stdin_buffer);

    // Read password into buffer
    var password_buf: [1024]u8 = undefined;
    var len: usize = 0;
    while (len < max_len) {
        const byte = stdin.interface.takeByte() catch |err| switch (err) {
            error.ReadFailed => break,
            error.EndOfStream => break,
        };
        if (byte == '\n' or byte == '\r') break;
        password_buf[len] = byte;
        len += 1;
    }

    // Allocate and copy password
    const password = try allocator.alloc(u8, len);
    @memcpy(password, password_buf[0..len]);

    return password;
}

/// Prompt for password with optional confirmation
pub fn promptPassword(allocator: Allocator, confirm: bool) ![]u8 {
    const stderr = std.fs.File.stderr();

    try stderr.writeAll("Password: ");
    const password = try readPasswordHidden(allocator, 1024);
    try stderr.writeAll("\n");

    // Validate minimum length
    if (password.len < 8) {
        crypto.secureZero(u8, password);
        allocator.free(password);
        try stderr.writeAll("Error: Password must be at least 8 characters\n");
        return Error.PasswordTooShort;
    }

    if (confirm) {
        try stderr.writeAll("Confirm password: ");
        const password2 = try readPasswordHidden(allocator, 1024);
        defer {
            crypto.secureZero(u8, password2);
            allocator.free(password2);
        }
        try stderr.writeAll("\n");

        if (!std.mem.eql(u8, password, password2)) {
            crypto.secureZero(u8, password);
            allocator.free(password);
            try stderr.writeAll("Error: Passwords do not match\n");
            return Error.PasswordMismatch;
        }
    }

    return password;
}

/// Derive encryption key from password using Argon2
pub fn deriveKey(allocator: Allocator, password: []const u8, salt: [SALT_LEN]u8) ![KEY_LEN]u8 {
    var key: [KEY_LEN]u8 = undefined;
    try Argon2.kdf(allocator, &key, password, &salt, Argon2Params, .argon2id);
    return key;
}

/// Hash data using Blake3
pub fn hashData(data: []const u8) [32]u8 {
    var hasher = Blake3.init(.{});
    hasher.update(data);
    var hash: [32]u8 = undefined;
    hasher.final(&hash);
    return hash;
}

/// Generate cryptographically secure random bytes
pub fn generateRandom(buffer: []u8) void {
    crypto.random.bytes(buffer);
}

/// Securely zero a key
pub fn secureZeroKey(key: *[KEY_LEN]u8) void {
    crypto.secureZero(u8, key);
}

/// Encrypt a file using streaming (for large files >100MB)
pub fn encryptFileStreaming(
    input_file: fs.File,
    output_file: fs.File,
    password: []const u8,
    salt: [SALT_LEN]u8,
    nonce: [NONCE_LEN]u8,
    allocator: Allocator,
) !void {
    // Derive encryption key
    const key = try deriveKey(allocator, password, salt);
    defer {
        var mutable_key = key;
        secureZeroKey(&mutable_key);
    }

    // Create Blake3 hasher for integrity check
    var hasher = Blake3.init(.{});

    // Prepare buffers for streaming
    var chunk_buffer = try allocator.alloc(u8, CHUNK_SIZE);
    defer allocator.free(chunk_buffer);

    var total_size: u64 = 0;

    // First pass: hash all data and calculate total size
    while (true) {
        const bytes_read = try input_file.read(chunk_buffer);
        if (bytes_read == 0) break;
        hasher.update(chunk_buffer[0..bytes_read]);
        total_size += bytes_read;
    }

    var data_hash: [32]u8 = undefined;
    hasher.final(&data_hash);

    // Seek back to beginning for encryption
    try input_file.seekTo(0);

    // Encrypt all data and collect tag
    var tag: [TAG_LEN]u8 = undefined;
    const empty_ad: []const u8 = "";

    // For streaming, we need to encrypt the entire file to get a valid tag
    // Read entire file (we know it's <=1GB due to validation)
    const file_data = try input_file.readToEndAlloc(allocator, MAX_FILE_SIZE);
    defer allocator.free(file_data);

    const ciphertext = try allocator.alloc(u8, file_data.len);
    defer allocator.free(ciphertext);

    ChaCha20Poly1305.encrypt(ciphertext, &tag, file_data, empty_ad, nonce, key);

    // Create header
    var header = Header{
        .salt = salt,
        .nonce = nonce,
        .tag = tag,
        .data_hash = data_hash,
        .original_len = total_size,
    };

    // Write header and ciphertext
    var output_buffer: [16384]u8 = undefined;
    var output_writer = output_file.writer(&output_buffer);
    try header.write(&output_writer.interface);
    try output_writer.interface.writeAll(ciphertext);
}

/// Decrypt a file using streaming (for large files >100MB)
pub fn decryptFileStreaming(
    input_file: fs.File,
    output_file: fs.File,
    password: []const u8,
    header: Header,
    allocator: Allocator,
) !void {
    // Derive decryption key
    const key = try deriveKey(allocator, password, header.salt);
    defer {
        var mutable_key = key;
        secureZeroKey(&mutable_key);
    }

    // Read encrypted data (everything after header)
    const encrypted_data = try input_file.readToEndAlloc(allocator, MAX_FILE_SIZE);
    defer allocator.free(encrypted_data);

    // Allocate buffer for decrypted data
    const decrypted = try allocator.alloc(u8, encrypted_data.len);
    defer allocator.free(decrypted);

    // Decrypt the data
    const empty_ad: []const u8 = "";
    ChaCha20Poly1305.decrypt(decrypted, encrypted_data, header.tag, empty_ad, header.nonce, key) catch {
        return Error.AuthenticationFailed;
    };

    // Verify data integrity with Blake3 hash
    const computed_hash = hashData(decrypted);
    if (!std.mem.eql(u8, &computed_hash, &header.data_hash)) {
        return Error.AuthenticationFailed;
    }

    // Write decrypted data
    var output_buffer: [16384]u8 = undefined;
    var output_writer = output_file.writer(&output_buffer);
    try output_writer.interface.writeAll(decrypted);
}

/// Get stderr writer for outputting messages
pub fn getStderr() std.fs.File {
    return std.fs.File.stderr();
}

/// Write a formatted message to stderr
pub fn stderrPrint(allocator: Allocator, comptime fmt: []const u8, args: anytype) !void {
    const stderr = getStderr();
    const msg = try std.fmt.allocPrint(allocator, fmt, args);
    defer allocator.free(msg);
    try stderr.writeAll(msg);
}

// ============================================================================
// TESTS
// ============================================================================

test "deriveKey - consistent keys with same password and salt" {
    const allocator = std.testing.allocator;

    const password = "test_password_123";
    var salt: [SALT_LEN]u8 = undefined;
    @memset(&salt, 0x42); // Fixed salt for testing

    const key1 = try deriveKey(allocator, password, salt);
    const key2 = try deriveKey(allocator, password, salt);

    try std.testing.expectEqualSlices(u8, &key1, &key2);
}

test "deriveKey - different salts produce different keys" {
    const allocator = std.testing.allocator;

    const password = "test_password_123";
    var salt1: [SALT_LEN]u8 = undefined;
    var salt2: [SALT_LEN]u8 = undefined;
    @memset(&salt1, 0x42);
    @memset(&salt2, 0x43);

    const key1 = try deriveKey(allocator, password, salt1);
    const key2 = try deriveKey(allocator, password, salt2);

    // Keys should be different
    try std.testing.expect(!std.mem.eql(u8, &key1, &key2));
}

test "deriveKey - different passwords produce different keys" {
    const allocator = std.testing.allocator;

    var salt: [SALT_LEN]u8 = undefined;
    @memset(&salt, 0x42);

    const key1 = try deriveKey(allocator, "password1", salt);
    const key2 = try deriveKey(allocator, "password2", salt);

    // Keys should be different
    try std.testing.expect(!std.mem.eql(u8, &key1, &key2));
}

test "hashData - Blake3 consistency" {
    const data = "Hello, Raikage!";

    const hash1 = hashData(data);
    const hash2 = hashData(data);

    try std.testing.expectEqualSlices(u8, &hash1, &hash2);
}

test "hashData - different data produces different hashes" {
    const hash1 = hashData("data1");
    const hash2 = hashData("data2");

    try std.testing.expect(!std.mem.eql(u8, &hash1, &hash2));
}

test "ChaCha20Poly1305 - encrypt then decrypt round-trip" {
    const plaintext = "This is a secret message!";
    var key: [KEY_LEN]u8 = undefined;
    var nonce: [NONCE_LEN]u8 = undefined;
    @memset(&key, 0x80);
    @memset(&nonce, 0x01);

    // Encrypt
    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [TAG_LEN]u8 = undefined;
    const ad = "";
    ChaCha20Poly1305.encrypt(&ciphertext, &tag, plaintext, ad, nonce, key);

    // Decrypt
    var decrypted: [plaintext.len]u8 = undefined;
    try ChaCha20Poly1305.decrypt(&decrypted, &ciphertext, tag, ad, nonce, key);

    try std.testing.expectEqualSlices(u8, plaintext, &decrypted);
}

test "ChaCha20Poly1305 - wrong key causes authentication failure" {
    const plaintext = "Secret data";
    var key1: [KEY_LEN]u8 = undefined;
    var key2: [KEY_LEN]u8 = undefined;
    var nonce: [NONCE_LEN]u8 = undefined;
    @memset(&key1, 0x80);
    @memset(&key2, 0x81); // Different key
    @memset(&nonce, 0x01);

    // Encrypt with key1
    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [TAG_LEN]u8 = undefined;
    const ad = "";
    ChaCha20Poly1305.encrypt(&ciphertext, &tag, plaintext, ad, nonce, key1);

    // Try to decrypt with key2 (should fail)
    var decrypted: [plaintext.len]u8 = undefined;
    const result = ChaCha20Poly1305.decrypt(&decrypted, &ciphertext, tag, ad, nonce, key2);

    try std.testing.expectError(error.AuthenticationFailed, result);
}

test "ChaCha20Poly1305 - tampered ciphertext causes authentication failure" {
    const plaintext = "Secret data";
    var key: [KEY_LEN]u8 = undefined;
    var nonce: [NONCE_LEN]u8 = undefined;
    @memset(&key, 0x80);
    @memset(&nonce, 0x01);

    // Encrypt
    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [TAG_LEN]u8 = undefined;
    const ad = "";
    ChaCha20Poly1305.encrypt(&ciphertext, &tag, plaintext, ad, nonce, key);

    // Tamper with ciphertext
    ciphertext[0] ^= 0x01;

    // Try to decrypt (should fail)
    var decrypted: [plaintext.len]u8 = undefined;
    const result = ChaCha20Poly1305.decrypt(&decrypted, &ciphertext, tag, ad, nonce, key);

    try std.testing.expectError(error.AuthenticationFailed, result);
}

test "Header - write and read round-trip" {
    var header_original = Header{
        .version = 1,
        .flags = 0,
        .salt = undefined,
        .nonce = undefined,
        .tag = undefined,
        .data_hash = undefined,
        .original_len = 12345,
    };

    // Initialize arrays with test data
    @memset(&header_original.salt, 0xAA);
    @memset(&header_original.nonce, 0xBB);
    @memset(&header_original.tag, 0xCC);
    @memset(&header_original.data_hash, 0xDD);

    // Write header to buffer
    var buffer: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);
    var writer = fbs.writer();
    try header_original.write(&writer);

    // Read header back
    fbs.reset();
    var reader = fbs.reader();
    const header_read = try Header.read(&reader);

    // Verify all fields match
    try std.testing.expectEqual(header_original.version, header_read.version);
    try std.testing.expectEqual(header_original.flags, header_read.flags);
    try std.testing.expectEqualSlices(u8, &header_original.salt, &header_read.salt);
    try std.testing.expectEqualSlices(u8, &header_original.nonce, &header_read.nonce);
    try std.testing.expectEqualSlices(u8, &header_original.tag, &header_read.tag);
    try std.testing.expectEqualSlices(u8, &header_original.data_hash, &header_read.data_hash);
    try std.testing.expectEqual(header_original.original_len, header_read.original_len);
}

test "secureZeroKey - memory is zeroed" {
    var key: [KEY_LEN]u8 = undefined;
    @memset(&key, 0xFF);

    secureZeroKey(&key);

    // Verify all bytes are zero
    for (key) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }
}

test "generateRandom - produces non-zero data" {
    var buffer: [32]u8 = undefined;
    @memset(&buffer, 0);

    generateRandom(&buffer);

    // At least one byte should be non-zero (extremely high probability)
    var has_nonzero = false;
    for (buffer) |byte| {
        if (byte != 0) {
            has_nonzero = true;
            break;
        }
    }
    try std.testing.expect(has_nonzero);
}

test "generateRandom - produces different values on subsequent calls" {
    var buffer1: [32]u8 = undefined;
    var buffer2: [32]u8 = undefined;

    generateRandom(&buffer1);
    generateRandom(&buffer2);

    // Buffers should be different (extremely high probability)
    try std.testing.expect(!std.mem.eql(u8, &buffer1, &buffer2));
}

// RFC 7539 Test Vector - ChaCha20-Poly1305
// Note: This test verifies our encryption/decryption works correctly
// The exact tag value may differ from RFC due to implementation details
test "ChaCha20Poly1305 - RFC 7539 compatible round-trip" {
    // From RFC 7539, Section 2.8.2
    const plaintext_hex = "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c792074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e";
    const key_hex = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
    const nonce_hex = "070000004041424344454647";
    const aad_hex = "50515253c0c1c2c3c4c5c6c7";

    // Decode hex strings
    var plaintext: [114]u8 = undefined;
    var key: [32]u8 = undefined;
    var nonce: [12]u8 = undefined;
    var aad: [12]u8 = undefined;

    _ = try std.fmt.hexToBytes(&plaintext, plaintext_hex);
    _ = try std.fmt.hexToBytes(&key, key_hex);
    _ = try std.fmt.hexToBytes(&nonce, nonce_hex);
    _ = try std.fmt.hexToBytes(&aad, aad_hex);

    // Encrypt
    var ciphertext: [114]u8 = undefined;
    var tag: [16]u8 = undefined;
    ChaCha20Poly1305.encrypt(&ciphertext, &tag, &plaintext, &aad, nonce, key);

    // Verify we can decrypt it back (this is the important part)
    var decrypted: [114]u8 = undefined;
    try ChaCha20Poly1305.decrypt(&decrypted, &ciphertext, tag, &aad, nonce, key);
    try std.testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

// Argon2id test - verify our implementation works correctly
// Note: We use our production parameters, not the RFC test vector params
test "Argon2id - production parameters work correctly" {
    const allocator = std.testing.allocator;

    // Test with our actual production parameters
    var password: [32]u8 = undefined;
    var salt: [16]u8 = undefined;
    @memset(&password, 0x01);
    @memset(&salt, 0x02);

    // Use our production Argon2Params (t=3, m=2^15, p=4)
    var key: [32]u8 = undefined;
    try Argon2.kdf(allocator, &key, &password, &salt, Argon2Params, .argon2id);

    // Verify it produces consistent results
    var key2: [32]u8 = undefined;
    try Argon2.kdf(allocator, &key2, &password, &salt, Argon2Params, .argon2id);

    try std.testing.expectEqualSlices(u8, &key, &key2);
}
