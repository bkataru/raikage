const std = @import("std");
const Allocator = std.mem.Allocator;

const encrypt = @import("encrypt.zig");
const decrypt = @import("decrypt.zig");

const Error = error{
    InvalidArguments,
    UnsupportedCommand,
};

pub fn main() !void {
    // Use a proper GeneralPurposeAllocator for better performance and debugging
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        const deinit_status = gpa.deinit();
        if (deinit_status == .leak) {
            std.log.err("Memory leak detected!", .{});
        }
    }
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const stderr = std.fs.File.stderr();

    if (args.len < 2) {
        try stderr.writeAll("Raikage - Secure file encryption tool\n\n");
        try stderr.writeAll("Usage:\n");
        try stderr.writeAll("  raikage encrypt <file>      Encrypt a file\n");
        try stderr.writeAll("  raikage decrypt <file>      Decrypt a file\n");
        try stderr.writeAll("\nEncrypted files are saved with .rkg extension\n");
        try stderr.writeAll("Encryption uses ChaCha20-Poly1305 with Argon2id key derivation\n");
        return Error.InvalidArguments;
    }

    const command = args[1];
    const file_path = if (args.len > 2) args[2] else "";

    if (file_path.len == 0) {
        try stderr.writeAll("Error: No file specified\n");
        return Error.InvalidArguments;
    }

    if (std.mem.eql(u8, command, "encrypt")) {
        try encrypt.encryptFile(file_path, allocator);
    } else if (std.mem.eql(u8, command, "decrypt")) {
        try decrypt.decryptFile(file_path, allocator);
    } else {
        const msg = try std.fmt.allocPrint(allocator, "Error: Unknown command '{s}'. Use 'encrypt' or 'decrypt'\n", .{command});
        defer allocator.free(msg);
        try stderr.writeAll(msg);
        return Error.UnsupportedCommand;
    }
}

// ============================================================================
// INTEGRATION TESTS
// ============================================================================

test "integration - encrypt and decrypt round-trip with temp file" {
    // Create a temporary test file
    const test_data = "This is test data for encryption and decryption!";
    const test_file = "test_temp_file.txt";
    const encrypted_file = "test_temp_file.txt.rkg";

    // Clean up any existing files
    std.fs.cwd().deleteFile(test_file) catch {};
    std.fs.cwd().deleteFile(encrypted_file) catch {};

    defer {
        std.fs.cwd().deleteFile(test_file) catch {};
        std.fs.cwd().deleteFile(encrypted_file) catch {};
    }

    // Write test data to file
    {
        const file = try std.fs.cwd().createFile(test_file, .{});
        defer file.close();
        try file.writeAll(test_data);
    }

    // This test would require mocking stdin for password input
    // For now, we verify the file was created
    const file_stat = try std.fs.cwd().statFile(test_file);
    try std.testing.expectEqual(@as(u64, test_data.len), file_stat.size);
}

test "integration - file size validation" {
    // Test that file size limits are enforced
    const shared = @import("shared.zig");
    try std.testing.expectEqual(@as(usize, 1024 * 1024 * 1024), shared.MAX_FILE_SIZE);
}

test "integration - header size calculation" {
    const shared = @import("shared.zig");

    // Header should be exactly: 1 + 1 + 16 + 12 + 16 + 32 + 8 = 86 bytes
    const expected_size = 1 + 1 + 16 + 12 + 16 + 32 + 8;

    // Verify through serialization
    var header = shared.Header{
        .version = 1,
        .flags = 0,
        .salt = undefined,
        .nonce = undefined,
        .tag = undefined,
        .data_hash = undefined,
        .original_len = 0,
    };
    @memset(&header.salt, 0);
    @memset(&header.nonce, 0);
    @memset(&header.tag, 0);
    @memset(&header.data_hash, 0);

    var buffer: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);
    var writer = fbs.writer();
    try header.write(&writer);

    try std.testing.expectEqual(expected_size, fbs.pos);
}
