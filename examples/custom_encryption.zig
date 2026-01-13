const std = @import("std");
const raikage = @import("raikage");

/// Example: Custom Encryption Workflow
///
/// This example demonstrates how to use Raikage as a library to build
/// custom encryption workflows. It shows:
/// - Creating test files
/// - Encrypting files with streaming mode
/// - Decrypting files
/// - Verifying content integrity
///
/// Usage: zig build run-custom-encryption
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== Raikage Custom Encryption Example ===\n\n", .{});

    // Create a test file with some content
    const original_filename = "sensitive_data.txt";
    const encrypted_filename = "sensitive_data.txt.encrypted";
    const decrypted_filename = "sensitive_data_decrypted.txt";
    const password = "super_secret_password_123";

    const original_content =
        \\This is sensitive data that needs encryption!
        \\
        \\It contains multiple lines of text.
        \\The content will be encrypted using ChaCha20-Poly1305 AEAD.
        \\
        \\Raikage ensures:
        \\- Confidentiality (encryption)
        \\- Authenticity (authentication tag)
        \\- Integrity (Blake3 hash)
    ;

    // Step 1: Create original file
    std.debug.print("Step 1: Creating original file...\n", .{});
    std.debug.print("  File: {s}\n", .{original_filename});
    std.debug.print("  Size: {} bytes\n\n", .{original_content.len});

    {
        const file = try std.fs.cwd().createFile(original_filename, .{});
        defer file.close();
        try file.writeAll(original_content);
    }

    // Step 2: Encrypt the file
    std.debug.print("Step 2: Encrypting file...\n", .{});
    std.debug.print("  Password: \"{s}\"\n", .{password});
    std.debug.print("  Using ChaCha20-Poly1305 + Argon2id + Blake3\n", .{});

    var salt: [raikage.SALT_LEN]u8 = undefined;
    var nonce: [raikage.NONCE_LEN]u8 = undefined;
    raikage.generateRandom(&salt);
    raikage.generateRandom(&nonce);

    {
        const input_file = try std.fs.cwd().openFile(original_filename, .{});
        defer input_file.close();

        const output_file = try std.fs.cwd().createFile(encrypted_filename, .{});
        defer output_file.close();

        const start = std.time.milliTimestamp();
        try raikage.encryptFileStreaming(input_file, output_file, password, salt, nonce, allocator);
        const elapsed = std.time.milliTimestamp() - start;

        std.debug.print("  Encryption completed in {}ms\n", .{elapsed});
    }

    // Check encrypted file size
    {
        const stat = try std.fs.cwd().statFile(encrypted_filename);
        const overhead: i64 = @as(i64, @intCast(stat.size)) - @as(i64, @intCast(original_content.len));
        std.debug.print("  Encrypted size: {} bytes (overhead: {} bytes)\n\n", .{ stat.size, overhead });
    }

    // Step 3: Decrypt the file
    std.debug.print("Step 3: Decrypting file...\n", .{});

    {
        const encrypted_file = try std.fs.cwd().openFile(encrypted_filename, .{});
        defer encrypted_file.close();

        // Read header from encrypted file (same way as decrypt.zig does it)
        var header_bytes: [86]u8 = undefined;
        const bytes_read = try encrypted_file.read(&header_bytes);
        if (bytes_read < 86) {
            std.debug.print("Error: Could not read complete header\n", .{});
            return error.InvalidFile;
        }

        // Parse header using fixed buffer stream
        var fbs = std.io.fixedBufferStream(&header_bytes);
        var reader = fbs.reader();
        const header = try raikage.Header.read(&reader);

        const output_file = try std.fs.cwd().createFile(decrypted_filename, .{});
        defer output_file.close();

        const start = std.time.milliTimestamp();
        try raikage.decryptFileStreaming(encrypted_file, output_file, password, header, allocator);
        const elapsed = std.time.milliTimestamp() - start;

        std.debug.print("  Decryption completed in {}ms\n\n", .{elapsed});
    }

    // Step 4: Verify content integrity
    std.debug.print("Step 4: Verifying content integrity...\n", .{});

    const decrypted_file = try std.fs.cwd().openFile(decrypted_filename, .{});
    defer decrypted_file.close();

    const decrypted_content = try decrypted_file.readToEndAlloc(allocator, raikage.MAX_FILE_SIZE);
    defer allocator.free(decrypted_content);

    const content_matches = std.mem.eql(u8, original_content, decrypted_content);
    std.debug.print("  Original and decrypted content match? {}\n", .{content_matches});

    if (content_matches) {
        std.debug.print("  ✓ Content integrity verified!\n", .{});
    } else {
        std.debug.print("  ✗ Content mismatch! Possible corruption.\n", .{});
    }

    // Clean up
    std.debug.print("\nCleaning up test files...\n", .{});
    try std.fs.cwd().deleteFile(original_filename);
    try std.fs.cwd().deleteFile(encrypted_filename);
    try std.fs.cwd().deleteFile(decrypted_filename);

    std.debug.print("\n✓ Custom encryption workflow completed successfully!\n", .{});
}
