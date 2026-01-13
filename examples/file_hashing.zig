const std = @import("std");
const raikage = @import("raikage");

/// Example: File Hashing using Blake3
///
/// This example demonstrates how to use Raikage's Blake3 hashing function
/// to compute cryptographic hashes of files for integrity verification.
///
/// Blake3 produces 256-bit (32 byte) hashes that can be used for:
/// - File integrity verification
/// - Deduplication
/// - Content-addressed storage
/// - Digital signatures
///
/// Usage: zig build run-file-hashing
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== Raikage File Hashing Example ===\n\n", .{});

    // Create a test file
    const test_filename = "example_test_file.txt";
    const test_content = "Hello, Raikage! This is a test file for Blake3 hashing.";

    std.debug.print("Creating test file: {s}\n", .{test_filename});
    std.debug.print("Content: \"{s}\"\n\n", .{test_content});

    {
        const file = try std.fs.cwd().createFile(test_filename, .{});
        defer file.close();
        try file.writeAll(test_content);
    }

    // Open and hash the file
    std.debug.print("Computing Blake3 hash...\n", .{});

    const file = try std.fs.cwd().openFile(test_filename, .{});
    defer file.close();

    const data = try file.readToEndAlloc(allocator, raikage.MAX_FILE_SIZE);
    defer allocator.free(data);

    const hash = raikage.hashData(data);

    std.debug.print("Blake3 hash ({} bytes):\n", .{hash.len});
    std.debug.print("  Hex: {X}\n", .{hash});
    std.debug.print("  Base64: ", .{});

    // Print base64 encoded hash
    var base64_buf: [64]u8 = undefined;
    const base64_encoder = std.base64.standard.Encoder;
    const encoded = base64_encoder.encode(&base64_buf, &hash);
    std.debug.print("{s}\n\n", .{encoded});

    // Demonstrate hash consistency
    std.debug.print("Verifying hash consistency...\n", .{});
    const hash2 = raikage.hashData(data);
    const hashes_match = std.mem.eql(u8, &hash, &hash2);
    std.debug.print("Same content produces same hash? {}\n", .{hashes_match});

    // Demonstrate hash changes with content
    const different_content = "Different content produces different hash!";
    const hash3 = raikage.hashData(different_content);
    const hashes_different = !std.mem.eql(u8, &hash, &hash3);
    std.debug.print("Different content produces different hash? {}\n", .{hashes_different});

    // Clean up test file
    try std.fs.cwd().deleteFile(test_filename);
    std.debug.print("\nTest file cleaned up.\n", .{});

    std.debug.print("\n✓ File hashing completed successfully!\n", .{});
}
