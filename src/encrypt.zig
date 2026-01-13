const std = @import("std");
const fs = std.fs;
const Allocator = std.mem.Allocator;
const shared = @import("shared.zig");

const ChaCha20Poly1305 = shared.ChaCha20Poly1305;

/// Encrypt a file with ChaCha20-Poly1305
pub fn encryptFile(input_path: []const u8, allocator: Allocator) !void {
    const stderr = shared.getStderr();

    try shared.stderrPrint(allocator, "Reading file: {s}\n", .{input_path});

    // Validate file exists and get size
    const input_file = try fs.cwd().openFile(input_path, .{});
    defer input_file.close();

    const file_stat = try input_file.stat();
    const file_size = file_stat.size;

    // Validate file size
    if (file_size > shared.MAX_FILE_SIZE) {
        try shared.stderrPrint(allocator, "Error: File too large (max {d} bytes)\n", .{shared.MAX_FILE_SIZE});
        return shared.Error.FileTooLarge;
    }

    try shared.stderrPrint(allocator, "File size: {d} bytes\n", .{file_size});

    // Get password with confirmation
    const password = try shared.promptPassword(allocator, true);
    defer {
        std.crypto.secureZero(u8, password);
        allocator.free(password);
    }

    // Generate cryptographically secure random salt and nonce
    var salt: [shared.SALT_LEN]u8 = undefined;
    var nonce: [shared.NONCE_LEN]u8 = undefined;
    shared.generateRandom(&salt);
    shared.generateRandom(&nonce);

    // Create output filename
    var output_path = try allocator.alloc(u8, input_path.len + 4);
    defer allocator.free(output_path);
    @memcpy(output_path[0..input_path.len], input_path);
    @memcpy(output_path[input_path.len..], ".rkg");

    // Check if output file already exists
    const file_exists = blk: {
        fs.cwd().access(output_path, .{}) catch {
            break :blk false;
        };
        break :blk true;
    };

    if (file_exists) {
        try shared.stderrPrint(allocator, "Warning: Output file '{s}' already exists. Overwrite? (y/N): ", .{output_path});
        var stdin_buffer: [16]u8 = undefined;
        var stdin = std.fs.File.stdin().reader(&stdin_buffer);
        var response: [2]u8 = undefined;
        const bytes_read = try stdin.interface.readSliceShort(&response);
        if (bytes_read == 0 or (response[0] != 'y' and response[0] != 'Y')) {
            try stderr.writeAll("Encryption cancelled.\n");
            return;
        }
    }

    // Determine if we should use streaming based on file size
    if (file_size >= shared.STREAMING_THRESHOLD) {
        try shared.stderrPrint(allocator, "Using streaming mode for large file...\n", .{});

        // Open output file
        const output_file = try fs.cwd().createFile(output_path, .{});
        defer output_file.close();

        // Re-open input file for streaming
        const input_file_stream = try fs.cwd().openFile(input_path, .{});
        defer input_file_stream.close();

        try shared.encryptFileStreaming(input_file_stream, output_file, password, salt, nonce, allocator);
    } else {
        // Use in-memory encryption for smaller files
        // Read file data
        const file_data = try input_file.readToEndAlloc(allocator, shared.MAX_FILE_SIZE);
        defer allocator.free(file_data);

        // Derive encryption key from password
        const key = try shared.deriveKey(allocator, password, salt);

        // Hash the original data for integrity checking
        const data_hash = shared.hashData(file_data);

        // Allocate buffer for ciphertext
        const ciphertext = try allocator.alloc(u8, file_data.len);
        defer allocator.free(ciphertext);

        // Encrypt the data
        var tag: [shared.TAG_LEN]u8 = undefined;
        const empty_ad: []const u8 = ""; // No additional authenticated data
        ChaCha20Poly1305.encrypt(ciphertext, &tag, file_data, empty_ad, nonce, key);

        // Build header
        var header = shared.Header{
            .salt = salt,
            .nonce = nonce,
            .tag = tag,
            .data_hash = data_hash,
            .original_len = @intCast(file_data.len),
        };

        // Write encrypted file
        const output_file = try fs.cwd().createFile(output_path, .{});
        defer output_file.close();

        var output_buffer: [16384]u8 = undefined; // Increased buffer size
        var output_writer = output_file.writer(&output_buffer);

        try header.write(&output_writer.interface);
        try output_writer.interface.writeAll(ciphertext);

        // Securely zero the key
        var mutable_key = key;
        shared.secureZeroKey(&mutable_key);
    }

    try shared.stderrPrint(allocator, "Successfully encrypted to: {s}\n", .{output_path});
}
