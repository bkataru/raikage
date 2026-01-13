const std = @import("std");
const fs = std.fs;
const Allocator = std.mem.Allocator;
const shared = @import("shared.zig");

const ChaCha20Poly1305 = shared.ChaCha20Poly1305;

/// Decrypt a file encrypted with ChaCha20-Poly1305
pub fn decryptFile(input_path: []const u8, allocator: Allocator) !void {
    const stderr = shared.getStderr();

    try shared.stderrPrint(allocator, "Reading encrypted file: {s}\n", .{input_path});

    // Open encrypted file to read header
    const input_file = try fs.cwd().openFile(input_path, .{});
    defer input_file.close();

    const file_stat = try input_file.stat();
    const file_size = file_stat.size;

    // Validate minimum file size
    const header_size = @sizeOf(shared.Header);
    if (file_size < header_size) {
        try stderr.writeAll("Error: File too small to be valid\n");
        return shared.Error.InvalidFile;
    }

    // Read just the header first
    var header_bytes: [86]u8 = undefined;
    const bytes_read = try input_file.read(&header_bytes);
    if (bytes_read < 86) {
        try stderr.writeAll("Error: Could not read complete header\n");
        return shared.Error.InvalidFile;
    }

    // Parse header
    var fbs = std.io.fixedBufferStream(&header_bytes);
    var reader = fbs.reader();
    const header = try shared.Header.read(&reader);

    // Validate version
    if (header.version != 1) {
        try shared.stderrPrint(allocator, "Error: Unsupported file version {d}\n", .{header.version});
        return shared.Error.InvalidFile;
    }

    // Get password (no confirmation for decryption)
    const password = try shared.promptPassword(allocator, false);
    defer {
        std.crypto.secureZero(u8, password);
        allocator.free(password);
    }

    // Determine output filename (remove .rkg extension)
    var output_path: []const u8 = undefined;
    var path_allocated = false;
    defer if (path_allocated) allocator.free(output_path);

    if (std.mem.endsWith(u8, input_path, ".rkg")) {
        output_path = input_path[0 .. input_path.len - 4];
    } else {
        // If no .rkg extension, add .decrypted
        const new_path = try allocator.alloc(u8, input_path.len + 10);
        @memcpy(new_path[0..input_path.len], input_path);
        @memcpy(new_path[input_path.len..], ".decrypted");
        output_path = new_path;
        path_allocated = true;
    }

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
        const bytes_read_resp = try stdin.interface.readSliceShort(&response);
        if (bytes_read_resp == 0 or (response[0] != 'y' and response[0] != 'Y')) {
            try stderr.writeAll("Decryption cancelled.\n");
            return;
        }
    }

    // Determine if we should use streaming based on file size
    if (file_size >= shared.STREAMING_THRESHOLD) {
        try shared.stderrPrint(allocator, "Using streaming mode for large file...\n", .{});

        // Create output file
        const output_file = try fs.cwd().createFile(output_path, .{});
        defer output_file.close();

        // Re-open input file for streaming (skip past header)
        const input_file_stream = try fs.cwd().openFile(input_path, .{});
        defer input_file_stream.close();
        try input_file_stream.seekTo(86); // Skip header

        try shared.decryptFileStreaming(input_file_stream, output_file, password, header, allocator);
    } else {
        // Use in-memory decryption for smaller files
        // Read encrypted file
        const file_data = try fs.cwd().readFileAlloc(allocator, input_path, shared.MAX_FILE_SIZE);
        defer allocator.free(file_data);

        // Extract encrypted data (everything after header)
        const encrypted_data = file_data[header_size..];

        // Validate encrypted data size
        if (encrypted_data.len < shared.TAG_LEN) {
            try stderr.writeAll("Error: Invalid encrypted file\n");
            return shared.Error.InvalidFile;
        }

        // The ciphertext is everything except we already have the tag in the header
        const ciphertext = encrypted_data;

        // Derive decryption key
        const key = try shared.deriveKey(allocator, password, header.salt);

        // Allocate buffer for decrypted data
        const decrypted = try allocator.alloc(u8, ciphertext.len);
        defer allocator.free(decrypted);

        // Decrypt the data
        const empty_ad: []const u8 = "";
        ChaCha20Poly1305.decrypt(decrypted, ciphertext, header.tag, empty_ad, header.nonce, key) catch {
            try stderr.writeAll("Error: Authentication failed - wrong password or corrupted file\n");
            return shared.Error.AuthenticationFailed;
        };

        // Verify data integrity with Blake3 hash
        const computed_hash = shared.hashData(decrypted);
        if (!std.mem.eql(u8, &computed_hash, &header.data_hash)) {
            try stderr.writeAll("Error: Data integrity check failed\n");
            return shared.Error.AuthenticationFailed;
        }

        // Validate decrypted size matches header
        const expected_len = header.original_len;
        if (decrypted.len != expected_len) {
            try stderr.writeAll("Error: Decrypted size mismatch\n");
            return shared.Error.InvalidFile;
        }

        // Write decrypted file
        const output_file = try fs.cwd().createFile(output_path, .{});
        defer output_file.close();

        var writer_buffer: [16384]u8 = undefined; // Increased buffer size
        var writer = output_file.writer(&writer_buffer);
        try writer.interface.writeAll(decrypted);

        // Securely zero the key
        var mutable_key = key;
        shared.secureZeroKey(&mutable_key);
    }

    try shared.stderrPrint(allocator, "Successfully decrypted to: {s}\n", .{output_path});
    try shared.stderrPrint(allocator, "Original size: {d} bytes\n", .{header.original_len});
}
