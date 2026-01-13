const std = @import("std");
const raikage = @import("raikage");

/// Example: Key Derivation using Argon2id
///
/// This example demonstrates how to use Raikage's key derivation function
/// to convert a password into a cryptographic key suitable for encryption.
///
/// Argon2id is used with these parameters:
/// - Time cost (t): 3 iterations
/// - Memory cost (m): 32MB (2^15 KB)
/// - Parallelism (p): 4 threads
///
/// Usage: zig build run-key-derivation
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== Raikage Key Derivation Example ===\n\n", .{});

    // Generate random salt (16 bytes)
    var salt: [raikage.SALT_LEN]u8 = undefined;
    raikage.generateRandom(&salt);

    std.debug.print("Generated salt ({} bytes):\n", .{salt.len});
    std.debug.print("  {X}\n\n", .{salt});

    // Derive key from password
    const password = "my_secure_password_123";
    std.debug.print("Deriving key from password: \"{s}\"\n", .{password});
    std.debug.print("Using Argon2id (t=3, m=32MB, p=4)...\n\n", .{});

    const start = std.time.milliTimestamp();
    const key = try raikage.deriveKey(allocator, password, salt);
    const elapsed = std.time.milliTimestamp() - start;

    defer {
        // Securely zero the key when done
        var mutable_key = key;
        raikage.secureZeroKey(&mutable_key);
    }

    std.debug.print("Key derived successfully in {}ms!\n", .{elapsed});
    std.debug.print("Derived key ({} bytes):\n", .{key.len});
    std.debug.print("  {X}\n\n", .{key});

    // Demonstrate that the same password + salt = same key
    const key2 = try raikage.deriveKey(allocator, password, salt);
    defer {
        var mutable_key2 = key2;
        raikage.secureZeroKey(&mutable_key2);
    }

    const keys_match = std.mem.eql(u8, &key, &key2);
    std.debug.print("Verification: Same password + salt produces same key? {}\n", .{keys_match});

    // Demonstrate that different salt = different key
    var different_salt: [raikage.SALT_LEN]u8 = undefined;
    raikage.generateRandom(&different_salt);

    const key3 = try raikage.deriveKey(allocator, password, different_salt);
    defer {
        var mutable_key3 = key3;
        raikage.secureZeroKey(&mutable_key3);
    }

    const keys_different = !std.mem.eql(u8, &key, &key3);
    std.debug.print("Verification: Different salt produces different key? {}\n", .{keys_different});

    std.debug.print("\n✓ Key derivation completed successfully!\n", .{});
}
