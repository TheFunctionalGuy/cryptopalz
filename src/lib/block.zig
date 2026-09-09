const std = @import("std");
const Allocator = std.mem.Allocator;
const aes = std.crypto.core.aes;

const util = @import("util.zig");

pub fn aes_cbc_encrypt(
    allocator: Allocator,
    iv: *const [16]u8,
    plaintext: []const u8,
    key: *const [16]u8,
) ![]const u8 {
    const padded_plaintext = try util.pkcs7(allocator, plaintext, 16);
    defer allocator.free(padded_plaintext);

    const ciphertext = try allocator.alloc(u8, padded_plaintext.len);

    var previous_ciphertext_block = iv;
    const aes_128 = aes.Aes128.initEnc(key.*);

    var i: usize = 0;
    while (i < padded_plaintext.len) : (i += 16) {
        var plaintext_block: [16]u8 = undefined;
        @memcpy(&plaintext_block, padded_plaintext[i..][0..16]);
        const ciphertext_block = ciphertext[i..][0..16];

        for (0..plaintext_block.len) |m| {
            plaintext_block[m] ^= previous_ciphertext_block[m];
        }

        aes_128.encrypt(ciphertext_block, &plaintext_block);

        previous_ciphertext_block = ciphertext_block;
    }

    return ciphertext;
}

pub fn aes_cbc_decrypt(
    allocator: Allocator,
    iv: *const [16]u8,
    ciphertext: []const u8,
    key: *const [16]u8,
) ![]const u8 {
    const padded_plaintext = try allocator.alloc(u8, ciphertext.len);
    defer allocator.free(padded_plaintext);

    var previous_ciphertext_block = iv;
    const aes_128 = aes.Aes128.initDec(key.*);

    var i: usize = 0;
    while (i < ciphertext.len) : (i += 16) {
        const ciphertext_block = ciphertext[i..][0..16];
        var plaintext_block = padded_plaintext[i..][0..16];

        aes_128.decrypt(plaintext_block, ciphertext_block);

        for (0..plaintext_block.len) |m| {
            plaintext_block[m] ^= previous_ciphertext_block[m];
        }

        previous_ciphertext_block = ciphertext_block;
    }

    return try util.remove_pkcs7(allocator, padded_plaintext);
}

test "AES-CBC" {
    const allocator = std.testing.allocator;

    const input = "This is a test input";
    const iv = [_]u8{0x00} ** 16;
    const key = "YELLOW SUBMARINE";

    const ciphertext = try aes_cbc_encrypt(allocator, &iv, input, key);
    defer allocator.free(ciphertext);

    const plaintext = try aes_cbc_decrypt(allocator, &iv, ciphertext, key);
    defer allocator.free(plaintext);

    try std.testing.expectEqualStrings(input, plaintext);
}
