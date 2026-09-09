const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

pub fn hamming_distance(
    first: []const u8,
    second: []const u8,
) usize {
    assert(first.len == second.len);

    var distance: usize = 0;

    for (0..first.len) |i| {
        const diff = first[i] ^ second[i];
        distance += @popCount(diff);
    }

    return distance;
}

test "Hamming distance" {
    const first_text = "this is a test";
    const second_text = "wokka wokka!!!";
    const expected_distance = 37;

    const distance = hamming_distance(first_text, second_text);

    try std.testing.expectEqual(expected_distance, distance);
}

pub fn windowed_normalized_hamming_distance(
    comptime window_count: usize,
    input: []const u8,
    keysize: usize,
) f64 {
    var distance: f64 = 0;

    // Compare every pair of blocks in the window.
    inline for (0..window_count) |i| {
        const first = input[i * keysize .. (i + 1) * keysize];

        inline for (i + 1..window_count) |j| {
            const second = input[j * keysize .. (j + 1) * keysize];

            distance += @as(f64, @floatFromInt(
                hamming_distance(first, second),
            )) / @as(f64, @floatFromInt(keysize));
        }
    }

    return distance;
}

pub fn pkcs7(
    allocator: Allocator,
    input: []const u8,
    block_size: usize,
) ![]u8 {
    const padding_length: u8 = @intCast(block_size - (input.len % block_size));

    const padding = try allocator.alloc(u8, padding_length);
    defer allocator.free(padding);

    @memset(padding, padding_length);

    return try std.mem.concat(allocator, u8, &.{ input, padding });
}

pub fn remove_pkcs7(
    allocator: Allocator,
    input: []const u8,
) ![]u8 {
    const padding_length: u8 = input[input.len - 1];

    const unpadded = try allocator.alloc(u8, input.len - padding_length);
    @memcpy(unpadded, input[0..unpadded.len]);

    return unpadded;
}

test "PKCS#7 - Full block" {
    const allocator = std.testing.allocator;

    const input = "YELLOW SUBMARINE";
    const expected_output = "YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10";

    const padded_input = try pkcs7(allocator, input, 16);
    defer allocator.free(padded_input);

    try std.testing.expectEqualStrings(expected_output, padded_input);
}

test "PKCS#7 - One missing" {
    const allocator = std.testing.allocator;

    const input = "YELLOW SUBMARIN";
    const expected_output = "YELLOW SUBMARIN\x01";

    const padded_input = try pkcs7(allocator, input, 16);
    defer allocator.free(padded_input);

    try std.testing.expectEqualStrings(expected_output, padded_input);
}

test "PKCS#7 - Inverse" {
    const allocator = std.testing.allocator;

    const input = "YELLOW SUBMARINE";

    const padded_input = try pkcs7(allocator, input, 16);
    defer allocator.free(padded_input);

    const depadded_input = try remove_pkcs7(allocator, padded_input);
    defer allocator.free(depadded_input);

    try std.testing.expectEqualStrings(input, depadded_input);
}
