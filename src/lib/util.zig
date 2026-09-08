const std = @import("std");
const assert = std.debug.assert;

pub fn hamming_distance(first: []const u8, second: []const u8) usize {
    assert(first.len == second.len);

    var distance: usize = 0;

    for (0..first.len) |i| {
        const diff = first[i] ^ second[i];
        distance += @popCount(diff);
    }

    return distance;
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

test "Hamming distance" {
    const first_text = "this is a test";
    const second_text = "wokka wokka!!!";
    const expected_distance = 37;

    const distance = hamming_distance(first_text, second_text);

    try std.testing.expectEqual(expected_distance, distance);
}
