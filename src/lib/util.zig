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

test "Hamming distance" {
    const first_text = "this is a test";
    const second_text = "wokka wokka!!!";
    const expected_distance = 37;

    const distance = hamming_distance(first_text, second_text);

    try std.testing.expectEqual(expected_distance, distance);
}
