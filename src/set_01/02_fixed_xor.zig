const std = @import("std");
const stderr = std.debug;
const assert = std.debug.assert;
const cryto = std.crypto;
const hex = cryto.codecs.hex;
const Allocator = std.mem.Allocator;
const Io = std.Io;

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);

    const io = init.io;

    var stdout_buffer: [1024]u8 = undefined;
    var stdout_file_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const stdout = &stdout_file_writer.interface;

    if (args.len != 3) {
        stderr.print("Please provide two hex strings as argument!\n", .{});

        return;
    }
    assert(args.len == 3);

    const xored = try fixed_xor(allocator, args[1], args[2]);
    defer allocator.free(xored);

    try stdout.print("{s}\n", .{xored});

    try stdout.flush();
}

// TODO: This can also be converted to comptime version using length of input as input.
// Then all the allocator shenanigans are not required anymore.
fn fixed_xor(allocator: Allocator, first: []const u8, second: []const u8) ![]u8 {
    assert(first.len == second.len);
    assert(first.len % 2 == 0);

    const first_decoded = try allocator.alloc(u8, first.len / 2);
    defer allocator.free(first_decoded);

    try hex.decode(first_decoded, first);

    const second_decoded = try allocator.alloc(u8, second.len / 2);
    defer allocator.free(second_decoded);

    try hex.decode(second_decoded, second);

    var xored = try allocator.alloc(u8, first_decoded.len);
    defer allocator.free(xored);

    for (0..first_decoded.len) |i| {
        xored[i] = first_decoded[i] ^ second_decoded[i];
    }

    const xored_encoded = try allocator.alloc(u8, first.len);
    errdefer allocator.free(xored_encoded);

    try hex.encode(xored_encoded, xored, .lower);

    return xored_encoded;
}

test "Challenge 2" {
    const allocator = std.testing.allocator;

    const first_input = "1c0111001f010100061a024b53535009181c";
    const second_input = "686974207468652062756c6c277320657965";
    const expected_output = "746865206b696420646f6e277420706c6179";

    const actual_output = try fixed_xor(allocator, first_input, second_input);
    defer allocator.free(actual_output);

    try std.testing.expectEqualStrings(expected_output, actual_output);
}
