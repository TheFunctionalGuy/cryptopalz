const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const cryto = std.crypto;
const hex = cryto.codecs.hex;
const base64 = cryto.codecs.base64;
const variant = base64.Variant.standard;

const ChallengeContext = @import("cryptopalz").ChallengeContext;

pub fn challenge(context: ChallengeContext) !void {
    const allocator = context.allocator;
    const args = context.args;
    const stdout = context.stdout;
    const stderr = context.stderr;

    if (args.len != 2) {
        try stderr.print("Please provide a hex string as argument.\n", .{});

        return;
    }
    assert(args.len == 2);

    const hex_input = args[1];

    const base64_string = try hex_to_base64(allocator, hex_input);
    defer allocator.free(base64_string);

    try stdout.print("{s}\n", .{base64_string});

    try stdout.flush();
}

fn hex_to_base64(allocator: Allocator, hex_input: []const u8) ![]const u8 {
    assert(hex_input.len % 2 == 0);

    const unhexed = try allocator.alloc(u8, hex_input.len / 2);
    defer allocator.free(unhexed);

    try hex.decode(unhexed, hex_input);

    const base64_string_buffer = try allocator.alloc(u8, base64.encodedLen(unhexed.len, variant));
    errdefer allocator.free(base64_string_buffer);

    return try base64.encode(base64_string_buffer, unhexed, variant);
}

test "Challenge 1" {
    const hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    const expected_output = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    const base64_string = try hex_to_base64(std.testing.allocator, hex_string);
    defer std.testing.allocator.free(base64_string);

    try std.testing.expectEqualStrings(expected_output, base64_string);
}
