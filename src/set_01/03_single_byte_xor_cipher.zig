const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const ascii = std.ascii;
const assert = std.debug.assert;
const cryto = std.crypto;
const hex = cryto.codecs.hex;

const ChallengeContext = @import("cryptopalz").ChallengeContext;
const stream = @import("cryptopalz").stream;

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

    const key_result = try stream.find_key(allocator, hex_input);

    try stdout.print("0x{x:02}\n", .{key_result.key});

    try stdout.flush();
}

test "Challenge 3" {
    const allocator = std.testing.allocator;
    const ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    const expected_key = 'X';

    const key_result = try stream.find_key(allocator, ciphertext);

    try std.testing.expectEqual(expected_key, key_result.key);
}
