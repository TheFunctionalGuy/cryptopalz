const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

const ChallengeContext = @import("cryptopalz").ChallengeContext;
const util = @import("cryptopalz").util;

pub fn challenge(context: ChallengeContext) !void {
    const allocator = context.allocator;
    const args = context.args;
    const stdout = context.stdout;
    const stderr = context.stderr;

    if (args.len != 3) {
        try stderr.print("Please provide plaintext and block size as argument.\n", .{});

        return;
    }
    assert(args.len == 3);

    const plaintext = args[1];
    const block_size = try std.fmt.parseInt(usize, args[2], 10);

    const padded = try util.pkcs7(allocator, plaintext, block_size);
    defer allocator.free(padded);

    try stdout.printHex(padded, .lower);
    try stdout.print("\n", .{});

    try stdout.flush();
}

test "Challenge 9" {
    const allocator = std.testing.allocator;

    const input = "YELLOW SUBMARINE";
    const expected_output = "YELLOW SUBMARINE\x04\x04\x04\x04";

    const padded_input = try util.pkcs7(allocator, input, 20);
    defer allocator.free(padded_input);

    try std.testing.expectEqualStrings(expected_output, padded_input);
}
