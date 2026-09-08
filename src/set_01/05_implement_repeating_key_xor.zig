const std = @import("std");
const stderr = std.debug;
const assert = std.debug.assert;
const cryto = std.crypto;
const hex = cryto.codecs.hex;
const Io = std.Io;

const stream = @import("cryptopalz").stream;

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);

    const io = init.io;

    var stdout_buffer: [1024]u8 = undefined;
    var stdout_file_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const stdout = &stdout_file_writer.interface;

    if (args.len != 3) {
        stderr.print("Please provide the plaintext and key as argument!\n", .{});

        return;
    }
    assert(args.len == 3);

    const ciphertext = try stream.repeating(allocator, args[1], args[2]);
    defer allocator.free(ciphertext);

    const encoded = try allocator.alloc(u8, ciphertext.len * 2);
    defer allocator.free(encoded);

    try hex.encode(encoded, ciphertext, .lower);

    try stdout.print("{s}\n", .{encoded});

    try stdout.flush();
}

test "Challenge 5" {
    const allocator = std.testing.allocator;

    const plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    const expected_ciphertext = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

    const ciphertext = try stream.repeating(allocator, plaintext, "ICE");
    defer allocator.free(ciphertext);

    const encoded = try allocator.alloc(u8, ciphertext.len * 2);
    defer allocator.free(encoded);

    try hex.encode(encoded, ciphertext, .lower);

    try std.testing.expectEqualStrings(expected_ciphertext, encoded);
}
