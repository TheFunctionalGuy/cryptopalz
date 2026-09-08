const std = @import("std");
const stderr = std.debug;
const ascii = std.ascii;
const assert = std.debug.assert;
const cryto = std.crypto;
const hex = cryto.codecs.hex;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const stream = @import("cryptopalz").stream;

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);

    const io = init.io;

    var stdout_buffer: [1024]u8 = undefined;
    var stdout_file_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const stdout = &stdout_file_writer.interface;

    if (args.len != 2) {
        stderr.print("Please provide a hex string as argument!\n", .{});

        return;
    }
    assert(args.len == 2);

    const hex_input = args[1];

    const key_result = try stream.find_key(allocator, hex_input);

    try stdout.print("{c}\n", .{key_result.key});

    try stdout.flush();
}

test "Challenge 3" {
    const allocator = std.testing.allocator;
    const ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    const expected_key = 'X';

    const key_result = try stream.find_key(allocator, ciphertext);

    try std.testing.expectEqual(expected_key, key_result.key);
}
