const std = @import("std");
const aes = std.crypto.core.aes;
const assert = std.debug.assert;
const crypto = std.crypto;
const base64 = crypto.codecs.base64;

const ChallengeContext = @import("cryptopalz").ChallengeContext;

pub fn challenge(context: ChallengeContext) !void {
    const allocator = context.allocator;
    const args = context.args;
    const stdout = context.stdout;
    const stderr = context.stderr;
    const io = context.io;

    if (args.len != 2) {
        try stderr.print("Please provide an AES-128-ECB encrypted file as argument.\n", .{});

        return;
    }
    assert(args.len == 2);

    const input_file = try std.Io.Dir.cwd().readFileAlloc(
        io,
        args[1],
        allocator,
        .limited(1024 * 1024),
    );
    defer allocator.free(input_file);

    var len: usize = 0;

    for (input_file) |character| {
        if (character != '\n' and character != '\r') {
            input_file[len] = character;
            len += 1;
        }
    }
    const trimmed_input_file = input_file[0..len];

    const decoded_buffer = try allocator.alloc(u8, try base64.decodedLen(trimmed_input_file.len, .standard));
    defer allocator.free(decoded_buffer);

    const decoded = try base64.decode(decoded_buffer, trimmed_input_file, .standard);

    assert(decoded.len % 16 == 0);

    const plaintext = try allocator.alloc(u8, decoded.len);
    defer allocator.free(plaintext);

    const key: [16]u8 = .{ 0x59, 0x45, 0x4C, 0x4C, 0x4F, 0x57, 0x20, 0x53, 0x55, 0x42, 0x4D, 0x41, 0x52, 0x49, 0x4E, 0x45 }; // "YELLOW SUBMARINE";
    const aes_128 = aes.Aes128.initDec(key);

    var start: usize = 0;
    while (start < decoded.len) : (start += 16) {
        const src = decoded[start..][0..16];
        const dst = plaintext[start..][0..16];

        aes_128.decrypt(dst, src);
    }

    try stdout.print("{s}\n", .{plaintext});

    try stdout.flush();
}
