const std = @import("std");
const stderr = std.debug;
const aes = std.crypto.core.aes;
const assert = std.debug.assert;
const cryto = std.crypto;
const base64 = cryto.codecs.base64;
const Io = std.Io;

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);

    const io = init.io;

    var stdout_buffer: [1024]u8 = undefined;
    var stdout_file_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const stdout = &stdout_file_writer.interface;

    if (args.len != 2) {
        stderr.print("Please provide a file as argument!\n", .{});

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
        const src: *const [16]u8 = @ptrCast(decoded[start .. start + 16]);
        const dst: *[16]u8 = @ptrCast(plaintext[start .. start + 16]);

        aes_128.decrypt(dst, src);
    }

    try stdout.print("{s}\n", .{plaintext});

    try stdout.flush();
}
