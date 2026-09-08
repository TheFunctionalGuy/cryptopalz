//! By convention, root.zig is the root source file when making a package.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Writer = std.Io.Writer;
const refAllDecls = std.testing.refAllDecls;

pub const stream = @import("lib/stream.zig");
pub const util = @import("lib/util.zig");

pub const ChallengeContext = struct {
    allocator: Allocator,
    stdout: *Writer,
    stderr: *Writer,
    args: []const []const u8,
    io: Io,
};

test "Libraries" {
    refAllDecls(stream);
    refAllDecls(util);
}
