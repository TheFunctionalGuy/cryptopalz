//! By convention, root.zig is the root source file when making a package.
pub const stream = @import("lib/stream.zig");
pub const util = @import("lib/util.zig");

test "root" {
    _ = util;
}
