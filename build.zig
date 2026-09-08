const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    {
        const mod = b.addModule("cryptopalz", .{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
        });

        // Set 01 challenges
        const challenges = [_]struct {
            name: []const u8,
            path: []const u8,
        }{
            .{
                .name = "01_convert_hex_to_base64",
                .path = "src/set_01/01_convert_hex_to_base64.zig",
            },
            .{
                .name = "02_fixed_xor",
                .path = "src/set_01/02_fixed_xor.zig",
            },
            .{
                .name = "03_single_byte_xor_cipher",
                .path = "src/set_01/03_single_byte_xor_cipher.zig",
            },
            .{
                .name = "04_detect_single_character_xor",
                .path = "src/set_01/04_detect_single_character_xor.zig",
            },
            .{
                .name = "05_implement_repeating_key_xor",
                .path = "src/set_01/05_implement_repeating_key_xor.zig",
            },
            .{
                .name = "06_break_repeating_key_xor",
                .path = "src/set_01/06_break_repeating_key_xor.zig",
            },
            .{
                .name = "07_aes_in_ecb_mode",
                .path = "src/set_01/07_aes_in_ecb_mode.zig",
            },
        };

        const test_step = b.step("test", "Run tests");

        for (challenges) |challenge| {
            // === zig build (install) ===
            {
                const exe = b.addExecutable(.{
                    .name = challenge.name,
                    .root_module = b.createModule(.{
                        .root_source_file = b.path(challenge.path),
                        .target = target,
                        .optimize = optimize,
                        .imports = &.{
                            .{ .name = "cryptopalz", .module = mod },
                        },
                    }),
                });

                b.installArtifact(exe);

                // === zig build run ===
                {
                    const step_name = try std.mem.concat(b.allocator, u8, &.{ "run-", challenge.name });
                    const step_description = try std.mem.concat(b.allocator, u8, &.{ "Run ", challenge.name, " executable" });
                    const run_step = b.step(step_name, step_description);

                    const run_cmd = b.addRunArtifact(exe);
                    run_step.dependOn(&run_cmd.step);

                    run_cmd.step.dependOn(b.getInstallStep());

                    if (b.args) |args| {
                        run_cmd.addArgs(args);
                    }
                }

                // === zig build test ===
                {
                    const mod_tests = b.addTest(.{
                        .root_module = mod,
                    });

                    const run_mod_tests = b.addRunArtifact(mod_tests);

                    const exe_tests = b.addTest(.{
                        .root_module = exe.root_module,
                    });

                    const run_exe_tests = b.addRunArtifact(exe_tests);

                    test_step.dependOn(&run_mod_tests.step);
                    test_step.dependOn(&run_exe_tests.step);
                }
            }
        }
    }
}
