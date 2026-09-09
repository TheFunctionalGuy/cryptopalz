const std = @import("std");
const Allocator = std.mem.Allocator;
const Csprng = std.Random.DefaultCsprng;
const Io = std.Io;

const ChallengeContext = @import("cryptopalz").ChallengeContext;
const block = @import("cryptopalz").block;

pub fn challenge(context: ChallengeContext) !void {
    const allocator = context.allocator;
    const stdout = context.stdout;
    const io = context.io;

    try aes_ecb_cbc_detector(allocator, io, stdout);

    try stdout.flush();
}

fn aes_ecb_cbc_detector(allocator: Allocator, io: Io, stdout: *Io.Writer) !void {
    const choosen_plaintext = [_]u8{0xAA} ** (16 * 4);

    const oracle_result = try aes_encryption_oracle(allocator, io, &choosen_plaintext);
    defer allocator.free(oracle_result.ciphertext);

    var blocks: std.StringHashMap(usize) = .init(allocator);
    defer blocks.deinit();

    var windows = std.mem.window(u8, oracle_result.ciphertext, 16, 16);

    while (windows.next()) |window| {
        if (blocks.getEntry(window)) |entry| {
            entry.value_ptr.* += 1;
        } else {
            try blocks.put(window, 0);
        }
    }

    var duplicated_blocks: usize = 0;
    var it = blocks.iterator();
    while (it.next()) |entry| {
        duplicated_blocks += entry.value_ptr.*;
    }

    const detected_mode = if (duplicated_blocks >= 2) block.ModeOfOperation.ECB else block.ModeOfOperation.CBC;

    if (detected_mode == oracle_result.mode) {
        try stdout.print("Detected: {s}\n", .{@tagName(detected_mode)});
    } else {
        try stdout.print("Guessed {s} but actually {s} was used.\n", .{ @tagName(detected_mode), @tagName(oracle_result.mode) });

        std.process.exit(1);
    }
}

const OracleResult = struct {
    mode: block.ModeOfOperation,
    ciphertext: []u8,
};

fn aes_encryption_oracle(allocator: Allocator, io: Io, plaintext: []const u8) !OracleResult {
    var secret_seed: [Csprng.secret_seed_length]u8 = undefined;
    io.random(&secret_seed);

    var csprng = Csprng.init(secret_seed);
    const random = csprng.random();

    const prefix_length = 5 + std.Random.uintAtMost(random, usize, 5);
    const prefix = try allocator.alloc(u8, prefix_length);
    defer allocator.free(prefix);
    io.random(prefix);

    const postfix_length = 5 + std.Random.uintAtMost(random, usize, 5);
    const postfix = try allocator.alloc(u8, postfix_length);
    defer allocator.free(postfix);
    io.random(postfix);

    const padded_plaintext = try std.mem.concat(allocator, u8, &.{ prefix, plaintext, postfix });
    defer allocator.free(padded_plaintext);

    const mode = std.Random.enumValue(random, block.ModeOfOperation);
    const key = random_key(io);

    switch (mode) {
        .ECB => return .{
            .mode = mode,
            .ciphertext = try block.aes_ecb_encrypt(allocator, padded_plaintext, &key),
        },
        .CBC => {
            const iv = random_key(io);

            return .{
                .mode = mode,
                .ciphertext = try block.aes_cbc_encrypt(allocator, &iv, padded_plaintext, &key),
            };
        },
    }
}

fn random_key(io: Io) [16]u8 {
    var random: [16]u8 = undefined;
    io.random(&random);

    return random;
}

test "Challenge 11" {}
