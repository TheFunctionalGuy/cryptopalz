const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;
const eql = std.mem.eql;
const refAllDecls = std.testing.refAllDecls;

const ChallengeContext = @import("cryptopalz").ChallengeContext;

const challenge_01 = @import("set_01/01_convert_hex_to_base64.zig");
const challenge_02 = @import("set_01/02_fixed_xor.zig");
const challenge_03 = @import("set_01/03_single_byte_xor_cipher.zig");
const challenge_04 = @import("set_01/04_detect_single_character_xor.zig");
const challenge_05 = @import("set_01/05_implement_repeating_key_xor.zig");
const challenge_06 = @import("set_01/06_break_repeating_key_xor.zig");
const challenge_07 = @import("set_01/07_aes_in_ecb_mode.zig");
const challenge_08 = @import("set_01/08_detect_aes_in_cbc_mode.zig");
const challenge_09 = @import("set_02/09_implement_pkcs7_padding.zig");
const challenge_10 = @import("set_02/10_implement_cbc_mode.zig");
const challenge_11 = @import("set_02/11_an_ebc_cbc_detection_oracle.zig");

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);

    const io = init.io;

    var stdout_buffer: [1024]u8 = undefined;
    var stdout_file_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const stdout = &stdout_file_writer.interface;

    var stderr_file_writer: Io.File.Writer = .init(.stderr(), io, &.{});
    const stderr = &stderr_file_writer.interface;

    if (args.len < 2) {
        const example = try std.mem.concat(allocator, u8, &.{ args[0], " 01 <ARGS_TO_CHALLENGE>" });
        defer allocator.free(example);

        try stderr.print("Please select a challenge by providing a challenge number.\n\n", .{});
        try stderr.print("Example: {s}\n", .{example});

        return;
    }
    assert(args.len >= 2);

    const context = ChallengeContext{
        .allocator = allocator,
        .stdout = stdout,
        .stderr = stderr,
        .args = args[1..],
        .io = io,
    };

    // Convert hex to base64:
    // https://cryptopals.com/sets/1/challenges/1
    if (eql(u8, args[1], "1") or eql(u8, args[1], "01")) {
        return challenge_01.challenge(context);
    }
    // Fixed XOR:
    // https://cryptopals.com/sets/1/challenges/2
    if (eql(u8, args[1], "2") or eql(u8, args[1], "02")) {
        return challenge_02.challenge(context);
    }
    // Single-byte XOR cipher:
    // https://cryptopals.com/sets/1/challenges/3
    if (eql(u8, args[1], "3") or eql(u8, args[1], "03")) {
        return challenge_03.challenge(context);
    }
    // Detect single-character XOR:
    // https://cryptopals.com/sets/1/challenges/4
    if (eql(u8, args[1], "4") or eql(u8, args[1], "04")) {
        return challenge_04.challenge(context);
    }
    // Implement repeating-key XOR:
    // https://cryptopals.com/sets/1/challenges/5
    if (eql(u8, args[1], "5") or eql(u8, args[1], "05")) {
        return challenge_05.challenge(context);
    }
    // Break repeating-key XOR:
    // https://cryptopals.com/sets/1/challenges/6
    if (eql(u8, args[1], "6") or eql(u8, args[1], "06")) {
        return challenge_06.challenge(context);
    }
    // AES in ECB mode:
    // https://cryptopals.com/sets/1/challenges/7
    if (eql(u8, args[1], "7") or eql(u8, args[1], "07")) {
        return challenge_07.challenge(context);
    }
    // Detect AES in ECB mode:
    // https://cryptopals.com/sets/1/challenges/8
    if (eql(u8, args[1], "8") or eql(u8, args[1], "08")) {
        return challenge_08.challenge(context);
    }
    // Implement PKCS#7 padding:
    // https://cryptopals.com/sets/2/challenges/9
    if (eql(u8, args[1], "9") or eql(u8, args[1], "09")) {
        return challenge_09.challenge(context);
    }
    // Implement CBC mode:
    // https://cryptopals.com/sets/2/challenges/10
    if (eql(u8, args[1], "10")) {
        return challenge_10.challenge(context);
    }
    // An ECB/CBC detection oracle:
    // https://cryptopals.com/sets/2/challenges/11
    if (eql(u8, args[1], "11")) {
        return challenge_11.challenge(context);
    }

    try stderr.print("Please provide valid challenge number.\n", .{});
}

test "Challanges" {
    refAllDecls(challenge_01);
    refAllDecls(challenge_02);
    refAllDecls(challenge_03);
    refAllDecls(challenge_04);
    refAllDecls(challenge_05);
    refAllDecls(challenge_06);
    refAllDecls(challenge_07);
    refAllDecls(challenge_08);
    refAllDecls(challenge_09);
    refAllDecls(challenge_10);
    refAllDecls(challenge_11);
}
