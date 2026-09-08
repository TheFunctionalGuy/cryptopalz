const std = @import("std");
const Allocator = std.mem.Allocator;
const ascii = std.ascii;
const assert = std.debug.assert;
const cryto = std.crypto;
const hex = cryto.codecs.hex;

const LETTER_FREQUENCY = [_]f64{
    0.0651738,
    0.0124248,
    0.0217339,
    0.0349835,
    0.1041442,
    0.0197881,
    0.0158610,
    0.0492888,
    0.0558094,
    0.0009033,
    0.0050529,
    0.0331490,
    0.0202124,
    0.0564513,
    0.0596302,
    0.0137645,
    0.0008606,
    0.0497563,
    0.0515760,
    0.0729357,
    0.0225134,
    0.0082903,
    0.0171272,
    0.0013692,
    0.0145984,
    0.0007836,
    0.1918182,
};

pub const KeyResult = struct {
    key: u8,
    score: f64,
};

pub fn find_key(allocator: Allocator, encoded_ciphertext: []const u8) !KeyResult {
    assert(encoded_ciphertext.len % 2 == 0);

    const ciphertext = try allocator.alloc(u8, encoded_ciphertext.len / 2);
    defer allocator.free(ciphertext);

    try hex.decode(ciphertext, encoded_ciphertext);

    return find_key_decoded(allocator, ciphertext);
}

pub fn find_key_decoded(allocator: Allocator, ciphertext: []const u8) !KeyResult {
    var best_score = std.math.floatMax(f64);
    var best_key: u8 = undefined;

    for (0x00..0x80) |key| {
        const current_score = try score(allocator, ciphertext, @intCast(key));

        if (current_score < best_score) {
            best_score = current_score;
            best_key = @intCast(key);
        }
    }

    return .{
        .key = best_key,
        .score = best_score,
    };
}

fn score(allocator: Allocator, ciphertext: []const u8, key: u8) !f64 {
    var result: f64 = 0.0;
    var letter_count: f64 = 0.0;
    var frequencies: [LETTER_FREQUENCY.len]f64 = undefined;

    const plaintext = try single(allocator, ciphertext, key);
    defer allocator.free(plaintext);

    for (plaintext) |character| {
        if (character == ' ') {
            letter_count += 1.0;
            frequencies[frequencies.len - 1] += 1.0;

            continue;
        }

        if (!ascii.isAlphabetic(character)) {
            continue;
        }

        letter_count += 1.0;

        const lower = ascii.toLower(character);

        frequencies[lower - 'a'] += 1.0;
    }

    for (0..frequencies.len) |i| {
        const diff = frequencies[i] / letter_count - LETTER_FREQUENCY[i];
        result += (diff * diff);
    }

    return result;
}

pub fn single(allocator: Allocator, plaintext: []const u8, key: u8) ![]u8 {
    const ciphertext = try allocator.alloc(u8, plaintext.len);

    for (0..plaintext.len) |i| {
        ciphertext[i] = plaintext[i] ^ key;
    }

    return ciphertext;
}

pub fn repeating(allocator: Allocator, plaintext: []const u8, key: []const u8) ![]u8 {
    const ciphertext = try allocator.alloc(u8, plaintext.len);

    for (0..plaintext.len) |i| {
        ciphertext[i] = plaintext[i] ^ key[i % key.len];
    }

    return ciphertext;
}
