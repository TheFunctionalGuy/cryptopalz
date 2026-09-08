const std = @import("std");
const stderr = std.debug;
const assert = std.debug.assert;
const cryto = std.crypto;
const mem = std.mem;
const base64 = cryto.codecs.base64;
const Allocator = mem.Allocator;
const Io = std.Io;

const stream = @import("cryptopalz").stream;
const util = @import("cryptopalz").util;

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

    const plaintext = try break_vignere(allocator, trimmed_input_file);

    try stdout.print("{s}\n", .{plaintext});

    try stdout.flush();
}

fn break_vignere(allocator: Allocator, ciphertext: []const u8) ![]const u8 {
    const decoded_buffer = try allocator.alloc(u8, try base64.decodedLen(ciphertext.len, .standard));
    defer allocator.free(decoded_buffer);

    const decoded = try base64.decode(decoded_buffer, ciphertext, .standard);

    const key_length = windowed_normalized_hamming_distance(decoded, 4);

    var decoded_padded = decoded;

    if (decoded.len % key_length != 0) {
        const zeroes = try allocator.alloc(u8, key_length - (decoded.len % key_length));
        defer allocator.free(zeroes);

        @memset(zeroes, 0);

        decoded_padded = try mem.concat(allocator, u8, &.{ decoded, zeroes });
    }
    assert(decoded_padded.len % key_length == 0);

    var blocks: std.ArrayList([]const u8) = .empty;
    defer blocks.deinit(allocator);

    var it = mem.window(u8, decoded_padded, key_length, key_length);
    while (it.next()) |chunk| {
        try blocks.append(allocator, chunk);
    }

    const transposed = try allocator.alloc([]u8, key_length);
    defer {
        for (transposed) |item| {
            allocator.free(item);
        }

        allocator.free(transposed);
    }

    const key = try allocator.alloc(u8, key_length);
    defer allocator.free(key);

    for (0..transposed.len) |i| {
        transposed[i] = try allocator.alloc(u8, blocks.items.len);

        for (0..blocks.items.len) |m| {
            transposed[i][m] = blocks.items[m][i];
        }

        const key_result = try stream.find_key_decoded(allocator, transposed[i]);
        key[i] = key_result.key;
    }

    const plaintext = try stream.repeating(allocator, decoded, key);

    if (decoded.len % key_length != 0) {
        allocator.free(decoded_padded);
    }

    return plaintext;
}

fn windowed_normalized_hamming_distance(
    input: []const u8,
    comptime window_size: usize,
) usize {
    var best_keysize: usize = 0;
    var best_distance: f64 = std.math.floatMax(f64);

    for (2..41) |keysize| {
        var distance: f64 = 0;

        // Compare every pair of blocks in the window.
        inline for (0..window_size) |i| {
            const first = input[i * keysize .. (i + 1) * keysize];

            inline for (i + 1..window_size) |j| {
                const second = input[j * keysize .. (j + 1) * keysize];

                distance += @as(f64, @floatFromInt(
                    util.hamming_distance(first, second),
                )) / @as(f64, @floatFromInt(keysize));
            }
        }

        if (distance < best_distance) {
            best_distance = distance;
            best_keysize = keysize;
        }
    }

    return best_keysize;
}

test "Challenge 6" {
    const allocator = std.testing.allocator;

    const base64_input =
        "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";
    const expected_output =
        \\I'm back and I'm ringin' the bell 
        \\A rockin' on the mike while the fly girls yell 
        \\In ecstasy in the back of me 
        \\Well that's my DJ Deshay cuttin' all them Z's 
        \\Hittin' hard and the girlies goin' crazy 
        \\Vanilla's on the mike, man I'm not lazy. 
        \\
        \\I'm lettin' my drug kick in 
        \\It controls my mouth and I begin 
        \\To just let it flow, let my concepts go 
        \\My posse's to the side yellin', Go Vanilla Go! 
        \\
        \\Smooth 'cause that's the way I will be 
        \\And if you don't give a damn, then 
        \\Why you starin' at me 
        \\So get off 'cause I control the stage 
        \\There's no dissin' allowed 
        \\I'm in my own phase 
        \\The girlies sa y they love me and that is ok 
        \\And I can dance better than any kid n' play 
        \\
        \\Stage 2 -- Yea the one ya' wanna listen to 
        \\It's off my head so let the beat play through 
        \\So I can funk it up and make it sound good 
        \\1-2-3 Yo -- Knock on some wood 
        \\For good luck, I like my rhymes atrocious 
        \\Supercalafragilisticexpialidocious 
        \\I'm an effect and that you can bet 
        \\I can take a fly girl and make her wet. 
        \\
        \\I'm like Samson -- Samson to Delilah 
        \\There's no denyin', You can try to hang 
        \\But you'll keep tryin' to get my style 
        \\Over and over, practice makes perfect 
        \\But not if you're a loafer. 
        \\
        \\You'll get nowhere, no place, no time, no girls 
        \\Soon -- Oh my God, homebody, you probably eat 
        \\Spaghetti with a spoon! Come on and say it! 
        \\
        \\VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino 
        \\Intoxicating so you stagger like a wino 
        \\So punks stop trying and girl stop cryin' 
        \\Vanilla Ice is sellin' and you people are buyin' 
        \\'Cause why the freaks are jockin' like Crazy Glue 
        \\Movin' and groovin' trying to sing along 
        \\All through the ghetto groovin' this here song 
        \\Now you're amazed by the VIP posse. 
        \\
        \\Steppin' so hard like a German Nazi 
        \\Startled by the bases hittin' ground 
        \\There's no trippin' on mine, I'm just gettin' down 
        \\Sparkamatic, I'm hangin' tight like a fanatic 
        \\You trapped me once and I thought that 
        \\You might have it 
        \\So step down and lend me your ear 
        \\'89 in my time! You, '90 is my year. 
        \\
        \\You're weakenin' fast, YO! and I can tell it 
        \\Your body's gettin' hot, so, so I can smell it 
        \\So don't be mad and don't be sad 
        \\'Cause the lyrics belong to ICE, You can call me Dad 
        \\You're pitchin' a fit, so step back and endure 
        \\Let the witch doctor, Ice, do the dance to cure 
        \\So come up close and don't be square 
        \\You wanna battle me -- Anytime, anywhere 
        \\
        \\You thought that I was weak, Boy, you're dead wrong 
        \\So come on, everybody and sing this song 
        \\
        \\Say -- Play that funky music Say, go white boy, go white boy go 
        \\play that funky music Go white boy, go white boy, go 
        \\Lay down and boogie and play that funky music till you die. 
        \\
        \\Play that funky music Come on, Come on, let me hear 
        \\Play that funky music white boy you say it, say it 
        \\Play that funky music A little louder now 
        \\Play that funky music, white boy Come on, Come on, Come on 
        \\Play that funky music 
        \\
    ;

    const actual_output = try break_vignere(allocator, base64_input);
    defer allocator.free(actual_output);

    try std.testing.expectEqualStrings(expected_output, actual_output);
}
