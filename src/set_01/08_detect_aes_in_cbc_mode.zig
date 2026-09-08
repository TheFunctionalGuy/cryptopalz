const ChallengeContext = @import("cryptopalz").ChallengeContext;

pub fn challenge(context: ChallengeContext) !void {
    const allocator = context.allocator;
    _ = allocator; // autofix
    const args = context.args;
    _ = args; // autofix
    const stdout = context.stdout;
    _ = stdout; // autofix
    const stderr = context.stderr;
    _ = stderr; // autofix
}
