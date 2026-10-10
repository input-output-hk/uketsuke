const std = @import("std");
const Io = std.Io;
const sign = @import("sign.zig");
const Diagnostic = sign.Diagnostic;

const usage =
    \\Sign a report locally; this program makes no network requests.
    \\Usage: uketsuke-sign --key bls.skey --file report.zip --pool POOL_HEX \
    \\  --campaign campaign.json --out request [--id PREVIOUS_SUBMISSION_ID]
    \\
    \\The campaign JSON requires service, network, campaign, lifetime_secs.
    \\A fresh random submission ID is used unless --id is supplied for recovery.
    \\Output: manifest.json (the exact signed bytes) and the curl configs
    \\upload.curl and receipt.curl (report path, public key, signature).
    \\Upload (curl 7.76.0 or newer): curl -K request/upload.curl
    \\Recover receipt: curl -K request/receipt.curl
    \\Never use a cold key. No private key is included in the generated files.
    \\
;

const Options = struct {
    key: ?[]const u8 = null,
    file: ?[]const u8 = null,
    pool: ?[]const u8 = null,
    campaign: ?[]const u8 = null,
    out: ?[]const u8 = null,
    id: ?[]const u8 = null,
    help: bool = false,
};

const max_key_bytes = 16 * 1024;
const max_campaign_bytes = 64 * 1024;

pub fn main(init: std.process.Init) void {
    const arena = init.arena.allocator();
    var d: Diagnostic = .{ .arena = arena };
    run(init.io, arena, init.minimal.args, &d) catch |err| {
        const message = switch (err) {
            error.Failed => d.message,
            else => @errorName(err),
        };
        var buffer: [1024]u8 = undefined;
        var stderr = Io.File.stderr().writer(init.io, &buffer);
        stderr.interface.print("signing failed: {s}\n", .{message}) catch {};
        stderr.interface.flush() catch {};
        std.process.exit(1);
    };
}

fn parseOptions(args: []const [:0]const u8, d: *Diagnostic) error{Failed}!Options {
    var options: Options = .{};
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg: []const u8 = args[i];
        if (std.mem.eql(u8, arg, "--help")) {
            options.help = true;
            continue;
        }
        if (!std.mem.startsWith(u8, arg, "--")) return d.fail("unexpected argument {s}; use --help", .{arg});
        const eq = std.mem.indexOfScalar(u8, arg, '=');
        const name = arg[2 .. eq orelse arg.len];
        const slot: *?[]const u8 = inline for (.{ "key", "file", "pool", "campaign", "out", "id" }) |field| {
            if (std.mem.eql(u8, name, field)) break &@field(options, field);
        } else return d.fail("unknown option --{s}; use --help", .{name});
        if (slot.* != null) return d.fail("--{s} given twice", .{name});
        slot.* = if (eq) |at| arg[at + 1 ..] else value: {
            i += 1;
            if (i == args.len) return d.fail("--{s} needs a value", .{name});
            const value: []const u8 = args[i];
            if (std.mem.startsWith(u8, value, "--")) return d.fail("--{s} needs a value; write --{s}={s} if it really starts with --", .{ name, name, value });
            break :value value;
        };
    }
    return options;
}

fn required(value: ?[]const u8, comptime name: []const u8, d: *Diagnostic) error{Failed}![]const u8 {
    return value orelse return d.fail("missing --" ++ name ++ "; use --help", .{});
}

fn permissions(comptime mode: u32, comptime fallback: Io.File.Permissions) Io.File.Permissions {
    return if (@hasDecl(Io.File.Permissions, "fromMode")) .fromMode(mode) else fallback;
}

const Digest = struct { hex: [64]u8, size: u64 };

/// Hashes the report, refusing a file that changes while it is read.
fn hashReport(io: Io, path: []const u8, d: *Diagnostic) !Digest {
    const file = Io.Dir.cwd().openFile(io, path, .{}) catch |err|
        return d.fail("cannot open --file {s}: {s}", .{ path, @errorName(err) });
    defer file.close(io);
    const before = try file.stat(io);
    if (before.kind != .file or before.size == 0 or before.size > sign.max_safe_integer) {
        return d.fail("--file must be a nonempty regular file with a safely representable size", .{});
    }
    var hash: std.crypto.hash.sha2.Sha256 = .init(.{});
    var size: u64 = 0;
    var buffer: [64 * 1024]u8 = undefined;
    while (true) {
        const n = file.readStreaming(io, &.{&buffer}) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return d.fail("cannot read --file {s}: {s}", .{ path, @errorName(err) }),
        };
        hash.update(buffer[0..n]);
        size += n;
    }
    const after = try file.stat(io);
    if (after.size != before.size or after.mtime.nanoseconds != before.mtime.nanoseconds or size != before.size) {
        return d.fail("report changed while hashing; retry with a stable file", .{});
    }
    return .{ .hex = std.fmt.bytesToHex(hash.finalResult(), .lower), .size = size };
}

fn readInput(io: Io, arena: std.mem.Allocator, path: []const u8, comptime name: []const u8, limit: usize, d: *Diagnostic) ![]u8 {
    return Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(limit)) catch |err|
        return d.fail("cannot read --" ++ name ++ " {s}: {s}", .{ path, @errorName(err) });
}

fn render(arena: std.mem.Allocator, route: sign.Route, request: sign.Request) ![]u8 {
    var out: Io.Writer.Allocating = .init(arena);
    try sign.writeCurlConfig(&out.writer, route, request);
    return out.written();
}

fn run(io: Io, arena: std.mem.Allocator, process_args: std.process.Args, d: *Diagnostic) !void {
    const options = try parseOptions(try process_args.toSlice(arena), d);
    if (options.help) {
        try Io.File.stdout().writeStreamingAll(io, usage);
        return;
    }
    const key_path = try required(options.key, "key", d);
    const file_arg = try required(options.file, "file", d);
    const pool = try required(options.pool, "pool", d);
    const campaign_path = try required(options.campaign, "campaign", d);
    const out_arg = try required(options.out, "out", d);
    if (!sign.isLowerHex(pool, 56)) return d.fail("--pool must be a 28-byte lowercase hex pool ID", .{});
    const id = options.id orelse id: {
        var bytes: [16]u8 = undefined;
        try io.randomSecure(&bytes);
        break :id try arena.dupe(u8, &std.fmt.bytesToHex(bytes, .lower));
    };
    if (!sign.isLowerHex(id, 32)) return d.fail("--id must be 16-byte lowercase hex", .{});

    const campaign = try sign.parseCampaign(arena, try readInput(io, arena, campaign_path, "campaign", max_campaign_bytes, d), d);
    const cwd = try std.process.currentPathAlloc(io, arena);
    const report = try std.fs.path.resolve(arena, &.{ cwd, file_arg });
    const out = try std.fs.path.resolve(arena, &.{ cwd, out_arg });
    const digest = try hashReport(io, report, d);
    const filename = std.fs.path.basename(report);
    if (!sign.isDisplayName(filename)) return d.fail("--file name must be nonblank UTF-8", .{});

    const now = Io.Clock.real.now(io).toSeconds();
    if (now <= 0) return d.fail("system clock is before 1970", .{});
    const expires_at = @as(u64, @intCast(now)) + campaign.lifetime_secs;
    if (expires_at > sign.max_safe_integer) return d.fail("campaign expiry is outside safe integer range", .{});
    const manifest = try sign.encodeManifest(arena, .{
        .service = campaign.service,
        .network = campaign.network,
        .campaign = campaign.campaign,
        .pool_id = pool,
        .submission_id = id,
        .file_hash = &digest.hex,
        .file_size = digest.size,
        .filename = filename,
        .expires_at = expires_at,
    });

    const key_text = try readInput(io, arena, key_path, "key", max_key_bytes, d);
    var key = parsed: {
        defer std.crypto.secureZero(u8, key_text);
        break :parsed try sign.parseKey(arena, key_text, d);
    };
    defer key.deinit();
    const request: sign.Request = .{
        .service = campaign.service,
        .submission_id = id,
        .report = report,
        .manifest = manifest,
        .public_key = key.publicKey(),
        .signature = key.sign(manifest),
    };

    const cwd_dir = Io.Dir.cwd();
    cwd_dir.createDir(io, out, permissions(0o700, .default_dir)) catch |err| return switch (err) {
        error.PathAlreadyExists => d.fail("--out {s} already exists; choose a new directory", .{out}),
        else => d.fail("cannot create --out {s}: {s}", .{ out, @errorName(err) }),
    };
    const dir = try cwd_dir.openDir(io, out, .{});
    defer dir.close(io);
    const files = [_]struct { name: []const u8, data: []const u8 }{
        .{ .name = "manifest.json", .data = manifest },
        .{ .name = "upload.curl", .data = try render(arena, .uploads, request) },
        .{ .name = "receipt.curl", .data = try render(arena, .receipts, request) },
    };
    for (files) |file| {
        try dir.writeFile(io, .{
            .sub_path = file.name,
            .data = file.data,
            .flags = .{ .exclusive = true, .permissions = permissions(0o600, .default_file) },
        });
    }

    const public_key_hex = std.fmt.bytesToHex(request.public_key, .lower);
    const summary = try std.json.Stringify.valueAlloc(arena, .{
        .submission_id = id,
        .file_hash = digest.hex[0..],
        .file_size = digest.size,
        .public_key = public_key_hex[0..],
        .request_directory = out,
    }, .{ .whitespace = .indent_2 });
    var buffer: [1024]u8 = undefined;
    var stdout = Io.File.stdout().writer(io, &buffer);
    try stdout.interface.print("{s}\n", .{summary});
    try stdout.interface.flush();
}

test {
    _ = sign;
}
