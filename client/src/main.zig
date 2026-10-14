const std = @import("std");
const Io = std.Io;
const sign = @import("sign.zig");
const send = @import("send.zig");
const Diagnostic = sign.Diagnostic;

const max_key_bytes = 16 * 1024;
const max_campaign_bytes = 64 * 1024;
// Stall covers the wait for the server's answer, during which it publishes to S3.
const limits: send.Limits = .{ .connect = .fromSeconds(30), .stall = .fromSeconds(60) };

const usage = std.fmt.comptimePrint(
    \\Sign a report with a Leios BLS key and upload it to Uketsuke.
    \\
    \\Usage: ukc send --key bls.skey --file report.zip --pool POOL_HEX \
    \\  --campaign URL_OR_FILE [--id PREVIOUS_SUBMISSION_ID]
    \\  Signs and uploads the report, then prints the receipt JSON.
    \\  A campaign URL must be HTTPS (HTTP only on loopback) and is refused unless
    \\  its service is the URL's own origin. SSL_CERT_FILE replaces the system CA
    \\  bundle. Proxy variables are ignored; behind a proxy, use ukc sign and
    \\  curl. Requests fail after {d} s without a connection or {d} s without
    \\  progress. The submission ID is printed to stderr before the upload;
    \\  rerun with --id to retry or recover a receipt.
    \\

    \\Usage: ukc sign --key bls.skey --file report.zip --pool POOL_HEX \
    \\  --campaign campaign.json --out request [--id PREVIOUS_SUBMISSION_ID]
    \\  Signs without network access. Writes manifest.json (the exact signed
    \\  bytes) and the curl configs upload.curl and receipt.curl.
    \\  Upload (curl 7.76.0 or newer): curl -q -K request/upload.curl
    \\  Recover receipt: curl -q -K request/receipt.curl
    \\
    \\The campaign JSON requires service, network, campaign, lifetime_secs.
    \\A fresh random submission ID is used unless --id is supplied for recovery.
    \\Never use a cold key. The private key never leaves this program.
    \\
, .{ limits.connect.toSeconds(), limits.stall.toSeconds() });

const Command = enum { sign, send };

const Options = struct {
    key: ?[]const u8 = null,
    file: ?[]const u8 = null,
    pool: ?[]const u8 = null,
    campaign: ?[]const u8 = null,
    out: ?[]const u8 = null,
    id: ?[]const u8 = null,
};

pub fn main(init: std.process.Init) void {
    const arena = init.arena.allocator();
    var d: Diagnostic = .{ .arena = arena };
    run(init, &d) catch |err| {
        const message = switch (err) {
            error.Failed => d.message,
            else => @errorName(err),
        };
        var buffer: [1024]u8 = undefined;
        var stderr = Io.File.stderr().writer(init.io, &buffer);
        stderr.interface.print("ukc: {s}\n", .{message}) catch {};
        stderr.interface.flush() catch {};
        std.process.exit(1);
    };
}

fn parseOptions(comptime command: Command, args: []const [:0]const u8, d: *Diagnostic) error{Failed}!Options {
    const names = switch (command) {
        .sign => .{ "key", "file", "pool", "campaign", "out", "id" },
        .send => .{ "key", "file", "pool", "campaign", "id" },
    };
    var options: Options = .{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg: []const u8 = args[i];
        if (!std.mem.startsWith(u8, arg, "--")) return d.fail("unexpected argument {s}; use --help", .{arg});
        const eq = std.mem.indexOfScalar(u8, arg, '=');
        const name = arg[2 .. eq orelse arg.len];
        const slot: *?[]const u8 = inline for (names) |field| {
            if (std.mem.eql(u8, name, field)) break &@field(options, field);
        } else return d.fail("unknown option --{s} for {t}; use --help", .{ name, command });
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

/// The report's SHA-256 and size, valid while its mtime is unchanged.
const Digest = struct { hex: [64]u8, size: u64, mtime: Io.Timestamp };

/// The report, opened once so `send` uploads the handle it hashed.
const Report = struct {
    file: Io.File,
    /// Absolute path, written into the curl upload config.
    path: []const u8,
    filename: []const u8,
    digest: Digest,
};

fn openReport(io: Io, arena: std.mem.Allocator, file_arg: []const u8, d: *Diagnostic) !Report {
    const path = try std.fs.path.resolve(arena, &.{ try std.process.currentPathAlloc(io, arena), file_arg });
    const filename = std.fs.path.basename(path);
    if (!sign.isDisplayName(filename)) return d.fail("--file name must be nonblank UTF-8", .{});
    const file = Io.Dir.cwd().openFile(io, path, .{}) catch |err|
        return d.fail("cannot open --file {s}: {s}", .{ path, @errorName(err) });
    errdefer file.close(io);
    return .{ .file = file, .path = path, .filename = filename, .digest = try hashReport(io, file, path, d) };
}

/// Hashes the report, refusing a file that changes while it is read.
fn hashReport(io: Io, file: Io.File, path: []const u8, d: *Diagnostic) !Digest {
    const before = try statReport(io, file, path, d);
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
    const after = try statReport(io, file, path, d);
    if (after.size != before.size or after.mtime.nanoseconds != before.mtime.nanoseconds or size != before.size) {
        return d.fail("report changed while hashing; retry with a stable file", .{});
    }
    return .{ .hex = std.fmt.bytesToHex(hash.finalResult(), .lower), .size = size, .mtime = before.mtime };
}

fn statReport(io: Io, file: Io.File, path: []const u8, d: *Diagnostic) !Io.File.Stat {
    return file.stat(io) catch |err| d.fail("cannot stat --file {s}: {s}", .{ path, @errorName(err) });
}

/// Refuses to upload a report that changed since it was hashed and signed.
fn checkUnchanged(io: Io, report: Report, d: *Diagnostic) !void {
    const now = try statReport(io, report.file, report.path, d);
    if (now.size != report.digest.size or now.mtime.nanoseconds != report.digest.mtime.nanoseconds) {
        return d.fail("--file {s} changed after signing; rerun with a stable file", .{report.path});
    }
}

fn readInput(io: Io, arena: std.mem.Allocator, path: []const u8, comptime name: []const u8, limit: usize, d: *Diagnostic) ![]u8 {
    return Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(limit)) catch |err|
        return d.fail("cannot read --" ++ name ++ " {s}: {s}", .{ path, @errorName(err) });
}

/// Everything both commands validate before signing.
const Inputs = struct {
    key_path: []const u8,
    pool: []const u8,
    id: []const u8,

    fn init(io: Io, arena: std.mem.Allocator, options: Options, d: *Diagnostic) !Inputs {
        const key_path = try required(options.key, "key", d);
        const pool = try required(options.pool, "pool", d);
        if (!sign.isLowerHex(pool, 56)) return d.fail("--pool must be a 28-byte lowercase hex pool ID", .{});
        const id = options.id orelse id: {
            var bytes: [16]u8 = undefined;
            try io.randomSecure(&bytes);
            break :id try arena.dupe(u8, &std.fmt.bytesToHex(bytes, .lower));
        };
        if (!sign.isLowerHex(id, 32)) return d.fail("--id must be 16-byte lowercase hex", .{});
        return .{ .key_path = key_path, .pool = pool, .id = id };
    }
};

fn signRequest(io: Io, arena: std.mem.Allocator, inputs: Inputs, campaign: sign.Campaign, report: Report, d: *Diagnostic) !sign.Request {
    const now = Io.Clock.real.now(io).toSeconds();
    if (now <= 0) return d.fail("system clock is before 1970", .{});
    const expires_at = @as(u64, @intCast(now)) + campaign.lifetime_secs;
    if (expires_at > sign.max_safe_integer) return d.fail("campaign expiry is outside safe integer range", .{});
    const manifest = try sign.encodeManifest(arena, .{
        .service = campaign.service,
        .network = campaign.network,
        .campaign = campaign.campaign,
        .pool_id = inputs.pool,
        .submission_id = inputs.id,
        .file_hash = &report.digest.hex,
        .file_size = report.digest.size,
        .filename = report.filename,
        .expires_at = expires_at,
    });

    const key_text = try readInput(io, arena, inputs.key_path, "key", max_key_bytes, d);
    var key = parsed: {
        defer std.crypto.secureZero(u8, key_text);
        break :parsed try sign.parseKey(arena, key_text, d);
    };
    defer key.deinit();
    return .{
        .service = campaign.service,
        .submission_id = inputs.id,
        .manifest = manifest,
        .public_key = key.publicKey(),
        .signature = key.sign(manifest),
    };
}

fn run(init: std.process.Init, d: *Diagnostic) !void {
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 2) return d.fail("missing command sign or send; use --help", .{});
    for (args[1..]) |arg| if (std.mem.eql(u8, arg, "--help")) {
        try Io.File.stdout().writeStreamingAll(io, usage);
        return;
    };
    const command_arg: []const u8 = args[1];
    const command = std.meta.stringToEnum(Command, command_arg) orelse
        return d.fail("unknown command {s}; use --help", .{command_arg});
    switch (command) {
        .sign => try runSign(init, arena, try parseOptions(.sign, args[2..], d), d),
        .send => try runSend(init, arena, try parseOptions(.send, args[2..], d), d),
    }
}

fn runSign(init: std.process.Init, arena: std.mem.Allocator, options: Options, d: *Diagnostic) !void {
    const io = init.io;
    const inputs = try Inputs.init(io, arena, options, d);
    const campaign_path = try required(options.campaign, "campaign", d);
    const out_arg = try required(options.out, "out", d);
    const campaign = try sign.parseCampaign(arena, try readInput(io, arena, campaign_path, "campaign", max_campaign_bytes, d), d);
    const report = try openReport(io, arena, try required(options.file, "file", d), d);
    report.file.close(io);
    const request = try signRequest(io, arena, inputs, campaign, report, d);

    const out = try std.fs.path.resolve(arena, &.{ try std.process.currentPathAlloc(io, arena), out_arg });
    const cwd_dir = Io.Dir.cwd();
    cwd_dir.createDir(io, out, .fromMode(0o700)) catch |err| return switch (err) {
        error.PathAlreadyExists => d.fail("--out {s} already exists; choose a new directory", .{out}),
        else => d.fail("cannot create --out {s}: {s}", .{ out, @errorName(err) }),
    };
    const dir = cwd_dir.openDir(io, out, .{}) catch |err| return d.fail("cannot open --out {s}: {s}", .{ out, @errorName(err) });
    defer dir.close(io);
    const files = [_]struct { name: []const u8, data: []const u8 }{
        .{ .name = "manifest.json", .data = request.manifest },
        .{ .name = "upload.curl", .data = try render(arena, .{ .uploads = report.path }, request) },
        .{ .name = "receipt.curl", .data = try render(arena, .receipts, request) },
    };
    for (files) |file| {
        dir.writeFile(io, .{
            .sub_path = file.name,
            .data = file.data,
            .flags = .{ .exclusive = true, .permissions = .fromMode(0o600) },
        }) catch |err| return d.fail("cannot write {s}/{s}: {s}", .{ out, file.name, @errorName(err) });
    }

    const public_key_hex = std.fmt.bytesToHex(request.public_key, .lower);
    try printJson(io, arena, .{
        .submission_id = inputs.id,
        .file_hash = report.digest.hex[0..],
        .file_size = report.digest.size,
        .public_key = public_key_hex[0..],
        .request_directory = out,
    });
}

fn render(arena: std.mem.Allocator, route: sign.Route, request: sign.Request) ![]u8 {
    var out: Io.Writer.Allocating = .init(arena);
    try sign.writeCurlConfig(&out.writer, arena, route, request);
    return out.written();
}

fn runSend(init: std.process.Init, arena: std.mem.Allocator, options: Options, d: *Diagnostic) !void {
    const io = init.io;
    const inputs = try Inputs.init(io, arena, options, d);
    const campaign_arg = try required(options.campaign, "campaign", d);
    const file_arg = try required(options.file, "file", d);

    // No proxies: std.http.Client returns an HTTPS CONNECT tunnel through a
    // plain proxy without a TLS handshake with the service.
    var client: std.http.Client = .{ .allocator = init.gpa, .io = io };
    defer client.deinit();
    // As with curl and OpenSSL, SSL_CERT_FILE replaces the system bundle.
    if (init.environ_map.get("SSL_CERT_FILE")) |path| {
        const now = Io.Clock.real.now(io);
        client.ca_bundle.addCertsFromFilePath(init.gpa, io, now, Io.Dir.cwd(), path) catch |err|
            return d.fail("cannot load SSL_CERT_FILE {s}: {s}", .{ path, @errorName(err) });
        // A set `now` stops the client from rescanning the system bundle.
        client.now = now;
    }
    const is_url = std.mem.startsWith(u8, campaign_arg, "https://") or std.mem.startsWith(u8, campaign_arg, "http://");
    const campaign = if (!is_url)
        try sign.parseCampaign(arena, try readInput(io, arena, campaign_arg, "campaign", max_campaign_bytes, d), d)
    else fetched: {
        const origin = sign.campaignUrlOrigin(campaign_arg) orelse
            return d.fail("--campaign URL must be https://host/path (http only on loopback) with a lowercase host and no default port", .{});
        const campaign = try sign.parseCampaign(arena, try send.fetchCampaign(&client, arena, campaign_arg, max_campaign_bytes, limits, d), d);
        if (!std.mem.eql(u8, campaign.service, origin)) {
            return d.fail("campaign at {s} names service {s}; a fetched campaign must name its own origin", .{ campaign_arg, campaign.service });
        }
        break :fetched campaign;
    };

    const report = try openReport(io, arena, file_arg, d);
    defer report.file.close(io);
    const request = try signRequest(io, arena, inputs, campaign, report, d);

    try checkUnchanged(io, report, d);
    // pread only: with sendfile, a canceled send on plain HTTP surfaces
    // differently from TLS, which always writes through the socket writer.
    var file = report.file.reader(io, &.{});
    file.mode = .positional_simple;
    try printErr(io, "submission {s}: uploading {d} bytes to {s}\n", .{ inputs.id, report.digest.size, campaign.service });
    const answer = send.upload(&client, arena, request, &file.interface, report.digest.size, limits, d) catch |err| switch (err) {
        error.Failed => return d.fail("{s}; retry with --id {s}", .{ d.message, inputs.id }),
        error.ReadFailed => return d.fail("cannot read --file {s}: {s}", .{ report.path, @errorName(file.err orelse err) }),
        else => return err,
    };
    const status = answer.status;
    if (status.class() != .success) {
        const transient = status.class() == .server_error or status == .request_timeout or status == .too_many_requests;
        return d.fail("upload {s} with HTTP {d}: {s}{s}", .{
            if (transient) "failed" else "rejected",
            @intFromEnum(status),
            answer.body,
            if (transient) try std.fmt.allocPrint(arena, "; retry with --id {s}", .{inputs.id}) else "",
        });
    }
    // A proxy or captive portal can answer 2xx too; only a receipt for this submission counts.
    const Receipt = struct { submission_id: []const u8 };
    const receipt = std.json.parseFromSliceLeaky(Receipt, arena, answer.body, .{ .ignore_unknown_fields = true }) catch null;
    if (receipt == null or !std.mem.eql(u8, receipt.?.submission_id, inputs.id)) {
        return d.fail("HTTP {d} answer is not a receipt for this submission: {s}; retry with --id {s}", .{ @intFromEnum(status), answer.body, inputs.id });
    }
    try Io.File.stdout().writeStreamingAll(io, answer.body);
    if (!std.mem.endsWith(u8, answer.body, "\n")) try Io.File.stdout().writeStreamingAll(io, "\n");
}

fn printJson(io: Io, arena: std.mem.Allocator, value: anytype) !void {
    const json = try std.json.Stringify.valueAlloc(arena, value, .{ .whitespace = .indent_2 });
    var buffer: [1024]u8 = undefined;
    var stdout = Io.File.stdout().writer(io, &buffer);
    try stdout.interface.print("{s}\n", .{json});
    try stdout.interface.flush();
}

fn printErr(io: Io, comptime format: []const u8, args: anytype) !void {
    var buffer: [1024]u8 = undefined;
    var stderr = Io.File.stderr().writer(io, &buffer);
    try stderr.interface.print(format, args);
    try stderr.interface.flush();
}

test {
    _ = sign;
    _ = send;
}
