//! HTTP(S) requests of `ukc send`: fetching a campaign and uploading a report.
//! Redirects are never followed, so the origin that answers is the one signed for.
//! std.http.Client has no timeouts; a watchdog task cancels a stalled transfer,
//! which interrupts its blocked socket call.

const std = @import("std");
const Io = std.Io;
const http = std.http;
const sign = @import("sign.zig");
const Diagnostic = sign.Diagnostic;

const max_response_bytes = 64 * 1024;

pub const Answer = struct { status: http.Status, body: []u8 };

/// How long a transfer may go without progress before it is canceled.
pub const Limits = struct {
    /// Name resolution, TCP connect and TLS handshake.
    connect: Io.Duration,
    /// Silence between chunks sent or received once connected, including the
    /// wait for the server's answer.
    stall: Io.Duration,
};

/// When a transfer last made progress; shared with its watchdog.
const Progress = struct {
    io: Io,
    /// Awake-clock nanoseconds when the transfer started.
    started: i64,
    /// Set by the first mark; wakes a watchdog waiting out the connect limit.
    connected: Io.Event = .unset,
    /// Awake-clock nanoseconds of the latest mark.
    last: std.atomic.Value(i64),

    fn init(io: Io) Progress {
        const started = now(io);
        return .{ .io = io, .started = started, .last = .init(started) };
    }

    fn mark(p: *Progress) void {
        p.last.store(now(p.io), .release);
        if (!p.connected.isSet()) p.connected.set(p.io);
    }

    fn now(io: Io) i64 {
        return @intCast(Io.Clock.awake.now(io).nanoseconds);
    }
};

const Phase = enum { connecting, transferring };

/// Returns the phase in which `progress` exceeded its limit.
fn watch(progress: *Progress, limits: Limits) Io.Cancelable!Phase {
    const io = progress.io;
    while (!progress.connected.isSet()) {
        const left = progress.started + nanoseconds(limits.connect) - Progress.now(io);
        if (left <= 0) return .connecting;
        progress.connected.waitTimeout(io, .{ .duration = .{ .raw = .fromNanoseconds(left), .clock = .awake } }) catch |err| switch (err) {
            // Also returned on a spurious wakeup; the loop rechecks the clock.
            error.Timeout => {},
            error.Canceled => |e| return e,
        };
    }
    while (true) {
        const left = progress.last.load(.acquire) + nanoseconds(limits.stall) - Progress.now(io);
        if (left <= 0) return .transferring;
        try io.sleep(.fromNanoseconds(left), .awake);
    }
}

fn nanoseconds(duration: Io.Duration) i64 {
    return @intCast(duration.nanoseconds);
}

fn Guarded(comptime transfer: anytype) type {
    const result = @typeInfo(@typeInfo(@TypeOf(transfer)).@"fn".return_type.?).error_union;
    return (result.error_set || Io.Cancelable || error{Failed})!result.payload;
}

/// Runs `transfer(&progress, args...)` and cancels it once `limits` are exceeded.
fn guarded(io: Io, limits: Limits, what: []const u8, d: *Diagnostic, comptime transfer: anytype, args: anytype) Guarded(transfer) {
    const U = union(enum) {
        done: @typeInfo(@TypeOf(transfer)).@"fn".return_type.?,
        exceeded: Io.Cancelable!Phase,
    };
    var progress: Progress = .init(io);
    var buffer: [2]U = undefined;
    var select: Io.Select(U) = .init(io, &buffer);
    defer select.cancelDiscard();
    select.concurrent(.done, transfer, .{&progress} ++ args) catch |err|
        return d.fail("cannot start {s}: {s}", .{ what, @errorName(err) });
    select.concurrent(.exceeded, watch, .{ &progress, limits }) catch |err| {
        // Waits for the transfer to finish, so its diagnostic cannot replace this one.
        select.cancelDiscard();
        return d.fail("cannot start the {s} timeout: {s}", .{ what, @errorName(err) });
    };
    switch (try select.await()) {
        .done => |result| return result,
        .exceeded => |phase| {
            const exceeded = try phase;
            // Waits for the transfer to finish, so its diagnostic cannot replace
            // this one. A transfer that succeeded just as the limit passed wins.
            while (select.cancel()) |late| switch (late) {
                .done => |result| if (result) |answer| return answer else |_| {},
                .exceeded => unreachable,
            };
            return switch (exceeded) {
                .connecting => d.fail("{s}: not connected after {f}", .{ what, limits.connect }),
                .transferring => d.fail("{s}: no progress for {f}", .{ what, limits.stall }),
            };
        },
    }
}

/// Fetches the campaign JSON at `url`; only a 200 answer is accepted.
pub fn fetchCampaign(client: *http.Client, arena: std.mem.Allocator, url: []const u8, limit: usize, limits: Limits, d: *Diagnostic) Guarded(fetchCampaignTask) {
    const uri = std.Uri.parse(url) catch return d.fail("--campaign {s} is not a URL", .{url});
    const what = try std.fmt.allocPrint(arena, "fetching {s}", .{url});
    return guarded(client.io, limits, what, d, fetchCampaignTask, .{ client, arena, uri, url, limit, d });
}

fn fetchCampaignTask(progress: *Progress, client: *http.Client, arena: std.mem.Allocator, uri: std.Uri, url: []const u8, limit: usize, d: *Diagnostic) ![]u8 {
    var req = client.request(.GET, uri, options(.default, &.{})) catch |err|
        return d.fail("cannot connect to {s}: {s}", .{ url, @errorName(err) });
    defer req.deinit();
    progress.mark();
    req.sendBodiless() catch |err| return d.fail("cannot request {s}: {s}", .{ url, @errorName(err) });
    const answer = try receive(&req, progress, arena, limit, url, d);
    if (answer.status != .ok) return d.fail("{s} answered HTTP {d}", .{ url, @intFromEnum(answer.status) });
    return answer.body;
}

/// Streams exactly `size` bytes from `report` as the body of the signed upload.
/// Returns error.ReadFailed for the caller to explain from its reader.
pub fn upload(client: *http.Client, arena: std.mem.Allocator, request: sign.Request, report: *Io.Reader, size: u64, limits: Limits, d: *Diagnostic) Guarded(uploadTask) {
    const url = try request.url(arena, .uploads);
    const uri = std.Uri.parse(url) catch return d.fail("service {s} does not form a URL", .{request.service});
    const headers = try request.headers(arena);
    const what = try std.fmt.allocPrint(arena, "uploading to {s}", .{request.service});
    return guarded(client.io, limits, what, d, uploadTask, .{ client, arena, uri, &headers, request.service, report, size, d });
}

fn uploadTask(progress: *Progress, client: *http.Client, arena: std.mem.Allocator, uri: std.Uri, headers: []const http.Header, service: []const u8, report: *Io.Reader, size: u64, d: *Diagnostic) !Answer {
    var req = client.request(.PUT, uri, options(.{ .override = "application/zip" }, headers)) catch |err|
        return d.fail("cannot connect to {s}: {s}", .{ service, @errorName(err) });
    defer req.deinit();
    progress.mark();
    req.transfer_encoding = .{ .content_length = size };

    const write_failed = if (sendBody(&req, progress, report, size)) |_| false else |err| switch (err) {
        error.ReadFailed => return error.ReadFailed,
        error.EndOfStream => return d.fail("report shrank after signing; the server accepts no body shorter than signed", .{}),
        // A task sees cancelation once: if the write consumed it, reading the
        // answer next would block beyond the watchdog's reach.
        error.WriteFailed => if (req.connection.?.stream_writer.err) |cause| switch (cause) {
            error.Canceled => return error.Canceled,
            else => true,
        } else true,
    };
    // A server that rejects the request early may close before the body is
    // sent; its answer is still read so the rejection reason is reported.
    return receive(&req, progress, arena, max_response_bytes, service, d) catch |err| {
        if (err != error.Failed or !write_failed) return err;
        const cause = req.connection.?.stream_writer.err orelse error.WriteFailed;
        return d.fail("sending the report failed: {s}; then {s}", .{ @errorName(cause), d.message });
    };
}

fn sendBody(req: *http.Client.Request, progress: *Progress, report: *Io.Reader, size: u64) Io.Reader.StreamError!void {
    // `report` streams straight into this buffer; it must be nonempty.
    // Each pass moves at most one buffer, so progress is marked per chunk.
    var buffer: [64 * 1024]u8 = undefined;
    var body = try req.sendBodyUnflushed(&buffer);
    var remaining = size;
    while (remaining != 0) {
        remaining -= try report.stream(&body.writer, .limited64(remaining));
        progress.mark();
    }
    try body.end();
    try req.connection.?.flush();
    progress.mark();
}

fn options(content_type: http.Client.Request.Headers.Value, headers: []const http.Header) http.Client.RequestOptions {
    return .{
        .keep_alive = false,
        .redirect_behavior = .unhandled,
        .headers = .{
            .content_type = content_type,
            // Requests no encoding; `receive` still decodes gzip or deflate from a proxy.
            .accept_encoding = .omit,
            .user_agent = .{ .override = "ukc" },
        },
        .extra_headers = headers,
    };
}

fn receive(req: *http.Client.Request, progress: *Progress, arena: std.mem.Allocator, limit: usize, url: []const u8, d: *Diagnostic) !Answer {
    var response = req.receiveHead(&.{}) catch |err| {
        const cause = if (err == error.ReadFailed) req.connection.?.getReadError() orelse err else err;
        return d.fail("no answer from {s}: {s}", .{ url, @errorName(cause) });
    };
    progress.mark();
    const status = response.head.status;
    const window: []u8 = switch (response.head.content_encoding) {
        .identity => &.{},
        .deflate, .gzip => try arena.alloc(u8, std.compress.flate.max_window_len),
        // receiveHead refuses encodings outside Request.accept_encoding (gzip, deflate).
        .zstd, .compress => unreachable,
    };
    var transfer: [64]u8 = undefined;
    var decompress: http.Decompress = undefined;
    const reader = response.readerDecompressing(&transfer, &decompress, window);
    var body: Io.Writer.Allocating = .init(arena);
    while (true) {
        _ = reader.stream(&body.writer, .limited(limit + 1 - body.written().len)) catch |err| switch (err) {
            error.EndOfStream => break,
            error.WriteFailed => return error.OutOfMemory,
            error.ReadFailed => {
                const connection = req.connection.?;
                const cause = if (response.bodyErr()) |e| @errorName(e) else if (connection.stream_reader.err) |e| @errorName(e) else "invalid compressed data or TLS failure";
                return d.fail("cannot read the answer from {s}: {s}", .{ url, cause });
            },
        };
        if (body.written().len > limit) return d.fail("{s} answered with more than {d} bytes", .{ url, limit });
        progress.mark();
    }
    return .{ .status = status, .body = body.written() };
}

const testing = std.testing;

test "a server that accepts but never answers is canceled after the stall limit" {
    const io = testing.io;
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var d: Diagnostic = .{ .arena = arena.allocator() };
    // The kernel completes the handshake from the backlog; nothing ever answers.
    const address: Io.net.IpAddress = try .parse("127.0.0.1", 0);
    var server = try address.listen(io, .{});
    defer server.deinit(io);
    const url = try std.fmt.allocPrint(arena.allocator(), "http://127.0.0.1:{d}/c.json", .{server.socket.address.getPort()});

    var client: http.Client = .{ .allocator = testing.allocator, .io = io };
    defer client.deinit();
    const limits: Limits = .{ .connect = .fromSeconds(5), .stall = .fromMilliseconds(200) };
    const started = Io.Clock.awake.now(io);
    try testing.expectError(error.Failed, fetchCampaign(&client, arena.allocator(), url, 1024, limits, &d));
    const elapsed = started.durationTo(Io.Clock.awake.now(io)).toMilliseconds();
    try testing.expect(std.mem.endsWith(u8, d.message, "/c.json: no progress for 200ms"));
    // The blocked read is interrupted, not left to run out.
    testing.expect(elapsed < 1000) catch |err| {
        std.debug.print("canceling took {d} ms\n", .{elapsed});
        return err;
    };
}

test "an upload to a peer that stops reading is canceled after the stall limit" {
    const io = testing.io;
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var d: Diagnostic = .{ .arena = arena.allocator() };
    // Never accepted, so never read: the body fills the socket buffers and the
    // write blocks. Canceling it must not leave the answer read blocking. An
    // in-memory body has no other cancelation point, as a TLS writer would not.
    const address: Io.net.IpAddress = try .parse("127.0.0.1", 0);
    var server = try address.listen(io, .{});
    defer server.deinit(io);
    const size = 64 * 1024 * 1024;
    const bytes = try arena.allocator().alloc(u8, size);
    @memset(bytes, 0);
    var report: Io.Reader = .fixed(bytes);

    var client: http.Client = .{ .allocator = testing.allocator, .io = io };
    defer client.deinit();
    const request: sign.Request = .{
        .service = try std.fmt.allocPrint(arena.allocator(), "http://127.0.0.1:{d}", .{server.socket.address.getPort()}),
        .submission_id = "10" ** 16,
        .manifest = "{}",
        .public_key = @splat(0),
        .signature = @splat(0),
    };
    const limits: Limits = .{ .connect = .fromSeconds(5), .stall = .fromMilliseconds(200) };
    const started = Io.Clock.awake.now(io);
    try testing.expectError(error.Failed, upload(&client, arena.allocator(), request, &report, size, limits, &d));
    const elapsed = started.durationTo(Io.Clock.awake.now(io)).toMilliseconds();
    try testing.expect(std.mem.endsWith(u8, d.message, ": no progress for 200ms"));
    testing.expect(elapsed < 2000) catch |err| {
        std.debug.print("canceling took {d} ms\n", .{elapsed});
        return err;
    };
}

test "the watchdog applies the connect limit until the first progress mark" {
    const io = testing.io;
    var progress: Progress = .init(io);
    try testing.expectEqual(.connecting, try watch(&progress, .{ .connect = .fromMilliseconds(20), .stall = .fromSeconds(60) }));
    progress.mark();
    try testing.expectEqual(.transferring, try watch(&progress, .{ .connect = .fromSeconds(60), .stall = .fromMilliseconds(20) }));
}
