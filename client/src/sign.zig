//! Input validation, Manifest encoding, BLS signing and curl request files.
//! Nothing here performs I/O; `main.zig` owns files, clock and entropy.

const std = @import("std");
const blst = @import("blst");
const Writer = std.Io.Writer;

pub const dst = "LEIOS_ARTIFACT_UPLOAD_V1_BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
pub const protocol = "leios-artifact-upload/v1";
pub const max_safe_integer: u64 = (1 << 53) - 1;

const key_types = [_][]const u8{
    "BlsSigningKey_bls12-381-BLS-Signature-Minimal-Signature-Size",
    // Spelling written by earlier cardano-cli releases.
    "BlsSigningKey_bls12-381-BLS-Signature-Mininimal-Signature-Size",
};

/// Carries the message for a failed run. Messages never include key material.
pub const Diagnostic = struct {
    arena: std.mem.Allocator,
    message: []const u8 = "",

    pub fn fail(d: *Diagnostic, comptime format: []const u8, args: anytype) error{Failed} {
        d.message = std.fmt.allocPrint(d.arena, format, args) catch "out of memory while reporting an error";
        return error.Failed;
    }
};

pub fn isLowerHex(text: []const u8, len: usize) bool {
    if (text.len != len) return false;
    for (text) |ch| switch (ch) {
        '0'...'9', 'a'...'f' => {},
        else => return false,
    };
    return true;
}

pub const SigningKey = struct {
    secret: blst.SecretKey,

    /// Zeroes the scalar with a volatile write the optimiser cannot drop.
    pub fn deinit(key: *SigningKey) void {
        std.crypto.secureZero(u8, std.mem.asBytes(&key.secret.key));
    }

    pub fn publicKey(key: *const SigningKey) [blst.P2_COMPRESS_BYTES]u8 {
        return blst.P2.public_key(&key.secret).compress();
    }

    pub fn sign(key: *const SigningKey, message: []const u8) [blst.P1_COMPRESS_BYTES]u8 {
        const hash = blst.P1.hash_to(message, dst, null);
        return hash.sign_with(&key.secret).compress();
    }
};

/// Parses a cardano-cli BLS signing-key TextEnvelope.
pub fn parseKey(gpa: std.mem.Allocator, text: []const u8, d: *Diagnostic) error{Failed}!SigningKey {
    const Envelope = struct { type: JsonString, cborHex: JsonString };
    const parsed = std.json.parseFromSlice(Envelope, gpa, text, .{ .ignore_unknown_fields = true }) catch
        return d.fail("--key is not a TextEnvelope JSON object", .{});
    defer parsed.deinit();
    const envelope = .{ .type = parsed.value.type.slice, .cborHex = parsed.value.cborHex.slice };

    const known_type = for (key_types) |name| {
        if (std.mem.eql(u8, envelope.type, name)) break true;
    } else false;
    var bytes: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &bytes);
    // CBOR header 0x5820: a 32-byte byte string.
    if (!known_type or envelope.cborHex.len != 68 or !std.mem.eql(u8, envelope.cborHex[0..4], "5820") or
        (std.fmt.hexToBytes(&bytes, envelope.cborHex[4..]) catch null) == null)
    {
        return d.fail("--key must be a Leios BLS signing-key TextEnvelope containing a 32-byte scalar", .{});
    }

    var key: SigningKey = .{ .secret = .{} };
    blst.c.scalar_from_bendian(&key.secret.key, &bytes);
    // Rejects zero and anything at or above the group order instead of reducing it.
    if (!blst.c.sk_check(&key.secret.key)) {
        key.deinit();
        return d.fail("invalid BLS secret scalar", .{});
    }
    return key;
}

/// A JSON string token. std.json alone also turns an array of numbers into bytes.
const JsonString = struct {
    slice: []const u8,

    pub fn jsonParse(gpa: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) std.json.ParseError(@TypeOf(source.*))!JsonString {
        if (try source.peekNextTokenType() != .string) return error.UnexpectedToken;
        return .{ .slice = try std.json.innerParse([]const u8, gpa, source, options) };
    }
};

/// A JSON number token. std.json alone also parses an integer out of a string.
const JsonInteger = struct {
    value: u64,

    pub fn jsonParse(gpa: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) std.json.ParseError(@TypeOf(source.*))!JsonInteger {
        if (try source.peekNextTokenType() != .number) return error.UnexpectedToken;
        return .{ .value = try std.json.innerParse(u64, gpa, source, options) };
    }
};

pub const Campaign = struct {
    service: []const u8,
    network: []const u8,
    campaign: []const u8,
    lifetime_secs: u64,
};

/// Strings in the result point into `arena`.
pub fn parseCampaign(arena: std.mem.Allocator, text: []const u8, d: *Diagnostic) error{Failed}!Campaign {
    const Json = struct { service: JsonString, network: JsonString, campaign: JsonString, lifetime_secs: JsonInteger };
    const json = std.json.parseFromSliceLeaky(Json, arena, text, .{}) catch
        return d.fail("campaign JSON must contain exactly service, network, campaign (strings) and lifetime_secs (integer)", .{});
    const campaign: Campaign = .{
        .service = json.service.slice,
        .network = json.network.slice,
        .campaign = json.campaign.slice,
        .lifetime_secs = json.lifetime_secs.value,
    };
    inline for (.{ "service", "network", "campaign" }) |field| {
        if (std.mem.trim(u8, @field(campaign, field), " \t\r\n").len == 0) {
            return d.fail("campaign " ++ field ++ " must be a nonempty string", .{});
        }
    }
    if (campaign.lifetime_secs == 0 or campaign.lifetime_secs > max_safe_integer) {
        return d.fail("campaign lifetime_secs must be a positive safe integer", .{});
    }
    if (!isAllowedOrigin(campaign.service)) {
        return d.fail("service must be a lowercase HTTPS origin without a trailing slash; HTTP is allowed only on loopback", .{});
    }
    return campaign;
}

/// Accepts exactly the serialized origin `scheme://host[:port]`: no path,
/// userinfo or default port, so the signed value is the one the server compares.
fn isAllowedOrigin(service: []const u8) bool {
    const Scheme = struct { prefix: []const u8, default_port: []const u8 };
    const scheme: Scheme = if (std.mem.startsWith(u8, service, "https://"))
        .{ .prefix = "https://", .default_port = "443" }
    else if (std.mem.startsWith(u8, service, "http://"))
        .{ .prefix = "http://", .default_port = "80" }
    else
        return false;
    const authority = service[scheme.prefix.len..];

    const host_end = if (std.mem.startsWith(u8, authority, "["))
        (std.mem.indexOfScalar(u8, authority, ']') orelse return false) + 1
    else
        std.mem.indexOfScalar(u8, authority, ':') orelse authority.len;
    const host = authority[0..host_end];
    if (!isHost(host)) return false;

    const rest = authority[host_end..];
    if (rest.len != 0) {
        if (rest[0] != ':') return false;
        const port = rest[1..];
        if (port.len == 0 or port[0] == '0' or std.mem.eql(u8, port, scheme.default_port)) return false;
        // parseInt alone also accepts a leading '+' and '_' separators.
        for (port) |ch| if (!std.ascii.isDigit(ch)) return false;
        _ = std.fmt.parseInt(u16, port, 10) catch return false;
    }

    if (std.mem.eql(u8, scheme.prefix, "https://")) return true;
    const loopback = [_][]const u8{ "127.0.0.1", "[::1]", "localhost" };
    return for (loopback) |name| {
        if (std.mem.eql(u8, host, name)) break true;
    } else false;
}

fn isHost(host: []const u8) bool {
    if (host.len == 0) return false;
    if (host[0] == '[') {
        if (host.len < 3 or host[host.len - 1] != ']') return false;
        for (host[1 .. host.len - 1]) |ch| switch (ch) {
            '0'...'9', 'a'...'f', ':', '.' => {},
            else => return false,
        };
        return true;
    }
    for (host) |ch| switch (ch) {
        '0'...'9', 'a'...'z', '.', '-' => {},
        else => return false,
    };
    return true;
}

/// Field order is the serialization order of the signed bytes.
pub const Manifest = struct {
    protocol: []const u8 = protocol,
    service: []const u8,
    network: []const u8,
    campaign: []const u8,
    pool_id: []const u8,
    submission_id: []const u8,
    file_hash: []const u8,
    file_size: u64,
    filename: []const u8,
    expires_at: u64,
};

pub fn encodeManifest(gpa: std.mem.Allocator, manifest: Manifest) error{OutOfMemory}![]u8 {
    return std.json.Stringify.valueAlloc(gpa, manifest, .{});
}

/// The server stores the filename as a UTF-8 display name.
pub fn isDisplayName(name: []const u8) bool {
    return std.unicode.utf8ValidateSlice(name) and std.mem.trim(u8, name, " \t\r\n").len != 0;
}

pub const Route = enum { uploads, receipts };

pub const Request = struct {
    service: []const u8,
    submission_id: []const u8,
    /// Absolute path of the signed report.
    report: []const u8,
    manifest: []const u8,
    public_key: [blst.P2_COMPRESS_BYTES]u8,
    signature: [blst.P1_COMPRESS_BYTES]u8,
};

/// Writes a `curl --config` file sending `request` to `route`.
pub fn writeCurlConfig(w: *Writer, route: Route, request: Request) Writer.Error!void {
    try w.print("# Submission {s}; holds no private key.\n", .{request.submission_id});
    try w.print("url = \"{s}/v1/{t}/{s}\"\n", .{ request.service, route, request.submission_id });
    if (route == .uploads) {
        try w.writeAll("upload-file = \"");
        try writeCurlString(w, request.report);
        try w.writeAll("\"\nheader = \"content-type: application/zip\"\n");
    }
    try w.writeAll("header = \"x-upload-manifest: ");
    try std.base64.standard.Encoder.encodeWriter(w, request.manifest);
    try w.print("\"\nheader = \"x-upload-key: {s}\"\n", .{std.fmt.bytesToHex(request.public_key, .lower)});
    try w.print("header = \"x-upload-signature: {s}\"\n", .{std.fmt.bytesToHex(request.signature, .lower)});
    // Report names and IPv6 hosts contain [] and {}, which curl otherwise expands.
    try w.writeAll("globoff\nfail-with-body\nsilent\nshow-error\n");
}

/// Escapes a value for a double-quoted curl config string.
fn writeCurlString(w: *Writer, value: []const u8) Writer.Error!void {
    for (value) |ch| switch (ch) {
        '\\' => try w.writeAll("\\\\"),
        '"' => try w.writeAll("\\\""),
        '\n' => try w.writeAll("\\n"),
        '\r' => try w.writeAll("\\r"),
        '\t' => try w.writeAll("\\t"),
        else => try w.writeByte(ch),
    };
}

const testing = std.testing;

// Public golden fixture at IntersectMBO/cardano-cli b788cd365e3dd6246d9099018f093ba351779f9c,
// cardano-cli/test/cardano-cli-golden/files/input/shelley/keys/bls_keys/.
const fixture_scalar = "6f4b2375c689e6ef27cd3fc2cce9ae8d221386c3641746ec4e8eb3d32ebd2b7c";
const fixture_public_key = "8f25d696f778b68ceca228315b9366423029d781a36c4353a9ccfc7b4e879b5827324000c1c0748d19f11ea92857d7ce004c3c11ef18949e6df8cfced42c25764ff95c3603973af54e38b7d760a2a9921959498ef895d66d8ba2266dcb69659b";
const group_order = "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001";

fn textEnvelope(comptime key_type: []const u8, comptime scalar: []const u8) []const u8 {
    return "{\"type\":\"" ++ key_type ++ "\",\"description\":\"\",\"cborHex\":\"5820" ++ scalar ++ "\"}";
}

fn verify(public_key: []const u8, signature: []const u8, message: []const u8, domain: []const u8) !bool {
    const pk = try blst.P2_Affine.from(public_key);
    const sig = try blst.P1_Affine.from(signature);
    return sig.core_verify(&pk, true, message, domain, null) == .SUCCESS;
}

test "both cardano-cli key spellings yield the golden public key and verifiable signatures" {
    var d: Diagnostic = .{ .arena = testing.allocator };
    inline for (key_types) |key_type| {
        var key = try parseKey(testing.allocator, textEnvelope(key_type, fixture_scalar), &d);
        defer key.deinit();
        const public_key = key.publicKey();
        try testing.expectEqualStrings(fixture_public_key, &std.fmt.bytesToHex(public_key, .lower));

        const message = "{\"protocol\":\"leios-artifact-upload/v1\"}";
        const signature = key.sign(message);
        try testing.expect(try verify(&public_key, &signature, message, dst));
        try testing.expect(!try verify(&public_key, &signature, message, "METSUKE_SUBMISSION_V1_BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_"));
        try testing.expect(!try verify(&public_key, &signature, message ++ " ", dst));
    }
}

test "cold keys, out-of-range scalars and malformed envelopes are rejected" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var d: Diagnostic = .{ .arena = arena.allocator() };
    const bls = key_types[0];
    const cases = [_]struct { text: []const u8, message: []const u8 }{
        .{ .text = textEnvelope("StakePoolSigningKey_ed25519", fixture_scalar), .message = "TextEnvelope containing a 32-byte scalar" },
        .{ .text = textEnvelope(bls, "00" ** 32), .message = "invalid BLS secret scalar" },
        .{ .text = textEnvelope(bls, group_order), .message = "invalid BLS secret scalar" },
        .{ .text = textEnvelope(bls, "ff" ** 32), .message = "invalid BLS secret scalar" },
        .{ .text = textEnvelope(bls, fixture_scalar[2..]), .message = "TextEnvelope containing a 32-byte scalar" },
        .{ .text = textEnvelope(bls, "zz" ++ fixture_scalar[2..]), .message = "TextEnvelope containing a 32-byte scalar" },
        .{ .text = "{\"type\":\"" ++ bls ++ "\",\"cborHex\":x5820" ++ fixture_scalar ++ "}", .message = "not a TextEnvelope JSON object" },
    };
    for (cases) |case| {
        try testing.expectError(error.Failed, parseKey(testing.allocator, case.text, &d));
        try testing.expect(std.mem.indexOf(u8, d.message, case.message) != null);
    }
}

test "campaign must be exactly the four fields with an allowed origin" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var d: Diagnostic = .{ .arena = arena.allocator() };
    const accepted = try parseCampaign(arena.allocator(),
        \\{"service":"http://[::1]:4100","network":"test","campaign":"glue","lifetime_secs":900}
    , &d);
    try testing.expectEqualStrings("http://[::1]:4100", accepted.service);
    try testing.expectEqual(@as(u64, 900), accepted.lifetime_secs);

    const rejected = [_][]const u8{
        \\{"service":"https://a.example","network":"n","campaign":"c"}
        ,
        \\{"service":"https://a.example","network":"n","campaign":"c","lifetime_secs":900,"extra":1}
        ,
        \\{"service":"https://a.example","network":" ","campaign":"c","lifetime_secs":900}
        ,
        \\{"service":"https://a.example","network":"n","campaign":"c","lifetime_secs":0}
        ,
        \\{"service":"https://a.example","network":"n","campaign":"c","lifetime_secs":9007199254740992}
        ,
        \\{"service":"https://a.example","network":"n","campaign":"c","lifetime_secs":-1}
        ,
        \\{"service":"https://a.example","network":"n","campaign":"c","lifetime_secs":"900"}
        ,
        \\{"service":"https://a.example","network":[110],"campaign":"c","lifetime_secs":900}
        ,
    };
    for (rejected) |text| try testing.expectError(error.Failed, parseCampaign(arena.allocator(), text, &d));
}

test "only serialized origins are signed, and plain HTTP only on loopback" {
    for ([_][]const u8{
        "https://uketsuke.example.org",
        "https://uketsuke.example.org:8443",
        "http://127.0.0.1:4100",
        "http://localhost",
        "http://[::1]:4100",
    }) |origin| try testing.expect(isAllowedOrigin(origin));
    for ([_][]const u8{
        "http://uketsuke.example.org",
        "https://uketsuke.example.org/",
        "https://uketsuke.example.org/v1",
        "https://Uketsuke.example.org",
        "https://uketsuke.example.org:443",
        "http://127.0.0.1:80",
        "https://uketsuke.example.org:0",
        "https://uketsuke.example.org:65536",
        "https://user@uketsuke.example.org",
        "https://uketsuke.example.org?x",
        "ftp://uketsuke.example.org",
        "https://",
        "http://[::1",
        "https://uketsuke.example.org:+8443",
        "https://uketsuke.example.org:4_43",
        "http://localhost:+80",
    }) |origin| try testing.expect(!isAllowedOrigin(origin));
}

test "upload config escapes the report path and disables globbing" {
    var out: Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try writeCurlConfig(&out.writer, .uploads, .{
        .service = "http://[::1]:4100",
        .submission_id = "10" ** 16,
        .report = "/tmp/a \"b\"\\c\nd[1]{x}.zip",
        .manifest = "{}",
        .public_key = @splat(0xaa),
        .signature = @splat(0xbb),
    });
    const config = out.written();
    try testing.expect(std.mem.indexOf(u8, config, "\nupload-file = \"/tmp/a \\\"b\\\"\\\\c\\nd[1]{x}.zip\"\n") != null);
    try testing.expect(std.mem.indexOf(u8, config, "\ngloboff\n") != null);
}
