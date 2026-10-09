const std = @import("std");
const linux = std.os.linux;
const beam = @import("beam");
const blst = @import("blst");

const dst = "LEIOS_ARTIFACT_UPLOAD_V1_BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";

/// BLST_ERROR from blst.h, in declaration order.
const BlstError = enum(blst.BLST_ERROR) {
    success,
    bad_encoding,
    point_not_on_curve,
    point_not_in_group,
    aggr_type_mismatch,
    verify_fail,
    pk_is_infinity,
    bad_scalar,
};

fn outcome(comptime tag: @EnumLiteral(), rc: blst.BLST_ERROR) beam.term {
    const reason = if (std.enums.fromInt(BlstError, rc)) |known| beam.make(known, .{}) else beam.make(rc, .{});
    return beam.make(.{ tag, reason }, .{});
}

/// Returns `:verified`, `{:rejected, reason}` for a signature that fails, or
/// `{:invalid_key, reason}` for a key that no roster should contain.
pub fn verify(key: [96]u8, signature: [48]u8, message: []const u8) beam.term {
    var pk: blst.blst_p2_affine = undefined;
    const pk_rc = blst.blst_p2_uncompress(&pk, &key);
    if (pk_rc != blst.BLST_SUCCESS) return outcome(.invalid_key, pk_rc);
    if (blst.blst_p2_affine_is_inf(&pk)) return outcome(.invalid_key, blst.BLST_PK_IS_INFINITY);
    if (!blst.blst_p2_affine_in_g2(&pk)) return outcome(.invalid_key, blst.BLST_POINT_NOT_IN_GROUP);

    var sig: blst.blst_p1_affine = undefined;
    const sig_rc = blst.blst_p1_uncompress(&sig, &signature);
    if (sig_rc != blst.BLST_SUCCESS) return outcome(.rejected, sig_rc);
    // blst_core_verify skips an infinite signature instead of rejecting it.
    if (blst.blst_p1_affine_is_inf(&sig)) return outcome(.rejected, blst.BLST_PK_IS_INFINITY);

    // Group-checks both points; hash_or_encode = true selects hash_to_curve.
    const rc = blst.blst_core_verify_pk_in_g2(&pk, &sig, true, message.ptr, message.len, dst, dst.len, null, 0);
    if (rc != blst.BLST_SUCCESS) return outcome(.rejected, rc);
    return beam.make(.verified, .{});
}

/// `:ok`, or `{:error, posix}` using Erlang's lowercase errno atoms.
fn result(err: linux.E) beam.term {
    if (err == .SUCCESS) return beam.make(.ok, .{});
    const name = std.enums.tagName(linux.E, err) orelse
        return beam.make(.{ .@"error", @intFromEnum(err) }, .{});
    var atom: [errno_atom_len]u8 = undefined;
    atom[0] = 'e';
    for (name, atom[1 .. name.len + 1]) |char, *lower| lower.* = std.ascii.toLower(char);
    return beam.make(.{ .@"error", beam.make_into_atom(atom[0 .. name.len + 1], .{}) }, .{});
}

/// Longest errno name plus the `e` prefix, so `result` cannot overrun its buffer.
const errno_atom_len = blk: {
    var longest: usize = 0;
    for (@typeInfo(linux.E).@"enum".fields) |field| longest = @max(longest, field.name.len);
    break :blk longest + 1;
};

fn open(path: [*:0]const u8, flags: linux.O, fd: *linux.fd_t) linux.E {
    while (true) {
        const rc = linux.open(path, flags, 0);
        switch (linux.errno(rc)) {
            .SUCCESS => {
                fd.* = @intCast(rc);
                return .SUCCESS;
            },
            .INTR => continue,
            else => |err| return err,
        }
    }
}

fn fsync(fd: linux.fd_t) linux.E {
    while (true) {
        switch (linux.errno(linux.fsync(fd))) {
            .INTR => continue,
            else => |err| return err,
        }
    }
}

const PathBuf = [linux.PATH_MAX]u8;

/// NUL-terminates `path` in `buf`. Paths arrive as `[]const u8` because Zigler
/// borrows those zero-copy, while a `[:0]const u8` parameter is copied into a
/// buffer its cleanup never frees.
fn terminate(path: []const u8, buf: *PathBuf) PathError![*:0]const u8 {
    if (path.len >= buf.len) return error.NameTooLong;
    if (std.mem.findScalar(u8, path, 0) != null) return error.EmbeddedNul;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    return buf[0..path.len :0];
}

const PathError = error{ NameTooLong, EmbeddedNul };

fn pathError(err: PathError) beam.term {
    return result(switch (err) {
        error.NameTooLong => .NAMETOOLONG,
        error.EmbeddedNul => .INVAL,
    });
}

/// fsyncs a directory; `follow = false` refuses a symlink as the final component.
pub fn fsync_directory(path: []const u8, follow: bool) beam.term {
    var buf: PathBuf = undefined;
    const c_path = terminate(path, &buf) catch |err| return pathError(err);
    var fd: linux.fd_t = undefined;
    const opened = open(c_path, .{ .DIRECTORY = true, .NOFOLLOW = !follow, .CLOEXEC = true }, &fd);
    if (opened != .SUCCESS) return result(opened);
    defer _ = linux.close(fd);
    return result(fsync(fd));
}

/// fsyncs a regular file, refusing symlinks, FIFOs and other special files.
pub fn fsync_regular(path: []const u8) beam.term {
    var buf: PathBuf = undefined;
    const c_path = terminate(path, &buf) catch |err| return pathError(err);
    var fd: linux.fd_t = undefined;
    const opened = open(c_path, .{ .NOFOLLOW = true, .NONBLOCK = true, .CLOEXEC = true }, &fd);
    if (opened != .SUCCESS) return result(opened);
    defer _ = linux.close(fd);
    var stat: linux.Statx = undefined;
    const statted = linux.errno(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .TYPE = true }, &stat));
    if (statted != .SUCCESS) return result(statted);
    if (linux.S.ISDIR(stat.mode)) return beam.make(.{ .@"error", .eisdir }, .{});
    // EFTYPE is BSD's "inappropriate file type"; Linux has no closer errno.
    if (!linux.S.ISREG(stat.mode)) return beam.make(.{ .@"error", .eftype }, .{});
    return result(fsync(fd));
}

/// Renames without replacing anything, not even an empty directory.
pub fn rename_noreplace(from: []const u8, to: []const u8) beam.term {
    var from_buf: PathBuf = undefined;
    var to_buf: PathBuf = undefined;
    const c_from = terminate(from, &from_buf) catch |err| return pathError(err);
    const c_to = terminate(to, &to_buf) catch |err| return pathError(err);
    return result(linux.errno(linux.renameat2(linux.AT.FDCWD, c_from, linux.AT.FDCWD, c_to, .{ .NOREPLACE = true })));
}
