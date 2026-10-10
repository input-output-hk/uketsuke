const std = @import("std");
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

