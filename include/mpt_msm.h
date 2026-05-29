/* SPDX-License-Identifier: MIT */
#ifndef MPT_MSM_H
#define MPT_MSM_H

#include <secp256k1.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Two-profile MSM API.
 *
 * mpt_msm_variable_time   -- Vendored Pippenger/Straus from
 *                            libsecp256k1 (third_party/secp256k1-msm).
 *                            NOT constant-time. Verifier path only;
 *                            do not call with secret scalars.
 *
 * mpt_msm_constant_time   -- Public-API loop (or future CT Pippenger
 *                            variant). Safe for the prover path.
 *
 * The naming is deliberate: the constant-time requirement should be
 * audit-visible at the call site. See cmpt-ct-and-batch.tex
 * (sec:two-profile, sec:msm-options).
 */

typedef int (*mpt_msm_callback)(
    unsigned char scalar_be32[32],
    unsigned char point_sec1_33[33],
    size_t idx,
    void* data);

/**
 * @brief Variable-time multi-scalar multiplication.
 *
 * Computes r = inp_g_sc * G + sum_{i=0..n-1} s_i * P_i, where
 * (s_i, P_i) is the i-th pair returned by the callback.
 *
 * NOT constant-time. Use only on the verifier path
 * (no secret scalars). Routing prover-side MSMs through this
 * entry point breaks the prover constant-time guarantee.
 *
 * @param ctx          libsecp256k1 context (any verify-capable context).
 * @param r_sec1_33    Output buffer; receives the SEC1-compressed
 *                     result point. Identity is encoded as 33 zero bytes.
 * @param inp_g_sc_be32 Optional 32-byte big-endian scalar to multiply by
 *                     the curve generator G; pass NULL to omit.
 * @param cb           Callback returning the i-th (scalar, point) pair.
 *                     Returning 0 aborts the MSM with failure.
 * @param cbdata       Opaque pointer passed through to cb.
 * @param n            Number of (scalar, point) pairs.
 *
 * @return 1 on success, 0 on failure (callback rejection or invalid input).
 */
SECP256K1_API int
mpt_msm_variable_time(
    secp256k1_context const* ctx,
    unsigned char r_sec1_33[33],
    unsigned char const inp_g_sc_be32[32],
    mpt_msm_callback cb,
    void* cbdata,
    size_t n);

/**
 * @brief Variable-time in-place scalar multiplication on an arbitrary point.
 *
 * Computes `*pubkey = scalar * (*pubkey)` using libsecp256k1's internal
 * `secp256k1_ecmult` (the variable-time single-output scalar mul that
 * powers ecmult_multi_var). Same VT-vs-CT speedup as a 1-term call to
 * `mpt_msm_variable_time`, but without the per-call scratch alloc — for
 * the small k (1..3) MSMs that show up in compact-sigma reconstruction,
 * the scratch alloc dominates and the MSM wrapper is a net regression.
 *
 * Use only on the verifier path (no secret scalars). The constant-time
 * equivalent is `secp256k1_ec_pubkey_tweak_mul`.
 *
 * @param ctx          libsecp256k1 context (any verify-capable context).
 * @param pubkey       In/out: point to be multiplied in place. Caller-owned.
 * @param scalar_be32  32-byte big-endian scalar. Reduced mod n internally.
 *
 * @return 1 on success, 0 on failure (NULL input, identity result, or
 *         pubkey serialization/parse failure).
 */
SECP256K1_API int
mpt_ec_pubkey_mul_var(
    secp256k1_context const* ctx,
    secp256k1_pubkey* pubkey,
    unsigned char const scalar_be32[32]);

#ifdef __cplusplus
}
#endif

#endif /* MPT_MSM_H */
