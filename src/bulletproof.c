#include "secp256k1_mpt.h"
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <secp256k1.h>

#define N_BITS 64
#define IPA_ROUNDS 6

/**
 * Generates a  secure 32-byte scalar (private key).
 * NOTE: This is a TEMPORARY duplication of a helper that will be moved to proof_util.c.
 * Returns 1 on success, 0 on failure.
 */
static int generate_random_scalar(
        const secp256k1_context* ctx,
        unsigned char* scalar_bytes)
{
    do {
        if (RAND_bytes(scalar_bytes, 32) != 1) {
            return 0; // Randomness failure
        }
    } while (secp256k1_ec_seckey_verify(ctx, scalar_bytes) != 1);
    return 1;
}
/**
 * Computes the point M = amount * G.
 * Internal helper used by commitment construction.
 */
static int compute_amount_point(
        const secp256k1_context* ctx,
        secp256k1_pubkey* mG,
        uint64_t amount)
{
    unsigned char amount_scalar[32] = {0};
    assert(amount != 0);

    for (int i = 0; i < 8; ++i) {
        amount_scalar[31 - i] = (amount >> (i * 8)) & 0xFF;
    }
    return secp256k1_ec_pubkey_create(ctx, mG, amount_scalar);
}
/**
 * Computes the modular dot product c = <a, b> = sum(a[i] * b[i]) mod q.
 * This function calculates the inner product of two scalar vectors.
 * ctx       The context.
 * out       Output 32-byte scalar (the inner product result).
 * a         Input scalar vector A (n * 32 bytes).
 * b         Input scalar vector B (n * 32 bytes).
 * n         The length of the vectors.
 * 1 on success, 0 on failure.
 */
int secp256k1_bulletproof_ipa_dot(const secp256k1_context* ctx, unsigned char* out, const unsigned char* a, const unsigned char* b, size_t n) {
    unsigned char acc[32] = {0};
    unsigned char term[32];
    for (size_t i = 0; i < n; i++) {
        /* Use internal mul */
        secp256k1_mpt_scalar_mul(term, a + i * 32, b + i * 32);
        /* Use internal add */
        secp256k1_mpt_scalar_add(acc, acc, term);
    }
    memcpy(out, acc, 32);
    return 1;
}

//We need this helper for the multi-scalar multiplication function below

int secp256k1_bulletproof_add_point_to_accumulator(
    const secp256k1_context* ctx,
    secp256k1_pubkey* acc,
    const secp256k1_pubkey* term)
{
    const secp256k1_pubkey* points[2] = {acc, term};
    secp256k1_pubkey temp_sum;

    if (secp256k1_ec_pubkey_combine(ctx, &temp_sum, points, 2) != 1) return 0;
    *acc = temp_sum;
    return 1;
}

/**
 * Computes Multiscalar Multiplication (MSM): R = sum(s[i] * P[i]).
 * ctx       The context.
 * r_out     Output point (the sum R).
 * points    Array of N input points (secp256k1_pubkey).
 * scalars   Flat array of N 32-byte scalars.
 * n         The number of terms (N).
 * return    1 on success, 0 on failure.
 * NOTE: This MSM is used only for Bulletproofs where all scalars are public.
 * It is NOT constant-time with respect to scalars and MUST NOT be used
 * for secret-key operations.
 */
int secp256k1_bulletproof_ipa_msm(
        const secp256k1_context* ctx,
        secp256k1_pubkey* r_out,
        const secp256k1_pubkey* points,
        const unsigned char* scalars,
        size_t n
) {
    secp256k1_pubkey acc;
    int initialized = 0;
    unsigned char zero[32] = {0};

    for (size_t i = 0; i < n; ++i) {
        /* Check if scalar is zero */
        if (memcmp(scalars + i * 32, zero, 32) == 0) {
            continue; /* 0 * P = Infinity, so we skip adding it */
        }

        secp256k1_pubkey term = points[i];
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &term, scalars + i * 32)) {
            return 0; /* Mathematical failure (should not happen with non-zero) */
        }

        if (!initialized) {
            acc = term;
            initialized = 1;
        } else {
            if (!secp256k1_bulletproof_add_point_to_accumulator(ctx, &acc, &term)) {
                return 0;
            }
        }
    }

    /* In Bulletproofs, this case cannot occur for valid proofs (aL/aR ≠ 0). */

    if (!initialized) {
        /* Optional: Handle edge case where all scalars are 0
           For now, just return a failure if the amount was 0. */
        return 0;
    }

    *r_out = acc;
    return 1;
}

/**
 * Computes component-wise: result[i] = a[i] * b[i] (Hadamard product)
 */
void scalar_vector_mul(const secp256k1_context* ctx, unsigned char res[][32],
                       unsigned char a[][32], unsigned char b[][32], size_t n) {
    for (size_t i = 0; i < n; i++) {
        secp256k1_mpt_scalar_mul(res[i], a[i], b[i]);
    }
}

/**
 * Computes component-wise: result[i] = a[i] + b[i]
 */
void scalar_vector_add(const secp256k1_context* ctx, unsigned char res[][32],
                       unsigned char a[][32], unsigned char b[][32], size_t n) {
    for (size_t i = 0; i < n; i++) {
        secp256k1_mpt_scalar_add(res[i], a[i], b[i]);
    }

}

/**
 * Fills a vector with powers of a scalar: [1, y, y^2, ..., y^{n-1}]
 */
void scalar_vector_powers(const secp256k1_context* ctx, unsigned char res[][32],
                          const unsigned char* y, size_t n) {
    unsigned char one[32] = {0};
    one[31] = 1;
    memcpy(res[0], one, 32);
    for (size_t i = 1; i < n; i++) {
        /* Use internal math to avoid zero-check failures */
        secp256k1_mpt_scalar_mul(res[i], res[i-1], y);
    }
}

/* y_pow_out = y^i (mod n), for i >= 0 */
static void scalar_pow_u32(const secp256k1_context* ctx,
                           unsigned char y_pow_out[32],
                           const unsigned char y[32],
                           unsigned int i)
{
    unsigned char one[32] = {0};
    one[31] = 1;
    memcpy(y_pow_out, one, 32);

    while (i--) {
        secp256k1_mpt_scalar_mul(y_pow_out, y_pow_out, y);
    }
}

/*Point = Scalar * Point (using public API)*/

static int secp256k1_bulletproof_point_scalar_mul(
        const secp256k1_context* ctx,
        secp256k1_pubkey* r_out,
        const secp256k1_pubkey* p_in,
        const unsigned char* s_scalar)
{
    *r_out = *p_in;
    return secp256k1_ec_pubkey_tweak_mul(ctx, r_out, s_scalar);
}

/* Computes:
 *   y_sum   = sum_{i=0}^{n-1} y^i
 *   two_sum = sum_{i=0}^{n-1} 2^i
 * Used in verifier computation of delta(y, z) in Bulletproofs.
 */
static void compute_delta_scalars(const secp256k1_context* ctx, unsigned char* y_sum,
                                  unsigned char* two_sum, const unsigned char* y, int n) {
    unsigned char y_pow[32], two_pow[32], one[32] = {0};
    int i;
    one[31] = 1;

    memset(y_sum, 0, 32);
    memset(two_sum, 0, 32);
    memcpy(y_pow, one, 32);
    memcpy(two_pow, one, 32);

    for (i = 0; i < n; i++) {
        secp256k1_mpt_scalar_add(y_sum, y_sum, y_pow);
        secp256k1_mpt_scalar_add(two_sum, two_sum, two_pow);

        secp256k1_mpt_scalar_mul(y_pow, y_pow, y); /* y^(i+1) */
        secp256k1_mpt_scalar_add(two_pow, two_pow, two_pow);
    }
}
/* Compare two secp256k1 public keys for equality.
 * Uses canonical compressed serialization (33 bytes).
 * This comparison is NOT constant-time but public keys
 * are not secret and this is used only in verification logic.
 */
static int pubkey_equal(const secp256k1_context* ctx, const secp256k1_pubkey* a, const secp256k1_pubkey* b) {
    return secp256k1_ec_pubkey_cmp(ctx, a, b) == 0;
}

/*
 * Fold a generator vector into a single generator according to the IPA
 * challenges u_j and u_j^{-1}.
 *
 * After log2(n) IPA rounds, each original generator G_i or H_i contributes to
 * the final generator with a scalar weight equal to the product of per-round
 * challenges determined by the binary index of i.
 *
 * For each round j:
 *   - bit = j-th bit of index i
 *
 *   G folding rule:
 *     left  (bit = 0): multiply by u_j^{-1}
 *     right (bit = 1): multiply by u_j
 *
 *   H folding rule (intentionally opposite):
 *     left  (bit = 0): multiply by u_j
 *     right (bit = 1): multiply by u_j^{-1}
 *
 * The final generator is computed as an MSM over the original generator vector
 * with the derived scalar weights.
 */
int fold_generators(
        const secp256k1_context* ctx,
        secp256k1_pubkey* final_point,
        const secp256k1_pubkey* generators,
        const unsigned char u[6][32],
        const unsigned char u_inv[6][32],
        int n,
        int is_H   /* 0 = G folding, 1 = H folding */
) {
    /* Safety Check: Ensure we don't overflow the fixed buffer */
    if (n > 64) return 0;

    unsigned char s_flat[64 * 32];
    unsigned char current_s[32];
    int i, j, ok = 0;

    for (i = 0; i < n; i++) {
        /* Initialize current_s = 1 */
        memset(current_s, 0, 32);
        current_s[31] = 1;

        for (j = 0; j < 6; j++) {
            /* Check the j-th bit of index i (from MSB down) */
            int bit = (i >> (5 - j)) & 1;

            if (!is_H) {
                /* G folding: bit 0 -> u_inv, bit 1 -> u */
                secp256k1_mpt_scalar_mul(current_s, current_s, bit ? u[j] : u_inv[j]);
            } else {
                /* H folding: bit 0 -> u, bit 1 -> u_inv */
                secp256k1_mpt_scalar_mul(current_s, current_s, bit ? u_inv[j] : u[j]);
            }
        }

        memcpy(s_flat + (i * 32), current_s, 32);
    }

    ok = secp256k1_bulletproof_ipa_msm(ctx, final_point, generators, s_flat, n);

    /* Cleanup stack usage */
    OPENSSL_cleanse(s_flat, sizeof(s_flat));
    OPENSSL_cleanse(current_s, 32);

    return ok;
}

/*
 * Apply the verifier-side IPA updates to P.
 * For each round i, update:
 *   P <- P + u_i^2 * L_i + u_i^{-2} * R_i
 * This mirrors the prover’s recursive folding and prepares P for the final
 * single-generator inner product check.
 */
int apply_ipa_folding_to_P(
        const secp256k1_context* ctx,
        secp256k1_pubkey* P,
        const secp256k1_pubkey* L_vec,
        const secp256k1_pubkey* R_vec,
        const unsigned char u[6][32],
        const unsigned char u_inv[6][32]
) {
    unsigned char u_sq[32], u_inv_sq[32];
    secp256k1_pubkey acc, tL, tR;
    const secp256k1_pubkey* pts[3];
    int i, ok = 1;

    for (i = 0; i < 6; i++) {
        /* 1. Compute Scalar Squares: u^2 and u^-2 */
        secp256k1_mpt_scalar_mul(u_sq, u[i], u[i]);
        secp256k1_mpt_scalar_mul(u_inv_sq, u_inv[i], u_inv[i]);

        /* 2. Prepare Accumulator (Current P) */
        acc = *P;

        /* 3. L term: L_i * u^2 */
        tL = L_vec[i];
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &tL, u_sq)) {
            ok = 0;
            break;
        }

        /* 4. R term: R_i * u^-2 */
        tR = R_vec[i];
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &tR, u_inv_sq)) {
            ok = 0;
            break;
        }

        /* 5. Combine: P_new = P_old + tL + tR */
        pts[0] = &acc; pts[1] = &tL; pts[2] = &tR;
        if (!secp256k1_ec_pubkey_combine(ctx, P, pts, 3)) {
            ok = 0;
            break;
        }
    }

    /* Cleanup intermediate scalars */
    OPENSSL_cleanse(u_sq, 32);
    OPENSSL_cleanse(u_inv_sq, 32);

    return ok;
}


/**
 * Computes the cross-term commitments L and R.
 * L = <a_L, G_R> + <b_R, H_L> + c_L * ux * g
 * R = <a_R, G_L> + <b_L, H_R> + c_R * ux * g
 *
 * ctx       The context.
 * L         Output: Commitment point L_j.
 * R         Output: Commitment point R_j.
 * half_n    Length of the input vector halves.
 * g         The blinding generator point (Pk_base in our case).
 * return    1 on success, 0 on failure.
 */
int secp256k1_bulletproof_ipa_compute_LR(
        const secp256k1_context* ctx,
        secp256k1_pubkey* L, secp256k1_pubkey* R,
        const unsigned char* a_L, const unsigned char* a_R,
        const unsigned char* b_L, const unsigned char* b_R,
        const secp256k1_pubkey* G_L, const secp256k1_pubkey* G_R,
        const secp256k1_pubkey* H_L, const secp256k1_pubkey* H_R,
        const secp256k1_pubkey* g,
        const unsigned char* ux,
        size_t half_n
) {
    /* Intermediate Scalars (Sensitive - derived from secrets) */
    unsigned char c_L_scalar[32], c_R_scalar[32];
    unsigned char cL_ux_scalar[32], cR_ux_scalar[32];

    /* Intermediate Points */
    secp256k1_pubkey T1, T2;

    int ok = 0;

    /* 1. Compute Cross-Term Scalars: c_L = <a_L, b_R>, c_R = <a_R, b_L> */
    if (!secp256k1_bulletproof_ipa_dot(ctx, c_L_scalar, a_L, b_R, half_n)) goto cleanup;
    if (!secp256k1_bulletproof_ipa_dot(ctx, c_R_scalar, a_R, b_L, half_n)) goto cleanup;

    /* 2. Compute L: L = <a_L, G_R> + <b_R, H_L> + (c_L * ux * g) */

    /* Term 1: <a_L, G_R> */
    if (!secp256k1_bulletproof_ipa_msm(ctx, L, G_R, a_L, half_n)) goto cleanup;

    /* Term 2: <b_R, H_L> */
    if (!secp256k1_bulletproof_ipa_msm(ctx, &T1, H_L, b_R, half_n)) goto cleanup;

    /* Combine T1 into L */
    if (!secp256k1_bulletproof_add_point_to_accumulator(ctx, L, &T1)) goto cleanup;

    /* Term 3: Blinding Factor (c_L * ux * g) */
    secp256k1_mpt_scalar_mul(cL_ux_scalar, c_L_scalar, ux);
    if (!secp256k1_bulletproof_point_scalar_mul(ctx, &T2, g, cL_ux_scalar)) goto cleanup;

    /* Combine T2 into L */
    if (!secp256k1_bulletproof_add_point_to_accumulator(ctx, L, &T2)) goto cleanup;


    /* 3. Compute R: R = <a_R, G_L> + <b_L, H_R> + (c_R * ux * g) */

    /* Term 1: <a_R, G_L> */
    if (!secp256k1_bulletproof_ipa_msm(ctx, R, G_L, a_R, half_n)) goto cleanup;

    /* Term 2: <b_L, H_R> */
    if (!secp256k1_bulletproof_ipa_msm(ctx, &T1, H_R, b_L, half_n)) goto cleanup;

    /* Combine T1 into R */
    if (!secp256k1_bulletproof_add_point_to_accumulator(ctx, R, &T1)) goto cleanup;

    /* Term 3: Blinding Factor (c_R * ux * g) */
    secp256k1_mpt_scalar_mul(cR_ux_scalar, c_R_scalar, ux);
    if (!secp256k1_bulletproof_point_scalar_mul(ctx, &T2, g, cR_ux_scalar)) goto cleanup;

    /* Combine T2 into R */
    if (!secp256k1_bulletproof_add_point_to_accumulator(ctx, R, &T2)) goto cleanup;

    ok = 1;

    cleanup:
    /* Securely wipe the cross-term scalars */
    OPENSSL_cleanse(c_L_scalar, 32);
    OPENSSL_cleanse(c_R_scalar, 32);
    OPENSSL_cleanse(cL_ux_scalar, 32);
    OPENSSL_cleanse(cR_ux_scalar, 32);

    return ok;
}
/**
 * Executes one IPA compression step (the vector update).
 * This computes the new compressed vectors (a', b', G', H') and overwrites the
 * first half of the input arrays (in-place).
 *
 * ctx       The context.
 * a, b      IN/OUT: Scalar vectors (a and b).
 * G, H      IN/OUT: Generator vectors (G and H).
 * half_n    The length of the new, compressed vectors (N/2).
 * x         The challenge scalar x.
 * x_inv     The challenge scalar inverse x^-1.
 * return    1 on success, 0 on failure.
 */
int secp256k1_bulletproof_ipa_compress_step(
        const secp256k1_context* ctx,
        unsigned char* a,
        unsigned char* b,
        secp256k1_pubkey* G,
        secp256k1_pubkey* H,
        size_t half_n,
        const unsigned char* x,
        const unsigned char* x_inv
) {
    size_t i;
    int ok = 1;

    /* Temporary variables (Sensitive - derived from secrets) */
    unsigned char t1_scalar[32], t2_scalar[32];

    /* Temporary variables (Public points) */
    secp256k1_pubkey left, right;
    const secp256k1_pubkey* pts[2];

    for (i = 0; i < half_n; ++i) {

        /* --- SCALAR VECTORS: a'[i] = a[i]*x + a[i+half_n]*x_inv --- */
        {
            unsigned char* a_L = a + i * 32;
            unsigned char* a_R = a + (i + half_n) * 32;

            secp256k1_mpt_scalar_mul(t1_scalar, a_L, x);
            secp256k1_mpt_scalar_mul(t2_scalar, a_R, x_inv);
            secp256k1_mpt_scalar_add(a_L, t1_scalar, t2_scalar); /* Update a[i] in-place */
        }

        /* --- SCALAR VECTORS: b'[i] = b[i]*x_inv + b[i+half_n]*x --- */
        {
            unsigned char* b_L = b + i * 32;
            unsigned char* b_R = b + (i + half_n) * 32;

            secp256k1_mpt_scalar_mul(t1_scalar, b_L, x_inv);
            secp256k1_mpt_scalar_mul(t2_scalar, b_R, x);
            secp256k1_mpt_scalar_add(b_L, t1_scalar, t2_scalar); /* Update b[i] in-place */
        }

        /* --- POINT VECTORS: G'[i] = G[i]*x_inv + G[i+half_n]*x --- */
        {
            left = G[i];
            right = G[i + half_n];

            if (!secp256k1_ec_pubkey_tweak_mul(ctx, &left, x_inv)) { ok = 0; goto cleanup; }
            if (!secp256k1_ec_pubkey_tweak_mul(ctx, &right, x)) { ok = 0; goto cleanup; }

            pts[0] = &left; pts[1] = &right;
            if (!secp256k1_ec_pubkey_combine(ctx, &G[i], pts, 2)) { ok = 0; goto cleanup; }
        }

        /* --- POINT VECTORS: H'[i] = H[i]*x + H[i+half_n]*x_inv --- */
        {
            left = H[i];
            right = H[i + half_n];

            if (!secp256k1_ec_pubkey_tweak_mul(ctx, &left, x)) { ok = 0; goto cleanup; }
            if (!secp256k1_ec_pubkey_tweak_mul(ctx, &right, x_inv)) { ok = 0; goto cleanup; }

            pts[0] = &left; pts[1] = &right;
            if (!secp256k1_ec_pubkey_combine(ctx, &H[i], pts, 2)) { ok = 0; goto cleanup; }
        }
    }

    cleanup:
    /* Securely wipe the intermediate scalars that mixed secrets */
    OPENSSL_cleanse(t1_scalar, 32);
    OPENSSL_cleanse(t2_scalar, 32);

    return ok;
}
static int scalar_is_zero(const unsigned char s[32]) {
    unsigned char z[32] = {0};
    return memcmp(s, z, 32) == 0;
}

/* Safe accumulate: acc <- acc + term. If acc not inited, acc = term. */
static int add_term(
        const secp256k1_context* ctx,
        secp256k1_pubkey* acc,
        int* acc_inited,
        const secp256k1_pubkey* term
) {
    if (!(*acc_inited)) {
        *acc = *term;
        *acc_inited = 1;
        return 1;
    } else {
        secp256k1_pubkey sum;
        const secp256k1_pubkey* pts[2] = { acc, term };
        if (!secp256k1_ec_pubkey_combine(ctx, &sum, pts, 2)) return 0;
        *acc = sum;
        return 1;
    }
}

/*
 * ux is the fixed IPA binding scalar.
 *
 * It MUST be derived exactly once from:
 *     ux = H(commit_inp || <a,b>)
 *
 * and reused consistently throughout the IPA:
 *   - L/R cross-term construction
 *   - final (a·b·ux)·g term
 *
 * It MUST NOT depend on per-round challenges (u_i),
 * and MUST be identical for prover and verifier.
 */
int derive_ipa_binding_challenge(
        const secp256k1_context* ctx,
        unsigned char* ux_out,
        const unsigned char* commit_inp_32,
        const unsigned char* dot_32)
{
    unsigned char hash_input[64];
    unsigned char hash_output[32];

    /* 1. Build hash input = commit_inp || dot */
    memcpy(hash_input, commit_inp_32, 32);
    memcpy(hash_input + 32, dot_32, 32);

    /* 2. Hash */
    SHA256(hash_input, 64, hash_output);

    /* 3. Reduce hash to a valid scalar */
    /* CRITICAL: Wraps the 32-byte random string into the curve order */
    secp256k1_mpt_scalar_reduce32(ux_out, hash_output);

    /* * 4. Verify (Sanity check)
     * Reduce32 guarantees the value is < Order.
     * This checks for the virtually impossible case where hash is exactly 0.
     */
    if (secp256k1_ec_seckey_verify(ctx, ux_out) != 1) {
        return 0;
    }

    return 1;
}
/* Derive u = H(last_challenge || L || R) reduced to a valid scalar.
 * IMPORTANT: use the SAME exact logic in verifier.
 */
int derive_ipa_round_challenge(
        const secp256k1_context* ctx,
        unsigned char u_out[32],
        const unsigned char last_challenge[32],
        const secp256k1_pubkey* L,
        const secp256k1_pubkey* R)
{
    unsigned char L_ser[33], R_ser[33];
    size_t len = 33;
    SHA256_CTX sha;
    unsigned char hash[32];

    if (!secp256k1_ec_pubkey_serialize(ctx, L_ser, &len, L, SECP256K1_EC_COMPRESSED)) return 0;
    len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, R_ser, &len, R, SECP256K1_EC_COMPRESSED)) return 0;

    SHA256_Init(&sha);
    SHA256_Update(&sha, last_challenge, 32);
    SHA256_Update(&sha, L_ser, 33);
    SHA256_Update(&sha, R_ser, 33);
    SHA256_Final(hash, &sha);
    secp256k1_mpt_scalar_reduce32(hash, hash);
    memcpy(u_out, hash, 32);

    /* Reject invalid scalar (0 or >= group order). */
    if (secp256k1_ec_seckey_verify(ctx, u_out) != 1) return 0;

    return 1;
}

/**
 * Executes the core recursive Inner Product Argument (IPA) Prover.
 * This function iteratively compresses the scalar and generator vectors down to
 * the final two scalars (a_final, b_final), while recording the L/R proof points.
 *
 * ctx           The context.
 * g             The special blinding generator point.
 * G_vec, H_vec  IN/OUT: Generator vectors (compressed in-place).
 * a_vec, b_vec  IN/OUT: Scalar vectors (compressed in-place).
 * n             The starting length of the vectors (must be power of two, e.g., 64).
 * commit_inp    32-byte initial commitment input for the transcript.
 * dot_out       Output: The final initial inner product <a,b>.
 * L_out, R_out  Output: Arrays to store the log2(n) L/R proof points.
 * a_final, b_final Output: The final scalar components.
 * return        1 on success, 0 on failure.
 */
/* You need this helper (or equivalent) somewhere shared by prover+verifier.
 *
 * Derive u = H(last_challenge || L || R) reduced to a valid scalar.
 * IMPORTANT: use the SAME exact logic in verifier.
 */


int secp256k1_bulletproof_run_ipa_prover(
        const secp256k1_context* ctx,
        const secp256k1_pubkey* g,
        secp256k1_pubkey* G_vec,
        secp256k1_pubkey* H_vec,
        unsigned char* a_vec,
        unsigned char* b_vec,
        size_t n,
        const unsigned char ipa_transcript_id[32],
        const unsigned char ux_scalar[32],
        secp256k1_pubkey* L_out,
        secp256k1_pubkey* R_out,
        unsigned char* a_final,
        unsigned char* b_final
) {
    size_t rounds = 0;
    size_t cur_n = n;
    size_t r;
    int ok = 0;

    unsigned char u_scalar[32], u_inv[32];
    unsigned char last_challenge[32];

    /* Validate n is power of 2 */
    if (n == 0 || (n & (n - 1)) != 0) return 0;

    /* Calculate log2(n) */
    while (cur_n > 1) { cur_n >>= 1; rounds++; }
    cur_n = n;

    /* Seed transcript */
    memcpy(last_challenge, ipa_transcript_id, 32);

    for (r = 0; r < rounds; ++r) {
        size_t half_n = cur_n >> 1;
        secp256k1_pubkey Lr, Rr;

        /* 1. Compute L and R for this round */
        if (!secp256k1_bulletproof_ipa_compute_LR(
                ctx, &Lr, &Rr,
                a_vec, a_vec + half_n * 32,
                b_vec, b_vec + half_n * 32,
                G_vec, G_vec + half_n,
                H_vec, H_vec + half_n,
                g,
                ux_scalar,
                half_n
        )) goto cleanup;

        /* Store L/R in output array */
        L_out[r] = Lr;
        R_out[r] = Rr;

        /* 2. Update Fiat-Shamir Transcript -> Generate u */
        if (!derive_ipa_round_challenge(ctx, u_scalar, last_challenge, &Lr, &Rr)) goto cleanup;

        /* 3. Compute u_inv */
        secp256k1_mpt_scalar_inverse(u_inv, u_scalar);

        /* Sanity check inverse (should be valid if u is valid) */
        if (!secp256k1_ec_seckey_verify(ctx, u_inv)) goto cleanup;

        /* Update transcript chaining variable */
        memcpy(last_challenge, u_scalar, 32);

        /* 4. Fold vectors (compress step) */
        if (!secp256k1_bulletproof_ipa_compress_step(
                ctx, a_vec, b_vec, G_vec, H_vec, half_n, u_scalar, u_inv
        )) goto cleanup;

        cur_n = half_n;
    }

    /* Final recursion output: a and b are now length 1 */
    memcpy(a_final, a_vec, 32);
    memcpy(b_final, b_vec, 32);

    ok = 1;

    cleanup:
    /* Wipe scalars used in folding */
    OPENSSL_cleanse(u_scalar, 32);
    OPENSSL_cleanse(u_inv, 32);

    return ok;
}
/*
 * Verifies a Bulletproof Inner Product Argument (IPA).
 *
 * Given:
 *   - the original generator vectors G_vec and H_vec,
 *   - the prover’s cross-term commitments L_i and R_i,
 *   - the final folded scalars a_final and b_final,
 *   - the binding scalar ux,
 *   - and the initial commitment P,
 *
 * this function re-derives all Fiat–Shamir challenges u_i from the transcript
 * and reconstructs the folded generators G_f and H_f implicitly.
 *
 * Verification checks that the folded commitment P' equals:
 *
 *     P' = a_final * G_f
 *        + b_final * H_f
 *        + (a_final * b_final * ux) * U
 *
 * where G_f and H_f are obtained by folding G_vec and H_vec using the challenges
 * u_i and their inverses, and P' is obtained by applying the same folding
 * operations to P using the L_i and R_i commitments.
 *
 * All group operations avoid explicit construction of the point at infinity,
 * which is not representable via the libsecp256k1 public-key API.
 */
static int ipa_verify_explicit(
        const secp256k1_context* ctx,
        const secp256k1_pubkey* G_vec,     /* original G generators */
        const secp256k1_pubkey* H_vec,     /* original H generators */
        const secp256k1_pubkey* U,
        const secp256k1_pubkey* P_in,      /* initial P */
        const secp256k1_pubkey* L_vec,
        const secp256k1_pubkey* R_vec,
        const unsigned char a_final[32],
        const unsigned char b_final[32],
        const unsigned char ux[32],
        const unsigned char ipa_transcript_id[32]
) {
    secp256k1_pubkey P = *P_in;
    secp256k1_pubkey Gf, Hf, RHS, tmp;
    int RHS_inited = 0;
    int ok = 0;

    unsigned char u[IPA_ROUNDS][32];
    unsigned char u_inv[IPA_ROUNDS][32];
    unsigned char last[32];

    /* ---- 1. Re-derive u_i ---- */
    memcpy(last, ipa_transcript_id, 32);
    for (int i = 0; i < IPA_ROUNDS; i++) {
        if (!derive_ipa_round_challenge(ctx, u[i], last, &L_vec[i], &R_vec[i]))
            goto cleanup;
        secp256k1_mpt_scalar_inverse(u_inv[i], u[i]);
        memcpy(last, u[i], 32);
    }

    /* ---- 2. Fold generators ---- */
    /* OPTIMIZATION: Removed Gtmp/Htmp allocations. Pass const pointers directly. */
    if (!fold_generators(ctx, &Gf, G_vec, u, u_inv, N_BITS, 0))
        goto cleanup;
    if (!fold_generators(ctx, &Hf, H_vec, u, u_inv, N_BITS, 1))
        goto cleanup;


    /* ---- 3. Compute RHS = a*Gf + b*Hf + (a*b*ux)*U ---- */

    /* Term 1: a * Gf */
    if (!scalar_is_zero(a_final)) {
        tmp = Gf;
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &tmp, a_final)) goto cleanup;
        if (!add_term(ctx, &RHS, &RHS_inited, &tmp)) goto cleanup;
    }

    /* Term 2: b * Hf */
    if (!scalar_is_zero(b_final)) {
        tmp = Hf;
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &tmp, b_final)) goto cleanup;
        if (!add_term(ctx, &RHS, &RHS_inited, &tmp)) goto cleanup;
    }

    /* Term 3: (a * b * ux) * U */
    unsigned char ab[32], ab_ux[32];
    secp256k1_mpt_scalar_mul(ab, a_final, b_final);
    secp256k1_mpt_scalar_mul(ab_ux, ab, ux);

    if (!scalar_is_zero(ab_ux)) {
        tmp = *U;
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &tmp, ab_ux)) goto cleanup;
        if (!add_term(ctx, &RHS, &RHS_inited, &tmp)) goto cleanup;
    }

    if (!RHS_inited) goto cleanup;

    /* ---- 4. Fold P using L/R ---- */
    if (!apply_ipa_folding_to_P(ctx, &P, L_vec, R_vec, u, u_inv))
        goto cleanup;

    /* ---- 5. Compare P and RHS ---- */
    unsigned char Pser[33], Rser[33];
    size_t len = 33;

    secp256k1_ec_pubkey_serialize(ctx, Pser, &len, &P, SECP256K1_EC_COMPRESSED);
    len = 33;
    secp256k1_ec_pubkey_serialize(ctx, Rser, &len, &RHS, SECP256K1_EC_COMPRESSED);

    if (memcmp(Pser, Rser, 33) == 0) {
        ok = 1;
    }

    cleanup:
    /* Hygiene: wipe derived scalars (not strictly secret, but good practice) */
    OPENSSL_cleanse(u, sizeof(u));
    OPENSSL_cleanse(u_inv, sizeof(u_inv));

    return ok;
}

/*
================================================================================
|                    BULLETPROOF IMPLEMENTATION                                |
================================================================================
*/
/**
 * Phase 1, Step 3: Computes the four required scalar vectors.
 */
int secp256k1_bulletproof_compute_vectors(
        const secp256k1_context* ctx,
        uint64_t value,
        unsigned char al[N_BITS][32],
        unsigned char ar[N_BITS][32],
        unsigned char sl[N_BITS][32],
        unsigned char sr[N_BITS][32])
{
    size_t i;
    int ok = 1;

    /* 1. Setup Constants Programmatically (Safer than hardcoding) */
    unsigned char one_scalar[32] = {0};
    unsigned char minus_one_scalar[32];
    unsigned char zero_scalar[32] = {0};

    one_scalar[31] = 1;

    /* Compute -1 by negating 1. This ensures curve order correctness. */
    memcpy(minus_one_scalar, one_scalar, 32);
    secp256k1_mpt_scalar_negate(minus_one_scalar, minus_one_scalar);

    /* 2. Encode value 'v' into al and ar */
    for (i = 0; i < N_BITS; ++i) {
        if ((value >> i) & 1) {
            /* Bit is 1: al = 1, ar = 0 */
            memcpy(al[i], one_scalar, 32);
            memcpy(ar[i], zero_scalar, 32);
        } else {
            /* Bit is 0: al = 0, ar = -1 */
            memcpy(al[i], zero_scalar, 32);
            memcpy(ar[i], minus_one_scalar, 32);
        }
    }

    /* 3. Generate random blinding vectors sl and sr */
    for (i = 0; i < N_BITS; ++i) {
        if (!generate_random_scalar(ctx, sl[i])) { ok = 0; goto cleanup; }
        if (!generate_random_scalar(ctx, sr[i])) { ok = 0; goto cleanup; }
    }

    return 1;

    cleanup:
    /* On failure, wipe everything to prevent leaking partial state */
    OPENSSL_cleanse(al, N_BITS * 32);
    OPENSSL_cleanse(ar, N_BITS * 32);
    OPENSSL_cleanse(sl, N_BITS * 32);
    OPENSSL_cleanse(sr, N_BITS * 32);
    return 0;
}

/**
 * Computes the Pedersen Commitment: C = value*G + blinding_factor*Pk_base.
 */
int secp256k1_bulletproof_create_commitment(
        const secp256k1_context* ctx,
        secp256k1_pubkey* commitment_C,
        uint64_t value,
        const unsigned char* blinding_factor,
        const secp256k1_pubkey* pk_base
) {
    secp256k1_pubkey G_term, Pk_term;
    const secp256k1_pubkey* points_to_add[2];
    int v_is_zero = (value == 0);

    /* 1. Compute r * Pk_base (The Blinding Term) */
    Pk_term = *pk_base;
    if (secp256k1_ec_pubkey_tweak_mul(ctx, &Pk_term, blinding_factor) != 1) return 0;

    /* 2. Handle Value Term */
    if (v_is_zero) {
        /* If v=0, C = 0*G + r*H = r*H.
           We skip G_term entirely because libsecp cannot represent infinity. */
        *commitment_C = Pk_term;
        return 1;
    }

    /* 3. Compute v * G (The Value Term) */
    if (!compute_amount_point(ctx, &G_term, value)) return 0;

    /* 4. Combine: C = v*G + r*Pk_base */
    points_to_add[0] = &G_term;
    points_to_add[1] = &Pk_term;
    if (secp256k1_ec_pubkey_combine(ctx, commitment_C, points_to_add, 2) != 1) return 0;

    return 1;
}

/**
 * Prover: generates a 64-bit Bulletproof range proof for `value` committed under `pk_base`.
 *
 * Proof binds to `context_id` (if non-NULL) via Fiat–Shamir and outputs a fixed-size
 * serialized proof (688 bytes in the current format).
 *
 * Security note: this implementation assumes all randomness (alpha, rho, s_L, s_R, tau1, tau2)
 * is sampled uniformly modulo the secp256k1 group order.
 */

int secp256k1_bulletproof_prove(
        const secp256k1_context* ctx,
        unsigned char* proof_out,
        size_t* proof_len,
        uint64_t value,
        const unsigned char* blinding_factor,
        const secp256k1_pubkey* pk_base,
        const unsigned char* context_id,
        unsigned int proof_type
) {
    /* --- 1. Variable Declarations --- */
    secp256k1_pubkey G_vec[N_BITS], H_vec[N_BITS];
    secp256k1_pubkey A, S, T1, T2, U;

    /* Secret Data (Must be wiped) */
    unsigned char al[N_BITS][32], ar[N_BITS][32];
    unsigned char sl[N_BITS][32], sr[N_BITS][32];
    unsigned char l_vec[N_BITS][32], r_vec[N_BITS][32];
    unsigned char r1_vec[N_BITS][32];

    unsigned char alpha[32], rho[32], rho_blinder[32];
    unsigned char tau1[32], tau2[32];
    unsigned char t1[32], t2[32];
    unsigned char t_hat[32], tau_x[32], mu[32];
    unsigned char a_final[32], b_final[32];

    /* Intermediate/Public Scalars */
    unsigned char y[32], z[32], x[32];
    unsigned char z_sq[32], z_neg[32], x_sq[32];
    unsigned char y_powers[N_BITS][32];
    unsigned char y_pow[32], two_pow[32];
    unsigned char ux_scalar[32];

    /* IPA Structures */
    secp256k1_pubkey L_vec[IPA_ROUNDS], R_vec[IPA_ROUNDS];
    unsigned char ipa_transcript[32];

    /* Constants */
    unsigned char one[32] = {0}; one[31] = 1;
    unsigned char minus_one[32];
    unsigned char zero[32] = {0};

    int ok = 0;
    size_t i, j;

    /* --- 2. Initialization --- */
    secp256k1_mpt_scalar_negate(minus_one, one);

    if (!secp256k1_mpt_get_generator_vector(ctx, G_vec, N_BITS, (const unsigned char*)"G", 1)) goto cleanup;
    if (!secp256k1_mpt_get_generator_vector(ctx, H_vec, N_BITS, (const unsigned char*)"H", 1)) goto cleanup;

    /* FIX: Use array to capture vector output, then assign to single struct U */
    {
        secp256k1_pubkey U_arr[1];
        if (!secp256k1_mpt_get_generator_vector(ctx, U_arr, 1, (const unsigned char*)"BP_U", 4)) goto cleanup;
        U = U_arr[0];
    }

    /* --- 3. Bit Decomposition & Blinding --- */
    for (i = 0; i < N_BITS; i++) {
        if ((value >> i) & 1) {
            memcpy(al[i], one, 32);
            memset(ar[i], 0, 32);
        } else {
            memset(al[i], 0, 32);
            memcpy(ar[i], minus_one, 32);
        }
        if (!generate_random_scalar(ctx, sl[i])) goto cleanup;
        if (!generate_random_scalar(ctx, sr[i])) goto cleanup;
    }
    if (!generate_random_scalar(ctx, alpha)) goto cleanup;
    if (!generate_random_scalar(ctx, rho)) goto cleanup;
    memcpy(rho_blinder, rho, 32);

    /* --- 4. Commitments A and S --- */
    {
        secp256k1_pubkey tG, tH, tBase;

        /* A = alpha*Base + <al, G> + <ar, H> */
        if (!secp256k1_bulletproof_ipa_msm(ctx, &tG, G_vec, (const unsigned char*)al, N_BITS)) goto cleanup;
        if (!secp256k1_bulletproof_ipa_msm(ctx, &tH, H_vec, (const unsigned char*)ar, N_BITS)) goto cleanup;
        tBase = *pk_base;
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &tBase, alpha)) goto cleanup;
        const secp256k1_pubkey* pts[3] = {&tBase, &tG, &tH};
        if (!secp256k1_ec_pubkey_combine(ctx, &A, pts, 3)) goto cleanup;

        /* S = rho*Base + <sl, G> + <sr, H> */
        if (!secp256k1_bulletproof_ipa_msm(ctx, &tG, G_vec, (const unsigned char*)sl, N_BITS)) goto cleanup;
        if (!secp256k1_bulletproof_ipa_msm(ctx, &tH, H_vec, (const unsigned char*)sr, N_BITS)) goto cleanup;
        tBase = *pk_base;
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &tBase, rho_blinder)) goto cleanup;
        const secp256k1_pubkey* pts2[3] = {&tBase, &tG, &tH};
        if (!secp256k1_ec_pubkey_combine(ctx, &S, pts2, 3)) goto cleanup;
    }

    /* --- 5. Fiat-Shamir (y, z) --- */
    {
        unsigned char A_ser[33], S_ser[33];
        size_t len = 33;
        SHA256_CTX sha;

        if (!secp256k1_ec_pubkey_serialize(ctx, A_ser, &len, &A, SECP256K1_EC_COMPRESSED)) goto cleanup;
        len = 33;
        if (!secp256k1_ec_pubkey_serialize(ctx, S_ser, &len, &S, SECP256K1_EC_COMPRESSED)) goto cleanup;

        SHA256_Init(&sha);
        if (context_id) SHA256_Update(&sha, context_id, 32);
        SHA256_Update(&sha, A_ser, 33);
        SHA256_Update(&sha, S_ser, 33);
        SHA256_Final(y, &sha);
        secp256k1_mpt_scalar_reduce32(y, y);

        SHA256_Init(&sha);
        if (context_id) SHA256_Update(&sha, context_id, 32);
        SHA256_Update(&sha, A_ser, 33);
        SHA256_Update(&sha, S_ser, 33);
        SHA256_Update(&sha, y, 32);
        SHA256_Final(z, &sha);
        secp256k1_mpt_scalar_reduce32(z, z);
    }

    /* --- 6. Polynomial Setup --- */
    scalar_vector_powers(ctx, y_powers, y, N_BITS);
    secp256k1_mpt_scalar_mul(z_sq, z, z);
    secp256k1_mpt_scalar_negate(z_neg, z);
    memcpy(two_pow, one, 32);

    for (i = 0; i < N_BITS; i++) {
        unsigned char two_pow_i[32] = {0};
        two_pow_i[31 - (i/8)] = (1 << (i%8));

        /* l0[i] = al[i] - z */
        secp256k1_mpt_scalar_add(l_vec[i], al[i], z_neg);

        /* r0[i] = y^i(ar[i] + z) + z^2 * 2^i */
        unsigned char tmp1[32];
        secp256k1_mpt_scalar_add(tmp1, ar[i], z);
        secp256k1_mpt_scalar_mul(r_vec[i], tmp1, y_powers[i]);
        secp256k1_mpt_scalar_mul(tmp1, z_sq, two_pow_i);
        secp256k1_mpt_scalar_add(r_vec[i], r_vec[i], tmp1);

        /* r1[i] = sr[i] * y^i */
        secp256k1_mpt_scalar_mul(r1_vec[i], sr[i], y_powers[i]);
    }

    /* t1 = <l0, r1> + <l1, r0> */
    {
        unsigned char dot1[32], dot2[32];
        if (!secp256k1_bulletproof_ipa_dot(ctx, dot1, (const unsigned char*)l_vec, (const unsigned char*)r1_vec, N_BITS)) goto cleanup;
        if (!secp256k1_bulletproof_ipa_dot(ctx, dot2, (const unsigned char*)sl, (const unsigned char*)r_vec, N_BITS)) goto cleanup;
        secp256k1_mpt_scalar_add(t1, dot1, dot2);
    }

    /* t2 = <l1, r1> */
    if (!secp256k1_bulletproof_ipa_dot(ctx, t2, (const unsigned char*)sl, (const unsigned char*)r1_vec, N_BITS)) goto cleanup;

    /* --- 7. Commit T1, T2 --- */
    if (!generate_random_scalar(ctx, tau1)) goto cleanup;
    if (!generate_random_scalar(ctx, tau2)) goto cleanup;

    /* T1 = t1*G + tau1*Base */
    {
        secp256k1_pubkey tG, tB;
        int has_g=0, has_b=0;

        if (memcmp(t1, zero, 32) != 0) {
            if (!secp256k1_ec_pubkey_create(ctx, &tG, t1)) goto cleanup;
            has_g=1;
        }
        if (memcmp(tau1, zero, 32) != 0) {
            tB = *pk_base;
            if (!secp256k1_ec_pubkey_tweak_mul(ctx, &tB, tau1)) goto cleanup;
            has_b=1;
        }

        if (has_g && has_b) {
            const secp256k1_pubkey* pts[2] = {&tG, &tB};
            if (!secp256k1_ec_pubkey_combine(ctx, &T1, pts, 2)) goto cleanup;
        } else if (has_g) T1 = tG; else if (has_b) T1 = tB;
        else { goto cleanup; }
    }

    /* T2 = t2*G + tau2*Base */
    {
        secp256k1_pubkey tG, tB;
        int has_g=0, has_b=0;

        if (memcmp(t2, zero, 32) != 0) {
            if (!secp256k1_ec_pubkey_create(ctx, &tG, t2)) goto cleanup;
            has_g=1;
        }
        if (memcmp(tau2, zero, 32) != 0) {
            tB = *pk_base;
            if (!secp256k1_ec_pubkey_tweak_mul(ctx, &tB, tau2)) goto cleanup;
            has_b=1;
        }

        if (has_g && has_b) {
            const secp256k1_pubkey* pts[2] = {&tG, &tB};
            if (!secp256k1_ec_pubkey_combine(ctx, &T2, pts, 2)) goto cleanup;
        } else if (has_g) T2 = tG; else if (has_b) T2 = tB;
        else { goto cleanup; }
    }

    /* --- 8. Challenge x --- */
    {
        unsigned char buf[33];
        size_t len = 33;
        SHA256_CTX sha;
        SHA256_Init(&sha);
        if (context_id) SHA256_Update(&sha, context_id, 32);
        SHA256_Update(&sha, y, 32);
        SHA256_Update(&sha, z, 32);
        secp256k1_ec_pubkey_serialize(ctx, buf, &len, &T1, SECP256K1_EC_COMPRESSED);
        SHA256_Update(&sha, buf, 33);
        len = 33;
        secp256k1_ec_pubkey_serialize(ctx, buf, &len, &T2, SECP256K1_EC_COMPRESSED);
        SHA256_Update(&sha, buf, 33);
        SHA256_Final(x, &sha);
        secp256k1_mpt_scalar_reduce32(x, x);
    }

    /* --- 9. Final Polynomial Evaluation --- */
    for (i = 0; i < N_BITS; i++) {
        unsigned char tmp[32];
        secp256k1_mpt_scalar_mul(tmp, sl[i], x);
        secp256k1_mpt_scalar_add(l_vec[i], l_vec[i], tmp);

        secp256k1_mpt_scalar_mul(tmp, r1_vec[i], x);
        secp256k1_mpt_scalar_add(r_vec[i], r_vec[i], tmp);
    }

    /* t_hat = <l, r> */
    if (!secp256k1_bulletproof_ipa_dot(ctx, t_hat, (const unsigned char*)l_vec, (const unsigned char*)r_vec, N_BITS)) goto cleanup;

    /* tau_x = tau2*x^2 + tau1*x + z^2*blinding_factor */
    secp256k1_mpt_scalar_mul(x_sq, x, x);
    secp256k1_mpt_scalar_mul(tau_x, tau2, x_sq);
    {
        unsigned char tmp_s[32];
        secp256k1_mpt_scalar_mul(tmp_s, tau1, x);
        secp256k1_mpt_scalar_add(tau_x, tau_x, tmp_s);
        secp256k1_mpt_scalar_mul(tmp_s, z_sq, blinding_factor);
        secp256k1_mpt_scalar_add(tau_x, tau_x, tmp_s);
    }

    /* mu = alpha + rho*x */
    {
        unsigned char tmp_s[32];
        secp256k1_mpt_scalar_mul(tmp_s, rho_blinder, x);
        secp256k1_mpt_scalar_add(mu, alpha, tmp_s);
    }

    /* --- 10. IPA Compression --- */
    SHA256(x, 32, ipa_transcript);
    if (!derive_ipa_binding_challenge(ctx, ux_scalar, ipa_transcript, t_hat)) goto cleanup;

    /* Normalize H vector */
    secp256k1_pubkey H_prime[N_BITS];
    unsigned char y_inv[32], y_inv_pow[32];
    secp256k1_mpt_scalar_inverse(y_inv, y);
    memcpy(y_inv_pow, one, 32);

    for (i = 0; i < N_BITS; i++) {
        H_prime[i] = H_vec[i];
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &H_prime[i], y_inv_pow)) goto cleanup;
        secp256k1_mpt_scalar_mul(y_inv_pow, y_inv_pow, y_inv);
    }

    /* Run Recursive IPA */
    if (!secp256k1_bulletproof_run_ipa_prover(
            ctx, &U, G_vec, H_prime,
            (unsigned char*)l_vec, (unsigned char*)r_vec,
            N_BITS, ipa_transcript, ux_scalar,
            L_vec, R_vec, a_final, b_final
    )) goto cleanup;

    /* --- 11. Serialization --- */
    unsigned char *ptr = proof_out;
    size_t ser_len_final;

#define SER_PT(P) do { \
        ser_len_final = 33; \
        if (!secp256k1_ec_pubkey_serialize(ctx, ptr, &ser_len_final, &P, SECP256K1_EC_COMPRESSED)) goto cleanup; \
        ptr += 33; \
    } while(0)

    SER_PT(A); SER_PT(S); SER_PT(T1); SER_PT(T2);
    for (j = 0; j < IPA_ROUNDS; j++) { SER_PT(L_vec[j]); }
    for (j = 0; j < IPA_ROUNDS; j++) { SER_PT(R_vec[j]); }

    memcpy(ptr, a_final, 32); ptr += 32;
    memcpy(ptr, b_final, 32); ptr += 32;
    memcpy(ptr, t_hat, 32);   ptr += 32;
    memcpy(ptr, tau_x, 32);   ptr += 32;
    memcpy(ptr, mu, 32);      ptr += 32;

    if (proof_len) *proof_len = 688;

    ok = 1;

    cleanup:
    OPENSSL_cleanse(al, sizeof(al));
    OPENSSL_cleanse(ar, sizeof(ar));
    OPENSSL_cleanse(sl, sizeof(sl));
    OPENSSL_cleanse(sr, sizeof(sr));
    OPENSSL_cleanse(l_vec, sizeof(l_vec));
    OPENSSL_cleanse(r_vec, sizeof(r_vec));
    OPENSSL_cleanse(r1_vec, sizeof(r1_vec));

    OPENSSL_cleanse(alpha, 32);
    OPENSSL_cleanse(rho, 32);
    OPENSSL_cleanse(rho_blinder, 32);
    OPENSSL_cleanse(tau1, 32);
    OPENSSL_cleanse(tau2, 32);
    OPENSSL_cleanse(t1, 32);
    OPENSSL_cleanse(t2, 32);
    OPENSSL_cleanse(a_final, 32);
    OPENSSL_cleanse(b_final, 32);

    OPENSSL_cleanse(y, 32);
    OPENSSL_cleanse(z, 32);
    OPENSSL_cleanse(x, 32);

#undef SER_PT
    return ok;
}

int secp256k1_bulletproof_verify(
        const secp256k1_context* ctx,
        const secp256k1_pubkey* G_vec,
        const secp256k1_pubkey* H_vec,
        const unsigned char* proof,
        size_t proof_len,
        const secp256k1_pubkey* commitment_C,
        const secp256k1_pubkey* pk_base,
        const unsigned char* context_id
) {
    /* ... (Step 1a-1f variable declarations and checks identical to before) ... */

    /* --- 1a. Variable Declarations --- */
    secp256k1_pubkey A, S, T1, T2;
    secp256k1_pubkey L_vec[6], R_vec[6];
    secp256k1_pubkey U;

    unsigned char a_final[32], b_final[32];
    unsigned char t_hat[32];
    unsigned char tau_x[32], mu[32];

    unsigned char y[32], z[32], x[32];
    unsigned char ux_scalar[32];

    unsigned char delta[32], z_sq[32], z_cu[32];
    unsigned char y_pow_sum[32], two_pow_sum[32];
    unsigned char term1[32], term2[32];
    unsigned char y_powers[64][32];
    unsigned char y_inv[32];
    unsigned char y_inv_powers[64][32];

    const unsigned char *ptr = proof;
    int i;

    /* --- 1b. Strict Length Check --- */
    if (proof_len != 688) {
        return 0;
    }

    /* --- 1c. Unpack Range Proof Points --- */
    if (!secp256k1_ec_pubkey_parse(ctx, &A, ptr, 33)) return 0; ptr += 33;
    if (!secp256k1_ec_pubkey_parse(ctx, &S, ptr, 33)) return 0; ptr += 33;
    if (!secp256k1_ec_pubkey_parse(ctx, &T1, ptr, 33)) return 0; ptr += 33;
    if (!secp256k1_ec_pubkey_parse(ctx, &T2, ptr, 33)) return 0; ptr += 33;

    /* --- 1d. Unpack IPA Points (L and R vectors) --- */
    for (i = 0; i < 6; i++) {
        if (!secp256k1_ec_pubkey_parse(ctx, &L_vec[i], ptr, 33)) return 0;
        ptr += 33;
    }
    for (i = 0; i < 6; i++) {
        if (!secp256k1_ec_pubkey_parse(ctx, &R_vec[i], ptr, 33)) return 0;
        ptr += 33;
    }

    /* --- 1e. Unpack Final Scalars --- */
    memcpy(a_final, ptr, 32); ptr += 32;
    memcpy(b_final, ptr, 32); ptr += 32;
    memcpy(t_hat,   ptr, 32); ptr += 32;
    memcpy(tau_x,   ptr, 32); ptr += 32;
    memcpy(mu,      ptr, 32); ptr += 32;

    /* --- 1f. Basic Validity Checks --- */
    if (!secp256k1_ec_seckey_verify(ctx, a_final)) return 0;
    if (!secp256k1_ec_seckey_verify(ctx, b_final)) return 0;
    if (!secp256k1_ec_seckey_verify(ctx, t_hat))   return 0;
    if (!secp256k1_ec_seckey_verify(ctx, tau_x))   return 0;
    if (!secp256k1_ec_seckey_verify(ctx, mu))      return 0;

    /* --- 1g. Derive Generators --- */
    /* FIX: Use array to capture vector output safely */
    {
        secp256k1_pubkey U_arr[1];
        if (!secp256k1_mpt_get_generator_vector(ctx, U_arr, 1, (const unsigned char*)"BP_U", 4)) {
            return 0;
        }
        U = U_arr[0];
    }

    /* =========================================================================
     * Step 2: Recompute Fiat–Shamir challenges y,z,x from transcript
     * ========================================================================= */
    /* ... (remainder of function unchanged) ... */

    /* --- 2a. Serialize Commitments for Hashing --- */
    unsigned char A_ser[33], S_ser[33], T1_ser[33], T2_ser[33];
    size_t slen = 33;
    SHA256_CTX sha;

    if (!secp256k1_ec_pubkey_serialize(ctx, A_ser, &slen, &A, SECP256K1_EC_COMPRESSED)) return 0;
    slen = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, S_ser, &slen, &S, SECP256K1_EC_COMPRESSED)) return 0;
    slen = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, T1_ser, &slen, &T1, SECP256K1_EC_COMPRESSED)) return 0;
    slen = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, T2_ser, &slen, &T2, SECP256K1_EC_COMPRESSED)) return 0;

    /* --- 2b. Derive Challenges y and z --- */
    SHA256_Init(&sha);
    if (context_id) SHA256_Update(&sha, context_id, 32);
    SHA256_Update(&sha, A_ser, 33);
    SHA256_Update(&sha, S_ser, 33);
    SHA256_Final(y, &sha);
    secp256k1_mpt_scalar_reduce32(y, y);

    SHA256_Init(&sha);
    if (context_id) SHA256_Update(&sha, context_id, 32);
    SHA256_Update(&sha, A_ser, 33);
    SHA256_Update(&sha, S_ser, 33);
    SHA256_Update(&sha, y, 32);
    SHA256_Final(z, &sha);
    secp256k1_mpt_scalar_reduce32(z, z);

    if (!secp256k1_ec_seckey_verify(ctx, y) || !secp256k1_ec_seckey_verify(ctx, z)) {
        return 0;
    }

    /* --- 2c. Pre-compute Scalar Powers --- */
    scalar_vector_powers(ctx, y_powers, y, 64);
    secp256k1_mpt_scalar_inverse(y_inv, y);
    scalar_vector_powers(ctx, y_inv_powers, y_inv, 64);

    /* --- 2d. Derive Challenge x --- */
    SHA256_Init(&sha);
    if (context_id) SHA256_Update(&sha, context_id, 32);
    SHA256_Update(&sha, y, 32);
    SHA256_Update(&sha, z, 32);
    SHA256_Update(&sha, T1_ser, 33);
    SHA256_Update(&sha, T2_ser, 33);
    SHA256_Final(x, &sha);
    secp256k1_mpt_scalar_reduce32(x, x);

    if (!secp256k1_ec_seckey_verify(ctx, x)) {
        return 0;
    }

    /* =========================================================================
      * Step 3: Verify polynomial identity
      * ========================================================================= */

    /* --- 3a. delta(y,z) --- */
    secp256k1_mpt_scalar_mul(z_sq, z, z);
    secp256k1_mpt_scalar_mul(z_cu, z_sq, z);

    compute_delta_scalars(ctx, y_pow_sum, two_pow_sum, y, 64);

    {
        unsigned char neg_z_sq[32], neg_term2[32];
        secp256k1_mpt_scalar_negate(neg_z_sq, z_sq);
        secp256k1_mpt_scalar_add(term1, z, neg_z_sq);
        secp256k1_mpt_scalar_mul(term1, term1, y_pow_sum);

        secp256k1_mpt_scalar_mul(term2, z_cu, two_pow_sum);
        secp256k1_mpt_scalar_negate(neg_term2, term2);
        secp256k1_mpt_scalar_add(delta, term1, neg_term2);
    }

    /* --- 3b. Polynomial identity check --- */
    {
        secp256k1_pubkey LHS;
        {
            unsigned char zero32[32] = {0};
            int have_t = 0, have_tau = 0;
            secp256k1_pubkey tG, tauH;

            if (memcmp(t_hat, zero32, 32) != 0) {
                if (!secp256k1_ec_pubkey_create(ctx, &tG, t_hat)) return 0;
                have_t = 1;
            }

            if (memcmp(tau_x, zero32, 32) != 0) {
                tauH = *pk_base;
                if (!secp256k1_ec_pubkey_tweak_mul(ctx, &tauH, tau_x)) return 0;
                have_tau = 1;
            }

            if (have_t && have_tau) {
                const secp256k1_pubkey* pts[2] = { &tG, &tauH };
                if (!secp256k1_ec_pubkey_combine(ctx, &LHS, pts, 2)) return 0;
            } else if (have_t) {
                LHS = tG;
            } else if (have_tau) {
                LHS = tauH;
            } else {
                return 0;
            }
        }

        secp256k1_pubkey RHS;
        {
            unsigned char zero[32] = {0};
            unsigned char x_sq[32];
            secp256k1_pubkey acc, tmp;
            int inited = 0;

            if (memcmp(z_sq, zero, 32) != 0) {
                tmp = *commitment_C;
                if (!secp256k1_ec_pubkey_tweak_mul(ctx, &tmp, z_sq)) return 0;
                acc = tmp; inited = 1;
            }
            if (memcmp(delta, zero, 32) != 0) {
                if (!secp256k1_ec_pubkey_create(ctx, &tmp, delta)) return 0;
                if (!inited) { acc = tmp; inited = 1; }
                else {
                    secp256k1_pubkey sum;
                    const secp256k1_pubkey* pts[2] = {&acc, &tmp};
                    if (!secp256k1_ec_pubkey_combine(ctx, &sum, pts, 2)) return 0;
                    acc = sum;
                }
            }
            if (memcmp(x, zero, 32) != 0) {
                tmp = T1;
                if (!secp256k1_ec_pubkey_tweak_mul(ctx, &tmp, x)) return 0;
                if (!inited) { acc = tmp; inited = 1; }
                else {
                    secp256k1_pubkey sum;
                    const secp256k1_pubkey* pts[2] = {&acc, &tmp};
                    if (!secp256k1_ec_pubkey_combine(ctx, &sum, pts, 2)) return 0;
                    acc = sum;
                }
            }
            secp256k1_mpt_scalar_mul(x_sq, x, x);
            if (memcmp(x_sq, zero, 32) != 0) {
                tmp = T2;
                if (!secp256k1_ec_pubkey_tweak_mul(ctx, &tmp, x_sq)) return 0;
                if (!inited) { acc = tmp; inited = 1; }
                else {
                    secp256k1_pubkey sum;
                    const secp256k1_pubkey* pts[2] = {&acc, &tmp};
                    if (!secp256k1_ec_pubkey_combine(ctx, &sum, pts, 2)) return 0;
                    acc = sum;
                }
            }

            if (!inited) return 0;
            RHS = acc;
        }

        if (!pubkey_equal(ctx, &LHS, &RHS)) return 0;
    }

    /* =========================================================================
     * Step 4: Build P and Verify IPA
     * =========================================================================*/

    unsigned char ipa_transcript_id[32];
    SHA256(x, 32, ipa_transcript_id);
    if (!derive_ipa_binding_challenge(ctx, ux_scalar, ipa_transcript_id, t_hat))
        return 0;

    secp256k1_pubkey P = A;

    /* P += x*S */
    {
        secp256k1_pubkey xS = S;
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &xS, x)) return 0;

        secp256k1_pubkey P_new;
        const secp256k1_pubkey* pts[2] = { &P, &xS };
        if (!secp256k1_ec_pubkey_combine(ctx, &P_new, pts, 2)) return 0;
        P = P_new;
    }

    /* P += sum_i [ (-z)*G_i + (z*y^i + z^2*2^i) * (y^{-i} * H_i) ] */
    unsigned char neg_z[32];
    memcpy(neg_z, z, 32);
    if (!secp256k1_ec_seckey_negate(ctx, neg_z)) return 0;

    for (int i = 0; i < 64; i++) {
        secp256k1_pubkey Gi = G_vec[i];
        secp256k1_pubkey Hi = H_vec[i];

        unsigned char h_scalar[32];
        unsigned char zy_i[32];
        unsigned char term2[32];
        unsigned char two_pow_i[32] = {0};

        /* Gi = (-z) * G_i */
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &Gi, neg_z)) return 0;

        /* zy_i = z * y^i */
        secp256k1_mpt_scalar_mul(zy_i, z, y_powers[i]);

        /* two_pow_i = 2^i */
        two_pow_i[31 - (i / 8)] = (1 << (i % 8));

        /* term2 = z^2 * 2^i */
        secp256k1_mpt_scalar_mul(term2, z_sq, two_pow_i);

        /* h_i = z*y^i + z^2*2^i */
        secp256k1_mpt_scalar_add(h_scalar, zy_i, term2);

        /* Normalize generator: H'_i = y^{-i} * H_i */
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &Hi, y_inv_powers[i])) return 0;

        /* Hi = h_i * H'_i */
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &Hi, h_scalar)) return 0;

        /* P += Gi + Hi */
        secp256k1_pubkey P_new;
        const secp256k1_pubkey* pts[3] = { &P, &Gi, &Hi };
        if (!secp256k1_ec_pubkey_combine(ctx, &P_new, pts, 3)) return 0;
        P = P_new;
    }

    /* P += (t_hat * ux) * U */
    {
        unsigned char zero32[32] = {0};
        unsigned char t_hat_ux[32];

        secp256k1_mpt_scalar_mul(t_hat_ux, t_hat, ux_scalar);

        if (memcmp(t_hat_ux, zero32, 32) != 0) {
            secp256k1_pubkey Q = U;
            if (!secp256k1_ec_pubkey_tweak_mul(ctx, &Q, t_hat_ux)) return 0;
            secp256k1_pubkey P_new;
            const secp256k1_pubkey* pts[2] = { &P, &Q };
            if (!secp256k1_ec_pubkey_combine(ctx, &P_new, pts, 2)) return 0;
            P = P_new;
        }
    }

    /* P -= mu*pk_base */
    {
        unsigned char neg_mu[32];
        memcpy(neg_mu, mu, 32);
        if (!secp256k1_ec_seckey_negate(ctx, neg_mu)) return 0;

        secp256k1_pubkey mu_term = *pk_base;
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &mu_term, neg_mu)) return 0;

        secp256k1_pubkey P_new;
        const secp256k1_pubkey* pts[2] = { &P, &mu_term };
        if (!secp256k1_ec_pubkey_combine(ctx, &P_new, pts, 2)) return 0;
        P = P_new;
    }

    /* Step 5: Run IPA Verification */
    secp256k1_pubkey P_unfolded = P;
    unsigned char last_challenge[32];
    unsigned char u[6][32], u_inv[6][32];

    memcpy(last_challenge, ipa_transcript_id, 32);

    for (i = 0; i < 6; i++) {
        if (!derive_ipa_round_challenge(ctx, u[i], last_challenge, &L_vec[i], &R_vec[i])) return 0;
        secp256k1_mpt_scalar_inverse(u_inv[i], u[i]);
        memcpy(last_challenge, u[i], 32);
    }

    secp256k1_pubkey Hprime[64];
    for (int k = 0; k < 64; k++) {
        Hprime[k] = H_vec[k];
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &Hprime[k], y_inv_powers[k])) return 0;
    }

    if (!ipa_verify_explicit(ctx, G_vec, Hprime, &U, &P_unfolded, L_vec, R_vec, a_final, b_final, ux_scalar, ipa_transcript_id)) {
        return 0;
    }

    return 1;
}