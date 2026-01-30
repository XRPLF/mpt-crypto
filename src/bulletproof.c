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
 * INTERNAL HELPER FUNCTIONS                           |
 * Computes the point M = amount * G. (Needed by commitment helper).
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

    /* If all scalars were zero, return the point at infinity?
       Actually, for Bulletproofs, we return a valid point.
       If nothing was added, create a point at infinity is tricky in pubkey API.
       But for range proofs, aL/aR will never be all zeros for a valid amount. */
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
static int pubkey_equal(
        const secp256k1_context* ctx,
        const secp256k1_pubkey* a,
        const secp256k1_pubkey* b
) {
    unsigned char as[33], bs[33];
    size_t alen = 33, blen = 33;

    if (!secp256k1_ec_pubkey_serialize(ctx, as, &alen, a, SECP256K1_EC_COMPRESSED)) return 0;
    if (!secp256k1_ec_pubkey_serialize(ctx, bs, &blen, b, SECP256K1_EC_COMPRESSED)) return 0;

    return memcmp(as, bs, 33) == 0;
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
    unsigned char s_flat[64 * 32];
    int i, j;

    for (i = 0; i < n; i++) {
        unsigned char current_s[32] = {0};
        current_s[31] = 1; /* 1 */

        for (j = 0; j < 6; j++) {
            int bit = (i >> (5 - j)) & 1;

            if (!is_H) {
                /* G': left*u_inv, right*u */
                secp256k1_mpt_scalar_mul(current_s, current_s, bit ? u[j] : u_inv[j]);
            } else {
                /* H': left*u, right*u_inv */
                secp256k1_mpt_scalar_mul(current_s, current_s, bit ? u_inv[j] : u[j]);
            }
        }

        memcpy(s_flat + (i * 32), current_s, 32);
    }

    return secp256k1_bulletproof_ipa_msm(ctx, final_point, generators, s_flat, n);
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
    for (int i = 0; i < 6; i++) {
        unsigned char u_sq[32], u_inv_sq[32];
        secp256k1_mpt_scalar_mul(u_sq, u[i], u[i]);
        secp256k1_mpt_scalar_mul(u_inv_sq, u_inv[i], u_inv[i]);

        secp256k1_pubkey acc = *P;

        /* L term: u^2 */
        secp256k1_pubkey tL = L_vec[i];
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &tL, u_sq)) return 0;

        /* R term: u^{-2} */
        secp256k1_pubkey tR = R_vec[i];
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &tR, u_inv_sq)) return 0;

        const secp256k1_pubkey* pts[3] = { &acc, &tL, &tR };
        if (!secp256k1_ec_pubkey_combine(ctx, P, pts, 3)) return 0;
    }
    return 1;
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
    unsigned char c_L_scalar[32], c_R_scalar[32]; // Cross-term scalars
    unsigned char cL_ux_scalar[32], cR_ux_scalar[32]; // Blinding term scalars
    secp256k1_pubkey T1, T2; // Intermediate points
    const secp256k1_pubkey* points_to_add[2];
    int all_ok = 1;

    /* 1. Compute Cross-Term Scalars: c_L = <a_L, b_R>, c_R = <a_R, b_L> */
    if (!secp256k1_bulletproof_ipa_dot(ctx, c_L_scalar, a_L, b_R, half_n)) all_ok = 0;
    if (all_ok && !secp256k1_bulletproof_ipa_dot(ctx, c_R_scalar, a_R, b_L, half_n)) all_ok = 0;

    /* 2. Compute L: L = (<a_L, G_R>) + (<b_R, H_L>) + (c_L * ux * g) */
    if (all_ok && !secp256k1_bulletproof_ipa_msm(ctx, L, G_R, a_L, half_n)) all_ok = 0; // Term 1: <a_L, G_R>
    if (all_ok && !secp256k1_bulletproof_ipa_msm(ctx, &T1, H_L, b_R, half_n)) all_ok = 0; // Term 2: <b_R, H_L>
    if (all_ok && !secp256k1_bulletproof_add_point_to_accumulator(ctx, L, &T1)) all_ok = 0; // L = Term 1 + Term 2

    /* 3. Compute Blinding Term for L: c_L * ux * g */
    if (all_ok) {
        secp256k1_mpt_scalar_mul(cL_ux_scalar, c_L_scalar, ux);
        if (all_ok && !secp256k1_bulletproof_point_scalar_mul(ctx, &T2, g, cL_ux_scalar)) all_ok = 0; // T2 = cL_ux * g
        if (all_ok && !secp256k1_bulletproof_add_point_to_accumulator(ctx, L, &T2)) all_ok = 0; // L = L + T2
    }

    /* 4. Compute R: R = (<a_R, G_L>) + (<b_L, H_R>) + (c_R * ux * g) */
    if (all_ok && !secp256k1_bulletproof_ipa_msm(ctx, R, G_L, a_R, half_n)) all_ok = 0; // Term 1: <a_R, G_L>
    if (all_ok && !secp256k1_bulletproof_ipa_msm(ctx, &T1, H_R, b_L, half_n)) all_ok = 0; // Term 2: <b_L, H_R>
    if (all_ok && !secp256k1_bulletproof_add_point_to_accumulator(ctx, R, &T1)) all_ok = 0; // R = Term 1 + Term 2

    /* 5. Compute Blinding Term for R: c_R * ux * g */
    if (all_ok) {
        secp256k1_mpt_scalar_mul(cR_ux_scalar, c_R_scalar, ux);
        if (all_ok && !secp256k1_bulletproof_point_scalar_mul(ctx, &T2, g, cR_ux_scalar)) all_ok = 0; // T2 = cR_ux * g
        if (all_ok && !secp256k1_bulletproof_add_point_to_accumulator(ctx, R, &T2)) all_ok = 0; // R = R + T2
    }

    return all_ok;
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
    int all_ok = 1;

    // Temporary variables for intermediate results
    unsigned char t1_scalar[32], t2_scalar[32];
    secp256k1_pubkey G_term, H_term;
    const secp256k1_pubkey* points_to_add[2];

    for (i = 0; i < half_n; ++i) {

        // --- SCALAR VECTORS: a'[i] = a[i] * x + a[i + half_n] * x_inv ---
        {
            unsigned char* a_L = a + i * 32;          // a[i]
            unsigned char* a_R = a + (i + half_n) * 32; // a[i + half_n]

            // t1_scalar = a_L * x
            // t2_scalar = a_R * x_inv
            // a[i] = t1_scalar + t2_scalar (Done in-place on a[i])
            secp256k1_mpt_scalar_mul(t1_scalar, a_L, x);
            secp256k1_mpt_scalar_mul(t2_scalar, a_R, x_inv);
            secp256k1_mpt_scalar_add(a_L, t1_scalar, t2_scalar);

        }

        // --- SCALAR VECTORS: b'[i] = b[i] * x_inv + b[i + half_n] * x ---
        {
            unsigned char* b_L = b + i * 32;
            unsigned char* b_R = b + (i + half_n) * 32;

            // t1_scalar = b_L * x_inv
            // t2_scalar = b_R * x
            // b[i] = t1_scalar + t2_scalar (Done in-place on b[i])
            secp256k1_mpt_scalar_mul(t1_scalar, b_L, x_inv);
            secp256k1_mpt_scalar_mul(t2_scalar, b_R, x);
            secp256k1_mpt_scalar_add(b_L, t1_scalar, t2_scalar);

        }

        // --- POINT VECTORS: G'[i] = G_L[i] * x_inv + G_R[i] * x ---
        {
            secp256k1_pubkey left = G[i];
            secp256k1_pubkey right = G[i + half_n];

            if (!secp256k1_ec_pubkey_tweak_mul(ctx, &left, x_inv)) return 0;
            if (!secp256k1_ec_pubkey_tweak_mul(ctx, &right, x)) return 0;

            const secp256k1_pubkey* pts[2] = { &left, &right };
            if (!secp256k1_ec_pubkey_combine(ctx, &G[i], pts, 2)) return 0;
        }

// --- POINT VECTORS: H'[i] = H_L[i] * x + H_R[i] * x_inv ---
        {
            secp256k1_pubkey left = H[i];
            secp256k1_pubkey right = H[i + half_n];

            if (!secp256k1_ec_pubkey_tweak_mul(ctx, &left, x)) return 0;
            if (!secp256k1_ec_pubkey_tweak_mul(ctx, &right, x_inv)) return 0;

            const secp256k1_pubkey* pts[2] = { &left, &right };
            if (!secp256k1_ec_pubkey_combine(ctx, &H[i], pts, 2)) return 0;
        }


        if (!all_ok) break; // Break loop if any step failed
    }

    return all_ok;
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

    /* 3. Interpret hash as scalar */
    memcpy(ux_out, hash_output, 32);

    /*
     * 4. Validate scalar:
     *    - non-zero
     *    - < secp256k1 group order
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
    size_t cur_n;

    unsigned char u_scalar[32], u_inv[32];
    unsigned char last_challenge[32];

    if (n == 0 || (n & (n - 1)) != 0) return 0;

    cur_n = n;
    while (cur_n > 1) { cur_n >>= 1; rounds++; }
    cur_n = n;

    /* Seed transcript exactly like verifier */
    memcpy(last_challenge, ipa_transcript_id, 32);

    for (size_t r = 0; r < rounds; ++r) {
        size_t half_n = cur_n >> 1;
        secp256k1_pubkey Lr, Rr;

        if (!secp256k1_bulletproof_ipa_compute_LR(
                ctx, &Lr, &Rr,
                a_vec, a_vec + half_n * 32,
                b_vec, b_vec + half_n * 32,
                G_vec, G_vec + half_n,
                H_vec, H_vec + half_n,
                g,
                ux_scalar,
                half_n
        )) return 0;

        L_out[r] = Lr;
        R_out[r] = Rr;

        if (!derive_ipa_round_challenge(ctx, u_scalar, last_challenge, &Lr, &Rr)) return 0;

        secp256k1_mpt_scalar_inverse(u_inv, u_scalar);
        if (!secp256k1_ec_seckey_verify(ctx, u_inv)) return 0;

        memcpy(last_challenge, u_scalar, 32);

        if (!secp256k1_bulletproof_ipa_compress_step(
                ctx, a_vec, b_vec, G_vec, H_vec, half_n, u_scalar, u_inv
        )) return 0;

        cur_n = half_n;
    }

    memcpy(a_final, a_vec, 32);
    memcpy(b_final, b_vec, 32);
    return 1;
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

    unsigned char u[IPA_ROUNDS][32];
    unsigned char u_inv[IPA_ROUNDS][32];
    unsigned char last[32];

    /* ---- 1. Re-derive u_i ---- */
    memcpy(last, ipa_transcript_id, 32);
    for (int i = 0; i < IPA_ROUNDS; i++) {
        if (!derive_ipa_round_challenge(ctx, u[i], last, &L_vec[i], &R_vec[i]))
            return 0;
        secp256k1_mpt_scalar_inverse(u_inv[i], u[i]);
        memcpy(last, u[i], 32);
    }

    /* ---- 2. Fold generators ---- */
    {
        secp256k1_pubkey Gtmp[N_BITS], Htmp[N_BITS];
        memcpy(Gtmp, G_vec, sizeof(Gtmp));
        memcpy(Htmp, H_vec, sizeof(Htmp));

        if (!fold_generators(ctx, &Gf, Gtmp, u, u_inv, N_BITS, 0))
            return 0;
        if (!fold_generators(ctx, &Hf, Htmp, u, u_inv, N_BITS, 1))
            return 0;
    }

    /* ---- 3. Compute RHS = a*Gf + b*Hf + (a*b*ux)*U ---- */
    if (!scalar_is_zero(a_final)) {
        tmp = Gf;
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &tmp, a_final)) return 0;
        if (!add_term(ctx, &RHS, &RHS_inited, &tmp)) return 0;
    }

    if (!scalar_is_zero(b_final)) {
        tmp = Hf;
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &tmp, b_final)) return 0;
        if (!add_term(ctx, &RHS, &RHS_inited, &tmp)) return 0;
    }

    unsigned char ab[32], ab_ux[32];
    secp256k1_mpt_scalar_mul(ab, a_final, b_final);
    secp256k1_mpt_scalar_mul(ab_ux, ab, ux);

    if (!scalar_is_zero(ab_ux)) {
        tmp = *U;
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &tmp, ab_ux)) return 0;
        if (!add_term(ctx, &RHS, &RHS_inited, &tmp)) return 0;
    }

    if (!RHS_inited) return 0;

    /* ---- 4. Fold P using L/R ---- */
    if (!apply_ipa_folding_to_P(ctx, &P, L_vec, R_vec, u, u_inv))
        return 0;

    /* ---- 5. Compare ---- */
    unsigned char Pser[33], Rser[33];
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(ctx, Pser, &len, &P, SECP256K1_EC_COMPRESSED);
    len = 33;
    secp256k1_ec_pubkey_serialize(ctx, Rser, &len, &RHS, SECP256K1_EC_COMPRESSED);

    return memcmp(Pser, Rser, 33) == 0;
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
    unsigned char current_bit;
    int all_ok = 1;
    const unsigned char N_MINUS_ONE_SCALAR[32] = {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
            0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
            0xBF, 0xEF, 0x90, 0xF0, 0xD2, 0xEB, 0xF9, 0x99
    };
    unsigned char one_scalar[32] = {0};
    one_scalar[31] = 0x01;
    unsigned char zero_scalar[32] = {0};

    // Assumes generate_random_scalar is available.

    /* 1. Encode value 'v' into a_l and a_r */
    for (i = 0; i < N_BITS; ++i) {
        current_bit = (value >> i) & 1; // Extract the i-th bit

        if (current_bit == 1) {
            // If bit is 1: a_l[i] = 1, a_r[i] = 0
            memcpy(al[i], one_scalar, 32);
            memcpy(ar[i], zero_scalar, 32);
        } else {
            // If bit is 0: a_l[i] = 0, a_r[i] = -1 (mod q)
            memcpy(al[i], zero_scalar, 32);
            memcpy(ar[i], N_MINUS_ONE_SCALAR, 32);
        }
    }

    /* 2. Generate random auxiliary scalars s_l and s_r */
    for (i = 0; i < N_BITS; ++i) {
        if (!generate_random_scalar(ctx, sl[i])) all_ok = 0;
        if (!generate_random_scalar(ctx, sr[i])) all_ok = 0;
    }

    return all_ok;
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

    unsigned char v_scalar[32] = {0};
    secp256k1_pubkey G_term, Pk_term;
    const secp256k1_pubkey* points_to_add[2];

    if (value == 0) return 0; /* Commitment must be to a non-zero value */

    /* 1. Convert value to scalar (v*G) */
    if (!compute_amount_point(ctx, &G_term, value)) return 0; // V_term = v*G

    /* 2. Compute r*Pk_base (R_term) */
    Pk_term = *pk_base; // Start with the recipient's public key
    if (secp256k1_ec_pubkey_tweak_mul(ctx, &Pk_term, blinding_factor) != 1) return 0; // R_term = r*Pk_base

    /* 3. Compute C = v*G + r*Pk_base */
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
)  {
/* 1. Variable Declarations */
    secp256k1_pubkey G_vec[N_BITS], H_vec[N_BITS];
    secp256k1_pubkey A, S;
    unsigned char al[N_BITS][32], ar[N_BITS][32]; /* bit vectors */
    unsigned char sl[N_BITS][32], sr[N_BITS][32]; /* blinding vectors */
    unsigned char alpha[32], rho_blinder[32];     /* scalars for A and S */
    uint64_t i;
    unsigned char x[32], x_sq[32], y[32], z[32], z_sq[32], z_neg[32]; /* Combined here */
    unsigned char t_hat[32], tau_x[32], tmp[32];           /* Added tau_x and tmp */

    /* ... */

    /* 2. Initialization & Generators */
    if (!secp256k1_mpt_get_generator_vector(ctx, G_vec, N_BITS, (const unsigned char*)"G", 1)) {
        fprintf(stderr, "DEBUG: Failed at Step 2 (G_vec)\n"); return 0;
    }

    if (!secp256k1_mpt_get_generator_vector(ctx, H_vec, N_BITS, (const unsigned char*)"H", 1)) {
        fprintf(stderr, "DEBUG: Failed at Step 2 (H_vec)\n"); return 0;
    }


    /* 3. Bit Decomposition (aL and aR) */
    unsigned char one[32] = {0};
    unsigned char minus_one[32];
    one[31] = 1;

    /* Compute -1 mod n */
    memcpy(minus_one, one, 32);
    if (!secp256k1_ec_seckey_negate(ctx, minus_one)) return 0;

    for (i = 0; i < N_BITS; i++) {
        memset(al[i], 0, 32);
        memset(ar[i], 0, 32);

        if ((value >> i) & 1) {
            memcpy(al[i], one, 32);
            /* ar[i] remains zero (1 - 1 = 0) */
        } else {
            /* al[i] remains zero */
            memcpy(ar[i], minus_one, 32); /* 0 - 1 = -1 */
        }
    }

    /* 4. Generate Blinding Vectors for S */
    for (i = 0; i < N_BITS; i++) {
        do { RAND_bytes(sl[i], 32); } while (!secp256k1_ec_seckey_verify(ctx, sl[i]));
        do { RAND_bytes(sr[i], 32); } while (!secp256k1_ec_seckey_verify(ctx, sr[i]));
    }
    do { RAND_bytes(alpha, 32); } while (!secp256k1_ec_seckey_verify(ctx, alpha));
    do { RAND_bytes(rho_blinder, 32); } while (!secp256k1_ec_seckey_verify(ctx, rho_blinder));


    /* 5. Compute Vector Commitment A */
    /* A = alpha * pk_base + <al, G_vec> + <ar, H_vec> */
    {
        secp256k1_pubkey term_G, term_H, term_alpha;

        // Term 1: <al, G_vec>
        if (!secp256k1_bulletproof_ipa_msm(ctx, &term_G, G_vec, (const unsigned char*)al, N_BITS)) return 0;
        // Term 2: <ar, H_vec>
        if (!secp256k1_bulletproof_ipa_msm(ctx, &term_H, H_vec, (const unsigned char*)ar, N_BITS)) return 0;
        // Term 3: alpha * pk_base
        term_alpha = *pk_base;
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &term_alpha, alpha)) return 0;
        // A = term_alpha + term_G + term_H
        const secp256k1_pubkey* points_A[3] = {&term_alpha, &term_G, &term_H};
        if (!secp256k1_ec_pubkey_combine(ctx, &A, points_A, 3)) return 0;
    }



    /* 6. Compute Vector Commitment S */
    /* S = rho_blinder * pk_base + <sl, G_vec> + <sr, H_vec> */
    {
        secp256k1_pubkey term_G, term_H, term_rho;

        // Term 1: <sl, G_vec>
        if (!secp256k1_bulletproof_ipa_msm(ctx, &term_G, G_vec, (const unsigned char*)sl, N_BITS)) return 0;

        // Term 2: <sr, H_vec>
        if (!secp256k1_bulletproof_ipa_msm(ctx, &term_H, H_vec, (const unsigned char*)sr, N_BITS)) return 0;

        // Term 3: rho_blinder * pk_base
        term_rho = *pk_base;
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &term_rho, rho_blinder)) return 0;

        // S = term_rho + term_G + term_H
        const secp256k1_pubkey* points_S[3] = {&term_rho, &term_G, &term_H};
        if (!secp256k1_ec_pubkey_combine(ctx, &S, points_S, 3)) return 0;

    }
    /* 7. Fiat-Shamir: Generate challenges y and z */

    /* 7. Fiat–Shamir challenges:
     * y = H(context_id || A || S)
     * z = H(context_id || A || S || y)
     */
    /* --- Prover Step 7: Generate y and z --- */
    unsigned char A_ser[33], S_ser[33];
    size_t slen = 33;
    SHA256_CTX sha;

    secp256k1_ec_pubkey_serialize(ctx, A_ser, &slen, &A, SECP256K1_EC_COMPRESSED);
    slen = 33;
    secp256k1_ec_pubkey_serialize(ctx, S_ser, &slen, &S, SECP256K1_EC_COMPRESSED);

/* y = Hash(context_id || A || S) */
    SHA256_Init(&sha);
    if (context_id) SHA256_Update(&sha, context_id, 32);
    SHA256_Update(&sha, A_ser, 33);
    SHA256_Update(&sha, S_ser, 33);
    SHA256_Final(y, &sha);

/* z = Hash(context_id || A || S || y) */
    SHA256_Init(&sha);
    if (context_id) SHA256_Update(&sha, context_id, 32);
    SHA256_Update(&sha, A_ser, 33);
    SHA256_Update(&sha, S_ser, 33);
    SHA256_Update(&sha, y, 32);
    SHA256_Final(z, &sha);



    /* --- 8. Construct Polynomial Vectors l0, l1, r0, r1 --- */
    unsigned char l0[N_BITS][32], l1[N_BITS][32];
    unsigned char r0[N_BITS][32], r1[N_BITS][32];
    unsigned char y_powers[N_BITS][32];
    unsigned char t1[32], t2[32], tau1[32], tau2[32];
    secp256k1_pubkey T1, T2;


    scalar_vector_powers(ctx, y_powers, y, N_BITS);

    /* 8a. Prepare z_sq and z_neg */
    secp256k1_mpt_scalar_mul(z_sq, z, z); /* z^2 */

    secp256k1_mpt_scalar_negate(z_neg, z); /* z_neg = -z */

    /* 8b. Construct l0,l1,r0,r1 (so that l(X)=l0 + X*l1 and r(X)=r0 + x*r1). */

    for (i = 0; i < N_BITS; i++) {
        unsigned char two_pow_i[32] = {0};
        unsigned char term_z_sq_2[32];

        two_pow_i[31 - (i/8)] = (1 << (i%8));

        /* l0[i] = al[i] - z  => al[i] + z_neg */
        secp256k1_mpt_scalar_add(l0[i], al[i], z_neg);
        memcpy(l1[i], sl[i], 32);

        /* r0[i] = y^i * (ar[i] + z) + z^2 * 2^i */
        unsigned char temp_r[32];
        secp256k1_mpt_scalar_add(temp_r, ar[i], z);
        secp256k1_mpt_scalar_mul(r0[i], temp_r, y_powers[i]);

        /* Add the z^2 * 2^i term */
        secp256k1_mpt_scalar_mul(term_z_sq_2, z_sq, two_pow_i);
        secp256k1_mpt_scalar_add(r0[i], r0[i], term_z_sq_2);

        /* r1[i] = y^i * sr[i] */
        secp256k1_mpt_scalar_mul(r1[i], sr[i], y_powers[i]);
    }

    /* 8c. Compute t1 = <l0, r1> + <l1, r0> */
    {
            unsigned char part1[32], part2[32];
            /* Ensure ipa_dot is also updated to use internal scalar math (see below) */
            if (!secp256k1_bulletproof_ipa_dot(ctx, part1, (const unsigned char*)l0, (const unsigned char*)r1, N_BITS)) return 0;
            if (!secp256k1_bulletproof_ipa_dot(ctx, part2, (const unsigned char*)l1, (const unsigned char*)r0, N_BITS)) return 0;

            /* Use the INTERNAL math wrapper instead of tweak_add */
            secp256k1_mpt_scalar_add(t1, part1, part2);
    }
    /* 8d. Compute t2 = <l1, r1> */
    if (!secp256k1_bulletproof_ipa_dot(ctx, t2, (const unsigned char*)l1, (const unsigned char*)r1, N_BITS)) return 0;

    /* 9. Generate blinding scalars and Commitments T1, T2 */
    generate_random_scalar(ctx, tau1);
    generate_random_scalar(ctx, tau2);
    /* --- Compute Commitment T1 --- */
/* T1 = t1*G + tau1*H */
    {
        unsigned char zero[32] = {0};
        secp256k1_pubkey g_term, h_term;
        int has_g = 0, has_h = 0;

        // t1*G
        if (memcmp(t1, zero, 32) != 0) {
            if (secp256k1_ec_pubkey_create(ctx, &g_term, t1)) has_g = 1;
        }

        // tau1*H
        h_term = *pk_base;
        if (memcmp(tau1, zero, 32) != 0) {
            if (secp256k1_ec_pubkey_tweak_mul(ctx, &h_term, tau1)) has_h = 1;
        }

        if (has_g && has_h) {
            const secp256k1_pubkey* pts[2] = {&g_term, &h_term};
            secp256k1_ec_pubkey_combine(ctx, &T1, pts, 2);
        } else if (has_g) {
            T1 = g_term;
        } else if (has_h) {
            T1 = h_term;
        } else {
        /* both terms missing => point at infinity, which we cannot represent/serialize */
        fprintf(stderr, "T1 would be infinity (tau1=0 and t1=0). Rejecting.\n");
        return 0;
    }

}

/* --- Compute Commitment T2 (The one currently crashing) --- */
    {
        unsigned char zero[32] = {0};
        secp256k1_pubkey g_term, h_term;
        int has_g = 0, has_h = 0;

        if (memcmp(t2, zero, 32) != 0) {
            if (secp256k1_ec_pubkey_create(ctx, &g_term, t2)) has_g = 1;
        }

        h_term = *pk_base;
        if (memcmp(tau2, zero, 32) != 0) {
            if (secp256k1_ec_pubkey_tweak_mul(ctx, &h_term, tau2)) has_h = 1;
        }

        if (has_g && has_h) {
            const secp256k1_pubkey* pts[2] = {&g_term, &h_term};
            secp256k1_ec_pubkey_combine(ctx, &T2, pts, 2);
        } else if (has_g) {
            T2 = g_term;
        } else if (has_h) {
            T2 = h_term;
        } else {
        /* both terms missing => point at infinity, which we cannot represent/serialize */
        fprintf(stderr, "T2 would be infinity (tau2=0 and t2=0). Rejecting.\n");
        return 0;
    }

}

    /* --- Step 10: Generate Final Challenge x --- */
    unsigned char T1_ser[33], T2_ser[33];
    size_t ser_len_t = 33;
    SHA256_CTX sha_x;

    /* 1. Serialize T1 and T2 for the transcript */
    if (!secp256k1_ec_pubkey_serialize(ctx, T1_ser, &ser_len_t, &T1, SECP256K1_EC_COMPRESSED)) return 0;
    ser_len_t = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, T2_ser, &ser_len_t, &T2, SECP256K1_EC_COMPRESSED)) return 0;

    /* 2. Fiat-Shamir: x = H(context_id || y || z || T1 || T2) */
    SHA256_Init(&sha_x);
    if (context_id) {
        SHA256_Update(&sha_x, context_id, 32);
    }
    SHA256_Update(&sha_x, y, 32);
    SHA256_Update(&sha_x, z, 32);
    SHA256_Update(&sha_x, T1_ser, 33);
    SHA256_Update(&sha_x, T2_ser, 33);
    SHA256_Final(x, &sha_x);

    /* 3. Verify the resulting scalar is valid for secp256k1 */
    if (!secp256k1_ec_seckey_verify(ctx, x)) {
        return 0;
    }
    unsigned char mu[32];
    unsigned char rho_x[32];

/* mu = alpha + rho_blinder * x (mod n) */
    secp256k1_mpt_scalar_mul(rho_x, rho_blinder, x);
    secp256k1_mpt_scalar_add(mu, alpha, rho_x);
    if (!secp256k1_ec_seckey_verify(ctx, mu)) return 0;


    /* --- Step 11: Evaluate Polynomials at Challenge x --- */
    unsigned char l_final[N_BITS][32], r_final[N_BITS][32];


    /* 1. Evaluate vector l(x) = l0 + l1*x */
    for (i = 0; i < N_BITS; i++) {
        /* l_final[i] = l1[i] * x */
        /* l_final[i] = (l1[i] * x) + l0[i] */
        secp256k1_mpt_scalar_mul(l_final[i], l1[i], x);
        secp256k1_mpt_scalar_add(l_final[i], l_final[i], l0[i]);

    }

    /* 2. Evaluate vector r(x) = r0 + r1*x */
    for (i = 0; i < N_BITS; i++) {
        /* r_final[i] = r1[i] * x */
        /* r_final[i] = (r1[i] * x) + r0[i] */
        secp256k1_mpt_scalar_mul(r_final[i], r1[i], x);
        secp256k1_mpt_scalar_add(r_final[i], r_final[i], r0[i]);
    }

    /* 3. Compute t_hat = <l, r> */
    /* This is the inner product of the two unfolded vectors */
    if (!secp256k1_bulletproof_ipa_dot(ctx, t_hat, (const unsigned char*)l_final,(const unsigned char*)r_final, N_BITS)) {
        return 0;
    }

    /* --- Step 12: Inner Product Argument (IPA) Compression --- */
    secp256k1_pubkey L_vec[6], R_vec[6]; /* log2(64) = 6 rounds */
    unsigned char a_final[32], b_final[32];
    unsigned char ipa_transcript_id[32];

    /* 12a. IPA transcript seed:
    * We bind the IPA sub-protocol to the range-proof transcript via x.
    */
    SHA256(x, 32, ipa_transcript_id);

    /* 12b. IPA binding scalar ux:
    * ux MUST be derived once from (ipa_transcript_id, t_hat) and then reused
    * consistently in L/R construction and the final (a*b*ux)*U term.
    */
    unsigned char ux_scalar[32];
    if (!derive_ipa_binding_challenge(ctx, ux_scalar, ipa_transcript_id, t_hat))
        return 0;

    secp256k1_pubkey U;
    if (!secp256k1_mpt_get_generator_vector(
            ctx, &U, 1,
            (const unsigned char*)"BP_U", 4
    )) return 0;

    // 12c. Normalize H generators: H'_i = y^{-i} * H_i

    secp256k1_pubkey H_prime[N_BITS];
    unsigned char y_inv[32];
    unsigned char y_inv_powers_temp[N_BITS][32];

    /* Calculate y^-1 and powers */
    secp256k1_mpt_scalar_inverse(y_inv, y);
    scalar_vector_powers(ctx, y_inv_powers_temp, y_inv, N_BITS);

    /* Construct H' = H^(y^-i) */
    for(int k=0; k<N_BITS; k++) {
        H_prime[k] = H_vec[k];
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &H_prime[k], y_inv_powers_temp[k]))
            return 0;
    }

    /* This will compress G_vec, H_vec, l_final, and r_final in-place */
    if (!secp256k1_bulletproof_run_ipa_prover(
            ctx,
            &U,
            G_vec, H_prime,
            (unsigned char*)l_final,
            (unsigned char*)r_final,
            N_BITS,
            ipa_transcript_id,
            ux_scalar,
            L_vec, R_vec,
            a_final, b_final
    )) return 0;

    /* 13. Serialize proof in the fixed layout:
    *   A,S,T1,T2 (4 * 33)
    *   L[0..5], R[0..5] (12 * 33)
    *   a_final, b_final, t_hat, tau_x, mu (5 * 32)
    * Total = 688 bytes.
    */

    /* Compute tau_x --- */
    unsigned char x_sq_val[32];

    /* Compute z_sq = z^2 and x_sq = x^2 */
    secp256k1_mpt_scalar_mul(z_sq, z, z);

    secp256k1_mpt_scalar_mul(x_sq_val, x, x);


    /* tau_x = (tau2 * x^2) + (tau1 * x) + (z^2 * rho) */
    /* Start with Term 3: z^2 * blinding_factor */
    /* Add Term 2: tau1 * x */
    /* Add Term 1: tau2 * x^2 */
    secp256k1_mpt_scalar_mul(tau_x, z_sq, blinding_factor);
    secp256k1_mpt_scalar_mul(tmp, tau1, x);
    secp256k1_mpt_scalar_add(tau_x, tau_x, tmp);
    secp256k1_mpt_scalar_mul(tmp, tau2, x_sq_val);
    secp256k1_mpt_scalar_add(tau_x, tau_x, tmp);


    /* Serialization --- */
    unsigned char *ptr = proof_out;
    size_t ser_len_final;
    int j;

    ser_len_final = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, ptr, &ser_len_final, &A, SECP256K1_EC_COMPRESSED)) return 0; ptr += 33;
    ser_len_final = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, ptr, &ser_len_final, &S, SECP256K1_EC_COMPRESSED)) return 0; ptr += 33;
    ser_len_final = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, ptr, &ser_len_final, &T1, SECP256K1_EC_COMPRESSED)) return 0; ptr += 33;
    ser_len_final = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, ptr, &ser_len_final, &T2, SECP256K1_EC_COMPRESSED)) return 0; ptr += 33;

    for (j = 0; j < 6; j++) {
        ser_len_final = 33;
        if (!secp256k1_ec_pubkey_serialize(ctx, ptr, &ser_len_final, &L_vec[j], SECP256K1_EC_COMPRESSED)) return 0;
        ptr += 33;
    }
    for (j = 0; j < 6; j++) {
        ser_len_final = 33;
        if (!secp256k1_ec_pubkey_serialize(ctx, ptr, &ser_len_final, &R_vec[j], SECP256K1_EC_COMPRESSED)) return 0;
        ptr += 33;
    }

    memcpy(ptr, a_final, 32); ptr += 32;
    memcpy(ptr, b_final, 32); ptr += 32;
    memcpy(ptr, t_hat, 32);   ptr += 32;
    memcpy(ptr, tau_x, 32);   ptr += 32;
    memcpy(ptr, mu, 32);      ptr += 32;

    *proof_len = 688;

    return 1;


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
    /* =========================================================================
     * Step 1: Decode proof and check basic well-formedness
     *   Proof encoding (688 bytes):
     *     A,S,T1,T2 (4*33)
     *     L[6],R[6] (12*33)
     *     a_final,b_final,t_hat,tau_x,mu (5*32)
     * ========================================================================= */

    /* --- 1a. Variable Declarations --- */

    /* Protocol Points */
    secp256k1_pubkey A, S, T1, T2;      /* Range Proof Commitments */
    secp256k1_pubkey L_vec[6], R_vec[6]; /* IPA Folding Points (log2(64) = 6) */
    secp256k1_pubkey U;                 /* IPA NUMS Generator */

    /* Protocol Scalars */
    unsigned char a_final[32], b_final[32]; /* Final folded vectors (single scalars) */
    unsigned char t_hat[32];                /* Final inner product */
    unsigned char tau_x[32], mu[32];        /* Aggregated blinding factors */

    /* Challenges (Fiat-Shamir) */
    unsigned char y[32], z[32], x[32];
    unsigned char ux_scalar[32];

    /* Pre-computation buffers */
    unsigned char delta[32], z_sq[32], z_cu[32];
    unsigned char y_pow_sum[32], two_pow_sum[32];
    unsigned char term1[32], term2[32];
    unsigned char y_powers[64][32];
    unsigned char y_inv[32];
    unsigned char y_inv_powers[64][32];

    /* Iterator & Pointer */
    const unsigned char *ptr = proof;
    int i;


    /* --- 1b. Strict Length Check --- */
    /* * Layout verification:
     * 4 Points (A, S, T1, T2)   @ 33 bytes = 132 bytes
     * 12 IPA Points (L*6, R*6)  @ 33 bytes = 396 bytes
     * 5 Scalars (a, b, t, tau, mu) @ 32 bytes = 160 bytes
     * Total: 688 bytes
     */
    if (proof_len != 688) {
        return 0; /* Invalid proof size */
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
    /* Ensure scalars are valid (non-zero logic handled by protocol, but must be < order) */
    if (!secp256k1_ec_seckey_verify(ctx, a_final)) return 0;
    if (!secp256k1_ec_seckey_verify(ctx, b_final)) return 0;
    if (!secp256k1_ec_seckey_verify(ctx, t_hat))   return 0;
    if (!secp256k1_ec_seckey_verify(ctx, tau_x))   return 0;
    if (!secp256k1_ec_seckey_verify(ctx, mu))      return 0;


    /* --- 1g. Derive Generators --- */
    /* * Derive the orthogonal generator U for the Inner Product Argument.
     * This uses a fixed string "BP_U" salted into the hash to ensure
     * U is a NUMS (Nothing Up My Sleeve) point.
     */
    if (!secp256k1_mpt_get_generator_vector(ctx, &U, 1, (const unsigned char*)"BP_U", 4)) {
        return 0;
    }

    /* =========================================================================
     * Step 2: Recompute Fiat–Shamir challenges y,z,x from transcript
     *   y = H(context_id || A || S)
     *   z = H(context_id || A || S || y)
     *   x = H(context_id || y || z || T1 || T2)
     *   Also precompute y^i and y^{-i}.
     * ========================================================================= */

    /* --- 2a. Serialize Commitments for Hashing --- */
    /* We need canonical 33-byte compressed serializations of A, S, T1, T2 */
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
    /* y = Hash(context || A || S) */
    SHA256_Init(&sha);
    if (context_id) SHA256_Update(&sha, context_id, 32);
    SHA256_Update(&sha, A_ser, 33);
    SHA256_Update(&sha, S_ser, 33);
    SHA256_Final(y, &sha);

    /* z = Hash(context || A || S || y) */
    SHA256_Init(&sha);
    if (context_id) SHA256_Update(&sha, context_id, 32);
    SHA256_Update(&sha, A_ser, 33);
    SHA256_Update(&sha, S_ser, 33);
    SHA256_Update(&sha, y, 32);
    SHA256_Final(z, &sha);

    /* Verify derived scalars are valid (non-zero, < order) */
    if (!secp256k1_ec_seckey_verify(ctx, y) || !secp256k1_ec_seckey_verify(ctx, z)) {
        return 0;
    }

    /* --- 2c. Pre-compute Scalar Powers --- */
    /* These vectors are used heavily in the polynomial check and IPA folding.
     * y_powers = [1, y, y^2, ...]
     * y_inv_powers = [1, y^-1, y^-2, ...]
     */
    scalar_vector_powers(ctx, y_powers, y, 64);

    secp256k1_mpt_scalar_inverse(y_inv, y);
    /* Note: If y is 0 (rejected above), inverse fails. verify(y) protects this. */

    scalar_vector_powers(ctx, y_inv_powers, y_inv, 64);

    /* --- 2d. Derive Challenge x --- */
    /* x = Hash(context || y || z || T1 || T2) */
    SHA256_Init(&sha);
    if (context_id) SHA256_Update(&sha, context_id, 32);
    SHA256_Update(&sha, y, 32);
    SHA256_Update(&sha, z, 32);
    SHA256_Update(&sha, T1_ser, 33);
    SHA256_Update(&sha, T2_ser, 33);
    SHA256_Final(x, &sha);

    if (!secp256k1_ec_seckey_verify(ctx, x)) {
        return 0;
    }

    /* =========================================================================
      * Step 3: Verify polynomial identity (range proof consistency)
      *   Check:  t_hat*G + tau_x*pk_base  ==  z^2*C + delta(y,z)*G + x*T1 + x^2*T2
      * ========================================================================= */

    /* --- 3a. delta(y,z) --- */
    secp256k1_mpt_scalar_mul(z_sq, z, z);
    secp256k1_mpt_scalar_mul(z_cu, z_sq, z);

    compute_delta_scalars(ctx, y_pow_sum, two_pow_sum, y, 64);

    {
        unsigned char neg_z_sq[32], neg_term2[32];
        secp256k1_mpt_scalar_negate(neg_z_sq, z_sq);           /* -z^2 */
        secp256k1_mpt_scalar_add(term1, z, neg_z_sq);          /* z - z^2 */
        secp256k1_mpt_scalar_mul(term1, term1, y_pow_sum);     /* (z - z^2)*sum(y^i) */

        secp256k1_mpt_scalar_mul(term2, z_cu, two_pow_sum);    /* z^3*sum(2^i) */
        secp256k1_mpt_scalar_negate(neg_term2, term2);
        secp256k1_mpt_scalar_add(delta, term1, neg_term2);     /* term1 - term2 */
    }


    /* --- 3b. Polynomial identity check --- */
    {
        /* LHS = t_hat*G + tau_x*pk_base */
        secp256k1_pubkey LHS;
        {
            unsigned char zero32[32] = {0};
            int have_t = 0, have_tau = 0;
            secp256k1_pubkey tG, tauH;

            /* tG = t_hat * G */
            if (memcmp(t_hat, zero32, 32) != 0) {
                if (!secp256k1_ec_pubkey_create(ctx, &tG, t_hat)) return 0;
                have_t = 1;
            }

            /* tauH = tau_x * pk_base */
            if (memcmp(tau_x, zero32, 32) != 0) {
                tauH = *pk_base;
                if (!secp256k1_ec_pubkey_tweak_mul(ctx, &tauH, tau_x)) return 0;
                have_tau = 1;
            }

            /* LHS = tG + tauH */
            if (have_t && have_tau) {
                const secp256k1_pubkey* pts[2] = { &tG, &tauH };
                if (!secp256k1_ec_pubkey_combine(ctx, &LHS, pts, 2)) return 0;
            } else if (have_t) {
                LHS = tG;
            } else if (have_tau) {
                LHS = tauH;
            } else {
                /* Both scalars are zero => point at infinity (not representable here) */
                return 0;
            }
        }

        /* RHS = z^2*C + delta*G + x*T1 + x^2*T2 */
        secp256k1_pubkey RHS;
        {
            unsigned char zero[32] = {0};
            unsigned char x_sq[32];
            secp256k1_pubkey acc, tmp;
            int inited = 0;

            /* z^2*C */
            if (memcmp(z_sq, zero, 32) != 0) {
                tmp = *commitment_C;
                if (!secp256k1_ec_pubkey_tweak_mul(ctx, &tmp, z_sq)) return 0;
                acc = tmp; inited = 1;
            }
            /* delta*G */
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
            /* x*T1 */
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
            /* x^2*T2 */
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
        // printf("\n Verification: The first equality check is passed!\n");
    }

    unsigned char u[6][32], u_inv[6][32], last_challenge[32];
    unsigned char ipa_transcript_id[32];
    SHA256(x, 32, ipa_transcript_id);
    if (!derive_ipa_binding_challenge(
            ctx, ux_scalar, ipa_transcript_id, t_hat))
        return 0;




    /* --- 4. Build P = A + x*S - z*<1,G> + <(z*y^i + z^2*2^i), H>  + (t_hat*ux)*U - mu*pk_base --- */
    /* =========================================================================
     * Step 4: Build IPA commitment point P for inner product verification
     *   Let H'_i = y^{-i} * H_i (normalized generators).
     *   P = A + x*S
     *       + sum_i [ (-z)*G_i + (z*y^i + z^2*2^i)*H'_i ]
     *       + (t_hat * ux)*U
     *       - mu*pk_base
     *   where ux = H(ipa_transcript_id || t_hat) (binding scalar).
     * =========================================================================*/
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
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &Gi, neg_z))
            return 0;

        /* zy_i = z * y^i */
        secp256k1_mpt_scalar_mul(zy_i, z, y_powers[i]);

        /* two_pow_i = 2^i */
        two_pow_i[31 - (i / 8)] = (1 << (i % 8));

        /* term2 = z^2 * 2^i */
        secp256k1_mpt_scalar_mul(term2, z_sq, two_pow_i);

        /* h_i = z*y^i + z^2*2^i */
        secp256k1_mpt_scalar_add(h_scalar, zy_i, term2);

        /* Normalize generator: H'_i = y^{-i} * H_i */
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &Hi, y_inv_powers[i]))
            return 0;

        /* Hi = h_i * H'_i */
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &Hi, h_scalar))
            return 0;

        /* P += Gi + Hi */
        secp256k1_pubkey P_new;
        const secp256k1_pubkey* pts[3] = { &P, &Gi, &Hi };
        if (!secp256k1_ec_pubkey_combine(ctx, &P_new, pts, 3))
            return 0;

        P = P_new;
    }



/* ---- CRITICAL IPA binding term ----
 * P += (t_hat * ux_scalar) * U
 */
    {
        unsigned char zero32[32] = {0};
        unsigned char t_hat_ux[32];

        secp256k1_mpt_scalar_mul(t_hat_ux, t_hat, ux_scalar);

        if (memcmp(t_hat_ux, zero32, 32) != 0) {
            secp256k1_pubkey Q = U;
            if (!secp256k1_ec_pubkey_tweak_mul(ctx, &Q, t_hat_ux))
                return 0;

            secp256k1_pubkey P_new;
            const secp256k1_pubkey* pts[2] = { &P, &Q };
            if (!secp256k1_ec_pubkey_combine(ctx, &P_new, pts, 2))
                return 0;

            P = P_new;
        }
    }

    /* - mu*pk_base --- */
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

    secp256k1_pubkey P_unfolded = P;

    /* =========================================================================
     * Step 5: Verify the Inner Product Argument (IPA)
     *   Recompute u_i from (ipa_transcript_id, L_i, R_i),
     *   fold generators and P, and check final single-scalar equation.
     * ========================================================================= */

    memcpy(last_challenge, ipa_transcript_id, 32);


    for (i = 0; i < 6; i++) {
        if (!derive_ipa_round_challenge(ctx, u[i], last_challenge, &L_vec[i], &R_vec[i])) return 0;
        secp256k1_mpt_scalar_inverse(u_inv[i], u[i]);
        memcpy(last_challenge, u[i], 32);
    }

    secp256k1_pubkey Hprime[64];
    for (int i = 0; i < 64; i++) {
        Hprime[i] = H_vec[i];
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &Hprime[i], y_inv_powers[i]))
            return 0;
    }
    if(!ipa_verify_explicit(ctx, G_vec, Hprime, &U, &P_unfolded, L_vec, R_vec, a_final, b_final, ux_scalar, ipa_transcript_id)) return 0;

    return 1;

}
