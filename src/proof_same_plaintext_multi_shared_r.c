#include "secp256k1_mpt.h"
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdlib.h>

/*
 * Calculates the size of the serialized proof:
 * Points:  Tr (33) + N * Tm_i (33*N)
 * Scalars: sm (32) + sr (32)
 * Total:   33*(N+1) + 64
 */
size_t secp256k1_mpt_proof_equality_shared_r_size(size_t n_recipients) {
    return (33 * (n_recipients + 1)) + 64;
}

/* Helper: Generate a valid random scalar */
static int generate_random_scalar(const secp256k1_context* ctx, unsigned char* scalar) {
    do {
        if (RAND_bytes(scalar, 32) != 1) return 0;
    } while (secp256k1_ec_seckey_verify(ctx, scalar) != 1);
    return 1;
}

/* Helper: Securely clear scalar memory */
static void secp256k1_mpt_scalar_clear(unsigned char* scalar) {
    if (scalar) {
        memset(scalar, 0, 32);
    }
}

/* Helper: Compare two public keys */
static int pubkey_equal(const secp256k1_context* ctx, const secp256k1_pubkey* pk1, const secp256k1_pubkey* pk2) {
    unsigned char b1[33], b2[33];
    size_t len1 = 33, len2 = 33;
    secp256k1_ec_pubkey_serialize(ctx, b1, &len1, pk1, SECP256K1_EC_COMPRESSED);
    secp256k1_ec_pubkey_serialize(ctx, b2, &len2, pk2, SECP256K1_EC_COMPRESSED);
    return (len1 == len2) && (memcmp(b1, b2, len1) == 0);
}


/*
 * Fiat-Shamir Challenge Generation
 * Hash( Domain || C1 || {C2_i, Pk_i} || Tr || {Tm_i} || ContextID )
 */
static int compute_challenge_equality_shared_r(
        const secp256k1_context* ctx,
        unsigned char* e_out,
        size_t n,
        const secp256k1_pubkey* C1,
        const secp256k1_pubkey* C2_vec,
        const secp256k1_pubkey* Pk_vec,
        const secp256k1_pubkey* Tr,
        const secp256k1_pubkey* Tm_vec,
        const unsigned char* context_id
) {
    SHA256_CTX sha;
    unsigned char buf[33];
    unsigned char h[32];
    size_t len = 33;
    size_t i;
    const char* domain = "MPT_POK_EQUALITY_SHARED_R";

    SHA256_Init(&sha);
    SHA256_Update(&sha, domain, strlen(domain));

    /* 1. Shared C1 */
    secp256k1_ec_pubkey_serialize(ctx, buf, &len, C1, SECP256K1_EC_COMPRESSED);
    SHA256_Update(&sha, buf, 33);

    /* 2. Pairs {C2_i, Pk_i} */
    for (i = 0; i < n; i++) {
        secp256k1_ec_pubkey_serialize(ctx, buf, &len, &C2_vec[i], SECP256K1_EC_COMPRESSED);
        SHA256_Update(&sha, buf, 33);
        secp256k1_ec_pubkey_serialize(ctx, buf, &len, &Pk_vec[i], SECP256K1_EC_COMPRESSED);
        SHA256_Update(&sha, buf, 33);
    }

    /* 3. Commitment Tr */
    secp256k1_ec_pubkey_serialize(ctx, buf, &len, Tr, SECP256K1_EC_COMPRESSED);
    SHA256_Update(&sha, buf, 33);

    /* 4. Commitments {Tm_i} */
    for (i = 0; i < n; i++) {
        secp256k1_ec_pubkey_serialize(ctx, buf, &len, &Tm_vec[i], SECP256K1_EC_COMPRESSED);
        SHA256_Update(&sha, buf, 33);
    }

    /* 5. Transaction Context */
    if (context_id) {
        SHA256_Update(&sha, context_id, 32);
    }
    /* Hash → reduce mod curve order */
    SHA256_Final(h, &sha);
    secp256k1_mpt_scalar_reduce32(e_out, h);
    return 1;

}

int secp256k1_mpt_prove_equality_shared_r(
        const secp256k1_context* ctx,
        unsigned char* proof_out,
        size_t* proof_len,
        uint64_t amount,
        const unsigned char* r_shared,
        size_t n,
        const secp256k1_pubkey* C1,
        const secp256k1_pubkey* C2_vec,
        const secp256k1_pubkey* Pk_vec,
        const unsigned char* context_id
) {
    /* Check buffer size */
    size_t required = secp256k1_mpt_proof_equality_shared_r_size(n);
    if (*proof_len < required) {
        *proof_len = required;
        return 0;
    }
    *proof_len = required;

    /* Local Variables */
    unsigned char k_m[32], k_r[32];      /* Random nonces */
    unsigned char m_scalar[32] = {0};    /* Amount as scalar */
    secp256k1_pubkey Tr;                 /* Commitment to randomness */
    secp256k1_pubkey* Tm_vec = NULL;     /* Commitments to amount */
    unsigned char e[32];                 /* Challenge */
    unsigned char s_m[32], s_r[32];      /* Responses */
    int ok = 0;
    size_t i;

    /* Allocate memory for variable number of recipients */
    Tm_vec = (secp256k1_pubkey*)malloc(sizeof(secp256k1_pubkey) * n);
    if (!Tm_vec) return 0;

    /* 1. Prepare Witnesses */
    /* Convert amount uint64 -> scalar (Big Endian) */
    for (i = 0; i < 8; i++) {
        m_scalar[31 - i] = (amount >> (i * 8)) & 0xFF;
    }

    /* 2. Sample Random Nonces k_m, k_r */
    if (!generate_random_scalar(ctx, k_m)) goto cleanup;
    if (!generate_random_scalar(ctx, k_r)) goto cleanup;

    /* 3. Compute Commitments */

    /* Tr = kr * G */
    if (!secp256k1_ec_pubkey_create(ctx, &Tr, k_r)) goto cleanup;

    /* Tm_i = km * G + kr * Pk_i */
    secp256k1_pubkey kmG;
    if (!secp256k1_ec_pubkey_create(ctx, &kmG, k_m)) goto cleanup;

    for (i = 0; i < n; i++) {
        secp256k1_pubkey krPk = Pk_vec[i];
        /* Calculate kr * Pk_i */
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &krPk, k_r)) goto cleanup;

        /* Combine km*G + kr*Pk */
        const secp256k1_pubkey* pts[2] = {&kmG, &krPk};
        if (!secp256k1_ec_pubkey_combine(ctx, &Tm_vec[i], pts, 2)) goto cleanup;
    }

    /* 4. Compute Challenge e */
   compute_challenge_equality_shared_r(ctx, e, n, C1, C2_vec, Pk_vec, &Tr, Tm_vec, context_id);

    /* 5. Compute Responses */
    /* s_m = k_m + e * m */
    secp256k1_mpt_scalar_mul(s_m, e, m_scalar); /* term = e * m */
    secp256k1_mpt_scalar_add(s_m, s_m, k_m);    /* s_m = term + k_m */

    /* s_r = k_r + e * r */
    secp256k1_mpt_scalar_mul(s_r, e, r_shared); /* term = e * r */
    secp256k1_mpt_scalar_add(s_r, s_r, k_r);    /* s_r = term + k_r */

    /* 6. Serialize Proof */
    unsigned char* ptr = proof_out;
    size_t len = 33;

    /* Serialize Tr */
    secp256k1_ec_pubkey_serialize(ctx, ptr, &len, &Tr, SECP256K1_EC_COMPRESSED);
    ptr += 33;

    /* Serialize Tm_i array */
    for (i = 0; i < n; i++) {
        secp256k1_ec_pubkey_serialize(ctx, ptr, &len, &Tm_vec[i], SECP256K1_EC_COMPRESSED);
        ptr += 33;
    }

    /* Serialize Scalars s_m, s_r */
    memcpy(ptr, s_m, 32); ptr += 32;
    memcpy(ptr, s_r, 32); ptr += 32;

    ok = 1;

    cleanup:
    /* Securely clear sensitive stack/heap data */
    secp256k1_mpt_scalar_clear(k_m);
    secp256k1_mpt_scalar_clear(k_r);
    if (Tm_vec) free(Tm_vec);
    return ok;
}

int secp256k1_mpt_verify_equality_shared_r(
        const secp256k1_context* ctx,
        const unsigned char* proof,
        size_t proof_len,
        size_t n,
        const secp256k1_pubkey* C1,
        const secp256k1_pubkey* C2_vec,
        const secp256k1_pubkey* Pk_vec,
        const unsigned char* context_id
) {
    if (proof_len != secp256k1_mpt_proof_equality_shared_r_size(n)) return 0;

    /* Local Variables */
    secp256k1_pubkey Tr;
    secp256k1_pubkey* Tm_vec = NULL;
    unsigned char s_m[32], s_r[32];
    unsigned char e[32];
    int ok = 0;
    size_t i;
    const unsigned char* ptr = proof;

    Tm_vec = (secp256k1_pubkey*)malloc(sizeof(secp256k1_pubkey) * n);
    if (!Tm_vec) return 0;

    /* 1. Deserialize Proof */
    if (!secp256k1_ec_pubkey_parse(ctx, &Tr, ptr, 33)) goto cleanup;
    ptr += 33;

    for (i = 0; i < n; i++) {
        if (!secp256k1_ec_pubkey_parse(ctx, &Tm_vec[i], ptr, 33)) goto cleanup;
        ptr += 33;
    }

    memcpy(s_m, ptr, 32); ptr += 32;
    memcpy(s_r, ptr, 32); ptr += 32;
    /* Scalar validity checks */
    if (!secp256k1_ec_seckey_verify(ctx, s_m)) goto cleanup;
    if (!secp256k1_ec_seckey_verify(ctx, s_r)) goto cleanup;

    /* 2. Recompute Challenge e */
    if (!compute_challenge_equality_shared_r(ctx, e, n, C1, C2_vec, Pk_vec, &Tr, Tm_vec, context_id))
        goto cleanup;

    /* 3. Verification Equations */

    /* Eq 1: sr * G == Tr + e * C1 */
    {
        secp256k1_pubkey LHS, RHS;
        secp256k1_pubkey eC1 = *C1;

        /* LHS = sr * G */
        if (!secp256k1_ec_pubkey_create(ctx, &LHS, s_r)) goto cleanup;

        /* RHS = Tr + e*C1 */
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &eC1, e)) goto cleanup;

        const secp256k1_pubkey* pts[2] = {&Tr, &eC1};
        if (!secp256k1_ec_pubkey_combine(ctx, &RHS, pts, 2)) goto cleanup;

        if (!pubkey_equal(ctx, &LHS, &RHS)) goto cleanup;
    }

    /* Eq 2: For each i, sm * G + sr * Pk_i == Tm_i + e * C2_i */
    {
        /* Precompute sm * G (Shared across all i) */
        secp256k1_pubkey smG;
        if (!secp256k1_ec_pubkey_create(ctx, &smG, s_m)) goto cleanup;

        for (i = 0; i < n; i++) {
            secp256k1_pubkey LHS, RHS;

            /* LHS = sm*G + sr*Pk_i */
            secp256k1_pubkey srPk = Pk_vec[i];
            if (!secp256k1_ec_pubkey_tweak_mul(ctx, &srPk, s_r)) goto cleanup;

            const secp256k1_pubkey* lhs_pts[2] = {&smG, &srPk};
            if (!secp256k1_ec_pubkey_combine(ctx, &LHS, lhs_pts, 2)) goto cleanup;

            /* RHS = Tm_i + e*C2_i */
            secp256k1_pubkey eC2 = C2_vec[i];
            if (!secp256k1_ec_pubkey_tweak_mul(ctx, &eC2, e)) goto cleanup;

            const secp256k1_pubkey* rhs_pts[2] = {&Tm_vec[i], &eC2};
            if (!secp256k1_ec_pubkey_combine(ctx, &RHS, rhs_pts, 2)) goto cleanup;

            if (!pubkey_equal(ctx, &LHS, &RHS)) goto cleanup;
        }
    }

    ok = 1;

    cleanup:
    if (Tm_vec) free(Tm_vec);
    return ok;
}