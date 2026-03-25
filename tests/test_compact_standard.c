#include "secp256k1_mpt.h"
#include "test_utils.h"
#include <secp256k1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    EXPECT(ctx != NULL);

    unsigned char seed[32];
    random_bytes(seed);
    EXPECT(secp256k1_context_randomize(ctx, seed));

    printf("=== Running Test: Compact AND-Composed Standard EC-ElGamal Proof ===\n");

    const int N = 3;
    uint64_t balance = 1000000;
    uint64_t amount = 123456;
    uint64_t remainder = balance - amount;

    unsigned char r[32], r_bal[32], r_b[32], sk_A[32], context_id[32];
    secp256k1_pubkey pk_A, H;

    random_scalar(ctx, r);
    random_scalar(ctx, r_bal);
    random_scalar(ctx, r_b);
    random_scalar(ctx, sk_A);
    random_scalar(ctx, context_id);

    EXPECT(secp256k1_ec_pubkey_create(ctx, &pk_A, sk_A));
    EXPECT(secp256k1_mpt_get_h_generator(ctx, &H));

    /* Generate recipient keys */
    unsigned char sk_recip[3][32];
    secp256k1_pubkey pks[3];
    for (int i = 0; i < N; i++) {
        random_scalar(ctx, sk_recip[i]);
        EXPECT(secp256k1_ec_pubkey_create(ctx, &pks[i], sk_recip[i]));
    }

    /* Standard EG ciphertexts with shared r:
     *   C1    = r*G
     *   C2_i  = r*pk_i + m*G
     *   PC_m  = r*G + m*H         (Pedersen commitment reusing r)
     */
    secp256k1_pubkey C1, C2_vec[3], PC_m;

    /* C1 = r*G */
    EXPECT(secp256k1_ec_pubkey_create(ctx, &C1, r));

    /* m*G */
    secp256k1_pubkey mG;
    {
        unsigned char m_scalar[32] = {0};
        for (int b = 0; b < 8; b++)
            m_scalar[31 - b] = (amount >> (b * 8)) & 0xFF;
        EXPECT(secp256k1_ec_pubkey_create(ctx, &mG, m_scalar));
    }

    /* C2_i = r*pk_i + m*G */
    for (int i = 0; i < N; i++) {
        secp256k1_pubkey rPk = pks[i];
        EXPECT(secp256k1_ec_pubkey_tweak_mul(ctx, &rPk, r));
        const secp256k1_pubkey *pts[2] = {&rPk, &mG};
        EXPECT(secp256k1_ec_pubkey_combine(ctx, &C2_vec[i], pts, 2));
    }

    /* PC_m = r*G + m*H */
    {
        secp256k1_pubkey rG, mH;
        EXPECT(secp256k1_ec_pubkey_create(ctx, &rG, r));
        unsigned char m_scalar[32] = {0};
        for (int b = 0; b < 8; b++)
            m_scalar[31 - b] = (amount >> (b * 8)) & 0xFF;
        mH = H;
        EXPECT(secp256k1_ec_pubkey_tweak_mul(ctx, &mH, m_scalar));
        const secp256k1_pubkey *pts[2] = {&rG, &mH};
        EXPECT(secp256k1_ec_pubkey_combine(ctx, &PC_m, pts, 2));
    }

    /* PC_b = r_b*G + v*H */
    secp256k1_pubkey PC_b;
    {
        secp256k1_pubkey rbG, vH;
        EXPECT(secp256k1_ec_pubkey_create(ctx, &rbG, r_b));
        unsigned char v_scalar[32] = {0};
        for (int b = 0; b < 8; b++)
            v_scalar[31 - b] = (remainder >> (b * 8)) & 0xFF;
        vH = H;
        EXPECT(secp256k1_ec_pubkey_tweak_mul(ctx, &vH, v_scalar));
        const secp256k1_pubkey *pts[2] = {&rbG, &vH};
        EXPECT(secp256k1_ec_pubkey_combine(ctx, &PC_b, pts, 2));
    }

    /* Balance ciphertext: C_bal = (r_bal*G, r_bal*pk_A + balance*G)
     * Remainder: C_rem = C_bal - C_send_to_A
     *   C1_rem = (r_bal - r)*G
     *   C2_rem = (r_bal - r)*pk_A + (balance - amount)*G
     *          = (r_bal - r)*pk_A + v*G
     *
     * Variant B relation: sk_A * C1_rem + v*G = C2_rem
     */
    secp256k1_pubkey C1_rem, C2_rem;
    {
        /* C1_rem = (r_bal - r)*G */
        unsigned char r_diff[32];
        memcpy(r_diff, r_bal, 32);
        unsigned char neg_r[32];
        secp256k1_mpt_scalar_negate(neg_r, r);
        secp256k1_mpt_scalar_add(r_diff, r_bal, neg_r);
        /* Need to reduce */
        secp256k1_mpt_scalar_reduce32(r_diff, r_diff);
        EXPECT(secp256k1_ec_pubkey_create(ctx, &C1_rem, r_diff));

        /* C2_rem = r_diff*pk_A + v*G */
        secp256k1_pubkey rdPk, vG;
        rdPk = pk_A;
        EXPECT(secp256k1_ec_pubkey_tweak_mul(ctx, &rdPk, r_diff));

        unsigned char v_scalar[32] = {0};
        for (int b = 0; b < 8; b++)
            v_scalar[31 - b] = (remainder >> (b * 8)) & 0xFF;
        EXPECT(secp256k1_ec_pubkey_create(ctx, &vG, v_scalar));

        const secp256k1_pubkey *pts[2] = {&rdPk, &vG};
        EXPECT(secp256k1_ec_pubkey_combine(ctx, &C2_rem, pts, 2));
    }

    /* Verify the Variant B relation holds: sk_A*C1_rem + v*G == C2_rem */
    {
        secp256k1_pubkey skC1r, vG, check;
        skC1r = C1_rem;
        EXPECT(secp256k1_ec_pubkey_tweak_mul(ctx, &skC1r, sk_A));
        unsigned char v_scalar[32] = {0};
        for (int b = 0; b < 8; b++)
            v_scalar[31 - b] = (remainder >> (b * 8)) & 0xFF;
        EXPECT(secp256k1_ec_pubkey_create(ctx, &vG, v_scalar));
        const secp256k1_pubkey *pts[2] = {&skC1r, &vG};
        EXPECT(secp256k1_ec_pubkey_combine(ctx, &check, pts, 2));
        EXPECT(secp256k1_ec_pubkey_cmp(ctx, &check, &C2_rem) == 0);
        printf("Variant B relation verified.\n");
    }

    /* --- Positive Case --- */
    printf("Generating compact standard proof for %d recipients...\n", N);

    unsigned char proof[SECP256K1_COMPACT_STANDARD_PROOF_SIZE];
    int res = secp256k1_compact_standard_prove(
        ctx, proof, amount, remainder, r, sk_A, r_b, N,
        &C1, C2_vec, pks, &PC_m, &pk_A, &PC_b, &C1_rem, &C2_rem,
        context_id);
    EXPECT(res == 1);
    printf("Proof generated: %d bytes.\n", SECP256K1_COMPACT_STANDARD_PROOF_SIZE);

    res = secp256k1_compact_standard_verify(
        ctx, proof, N, &C1, C2_vec, pks, &PC_m, &pk_A, &PC_b,
        &C1_rem, &C2_rem, context_id);
    EXPECT(res == 1);
    printf("Proof verified successfully.\n");

    /* --- Negative: Wrong context --- */
    printf("Testing wrong context...\n");
    {
        unsigned char fake_ctx[32];
        memcpy(fake_ctx, context_id, 32);
        fake_ctx[0] ^= 0xFF;
        res = secp256k1_compact_standard_verify(
            ctx, proof, N, &C1, C2_vec, pks, &PC_m, &pk_A, &PC_b,
            &C1_rem, &C2_rem, fake_ctx);
        EXPECT(res == 0);
    }
    printf("Wrong context: rejected OK.\n");

    /* --- Negative: Tampered C1 --- */
    printf("Testing tampered C1...\n");
    {
        secp256k1_pubkey C1_bad = C1;
        unsigned char tweak[32] = {0};
        tweak[31] = 1;
        EXPECT(secp256k1_ec_pubkey_tweak_add(ctx, &C1_bad, tweak));
        res = secp256k1_compact_standard_verify(
            ctx, proof, N, &C1_bad, C2_vec, pks, &PC_m, &pk_A, &PC_b,
            &C1_rem, &C2_rem, context_id);
        EXPECT(res == 0);
    }
    printf("Tampered C1: rejected OK.\n");

    /* --- Negative: Tampered C2_0 --- */
    printf("Testing tampered C2_0...\n");
    {
        secp256k1_pubkey C2_bad[3];
        memcpy(C2_bad, C2_vec, sizeof(C2_vec));
        unsigned char tweak[32] = {0};
        tweak[31] = 1;
        EXPECT(secp256k1_ec_pubkey_tweak_add(ctx, &C2_bad[0], tweak));
        res = secp256k1_compact_standard_verify(
            ctx, proof, N, &C1, C2_bad, pks, &PC_m, &pk_A, &PC_b,
            &C1_rem, &C2_rem, context_id);
        EXPECT(res == 0);
    }
    printf("Tampered C2_0: rejected OK.\n");

    /* --- Negative: Corrupted proof byte --- */
    printf("Testing corrupted proof...\n");
    {
        unsigned char bad[SECP256K1_COMPACT_STANDARD_PROOF_SIZE];
        memcpy(bad, proof, SECP256K1_COMPACT_STANDARD_PROOF_SIZE);
        bad[SECP256K1_COMPACT_STANDARD_PROOF_SIZE - 1] ^= 0x01;
        res = secp256k1_compact_standard_verify(
            ctx, bad, N, &C1, C2_vec, pks, &PC_m, &pk_A, &PC_b,
            &C1_rem, &C2_rem, context_id);
        EXPECT(res == 0);
    }
    printf("Corrupted proof: rejected OK.\n");

    /* --- Negative: Wrong PC_b (wrong remainder) --- */
    printf("Testing wrong PC_b...\n");
    {
        secp256k1_pubkey PC_b_bad;
        unsigned char bad_rb[32];
        random_scalar(ctx, bad_rb);
        EXPECT(secp256k1_ec_pubkey_create(ctx, &PC_b_bad, bad_rb));
        res = secp256k1_compact_standard_verify(
            ctx, proof, N, &C1, C2_vec, pks, &PC_m, &pk_A, &PC_b_bad,
            &C1_rem, &C2_rem, context_id);
        EXPECT(res == 0);
    }
    printf("Wrong PC_b: rejected OK.\n");

    secp256k1_context_destroy(ctx);
    printf("ALL COMPACT STANDARD SIGMA TESTS PASSED\n");
    return 0;
}
