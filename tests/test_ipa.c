#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <secp256k1.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "secp256k1_mpt.h"

#define N_BITS 64
#define IPA_ROUNDS 6

/* ---- Forward declarations from your code ---- */

int secp256k1_bulletproof_run_ipa_prover(
        const secp256k1_context* ctx,
        const secp256k1_pubkey* U,
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
);

int derive_ipa_round_challenge(
        const secp256k1_context* ctx,
        unsigned char u_out[32],
        const unsigned char last_challenge[32],
        const secp256k1_pubkey* L,
        const secp256k1_pubkey* R
);

int fold_generators(
        const secp256k1_context* ctx,
        secp256k1_pubkey* final_point,
        const secp256k1_pubkey* generators,
        const unsigned char u[IPA_ROUNDS][32],
        const unsigned char u_inv[IPA_ROUNDS][32],
        int n,
        int is_H
);

int apply_ipa_folding_to_P(
        const secp256k1_context* ctx,
        secp256k1_pubkey* P,
        const secp256k1_pubkey* L_vec,
        const secp256k1_pubkey* R_vec,
        const unsigned char u[IPA_ROUNDS][32],
        const unsigned char u_inv[IPA_ROUNDS][32]
);

int secp256k1_bulletproof_ipa_dot(
        const secp256k1_context* ctx,
        unsigned char* out,
        const unsigned char* a,
        const unsigned char* b,
        size_t n
);

extern int secp256k1_mpt_get_generator_vector(
        const secp256k1_context* ctx,
        secp256k1_pubkey* vec,
        size_t n,
        const unsigned char* label,
        size_t label_len
);

/* ---- Helpers ---- */

static void random_scalar(const secp256k1_context* ctx, unsigned char s[32]) {
    do { RAND_bytes(s, 32); }
    while (!secp256k1_ec_seckey_verify(ctx, s)); /* rejects 0 and >= order */
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
static void print_pubkey(
        const secp256k1_context* ctx,
        const char* label,
        const secp256k1_pubkey* pk
) {
    unsigned char ser[33];
    size_t len = 33;

    if (!secp256k1_ec_pubkey_serialize(
            ctx, ser, &len, pk, SECP256K1_EC_COMPRESSED)) {
        printf("%s: <serialize failed>\n", label);
        return;
    }

    printf("%s = ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", ser[i]);
    }
    printf("\n");
}


int main(void) {
    secp256k1_context* ctx =
            secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    printf("[IPA TEST] Prove + Verify\n");

    /* ------------------------------------------------------------ */
    /* 1. Generators                                                */
    /* ------------------------------------------------------------ */
    secp256k1_pubkey G[N_BITS], H[N_BITS], U;
    assert(secp256k1_mpt_get_generator_vector(ctx, G, N_BITS, (unsigned char*)"G", 1));
    assert(secp256k1_mpt_get_generator_vector(ctx, H, N_BITS, (unsigned char*)"H", 1));
    assert(secp256k1_mpt_get_generator_vector(ctx, &U, 1, (unsigned char*)"BP_U", 4));

    /* Keep originals for verifier */
    secp256k1_pubkey G0[N_BITS], H0[N_BITS];
    memcpy(G0, G, sizeof(G0));
    memcpy(H0, H, sizeof(H0));

    /* ------------------------------------------------------------ */
    /* 2. Random witness vectors                                    */
    /* ------------------------------------------------------------ */
    unsigned char a[N_BITS][32], b[N_BITS][32];
    for (int i = 0; i < N_BITS; i++) {
        random_scalar(ctx, a[i]);
        random_scalar(ctx, b[i]);
    }

    /* ------------------------------------------------------------ */
    /* 3. dot = <a,b>                                               */
    /* ------------------------------------------------------------ */
    unsigned char dot[32];
    assert(secp256k1_bulletproof_ipa_dot(
            ctx, dot, (unsigned char*)a, (unsigned char*)b, N_BITS));

    /* ------------------------------------------------------------ */
    /* 4. Transcript + ux                                           */
    /* ------------------------------------------------------------ */
    unsigned char ipa_transcript_id[32];
    SHA256((unsigned char*)"IPA_TEST", 8, ipa_transcript_id);

    unsigned char ux[32];
    {
        SHA256_CTX sha;
        SHA256_Init(&sha);
        SHA256_Update(&sha, ipa_transcript_id, 32);
        SHA256_Update(&sha, dot, 32);
        SHA256_Final(ux, &sha);
        assert(secp256k1_ec_seckey_verify(ctx, ux));
    }

    /* ------------------------------------------------------------ */
    /* 5. Build commitment P                                       */
    /* ------------------------------------------------------------ */
    secp256k1_pubkey P, tmp;
    int P_inited = 0;

    for (int i = 0; i < N_BITS; i++) {
        if (!scalar_is_zero(a[i])) {
            tmp = G0[i];
            secp256k1_ec_pubkey_tweak_mul(ctx, &tmp, a[i]);
            add_term(ctx, &P, &P_inited, &tmp);
        }
        if (!scalar_is_zero(b[i])) {
            tmp = H0[i];
            secp256k1_ec_pubkey_tweak_mul(ctx, &tmp, b[i]);
            add_term(ctx, &P, &P_inited, &tmp);
        }
    }

    unsigned char dot_ux[32];
    secp256k1_mpt_scalar_mul(dot_ux, dot, ux);
    if (!scalar_is_zero(dot_ux)) {
        tmp = U;
        secp256k1_ec_pubkey_tweak_mul(ctx, &tmp, dot_ux);
        add_term(ctx, &P, &P_inited, &tmp);
    }

    assert(P_inited);

    /* ------------------------------------------------------------ */
    /* 6. Prover: generate IPA proof                                */
    /* ------------------------------------------------------------ */
    secp256k1_pubkey L[IPA_ROUNDS], R[IPA_ROUNDS];
    unsigned char a_final[32], b_final[32];

    assert(secp256k1_bulletproof_run_ipa_prover(
            ctx,
            &U,
            G, H,
            (unsigned char*)a,
            (unsigned char*)b,
            N_BITS,
            ipa_transcript_id,
            ux,
            L, R,
            a_final, b_final
    ));

    /* ------------------------------------------------------------ */
    /* 7. Verifier: call verification function                      */
    /* ------------------------------------------------------------ */


    int ok = ipa_verify_explicit(
            ctx,
            G0, H0,
            &U,
            &P,          /* IMPORTANT: unfolded P */
            L, R,
            a_final, b_final,
            ux,
            ipa_transcript_id
    );

    printf("[IPA TEST] verification: %s\n", ok ? "PASSED" : "FAILED");
    assert(ok);

    secp256k1_context_destroy(ctx);
    return 0;
}
