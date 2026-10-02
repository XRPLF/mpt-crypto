/* Round-trip and negative tests for the AND-composed "both mirrors"
 * key-rotation proofs (both-issuer, both-holder).
 *
 * Relation under test:
 *   pk_anchor     = sk*G
 *   C2 - sk*C1    = b*G
 *   D1_1          = r*G
 *   D2_1          = b*G + r*pk_target1
 *   D1_2         == D1_1              (mandatory, not a sigma conjunct)
 *   D2_2          = b*G + r*pk_target2
 *
 * The D1_2 == D1_1 case is the one this proof exists to test: the review
 * found the holder-anchored analogue specified in prose only, with this
 * exact check stated as something validators "may" perform rather than a
 * mandatory step, so a mismatched D1_2 went undetected. That must be
 * rejected unconditionally, independent of whether the sigma proof itself
 * verifies.
 */
#include "secp256k1_mpt.h"
#include "test_utils.h"
#include <secp256k1.h>
#include <stdio.h>
#include <string.h>

/* Build an EC-ElGamal ciphertext (r*G, b*G + r*pk), skipping b*G when b == 0.
 */
static void make_ct(secp256k1_context const *ctx, secp256k1_pubkey *c1,
                    secp256k1_pubkey *c2, uint64_t b, unsigned char const *r,
                    secp256k1_pubkey const *pk)
{
  EXPECT(secp256k1_ec_pubkey_create(ctx, c1, r));
  secp256k1_pubkey rpk = *pk;
  EXPECT(secp256k1_ec_pubkey_tweak_mul(ctx, &rpk, r));
  secp256k1_pubkey bG;
  if (value_times_g(ctx, &bG, b))
  {
    secp256k1_pubkey const *pts[2] = {&bG, &rpk};
    EXPECT(secp256k1_ec_pubkey_combine(ctx, c2, pts, 2));
  }
  else
  {
    *c2 = rpk;
  }
}

static void run_both_issuer_case(secp256k1_context const *ctx, uint64_t balance,
                                 int negatives)
{
  printf("\n--- both-issuer (balance=%llu) ---\n", (unsigned long long)balance);

  unsigned char sk_I[32], r_old[32], r_new[32], sk_I_new[32], sk_A_new[32];
  unsigned char context_id[32];
  secp256k1_pubkey pk_I, pk_I_new, pk_A_new, E1, E2, E1_new, E2_new, F1_new,
      F2_new;
  unsigned char proof[SECP256K1_ROTATE_BOTH_MIRRORS_PROOF_SIZE];

  random_scalar(ctx, sk_I);
  random_scalar(ctx, r_old);
  random_scalar(ctx, r_new);
  random_scalar(ctx, sk_I_new);
  random_scalar(ctx, sk_A_new);
  random_bytes(context_id);

  EXPECT(secp256k1_ec_pubkey_create(ctx, &pk_I, sk_I));
  EXPECT(secp256k1_ec_pubkey_create(ctx, &pk_I_new, sk_I_new));
  EXPECT(secp256k1_ec_pubkey_create(ctx, &pk_A_new, sk_A_new));

  make_ct(ctx, &E1, &E2, balance, r_old, &pk_I);
  /* Both new ciphertexts share the same first component r_new*G. */
  make_ct(ctx, &E1_new, &E2_new, balance, r_new, &pk_I_new);
  make_ct(ctx, &F1_new, &F2_new, balance, r_new, &pk_A_new);
  EXPECT(secp256k1_ec_pubkey_cmp(ctx, &E1_new, &F1_new) == 0);

  EXPECT(secp256k1_rotate_mirror_both_issuer_prove(
      ctx, proof, balance, sk_I, r_new, &pk_I, &E1, &E2, &pk_I_new, &pk_A_new,
      &E1_new, &E2_new, &F1_new, &F2_new, context_id));
  EXPECT(secp256k1_rotate_mirror_both_issuer_verify(
      ctx, proof, &pk_I, &E1, &E2, &pk_I_new, &pk_A_new, &E1_new, &E2_new,
      &F1_new, &F2_new, context_id));
  printf("  round-trip OK\n");

  if (!negatives)
    return;

  /* The mandatory shared-randomness check: a mismatched F1' must be
   * rejected even though the sigma proof over (E1', E2') alone is honest --
   * this is exactly the gap Finding f:mhaud found in the holder-anchored
   * analogue's original prose spec. */
  {
    unsigned char r_other[32];
    secp256k1_pubkey F1_bad, F2_bad;
    random_scalar(ctx, r_other);
    make_ct(ctx, &F1_bad, &F2_bad, balance, r_other, &pk_A_new);
    EXPECT(secp256k1_ec_pubkey_cmp(ctx, &F1_bad, &E1_new) != 0);
    EXPECT(!secp256k1_rotate_mirror_both_issuer_verify(
        ctx, proof, &pk_I, &E1, &E2, &pk_I_new, &pk_A_new, &E1_new, &E2_new,
        &F1_bad, &F2_bad, context_id));
  }
  printf("  mismatched shared-randomness (F1' != E1') rejected\n");

  /* Each response scalar tampered. */
  for (int off = 0; off < SECP256K1_ROTATE_BOTH_MIRRORS_PROOF_SIZE; off += 32)
  {
    unsigned char bad[SECP256K1_ROTATE_BOTH_MIRRORS_PROOF_SIZE];
    memcpy(bad, proof, sizeof(bad));
    bad[off + 31] ^= 0x01;
    EXPECT(!secp256k1_rotate_mirror_both_issuer_verify(
        ctx, bad, &pk_I, &E1, &E2, &pk_I_new, &pk_A_new, &E1_new, &E2_new,
        &F1_new, &F2_new, context_id));
  }
  printf("  tampered scalars rejected (4/4)\n");

  /* Wrong / absent context id. */
  {
    unsigned char other[32];
    random_bytes(other);
    EXPECT(!secp256k1_rotate_mirror_both_issuer_verify(
        ctx, proof, &pk_I, &E1, &E2, &pk_I_new, &pk_A_new, &E1_new, &E2_new,
        &F1_new, &F2_new, other));
    EXPECT(!secp256k1_rotate_mirror_both_issuer_verify(
        ctx, proof, &pk_I, &E1, &E2, &pk_I_new, &pk_A_new, &E1_new, &E2_new,
        &F1_new, &F2_new, NULL));
  }
  printf("  wrong / absent context_id rejected\n");

  /* A prover claiming a balance it cannot decrypt to must fail. */
  {
    unsigned char bad_proof[SECP256K1_ROTATE_BOTH_MIRRORS_PROOF_SIZE];
    secp256k1_pubkey G1, G2, H1, H2;
    make_ct(ctx, &G1, &G2, balance + 1, r_new, &pk_I_new);
    make_ct(ctx, &H1, &H2, balance + 1, r_new, &pk_A_new);
    if (secp256k1_rotate_mirror_both_issuer_prove(
            ctx, bad_proof, balance + 1, sk_I, r_new, &pk_I, &E1, &E2,
            &pk_I_new, &pk_A_new, &G1, &G2, &H1, &H2, context_id))
    {
      EXPECT(!secp256k1_rotate_mirror_both_issuer_verify(
          ctx, bad_proof, &pk_I, &E1, &E2, &pk_I_new, &pk_A_new, &G1, &G2, &H1,
          &H2, context_id));
    }
  }
  printf("  mismatched balance rejected\n");
}

static void run_both_holder_case(secp256k1_context const *ctx, uint64_t balance,
                                 int negatives)
{
  printf("\n--- both-holder (balance=%llu) ---\n", (unsigned long long)balance);

  unsigned char sk_H[32], r_old[32], r_new[32], sk_I_new[32], sk_A_new[32];
  unsigned char context_id[32];
  secp256k1_pubkey pk_H, pk_I_new, pk_A_new, S1, S2, E1_new, E2_new, F1_new,
      F2_new;
  unsigned char proof[SECP256K1_ROTATE_BOTH_MIRRORS_PROOF_SIZE];

  random_scalar(ctx, sk_H);
  random_scalar(ctx, r_old);
  random_scalar(ctx, r_new);
  random_scalar(ctx, sk_I_new);
  random_scalar(ctx, sk_A_new);
  random_bytes(context_id);

  EXPECT(secp256k1_ec_pubkey_create(ctx, &pk_H, sk_H));
  EXPECT(secp256k1_ec_pubkey_create(ctx, &pk_I_new, sk_I_new));
  EXPECT(secp256k1_ec_pubkey_create(ctx, &pk_A_new, sk_A_new));

  make_ct(ctx, &S1, &S2, balance, r_old, &pk_H);
  make_ct(ctx, &E1_new, &E2_new, balance, r_new, &pk_I_new);
  make_ct(ctx, &F1_new, &F2_new, balance, r_new, &pk_A_new);

  EXPECT(secp256k1_rotate_mirror_both_holder_prove(
      ctx, proof, balance, sk_H, r_new, &pk_H, &S1, &S2, &pk_I_new, &pk_A_new,
      &E1_new, &E2_new, &F1_new, &F2_new, context_id));
  EXPECT(secp256k1_rotate_mirror_both_holder_verify(
      ctx, proof, &pk_H, &S1, &S2, &pk_I_new, &pk_A_new, &E1_new, &E2_new,
      &F1_new, &F2_new, context_id));
  printf("  round-trip OK\n");

  /* Domain separation from both-issuer: same statement shape, different
   * tag. */
  EXPECT(!secp256k1_rotate_mirror_both_issuer_verify(
      ctx, proof, &pk_H, &S1, &S2, &pk_I_new, &pk_A_new, &E1_new, &E2_new,
      &F1_new, &F2_new, context_id));
  printf("  cross-variant substitution rejected\n");

  if (!negatives)
    return;

  /* The exact bug Finding f:mhaud found: a mismatched F1' must be rejected.
   */
  {
    unsigned char r_other[32];
    secp256k1_pubkey F1_bad, F2_bad;
    random_scalar(ctx, r_other);
    make_ct(ctx, &F1_bad, &F2_bad, balance, r_other, &pk_A_new);
    EXPECT(!secp256k1_rotate_mirror_both_holder_verify(
        ctx, proof, &pk_H, &S1, &S2, &pk_I_new, &pk_A_new, &E1_new, &E2_new,
        &F1_bad, &F2_bad, context_id));
  }
  printf("  mismatched shared-randomness (F1' != E1') rejected\n");
}

int main(void)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                    SECP256K1_CONTEXT_VERIFY);
  EXPECT(ctx != NULL);

  printf("=== key rotation: AND-composed both-mirrors proofs ===\n");

  run_both_issuer_case(ctx, 1234567, 1);
  run_both_issuer_case(ctx, 0, 0);
  run_both_issuer_case(ctx, UINT64_MAX, 0);

  run_both_holder_case(ctx, 7654321, 1);
  run_both_holder_case(ctx, 0, 0);

  secp256k1_context_destroy(ctx);
  printf("\nAll both-mirrors tests passed.\n");
  return 0;
}
