#include "secp256k1_mpt.h"
#include "test_utils.h"
#include <secp256k1.h>
#include <stdio.h>
#include <string.h>

/* Exercise the ConvertBack prove/verify path end-to-end for a given balance.
 * When balance == 0, B2 omits the balance*G term (paper convention:
 * libsecp256k1 cannot represent the point at infinity). Runs the full
 * negative-path battery only for the primary case.
 */
static void run_convertback_case(const secp256k1_context *ctx, uint64_t balance,
                                 int run_negative_tests, const char *label)
{
  /* Withdrawal is distinct from balance; the ConvertBack proof only binds
   * balance (via B1/B2/PC_b). We pick a withdrawal just to exercise the
   * auxiliary encryption check when balance > 0. */
  const uint64_t withdrawal = (balance == 0) ? 0 : 250000;

  printf("\n--- %s (balance=%llu) ---\n", label, (unsigned long long)balance);

  unsigned char r_w[32], r_bal[32], sk_A[32], rho[32], context_id[32];
  secp256k1_pubkey pk_A, H;

  random_scalar(ctx, r_w);
  random_scalar(ctx, r_bal);
  random_scalar(ctx, sk_A);
  random_scalar(ctx, rho);
  random_bytes(context_id);

  EXPECT(secp256k1_ec_pubkey_create(ctx, &pk_A, sk_A));
  EXPECT(secp256k1_mpt_get_h_generator(ctx, &H));

  /* Withdrawal ciphertext: C1_w = r_w*G, C2_w = m*G + r_w*P_A
   * (skip m*G when withdrawal = 0). */
  secp256k1_pubkey C1_w, C2_w;
  EXPECT(secp256k1_ec_pubkey_create(ctx, &C1_w, r_w));
  {
    secp256k1_pubkey rwPA = pk_A;
    EXPECT(secp256k1_ec_pubkey_tweak_mul(ctx, &rwPA, r_w));
    secp256k1_pubkey mG;
    if (value_times_g(ctx, &mG, withdrawal))
    {
      const secp256k1_pubkey *pts[2] = {&mG, &rwPA};
      EXPECT(secp256k1_ec_pubkey_combine(ctx, &C2_w, pts, 2));
    }
    else
    {
      C2_w = rwPA;
    }
  }

  /* Skip the deterministic ciphertext sanity check for withdrawal=0
   * (elgamal_verify_encryption's internal handling of m=0 is out of
   * scope for this test). */
  if (withdrawal > 0)
  {
    EXPECT(secp256k1_elgamal_verify_encryption(ctx, &C1_w, &C2_w, &pk_A,
                                               withdrawal, r_w));
  }

  /* On-ledger balance ciphertext: B1 = r_bal*G,
   * B2 = balance*G + r_bal*P_A (skip balance*G when balance = 0). */
  secp256k1_pubkey B1, B2;
  EXPECT(secp256k1_ec_pubkey_create(ctx, &B1, r_bal));
  {
    secp256k1_pubkey rbalPA = pk_A;
    EXPECT(secp256k1_ec_pubkey_tweak_mul(ctx, &rbalPA, r_bal));
    secp256k1_pubkey balG;
    if (value_times_g(ctx, &balG, balance))
    {
      const secp256k1_pubkey *pts[2] = {&balG, &rbalPA};
      EXPECT(secp256k1_ec_pubkey_combine(ctx, &B2, pts, 2));
    }
    else
    {
      B2 = rbalPA;
    }
  }

  /* PC_b = balance*G + rho*H (secp256k1_mpt_pedersen_commit handles
   * balance=0 internally). */
  secp256k1_pubkey PC_b;
  EXPECT(secp256k1_mpt_pedersen_commit(ctx, &PC_b, balance, rho));

  /* Positive case */
  unsigned char proof[SECP256K1_COMPACT_CONVERTBACK_PROOF_SIZE];
  int res = secp256k1_compact_convertback_prove(
      ctx, proof, balance, sk_A, rho, &pk_A, &B1, &B2, &PC_b, context_id);
  EXPECT(res == 1);

  res = secp256k1_compact_convertback_verify(ctx, proof, &pk_A, &B1, &B2, &PC_b,
                                             context_id);
  EXPECT(res == 1);
  printf("  prove + verify OK.\n");

  if (!run_negative_tests)
    return;

  /* Negative: Wrong context */
  {
    unsigned char fake_ctx[32];
    memcpy(fake_ctx, context_id, 32);
    fake_ctx[0] ^= 0xFF;
    res = secp256k1_compact_convertback_verify(ctx, proof, &pk_A, &B1, &B2,
                                               &PC_b, fake_ctx);
    EXPECT(res == 0);
  }

  /* Negative: Corrupted proof byte */
  {
    unsigned char bad[SECP256K1_COMPACT_CONVERTBACK_PROOF_SIZE];
    memcpy(bad, proof, SECP256K1_COMPACT_CONVERTBACK_PROOF_SIZE);
    bad[SECP256K1_COMPACT_CONVERTBACK_PROOF_SIZE - 1] ^= 0x01;
    res = secp256k1_compact_convertback_verify(ctx, bad, &pk_A, &B1, &B2, &PC_b,
                                               context_id);
    EXPECT(res == 0);
  }

  /* Negative: Wrong PC_b */
  {
    secp256k1_pubkey PC_b_bad;
    unsigned char bad_rho[32];
    random_scalar(ctx, bad_rho);
    EXPECT(secp256k1_mpt_pedersen_commit(ctx, &PC_b_bad, balance, bad_rho));
    res = secp256k1_compact_convertback_verify(ctx, proof, &pk_A, &B1, &B2,
                                               &PC_b_bad, context_id);
    EXPECT(res == 0);
  }

  /* Negative: Tampered B2 */
  {
    secp256k1_pubkey B2_bad = B2;
    unsigned char tweak[32] = {0};
    tweak[31] = 1;
    EXPECT(secp256k1_ec_pubkey_tweak_add(ctx, &B2_bad, tweak));
    res = secp256k1_compact_convertback_verify(ctx, proof, &pk_A, &B1, &B2_bad,
                                               &PC_b, context_id);
    EXPECT(res == 0);
  }

  /* Negative: Wrong pk_A */
  {
    unsigned char sk_bad[32];
    secp256k1_pubkey pk_bad;
    random_scalar(ctx, sk_bad);
    EXPECT(secp256k1_ec_pubkey_create(ctx, &pk_bad, sk_bad));
    res = secp256k1_compact_convertback_verify(ctx, proof, &pk_bad, &B1, &B2,
                                               &PC_b, context_id);
    EXPECT(res == 0);
  }

  printf("  negative-path checks OK.\n");
}

int main(void)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                    SECP256K1_CONTEXT_VERIFY);
  EXPECT(ctx != NULL);

  unsigned char seed[32];
  random_bytes(seed);
  EXPECT(secp256k1_context_randomize(ctx, seed));

  printf("=== Running Test: Compact ConvertBack Proof (128 bytes) ===\n");

  /* Primary case. */
  run_convertback_case(ctx, /*balance=*/1000000, /*run_negative_tests=*/1,
                       "primary");

  /* Zero-balance case: exercises the zero-witness path in
   * compute_sigma_response for z_b, and the omitted-balance*G term in
   * B2 and PC_b. Tracks issue #38. */
  run_convertback_case(ctx, /*balance=*/0, /*run_negative_tests=*/0,
                       "zero balance");

  secp256k1_context_destroy(ctx);
  printf("\nALL COMPACT CONVERTBACK TESTS PASSED\n");
  return 0;
}
