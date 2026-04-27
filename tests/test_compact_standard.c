#include "secp256k1_mpt.h"
#include "test_utils.h"
#include <secp256k1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Build C1 = r*G, C2_i = r*pk_i + m*G (term skipped when m == 0), PC_m = m*G +
 * r*H (m*G term skipped when m == 0), PC_b = v*G + r_b*H (v*G term skipped when
 * v == 0), B1/B2 from the remainder-ciphertext subtraction. Runs the full
 * prove/verify flow plus optional negative-path assertions.
 */
static void run_compact_standard_case(const secp256k1_context *ctx,
                                      uint64_t amount, uint64_t balance,
                                      int run_negative_tests, const char *label)
{
  EXPECT(balance >= amount);
  const uint64_t remainder = balance - amount;
  const int N = 3;

  printf("\n--- %s (amount=%llu, balance=%llu, remainder=%llu) ---\n", label,
         (unsigned long long)amount, (unsigned long long)balance,
         (unsigned long long)remainder);

  unsigned char r[32], r_bal[32], r_b[32], sk_A[32], context_id[32];
  secp256k1_pubkey pk_A, H;

  random_scalar(ctx, r);
  random_scalar(ctx, r_bal);
  random_scalar(ctx, r_b);
  random_scalar(ctx, sk_A);
  random_bytes(context_id);

  EXPECT(secp256k1_ec_pubkey_create(ctx, &pk_A, sk_A));
  EXPECT(secp256k1_mpt_get_h_generator(ctx, &H));

  /* Recipient keys */
  unsigned char sk_recip[3][32];
  secp256k1_pubkey pks[3];
  for (int i = 0; i < N; i++)
  {
    random_scalar(ctx, sk_recip[i]);
    EXPECT(secp256k1_ec_pubkey_create(ctx, &pks[i], sk_recip[i]));
  }

  /* C1 = r*G */
  secp256k1_pubkey C1;
  EXPECT(secp256k1_ec_pubkey_create(ctx, &C1, r));

  /* m*G, if m > 0 */
  secp256k1_pubkey mG;
  const int has_mG = value_times_g(ctx, &mG, amount);

  /* C2_i = r*pk_i + m*G (skip m*G when amount=0) */
  secp256k1_pubkey C2_vec[3];
  for (int i = 0; i < N; i++)
  {
    secp256k1_pubkey rPk = pks[i];
    EXPECT(secp256k1_ec_pubkey_tweak_mul(ctx, &rPk, r));
    if (has_mG)
    {
      const secp256k1_pubkey *pts[2] = {&rPk, &mG};
      EXPECT(secp256k1_ec_pubkey_combine(ctx, &C2_vec[i], pts, 2));
    }
    else
    {
      C2_vec[i] = rPk;
    }
  }

  /* PC_m = m*G + r*H (skip m*G when amount=0) */
  secp256k1_pubkey PC_m;
  {
    secp256k1_pubkey rH = H;
    EXPECT(secp256k1_ec_pubkey_tweak_mul(ctx, &rH, r));
    if (has_mG)
    {
      const secp256k1_pubkey *pts[2] = {&mG, &rH};
      EXPECT(secp256k1_ec_pubkey_combine(ctx, &PC_m, pts, 2));
    }
    else
    {
      PC_m = rH;
    }
  }

  /* PC_b = v*G + r_b*H (skip v*G when remainder=0) */
  secp256k1_pubkey PC_b;
  {
    secp256k1_pubkey vG;
    const int has_vG = value_times_g(ctx, &vG, remainder);
    secp256k1_pubkey rbH = H;
    EXPECT(secp256k1_ec_pubkey_tweak_mul(ctx, &rbH, r_b));
    if (has_vG)
    {
      const secp256k1_pubkey *pts[2] = {&vG, &rbH};
      EXPECT(secp256k1_ec_pubkey_combine(ctx, &PC_b, pts, 2));
    }
    else
    {
      PC_b = rbH;
    }
  }

  /* r_diff = r_bal - r (mod n); must be non-zero so B1 is a valid point. */
  unsigned char r_diff[32];
  {
    unsigned char neg_r[32];
    secp256k1_mpt_scalar_negate(neg_r, r);
    secp256k1_mpt_scalar_add(r_diff, r_bal, neg_r);
    secp256k1_mpt_scalar_reduce32(r_diff, r_diff);
    EXPECT(secp256k1_ec_seckey_verify(ctx, r_diff));
  }

  /* B1 = r_diff*G */
  secp256k1_pubkey B1;
  EXPECT(secp256k1_ec_pubkey_create(ctx, &B1, r_diff));

  /* B2 = r_diff*pk_A + v*G (skip v*G when remainder=0) */
  secp256k1_pubkey B2;
  {
    secp256k1_pubkey rdPk = pk_A;
    EXPECT(secp256k1_ec_pubkey_tweak_mul(ctx, &rdPk, r_diff));
    secp256k1_pubkey vG;
    const int has_vG = value_times_g(ctx, &vG, remainder);
    if (has_vG)
    {
      const secp256k1_pubkey *pts[2] = {&rdPk, &vG};
      EXPECT(secp256k1_ec_pubkey_combine(ctx, &B2, pts, 2));
    }
    else
    {
      B2 = rdPk;
    }
  }

  /* Sanity: Variant B relation holds: sk_A*B1 + v*G == B2 (v*G skipped when 0).
   */
  {
    secp256k1_pubkey skB1 = B1, check;
    EXPECT(secp256k1_ec_pubkey_tweak_mul(ctx, &skB1, sk_A));
    secp256k1_pubkey vG;
    const int has_vG = value_times_g(ctx, &vG, remainder);
    if (has_vG)
    {
      const secp256k1_pubkey *pts[2] = {&skB1, &vG};
      EXPECT(secp256k1_ec_pubkey_combine(ctx, &check, pts, 2));
    }
    else
    {
      check = skB1;
    }
    EXPECT(secp256k1_ec_pubkey_cmp(ctx, &check, &B2) == 0);
  }

  /* Positive case */
  unsigned char proof[SECP256K1_COMPACT_STANDARD_PROOF_SIZE];
  int res = secp256k1_compact_standard_prove(
      ctx, proof, amount, remainder, r, sk_A, r_b, N, &C1, C2_vec, pks, &PC_m,
      &pk_A, &PC_b, &B1, &B2, context_id);
  EXPECT(res == 1);

  res =
      secp256k1_compact_standard_verify(ctx, proof, N, &C1, C2_vec, pks, &PC_m,
                                        &pk_A, &PC_b, &B1, &B2, context_id);
  EXPECT(res == 1);
  printf("  prove + verify OK.\n");

  if (!run_negative_tests)
    return;

  /* Negative: Wrong context */
  {
    unsigned char fake_ctx[32];
    memcpy(fake_ctx, context_id, 32);
    fake_ctx[0] ^= 0xFF;
    res = secp256k1_compact_standard_verify(ctx, proof, N, &C1, C2_vec, pks,
                                            &PC_m, &pk_A, &PC_b, &B1, &B2,
                                            fake_ctx);
    EXPECT(res == 0);
  }

  /* Negative: Tampered C1 */
  {
    secp256k1_pubkey C1_bad = C1;
    unsigned char tweak[32] = {0};
    tweak[31] = 1;
    EXPECT(secp256k1_ec_pubkey_tweak_add(ctx, &C1_bad, tweak));
    res = secp256k1_compact_standard_verify(ctx, proof, N, &C1_bad, C2_vec, pks,
                                            &PC_m, &pk_A, &PC_b, &B1, &B2,
                                            context_id);
    EXPECT(res == 0);
  }

  /* Negative: Tampered C2_0 */
  {
    secp256k1_pubkey C2_bad[3];
    memcpy(C2_bad, C2_vec, sizeof(C2_vec));
    unsigned char tweak[32] = {0};
    tweak[31] = 1;
    EXPECT(secp256k1_ec_pubkey_tweak_add(ctx, &C2_bad[0], tweak));
    res = secp256k1_compact_standard_verify(ctx, proof, N, &C1, C2_bad, pks,
                                            &PC_m, &pk_A, &PC_b, &B1, &B2,
                                            context_id);
    EXPECT(res == 0);
  }

  /* Negative: Corrupted proof byte */
  {
    unsigned char bad[SECP256K1_COMPACT_STANDARD_PROOF_SIZE];
    memcpy(bad, proof, SECP256K1_COMPACT_STANDARD_PROOF_SIZE);
    bad[SECP256K1_COMPACT_STANDARD_PROOF_SIZE - 1] ^= 0x01;
    res =
        secp256k1_compact_standard_verify(ctx, bad, N, &C1, C2_vec, pks, &PC_m,
                                          &pk_A, &PC_b, &B1, &B2, context_id);
    EXPECT(res == 0);
  }

  /* Negative: Wrong PC_b */
  {
    secp256k1_pubkey PC_b_bad;
    unsigned char bad_rb[32];
    random_scalar(ctx, bad_rb);
    EXPECT(secp256k1_ec_pubkey_create(ctx, &PC_b_bad, bad_rb));
    res = secp256k1_compact_standard_verify(ctx, proof, N, &C1, C2_vec, pks,
                                            &PC_m, &pk_A, &PC_b_bad, &B1, &B2,
                                            context_id);
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

  printf(
      "=== Running Test: Compact AND-Composed Standard EC-ElGamal Proof ===\n");

  /* Primary case: non-zero amount, non-zero remainder. Runs full negatives. */
  run_compact_standard_case(ctx, /*amount=*/123456, /*balance=*/1000000,
                            /*run_negative_tests=*/1, "primary");

  /* Zero-amount case (m = 0): exercises the zero-witness path in
   * compute_sigma_response for z_m, and the omitted-G-term path for
   * C2_i / PC_m. Tracks issue #38. */
  run_compact_standard_case(ctx, /*amount=*/0, /*balance=*/1000000,
                            /*run_negative_tests=*/0, "zero amount");

  /* Zero-remainder case (v = 0, i.e. amount == balance): exercises the
   * zero-witness path in compute_sigma_response for z_b, and the omitted-G
   * -term path for PC_b / B2. */
  run_compact_standard_case(ctx, /*amount=*/1000000, /*balance=*/1000000,
                            /*run_negative_tests=*/0, "zero remainder");

  secp256k1_context_destroy(ctx);
  printf("\nALL COMPACT STANDARD SIGMA TESTS PASSED\n");
  return 0;
}
