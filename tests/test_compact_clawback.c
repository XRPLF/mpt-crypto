#include "secp256k1_mpt.h"
#include "test_utils.h"
#include <secp256k1.h>
#include <stdio.h>
#include <string.h>

/* Encode uint64 as a 32-byte big-endian scalar (local to this test; the
 * helper from PR A's test_utils.h is not yet on this branch). */
static void clawback_uint64_to_scalar32(unsigned char out[32], uint64_t v)
{
  memset(out, 0, 32);
  for (int i = 0; i < 8; i++)
    out[31 - i] = (v >> (i * 8)) & 0xFF;
}

/* Build C1 = r*G, C2 = m*G + r*P_iss (m*G term skipped when m == 0 —
 * libsecp256k1 cannot emit the point at infinity). Runs the full
 * prove/verify flow plus optional negative-path assertions.
 */
static void run_clawback_case(const secp256k1_context *ctx, uint64_t amount,
                              int run_negative_tests, const char *label)
{
  printf("\n--- %s (amount=%llu) ---\n", label, (unsigned long long)amount);

  unsigned char sk_iss[32], r_enc[32], context_id[32];
  secp256k1_pubkey P_iss;

  random_scalar(ctx, sk_iss);
  random_scalar(ctx, r_enc);
  random_bytes(context_id);

  EXPECT(secp256k1_ec_pubkey_create(ctx, &P_iss, sk_iss));

  /* C1 = r*G */
  secp256k1_pubkey C1;
  EXPECT(secp256k1_ec_pubkey_create(ctx, &C1, r_enc));

  /* C2 = r*P_iss (+ m*G if amount > 0) */
  secp256k1_pubkey C2;
  {
    secp256k1_pubkey rP = P_iss;
    EXPECT(secp256k1_ec_pubkey_tweak_mul(ctx, &rP, r_enc));
    if (amount > 0)
    {
      unsigned char m_scalar[32];
      clawback_uint64_to_scalar32(m_scalar, amount);
      secp256k1_pubkey mG;
      EXPECT(secp256k1_ec_pubkey_create(ctx, &mG, m_scalar));
      const secp256k1_pubkey *pts[2] = {&mG, &rP};
      EXPECT(secp256k1_ec_pubkey_combine(ctx, &C2, pts, 2));
    }
    else
    {
      C2 = rP;
    }
  }

  /* Sanity: C2 - m*G == sk_iss*C1 (i.e., r*P_iss == sk_iss*r*G). When
   * amount=0, m*G is infinity so C2 - m*G == C2 and we skip the
   * subtraction. */
  {
    secp256k1_pubkey lhs;
    if (amount == 0)
    {
      lhs = C2;
    }
    else
    {
      unsigned char m_scalar[32];
      clawback_uint64_to_scalar32(m_scalar, amount);
      secp256k1_pubkey mG;
      EXPECT(secp256k1_ec_pubkey_create(ctx, &mG, m_scalar));
      unsigned char neg_one[32];
      unsigned char one[32] = {0};
      one[31] = 1;
      secp256k1_mpt_scalar_negate(neg_one, one);
      secp256k1_pubkey neg_mG = mG;
      EXPECT(secp256k1_ec_pubkey_tweak_mul(ctx, &neg_mG, neg_one));
      const secp256k1_pubkey *sub_pts[2] = {&C2, &neg_mG};
      EXPECT(secp256k1_ec_pubkey_combine(ctx, &lhs, sub_pts, 2));
    }
    secp256k1_pubkey skC1 = C1;
    EXPECT(secp256k1_ec_pubkey_tweak_mul(ctx, &skC1, sk_iss));
    EXPECT(secp256k1_ec_pubkey_cmp(ctx, &lhs, &skC1) == 0);
    printf("  relation OK: C2 - m*G == sk_iss*C1.\n");
  }

  /* Positive case */
  unsigned char proof[SECP256K1_COMPACT_CLAWBACK_PROOF_SIZE];
  int res = secp256k1_compact_clawback_prove(ctx, proof, amount, sk_iss, &P_iss,
                                             &C1, &C2, context_id);
  EXPECT(res == 1);

  res = secp256k1_compact_clawback_verify(ctx, proof, amount, &P_iss, &C1, &C2,
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
    res = secp256k1_compact_clawback_verify(ctx, proof, amount, &P_iss, &C1,
                                            &C2, fake_ctx);
    EXPECT(res == 0);
  }

  /* Negative: Corrupted proof byte */
  {
    unsigned char bad[SECP256K1_COMPACT_CLAWBACK_PROOF_SIZE];
    memcpy(bad, proof, SECP256K1_COMPACT_CLAWBACK_PROOF_SIZE);
    bad[SECP256K1_COMPACT_CLAWBACK_PROOF_SIZE - 1] ^= 0x01;
    res = secp256k1_compact_clawback_verify(ctx, bad, amount, &P_iss, &C1, &C2,
                                            context_id);
    EXPECT(res == 0);
  }

  /* Negative: Wrong amount */
  {
    res = secp256k1_compact_clawback_verify(ctx, proof, amount + 1, &P_iss, &C1,
                                            &C2, context_id);
    EXPECT(res == 0);
  }

  /* Negative: Wrong C1 */
  {
    secp256k1_pubkey C1_bad = C1;
    unsigned char tweak[32] = {0};
    tweak[31] = 1;
    EXPECT(secp256k1_ec_pubkey_tweak_add(ctx, &C1_bad, tweak));
    res = secp256k1_compact_clawback_verify(ctx, proof, amount, &P_iss, &C1_bad,
                                            &C2, context_id);
    EXPECT(res == 0);
  }

  /* Negative: Wrong issuer key */
  {
    unsigned char sk_bad[32];
    secp256k1_pubkey pk_bad;
    random_scalar(ctx, sk_bad);
    EXPECT(secp256k1_ec_pubkey_create(ctx, &pk_bad, sk_bad));
    res = secp256k1_compact_clawback_verify(ctx, proof, amount, &pk_bad, &C1,
                                            &C2, context_id);
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

  printf("=== Running Test: Compact Clawback Proof (64 bytes) ===\n");

  /* Primary case: non-zero amount. Runs full negatives. */
  run_clawback_case(ctx, /*amount=*/500000, /*run_negative_tests=*/1,
                    "primary");

  /* Zero-amount case: exercises the 33-zero-bytes transcript convention and
   * the omitted-m*G paths in prove/verify. Tracks issue #39 and ToB S9/I9.
   * Negatives are enabled: the "wrong amount" negative becomes amount=1,
   * which specifically exercises the transcript-distinguishability boundary
   * between the 33-zero sentinel and a serialized 1*G. */
  run_clawback_case(ctx, /*amount=*/0, /*run_negative_tests=*/1, "zero amount");

  secp256k1_context_destroy(ctx);
  printf("\nALL COMPACT CLAWBACK TESTS PASSED\n");
  return 0;
}
