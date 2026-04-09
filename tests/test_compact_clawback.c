#include "secp256k1_mpt.h"
#include "test_utils.h"
#include <secp256k1.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                    SECP256K1_CONTEXT_VERIFY);
  EXPECT(ctx != NULL);

  unsigned char seed[32];
  random_bytes(seed);
  EXPECT(secp256k1_context_randomize(ctx, seed));

  printf("=== Running Test: Compact Clawback Proof (64 bytes) ===\n");

  uint64_t amount = 500000;

  unsigned char sk_iss[32], r_enc[32], context_id[32];
  secp256k1_pubkey P_iss;

  random_scalar(ctx, sk_iss);
  random_scalar(ctx, r_enc);
  random_scalar(ctx, context_id);

  EXPECT(secp256k1_ec_pubkey_create(ctx, &P_iss, sk_iss));

  /* Issuer-mirror ciphertext: C1 = r*G, C2 = m*G + r*P_iss */
  secp256k1_pubkey C1, C2;
  EXPECT(secp256k1_ec_pubkey_create(ctx, &C1, r_enc));
  {
    unsigned char m_scalar[32] = {0};
    for (int b = 0; b < 8; b++)
      m_scalar[31 - b] = (amount >> (b * 8)) & 0xFF;
    secp256k1_pubkey mG, rP;
    EXPECT(secp256k1_ec_pubkey_create(ctx, &mG, m_scalar));
    rP = P_iss;
    EXPECT(secp256k1_ec_pubkey_tweak_mul(ctx, &rP, r_enc));
    const secp256k1_pubkey *pts[2] = {&mG, &rP};
    EXPECT(secp256k1_ec_pubkey_combine(ctx, &C2, pts, 2));
  }

  /* Verify relation: C2 - m*G = sk_iss*C1 (i.e., r*P_iss = sk_iss*r*G) */
  {
    unsigned char m_scalar[32] = {0};
    for (int b = 0; b < 8; b++)
      m_scalar[31 - b] = (amount >> (b * 8)) & 0xFF;
    secp256k1_pubkey mG;
    EXPECT(secp256k1_ec_pubkey_create(ctx, &mG, m_scalar));
    unsigned char neg_one[32];
    unsigned char one[32] = {0};
    one[31] = 1;
    secp256k1_mpt_scalar_negate(neg_one, one);
    secp256k1_pubkey neg_mG = mG;
    EXPECT(secp256k1_ec_pubkey_tweak_mul(ctx, &neg_mG, neg_one));
    secp256k1_pubkey lhs;
    const secp256k1_pubkey *sub_pts[2] = {&C2, &neg_mG};
    EXPECT(secp256k1_ec_pubkey_combine(ctx, &lhs, sub_pts, 2));
    secp256k1_pubkey skC1 = C1;
    EXPECT(secp256k1_ec_pubkey_tweak_mul(ctx, &skC1, sk_iss));
    EXPECT(secp256k1_ec_pubkey_cmp(ctx, &lhs, &skC1) == 0);
    printf("Clawback relation verified: C2 - m*G == sk_iss*C1.\n");
  }

  /* --- Positive Case --- */
  printf("Generating compact clawback proof...\n");

  unsigned char proof[SECP256K1_COMPACT_CLAWBACK_PROOF_SIZE];
  int res = secp256k1_compact_clawback_prove(ctx, proof, amount, sk_iss, &P_iss,
                                             &C1, &C2, context_id);
  EXPECT(res == 1);
  printf("Proof generated: %d bytes.\n", SECP256K1_COMPACT_CLAWBACK_PROOF_SIZE);

  res = secp256k1_compact_clawback_verify(ctx, proof, amount, &P_iss, &C1, &C2,
                                          context_id);
  EXPECT(res == 1);
  printf("Proof verified successfully.\n");

  /* --- Negative: Wrong context --- */
  printf("Testing wrong context...\n");
  {
    unsigned char fake_ctx[32];
    memcpy(fake_ctx, context_id, 32);
    fake_ctx[0] ^= 0xFF;
    res = secp256k1_compact_clawback_verify(ctx, proof, amount, &P_iss, &C1,
                                            &C2, fake_ctx);
    EXPECT(res == 0);
  }
  printf("Wrong context: rejected OK.\n");

  /* --- Negative: Corrupted proof byte --- */
  printf("Testing corrupted proof...\n");
  {
    unsigned char bad[SECP256K1_COMPACT_CLAWBACK_PROOF_SIZE];
    memcpy(bad, proof, SECP256K1_COMPACT_CLAWBACK_PROOF_SIZE);
    bad[SECP256K1_COMPACT_CLAWBACK_PROOF_SIZE - 1] ^= 0x01;
    res = secp256k1_compact_clawback_verify(ctx, bad, amount, &P_iss, &C1, &C2,
                                            context_id);
    EXPECT(res == 0);
  }
  printf("Corrupted proof: rejected OK.\n");

  /* --- Negative: Wrong amount --- */
  printf("Testing wrong amount...\n");
  {
    res = secp256k1_compact_clawback_verify(ctx, proof, amount + 1, &P_iss, &C1,
                                            &C2, context_id);
    EXPECT(res == 0);
  }
  printf("Wrong amount: rejected OK.\n");

  /* --- Negative: Wrong C1 (tampered ciphertext) --- */
  printf("Testing tampered C1...\n");
  {
    secp256k1_pubkey C1_bad = C1;
    unsigned char tweak[32] = {0};
    tweak[31] = 1;
    EXPECT(secp256k1_ec_pubkey_tweak_add(ctx, &C1_bad, tweak));
    res = secp256k1_compact_clawback_verify(ctx, proof, amount, &P_iss, &C1_bad,
                                            &C2, context_id);
    EXPECT(res == 0);
  }
  printf("Tampered C1: rejected OK.\n");

  /* --- Negative: Wrong issuer key --- */
  printf("Testing wrong issuer key...\n");
  {
    unsigned char sk_bad[32];
    secp256k1_pubkey pk_bad;
    random_scalar(ctx, sk_bad);
    EXPECT(secp256k1_ec_pubkey_create(ctx, &pk_bad, sk_bad));
    res = secp256k1_compact_clawback_verify(ctx, proof, amount, &pk_bad, &C1,
                                            &C2, context_id);
    EXPECT(res == 0);
  }
  printf("Wrong issuer key: rejected OK.\n");

  secp256k1_context_destroy(ctx);
  printf("ALL COMPACT CLAWBACK TESTS PASSED\n");
  return 0;
}
