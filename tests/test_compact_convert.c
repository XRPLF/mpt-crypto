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

  printf("=== Running Test: Compact Convert/Clawback Proof ===\n");

  uint64_t amount = 500000;

  unsigned char r[32], sk_A[32], context_id[32];
  secp256k1_pubkey pk_A;

  random_scalar(ctx, r);
  random_scalar(ctx, sk_A);
  random_scalar(ctx, context_id);

  EXPECT(secp256k1_ec_pubkey_create(ctx, &pk_A, sk_A));

  /* Standard EG ciphertext: C1 = r*G, C2 = m*G + r*P_A */
  secp256k1_pubkey C1, C2;

  EXPECT(secp256k1_ec_pubkey_create(ctx, &C1, r));

  {
    unsigned char m_scalar[32] = {0};
    for (int b = 0; b < 8; b++)
      m_scalar[31 - b] = (amount >> (b * 8)) & 0xFF;
    secp256k1_pubkey mG, rPA;
    EXPECT(secp256k1_ec_pubkey_create(ctx, &mG, m_scalar));
    rPA = pk_A;
    EXPECT(secp256k1_ec_pubkey_tweak_mul(ctx, &rPA, r));
    const secp256k1_pubkey *pts[2] = {&mG, &rPA};
    EXPECT(secp256k1_ec_pubkey_combine(ctx, &C2, pts, 2));
  }

  /* --- Positive Case --- */
  printf("Generating compact convert proof...\n");

  unsigned char proof[SECP256K1_COMPACT_CONVERT_PROOF_SIZE];
  int res = secp256k1_compact_convert_prove(ctx, proof, amount, r, &C1, &C2,
                                            &pk_A, context_id);
  EXPECT(res == 1);
  printf("Proof generated: %d bytes.\n", SECP256K1_COMPACT_CONVERT_PROOF_SIZE);

  res = secp256k1_compact_convert_verify(ctx, proof, amount, &C1, &C2, &pk_A,
                                         context_id);
  EXPECT(res == 1);
  printf("Proof verified successfully.\n");

  /* --- Negative: Wrong context --- */
  printf("Testing wrong context...\n");
  {
    unsigned char fake_ctx[32];
    memcpy(fake_ctx, context_id, 32);
    fake_ctx[0] ^= 0xFF;
    res = secp256k1_compact_convert_verify(ctx, proof, amount, &C1, &C2, &pk_A,
                                           fake_ctx);
    EXPECT(res == 0);
  }
  printf("Wrong context: rejected OK.\n");

  /* --- Negative: Wrong amount --- */
  printf("Testing wrong amount...\n");
  {
    res = secp256k1_compact_convert_verify(ctx, proof, amount + 1, &C1, &C2,
                                           &pk_A, context_id);
    EXPECT(res == 0);
  }
  printf("Wrong amount: rejected OK.\n");

  /* --- Negative: Tampered C1 --- */
  printf("Testing tampered C1...\n");
  {
    secp256k1_pubkey C1_bad = C1;
    unsigned char tweak[32] = {0};
    tweak[31] = 1;
    EXPECT(secp256k1_ec_pubkey_tweak_add(ctx, &C1_bad, tweak));
    res = secp256k1_compact_convert_verify(ctx, proof, amount, &C1_bad, &C2,
                                           &pk_A, context_id);
    EXPECT(res == 0);
  }
  printf("Tampered C1: rejected OK.\n");

  /* --- Negative: Corrupted proof byte --- */
  printf("Testing corrupted proof...\n");
  {
    unsigned char bad[SECP256K1_COMPACT_CONVERT_PROOF_SIZE];
    memcpy(bad, proof, SECP256K1_COMPACT_CONVERT_PROOF_SIZE);
    bad[SECP256K1_COMPACT_CONVERT_PROOF_SIZE - 1] ^= 0x01;
    res = secp256k1_compact_convert_verify(ctx, bad, amount, &C1, &C2, &pk_A,
                                           context_id);
    EXPECT(res == 0);
  }
  printf("Corrupted proof: rejected OK.\n");

  /* --- Negative: Wrong pk_A --- */
  printf("Testing wrong pk_A...\n");
  {
    unsigned char sk_bad[32];
    secp256k1_pubkey pk_bad;
    random_scalar(ctx, sk_bad);
    EXPECT(secp256k1_ec_pubkey_create(ctx, &pk_bad, sk_bad));
    res = secp256k1_compact_convert_verify(ctx, proof, amount, &C1, &C2,
                                           &pk_bad, context_id);
    EXPECT(res == 0);
  }
  printf("Wrong pk_A: rejected OK.\n");

  secp256k1_context_destroy(ctx);
  printf("ALL COMPACT CONVERT TESTS PASSED\n");
  return 0;
}
