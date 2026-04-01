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

  printf("=== Running Test: Compact ConvertBack Proof ===\n");

  uint64_t balance = 1000000;
  uint64_t withdrawal = 250000;

  unsigned char r_w[32], r_bal[32], sk_A[32], rho[32], context_id[32];
  secp256k1_pubkey pk_A, H;

  random_scalar(ctx, r_w);
  random_scalar(ctx, r_bal);
  random_scalar(ctx, sk_A);
  random_scalar(ctx, rho);
  random_scalar(ctx, context_id);

  EXPECT(secp256k1_ec_pubkey_create(ctx, &pk_A, sk_A));
  EXPECT(secp256k1_mpt_get_h_generator(ctx, &H));

  /* Withdrawal ciphertext: C1_w = r_w*G, C2_w = m*G + r_w*P_A */
  secp256k1_pubkey C1_w, C2_w;
  EXPECT(secp256k1_ec_pubkey_create(ctx, &C1_w, r_w));
  {
    unsigned char m_scalar[32] = {0};
    for (int b = 0; b < 8; b++)
      m_scalar[31 - b] = (withdrawal >> (b * 8)) & 0xFF;
    secp256k1_pubkey mG, rwPA;
    EXPECT(secp256k1_ec_pubkey_create(ctx, &mG, m_scalar));
    rwPA = pk_A;
    EXPECT(secp256k1_ec_pubkey_tweak_mul(ctx, &rwPA, r_w));
    const secp256k1_pubkey *pts[2] = {&mG, &rwPA};
    EXPECT(secp256k1_ec_pubkey_combine(ctx, &C2_w, pts, 2));
  }

  /* On-ledger balance ciphertext: B1 = r_bal*G, B2 = balance*G + r_bal*P_A */
  secp256k1_pubkey B1, B2;
  EXPECT(secp256k1_ec_pubkey_create(ctx, &B1, r_bal));
  {
    unsigned char bal_scalar[32] = {0};
    for (int b = 0; b < 8; b++)
      bal_scalar[31 - b] = (balance >> (b * 8)) & 0xFF;
    secp256k1_pubkey balG, rbalPA;
    EXPECT(secp256k1_ec_pubkey_create(ctx, &balG, bal_scalar));
    rbalPA = pk_A;
    EXPECT(secp256k1_ec_pubkey_tweak_mul(ctx, &rbalPA, r_bal));
    const secp256k1_pubkey *pts[2] = {&balG, &rbalPA};
    EXPECT(secp256k1_ec_pubkey_combine(ctx, &B2, pts, 2));
  }

  /* PC_b = balance*G + rho*H */
  secp256k1_pubkey PC_b;
  EXPECT(secp256k1_mpt_pedersen_commit(ctx, &PC_b, balance, rho));

  /* Verify relation: B2 - balance*G = sk_A*B1 */
  {
    unsigned char bal_scalar[32] = {0};
    for (int b = 0; b < 8; b++)
      bal_scalar[31 - b] = (balance >> (b * 8)) & 0xFF;
    secp256k1_pubkey balG, skB1;
    EXPECT(secp256k1_ec_pubkey_create(ctx, &balG, bal_scalar));
    /* B2 - balance*G */
    unsigned char neg_one[32];
    unsigned char one[32] = {0};
    one[31] = 1;
    secp256k1_mpt_scalar_negate(neg_one, one);
    secp256k1_pubkey neg_balG = balG;
    EXPECT(secp256k1_ec_pubkey_tweak_mul(ctx, &neg_balG, neg_one));
    secp256k1_pubkey lhs;
    const secp256k1_pubkey *sub_pts[2] = {&B2, &neg_balG};
    EXPECT(secp256k1_ec_pubkey_combine(ctx, &lhs, sub_pts, 2));
    /* sk_A*B1 */
    skB1 = B1;
    EXPECT(secp256k1_ec_pubkey_tweak_mul(ctx, &skB1, sk_A));
    EXPECT(secp256k1_ec_pubkey_cmp(ctx, &lhs, &skB1) == 0);
    printf("Balance decryption relation verified.\n");
  }

  /* --- Positive Case --- */
  printf("Generating compact convertback proof...\n");

  unsigned char proof[SECP256K1_COMPACT_CONVERTBACK_PROOF_SIZE];
  int res = secp256k1_compact_convertback_prove(
      ctx, proof, withdrawal, balance, r_w, sk_A, rho, &C1_w, &C2_w, &pk_A, &B1,
      &B2, &PC_b, context_id);
  EXPECT(res == 1);
  printf("Proof generated: %d bytes.\n",
         SECP256K1_COMPACT_CONVERTBACK_PROOF_SIZE);

  res = secp256k1_compact_convertback_verify(
      ctx, proof, withdrawal, &C1_w, &C2_w, &pk_A, &B1, &B2, &PC_b, context_id);
  EXPECT(res == 1);
  printf("Proof verified successfully.\n");

  /* --- Negative: Wrong context --- */
  printf("Testing wrong context...\n");
  {
    unsigned char fake_ctx[32];
    memcpy(fake_ctx, context_id, 32);
    fake_ctx[0] ^= 0xFF;
    res = secp256k1_compact_convertback_verify(
        ctx, proof, withdrawal, &C1_w, &C2_w, &pk_A, &B1, &B2, &PC_b, fake_ctx);
    EXPECT(res == 0);
  }
  printf("Wrong context: rejected OK.\n");

  /* --- Negative: Wrong withdrawal amount --- */
  printf("Testing wrong withdrawal amount...\n");
  {
    res = secp256k1_compact_convertback_verify(ctx, proof, withdrawal + 1,
                                               &C1_w, &C2_w, &pk_A, &B1, &B2,
                                               &PC_b, context_id);
    EXPECT(res == 0);
  }
  printf("Wrong withdrawal amount: rejected OK.\n");

  /* --- Negative: Tampered C1_w --- */
  printf("Testing tampered C1_w...\n");
  {
    secp256k1_pubkey C1w_bad = C1_w;
    unsigned char tweak[32] = {0};
    tweak[31] = 1;
    EXPECT(secp256k1_ec_pubkey_tweak_add(ctx, &C1w_bad, tweak));
    res = secp256k1_compact_convertback_verify(ctx, proof, withdrawal, &C1w_bad,
                                               &C2_w, &pk_A, &B1, &B2, &PC_b,
                                               context_id);
    EXPECT(res == 0);
  }
  printf("Tampered C1_w: rejected OK.\n");

  /* --- Negative: Corrupted proof byte --- */
  printf("Testing corrupted proof...\n");
  {
    unsigned char bad[SECP256K1_COMPACT_CONVERTBACK_PROOF_SIZE];
    memcpy(bad, proof, SECP256K1_COMPACT_CONVERTBACK_PROOF_SIZE);
    bad[SECP256K1_COMPACT_CONVERTBACK_PROOF_SIZE - 1] ^= 0x01;
    res = secp256k1_compact_convertback_verify(
        ctx, bad, withdrawal, &C1_w, &C2_w, &pk_A, &B1, &B2, &PC_b, context_id);
    EXPECT(res == 0);
  }
  printf("Corrupted proof: rejected OK.\n");

  /* --- Negative: Wrong PC_b --- */
  printf("Testing wrong PC_b...\n");
  {
    secp256k1_pubkey PC_b_bad;
    unsigned char bad_rho[32];
    random_scalar(ctx, bad_rho);
    EXPECT(secp256k1_mpt_pedersen_commit(ctx, &PC_b_bad, balance, bad_rho));
    res = secp256k1_compact_convertback_verify(ctx, proof, withdrawal, &C1_w,
                                               &C2_w, &pk_A, &B1, &B2,
                                               &PC_b_bad, context_id);
    EXPECT(res == 0);
  }
  printf("Wrong PC_b: rejected OK.\n");

  /* --- Negative: Wrong B2 (tampered balance ciphertext) --- */
  printf("Testing tampered B2...\n");
  {
    secp256k1_pubkey B2_bad = B2;
    unsigned char tweak[32] = {0};
    tweak[31] = 1;
    EXPECT(secp256k1_ec_pubkey_tweak_add(ctx, &B2_bad, tweak));
    res = secp256k1_compact_convertback_verify(ctx, proof, withdrawal, &C1_w,
                                               &C2_w, &pk_A, &B1, &B2_bad,
                                               &PC_b, context_id);
    EXPECT(res == 0);
  }
  printf("Tampered B2: rejected OK.\n");

  secp256k1_context_destroy(ctx);
  printf("ALL COMPACT CONVERTBACK TESTS PASSED\n");
  return 0;
}
