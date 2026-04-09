#include "secp256k1_mpt.h"
#include "test_utils.h"
#include <secp256k1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void test_pok_sk(void)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                    SECP256K1_CONTEXT_VERIFY);
  EXPECT(ctx != NULL);

  unsigned char sk[32], context_id[32];
  unsigned char proof[SECP256K1_POK_SK_PROOF_SIZE];
  secp256k1_pubkey pk;

  printf("=== Running Test: Compact PoK SK Registration (64 bytes) ===\n");

  random_scalar(ctx, sk);
  EXPECT(secp256k1_ec_pubkey_create(ctx, &pk, sk));
  random_bytes(context_id);

  /* --- Positive Case --- */
  EXPECT(secp256k1_mpt_pok_sk_prove(ctx, proof, &pk, sk, context_id) == 1);
  printf("Proof generated: %d bytes.\n", SECP256K1_POK_SK_PROOF_SIZE);

  EXPECT(secp256k1_mpt_pok_sk_verify(ctx, proof, &pk, context_id) == 1);
  printf("Proof verified successfully.\n");

  /* --- Negative: Wrong context --- */
  printf("Testing wrong context...\n");
  {
    unsigned char wrong_context[32];
    memcpy(wrong_context, context_id, 32);
    wrong_context[0] ^= 0xFF;
    EXPECT(secp256k1_mpt_pok_sk_verify(ctx, proof, &pk, wrong_context) == 0);
  }
  printf("Wrong context: rejected OK.\n");

  /* --- Negative: Corrupted proof byte --- */
  printf("Testing corrupted proof...\n");
  {
    unsigned char bad[SECP256K1_POK_SK_PROOF_SIZE];
    memcpy(bad, proof, SECP256K1_POK_SK_PROOF_SIZE);
    bad[SECP256K1_POK_SK_PROOF_SIZE - 1] ^= 0x01;
    EXPECT(secp256k1_mpt_pok_sk_verify(ctx, bad, &pk, context_id) == 0);
  }
  printf("Corrupted proof: rejected OK.\n");

  /* --- Negative: Wrong public key --- */
  printf("Testing wrong public key...\n");
  {
    unsigned char sk_bad[32];
    secp256k1_pubkey pk_bad;
    random_scalar(ctx, sk_bad);
    EXPECT(secp256k1_ec_pubkey_create(ctx, &pk_bad, sk_bad));
    EXPECT(secp256k1_mpt_pok_sk_verify(ctx, proof, &pk_bad, context_id) == 0);
  }
  printf("Wrong public key: rejected OK.\n");

  /* --- Positive: No context_id (NULL) --- */
  printf("Testing NULL context_id...\n");
  {
    unsigned char proof_no_ctx[SECP256K1_POK_SK_PROOF_SIZE];
    EXPECT(secp256k1_mpt_pok_sk_prove(ctx, proof_no_ctx, &pk, sk, NULL) == 1);
    EXPECT(secp256k1_mpt_pok_sk_verify(ctx, proof_no_ctx, &pk, NULL) == 1);
  }
  printf("NULL context_id: accepted OK.\n");

  secp256k1_context_destroy(ctx);
}

int main(void)
{
  test_pok_sk();
  printf("ALL POK SK TESTS PASSED\n");
  return 0;
}
