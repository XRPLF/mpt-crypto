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

/* The registration transcript is consensus-critical and already shipped, so it
 * is pinned here against a proof generated before proof_pok_sk.c was
 * generalised over its domain tag. Nonce derivation is salted with fresh
 * entropy, so proofs are not byte-reproducible and this cannot be a
 * known-answer test on the prover; what it pins is the property that actually
 * matters, that the current verifier still accepts proofs issued by the old
 * one. A change to the domain tag, the point serialization, the transcript
 * order or the context_id handling all break it. */
void test_pok_sk_legacy_vector(void)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                    SECP256K1_CONTEXT_VERIFY);
  EXPECT(ctx != NULL);

  static const unsigned char kLegacyProof[SECP256K1_POK_SK_PROOF_SIZE] = {
      0x7B, 0x25, 0x0F, 0xEE, 0x02, 0x80, 0xA5, 0x6D, 0x23, 0x02, 0x8A,
      0x69, 0x4B, 0x16, 0x36, 0x59, 0x00, 0x64, 0xBF, 0x6A, 0x8C, 0xEC,
      0xFD, 0x1B, 0x8C, 0x80, 0x08, 0x65, 0x34, 0x6A, 0xF5, 0xD7, 0x33,
      0x0D, 0xA1, 0x90, 0x65, 0xA5, 0xC8, 0xE6, 0x57, 0xE4, 0xF8, 0x60,
      0xDF, 0xC9, 0x35, 0x9E, 0x51, 0x4B, 0x9D, 0xB6, 0x44, 0xE5, 0xD9,
      0xCF, 0x44, 0x88, 0x81, 0xEC, 0xE5, 0x09, 0xAB, 0xF2};

  unsigned char sk[32], context_id[32];
  secp256k1_pubkey pk;

  printf("=== Running Test: PoK SK legacy vector (transcript stability) ===\n");

  for (int i = 0; i < 32; i++)
  {
    sk[i] = (unsigned char)(i + 1);
    context_id[i] = (unsigned char)(0xA0 + i);
  }

  EXPECT(secp256k1_ec_pubkey_create(ctx, &pk, sk));
  EXPECT(secp256k1_mpt_pok_sk_verify(ctx, kLegacyProof, &pk, context_id) == 1);

  /* Same bytes must not pass under the RecoveryKey tag. */
  EXPECT(secp256k1_rotate_recovery_key_verify(ctx, kLegacyProof, &pk,
                                              context_id) == 0);

  printf("Legacy registration proof still verifies.\n");

  secp256k1_context_destroy(ctx);
}

int main(void)
{
  test_pok_sk();
  test_pok_sk_legacy_vector();
  printf("ALL POK SK TESTS PASSED\n");
  return 0;
}
