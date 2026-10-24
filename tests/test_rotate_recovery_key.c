/* Round-trip and negative tests for pi_rec, the RecoveryKey possession proof.
 *
 * Relation under test:
 *   pk_H' = sk_H'*G
 *
 * This is the same relation as key registration (secp256k1_mpt_pok_sk_*) and
 * shares its implementation, so the tests that matter most here are the ones
 * that pin the separation between them: a proof made under one domain tag must
 * not verify under the other, in either direction, even though the statement
 * and the witness are identical.
 */
#include "secp256k1_mpt.h"
#include "test_utils.h"
#include <secp256k1.h>
#include <stdio.h>
#include <string.h>

void test_rotate_recovery_key_roundtrip(void)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                    SECP256K1_CONTEXT_VERIFY);
  EXPECT(ctx != NULL);

  unsigned char sk[32], context_id[32];
  unsigned char proof[SECP256K1_ROTATE_RECOVERY_KEY_PROOF_SIZE];
  secp256k1_pubkey pk;

  printf("=== Running Test: pi_rec RecoveryKey possession (64 bytes) ===\n");

  random_scalar(ctx, sk);
  EXPECT(secp256k1_ec_pubkey_create(ctx, &pk, sk));
  random_bytes(context_id);

  EXPECT(secp256k1_rotate_recovery_key_prove(ctx, proof, sk, &pk, context_id) ==
         1);
  EXPECT(secp256k1_rotate_recovery_key_verify(ctx, proof, &pk, context_id) ==
         1);
  printf("Round-trip with context_id: OK.\n");

  /* Recovery mode binds a transaction context with an empty TxSpecific field,
   * but a NULL digest must still work: NULL and 32 zero bytes are distinct. */
  {
    unsigned char proof_no_ctx[SECP256K1_ROTATE_RECOVERY_KEY_PROOF_SIZE];
    unsigned char zero_ctx[32];
    memset(zero_ctx, 0, sizeof(zero_ctx));

    EXPECT(secp256k1_rotate_recovery_key_prove(ctx, proof_no_ctx, sk, &pk,
                                               NULL) == 1);
    EXPECT(secp256k1_rotate_recovery_key_verify(ctx, proof_no_ctx, &pk, NULL) ==
           1);
    EXPECT(secp256k1_rotate_recovery_key_verify(ctx, proof_no_ctx, &pk,
                                                zero_ctx) == 0);
    EXPECT(secp256k1_rotate_recovery_key_verify(ctx, proof, &pk, NULL) == 0);
  }
  printf("NULL context_id round-trips and is distinct from zeroes: OK.\n");

  /* --- Negative: each response scalar tampered --- */
  for (int i = 0; i < SECP256K1_ROTATE_RECOVERY_KEY_PROOF_SIZE; i += 32)
  {
    unsigned char bad[SECP256K1_ROTATE_RECOVERY_KEY_PROOF_SIZE];
    memcpy(bad, proof, sizeof(bad));
    bad[i + 31] ^= 0x01;
    EXPECT(secp256k1_rotate_recovery_key_verify(ctx, bad, &pk, context_id) ==
           0);
  }
  printf("Tampered e and s: rejected OK.\n");

  /* --- Negative: wrong context --- */
  {
    unsigned char wrong_context[32];
    memcpy(wrong_context, context_id, 32);
    wrong_context[0] ^= 0xFF;
    EXPECT(secp256k1_rotate_recovery_key_verify(ctx, proof, &pk,
                                                wrong_context) == 0);
  }
  printf("Wrong context: rejected OK.\n");

  /* --- Negative: wrong public key --- */
  {
    unsigned char sk_bad[32];
    secp256k1_pubkey pk_bad;
    random_scalar(ctx, sk_bad);
    EXPECT(secp256k1_ec_pubkey_create(ctx, &pk_bad, sk_bad));
    EXPECT(secp256k1_rotate_recovery_key_verify(ctx, proof, &pk_bad,
                                                context_id) == 0);
  }
  printf("Wrong public key: rejected OK.\n");

  secp256k1_context_destroy(ctx);
}

/* The two instantiations of the Schnorr relation must not be interchangeable:
 * a key-registration proof replayed as a RecoveryKey registration would let an
 * attacker who observed a Convert install a RecoveryKey on that account. */
void test_rotate_recovery_key_domain_separation(void)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                    SECP256K1_CONTEXT_VERIFY);
  EXPECT(ctx != NULL);

  unsigned char sk[32], context_id[32];
  unsigned char proof_rec[SECP256K1_ROTATE_RECOVERY_KEY_PROOF_SIZE];
  unsigned char proof_reg[SECP256K1_POK_SK_PROOF_SIZE];
  secp256k1_pubkey pk;

  printf("=== Running Test: pi_rec / pok_sk domain separation ===\n");

  random_scalar(ctx, sk);
  EXPECT(secp256k1_ec_pubkey_create(ctx, &pk, sk));
  random_bytes(context_id);

  EXPECT(secp256k1_rotate_recovery_key_prove(ctx, proof_rec, sk, &pk,
                                             context_id) == 1);
  EXPECT(secp256k1_mpt_pok_sk_prove(ctx, proof_reg, &pk, sk, context_id) == 1);

  /* Same statement, same witness, same context, and the challenges must still
   * differ because the tag is hashed first. (The responses differ too, but
   * that alone proves nothing: nonce derivation is salted with fresh entropy,
   * so two proofs under the same tag differ as well.) */
  EXPECT(memcmp(proof_rec, proof_reg, 32) != 0);

  EXPECT(secp256k1_mpt_pok_sk_verify(ctx, proof_rec, &pk, context_id) == 0);
  EXPECT(secp256k1_rotate_recovery_key_verify(ctx, proof_reg, &pk,
                                              context_id) == 0);

  printf("Cross-tag substitution rejected in both directions: OK.\n");

  secp256k1_context_destroy(ctx);
}

int main(void)
{
  test_rotate_recovery_key_roundtrip();
  test_rotate_recovery_key_domain_separation();
  printf("ALL ROTATE RECOVERY KEY TESTS PASSED\n");
  return 0;
}
