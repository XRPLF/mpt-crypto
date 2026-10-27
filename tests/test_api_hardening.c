/*
 * Regression tests for the Zellic API-boundary findings.
 *
 *   DEFI-1108  secp256k1_bulletproof_create_commitment did not validate its
 *              required pointer arguments before dereferencing them.
 *   DEFI-1109  secp256k1_elgamal_add / _subtract cannot represent an identity
 *              result. Not fixed -- the limitation is now documented, and the
 *              tests below pin the behaviour so that changing it has to be a
 *              deliberate, test-visible decision.
 *   DEFI-1110  secp256k1_bulletproof_prove_agg overwrote the caller-supplied
 *              *proof_len capacity before the only check that used it, so an
 *              undersized proof_out was serialized past its end.
 */

#include "secp256k1_mpt.h"
#include "test_utils.h"
#include <secp256k1.h>
#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* DEFI-1108: NULL-argument handling at the commitment entry point.    */
/* ------------------------------------------------------------------ */
static void test_create_commitment_null_args(secp256k1_context *ctx)
{
  printf("\n[TEST] DEFI-1108: create_commitment rejects NULL arguments\n");

  secp256k1_pubkey h_generator;
  EXPECT(secp256k1_mpt_get_h_generator(ctx, &h_generator) == 1);

  unsigned char blinding[32];
  random_scalar(ctx, blinding);

  secp256k1_pubkey commitment;

  /* Baseline: the same arguments succeed when all are non-NULL. */
  EXPECT(secp256k1_bulletproof_create_commitment(ctx, &commitment, 42, blinding,
                                                 &h_generator) == 1);

  /* Each required pointer, individually NULL, must return 0 rather than
     dereference. value == 0 takes the early-return branch that writes
     *commitment_C directly, so it is covered separately. */
  EXPECT(secp256k1_bulletproof_create_commitment(NULL, &commitment, 42,
                                                 blinding, &h_generator) == 0);
  EXPECT(secp256k1_bulletproof_create_commitment(ctx, NULL, 42, blinding,
                                                 &h_generator) == 0);
  EXPECT(secp256k1_bulletproof_create_commitment(ctx, &commitment, 42, NULL,
                                                 &h_generator) == 0);
  EXPECT(secp256k1_bulletproof_create_commitment(ctx, &commitment, 42, blinding,
                                                 NULL) == 0);

  /* value == 0 path: *commitment_C is assigned before any combine. */
  EXPECT(secp256k1_bulletproof_create_commitment(ctx, NULL, 0, blinding,
                                                 &h_generator) == 0);
  EXPECT(secp256k1_bulletproof_create_commitment(ctx, &commitment, 0, blinding,
                                                 NULL) == 0);

  printf("  PASSED\n");
}

/* ------------------------------------------------------------------ */
/* DEFI-1110: proof_out capacity is honoured.                         */
/* ------------------------------------------------------------------ */
static void test_prove_agg_capacity(secp256k1_context *ctx)
{
  printf("\n[TEST] DEFI-1110: prove_agg honours the proof_out capacity\n");

  secp256k1_pubkey h_generator;
  EXPECT(secp256k1_mpt_get_h_generator(ctx, &h_generator) == 1);

  unsigned char blindings[32];
  random_scalar(ctx, blindings);
  const unsigned char *blindings_flat = blindings;

  uint64_t values[1] = {12345};

  unsigned char context_id[32];
  EXPECT(RAND_bytes(context_id, 32) == 1);

  /* Size query: proof_out == NULL reports the required length, writes
     nothing, and succeeds. */
  size_t required = 0;
  EXPECT(secp256k1_bulletproof_prove_agg(ctx, NULL, &required, values,
                                         blindings_flat, 1, &h_generator,
                                         context_id) == 1);
  EXPECT(required == kMPT_SINGLE_BULLETPROOF_SIZE);

  /* Exact capacity: succeeds and reports the bytes written. */
  unsigned char proof[kMPT_SINGLE_BULLETPROOF_SIZE];
  size_t proof_len = sizeof(proof);
  EXPECT(secp256k1_bulletproof_prove_agg(ctx, proof, &proof_len, values,
                                         blindings_flat, 1, &h_generator,
                                         context_id) == 1);
  EXPECT(proof_len == kMPT_SINGLE_BULLETPROOF_SIZE);

  /* Undersized capacity: must fail, must report the required length, and
     must not write a single byte of proof_out.

     The buffer is deliberately allocated at full size while the *declared*
     capacity is one byte short. Before the fix the entire proof was
     serialized here, so a real caller with a genuinely short allocation took
     an out-of-bounds write; with a full-size allocation the over-write lands
     in our own canary region and is detectable without invoking undefined
     behaviour. */
  unsigned char guarded[kMPT_SINGLE_BULLETPROOF_SIZE];
  memset(guarded, 0xA5, sizeof(guarded));

  size_t short_len = kMPT_SINGLE_BULLETPROOF_SIZE - 1;
  EXPECT(secp256k1_bulletproof_prove_agg(ctx, guarded, &short_len, values,
                                         blindings_flat, 1, &h_generator,
                                         context_id) == 0);
  EXPECT(short_len == kMPT_SINGLE_BULLETPROOF_SIZE);

  for (size_t i = 0; i < sizeof(guarded); i++)
    EXPECT(guarded[i] == 0xA5);

  /* A zero declared capacity is the degenerate case of the same bug. */
  memset(guarded, 0xA5, sizeof(guarded));
  size_t zero_len = 0;
  EXPECT(secp256k1_bulletproof_prove_agg(ctx, guarded, &zero_len, values,
                                         blindings_flat, 1, &h_generator,
                                         context_id) == 0);
  EXPECT(zero_len == kMPT_SINGLE_BULLETPROOF_SIZE);
  for (size_t i = 0; i < sizeof(guarded); i++)
    EXPECT(guarded[i] == 0xA5);

  /* NULL proof_len with a non-NULL proof_out has no capacity to check
     against, so it must fail rather than guess. */
  EXPECT(secp256k1_bulletproof_prove_agg(ctx, guarded, NULL, values,
                                         blindings_flat, 1, &h_generator,
                                         context_id) == 0);

  /* Required pointers. */
  size_t len = sizeof(proof);
  EXPECT(secp256k1_bulletproof_prove_agg(NULL, proof, &len, values,
                                         blindings_flat, 1, &h_generator,
                                         context_id) == 0);
  EXPECT(secp256k1_bulletproof_prove_agg(ctx, proof, &len, NULL, blindings_flat,
                                         1, &h_generator, context_id) == 0);
  EXPECT(secp256k1_bulletproof_prove_agg(ctx, proof, &len, values, NULL, 1,
                                         &h_generator, context_id) == 0);
  EXPECT(secp256k1_bulletproof_prove_agg(ctx, proof, &len, values,
                                         blindings_flat, 1, NULL,
                                         context_id) == 0);

  /* context_id is documented as optional. */
  len = sizeof(proof);
  EXPECT(secp256k1_bulletproof_prove_agg(ctx, proof, &len, values,
                                         blindings_flat, 1, &h_generator,
                                         NULL) == 1);
  EXPECT(len == kMPT_SINGLE_BULLETPROOF_SIZE);

  printf("  PASSED\n");
}

/* ------------------------------------------------------------------ */
/* DEFI-1109: identity results are not representable.                 */
/* ------------------------------------------------------------------ */
static void test_elgamal_identity_result(secp256k1_context *ctx)
{
  printf("\n[TEST] DEFI-1109: elgamal add/subtract on identity results\n");

  unsigned char privkey[32];
  secp256k1_pubkey pubkey;
  EXPECT(secp256k1_elgamal_generate_keypair(ctx, privkey, &pubkey) == 1);

  unsigned char r[32];
  random_scalar(ctx, r);

  secp256k1_pubkey c1, c2;
  EXPECT(secp256k1_elgamal_encrypt(ctx, &c1, &c2, &pubkey, 100, r) == 1);

  secp256k1_pubkey out1, out2;

  /* Subtracting a ciphertext from itself cancels both components. Documented
     as returning 0: the identity has no secp256k1_pubkey representation. */
  EXPECT(secp256k1_elgamal_subtract(ctx, &out1, &out2, &c1, &c2, &c1, &c2) ==
         0);

  /* Adding a ciphertext to its own negation is the same case. */
  secp256k1_pubkey neg_c1 = c1, neg_c2 = c2;
  EXPECT(secp256k1_ec_pubkey_negate(ctx, &neg_c1) == 1);
  EXPECT(secp256k1_ec_pubkey_negate(ctx, &neg_c2) == 1);
  EXPECT(secp256k1_elgamal_add(ctx, &out1, &out2, &c1, &c2, &neg_c1, &neg_c2) ==
         0);

  /* A single cancelling component is enough to fail, even when the other
     component is perfectly representable. */
  unsigned char r2[32];
  random_scalar(ctx, r2);
  secp256k1_pubkey d1, d2;
  EXPECT(secp256k1_elgamal_encrypt(ctx, &d1, &d2, &pubkey, 7, r2) == 1);
  EXPECT(secp256k1_elgamal_subtract(ctx, &out1, &out2, &c1, &d2, &c1, &c2) ==
         0);

  /* The ordinary case still works, so the failures above are specific to the
     identity and not a blanket breakage. */
  EXPECT(secp256k1_elgamal_subtract(ctx, &out1, &out2, &c1, &c2, &d1, &d2) ==
         1);
  EXPECT(secp256k1_elgamal_add(ctx, &out1, &out2, &c1, &c2, &d1, &d2) == 1);

  printf("  PASSED (limitation pinned; see secp256k1_mpt.h)\n");
}

int main(void)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                    SECP256K1_CONTEXT_VERIFY);
  EXPECT(ctx != NULL);

  test_create_commitment_null_args(ctx);
  test_prove_agg_capacity(ctx);
  test_elgamal_identity_result(ctx);

  secp256k1_context_destroy(ctx);
  printf("\n[TEST] All API hardening tests completed successfully\n");
  return 0;
}
