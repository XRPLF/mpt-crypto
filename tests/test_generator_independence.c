/*
 * Generator independence regression test.
 *
 * The Bulletproof soundness argument requires the Pedersen blinding base
 * (pk_base, from secp256k1_mpt_get_h_generator) to be independent of every
 * entry of the G and H generator vectors. Before PR #63 the vectors were
 * derived from the labels ("G", 1) / ("H", 1), which made H_vec[0] equal to
 * pk_base and admitted forged range proofs. PR #63 moved the vectors to
 * ("BP_G", 4) / ("BP_H", 4); this test pins that separation so a future label
 * or index change cannot silently collide them again.
 *
 * Comparison is on the 33-byte compressed serialization, which is injective
 * on curve points, so byte equality is point equality.
 */

#include "secp256k1_mpt.h"
#include "test_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Mirrors BP_VALUE_BITS * BP_MAX_VALUES in src/bulletproof_aggregated.c: the
 * largest generator-vector length the protocol can request. */
#define GEN_VEC_LEN (64 * 4)

/* pk_base, G_vec, H_vec, U */
#define TOTAL_POINTS (1 + GEN_VEC_LEN + GEN_VEC_LEN + 1)

static void serialize_or_die(const secp256k1_context *ctx,
                             unsigned char out[33], const secp256k1_pubkey *p)
{
  size_t len = 33;
  EXPECT(secp256k1_ec_pubkey_serialize(ctx, out, &len, p,
                                       SECP256K1_EC_COMPRESSED) == 1);
  EXPECT(len == 33);
}

static void test_generator_independence(void)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                    SECP256K1_CONTEXT_VERIFY);
  secp256k1_pubkey pk_base;
  secp256k1_pubkey *G_vec = NULL;
  secp256k1_pubkey *H_vec = NULL;
  secp256k1_pubkey U_arr[1];
  unsigned char (*ser)[33] = NULL;
  size_t count = 0;

  printf("Running test: Bulletproof generator independence...\n");

  G_vec = (secp256k1_pubkey *)malloc(GEN_VEC_LEN * sizeof(secp256k1_pubkey));
  H_vec = (secp256k1_pubkey *)malloc(GEN_VEC_LEN * sizeof(secp256k1_pubkey));
  ser = (unsigned char (*)[33])malloc(TOTAL_POINTS * 33);
  EXPECT(G_vec != NULL && H_vec != NULL && ser != NULL);

  /* Derive exactly what the prover and verifier derive. */
  EXPECT(secp256k1_mpt_get_h_generator(ctx, &pk_base) == 1);
  EXPECT(secp256k1_mpt_get_generator_vector(
             ctx, G_vec, GEN_VEC_LEN, (const unsigned char *)"BP_G", 4) == 1);
  EXPECT(secp256k1_mpt_get_generator_vector(
             ctx, H_vec, GEN_VEC_LEN, (const unsigned char *)"BP_H", 4) == 1);
  EXPECT(secp256k1_mpt_get_generator_vector(
             ctx, U_arr, 1, (const unsigned char *)"BP_U", 4) == 1);

  serialize_or_die(ctx, ser[count++], &pk_base);
  for (size_t i = 0; i < GEN_VEC_LEN; i++)
    serialize_or_die(ctx, ser[count++], &G_vec[i]);
  for (size_t i = 0; i < GEN_VEC_LEN; i++)
    serialize_or_die(ctx, ser[count++], &H_vec[i]);
  serialize_or_die(ctx, ser[count++], &U_arr[0]);
  EXPECT(count == TOTAL_POINTS);

  /* 1. The invariant the soundness argument depends on: pk_base is distinct
   *    from every generator-vector entry (and from U). */
  for (size_t i = 1; i < TOTAL_POINTS; i++)
    EXPECT(memcmp(ser[0], ser[i], 33) != 0);
  printf("  pk_base distinct from all %d vector generators: OK\n",
         (int)(TOTAL_POINTS - 1));

  /* 2. Belt and braces: the whole union is pairwise distinct, which also
   *    catches label or index reuse between G_vec, H_vec and U. */
  for (size_t i = 0; i < TOTAL_POINTS; i++)
    for (size_t j = i + 1; j < TOTAL_POINTS; j++)
      EXPECT(memcmp(ser[i], ser[j], 33) != 0);
  printf("  all %d generators pairwise distinct: OK\n", (int)TOTAL_POINTS);

  free(G_vec);
  free(H_vec);
  free(ser);
  secp256k1_context_destroy(ctx);

  printf("Test passed! Generator independence holds.\n");
}

int main(void)
{
  test_generator_independence();
  printf("\n[SUCCESS] All assertions passed!\n");
  return 0;
}
