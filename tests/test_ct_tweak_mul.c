/* Algebraic-equivalence tests for mpt_ct_pubkey_tweak_mul.
 *
 * The wrapper routes secret-scalar point multiplications through
 * secp256k1_ecdh (which uses constant-time secp256k1_ecmult_const)
 * and parses the resulting raw point back into a secp256k1_pubkey.
 * This test fixes the wrapper's algebraic behaviour against the
 * existing variable-time secp256k1_ec_pubkey_tweak_mul on every
 * input both functions accept (i.e., 0 < scalar < group_order).
 *
 * It does NOT measure timing — that is asserted only at the source
 * level by the wrapper's documented dispatch path. */

#include "secp256k1_mpt.h"
#include "test_utils.h"

#include "../src/mpt_internal.h"

#include <stdio.h>
#include <string.h>

static void serialize33(secp256k1_context const *ctx, unsigned char out[33],
                        secp256k1_pubkey const *pk)
{
  size_t len = 33;
  EXPECT(secp256k1_ec_pubkey_serialize(ctx, out, &len, pk,
                                       SECP256K1_EC_COMPRESSED) == 1);
  EXPECT(len == 33);
}

/* For a uniformly-random valid scalar and a uniformly-random base
 * point, the new wrapper and the legacy primitive must produce
 * byte-identical output. */
static void test_random_scalar_random_point(secp256k1_context *ctx)
{
  printf("test_random_scalar_random_point...\n");
  for (int trial = 0; trial < 64; ++trial)
  {
    unsigned char base_sk[32], scalar[32];
    random_scalar(ctx, base_sk);
    random_scalar(ctx, scalar);

    secp256k1_pubkey base;
    EXPECT(secp256k1_ec_pubkey_create(ctx, &base, base_sk) == 1);

    secp256k1_pubkey p_legacy = base, p_ct = base;
    EXPECT(secp256k1_ec_pubkey_tweak_mul(ctx, &p_legacy, scalar) == 1);
    EXPECT(mpt_ct_pubkey_tweak_mul(ctx, &p_ct, scalar) == 1);

    unsigned char ser_legacy[33], ser_ct[33];
    serialize33(ctx, ser_legacy, &p_legacy);
    serialize33(ctx, ser_ct, &p_ct);
    EXPECT(memcmp(ser_legacy, ser_ct, 33) == 0);
  }
  printf("SUCCESS: 64 random (scalar, point) pairs match\n");
}

/* Edge cases that exercise the wNAF representation differently:
 * scalar = 1, scalar = 2, scalar = group_order - 1, and a few
 * fixed bit patterns the legacy variable-time path treats specially. */
static void test_edge_case_scalars(secp256k1_context *ctx)
{
  printf("test_edge_case_scalars...\n");

  static unsigned char const order_minus_one[32] = {
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48,
      0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x40};

  unsigned char scalar_one[32] = {0};
  scalar_one[31] = 1;
  unsigned char scalar_two[32] = {0};
  scalar_two[31] = 2;
  unsigned char scalar_repeat[32];
  memset(scalar_repeat, 0xAA, 32); /* high Hamming weight */
  unsigned char scalar_sparse[32] = {0};
  scalar_sparse[0] = 0x80; /* single high bit */

  unsigned char const *test_scalars[] = {scalar_one, scalar_two, scalar_repeat,
                                         scalar_sparse, order_minus_one};
  char const *names[] = {"1", "2", "0xAA..AA", "high-bit only", "n-1"};

  unsigned char base_sk[32];
  random_scalar(ctx, base_sk);
  secp256k1_pubkey base;
  EXPECT(secp256k1_ec_pubkey_create(ctx, &base, base_sk) == 1);

  for (size_t i = 0; i < sizeof(test_scalars) / sizeof(test_scalars[0]); ++i)
  {
    secp256k1_pubkey p_legacy = base, p_ct = base;
    EXPECT(secp256k1_ec_pubkey_tweak_mul(ctx, &p_legacy, test_scalars[i]) == 1);
    EXPECT(mpt_ct_pubkey_tweak_mul(ctx, &p_ct, test_scalars[i]) == 1);

    unsigned char ser_legacy[33], ser_ct[33];
    serialize33(ctx, ser_legacy, &p_legacy);
    serialize33(ctx, ser_ct, &p_ct);
    EXPECT(memcmp(ser_legacy, ser_ct, 33) == 0);
    printf("  scalar=%s: ok\n", names[i]);
  }
}

/* Both functions must reject zero and >= group_order scalars. The
 * wrapper additionally must not corrupt the caller's point on
 * failure — pubkey_parse is only invoked on success. */
static void test_invalid_scalars_rejected(secp256k1_context *ctx)
{
  printf("test_invalid_scalars_rejected...\n");

  unsigned char base_sk[32];
  random_scalar(ctx, base_sk);
  secp256k1_pubkey base;
  EXPECT(secp256k1_ec_pubkey_create(ctx, &base, base_sk) == 1);

  unsigned char zero[32] = {0};
  /* The group order itself, which fails seckey_verify. */
  static unsigned char const order[32] = {
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48,
      0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41};
  unsigned char overflow[32];
  memset(overflow, 0xFF, 32);

  unsigned char const *invalid_scalars[] = {zero, order, overflow};
  char const *names[] = {"zero", "order", "all-ones"};

  for (size_t i = 0; i < sizeof(invalid_scalars) / sizeof(invalid_scalars[0]);
       ++i)
  {
    secp256k1_pubkey p = base;
    EXPECT(mpt_ct_pubkey_tweak_mul(ctx, &p, invalid_scalars[i]) == 0);
    printf("  scalar=%s: correctly rejected\n", names[i]);
  }
}

int main(void)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                    SECP256K1_CONTEXT_VERIFY);
  EXPECT(ctx != NULL);

  test_random_scalar_random_point(ctx);
  test_edge_case_scalars(ctx);
  test_invalid_scalars_rejected(ctx);

  secp256k1_context_destroy(ctx);
  printf("All ct_tweak_mul equivalence tests passed.\n");
  return 0;
}
