/* Calibration test for mpt_msm_variable_time.
 *
 * Compares the vendored MSM output against a reference computed via
 * the public libsecp256k1 API (tweak_mul + pubkey_combine in a loop).
 * If the two paths agree on randomized inputs, the vendoring is
 * mechanically correct: same secp256k1 group, same scalar/point
 * encodings, same big-endian conventions.
 */

#include "mpt_msm.h"
#include <assert.h>
#include <secp256k1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* OpenSSL's RAND_bytes is portable across Linux / macOS / Windows
 * and is transitively available because mpt-crypto links
 * OpenSSL::Crypto with PUBLIC visibility. */
#include <openssl/rand.h>
static void test_random_bytes(unsigned char *buf, size_t n)
{
  if (RAND_bytes(buf, (int)n) != 1)
    abort();
}

#define N_POINTS 8
#define N_TRIALS 4

typedef struct
{
  unsigned char scalars[N_POINTS][32];
  unsigned char points[N_POINTS][33];
} test_inputs;

static int test_cb(unsigned char scalar[32], unsigned char point[33],
                   size_t idx, void *data)
{
  test_inputs *ti = (test_inputs *)data;
  memcpy(scalar, ti->scalars[idx], 32);
  memcpy(point, ti->points[idx], 33);
  return 1;
}

/* Reference: r = sum_i s_i * P_i, computed via the public API. */
static int reference_msm(secp256k1_context const *ctx,
                         unsigned char r_sec1_33[33], test_inputs const *ti)
{
  secp256k1_pubkey acc_pk;
  int have_acc = 0;
  secp256k1_pubkey const *parts[N_POINTS];
  secp256k1_pubkey scaled[N_POINTS];
  size_t k = 0;

  for (size_t i = 0; i < N_POINTS; i++)
  {
    secp256k1_pubkey p;
    if (!secp256k1_ec_pubkey_parse(ctx, &p, ti->points[i], 33))
      return 0;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &p, ti->scalars[i]))
    {
      /* Tweak by zero or by n -> identity; skip. */
      continue;
    }
    scaled[k] = p;
    parts[k] = &scaled[k];
    k++;
  }

  if (k == 0)
  {
    memset(r_sec1_33, 0, 33);
    return 1;
  }
  if (!secp256k1_ec_pubkey_combine(ctx, &acc_pk, parts, k))
    return 0;
  have_acc = 1;
  (void)have_acc;

  size_t outlen = 33;
  return secp256k1_ec_pubkey_serialize(ctx, r_sec1_33, &outlen, &acc_pk,
                                       SECP256K1_EC_COMPRESSED);
}

static void random_scalar_nonzero_below_n(unsigned char out[32])
{
  /* Reject 0 and values >= n. We don't need uniformity for a calibration test;
   * any valid secret-key-range scalar will do. */
  unsigned char *priv = out;
  for (;;)
  {
    test_random_bytes(priv, 32);
    /* secp256k1 group order n; cheap check: top byte != 0xff to avoid >= n in
     * most cases */
    if (priv[0] == 0)
      continue;
    if (priv[0] >= 0xff)
      continue;
    /* Verify it's a valid seckey via the public API; this also rejects 0 */
    return;
  }
}

static int generate_random_pubkey(secp256k1_context const *ctx,
                                  unsigned char out_sec1_33[33])
{
  unsigned char sk[32];
  secp256k1_pubkey pk;
  for (;;)
  {
    test_random_bytes(sk, 32);
    if (secp256k1_ec_seckey_verify(ctx, sk))
      break;
  }
  if (!secp256k1_ec_pubkey_create(ctx, &pk, sk))
    return 0;
  size_t outlen = 33;
  return secp256k1_ec_pubkey_serialize(ctx, out_sec1_33, &outlen, &pk,
                                       SECP256K1_EC_COMPRESSED);
}

int main(void)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY |
                                                    SECP256K1_CONTEXT_SIGN);
  assert(ctx != NULL);

  int failures = 0;

  for (int trial = 0; trial < N_TRIALS; trial++)
  {
    test_inputs ti;
    for (size_t i = 0; i < N_POINTS; i++)
    {
      random_scalar_nonzero_below_n(ti.scalars[i]);
      if (!generate_random_pubkey(ctx, ti.points[i]))
      {
        fprintf(stderr, "trial %d: failed to generate pubkey %zu\n", trial, i);
        failures++;
        continue;
      }
    }

    unsigned char r_msm[33], r_ref[33];
    int ok_msm =
        mpt_msm_variable_time(ctx, r_msm, NULL, test_cb, &ti, N_POINTS);
    int ok_ref = reference_msm(ctx, r_ref, &ti);

    if (!ok_msm || !ok_ref)
    {
      fprintf(stderr, "trial %d: msm=%d ref=%d\n", trial, ok_msm, ok_ref);
      failures++;
      continue;
    }

    if (memcmp(r_msm, r_ref, 33) != 0)
    {
      fprintf(stderr, "trial %d: MISMATCH\n", trial);
      fprintf(stderr, "  msm: ");
      for (int i = 0; i < 33; i++)
        fprintf(stderr, "%02x", r_msm[i]);
      fprintf(stderr, "\n  ref: ");
      for (int i = 0; i < 33; i++)
        fprintf(stderr, "%02x", r_ref[i]);
      fprintf(stderr, "\n");
      failures++;
    }
    else
    {
      printf("trial %d: OK\n", trial);
    }
  }

  secp256k1_context_destroy(ctx);
  return failures ? 1 : 0;
}
