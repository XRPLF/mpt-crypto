/* Microbenchmark for compact-sigma verifiers, focused on compact_standard
 * (the largest reconstruction MSM: 6 + n_recipients equations of 2-3 mults
 * each). Mirrors the setup of tests/test_compact_standard.c.
 *
 * Not registered with ctest. Build manually:
 *   cmake --build build --target bench_compact_sigma
 *   ./tests/bench_compact_sigma
 *
 * Used to ground the speedup claim from replacing the per-equation
 * tweak_mul+combine reconstruction chain with mpt_msm_variable_time
 * (issue #88, compact-sigma side).
 */
#include "secp256k1_mpt.h"
#include "test_utils.h"
#include <secp256k1.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BENCH_ITERS 5000
#define N_RECIPIENTS 3

static inline double elapsed_ms(struct timespec a, struct timespec b)
{
  return (b.tv_sec - a.tv_sec) * 1000.0 + (b.tv_nsec - a.tv_nsec) / 1e6;
}

static int value_times_g_local(const secp256k1_context *ctx,
                               secp256k1_pubkey *out, uint64_t v)
{
  if (v == 0)
    return 0;
  unsigned char buf[32] = {0};
  for (int i = 0; i < 8; i++)
    buf[31 - i] = (unsigned char)((v >> (8 * i)) & 0xff);
  return secp256k1_ec_pubkey_create(ctx, out, buf);
}

static void bench_compact_standard(secp256k1_context *ctx)
{
  const uint64_t amount = 123456, balance = 1000000;
  const uint64_t remainder = balance - amount;
  const size_t N = N_RECIPIENTS;

  unsigned char r[32], r_b[32], sk_A[32], context_id[32];
  random_scalar(ctx, r);
  random_scalar(ctx, r_b);
  random_scalar(ctx, sk_A);
  EXPECT(RAND_bytes(context_id, 32) == 1);

  secp256k1_pubkey pk_A, H;
  EXPECT(secp256k1_ec_pubkey_create(ctx, &pk_A, sk_A));
  EXPECT(secp256k1_mpt_get_h_generator(ctx, &H));

  /* Recipient keys */
  secp256k1_pubkey pks[N_RECIPIENTS];
  for (size_t i = 0; i < N; i++)
  {
    unsigned char sk_i[32];
    random_scalar(ctx, sk_i);
    EXPECT(secp256k1_ec_pubkey_create(ctx, &pks[i], sk_i));
  }

  /* C1 = r*G */
  secp256k1_pubkey C1;
  EXPECT(secp256k1_ec_pubkey_create(ctx, &C1, r));

  secp256k1_pubkey mG;
  EXPECT(value_times_g_local(ctx, &mG, amount));

  /* C2_i = r*pk_i + m*G */
  secp256k1_pubkey C2_vec[N_RECIPIENTS];
  for (size_t i = 0; i < N; i++)
  {
    secp256k1_pubkey rPk = pks[i];
    EXPECT(secp256k1_ec_pubkey_tweak_mul(ctx, &rPk, r));
    const secp256k1_pubkey *pts[2] = {&rPk, &mG};
    EXPECT(secp256k1_ec_pubkey_combine(ctx, &C2_vec[i], pts, 2));
  }

  /* PC_m = m*G + r*H */
  secp256k1_pubkey PC_m;
  {
    secp256k1_pubkey rH = H;
    EXPECT(secp256k1_ec_pubkey_tweak_mul(ctx, &rH, r));
    const secp256k1_pubkey *pts[2] = {&mG, &rH};
    EXPECT(secp256k1_ec_pubkey_combine(ctx, &PC_m, pts, 2));
  }

  /* PC_b = v*G + r_b*H */
  secp256k1_pubkey PC_b;
  {
    secp256k1_pubkey vG;
    EXPECT(value_times_g_local(ctx, &vG, remainder));
    secp256k1_pubkey rbH = H;
    EXPECT(secp256k1_ec_pubkey_tweak_mul(ctx, &rbH, r_b));
    const secp256k1_pubkey *pts[2] = {&vG, &rbH};
    EXPECT(secp256k1_ec_pubkey_combine(ctx, &PC_b, pts, 2));
  }

  /* r_diff = r_bal - r; here we use r_bal = r + 1 to keep things simple. */
  unsigned char r_bal[32];
  memcpy(r_bal, r, 32);
  unsigned char one[32] = {0};
  one[31] = 1;
  secp256k1_mpt_scalar_add(r_bal, r_bal, one);
  secp256k1_mpt_scalar_reduce32(r_bal, r_bal);
  EXPECT(secp256k1_ec_seckey_verify(ctx, r_bal));

  unsigned char r_diff[32];
  {
    unsigned char neg_r[32];
    secp256k1_mpt_scalar_negate(neg_r, r);
    secp256k1_mpt_scalar_add(r_diff, r_bal, neg_r);
    secp256k1_mpt_scalar_reduce32(r_diff, r_diff);
    EXPECT(secp256k1_ec_seckey_verify(ctx, r_diff));
  }

  /* B1 = r_diff*G */
  secp256k1_pubkey B1;
  EXPECT(secp256k1_ec_pubkey_create(ctx, &B1, r_diff));

  /* B2 = r_diff*pk_A + v*G */
  secp256k1_pubkey B2;
  {
    secp256k1_pubkey rdPk = pk_A;
    EXPECT(secp256k1_ec_pubkey_tweak_mul(ctx, &rdPk, r_diff));
    secp256k1_pubkey vG;
    EXPECT(value_times_g_local(ctx, &vG, remainder));
    const secp256k1_pubkey *pts[2] = {&rdPk, &vG};
    EXPECT(secp256k1_ec_pubkey_combine(ctx, &B2, pts, 2));
  }

  unsigned char proof[SECP256K1_COMPACT_STANDARD_PROOF_SIZE];
  EXPECT(secp256k1_compact_standard_prove(ctx, proof, amount, remainder, r,
                                          sk_A, r_b, N, &C1, C2_vec, pks, &PC_m,
                                          &pk_A, &PC_b, &B1, &B2, context_id));

  /* Warmup */
  for (int i = 0; i < 64; i++)
    EXPECT(secp256k1_compact_standard_verify(ctx, proof, N, &C1, C2_vec, pks,
                                             &PC_m, &pk_A, &PC_b, &B1, &B2,
                                             context_id));

  struct timespec ts, te;
  timespec_get(&ts, TIME_UTC);
  for (int i = 0; i < BENCH_ITERS; i++)
  {
    int ok = secp256k1_compact_standard_verify(ctx, proof, N, &C1, C2_vec, pks,
                                               &PC_m, &pk_A, &PC_b, &B1, &B2,
                                               context_id);
    EXPECT(ok);
  }
  timespec_get(&te, TIME_UTC);
  printf("  compact_standard (n_recip=%zu): %.4f ms/verify (%d iters)\n", N,
         elapsed_ms(ts, te) / BENCH_ITERS, BENCH_ITERS);
}

static void bench_compact_clawback(secp256k1_context *ctx)
{
  unsigned char sk_iss[32], r[32], context_id[32];
  const uint64_t amount = 42;
  random_scalar(ctx, sk_iss);
  random_scalar(ctx, r);
  EXPECT(RAND_bytes(context_id, 32) == 1);

  secp256k1_pubkey P_iss;
  EXPECT(secp256k1_ec_pubkey_create(ctx, &P_iss, sk_iss));

  /* Build C1 = r*G; C2 = r*P_iss + amount*G. */
  secp256k1_pubkey C1;
  EXPECT(secp256k1_ec_pubkey_create(ctx, &C1, r));
  secp256k1_pubkey C2;
  {
    secp256k1_pubkey mG, rPiss = P_iss;
    EXPECT(value_times_g_local(ctx, &mG, amount));
    EXPECT(secp256k1_ec_pubkey_tweak_mul(ctx, &rPiss, r));
    const secp256k1_pubkey *pts[2] = {&rPiss, &mG};
    EXPECT(secp256k1_ec_pubkey_combine(ctx, &C2, pts, 2));
  }

  unsigned char proof[SECP256K1_COMPACT_CLAWBACK_PROOF_SIZE];
  EXPECT(secp256k1_compact_clawback_prove(ctx, proof, amount, sk_iss, &P_iss,
                                          &C1, &C2, context_id));

  for (int i = 0; i < 64; i++)
    EXPECT(secp256k1_compact_clawback_verify(ctx, proof, amount, &P_iss, &C1,
                                             &C2, context_id));

  struct timespec ts, te;
  timespec_get(&ts, TIME_UTC);
  for (int i = 0; i < BENCH_ITERS; i++)
  {
    int ok = secp256k1_compact_clawback_verify(ctx, proof, amount, &P_iss, &C1,
                                               &C2, context_id);
    EXPECT(ok);
  }
  timespec_get(&te, TIME_UTC);
  printf("  compact_clawback              : %.4f ms/verify (%d iters)\n",
         elapsed_ms(ts, te) / BENCH_ITERS, BENCH_ITERS);
}

static void bench_compact_convertback(secp256k1_context *ctx)
{
  unsigned char sk_A[32], rho[32], context_id[32];
  const uint64_t balance = 99;
  random_scalar(ctx, sk_A);
  random_scalar(ctx, rho);
  EXPECT(RAND_bytes(context_id, 32) == 1);

  secp256k1_pubkey pk_A, H;
  EXPECT(secp256k1_ec_pubkey_create(ctx, &pk_A, sk_A));
  EXPECT(secp256k1_mpt_get_h_generator(ctx, &H));

  /* Build the convertback statement points. Mirror test_compact_convertback:
   *   B1 = r_bal*G; B2 = balance*G + r_bal*pk_A   (encryption of balance)
   *   PC_b = balance*G + rho*H                    (Pedersen with witness rho)
   * Note: r_bal is the encryption blinding (unrelated to rho, which is the
   * Pedersen blinding). */
  unsigned char r_bal[32];
  random_scalar(ctx, r_bal);

  secp256k1_pubkey B1;
  EXPECT(secp256k1_ec_pubkey_create(ctx, &B1, r_bal));

  secp256k1_pubkey B2;
  {
    secp256k1_pubkey rPk = pk_A;
    EXPECT(secp256k1_ec_pubkey_tweak_mul(ctx, &rPk, r_bal));
    secp256k1_pubkey vG;
    EXPECT(value_times_g_local(ctx, &vG, balance));
    const secp256k1_pubkey *pts[2] = {&vG, &rPk};
    EXPECT(secp256k1_ec_pubkey_combine(ctx, &B2, pts, 2));
  }

  secp256k1_pubkey PC_b;
  EXPECT(secp256k1_mpt_pedersen_commit(ctx, &PC_b, balance, rho));

  unsigned char proof[SECP256K1_COMPACT_CONVERTBACK_PROOF_SIZE];
  EXPECT(secp256k1_compact_convertback_prove(
      ctx, proof, balance, sk_A, rho, &pk_A, &B1, &B2, &PC_b, context_id));

  for (int i = 0; i < 64; i++)
    EXPECT(secp256k1_compact_convertback_verify(ctx, proof, &pk_A, &B1, &B2,
                                                &PC_b, context_id));

  struct timespec ts, te;
  timespec_get(&ts, TIME_UTC);
  for (int i = 0; i < BENCH_ITERS; i++)
  {
    int ok = secp256k1_compact_convertback_verify(ctx, proof, &pk_A, &B1, &B2,
                                                  &PC_b, context_id);
    EXPECT(ok);
  }
  timespec_get(&te, TIME_UTC);
  printf("  compact_convertback           : %.4f ms/verify (%d iters)\n",
         elapsed_ms(ts, te) / BENCH_ITERS, BENCH_ITERS);
}

static void bench_pok_sk(secp256k1_context *ctx)
{
  unsigned char sk[32], context_id[32];
  random_scalar(ctx, sk);
  EXPECT(RAND_bytes(context_id, 32) == 1);

  secp256k1_pubkey pk;
  EXPECT(secp256k1_ec_pubkey_create(ctx, &pk, sk));

  unsigned char proof[SECP256K1_POK_SK_PROOF_SIZE];
  EXPECT(secp256k1_mpt_pok_sk_prove(ctx, proof, &pk, sk, context_id));

  for (int i = 0; i < 64; i++)
    EXPECT(secp256k1_mpt_pok_sk_verify(ctx, proof, &pk, context_id));

  struct timespec ts, te;
  timespec_get(&ts, TIME_UTC);
  for (int i = 0; i < BENCH_ITERS; i++)
  {
    int ok = secp256k1_mpt_pok_sk_verify(ctx, proof, &pk, context_id);
    EXPECT(ok);
  }
  timespec_get(&te, TIME_UTC);
  printf("  pok_sk                        : %.4f ms/verify (%d iters)\n",
         elapsed_ms(ts, te) / BENCH_ITERS, BENCH_ITERS);
}

int main(void)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                    SECP256K1_CONTEXT_VERIFY);
  EXPECT(ctx);
  printf("[BENCH] compact-sigma verifiers, %d iters each\n", BENCH_ITERS);
  bench_compact_standard(ctx);
  bench_compact_clawback(ctx);
  bench_compact_convertback(ctx);
  bench_pok_sk(ctx);
  secp256k1_context_destroy(ctx);
  return 0;
}
