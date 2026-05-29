/* Tests for secp256k1_bulletproof_verify_batch_agg (issue #88).
 *
 * Covers:
 *   - n_proofs in {1, 2, 8} with uniform m=2
 *   - n_proofs=4 with mixed m in {1, 2}
 *   - positive and negative paths (tamper one proof's commitment, batch
 *     must reject)
 *   - throughput benchmark vs serial per-proof verify_agg for n_proofs=64
 */
#include "secp256k1_mpt.h"
#include "test_utils.h"
#include <secp256k1.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BP_VALUE_BITS 64
#define BP_TOTAL_BITS(m) ((size_t)(BP_VALUE_BITS * (m)))

static inline double elapsed_ms(struct timespec a, struct timespec b)
{
  return (b.tv_sec - a.tv_sec) * 1000.0 + (b.tv_nsec - a.tv_nsec) / 1e6;
}

/* Owns: m, value vector, blindings, commitments, proof bytes, context_id. */
typedef struct
{
  size_t m;
  uint64_t *values;
  unsigned char (*blindings)[32];
  secp256k1_pubkey *commitments;
  unsigned char *proof;
  size_t proof_len;
  unsigned char context_id[32];
} batch_proof;

static void batch_proof_free(batch_proof *p)
{
  if (!p)
    return;
  free(p->values);
  free(p->blindings);
  free(p->commitments);
  free(p->proof);
  memset(p, 0, sizeof(*p));
}

/* Build one proof with given m and value list. Always succeeds (panics on
 * any underlying failure since tests EXPECT). The caller is expected to
 * supply the right number of value slots (`m`). */
static void batch_proof_build(secp256k1_context *ctx, batch_proof *out,
                              size_t m, const uint64_t *values,
                              const secp256k1_pubkey *h_generator)
{
  memset(out, 0, sizeof(*out));
  out->m = m;
  out->values = (uint64_t *)malloc(m * sizeof(uint64_t));
  out->blindings = (unsigned char (*)[32])malloc(m * 32);
  out->commitments = (secp256k1_pubkey *)malloc(m * sizeof(secp256k1_pubkey));
  EXPECT(out->values && out->blindings && out->commitments);
  for (size_t j = 0; j < m; j++)
    out->values[j] = values[j];

  EXPECT(RAND_bytes(out->context_id, 32) == 1);

  for (size_t j = 0; j < m; j++)
  {
    random_scalar(ctx, out->blindings[j]);
    EXPECT(secp256k1_bulletproof_create_commitment(
        ctx, &out->commitments[j], out->values[j], out->blindings[j],
        h_generator));
  }

  unsigned char buf[4096];
  size_t plen = sizeof(buf);
  EXPECT(secp256k1_bulletproof_prove_agg(ctx, buf, &plen, out->values,
                                         (const unsigned char *)out->blindings,
                                         m, h_generator, out->context_id));
  out->proof = (unsigned char *)malloc(plen);
  EXPECT(out->proof);
  memcpy(out->proof, buf, plen);
  out->proof_len = plen;
}

/* Build the batch-call argument arrays from a list of batch_proofs.
 * Caller frees the returned arrays. */
static void collect_batch_args(const batch_proof *proofs, size_t n_proofs,
                               const unsigned char ***out_proof_bytes,
                               size_t **out_proof_lens,
                               const secp256k1_pubkey ***out_commit_vecs,
                               size_t **out_m_vec,
                               const unsigned char ***out_context_ids)
{
  const unsigned char **pb =
      (const unsigned char **)malloc(n_proofs * sizeof(*pb));
  size_t *plens = (size_t *)malloc(n_proofs * sizeof(*plens));
  const secp256k1_pubkey **cv =
      (const secp256k1_pubkey **)malloc(n_proofs * sizeof(*cv));
  size_t *mv = (size_t *)malloc(n_proofs * sizeof(*mv));
  const unsigned char **ctxids =
      (const unsigned char **)malloc(n_proofs * sizeof(*ctxids));
  EXPECT(pb && plens && cv && mv && ctxids);
  for (size_t i = 0; i < n_proofs; i++)
  {
    pb[i] = proofs[i].proof;
    plens[i] = proofs[i].proof_len;
    cv[i] = proofs[i].commitments;
    mv[i] = proofs[i].m;
    ctxids[i] = proofs[i].context_id;
  }
  *out_proof_bytes = pb;
  *out_proof_lens = plens;
  *out_commit_vecs = cv;
  *out_m_vec = mv;
  *out_context_ids = ctxids;
}

static void run_batch_case(secp256k1_context *ctx, const char *name,
                           const size_t *m_per_proof,
                           const uint64_t *const *vals, size_t n_proofs,
                           int run_bench)
{
  printf("\n[BATCH] %s (n_proofs = %zu)\n", name, n_proofs);

  /* Compute max_m and allocate shared G_vec/H_vec sized for it. */
  size_t max_m = 0;
  for (size_t i = 0; i < n_proofs; i++)
    if (m_per_proof[i] > max_m)
      max_m = m_per_proof[i];
  const size_t max_n = BP_TOTAL_BITS(max_m);

  secp256k1_pubkey h_generator;
  EXPECT(secp256k1_mpt_get_h_generator(ctx, &h_generator));

  secp256k1_pubkey *G_vec =
      (secp256k1_pubkey *)malloc(max_n * sizeof(secp256k1_pubkey));
  secp256k1_pubkey *H_vec =
      (secp256k1_pubkey *)malloc(max_n * sizeof(secp256k1_pubkey));
  EXPECT(G_vec && H_vec);
  EXPECT(secp256k1_mpt_get_generator_vector(ctx, G_vec, max_n,
                                            (const unsigned char *)"BP_G", 4));
  EXPECT(secp256k1_mpt_get_generator_vector(ctx, H_vec, max_n,
                                            (const unsigned char *)"BP_H", 4));

  batch_proof *proofs = (batch_proof *)calloc(n_proofs, sizeof(batch_proof));
  EXPECT(proofs);
  for (size_t i = 0; i < n_proofs; i++)
    batch_proof_build(ctx, &proofs[i], m_per_proof[i], vals[i], &h_generator);

  const unsigned char **arg_proofs;
  size_t *arg_lens;
  const secp256k1_pubkey **arg_commit_vecs;
  size_t *arg_m_vec;
  const unsigned char **arg_ctxids;
  collect_batch_args(proofs, n_proofs, &arg_proofs, &arg_lens, &arg_commit_vecs,
                     &arg_m_vec, &arg_ctxids);

  /* Positive: every proof must verify individually, and the batch
   * verifier must return 1. */
  for (size_t i = 0; i < n_proofs; i++)
  {
    const size_t n_i = BP_TOTAL_BITS(m_per_proof[i]);
    /* G_vec / H_vec for the smaller proof = prefix of the batch's vector. */
    EXPECT(secp256k1_bulletproof_verify_agg(
        ctx, G_vec, H_vec, proofs[i].proof, proofs[i].proof_len,
        proofs[i].commitments, m_per_proof[i], &h_generator,
        proofs[i].context_id));
    (void)n_i;
  }

  struct timespec ts, te;
  timespec_get(&ts, TIME_UTC);
  int ok = secp256k1_bulletproof_verify_batch_agg(
      ctx, G_vec, H_vec, arg_proofs, arg_lens, arg_commit_vecs, arg_m_vec,
      &h_generator, arg_ctxids, n_proofs);
  timespec_get(&te, TIME_UTC);
  EXPECT(ok);
  printf("  PASSED (batch positive)\n");
  if (run_bench)
  {
    double t_batch = elapsed_ms(ts, te);

    /* Serial reference: verify each proof one at a time. */
    struct timespec ss, se;
    timespec_get(&ss, TIME_UTC);
    for (size_t i = 0; i < n_proofs; i++)
    {
      ok = secp256k1_bulletproof_verify_agg(
          ctx, G_vec, H_vec, proofs[i].proof, proofs[i].proof_len,
          proofs[i].commitments, m_per_proof[i], &h_generator,
          proofs[i].context_id);
      EXPECT(ok);
    }
    timespec_get(&se, TIME_UTC);
    double t_serial = elapsed_ms(ss, se);

    printf("  [BENCH] batch:  %.3f ms (%.3f ms/proof)\n", t_batch,
           t_batch / (double)n_proofs);
    printf("  [BENCH] serial: %.3f ms (%.3f ms/proof)\n", t_serial,
           t_serial / (double)n_proofs);
    printf("  [BENCH] speedup: %.2fx\n", t_serial / t_batch);
  }

  /* Negative: replace proofs[last].commitment with a fresh commitment to
   * a different value. The batched MSM must return identity only if every
   * proof verifies, so this must reject. */
  {
    /* Swap the last commitment to a wrong value (+1 with wraparound). */
    unsigned char bad_blinding[32];
    random_scalar(ctx, bad_blinding);
    secp256k1_pubkey orig_last =
        proofs[n_proofs - 1].commitments[m_per_proof[n_proofs - 1] - 1];
    uint64_t bad_value =
        proofs[n_proofs - 1].values[m_per_proof[n_proofs - 1] - 1] == UINT64_MAX
            ? proofs[n_proofs - 1].values[m_per_proof[n_proofs - 1] - 1] - 1
            : proofs[n_proofs - 1].values[m_per_proof[n_proofs - 1] - 1] + 1;
    EXPECT(secp256k1_bulletproof_create_commitment(
        ctx, &proofs[n_proofs - 1].commitments[m_per_proof[n_proofs - 1] - 1],
        bad_value, bad_blinding, &h_generator));

    /* The arg arrays already point to the (now-mutated) commitments[]. */
    ok = secp256k1_bulletproof_verify_batch_agg(
        ctx, G_vec, H_vec, arg_proofs, arg_lens, arg_commit_vecs, arg_m_vec,
        &h_generator, arg_ctxids, n_proofs);
    EXPECT(ok == 0);
    printf("  PASSED (batch negative: tampered last commitment rejected)\n");

    /* Restore for cleanup. */
    proofs[n_proofs - 1].commitments[m_per_proof[n_proofs - 1] - 1] = orig_last;
  }

  free(arg_proofs);
  free(arg_lens);
  free(arg_commit_vecs);
  free(arg_m_vec);
  free(arg_ctxids);
  for (size_t i = 0; i < n_proofs; i++)
    batch_proof_free(&proofs[i]);
  free(proofs);
  free(G_vec);
  free(H_vec);
}

int main(void)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                    SECP256K1_CONTEXT_VERIFY);
  EXPECT(ctx != NULL);

  /* n_proofs = 1, m = 2 -- exercises the batch path with the minimum. */
  {
    uint64_t v0[] = {0, 1};
    const uint64_t *vals[] = {v0};
    size_t mp[] = {2};
    run_batch_case(ctx, "Single proof through batch path", mp, vals, 1, 0);
  }

  /* n_proofs = 2, both m=2. */
  {
    uint64_t v0[] = {0, 1};
    uint64_t v1[] = {1, UINT64_MAX};
    const uint64_t *vals[] = {v0, v1};
    size_t mp[] = {2, 2};
    run_batch_case(ctx, "Two proofs, m=2 each", mp, vals, 2, 0);
  }

  /* n_proofs = 4, mixed m in {1, 2}. */
  {
    uint64_t v0[] = {7};
    uint64_t v1[] = {0, 1};
    uint64_t v2[] = {42};
    uint64_t v3[] = {UINT64_MAX, 0};
    const uint64_t *vals[] = {v0, v1, v2, v3};
    size_t mp[] = {1, 2, 1, 2};
    run_batch_case(ctx, "Four proofs, mixed m in {1, 2}", mp, vals, 4, 0);
  }

  /* n_proofs = 8, uniform m=2 (small batch). */
  {
    size_t mp[8] = {2, 2, 2, 2, 2, 2, 2, 2};
    uint64_t v[8][2] = {{0, 1}, {2, 3},   {4, 5},   {6, 7},
                        {8, 9}, {10, 11}, {12, 13}, {14, 15}};
    const uint64_t *vals[8];
    for (int i = 0; i < 8; i++)
      vals[i] = v[i];
    run_batch_case(ctx, "Eight proofs, m=2", mp, vals, 8, 1);
  }

  /* n_proofs = 64, uniform m=2 -- benchmark target from #88 ("Realistic gain
   * at n=64"). */
  {
    size_t *mp = (size_t *)malloc(64 * sizeof(size_t));
    uint64_t (*v)[2] = (uint64_t (*)[2])malloc(64 * 2 * sizeof(uint64_t));
    const uint64_t **vals = (const uint64_t **)malloc(64 * sizeof(uint64_t *));
    EXPECT(mp && v && vals);
    for (int i = 0; i < 64; i++)
    {
      mp[i] = 2;
      v[i][0] = (uint64_t)i;
      v[i][1] = (uint64_t)(2 * i + 1);
      vals[i] = v[i];
    }
    run_batch_case(ctx, "Sixty-four proofs, m=2", mp, vals, 64, 1);
    free(mp);
    free(v);
    free(vals);
  }

  secp256k1_context_destroy(ctx);
  printf("\n[TEST] All batched-Bulletproof tests completed successfully\n");
  return 0;
}
