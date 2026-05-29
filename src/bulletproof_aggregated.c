/**
 * @file bulletproof_aggregated.c
 * @brief Aggregated Bulletproof Range Proofs (Logarithmic Size).
 *
 * This module implements non-interactive zero-knowledge range proofs based on
 * the Bulletproofs protocol (Bünz et al., 2018). It allows a prover to
 * demonstrate that a committed value lies within the range \f$ [0, 2^{64}) \f$
 * without revealing the value itself.
 *
 * @details
 * **Protocol Overview:**
 * The implementation follows the standard single-value and aggregated
 * Bulletproof logic:
 * 1. **Pedersen Commitment:** The value \f$ v \f$ is committed as \f$ V = v
 * \cdot G + r \cdot H \f$.
 * 2. **Bit Decomposition:** The value is decomposed into 64 bits \f$
 * \mathbf{a}_L \f$.
 * 3. **Polynomial Commitment:** The prover commits to polynomials defining the
 * range constraints.
 * 4. **Inner Product Argument (IPA):** A recursive argument reduces the proof
 * size to logarithmic complexity \f$ \mathcal{O}(\log n) \f$.
 *
 * **Aggregation:**
 * This implementation supports aggregating \f$ m \f$ proofs into a single
 * verification process. The total vector length is \f$ n = 64 \cdot m \f$.
 * Aggregation significantly reduces the on-chain footprint compared to \f$ m
 * \f$ individual proofs.
 *
 * **Fiat-Shamir Transcript:**
 * The non-interactive challenge generation follows a strict dependency chain to
 * ensure binding and special soundness:
 * - \f$ \mathcal{T}_0 \f$: Domain Tag || ContextID || Value Commitments (\f$ V
 * \f$)
 * - \f$ y, z \f$: Derived from \f$ \mathcal{T}_0 \parallel A \parallel S \f$
 * - \f$ x \f$: Derived from \f$ z \parallel T_1 \parallel T_2 \f$
 * - \f$ \mu \f$: Derived from \f$ x \f$ (for the IPA)
 *
 * **Dependencies:**
 * - Relies on `secp256k1` for elliptic curve arithmetic.
 * - Uses `SHA256` for the Fiat-Shamir transformation.
 *
 * @see [Spec (ConfidentialMPT_20260201.pdf) Section 3.3.6 Range Proof (using
 * Bulletproofs)]
 */
#include "mpt_internal.h"
#include "mpt_msm.h"
#include "secp256k1_mpt.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <secp256k1.h>
#include <stdlib.h>
#include <string.h>

/* Bit-size of each value proved in range */
#define BP_VALUE_BITS 64

/* Compute total vector length for aggregated Bulletproof */
#define BP_TOTAL_BITS(m) ((size_t)(BP_VALUE_BITS * (m)))

/* Maximum number of values that can be aggregated in a single proof
 * to prevent excessive memory allocation. */
#define BP_MAX_VALUES 4

/* Compute IPA rounds = log2(total_bits) */
static inline size_t bp_ipa_rounds(size_t total_bits)
{
  size_t r = 0;
  while (total_bits > 1)
  {
    total_bits >>= 1;
    r++;
  }
  return r;
}

/* compute_amount_point is provided by mpt_internal.h.
 * It returns 0 for amount == 0 because libsecp cannot represent the
 * point at infinity.  secp256k1_mpt_pedersen_commit handles the
 * v == 0 case explicitly before reaching this helper. */
/**
 * Safely adds a point to an accumulator (acc += term).
 * Handles uninitialized accumulators by assignment instead of addition.
 */
static int add_term(const secp256k1_context *ctx, secp256k1_pubkey *acc,
                    int *acc_inited, const secp256k1_pubkey *term)
{
  if (!(*acc_inited))
  {
    *acc = *term;
    *acc_inited = 1;
    return 1;
  }
  else
  {
    const secp256k1_pubkey *pts[2] = {acc, term};
    secp256k1_pubkey sum;
    if (!secp256k1_ec_pubkey_combine(ctx, &sum, pts, 2))
      return 0;
    *acc = sum;
    return 1;
  }
}

/**
 * Computes modular subtraction of two scalars: res = a - b (mod q).
 */
static void secp256k1_mpt_scalar_sub(unsigned char *res, const unsigned char *a,
                                     const unsigned char *b)
{
  unsigned char neg_b[32];
  memcpy(neg_b, b, 32);
  secp256k1_mpt_scalar_negate(neg_b, neg_b); /* neg_b = -b mod q */
  secp256k1_mpt_scalar_add(res, a, neg_b);   /* res = a + (-b) */
  OPENSSL_cleanse(neg_b, 32);
}
/**
 * Computes the modular dot product c = <a, b> = sum(a[i] * b[i]) mod q.
 * This function calculates the inner product of two scalar vectors.
 * ctx       The context.
 * out       Output 32-byte scalar (the inner product result).
 * a         Input scalar vector A (n * 32 bytes).
 * b         Input scalar vector B (n * 32 bytes).
 * n         The length of the vectors.
 * 1 on success, 0 on failure.
 */
int secp256k1_bulletproof_ipa_dot(const secp256k1_context *ctx,
                                  unsigned char *out, const unsigned char *a,
                                  const unsigned char *b, size_t n)
{
  (void)ctx;
  unsigned char acc[32] = {0};
  unsigned char term[32];

  for (size_t i = 0; i < n; i++)
  {
    secp256k1_mpt_scalar_mul(term, a + i * 32, b + i * 32);
    secp256k1_mpt_scalar_add(acc, acc, term);
  }
  memcpy(out, acc, 32);
  return 1;
}
/**
 * Internal helper for multi-scalar multiplication.
 * Adds a point to the accumulator.
 */

int secp256k1_bulletproof_add_point_to_accumulator(const secp256k1_context *ctx,
                                                   secp256k1_pubkey *acc,
                                                   const secp256k1_pubkey *term)
{
  const secp256k1_pubkey *points[2] = {acc, term};
  secp256k1_pubkey temp_sum;

  if (secp256k1_ec_pubkey_combine(ctx, &temp_sum, points, 2) != 1)
    return 0;
  *acc = temp_sum;
  return 1;
}

static int scalar_is_zero(const unsigned char s[32])
{
  unsigned char b = 0;
  for (int i = 0; i < 32; i++)
  {
    b |= s[i];
  }
  return (b == 0) ? 1 : 0;
}

/**
 * Computes Multiscalar Multiplication (MSM): R = sum(s[i] * P[i]).
 * This function is called in two contexts:
 * 1. secp256k1_bulletproof_ipa_compute_LR (prover only):
 * - Round 0: scalars are a_L/b_R in {0,1}, derived from the prover's secret.
 * - Rounds 1+: scalars are general 256-bit folded values.
 * Timing varies with the scalar's Hamming weight. Because the prover
 * operates on their own secret, exploitation requires an external attacker
 * to have precise timing observation over the prover's local execution
 * environment.
 * 2. fold_generators (verifier) and calculate_commitment_term (prover):
 * Scalars are either public Fiat-Shamir values or sparse bit vectors.
 * There is no secret timing concern in these contexts.
 */

int secp256k1_bulletproof_ipa_msm(const secp256k1_context *ctx,
                                  secp256k1_pubkey *r_out,
                                  const secp256k1_pubkey *points,
                                  const unsigned char *scalars, size_t n)
{
  secp256k1_pubkey acc;
  memset(&acc, 0, sizeof(acc));
  int initialized = 0;

  for (size_t i = 0; i < n; ++i)
  {
    unsigned char s_tmp[32];
    memcpy(s_tmp, scalars + i * 32, 32);

    if (scalar_is_zero(s_tmp))
    {
      continue;
    }

    secp256k1_pubkey term = points[i];
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &term, s_tmp))
      return 0;

    if (!add_term(ctx, &acc, &initialized, &term))
      return 0;
  }

  if (!initialized)
    return 0;

  *r_out = acc;
  return 1;
}

/* Try to add MSM(points, scalars) into acc.
 * If MSM is all-zero, do nothing and succeed.
 */
static int msm_try_add(const secp256k1_context *ctx, secp256k1_pubkey *acc,
                       int *acc_inited, const secp256k1_pubkey *points,
                       const unsigned char *scalars, size_t n)
{
  secp256k1_pubkey tmp;

  /* MSM returns 0 iff all scalars are zero.
   * In that case, we have nothing to add, so we return success (1). */
  if (!secp256k1_bulletproof_ipa_msm(ctx, &tmp, points, scalars, n))
  {
    return 1;
  }
  return add_term(ctx, acc, acc_inited, &tmp);
}

/**
 * Computes component-wise: result[i] = a[i] * b[i] (Hadamard product)
 */
void scalar_vector_mul(const secp256k1_context *ctx, unsigned char res[][32],
                       unsigned char a[][32], unsigned char b[][32], size_t n)
{
  (void)ctx;
  for (size_t i = 0; i < n; i++)
  {
    secp256k1_mpt_scalar_mul(res[i], a[i], b[i]);
  }
}

/**
 * Computes component-wise: result[i] = a[i] + b[i]
 */
void scalar_vector_add(const secp256k1_context *ctx, unsigned char res[][32],
                       unsigned char a[][32], unsigned char b[][32], size_t n)
{
  (void)ctx;
  for (size_t i = 0; i < n; i++)
  {
    secp256k1_mpt_scalar_add(res[i], a[i], b[i]);
  }
}

/**
 * Fills a vector with powers of a scalar: [1, y, y^2, ..., y^{n-1}]
 */
void scalar_vector_powers(const secp256k1_context *ctx, unsigned char res[][32],
                          const unsigned char *y, size_t n)
{
  (void)ctx;
  if (n == 0)
    return;

  unsigned char one[32] = {0};
  one[31] = 1;
  memcpy(res[0], one, 32);

  for (size_t i = 1; i < n; i++)
  {
    secp256k1_mpt_scalar_mul(res[i], res[i - 1], y);
  }
}
/**
 * Compute y^i for small i.
 */
static void scalar_pow_u32(const secp256k1_context *ctx,
                           unsigned char y_pow_out[32],
                           const unsigned char y[32], unsigned int i)
{
  (void)ctx;
  unsigned char one[32] = {0};
  one[31] = 1;
  memcpy(y_pow_out, one, 32);

  while (i--)
  {
    secp256k1_mpt_scalar_mul(y_pow_out, y_pow_out, y);
  }
}
/**
 * z_j2 = z^(j+2) for j = 0..m-1 (small exponent)
 */
static void compute_z_pows_j2(const secp256k1_context *ctx,
                              unsigned char (*z_j2)[32], /* m x 32 */
                              const unsigned char z[32], size_t m)
{
  for (size_t j = 0; j < m; j++)
  {
    scalar_pow_u32(ctx, z_j2[j], z, (unsigned int)(j + 2));
  }
}

/**
 * Computes per-block y-power sums for aggregated Bulletproofs.
 * For block j (0-based):
 *   y_block_sum[j] = sum_{i=0}^{63} y^{64*j + i}
 * Also computes:
 *   two_sum = sum_{i=0}^{63} 2^i
 * These are used by the caller to construct delta(y, z).
 */
static void
compute_delta_scalars(const secp256k1_context *ctx,
                      unsigned char (*y_block_sum)[32], /* m blocks */
                      unsigned char two_sum[32], const unsigned char y[32],
                      size_t m)
{
  (void)ctx;

  unsigned char one[32] = {0};
  unsigned char y_pow[32];
  unsigned char two_pow[32];

  one[31] = 1;

  /* Compute two_sum = sum_{i=0}^{63} 2^i */
  memset(two_sum, 0, 32);
  memcpy(two_pow, one, 32);
  for (size_t i = 0; i < 64; i++)
  {
    secp256k1_mpt_scalar_add(two_sum, two_sum, two_pow);
    secp256k1_mpt_scalar_add(two_pow, two_pow, two_pow);
  }

  /* Compute y_block_sum[j] = sum_{i=0}^{63} y^{64j + i} */
  memcpy(y_pow, one, 32); /* y^0 */

  for (size_t j = 0; j < m; j++)
  {
    memset(y_block_sum[j], 0, 32);

    for (size_t i = 0; i < 64; i++)
    {
      secp256k1_mpt_scalar_add(y_block_sum[j], y_block_sum[j], y_pow);
      secp256k1_mpt_scalar_mul(y_pow, y_pow, y); /* advance y^k */
    }
  }
}
/**
 * u_flat and uinv_flat are arrays of length (rounds * 32):
 *   u_j     = u_flat    + 32*j
 *   u_j_inv = uinv_flat + 32*j
 */
int fold_generators(const secp256k1_context *ctx, secp256k1_pubkey *final_point,
                    const secp256k1_pubkey *generators,
                    const unsigned char *u_flat, const unsigned char *uinv_flat,
                    size_t n, size_t rounds,
                    int is_H /* 0 = G folding, 1 = H folding */
)
{
  /* n must be power-of-two and rounds must match log2(n) */
  if (n == 0 || (n & (n - 1)) != 0)
    return 0;
  if (((size_t)1 << rounds) != n)
    return 0;

  /* Allocate scalars for MSM: n * 32 bytes */
  unsigned char *s_flat = (unsigned char *)malloc(n * 32);
  if (!s_flat)
    return 0;

  unsigned char current_s[32];
  int ok = 0;

  for (size_t i = 0; i < n; i++)
  {
    /* current_s = 1 */
    memset(current_s, 0, 32);
    current_s[31] = 1;

    for (size_t j = 0; j < rounds; j++)
    {
      /* bit from MSB to LSB across 'rounds' bits */
      int bit = (int)((i >> (rounds - 1 - j)) & 1);

      const unsigned char *uj = u_flat + 32 * j;
      const unsigned char *ujinv = uinv_flat + 32 * j;

      if (!is_H)
      {
        /* G folding: bit 0 -> u_inv, bit 1 -> u */
        secp256k1_mpt_scalar_mul(current_s, current_s, bit ? uj : ujinv);
      }
      else
      {
        /* H folding: bit 0 -> u, bit 1 -> u_inv */
        secp256k1_mpt_scalar_mul(current_s, current_s, bit ? ujinv : uj);
      }
    }

    memcpy(s_flat + (i * 32), current_s, 32);
  }

  ok = secp256k1_bulletproof_ipa_msm(ctx, final_point, generators, s_flat, n);

  OPENSSL_cleanse(current_s, 32);
  OPENSSL_cleanse(s_flat, n * 32);
  free(s_flat);

  return ok;
}
/*
 * Apply verifier-side IPA updates to P for `rounds` rounds.
 * Update rule per round i:
 *   P <- P + (u_i^2) * L_i + (u_i^{-2}) * R_i
 * u_flat / uinv_flat are (rounds * 32)-byte arrays:
 *   u_i    = u_flat    + 32*i
 *   u_iinv = uinv_flat + 32*i
 */
int apply_ipa_folding_to_P(const secp256k1_context *ctx, secp256k1_pubkey *P,
                           const secp256k1_pubkey *L_vec,
                           const secp256k1_pubkey *R_vec,
                           const unsigned char *u_flat,
                           const unsigned char *uinv_flat, size_t rounds)
{
  unsigned char u_sq[32], uinv_sq[32];
  secp256k1_pubkey tL, tR;
  const secp256k1_pubkey *pts[3];

  for (size_t i = 0; i < rounds; i++)
  {
    const unsigned char *ui = u_flat + 32 * i;
    const unsigned char *uiinv = uinv_flat + 32 * i;

    /* u_sq = u_i^2, uinv_sq = (u_i^{-1})^2 = u_i^{-2} */
    secp256k1_mpt_scalar_mul(u_sq, ui, ui);
    secp256k1_mpt_scalar_mul(uinv_sq, uiinv, uiinv);

    /* tL = (u_i^2) * L_i */
    tL = L_vec[i];
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &tL, u_sq))
    {
      OPENSSL_cleanse(u_sq, 32);
      OPENSSL_cleanse(uinv_sq, 32);
      return 0;
    }

    /* tR = (u_i^{-2}) * R_i */
    tR = R_vec[i];
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &tR, uinv_sq))
    {
      OPENSSL_cleanse(u_sq, 32);
      OPENSSL_cleanse(uinv_sq, 32);
      return 0;
    }

    /* P <- P + tL + tR */
    pts[0] = P;
    pts[1] = &tL;
    pts[2] = &tR;

    secp256k1_pubkey newP;
    if (!secp256k1_ec_pubkey_combine(ctx, &newP, pts, 3))
    {
      OPENSSL_cleanse(u_sq, 32);
      OPENSSL_cleanse(uinv_sq, 32);
      return 0;
    }
    *P = newP;
  }

  OPENSSL_cleanse(u_sq, 32);
  OPENSSL_cleanse(uinv_sq, 32);
  return 1;
}

/**
 * Computes the cross-term commitments L and R.
 * L = <a_L, G_R> + <b_R, H_L> + c_L * ux * g
 * R = <a_R, G_L> + <b_L, H_R> + c_R * ux * g
 * ctx       The context.
 * L         Output: Commitment point L_j.
 * R         Output: Commitment point R_j.
 * half_n    Length of the input vector halves.
 * g         The blinding generator point (Pk_base in our case).
 * return    1 on success, 0 on failure.
 */

int secp256k1_bulletproof_ipa_compute_LR(
    const secp256k1_context *ctx, secp256k1_pubkey *L, secp256k1_pubkey *R,
    const unsigned char *a_L, const unsigned char *a_R,
    const unsigned char *b_L, const unsigned char *b_R,
    const secp256k1_pubkey *G_L, const secp256k1_pubkey *G_R,
    const secp256k1_pubkey *H_L, const secp256k1_pubkey *H_R,
    const secp256k1_pubkey *U, const unsigned char *ux, size_t half_n)
{
  unsigned char cL[32], cR[32];
  unsigned char cLux[32], cRux[32];

  secp256k1_pubkey acc, term;
  int acc_inited; /* Tracks if acc contains a valid point */

  /* cL = <a_L, b_R>, cR = <a_R, b_L> */
  if (!secp256k1_bulletproof_ipa_dot(ctx, cL, a_L, b_R, half_n))
    return 0;
  if (!secp256k1_bulletproof_ipa_dot(ctx, cR, a_R, b_L, half_n))
    return 0;

  /* ---------------- L Calculation ---------------- */
  acc_inited = 0;

  /* Try adding terms. correct logic updates acc_inited to 1 */
  if (!msm_try_add(ctx, &acc, &acc_inited, G_R, a_L, half_n))
    goto cleanup;
  if (!msm_try_add(ctx, &acc, &acc_inited, H_L, b_R, half_n))
    goto cleanup;

  secp256k1_mpt_scalar_mul(cLux, cL, ux);
  if (!scalar_is_zero(cLux))
  {
    term = *U;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &term, cLux))
      goto cleanup;
    if (!add_term(ctx, &acc, &acc_inited, &term))
      goto cleanup;
  }

  /* Check initialization explicitly */
  if (acc_inited == 0)
  {
    /* L resulted in Infinity. This is theoretically possible but invalid for
     * serialization. We cannot proceed. */
    goto cleanup;
  }
  *L = acc;

  /* ---------------- R Calculation ---------------- */
  acc_inited = 0;

  if (!msm_try_add(ctx, &acc, &acc_inited, G_L, a_R, half_n))
    goto cleanup;
  if (!msm_try_add(ctx, &acc, &acc_inited, H_R, b_L, half_n))
    goto cleanup;

  secp256k1_mpt_scalar_mul(cRux, cR, ux);
  if (!scalar_is_zero(cRux))
  {
    term = *U;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &term, cRux))
      goto cleanup;
    if (!add_term(ctx, &acc, &acc_inited, &term))
      goto cleanup;
  }

  if (acc_inited == 0)
  {
    goto cleanup;
  }
  *R = acc;

  OPENSSL_cleanse(cL, 32);
  OPENSSL_cleanse(cR, 32);
  OPENSSL_cleanse(cLux, 32);
  OPENSSL_cleanse(cRux, 32);
  return 1;

cleanup:
  OPENSSL_cleanse(cL, 32);
  OPENSSL_cleanse(cR, 32);
  OPENSSL_cleanse(cLux, 32);
  OPENSSL_cleanse(cRux, 32);
  return 0;
}
/**
 * One IPA compression step (in-place).
 *
 * Input vectors are length (2*half_n):
 *   a[0..2*half_n-1], b[0..2*half_n-1],
 *   G[0..2*half_n-1], H[0..2*half_n-1]
 *
 * After return, the first half contains folded vectors:
 *   a'[0..half_n-1], b'[0..half_n-1], G'[0..half_n-1], H'[0..half_n-1]
 *
 * Formulas (matching prover/verifier conventions):
 *   a'[i] = aL[i]*x + aR[i]*x_inv
 *   b'[i] = bL[i]*x_inv + bR[i]*x
 *   G'[i] = GL[i]*x_inv + GR[i]*x
 *   H'[i] = HL[i]*x + HR[i]*x_inv
 */
int secp256k1_bulletproof_ipa_compress_step(const secp256k1_context *ctx,
                                            unsigned char *a, unsigned char *b,
                                            secp256k1_pubkey *G,
                                            secp256k1_pubkey *H, size_t half_n,
                                            const unsigned char *x,
                                            const unsigned char *x_inv)
{
  size_t i;
  int ok = 0;

  unsigned char t1[32], t2[32];
  secp256k1_pubkey left, right;
  const secp256k1_pubkey *pts[2];

  if (ctx == NULL || a == NULL || b == NULL || G == NULL || H == NULL)
    return 0;
  if (half_n == 0)
    return 0;

  /* x and x_inv must be valid non-zero scalars */
  if (secp256k1_ec_seckey_verify(ctx, x) != 1)
    return 0;
  if (secp256k1_ec_seckey_verify(ctx, x_inv) != 1)
    return 0;

  for (i = 0; i < half_n; ++i)
  {
    unsigned char *aL = a + (i * 32);
    unsigned char *aR = a + ((i + half_n) * 32);

    unsigned char *bL = b + (i * 32);
    unsigned char *bR = b + ((i + half_n) * 32);

    /* a'[i] = aL*x + aR*x_inv */
    secp256k1_mpt_scalar_mul(t1, aL, x);
    secp256k1_mpt_scalar_mul(t2, aR, x_inv);
    secp256k1_mpt_scalar_add(aL, t1, t2);

    /* b'[i] = bL*x_inv + bR*x */
    secp256k1_mpt_scalar_mul(t1, bL, x_inv);
    secp256k1_mpt_scalar_mul(t2, bR, x);
    secp256k1_mpt_scalar_add(bL, t1, t2);

    /* G'[i] = GL*x_inv + GR*x */
    left = G[i];
    right = G[i + half_n];
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &left, x_inv))
      goto cleanup;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &right, x))
      goto cleanup;
    pts[0] = &left;
    pts[1] = &right;
    if (!secp256k1_ec_pubkey_combine(ctx, &G[i], pts, 2))
      goto cleanup;

    /* H'[i] = HL*x + HR*x_inv */
    left = H[i];
    right = H[i + half_n];
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &left, x))
      goto cleanup;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &right, x_inv))
      goto cleanup;
    pts[0] = &left;
    pts[1] = &right;
    if (!secp256k1_ec_pubkey_combine(ctx, &H[i], pts, 2))
      goto cleanup;
  }

  ok = 1;

cleanup:
  OPENSSL_cleanse(t1, 32);
  OPENSSL_cleanse(t2, 32);
  return ok;
}

/*
 * ux is the fixed IPA binding scalar.
 *
 * It MUST be derived exactly once from:
 *     ux = H(commit_inp || <a,b>)
 *
 * and reused consistently throughout the IPA:
 *   - L/R cross-term construction
 *   - final (a·b·ux)·g term
 *
 * It MUST NOT depend on per-round challenges (u_i),
 * and MUST be identical for prover and verifier.
 */
int derive_ipa_binding_challenge(const secp256k1_context *ctx,
                                 unsigned char *ux_out,
                                 const unsigned char *commit_inp_32,
                                 const unsigned char *dot_32)
{
  unsigned char hash_input[64];
  unsigned char hash_output[32];
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  int ok = 0;

  if (!mdctx)
    return 0;

  /* 1. Build hash input = commit_inp || dot */
  memcpy(hash_input, commit_inp_32, 32);
  memcpy(hash_input + 32, dot_32, 32);

  /* 2. Hash */
  if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1)
    goto cleanup;
  if (EVP_DigestUpdate(mdctx, hash_input, 64) != 1)
    goto cleanup;
  if (EVP_DigestFinal_ex(mdctx, hash_output, NULL) != 1)
    goto cleanup;

  /* 3. Reduce hash to a valid scalar */
  secp256k1_mpt_scalar_reduce32(ux_out, hash_output);

  /* 4. Verify (Sanity check) */
  if (secp256k1_ec_seckey_verify(ctx, ux_out) != 1)
    goto cleanup;

  ok = 1;

cleanup:
  EVP_MD_CTX_free(mdctx);
  return ok;
}

/**
 * Derive u = H(last_challenge || L || R) reduced to a valid scalar.
 * IMPORTANT: use the SAME exact logic in verifier.
 */

int derive_ipa_round_challenge(const secp256k1_context *ctx,
                               unsigned char u_out[32],
                               const unsigned char last_challenge[32],
                               const secp256k1_pubkey *L,
                               const secp256k1_pubkey *R)
{
  unsigned char L_ser[33], R_ser[33];
  size_t len;
  unsigned char hash[32];
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  int ok = 0;

  if (!mdctx)
    return 0;

  len = 33;
  if (!secp256k1_ec_pubkey_serialize(ctx, L_ser, &len, L,
                                     SECP256K1_EC_COMPRESSED) ||
      len != 33)
    goto cleanup;

  len = 33;
  if (!secp256k1_ec_pubkey_serialize(ctx, R_ser, &len, R,
                                     SECP256K1_EC_COMPRESSED) ||
      len != 33)
    goto cleanup;

  if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1)
    goto cleanup;
  if (EVP_DigestUpdate(mdctx, last_challenge, 32) != 1)
    goto cleanup;
  if (EVP_DigestUpdate(mdctx, L_ser, 33) != 1)
    goto cleanup;
  if (EVP_DigestUpdate(mdctx, R_ser, 33) != 1)
    goto cleanup;
  if (EVP_DigestFinal_ex(mdctx, hash, NULL) != 1)
    goto cleanup;

  secp256k1_mpt_scalar_reduce32(hash, hash);
  memcpy(u_out, hash, 32);

  if (secp256k1_ec_seckey_verify(ctx, u_out) != 1)
    goto cleanup;

  ok = 1;

cleanup:
  EVP_MD_CTX_free(mdctx);
  return ok;
}

/**
 * Runs the Inner Product Argument (IPA) prover.
 * Recursively folds vectors G, H, a, and b into a single final term,
 * producing log2(n) pairs of cross-term commitments (stored in L_out/R_out).
 * Returns 1 on success, 0 on failure.
 */
int secp256k1_bulletproof_run_ipa_prover(
    const secp256k1_context *ctx, const secp256k1_pubkey *g,
    secp256k1_pubkey *G_vec, secp256k1_pubkey *H_vec, unsigned char *a_vec,
    unsigned char *b_vec, size_t n, const unsigned char ipa_transcript_id[32],
    const unsigned char ux_scalar[32], secp256k1_pubkey *L_out,
    secp256k1_pubkey *R_out, size_t max_rounds, size_t *rounds_out,
    unsigned char a_final[32], unsigned char b_final[32])
{
  size_t rounds = 0;
  size_t cur_n = n;
  int ok = 0;

  unsigned char u_scalar[32], u_inv[32];
  unsigned char last_challenge[32];

  /* Validate n is power of 2 */
  if (n == 0 || (n & (n - 1)) != 0)
    return 0;

  /* rounds = log2(n) */
  while (cur_n > 1)
  {
    cur_n >>= 1;
    rounds++;
  }
  cur_n = n;

  /* Bounds check (CRITICAL for aggregated proofs) */
  if (rounds > max_rounds)
    return 0;

  /* Seed transcript */
  memcpy(last_challenge, ipa_transcript_id, 32);

  for (size_t r = 0; r < rounds; ++r)
  {
    size_t half_n = cur_n >> 1;
    secp256k1_pubkey Lr, Rr;

    /* 1) Compute cross-term commitments Lr, Rr */
    if (!secp256k1_bulletproof_ipa_compute_LR(
            ctx, &Lr, &Rr, a_vec, a_vec + half_n * 32, b_vec,
            b_vec + half_n * 32, G_vec, G_vec + half_n, H_vec, H_vec + half_n,
            g, ux_scalar, half_n))
      goto cleanup;

    /* 2) Store L/R */
    L_out[r] = Lr;
    R_out[r] = Rr;

    /* 3) Fiat–Shamir round challenge u_r */
    if (!derive_ipa_round_challenge(ctx, u_scalar, last_challenge, &Lr, &Rr))
      goto cleanup;

    /* 4) u_r^{-1} */
    secp256k1_mpt_scalar_inverse(u_inv, u_scalar);
    if (!secp256k1_ec_seckey_verify(ctx, u_inv))
      goto cleanup;

    /* 5) Update transcript chaining state */
    memcpy(last_challenge, u_scalar, 32);

    /* 6) Fold vectors in-place */
    if (!secp256k1_bulletproof_ipa_compress_step(
            ctx, a_vec, b_vec, G_vec, H_vec, half_n, u_scalar, u_inv))
      goto cleanup;

    cur_n = half_n;
  }

  /* Final folded scalars */
  memcpy(a_final, a_vec, 32);
  memcpy(b_final, b_vec, 32);

  if (rounds_out)
    *rounds_out = rounds;
  ok = 1;

cleanup:
  OPENSSL_cleanse(u_scalar, 32);
  OPENSSL_cleanse(u_inv, 32);
  return ok;
}

/* The previous static helper ipa_verify_explicit() was replaced by the
 * consolidated single-MSM check (see bp_verify_consolidated_msm below).
 * The corresponding round-by-round IPA-verify path is still exercised by
 * tests/test_ipa.c, which carries its own implementation. */
/**
 * Phase 1, Step 3 (Aggregated):
 * Compute al, ar, sl, sr vectors for ONE value block inside an aggregated
 * proof.
 *
 * The caller is responsible for:
 *   - allocating al/ar/sl/sr of length (BP_VALUE_BITS * m)
 *   - calling this once per value with block_index = j
 *
 * Block layout:
 *   bits for value j occupy indices:
 *     [BP_VALUE_BITS * j .. BP_VALUE_BITS * j + BP_VALUE_BITS - 1]
 */
int secp256k1_bulletproof_compute_vectors_block(
    const secp256k1_context *ctx, uint64_t value,
    size_t block_index, /* j-th value */
    unsigned char *al,  /* length = BP_TOTAL_BITS(m) * 32 */
    unsigned char *ar, unsigned char *sl, unsigned char *sr)
{
  const size_t offset = BP_VALUE_BITS * block_index;

  /* Scalars */
  unsigned char one[32] = {0};
  unsigned char minus_one[32];

  one[31] = 1;
  memcpy(minus_one, one, 32);
  secp256k1_mpt_scalar_negate(minus_one, minus_one);

  /* ---- 1. Encode value bits into al/ar ---- */
  for (size_t i = 0; i < BP_VALUE_BITS; i++)
  {
    size_t idx = offset + i;
    unsigned char bit = (unsigned char)((value >> i) & 1);
    unsigned char mask =
        (unsigned char)(-bit); /* 0xFF if bit==1, 0x00 if bit==0 */

    for (int b = 0; b < 32; b++)
    {
      al[idx * 32 + b] = one[b] & mask;
      ar[idx * 32 + b] = minus_one[b] & ~mask;
    }
  }
  /* ---- 2. Generate random blinding vectors sl/sr ---- */
  for (size_t i = 0; i < BP_VALUE_BITS; i++)
  {
    size_t idx = offset + i;

    if (!generate_random_scalar(ctx, sl + idx * 32))
    {
      goto cleanup;
    }
    if (!generate_random_scalar(ctx, sr + idx * 32))
    {
      goto cleanup;
    }
  }

  return 1;

cleanup:
  /* Wipe only the affected block */
  OPENSSL_cleanse(al + offset * 32, BP_VALUE_BITS * 32);
  OPENSSL_cleanse(ar + offset * 32, BP_VALUE_BITS * 32);
  OPENSSL_cleanse(sl + offset * 32, BP_VALUE_BITS * 32);
  OPENSSL_cleanse(sr + offset * 32, BP_VALUE_BITS * 32);
  return 0;
}
/**
 * Computes the Pedersen Commitment: C = value*G + blinding_factor*Pk_base.
 */
int secp256k1_bulletproof_create_commitment(
    const secp256k1_context *ctx, secp256k1_pubkey *commitment_C,
    uint64_t value, const unsigned char *blinding_factor,
    const secp256k1_pubkey *h_generator)
{
  secp256k1_pubkey G_term, Pk_term;
  const secp256k1_pubkey *points_to_add[2];
  int v_is_zero = (value == 0);

  /* 1. Compute r * Pk_base (The Blinding Term) */
  Pk_term = *h_generator;
  if (secp256k1_ec_pubkey_tweak_mul(ctx, &Pk_term, blinding_factor) != 1)
    return 0;

  /* 2. Handle Value Term */
  if (v_is_zero)
  {
    /* If v=0, C = 0*G + r*H = r*H.
       We skip G_term entirely because libsecp cannot represent infinity. */
    *commitment_C = Pk_term;
    return 1;
  }

  /* 3. Compute v * G (The Value Term) */
  if (!compute_amount_point(ctx, &G_term, value))
    return 0;

  /* 4. Combine: C = v*G + r*Pk_base */
  points_to_add[0] = &G_term;
  points_to_add[1] = &Pk_term;
  if (secp256k1_ec_pubkey_combine(ctx, commitment_C, points_to_add, 2) != 1)
    return 0;

  return 1;
}

/* Helper for a vector 0 */
static int scalar_vector_all_zero(const unsigned char *scalars, size_t n)
{
  unsigned char zero[32] = {0};
  for (size_t i = 0; i < n; ++i)
  {
    if (memcmp(scalars + 32 * i, zero, 32) != 0)
      return 0; /* found non-zero */
  }
  return 1; /* all zero */
}

/* Helper to calculate commitment terms like A and S */
static int calculate_commitment_term(
    const secp256k1_context *ctx, secp256k1_pubkey *out,
    const secp256k1_pubkey *h_generator, const unsigned char *base_scalar,
    const unsigned char *vec_l, const unsigned char *vec_r,
    const secp256k1_pubkey *G_vec, const secp256k1_pubkey *H_vec, size_t n)
{
  secp256k1_pubkey tG, tH, tB;
  const secp256k1_pubkey *pts[3];
  int n_pts = 0;

  /* 1. base_scalar * Base */
  tB = *h_generator;
  if (!secp256k1_ec_pubkey_tweak_mul(ctx, &tB, base_scalar))
    return 0;
  pts[n_pts++] = &tB;

  /* 2. <vec_l, G> */
  if (!scalar_vector_all_zero(vec_l, n))
  {
    if (!secp256k1_bulletproof_ipa_msm(ctx, &tG, G_vec, vec_l, n))
      return 0; /* REAL FAILURE */
    pts[n_pts++] = &tG;
  }

  /* 3. <vec_r, H> */
  if (!scalar_vector_all_zero(vec_r, n))
  {
    if (!secp256k1_bulletproof_ipa_msm(ctx, &tH, H_vec, vec_r, n))
      return 0; /* REAL FAILURE */
    pts[n_pts++] = &tH;
  }

  if (n_pts == 1)
  {
    *out = *pts[0];
    return 1;
  }

  if (!secp256k1_ec_pubkey_combine(ctx, out, pts, n_pts))
    return 0;

  return 1;
}

/**
 * Generates an aggregated Bulletproof for m values.
 *
 * This function constructs a range proof asserting that all m values are within
 * the [0, 2^64) range. The proof is serialized into proof_out.
 *
 * Inputs:
 * - values: Array of m 64-bit integers to prove.
 * - blindings_flat: Array of m 32-byte blinding factors (one per value).
 * - m: Number of values to aggregate (must be a power of 2).
 * - h_generator: Generator H used for the commitments (C = vG + rH).
 * - context_id: Optional 32-byte unique ID to bind the proof to a context.
 *
 * Outputs:
 * - proof_out: Buffer to receive the serialized proof.
 * - proof_len: On input, size of proof_out. On output, actual proof size.
 *
 * Returns 1 on success, 0 on failure.
 */
int secp256k1_bulletproof_prove_agg(
    const secp256k1_context *ctx, unsigned char *proof_out, size_t *proof_len,
    const uint64_t *values, const unsigned char *blindings_flat, size_t m,
    const secp256k1_pubkey *h_generator, const unsigned char *context_id)
{
  /* ---- 0. Dimensions ---- */
  const size_t n = BP_TOTAL_BITS(m);      /* 64*m */
  const size_t rounds = bp_ipa_rounds(n); /* log2(64*m) */

  /* 64*m must be power-of-two -> m must be power-of-two */
  if (m == 0 || m > BP_MAX_VALUES)
    return 0;
  if ((n & (n - 1)) != 0)
    return 0;

  /* Proof length = 4*33 + 2*rounds*33 + 5*32 */
  const size_t proof_size = 292 + 66 * rounds;
  if (proof_len)
    *proof_len = proof_size;

  int ok = 0;

  /* ---- 1. Allocate vectors ---- */
  secp256k1_pubkey *G_vec =
      (secp256k1_pubkey *)malloc(n * sizeof(secp256k1_pubkey));
  secp256k1_pubkey *H_vec =
      (secp256k1_pubkey *)malloc(n * sizeof(secp256k1_pubkey));
  secp256k1_pubkey *H_prime =
      (secp256k1_pubkey *)malloc(n * sizeof(secp256k1_pubkey));
  unsigned char *al = (unsigned char *)malloc(n * 32);
  unsigned char *ar = (unsigned char *)malloc(n * 32);
  unsigned char *sl = (unsigned char *)malloc(n * 32);
  unsigned char *sr = (unsigned char *)malloc(n * 32);
  unsigned char *l_vec = (unsigned char *)malloc(n * 32);
  unsigned char *r_vec = (unsigned char *)malloc(n * 32);
  unsigned char *r1_vec = (unsigned char *)malloc(n * 32);

  secp256k1_pubkey *L_vec =
      (secp256k1_pubkey *)malloc(rounds * sizeof(secp256k1_pubkey));
  secp256k1_pubkey *R_vec =
      (secp256k1_pubkey *)malloc(rounds * sizeof(secp256k1_pubkey));

  unsigned char *y_powers = (unsigned char *)malloc(n * 32); /* y^i */
  unsigned char *z_j2 = (unsigned char *)malloc(m * 32);     /* z^(j+2) */

  if (!G_vec || !H_vec || !H_prime || !al || !ar || !sl || !sr || !l_vec ||
      !r_vec || !r1_vec || !L_vec || !R_vec || !y_powers || !z_j2)
  {
    goto cleanup;
  }

  /* ---- 2. Scalars / points ---- */
  secp256k1_pubkey A, S, T1, T2, U;

  unsigned char alpha[32], rho[32];
  unsigned char tau1[32], tau2[32];
  unsigned char t1[32], t2[32];
  unsigned char t_hat[32], tau_x[32], mu[32];
  unsigned char a_final[32], b_final[32];

  unsigned char y[32], z[32], x[32];
  unsigned char z_sq[32], z_neg[32], x_sq[32];
  unsigned char ux_scalar[32];
  unsigned char ipa_transcript[32];

  unsigned char one[32] = {0};
  one[31] = 1;
  unsigned char minus_one[32];
  secp256k1_mpt_scalar_negate(minus_one, one);
  unsigned char zero[32] = {0};

  /* ---- 3. Generator vectors ---- */
  if (!secp256k1_mpt_get_generator_vector(ctx, G_vec, n,
                                          (const unsigned char *)"BP_G", 4))
    goto cleanup;
  if (!secp256k1_mpt_get_generator_vector(ctx, H_vec, n,
                                          (const unsigned char *)"BP_H", 4))
    goto cleanup;
  {
    secp256k1_pubkey U_arr[1];
    if (!secp256k1_mpt_get_generator_vector(ctx, U_arr, 1,
                                            (const unsigned char *)"BP_U", 4))
      goto cleanup;
    U = U_arr[0];
  }

  /* ---- 4. Bit-decomposition for m values into al/ar (concat) + random sl/sr
   * ---- */
  for (size_t j = 0; j < m; j++)
  {
    uint64_t v = values[j];
    for (size_t i = 0; i < BP_VALUE_BITS; i++)
    {
      const size_t k = j * BP_VALUE_BITS + i; /* 0..n-1 */
      unsigned char *al_k = al + 32 * k;
      unsigned char *ar_k = ar + 32 * k;
      unsigned char *sl_k = sl + 32 * k;
      unsigned char *sr_k = sr + 32 * k;

      /* Constant-time bit decomposition to prevent cache-timing leaks */
      unsigned char bit = (unsigned char)((v >> i) & 1);
      unsigned char mask =
          (unsigned char)(0 - bit); /* 0xFF if bit==1, 0x00 if bit==0 */

      for (int b = 0; b < 32; b++)
      {
        al_k[b] = one[b] & mask;
        ar_k[b] = minus_one[b] & ~mask;
      }

      if (!generate_random_scalar(ctx, sl_k))
        goto cleanup;
      if (!generate_random_scalar(ctx, sr_k))
        goto cleanup;
    }
  }

  if (!generate_random_scalar(ctx, alpha))
    goto cleanup;
  if (!generate_random_scalar(ctx, rho))
    goto cleanup;

  /* ---- 5. Commitments A and S ----
   * A = alpha*Base + <al,G> + <ar,H>
   * S = rho*Base   + <sl,G> + <sr,H>
   */
  if (!calculate_commitment_term(ctx, &A, h_generator, alpha, al, ar, G_vec,
                                 H_vec, n))
    goto cleanup;
  if (!calculate_commitment_term(ctx, &S, h_generator, rho, sl, sr, G_vec,
                                 H_vec, n))
    goto cleanup;

  /* ---- 6. Fiat–Shamir y,z ---- */
  {
    unsigned char A_ser[33], S_ser[33];
    size_t len;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    int fs_ok = 1;

    if (!mdctx)
      goto cleanup;

    len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, A_ser, &len, &A,
                                       SECP256K1_EC_COMPRESSED) ||
        len != 33)
    {
      fs_ok = 0;
      goto fs_cleanup;
    }

    len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, S_ser, &len, &S,
                                       SECP256K1_EC_COMPRESSED) ||
        len != 33)
    {
      fs_ok = 0;
      goto fs_cleanup;
    }

    // y = H(domain || V* || A || S || context)
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1)
    {
      fs_ok = 0;
      goto fs_cleanup;
    }
    if (EVP_DigestUpdate(mdctx, "MPT_BULLETPROOF_RANGE", 21) != 1)
    {
      fs_ok = 0;
      goto fs_cleanup;
    }

    for (size_t i = 0; i < m; i++)
    {
      secp256k1_pubkey V_temp;
      unsigned char V_ser[33];
      size_t v_len = 33;
      if (!secp256k1_bulletproof_create_commitment(
              ctx, &V_temp, values[i], blindings_flat + 32 * i, h_generator))
      {
        fs_ok = 0;
        goto fs_cleanup;
      }
      if (!secp256k1_ec_pubkey_serialize(ctx, V_ser, &v_len, &V_temp,
                                         SECP256K1_EC_COMPRESSED) ||
          v_len != 33)
      {
        fs_ok = 0;
        goto fs_cleanup;
      }
      if (EVP_DigestUpdate(mdctx, V_ser, 33) != 1)
      {
        fs_ok = 0;
        goto fs_cleanup;
      }
    }

    if (EVP_DigestUpdate(mdctx, A_ser, 33) != 1)
    {
      fs_ok = 0;
      goto fs_cleanup;
    }
    if (EVP_DigestUpdate(mdctx, S_ser, 33) != 1)
    {
      fs_ok = 0;
      goto fs_cleanup;
    }
    if (context_id && EVP_DigestUpdate(mdctx, context_id, 32) != 1)
    {
      fs_ok = 0;
      goto fs_cleanup;
    }
    if (EVP_DigestFinal_ex(mdctx, y, NULL) != 1)
    {
      fs_ok = 0;
      goto fs_cleanup;
    }
    secp256k1_mpt_scalar_reduce32(y, y);

    // z = H(domain || V* || A || S || y || context)
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1)
    {
      fs_ok = 0;
      goto fs_cleanup;
    }
    if (EVP_DigestUpdate(mdctx, "MPT_BULLETPROOF_RANGE", 21) != 1)
    {
      fs_ok = 0;
      goto fs_cleanup;
    }

    for (size_t i = 0; i < m; i++)
    {
      secp256k1_pubkey V_temp;
      unsigned char V_ser[33];
      size_t v_len = 33;
      if (!secp256k1_bulletproof_create_commitment(
              ctx, &V_temp, values[i], blindings_flat + 32 * i, h_generator))
      {
        fs_ok = 0;
        goto fs_cleanup;
      }
      if (!secp256k1_ec_pubkey_serialize(ctx, V_ser, &v_len, &V_temp,
                                         SECP256K1_EC_COMPRESSED) ||
          v_len != 33)
      {
        fs_ok = 0;
        goto fs_cleanup;
      }
      if (EVP_DigestUpdate(mdctx, V_ser, 33) != 1)
      {
        fs_ok = 0;
        goto fs_cleanup;
      }
    }

    if (EVP_DigestUpdate(mdctx, A_ser, 33) != 1)
    {
      fs_ok = 0;
      goto fs_cleanup;
    }
    if (EVP_DigestUpdate(mdctx, S_ser, 33) != 1)
    {
      fs_ok = 0;
      goto fs_cleanup;
    }
    if (EVP_DigestUpdate(mdctx, y, 32) != 1)
    {
      fs_ok = 0;
      goto fs_cleanup;
    }
    if (context_id && EVP_DigestUpdate(mdctx, context_id, 32) != 1)
    {
      fs_ok = 0;
      goto fs_cleanup;
    }
    if (EVP_DigestFinal_ex(mdctx, z, NULL) != 1)
    {
      fs_ok = 0;
      goto fs_cleanup;
    }
    secp256k1_mpt_scalar_reduce32(z, z);

    memcpy(z_neg, z, 32);
    secp256k1_mpt_scalar_negate(z_neg, z_neg);

  fs_cleanup:
    EVP_MD_CTX_free(mdctx);
    if (!fs_ok)
      goto cleanup;
  }

  /* ---- 7. Aggregated polynomial setup ---- */

  /* y_powers[k] = y^k */
  {
    unsigned char ypow[32];
    memcpy(ypow, one, 32);

    for (size_t k = 0; k < n; k++)
    {
      memcpy(y_powers + 32 * k, ypow, 32);
      secp256k1_mpt_scalar_mul(ypow, ypow, y);
    }
    OPENSSL_cleanse(ypow, 32);
  }

  /* z_j2[j] = z^(j+2) */
  compute_z_pows_j2(ctx, (unsigned char (*)[32])z_j2, z, m);

  /* l0, r0, r1 */
  for (size_t block = 0; block < m; block++)
  {
    const unsigned char *zblk = z_j2 + 32 * block; /* z^(block+2) */

    for (size_t i = 0; i < BP_VALUE_BITS; i++)
    {
      size_t k = block * BP_VALUE_BITS + i;

      unsigned char *l0 = l_vec + 32 * k;
      unsigned char *r0 = r_vec + 32 * k;
      unsigned char *r1 = r1_vec + 32 * k;

      const unsigned char *al_k = al + 32 * k;
      const unsigned char *ar_k = ar + 32 * k;
      const unsigned char *sr_k = sr + 32 * k;
      const unsigned char *yk = y_powers + 32 * k;

      unsigned char two_i[32] = {0};
      two_i[31 - (i >> 3)] = (unsigned char)(1u << (i & 7));

      /* l0 = aL - z */
      secp256k1_mpt_scalar_add(l0, al_k, z_neg);

      /* r0 = y^k * (aR + z) + z^(block+2) * 2^i */
      {
        unsigned char tmp1[32], tmp2[32];

        /* tmp1 = aR + z */
        secp256k1_mpt_scalar_add(tmp1, ar_k, z);

        /* r0 = y^k * tmp1 */
        secp256k1_mpt_scalar_mul(r0, tmp1, yk);

        /* tmp2 = z^(block+2) * 2^i */
        secp256k1_mpt_scalar_mul(tmp2, zblk, two_i);

        /* r0 += tmp2 */
        secp256k1_mpt_scalar_add(r0, r0, tmp2);

        OPENSSL_cleanse(tmp1, 32);
        OPENSSL_cleanse(tmp2, 32);
      }

      /* r1 = sR * y^k */
      secp256k1_mpt_scalar_mul(r1, sr_k, yk);
    }
  }

  /* t1 = <l0, r1> + <l1, r0> */
  {
    unsigned char dot1[32], dot2[32];
    if (!secp256k1_bulletproof_ipa_dot(ctx, dot1, l_vec, r1_vec, n))
      goto cleanup;
    if (!secp256k1_bulletproof_ipa_dot(ctx, dot2, sl, r_vec, n))
      goto cleanup;
    secp256k1_mpt_scalar_add(t1, dot1, dot2);
    OPENSSL_cleanse(dot1, 32);
    OPENSSL_cleanse(dot2, 32);
  }

  /* t2 = <l1, r1> */
  if (!secp256k1_bulletproof_ipa_dot(ctx, t2, sl, r1_vec, n))
    goto cleanup;

  /* Make sure these exist before T1/T2 */
  if (!generate_random_scalar(ctx, tau1))
    goto cleanup;
  if (!generate_random_scalar(ctx, tau2))
    goto cleanup;

  /* ---- 8. Commit T1, T2 ---- */
  /* T1 = t1*G + tau1*Base   where G = G_vec[0].
   * When t1 == 0 the t1*G term is the point at infinity (which libsecp256k1
   * cannot emit), so commit T1 = tau1*Base directly. */
  {
    secp256k1_pubkey tG, tB;
    const secp256k1_pubkey *pts[2];

    tB = *h_generator;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &tB, tau1))
      goto cleanup;

    if (memcmp(t1, zero, 32) == 0)
    {
      T1 = tB;
    }
    else
    {
      if (!secp256k1_ec_pubkey_create(ctx, &tG, t1))
        goto cleanup;
      pts[0] = &tG;
      pts[1] = &tB;
      if (!secp256k1_ec_pubkey_combine(ctx, &T1, pts, 2))
        goto cleanup;
    }
  }

  /* T2 = t2*G + tau2*Base. Same t2==0 short-circuit as above. */
  {
    secp256k1_pubkey tG, tB;
    const secp256k1_pubkey *pts[2];

    tB = *h_generator;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &tB, tau2))
      goto cleanup;

    if (memcmp(t2, zero, 32) == 0)
    {
      T2 = tB;
    }
    else
    {
      if (!secp256k1_ec_pubkey_create(ctx, &tG, t2))
        goto cleanup;
      pts[0] = &tG;
      pts[1] = &tB;
      if (!secp256k1_ec_pubkey_combine(ctx, &T2, pts, 2))
        goto cleanup;
    }
  }

  /* ---- 9. Challenge x ---- */
  /* x = H(A || S || y || z || T1 || T2 || context_id) */
  {
    unsigned char A_ser[33], S_ser[33], T1_ser[33], T2_ser[33];
    size_t len;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    int fs_ok = 0;

    if (!mdctx)
      goto cleanup;

    len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, A_ser, &len, &A,
                                       SECP256K1_EC_COMPRESSED) ||
        len != 33)
      goto fs_x_cleanup;
    len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, S_ser, &len, &S,
                                       SECP256K1_EC_COMPRESSED) ||
        len != 33)
      goto fs_x_cleanup;
    len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, T1_ser, &len, &T1,
                                       SECP256K1_EC_COMPRESSED) ||
        len != 33)
      goto fs_x_cleanup;
    len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, T2_ser, &len, &T2,
                                       SECP256K1_EC_COMPRESSED) ||
        len != 33)
      goto fs_x_cleanup;

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1)
      goto fs_x_cleanup;
    if (EVP_DigestUpdate(mdctx, A_ser, 33) != 1)
      goto fs_x_cleanup;
    if (EVP_DigestUpdate(mdctx, S_ser, 33) != 1)
      goto fs_x_cleanup;
    if (EVP_DigestUpdate(mdctx, y, 32) != 1)
      goto fs_x_cleanup;
    if (EVP_DigestUpdate(mdctx, z, 32) != 1)
      goto fs_x_cleanup;
    if (EVP_DigestUpdate(mdctx, T1_ser, 33) != 1)
      goto fs_x_cleanup;
    if (EVP_DigestUpdate(mdctx, T2_ser, 33) != 1)
      goto fs_x_cleanup;
    if (context_id && EVP_DigestUpdate(mdctx, context_id, 32) != 1)
      goto fs_x_cleanup;
    if (EVP_DigestFinal_ex(mdctx, x, NULL) != 1)
      goto fs_x_cleanup;

    secp256k1_mpt_scalar_reduce32(x, x);
    if (memcmp(x, zero, 32) == 0)
      goto fs_x_cleanup; /* avoid infinity later */

    fs_ok = 1;

  fs_x_cleanup:
    EVP_MD_CTX_free(mdctx);
    if (!fs_ok)
      goto cleanup;
  }

  /* ---- 10. Evaluate l(x), r(x), t_hat ---- */
  for (size_t k = 0; k < n; k++)
  {
    unsigned char tmp[32];

    /* l = l0 + sL*x */
    secp256k1_mpt_scalar_mul(tmp, sl + 32 * k, x);
    secp256k1_mpt_scalar_add(l_vec + 32 * k, l_vec + 32 * k, tmp);

    /* r = r0 + r1*x */
    secp256k1_mpt_scalar_mul(tmp, r1_vec + 32 * k, x);
    secp256k1_mpt_scalar_add(r_vec + 32 * k, r_vec + 32 * k, tmp);

    OPENSSL_cleanse(tmp, 32);
  }

  if (!secp256k1_bulletproof_ipa_dot(ctx, t_hat, l_vec, r_vec, n))
    goto cleanup;

  /* ---- 11. tau_x and mu (aggregation changes tau_x) ---- */
  secp256k1_mpt_scalar_mul(x_sq, x, x);

  /* tau_x = tau2*x^2 + tau1*x + sum_j z^(j+2) * blinding_j */
  secp256k1_mpt_scalar_mul(tau_x, tau2, x_sq);
  {
    unsigned char tmp[32];
    secp256k1_mpt_scalar_mul(tmp, tau1, x);
    secp256k1_mpt_scalar_add(tau_x, tau_x, tmp);

    /* + sum_j z^(j+2) * r_j */
    for (size_t j = 0; j < m; j++)
    {
      unsigned char add[32];
      secp256k1_mpt_scalar_mul(add, z_j2 + 32 * j, blindings_flat + 32 * j);
      secp256k1_mpt_scalar_add(tau_x, tau_x, add);
      OPENSSL_cleanse(add, 32);
    }

    OPENSSL_cleanse(tmp, 32);
  }

  /* mu = alpha + rho*x */
  {
    unsigned char tmp[32];
    secp256k1_mpt_scalar_mul(tmp, rho, x);
    secp256k1_mpt_scalar_add(mu, alpha, tmp);
    OPENSSL_cleanse(tmp, 32);
  }

  /* ---- 12. IPA transcript + ux (binding), and H' normalization ---- */

  /* 12a. Build a stable IPA transcript seed (32 bytes).
   *
   * IMPORTANT:
   *  - Prover and verifier MUST hash the exact same bytes in the exact same
   * order.
   *  - Use only public elements that both sides already know.
   *  - Do NOT depend on internal intermediate buffers.
   *
   * Minimal, safe choice: A||S||T1||T2 || y||z||x || t_hat || context_id
   * (All points are serialized compressed 33 bytes.)
   */
  {
    unsigned char A_ser[33], S_ser[33], T1_ser[33], T2_ser[33];
    size_t ser_len;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    int fs_ok = 0;

    if (!mdctx)
      goto cleanup;

    ser_len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, A_ser, &ser_len, &A,
                                       SECP256K1_EC_COMPRESSED) ||
        ser_len != 33)
      goto fs_ipa_cleanup;

    ser_len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, S_ser, &ser_len, &S,
                                       SECP256K1_EC_COMPRESSED) ||
        ser_len != 33)
      goto fs_ipa_cleanup;

    ser_len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, T1_ser, &ser_len, &T1,
                                       SECP256K1_EC_COMPRESSED) ||
        ser_len != 33)
      goto fs_ipa_cleanup;

    ser_len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, T2_ser, &ser_len, &T2,
                                       SECP256K1_EC_COMPRESSED) ||
        ser_len != 33)
      goto fs_ipa_cleanup;

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1)
      goto fs_ipa_cleanup;

    if (EVP_DigestUpdate(mdctx, A_ser, 33) != 1)
      goto fs_ipa_cleanup;
    if (EVP_DigestUpdate(mdctx, S_ser, 33) != 1)
      goto fs_ipa_cleanup;
    if (EVP_DigestUpdate(mdctx, T1_ser, 33) != 1)
      goto fs_ipa_cleanup;
    if (EVP_DigestUpdate(mdctx, T2_ser, 33) != 1)
      goto fs_ipa_cleanup;
    if (EVP_DigestUpdate(mdctx, y, 32) != 1)
      goto fs_ipa_cleanup;
    if (EVP_DigestUpdate(mdctx, z, 32) != 1)
      goto fs_ipa_cleanup;
    if (EVP_DigestUpdate(mdctx, x, 32) != 1)
      goto fs_ipa_cleanup;
    if (EVP_DigestUpdate(mdctx, t_hat, 32) != 1)
      goto fs_ipa_cleanup;
    if (context_id && EVP_DigestUpdate(mdctx, context_id, 32) != 1)
      goto fs_ipa_cleanup;

    if (EVP_DigestFinal_ex(mdctx, ipa_transcript, NULL) != 1)
      goto fs_ipa_cleanup;

    fs_ok = 1;

  fs_ipa_cleanup:
    EVP_MD_CTX_free(mdctx);
    if (!fs_ok)
      goto cleanup;
  }

  /* 12b. Derive u_x = H(ipa_transcript || t_hat) reduced to scalar. */
  if (!derive_ipa_binding_challenge(ctx, ux_scalar, ipa_transcript, t_hat))
    goto cleanup;

  /* 12c. Normalize H: H'[k] = H[k] * y^{-k}.
   *
   * NOTE:
   *  - Requires y != 0.
   *  - If y==0 (mod q), abort (cannot invert).
   */
  {
    unsigned char y_inv[32];
    unsigned char y_inv_pow[32]; /* (y^{-1})^k */
    if (memcmp(y, zero, 32) == 0)
      goto cleanup;

    secp256k1_mpt_scalar_inverse(y_inv, y);
    memcpy(y_inv_pow, one, 32);

    for (size_t k = 0; k < n; k++)
    {
      H_prime[k] = H_vec[k];
      /* H_prime[k] = H_vec[k] * (y^{-1})^k */
      if (!secp256k1_ec_pubkey_tweak_mul(ctx, &H_prime[k], y_inv_pow))
        goto cleanup;
      secp256k1_mpt_scalar_mul(y_inv_pow, y_inv_pow, y_inv);
    }

    OPENSSL_cleanse(y_inv, 32);
    OPENSSL_cleanse(y_inv_pow, 32);
  }

  /* 12d. Run IPA prover */
  {
    size_t rounds_used = 0;

    if (!secp256k1_bulletproof_run_ipa_prover(
            ctx, &U,              /* binding generator point */
            G_vec,                /* G */
            H_prime,              /* H' */
            l_vec,                /* l(x) scalars (flat 32*n) */
            r_vec,                /* r(x) scalars (flat 32*n) */
            n, ipa_transcript,    /* 32-byte seed */
            ux_scalar,            /* u_x scalar */
            L_vec, R_vec, rounds, /* max_rounds = log2(n) */
            &rounds_used, a_final, b_final))
      goto cleanup;

    if (rounds_used != rounds)
      goto cleanup;
  }

  /* ---- 13. Serialize (uses rounds) ---- */
  {
    const size_t expected = 292 + 66 * rounds; /* 4*33 + 2*rounds*33 + 5*32 */

    /* Standard pattern: query size only */
    if (proof_out == NULL)
    {
      if (proof_len)
        *proof_len = expected;
      ok = 1;
      goto cleanup;
    }

    if (proof_len == NULL)
      goto cleanup;

    if (*proof_len < expected)
    {
      *proof_len = expected;
      goto cleanup; /* not enough space */
    }

    unsigned char *ptr = proof_out;
    size_t ser_len;

#define SER_PT(P)                                                              \
  do                                                                           \
  {                                                                            \
    ser_len = 33;                                                              \
    if (!secp256k1_ec_pubkey_serialize(ctx, ptr, &ser_len, &(P),               \
                                       SECP256K1_EC_COMPRESSED))               \
      goto cleanup;                                                            \
    if (ser_len != 33)                                                         \
      goto cleanup;                                                            \
    ptr += 33;                                                                 \
  } while (0)

    SER_PT(A);
    SER_PT(S);
    SER_PT(T1);
    SER_PT(T2);

    for (size_t r = 0; r < rounds; r++)
      SER_PT(L_vec[r]);
    for (size_t r = 0; r < rounds; r++)
      SER_PT(R_vec[r]);

    memcpy(ptr, a_final, 32);
    ptr += 32;
    memcpy(ptr, b_final, 32);
    ptr += 32;
    memcpy(ptr, t_hat, 32);
    ptr += 32;
    memcpy(ptr, tau_x, 32);
    ptr += 32;
    memcpy(ptr, mu, 32);
    ptr += 32;

#undef SER_PT

    /* Final sanity */
    if ((size_t)(ptr - proof_out) != expected)
      goto cleanup;

    *proof_len = expected;
  }

  ok = 1;

cleanup:

  /* wipe sensitive scalars; free buffers */
  if (al)
    OPENSSL_cleanse(al, n * 32);
  if (ar)
    OPENSSL_cleanse(ar, n * 32);
  if (sl)
    OPENSSL_cleanse(sl, n * 32);
  if (sr)
    OPENSSL_cleanse(sr, n * 32);
  if (l_vec)
    OPENSSL_cleanse(l_vec, n * 32);
  if (r_vec)
    OPENSSL_cleanse(r_vec, n * 32);
  if (r1_vec)
    OPENSSL_cleanse(r1_vec, n * 32);

  OPENSSL_cleanse(alpha, 32);
  OPENSSL_cleanse(rho, 32);
  OPENSSL_cleanse(tau1, 32);
  OPENSSL_cleanse(tau2, 32);
  OPENSSL_cleanse(t1, 32);
  OPENSSL_cleanse(t2, 32);
  OPENSSL_cleanse(t_hat, 32);
  OPENSSL_cleanse(tau_x, 32);
  OPENSSL_cleanse(mu, 32);

  OPENSSL_cleanse(y, 32);
  OPENSSL_cleanse(z, 32);
  OPENSSL_cleanse(x, 32);
  OPENSSL_cleanse(z_sq, 32);
  OPENSSL_cleanse(z_neg, 32);
  OPENSSL_cleanse(x_sq, 32);
  OPENSSL_cleanse(ux_scalar, 32);
  OPENSSL_cleanse(ipa_transcript, 32);

  if (G_vec)
  {
    OPENSSL_cleanse(G_vec, n * sizeof(secp256k1_pubkey));
    free(G_vec);
  }
  if (H_vec)
  {
    OPENSSL_cleanse(H_vec, n * sizeof(secp256k1_pubkey));
    free(H_vec);
  }
  if (H_prime)
  {
    OPENSSL_cleanse(H_prime, n * sizeof(secp256k1_pubkey));
    free(H_prime);
  }

  free(al);
  free(ar);
  free(sl);
  free(sr);
  free(l_vec);
  free(r_vec);
  free(r1_vec);

  if (L_vec)
  {
    OPENSSL_cleanse(L_vec, rounds * sizeof(secp256k1_pubkey));
    free(L_vec);
  }
  if (R_vec)
  {
    OPENSSL_cleanse(R_vec, rounds * sizeof(secp256k1_pubkey));
    free(R_vec);
  }

  if (y_powers)
  {
    OPENSSL_cleanse(y_powers, n * 32);
    free(y_powers);
  }
  if (z_j2)
  {
    OPENSSL_cleanse(z_j2, m * 32);
    free(z_j2);
  }

  return ok;
}
/* -------------------------------------------------------------------------
 * Consolidated single-MSM verification (issue #100).
 *
 * Collapses both the range-check identity
 *
 *   t_hat*G + tau_x*H_pk
 *     == sum_j z^(j+2)*V_j + delta*G + x*T1 + x^2*T2          (E1)
 *
 * and the inner-product-collapsed check
 *
 *   P + sum_i u_i^2 *L_i + sum_i u_i^{-2}*R_i
 *     == a*sum_k s_k*G_k + b*sum_k s_k^{-1}*y^{-k}*H_k + a*b*u_x*U   (E2)
 *
 * with P = A + x*S + sum_k (-z)*G_k
 *        + sum_k y^{-k}*(z*y^k + z^(j_k+2)*2^{i_k}) *H_k
 *        + t_hat*u_x*U - mu*H_pk,
 *
 * into one variable-time MSM that must return the identity. The two
 * residuals are batched as E1 + c*E2 = 0 with a fresh Fiat-Shamir RLC
 * weight c bound to all proof bytes via the IPA challenge chain plus the
 * remaining scalars (tau_x, mu, a, b). Soundness: a malicious prover that
 * makes both residuals individually non-zero would need to predict c, and
 * c is derived after the prover commits to the entire proof.
 *
 * s_k = prod_j (bit_{rounds-1-j}(k) ? u_j : u_j^{-1}), matching the
 * verifier-side G-fold pattern in fold_generators(); s_k^{-1} matches the
 * H-fold pattern.
 *
 * The total MSM has 2n + 2*rounds + m + 6 (point, scalar) pairs plus an
 * optional G coefficient supplied via mpt_msm_variable_time's
 * inp_g_sc_be32 parameter.
 */

typedef struct
{
  unsigned char const *scalars_flat; /* n_terms * 32 bytes, big-endian */
  unsigned char const *points_ser;   /* n_terms * 33 bytes, SEC1-compressed */
  size_t n_terms;
} bp_verify_msm_cbdata;

static int bp_verify_msm_cb(unsigned char scalar_be32[32],
                            unsigned char point_sec1_33[33], size_t idx,
                            void *data)
{
  bp_verify_msm_cbdata const *d = (bp_verify_msm_cbdata const *)data;
  if (idx >= d->n_terms)
    return 0;
  memcpy(scalar_be32, d->scalars_flat + 32 * idx, 32);
  memcpy(point_sec1_33, d->points_ser + 33 * idx, 33);
  return 1;
}

/* -------------------------------------------------------------------------
 * Per-proof derived state (issue #88, shared with #100 single-proof path).
 *
 * Captures everything one aggregated-BP proof's verification needs *after*
 * parsing + FS-challenge derivation but *before* the per-coordinate
 * coefficient assembly. Used both by the single-proof verifier and by the
 * batch verifier; the batch version simply holds n_proofs of these.
 *
 * Memory ownership: bp_proof_state_init allocates the variable-length
 * arrays (L_vec, R_vec, y_inv_powers, u_flat, uinv_flat, s_G_flat). The
 * caller must invoke bp_proof_state_free on success or failure to release
 * them; bp_proof_state_free is idempotent and tolerates NULL pointers
 * (zeroed-state safe).
 */
typedef struct
{
  /* Parsed proof points */
  secp256k1_pubkey A, S, T1, T2;
  secp256k1_pubkey *L_vec; /* [rounds] */
  secp256k1_pubkey *R_vec; /* [rounds] */
  /* Parsed proof scalars */
  unsigned char a_final[32];
  unsigned char b_final[32];
  unsigned char t_hat[32];
  unsigned char tau_x[32];
  unsigned char mu[32];
  /* Outer FS challenges */
  unsigned char y[32];
  unsigned char z[32];
  unsigned char x[32];
  /* Derived */
  unsigned char delta[32];
  unsigned char *y_inv_powers; /* [n*32] */
  /* IPA state */
  unsigned char ipa_transcript_id[32];
  unsigned char ux_scalar[32];
  unsigned char *u_flat;    /* [rounds*32] */
  unsigned char *uinv_flat; /* [rounds*32] */
  unsigned char *s_G_flat;  /* [n*32]; G-fold weights. s_H_k = s_G_k^{-1}. */
  /* Intra-proof RLC weight that batches E1 + c*E2 = 0 */
  unsigned char c_scalar[32];
  /* Sizes (derive from m) */
  size_t m, n, rounds;
} bp_proof_state;

static void bp_proof_state_free(bp_proof_state *st)
{
  if (!st)
    return;
  free(st->L_vec);
  st->L_vec = NULL;
  free(st->R_vec);
  st->R_vec = NULL;
  free(st->y_inv_powers);
  st->y_inv_powers = NULL;
  free(st->u_flat);
  st->u_flat = NULL;
  free(st->uinv_flat);
  st->uinv_flat = NULL;
  free(st->s_G_flat);
  st->s_G_flat = NULL;
}

static int bp_proof_state_init(const secp256k1_context *ctx, bp_proof_state *st,
                               const secp256k1_pubkey *commitment_C_vec,
                               const unsigned char *proof, size_t proof_len,
                               size_t m, const unsigned char *context_id)
{
  memset(st, 0, sizeof(*st));

  if (m == 0 || m > BP_MAX_VALUES)
    return 0;
  if ((m & (m - 1)) != 0)
    return 0;
  st->m = m;
  st->n = BP_TOTAL_BITS(m);
  st->rounds = bp_ipa_rounds(st->n);

  if (proof_len != 292 + 66 * st->rounds)
    return 0;

  st->L_vec = (secp256k1_pubkey *)malloc(st->rounds * sizeof(secp256k1_pubkey));
  st->R_vec = (secp256k1_pubkey *)malloc(st->rounds * sizeof(secp256k1_pubkey));
  st->y_inv_powers = (unsigned char *)malloc(st->n * 32);
  st->u_flat = (unsigned char *)malloc(st->rounds * 32);
  st->uinv_flat = (unsigned char *)malloc(st->rounds * 32);
  st->s_G_flat = (unsigned char *)malloc(st->n * 32);
  if (!st->L_vec || !st->R_vec || !st->y_inv_powers || !st->u_flat ||
      !st->uinv_flat || !st->s_G_flat)
    return 0;

  /* --- Parse proof bytes --- */
  const unsigned char *ptr = proof;
  if (!secp256k1_ec_pubkey_parse(ctx, &st->A, ptr, 33))
    return 0;
  ptr += 33;
  if (!secp256k1_ec_pubkey_parse(ctx, &st->S, ptr, 33))
    return 0;
  ptr += 33;
  if (!secp256k1_ec_pubkey_parse(ctx, &st->T1, ptr, 33))
    return 0;
  ptr += 33;
  if (!secp256k1_ec_pubkey_parse(ctx, &st->T2, ptr, 33))
    return 0;
  ptr += 33;
  for (size_t i = 0; i < st->rounds; i++)
  {
    if (!secp256k1_ec_pubkey_parse(ctx, &st->L_vec[i], ptr, 33))
      return 0;
    ptr += 33;
  }
  for (size_t i = 0; i < st->rounds; i++)
  {
    if (!secp256k1_ec_pubkey_parse(ctx, &st->R_vec[i], ptr, 33))
      return 0;
    ptr += 33;
  }
  memcpy(st->a_final, ptr, 32);
  ptr += 32;
  memcpy(st->b_final, ptr, 32);
  ptr += 32;
  memcpy(st->t_hat, ptr, 32);
  ptr += 32;
  memcpy(st->tau_x, ptr, 32);
  ptr += 32;
  memcpy(st->mu, ptr, 32);
  ptr += 32;

  if (!secp256k1_ec_seckey_verify(ctx, st->a_final))
    return 0;
  if (!secp256k1_ec_seckey_verify(ctx, st->b_final))
    return 0;
  if (!secp256k1_ec_seckey_verify(ctx, st->t_hat))
    return 0;
  if (!secp256k1_ec_seckey_verify(ctx, st->tau_x))
    return 0;
  if (!secp256k1_ec_seckey_verify(ctx, st->mu))
    return 0;

  /* --- Serialize A, S, T1, T2 once for FS hashing --- */
  unsigned char A_ser[33], S_ser[33], T1_ser[33], T2_ser[33];
  size_t slen;
  slen = 33;
  if (!secp256k1_ec_pubkey_serialize(ctx, A_ser, &slen, &st->A,
                                     SECP256K1_EC_COMPRESSED) ||
      slen != 33)
    return 0;
  slen = 33;
  if (!secp256k1_ec_pubkey_serialize(ctx, S_ser, &slen, &st->S,
                                     SECP256K1_EC_COMPRESSED) ||
      slen != 33)
    return 0;
  slen = 33;
  if (!secp256k1_ec_pubkey_serialize(ctx, T1_ser, &slen, &st->T1,
                                     SECP256K1_EC_COMPRESSED) ||
      slen != 33)
    return 0;
  slen = 33;
  if (!secp256k1_ec_pubkey_serialize(ctx, T2_ser, &slen, &st->T2,
                                     SECP256K1_EC_COMPRESSED) ||
      slen != 33)
    return 0;

  /* --- FS challenges y, z, x via dedicated EVP_MD_CTX scope --- */
  {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    int fs_ok = 0;
    if (!mdctx)
      return 0;

    /* y = H("MPT_BULLETPROOF_RANGE" || C_i... || A || S || context) */
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1)
      goto fs_cleanup;
    if (EVP_DigestUpdate(mdctx, "MPT_BULLETPROOF_RANGE", 21) != 1)
      goto fs_cleanup;
    for (size_t i = 0; i < m; i++)
    {
      unsigned char C_ser[33];
      size_t c_len = 33;
      if (!secp256k1_ec_pubkey_serialize(ctx, C_ser, &c_len,
                                         &commitment_C_vec[i],
                                         SECP256K1_EC_COMPRESSED) ||
          c_len != 33)
        goto fs_cleanup;
      if (EVP_DigestUpdate(mdctx, C_ser, 33) != 1)
        goto fs_cleanup;
    }
    if (EVP_DigestUpdate(mdctx, A_ser, 33) != 1)
      goto fs_cleanup;
    if (EVP_DigestUpdate(mdctx, S_ser, 33) != 1)
      goto fs_cleanup;
    if (context_id && EVP_DigestUpdate(mdctx, context_id, 32) != 1)
      goto fs_cleanup;
    if (EVP_DigestFinal_ex(mdctx, st->y, NULL) != 1)
      goto fs_cleanup;
    secp256k1_mpt_scalar_reduce32(st->y, st->y);

    /* z = H(...||y) */
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1)
      goto fs_cleanup;
    if (EVP_DigestUpdate(mdctx, "MPT_BULLETPROOF_RANGE", 21) != 1)
      goto fs_cleanup;
    for (size_t i = 0; i < m; i++)
    {
      unsigned char C_ser[33];
      size_t c_len = 33;
      if (!secp256k1_ec_pubkey_serialize(ctx, C_ser, &c_len,
                                         &commitment_C_vec[i],
                                         SECP256K1_EC_COMPRESSED) ||
          c_len != 33)
        goto fs_cleanup;
      if (EVP_DigestUpdate(mdctx, C_ser, 33) != 1)
        goto fs_cleanup;
    }
    if (EVP_DigestUpdate(mdctx, A_ser, 33) != 1)
      goto fs_cleanup;
    if (EVP_DigestUpdate(mdctx, S_ser, 33) != 1)
      goto fs_cleanup;
    if (EVP_DigestUpdate(mdctx, st->y, 32) != 1)
      goto fs_cleanup;
    if (context_id && EVP_DigestUpdate(mdctx, context_id, 32) != 1)
      goto fs_cleanup;
    if (EVP_DigestFinal_ex(mdctx, st->z, NULL) != 1)
      goto fs_cleanup;
    secp256k1_mpt_scalar_reduce32(st->z, st->z);
    if (!secp256k1_ec_seckey_verify(ctx, st->y) ||
        !secp256k1_ec_seckey_verify(ctx, st->z))
      goto fs_cleanup;

    /* x = H(A || S || y || z || T1 || T2 || context) */
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1)
      goto fs_cleanup;
    if (EVP_DigestUpdate(mdctx, A_ser, 33) != 1)
      goto fs_cleanup;
    if (EVP_DigestUpdate(mdctx, S_ser, 33) != 1)
      goto fs_cleanup;
    if (EVP_DigestUpdate(mdctx, st->y, 32) != 1)
      goto fs_cleanup;
    if (EVP_DigestUpdate(mdctx, st->z, 32) != 1)
      goto fs_cleanup;
    if (EVP_DigestUpdate(mdctx, T1_ser, 33) != 1)
      goto fs_cleanup;
    if (EVP_DigestUpdate(mdctx, T2_ser, 33) != 1)
      goto fs_cleanup;
    if (context_id && EVP_DigestUpdate(mdctx, context_id, 32) != 1)
      goto fs_cleanup;
    if (EVP_DigestFinal_ex(mdctx, st->x, NULL) != 1)
      goto fs_cleanup;
    secp256k1_mpt_scalar_reduce32(st->x, st->x);
    if (!secp256k1_ec_seckey_verify(ctx, st->x))
      goto fs_cleanup;

    fs_ok = 1;
  fs_cleanup:
    EVP_MD_CTX_free(mdctx);
    if (!fs_ok)
      return 0;
  }

  /* --- y_inv_powers (the prover-side y_powers vector is not needed
   * verifier-side because the consolidated MSM only references y^{-k}). --- */
  {
    unsigned char y_inv[32];
    secp256k1_mpt_scalar_inverse(y_inv, st->y);
    scalar_vector_powers(ctx, (unsigned char (*)[32])st->y_inv_powers, y_inv,
                         st->n);
  }

  /* --- delta(y, z) for aggregation:
   *   delta = (z - z^2) * sum_{k=0..n-1} y^k - sum_{j=0..m-1} z^(j+3) *
   * <1,2^64>
   */
  {
    unsigned char z_sq[32];
    secp256k1_mpt_scalar_mul(z_sq, st->z, st->z);

    unsigned char (*y_block_sum)[32] = (unsigned char (*)[32])malloc(m * 32);
    if (!y_block_sum)
      return 0;

    unsigned char two_sum[32];
    compute_delta_scalars(ctx, y_block_sum, two_sum, st->y, m);

    unsigned char sum_y_all[32] = {0};
    for (size_t j = 0; j < m; j++)
      secp256k1_mpt_scalar_add(sum_y_all, sum_y_all, y_block_sum[j]);

    unsigned char z_minus_z2[32], tmp[32];
    secp256k1_mpt_scalar_sub(z_minus_z2, st->z, z_sq);
    secp256k1_mpt_scalar_mul(tmp, z_minus_z2, sum_y_all);
    memcpy(st->delta, tmp, 32);

    for (size_t j = 0; j < m; j++)
    {
      unsigned char z_j3[32];
      scalar_pow_u32(ctx, z_j3, st->z, (unsigned int)(j + 3));
      secp256k1_mpt_scalar_mul(tmp, z_j3, two_sum);
      secp256k1_mpt_scalar_negate(tmp, tmp);
      secp256k1_mpt_scalar_add(st->delta, st->delta, tmp);
    }

    free(y_block_sum);
  }

  /* --- ipa_transcript_id binds A, S, T1, T2, y, z, x, t_hat, context_id --- */
  {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    int hash_ok = 0;
    unsigned int md_len = 0;
    if (!mdctx)
      return 0;
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1)
      goto tid_cleanup;
    if (EVP_DigestUpdate(mdctx, A_ser, 33) != 1)
      goto tid_cleanup;
    if (EVP_DigestUpdate(mdctx, S_ser, 33) != 1)
      goto tid_cleanup;
    if (EVP_DigestUpdate(mdctx, T1_ser, 33) != 1)
      goto tid_cleanup;
    if (EVP_DigestUpdate(mdctx, T2_ser, 33) != 1)
      goto tid_cleanup;
    if (EVP_DigestUpdate(mdctx, st->y, 32) != 1)
      goto tid_cleanup;
    if (EVP_DigestUpdate(mdctx, st->z, 32) != 1)
      goto tid_cleanup;
    if (EVP_DigestUpdate(mdctx, st->x, 32) != 1)
      goto tid_cleanup;
    if (EVP_DigestUpdate(mdctx, st->t_hat, 32) != 1)
      goto tid_cleanup;
    if (context_id && EVP_DigestUpdate(mdctx, context_id, 32) != 1)
      goto tid_cleanup;
    if (EVP_DigestFinal_ex(mdctx, st->ipa_transcript_id, &md_len) != 1 ||
        md_len != 32)
      goto tid_cleanup;
    hash_ok = 1;
  tid_cleanup:
    EVP_MD_CTX_free(mdctx);
    if (!hash_ok)
      return 0;
  }

  if (!derive_ipa_binding_challenge(ctx, st->ux_scalar, st->ipa_transcript_id,
                                    st->t_hat))
    return 0;

  /* --- IPA round challenges u_i and inverses --- */
  {
    unsigned char last[32];
    memcpy(last, st->ipa_transcript_id, 32);
    for (size_t i = 0; i < st->rounds; i++)
    {
      unsigned char *ui = st->u_flat + 32 * i;
      unsigned char *uiinv = st->uinv_flat + 32 * i;
      if (!derive_ipa_round_challenge(ctx, ui, last, &st->L_vec[i],
                                      &st->R_vec[i]))
        return 0;
      secp256k1_mpt_scalar_inverse(uiinv, ui);
      if (!secp256k1_ec_seckey_verify(ctx, uiinv))
        return 0;
      memcpy(last, ui, 32);
    }
  }

  /* --- s_G_k for k = 0..n-1 (G-fold pattern) --- */
  for (size_t k = 0; k < st->n; k++)
  {
    unsigned char cur[32] = {0};
    cur[31] = 1;
    for (size_t j = 0; j < st->rounds; j++)
    {
      int bit = (int)((k >> (st->rounds - 1 - j)) & 1);
      const unsigned char *uj = st->u_flat + 32 * j;
      const unsigned char *ujinv = st->uinv_flat + 32 * j;
      secp256k1_mpt_scalar_mul(cur, cur, bit ? uj : ujinv);
    }
    memcpy(st->s_G_flat + 32 * k, cur, 32);
  }

  /* --- Intra-proof RLC weight c that batches E1 + c*E2 = 0 ---
   *   c = H("MPT_BP_VERIFY_BATCH_RLC" || u_{rounds-1} || tau_x || mu || a ||
   * b). Identical to the single-proof derivation in #100. */
  {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    unsigned char hash[32];
    unsigned int hlen = 0;
    int hash_ok = 0;
    if (!mdctx)
      return 0;
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1)
      goto c_cleanup;
    if (EVP_DigestUpdate(mdctx, "MPT_BP_VERIFY_BATCH_RLC", 23) != 1)
      goto c_cleanup;
    if (EVP_DigestUpdate(mdctx, st->u_flat + 32 * (st->rounds - 1), 32) != 1)
      goto c_cleanup;
    if (EVP_DigestUpdate(mdctx, st->tau_x, 32) != 1)
      goto c_cleanup;
    if (EVP_DigestUpdate(mdctx, st->mu, 32) != 1)
      goto c_cleanup;
    if (EVP_DigestUpdate(mdctx, st->a_final, 32) != 1)
      goto c_cleanup;
    if (EVP_DigestUpdate(mdctx, st->b_final, 32) != 1)
      goto c_cleanup;
    if (EVP_DigestFinal_ex(mdctx, hash, &hlen) != 1 || hlen != 32)
      goto c_cleanup;
    secp256k1_mpt_scalar_reduce32(st->c_scalar, hash);
    if (!secp256k1_ec_seckey_verify(ctx, st->c_scalar))
      goto c_cleanup;
    hash_ok = 1;
  c_cleanup:
    EVP_MD_CTX_free(mdctx);
    if (!hash_ok)
      return 0;
  }

  return 1;
}

static int bp_verify_consolidated_msm(const secp256k1_context *ctx,
                                      const secp256k1_pubkey *G_vec,
                                      const secp256k1_pubkey *H_vec,
                                      const secp256k1_pubkey *V_vec,
                                      const secp256k1_pubkey *h_generator,
                                      const secp256k1_pubkey *U,
                                      const bp_proof_state *st)
{
  /* Aliases that keep the assembly loops readable while still mapping
   * one-to-one onto the equations in the file-level comment block. */
  const unsigned char *a_final = st->a_final;
  const unsigned char *b_final = st->b_final;
  const unsigned char *t_hat = st->t_hat;
  const unsigned char *tau_x = st->tau_x;
  const unsigned char *mu = st->mu;
  const unsigned char *z = st->z;
  const unsigned char *x = st->x;
  const unsigned char *delta = st->delta;
  const unsigned char *ux_scalar = st->ux_scalar;
  const unsigned char *c_scalar = st->c_scalar;
  const unsigned char *y_inv_powers = st->y_inv_powers;
  const unsigned char *u_flat = st->u_flat;
  const unsigned char *uinv_flat = st->uinv_flat;
  const unsigned char *s_G_flat = st->s_G_flat;
  const secp256k1_pubkey *A = &st->A;
  const secp256k1_pubkey *S = &st->S;
  const secp256k1_pubkey *T1 = &st->T1;
  const secp256k1_pubkey *T2 = &st->T2;
  const secp256k1_pubkey *L_vec = st->L_vec;
  const secp256k1_pubkey *R_vec = st->R_vec;
  const size_t m = st->m, n = st->n, rounds = st->rounds;

  int ok = 0;
  unsigned char *points_ser = NULL;
  unsigned char *scalars_flat = NULL;
  unsigned char (*z_jp2)[32] = NULL;

  const size_t n_terms = 2 * n + 2 * rounds + m + 6;
  points_ser = (unsigned char *)malloc(n_terms * 33);
  scalars_flat = (unsigned char *)malloc(n_terms * 32);
  z_jp2 = (unsigned char (*)[32])malloc(m * 32);

  if (!points_ser || !scalars_flat || !z_jp2)
    goto cleanup;

  /* ---- Precompute z^(j+2) for j = 0..m-1 ---- */
  for (size_t j = 0; j < m; j++)
    scalar_pow_u32(ctx, z_jp2[j], z, (unsigned int)(j + 2));

  /* ---- (5) Assemble (scalar, point) pairs.
   *
   * Layout (idx -> term):
   *   0           : H_pk          coeff = tau_x - c*mu
   *   1..m        : V_j           coeff = -z^(j+2)
   *   m+1         : T1            coeff = -x
   *   m+2         : T2            coeff = -x^2
   *   m+3         : A             coeff = c
   *   m+4         : S             coeff = c*x
   *   m+5 ..      : G_k           coeff = c*(-z - a*s_k)
   *   m+5+n ..    : H_k           coeff = c*(z + z^(j_k+2)*2^{i_k}*y^{-k}
   *                                          - b*s_k^{-1}*y^{-k})
   *   m+5+2n      : U             coeff = c*u_x*(t_hat - a*b)
   *   m+6+2n ..   : L_i           coeff = c*u_i^2
   *   m+6+2n+r .. : R_i           coeff = c*u_i^{-2}
   *
   * G's coefficient (t_hat - delta) is passed via mpt_msm_variable_time's
   * inp_g_sc_be32 parameter.
   */
  size_t idx = 0;
  {
#define BP_WRITE_POINT(P_ptr)                                                  \
  do                                                                           \
  {                                                                            \
    size_t L_ = 33;                                                            \
    if (!secp256k1_ec_pubkey_serialize(ctx, points_ser + 33 * idx, &L_,        \
                                       (P_ptr), SECP256K1_EC_COMPRESSED) ||    \
        L_ != 33)                                                              \
      goto cleanup;                                                            \
  } while (0)
#define BP_WRITE_SCALAR(SRC) memcpy(scalars_flat + 32 * idx, (SRC), 32)
#define BP_BUMP() (idx++)

    /* (5a) H_pk: tau_x - c*mu */
    {
      unsigned char neg_mu[32], c_neg_mu[32], coef[32];
      memcpy(neg_mu, mu, 32);
      secp256k1_mpt_scalar_negate(neg_mu, neg_mu);
      secp256k1_mpt_scalar_mul(c_neg_mu, c_scalar, neg_mu);
      secp256k1_mpt_scalar_add(coef, tau_x, c_neg_mu);
      BP_WRITE_SCALAR(coef);
      BP_WRITE_POINT(h_generator);
      BP_BUMP();
    }

    /* (5b) V_j: -z^(j+2) */
    for (size_t j = 0; j < m; j++)
    {
      unsigned char coef[32];
      memcpy(coef, z_jp2[j], 32);
      secp256k1_mpt_scalar_negate(coef, coef);
      BP_WRITE_SCALAR(coef);
      BP_WRITE_POINT(&V_vec[j]);
      BP_BUMP();
    }

    /* (5c) T1: -x */
    {
      unsigned char coef[32];
      memcpy(coef, x, 32);
      secp256k1_mpt_scalar_negate(coef, coef);
      BP_WRITE_SCALAR(coef);
      BP_WRITE_POINT(T1);
      BP_BUMP();
    }

    /* (5d) T2: -x^2 */
    {
      unsigned char x_sq[32], coef[32];
      secp256k1_mpt_scalar_mul(x_sq, x, x);
      memcpy(coef, x_sq, 32);
      secp256k1_mpt_scalar_negate(coef, coef);
      BP_WRITE_SCALAR(coef);
      BP_WRITE_POINT(T2);
      BP_BUMP();
    }

    /* (5e) A: c */
    BP_WRITE_SCALAR(c_scalar);
    BP_WRITE_POINT(A);
    BP_BUMP();

    /* (5f) S: c*x */
    {
      unsigned char coef[32];
      secp256k1_mpt_scalar_mul(coef, c_scalar, x);
      BP_WRITE_SCALAR(coef);
      BP_WRITE_POINT(S);
      BP_BUMP();
    }

    /* (5g) G_k: c*(-z - a*s_k) */
    {
      unsigned char neg_z[32];
      memcpy(neg_z, z, 32);
      secp256k1_mpt_scalar_negate(neg_z, neg_z);
      for (size_t k = 0; k < n; k++)
      {
        unsigned char a_sk[32], inner[32], coef[32];
        secp256k1_mpt_scalar_mul(a_sk, a_final, s_G_flat + 32 * k);
        secp256k1_mpt_scalar_negate(a_sk, a_sk);
        secp256k1_mpt_scalar_add(inner, neg_z, a_sk);
        secp256k1_mpt_scalar_mul(coef, c_scalar, inner);
        BP_WRITE_SCALAR(coef);
        BP_WRITE_POINT(&G_vec[k]);
        BP_BUMP();
      }
    }

    /* (5h) H_k: c*(z + z^(j_k+2)*2^{i_k}*y^{-k} - b*s_k^{-1}*y^{-k})
     *
     * s_k^{-1} matches the H-fold pattern: bit-flip of s_G_k's selectors.
     * Compute it inline to avoid n scalar inversions (each ~256 squarings).
     */
    for (size_t k = 0; k < n; k++)
    {
      const size_t j_k = k / BP_VALUE_BITS;
      const size_t i_k = k % BP_VALUE_BITS;
      const unsigned char *y_inv_k = y_inv_powers + 32 * k;

      unsigned char s_H_k[32] = {0};
      s_H_k[31] = 1;
      for (size_t j = 0; j < rounds; j++)
      {
        int bit = (int)((k >> (rounds - 1 - j)) & 1);
        const unsigned char *uj = u_flat + 32 * j;
        const unsigned char *ujinv = uinv_flat + 32 * j;
        secp256k1_mpt_scalar_mul(s_H_k, s_H_k, bit ? ujinv : uj);
      }

      unsigned char two_i[32] = {0};
      two_i[31 - (i_k / 8)] = (unsigned char)(1u << (i_k % 8));

      unsigned char term1[32], term2[32], inner[32], coef[32];
      /* term1 = z^(j_k+2) * 2^{i_k} * y^{-k} */
      secp256k1_mpt_scalar_mul(term1, z_jp2[j_k], two_i);
      secp256k1_mpt_scalar_mul(term1, term1, y_inv_k);
      /* term2 = -b * s_H_k * y^{-k} */
      secp256k1_mpt_scalar_mul(term2, b_final, s_H_k);
      secp256k1_mpt_scalar_mul(term2, term2, y_inv_k);
      secp256k1_mpt_scalar_negate(term2, term2);
      /* inner = z + term1 + term2 */
      secp256k1_mpt_scalar_add(inner, z, term1);
      secp256k1_mpt_scalar_add(inner, inner, term2);
      secp256k1_mpt_scalar_mul(coef, c_scalar, inner);
      BP_WRITE_SCALAR(coef);
      BP_WRITE_POINT(&H_vec[k]);
      BP_BUMP();
    }

    /* (5i) U: c*u_x*(t_hat - a*b) */
    {
      unsigned char ab[32], t_minus_ab[32], coef[32];
      secp256k1_mpt_scalar_mul(ab, a_final, b_final);
      secp256k1_mpt_scalar_negate(ab, ab);
      secp256k1_mpt_scalar_add(t_minus_ab, t_hat, ab);
      secp256k1_mpt_scalar_mul(coef, c_scalar, t_minus_ab);
      secp256k1_mpt_scalar_mul(coef, coef, ux_scalar);
      BP_WRITE_SCALAR(coef);
      BP_WRITE_POINT(U);
      BP_BUMP();
    }

    /* (5j) L_i: c*u_i^2 */
    for (size_t i = 0; i < rounds; i++)
    {
      unsigned char u_sq[32], coef[32];
      const unsigned char *ui = u_flat + 32 * i;
      secp256k1_mpt_scalar_mul(u_sq, ui, ui);
      secp256k1_mpt_scalar_mul(coef, c_scalar, u_sq);
      BP_WRITE_SCALAR(coef);
      BP_WRITE_POINT(&L_vec[i]);
      BP_BUMP();
    }

    /* (5k) R_i: c*u_i^{-2} */
    for (size_t i = 0; i < rounds; i++)
    {
      unsigned char uinv_sq[32], coef[32];
      const unsigned char *uiinv = uinv_flat + 32 * i;
      secp256k1_mpt_scalar_mul(uinv_sq, uiinv, uiinv);
      secp256k1_mpt_scalar_mul(coef, c_scalar, uinv_sq);
      BP_WRITE_SCALAR(coef);
      BP_WRITE_POINT(&R_vec[i]);
      BP_BUMP();
    }

#undef BP_WRITE_POINT
#undef BP_WRITE_SCALAR
#undef BP_BUMP
  }

  if (idx != n_terms)
    goto cleanup;

  /* ---- (6) G coefficient: t_hat - delta (Check 1 only; E2 has no G). ---- */
  unsigned char g_coef[32];
  {
    unsigned char neg_delta[32];
    memcpy(neg_delta, delta, 32);
    secp256k1_mpt_scalar_negate(neg_delta, neg_delta);
    secp256k1_mpt_scalar_add(g_coef, t_hat, neg_delta);
  }

  /* ---- (7) Single MSM call; expected result = identity. ---- */
  unsigned char result[33];
  bp_verify_msm_cbdata cb_data = {scalars_flat, points_ser, n_terms};
  if (!mpt_msm_variable_time(ctx, result, g_coef, bp_verify_msm_cb, &cb_data,
                             n_terms))
    goto cleanup;

  /* Identity is encoded as 33 zero bytes by mpt_msm_variable_time. */
  unsigned char zero33[33] = {0};
  ok = (memcmp(result, zero33, 33) == 0) ? 1 : 0;

cleanup:
  free(points_ser);
  free(scalars_flat);
  free(z_jp2);
  return ok;
}

/**
 * Verifies an aggregated Bulletproof range proof for m commitments.
 *
 * Checks that the values committed in `commitment_C_vec` are all within the
 * [0, 2^64) range.
 *
 * Usage Notes:
 * - The generator vectors G_vec and H_vec must have length n = 64 * m.
 * - The commitment array `commitment_C_vec` must contain m elements.
 * (For a single proof where m=1, pass a pointer to the single commitment).
 * - To bind commitments to the proof transcript, include them in the
 * `context_id` hash before calling this function.
 *
 * Serialized Proof Format:
 * - A, S, T1, T2       (4 * 33 bytes)
 * - L_vec              (rounds * 33 bytes)
 * - R_vec              (rounds * 33 bytes)
 * - a, b               (2 * 32 bytes)
 * - t_hat, tau_x, mu   (3 * 32 bytes)
 *
 * Total Size: 292 + (66 * rounds) bytes, where rounds = log2(64 * m).
 *
 * Returns 1 if valid, 0 otherwise.
 */

int secp256k1_bulletproof_verify_agg(
    const secp256k1_context *ctx,
    const secp256k1_pubkey *G_vec, /* length n = 64*m */
    const secp256k1_pubkey *H_vec, /* length n = 64*m */
    const unsigned char *proof, size_t proof_len,
    const secp256k1_pubkey *commitment_C_vec, /* length m */
    size_t m, const secp256k1_pubkey *h_generator,
    const unsigned char *context_id)
{
  if (!ctx || !G_vec || !H_vec || !proof || !commitment_C_vec || !h_generator)
    return 0;

  /* Derive U (HKDF-derived, identical across all proofs in any batch). */
  secp256k1_pubkey U;
  {
    secp256k1_pubkey U_arr[1];
    if (!secp256k1_mpt_get_generator_vector(ctx, U_arr, 1,
                                            (const unsigned char *)"BP_U", 4))
      return 0;
    U = U_arr[0];
  }

  bp_proof_state st;
  if (!bp_proof_state_init(ctx, &st, commitment_C_vec, proof, proof_len, m,
                           context_id))
  {
    bp_proof_state_free(&st);
    return 0;
  }

  int ok = bp_verify_consolidated_msm(ctx, G_vec, H_vec, commitment_C_vec,
                                      h_generator, &U, &st);
  bp_proof_state_free(&st);
  return ok ? 1 : 0;
}

/* -------------------------------------------------------------------------
 * Batched aggregated-Bulletproof verification (issue #88).
 *
 * Verifies n_proofs aggregated proofs via BBB+18 sec. 6.1 RLC stacking
 * in a single mpt_msm_variable_time call. Per-proof inner check is the
 * same E1 + c_i*E2 = 0 collapse from #100, then the batch sums
 *   sum_i rho^i * (E1_i + c_i * E2_i) = 0
 * with rho derived after every proof's c_i is fixed.
 *
 * Efficiency win: the shared generators G_vec / H_vec / h_generator / U
 * contribute one MSM term each regardless of batch size, because their
 * per-proof coefficients are summed before the MSM rather than
 * accumulated point-by-point. For a batch of B proofs at m=2 this
 * collapses ~B*278 terms down to ~258 + 20*B.
 */

int secp256k1_bulletproof_verify_batch_agg(
    const secp256k1_context *ctx, const secp256k1_pubkey *G_vec,
    const secp256k1_pubkey *H_vec, const unsigned char *const *proofs,
    const size_t *proof_lens, const secp256k1_pubkey *const *commitment_C_vecs,
    const size_t *m_vec, const secp256k1_pubkey *h_generator,
    const unsigned char *const *context_ids, size_t n_proofs)
{
  if (!ctx || !G_vec || !H_vec || !proofs || !proof_lens ||
      !commitment_C_vecs || !m_vec || !h_generator || !context_ids ||
      n_proofs == 0)
    return 0;

  int ok = 0;
  bp_proof_state *states = NULL;
  unsigned char *G_coeffs = NULL;
  unsigned char *H_coeffs = NULL;
  unsigned char *points_ser = NULL;
  unsigned char *scalars_flat = NULL;
  unsigned char (*z_jp2_max)[32] = NULL;

  /* Validate m_vec entries and compute max_m / max_n. */
  size_t max_m = 0;
  for (size_t i = 0; i < n_proofs; i++)
  {
    if (m_vec[i] == 0 || m_vec[i] > BP_MAX_VALUES)
      return 0;
    if ((m_vec[i] & (m_vec[i] - 1)) != 0)
      return 0;
    if (m_vec[i] > max_m)
      max_m = m_vec[i];
  }
  const size_t max_n = BP_TOTAL_BITS(max_m);

  /* Derive U (shared across all proofs in the batch). */
  secp256k1_pubkey U;
  {
    secp256k1_pubkey U_arr[1];
    if (!secp256k1_mpt_get_generator_vector(ctx, U_arr, 1,
                                            (const unsigned char *)"BP_U", 4))
      return 0;
    U = U_arr[0];
  }

  /* Pass 1: parse + derive per-proof state (incl. each proof's c_scalar). */
  states = (bp_proof_state *)calloc(n_proofs, sizeof(bp_proof_state));
  if (!states)
    return 0;
  for (size_t i = 0; i < n_proofs; i++)
  {
    if (!commitment_C_vecs[i] || !proofs[i])
      goto cleanup;
    if (!bp_proof_state_init(ctx, &states[i], commitment_C_vecs[i], proofs[i],
                             proof_lens[i], m_vec[i], context_ids[i]))
      goto cleanup;
  }

  /* Derive batch RLC weight rho.
   *   rho = H("MPT_BP_VERIFY_BATCH" || c_0 || c_1 || ... || c_{n_proofs-1}).
   * Each c_i transitively binds all of proof_i's bytes (incl. commitments
   * and context_id) via the FS chain, so rho binds every input to the
   * batch verifier. */
  unsigned char rho[32];
  {
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    unsigned char hash[32];
    unsigned int hlen = 0;
    int rho_ok = 0;
    if (!md)
      goto cleanup;
    if (EVP_DigestInit_ex(md, EVP_sha256(), NULL) != 1)
      goto rho_cleanup;
    if (EVP_DigestUpdate(md, "MPT_BP_VERIFY_BATCH", 19) != 1)
      goto rho_cleanup;
    for (size_t i = 0; i < n_proofs; i++)
    {
      if (EVP_DigestUpdate(md, states[i].c_scalar, 32) != 1)
        goto rho_cleanup;
    }
    if (EVP_DigestFinal_ex(md, hash, &hlen) != 1 || hlen != 32)
      goto rho_cleanup;
    secp256k1_mpt_scalar_reduce32(rho, hash);
    if (!secp256k1_ec_seckey_verify(ctx, rho))
      goto rho_cleanup;
    rho_ok = 1;
  rho_cleanup:
    EVP_MD_CTX_free(md);
    if (!rho_ok)
      goto cleanup;
  }

  /* Shared accumulators. */
  G_coeffs = (unsigned char *)calloc(max_n, 32);
  H_coeffs = (unsigned char *)calloc(max_n, 32);
  unsigned char H_pk_coef[32] = {0};
  unsigned char U_coef[32] = {0};
  unsigned char G_gen_coef[32] = {0};

  /* Total MSM term count: shared + per-proof slots. */
  size_t total_per_proof_terms = 0;
  for (size_t i = 0; i < n_proofs; i++)
    total_per_proof_terms += m_vec[i] + 4 + 2 * states[i].rounds;
  const size_t shared_terms = 2 * max_n + 2; /* G_k + H_k + H_pk + U */
  const size_t n_terms = shared_terms + total_per_proof_terms;

  points_ser = (unsigned char *)malloc(n_terms * 33);
  scalars_flat = (unsigned char *)malloc(n_terms * 32);
  z_jp2_max = (unsigned char (*)[32])malloc(max_m * 32);
  if (!G_coeffs || !H_coeffs || !points_ser || !scalars_flat || !z_jp2_max)
    goto cleanup;

  /* Pass 2: per-proof contribution accumulation.
   * Per-proof points are written to the [shared_terms ..] tail.
   * Shared coefficients are summed into G_coeffs / H_coeffs / H_pk_coef /
   * U_coef / G_gen_coef. */
  size_t pp_idx = shared_terms;
  unsigned char rho_i[32] = {0};
  rho_i[31] = 1; /* rho^0 = 1 */

  for (size_t i = 0; i < n_proofs; i++)
  {
    const bp_proof_state *st = &states[i];
    const size_t m = st->m, n = st->n, rounds = st->rounds;
    const unsigned char *c = st->c_scalar;
    const unsigned char *z = st->z, *x = st->x;
    const unsigned char *a = st->a_final, *b = st->b_final;
    const unsigned char *t_hat = st->t_hat, *tau_x = st->tau_x, *mu = st->mu;
    const unsigned char *ux = st->ux_scalar;
    const unsigned char *delta = st->delta;

    if (i > 0)
      secp256k1_mpt_scalar_mul(rho_i, rho_i, rho);

    /* z^(j+2) for j=0..m-1 (reuses z_jp2_max scratch). */
    for (size_t j = 0; j < m; j++)
      scalar_pow_u32(ctx, z_jp2_max[j], z, (unsigned int)(j + 2));

    unsigned char rho_c[32];
    secp256k1_mpt_scalar_mul(rho_c, rho_i, c);

    /* G_gen_coef += rho_i * (t_hat - delta) */
    {
      unsigned char tmp[32], tmp2[32];
      memcpy(tmp, delta, 32);
      secp256k1_mpt_scalar_negate(tmp, tmp);
      secp256k1_mpt_scalar_add(tmp, tmp, t_hat);
      secp256k1_mpt_scalar_mul(tmp2, rho_i, tmp);
      secp256k1_mpt_scalar_add(G_gen_coef, G_gen_coef, tmp2);
    }

    /* H_pk_coef += rho_i*tau_x - rho_c*mu */
    {
      unsigned char neg_mu[32], rc_mu[32], r_tau[32], tmp[32];
      memcpy(neg_mu, mu, 32);
      secp256k1_mpt_scalar_negate(neg_mu, neg_mu);
      secp256k1_mpt_scalar_mul(rc_mu, rho_c, neg_mu);
      secp256k1_mpt_scalar_mul(r_tau, rho_i, tau_x);
      secp256k1_mpt_scalar_add(tmp, r_tau, rc_mu);
      secp256k1_mpt_scalar_add(H_pk_coef, H_pk_coef, tmp);
    }

    /* U_coef += rho_c * ux * (t_hat - a*b) */
    {
      unsigned char ab[32], t_minus_ab[32], coef[32];
      secp256k1_mpt_scalar_mul(ab, a, b);
      secp256k1_mpt_scalar_negate(ab, ab);
      secp256k1_mpt_scalar_add(t_minus_ab, t_hat, ab);
      secp256k1_mpt_scalar_mul(coef, rho_c, t_minus_ab);
      secp256k1_mpt_scalar_mul(coef, coef, ux);
      secp256k1_mpt_scalar_add(U_coef, U_coef, coef);
    }

    /* G_k accumulator: G_coeffs[k] += rho_c * (-z - a*s_k) */
    {
      unsigned char neg_z[32];
      memcpy(neg_z, z, 32);
      secp256k1_mpt_scalar_negate(neg_z, neg_z);
      for (size_t k = 0; k < n; k++)
      {
        unsigned char a_sk[32], inner[32], coef[32];
        secp256k1_mpt_scalar_mul(a_sk, a, st->s_G_flat + 32 * k);
        secp256k1_mpt_scalar_negate(a_sk, a_sk);
        secp256k1_mpt_scalar_add(inner, neg_z, a_sk);
        secp256k1_mpt_scalar_mul(coef, rho_c, inner);
        secp256k1_mpt_scalar_add(G_coeffs + 32 * k, G_coeffs + 32 * k, coef);
      }
    }

    /* H_k accumulator: H_coeffs[k] +=
     *   rho_c * (z + z^(j_k+2)*2^{i_k}*y^{-k} - b * s_k^{-1} * y^{-k}) */
    for (size_t k = 0; k < n; k++)
    {
      const size_t j_k = k / BP_VALUE_BITS;
      const size_t i_k = k % BP_VALUE_BITS;
      const unsigned char *y_inv_k = st->y_inv_powers + 32 * k;

      unsigned char s_H_k[32] = {0};
      s_H_k[31] = 1;
      for (size_t j = 0; j < rounds; j++)
      {
        int bit = (int)((k >> (rounds - 1 - j)) & 1);
        const unsigned char *uj = st->u_flat + 32 * j;
        const unsigned char *ujinv = st->uinv_flat + 32 * j;
        secp256k1_mpt_scalar_mul(s_H_k, s_H_k, bit ? ujinv : uj);
      }

      unsigned char two_i[32] = {0};
      two_i[31 - (i_k / 8)] = (unsigned char)(1u << (i_k % 8));

      unsigned char term1[32], term2[32], inner[32], coef[32];
      secp256k1_mpt_scalar_mul(term1, z_jp2_max[j_k], two_i);
      secp256k1_mpt_scalar_mul(term1, term1, y_inv_k);
      secp256k1_mpt_scalar_mul(term2, b, s_H_k);
      secp256k1_mpt_scalar_mul(term2, term2, y_inv_k);
      secp256k1_mpt_scalar_negate(term2, term2);
      secp256k1_mpt_scalar_add(inner, z, term1);
      secp256k1_mpt_scalar_add(inner, inner, term2);
      secp256k1_mpt_scalar_mul(coef, rho_c, inner);
      secp256k1_mpt_scalar_add(H_coeffs + 32 * k, H_coeffs + 32 * k, coef);
    }

#define BAT_WRITE_POINT(P_ptr)                                                 \
  do                                                                           \
  {                                                                            \
    size_t L_ = 33;                                                            \
    if (!secp256k1_ec_pubkey_serialize(ctx, points_ser + 33 * pp_idx, &L_,     \
                                       (P_ptr), SECP256K1_EC_COMPRESSED) ||    \
        L_ != 33)                                                              \
      goto cleanup;                                                            \
  } while (0)
#define BAT_WRITE_SCALAR(SRC) memcpy(scalars_flat + 32 * pp_idx, (SRC), 32)

    /* Per-proof: V_j = -rho_i * z^(j+2) */
    for (size_t j = 0; j < m; j++)
    {
      unsigned char coef[32];
      memcpy(coef, z_jp2_max[j], 32);
      secp256k1_mpt_scalar_negate(coef, coef);
      secp256k1_mpt_scalar_mul(coef, coef, rho_i);
      BAT_WRITE_SCALAR(coef);
      BAT_WRITE_POINT(&commitment_C_vecs[i][j]);
      pp_idx++;
    }
    /* T1: -rho_i * x */
    {
      unsigned char coef[32];
      memcpy(coef, x, 32);
      secp256k1_mpt_scalar_negate(coef, coef);
      secp256k1_mpt_scalar_mul(coef, coef, rho_i);
      BAT_WRITE_SCALAR(coef);
      BAT_WRITE_POINT(&st->T1);
      pp_idx++;
    }
    /* T2: -rho_i * x^2 */
    {
      unsigned char x_sq[32], coef[32];
      secp256k1_mpt_scalar_mul(x_sq, x, x);
      memcpy(coef, x_sq, 32);
      secp256k1_mpt_scalar_negate(coef, coef);
      secp256k1_mpt_scalar_mul(coef, coef, rho_i);
      BAT_WRITE_SCALAR(coef);
      BAT_WRITE_POINT(&st->T2);
      pp_idx++;
    }
    /* A: rho_c */
    BAT_WRITE_SCALAR(rho_c);
    BAT_WRITE_POINT(&st->A);
    pp_idx++;
    /* S: rho_c * x */
    {
      unsigned char coef[32];
      secp256k1_mpt_scalar_mul(coef, rho_c, x);
      BAT_WRITE_SCALAR(coef);
      BAT_WRITE_POINT(&st->S);
      pp_idx++;
    }
    /* L_j: rho_c * u_j^2 */
    for (size_t j = 0; j < rounds; j++)
    {
      unsigned char u_sq[32], coef[32];
      const unsigned char *uj = st->u_flat + 32 * j;
      secp256k1_mpt_scalar_mul(u_sq, uj, uj);
      secp256k1_mpt_scalar_mul(coef, rho_c, u_sq);
      BAT_WRITE_SCALAR(coef);
      BAT_WRITE_POINT(&st->L_vec[j]);
      pp_idx++;
    }
    /* R_j: rho_c * u_j^{-2} */
    for (size_t j = 0; j < rounds; j++)
    {
      unsigned char uinv_sq[32], coef[32];
      const unsigned char *ujinv = st->uinv_flat + 32 * j;
      secp256k1_mpt_scalar_mul(uinv_sq, ujinv, ujinv);
      secp256k1_mpt_scalar_mul(coef, rho_c, uinv_sq);
      BAT_WRITE_SCALAR(coef);
      BAT_WRITE_POINT(&st->R_vec[j]);
      pp_idx++;
    }

#undef BAT_WRITE_POINT
#undef BAT_WRITE_SCALAR
  }

  if (pp_idx != n_terms)
    goto cleanup;

  /* Write the shared slots: G_k (k=0..max_n-1), H_k, h_generator, U. */
  for (size_t k = 0; k < max_n; k++)
  {
    size_t L_ = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, points_ser + 33 * k, &L_, &G_vec[k],
                                       SECP256K1_EC_COMPRESSED) ||
        L_ != 33)
      goto cleanup;
    memcpy(scalars_flat + 32 * k, G_coeffs + 32 * k, 32);
  }
  for (size_t k = 0; k < max_n; k++)
  {
    size_t L_ = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, points_ser + 33 * (max_n + k), &L_,
                                       &H_vec[k], SECP256K1_EC_COMPRESSED) ||
        L_ != 33)
      goto cleanup;
    memcpy(scalars_flat + 32 * (max_n + k), H_coeffs + 32 * k, 32);
  }
  {
    size_t L_ = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, points_ser + 33 * (2 * max_n), &L_,
                                       h_generator, SECP256K1_EC_COMPRESSED) ||
        L_ != 33)
      goto cleanup;
    memcpy(scalars_flat + 32 * (2 * max_n), H_pk_coef, 32);
  }
  {
    size_t L_ = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, points_ser + 33 * (2 * max_n + 1),
                                       &L_, &U, SECP256K1_EC_COMPRESSED) ||
        L_ != 33)
      goto cleanup;
    memcpy(scalars_flat + 32 * (2 * max_n + 1), U_coef, 32);
  }

  /* Single batched MSM call; expected result = identity. */
  {
    unsigned char result[33];
    bp_verify_msm_cbdata cb_data = {scalars_flat, points_ser, n_terms};
    if (!mpt_msm_variable_time(ctx, result, G_gen_coef, bp_verify_msm_cb,
                               &cb_data, n_terms))
      goto cleanup;
    unsigned char zero33[33] = {0};
    ok = (memcmp(result, zero33, 33) == 0) ? 1 : 0;
  }

cleanup:
  free(G_coeffs);
  free(H_coeffs);
  free(points_ser);
  free(scalars_flat);
  free(z_jp2_max);
  if (states)
  {
    for (size_t i = 0; i < n_proofs; i++)
      bp_proof_state_free(&states[i]);
    free(states);
  }
  return ok;
}
