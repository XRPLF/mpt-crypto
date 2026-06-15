/**
 * @file elgamal.c
 * @brief EC-ElGamal Encryption for Confidential Balances.
 *
 * This module implements additive homomorphic encryption using the ElGamal
 * scheme over the secp256k1 elliptic curve. It provides the core mechanism
 * for representing confidential balances and transferring value on the ledger.
 *
 * @details
 * **Encryption Scheme:**
 * Given a public key \f$ Q = sk \cdot G \f$ and a plaintext amount \f$ m \f$,
 * encryption with randomness \f$ r \f$ produces a ciphertext pair \f$ (C_1,
 * C_2) \f$:
 * - \f$ C_1 = r \cdot G \f$ (Ephemeral public key)
 * - \f$ C_2 = m \cdot G + r \cdot Q \f$ (Masked amount)
 *
 * **Homomorphism:**
 * The scheme is additively homomorphic:
 * \f[ Enc(m_1) + Enc(m_2) = (C_{1,1}+C_{1,2}, C_{2,1}+C_{2,2}) = Enc(m_1 + m_2)
 * \f] This allows validators to update balances (e.g., add incoming transfers)
 * without decrypting them.
 *
 * **Decryption (Discrete Logarithm):**
 * Decryption involves two steps:
 * 1. Remove the mask: \f$ M = C_2 - sk \cdot C_1 = m \cdot G \f$.
 * 2. Recover \f$ m \f$ from \f$ M \f$: This requires solving the Discrete
 * Logarithm Problem (DLP) for \f$ m \f$. Since balances are 64-bit integers but
 * typically small in "human" terms, this implementation uses an optimized
 * search for ranges relevant to transaction processing (e.g., 0 to 1,000,000).
 *
 * **Canonical Zero:**
 * To ensure deterministic ledger state for empty accounts, a "Canonical
 * Encrypted Zero" is defined using randomness derived deterministically from
 * the account ID and token ID.
 *
 * @see [Spec (ConfidentialMPT_20260201.pdf) Section 3.2.2] ElGamal Encryption
 */
#include "mpt_internal.h"
#include "secp256k1_mpt.h"
#include "bsgs_dlp.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>

/* --- Internal Helpers --- */

/* --- Key Generation --- */

int secp256k1_elgamal_generate_keypair(const secp256k1_context *ctx,
                                       unsigned char *privkey,
                                       secp256k1_pubkey *pubkey)
{
  MPT_ARG_CHECK(ctx != NULL);
  MPT_ARG_CHECK(privkey != NULL);
  MPT_ARG_CHECK(pubkey != NULL);

  do
  {
    if (RAND_bytes(privkey, kMPT_PRIVKEY_SIZE) != 1)
      return 0;
  } while (!secp256k1_ec_seckey_verify(ctx, privkey));

  if (!secp256k1_ec_pubkey_create(ctx, pubkey, privkey))
  {
    OPENSSL_cleanse(privkey, kMPT_PRIVKEY_SIZE); // Cleanup on failure
    return 0;
  }
  return 1;
}

/* --- Encryption --- */

int secp256k1_elgamal_encrypt(const secp256k1_context *ctx,
                              secp256k1_pubkey *c1, secp256k1_pubkey *c2,
                              const secp256k1_pubkey *pubkey_Q, uint64_t amount,
                              const unsigned char *blinding_factor)
{
  MPT_ARG_CHECK(ctx != NULL);
  MPT_ARG_CHECK(c1 != NULL);
  MPT_ARG_CHECK(c2 != NULL);
  MPT_ARG_CHECK(pubkey_Q != NULL);
  MPT_ARG_CHECK(blinding_factor != NULL);

  secp256k1_pubkey S, mG;
  const secp256k1_pubkey *pts[2];

  /* 1. C1 = r * G */
  if (!secp256k1_ec_pubkey_create(ctx, c1, blinding_factor))
    return 0;

  /* 2. S = r * Q (Shared Secret) */
  S = *pubkey_Q;
  if (!mpt_ct_pubkey_tweak_mul(ctx, &S, blinding_factor))
    return 0;

  /* 3. C2 = S + m*G */
  if (amount == 0)
  {
    *c2 = S; // m*G is infinity, so C2 = S
  }
  else
  {
    if (!compute_amount_point(ctx, &mG, amount))
      return 0;
    pts[0] = &mG;
    pts[1] = &S;
    if (!secp256k1_ec_pubkey_combine(ctx, c2, pts, 2))
      return 0;
  }

  return 1;
}

/* --- Decryption --- */

/* Branchless brute-force DLP solver over the range [range_low, range_high].
 *
 * Runs exactly `range_high - effective_low + 1` iterations regardless of
 * whether and where the target is found, where effective_low = max(1,
 * range_low). This is a "fixed iteration count" property, not a full
 * constant-time guarantee: the underlying libsecp256k1 EC operations are
 * themselves variable-time, so this loop hides the position of the match but
 * not microarchitectural variations of individual point ops.
 *
 * On success, `*out_amount` holds the recovered `i` such that `i*G`
 * serializes to `target_ser`, and `*out_is_found` is 1; if no match is
 * found, `*out_is_found` is 0.  Returns 0 on internal failure (e.g.,
 * libsecp256k1 serialization fail). */
static int secp256k1_solve_dlp_small_range_fixed(
    const secp256k1_context *ctx, uint64_t *out_amount, uint64_t *out_is_found,
    const unsigned char target_ser[33], uint64_t range_low, uint64_t range_high)
{
  /* The zero case (m=0) is handled separately by the caller.
   * Effective start for this loop is max(1, range_low). */
  uint64_t effective_low = (range_low < 1) ? 1 : range_low;

  if (effective_low > range_high)
  {
    *out_amount = 0;
    *out_is_found = 0;
    return 1;
  }

  unsigned char one[kMPT_SCALAR_SIZE] = {0};
  one[kMPT_SCALAR_SIZE - 1] = 1;

  secp256k1_pubkey G_point;
  if (!secp256k1_ec_pubkey_create(ctx, &G_point, one))
  {
    OPENSSL_cleanse(one, kMPT_SCALAR_SIZE);
    return 0;
  }

  /* Compute starting point: effective_low * G.
   * If effective_low == 1, this is just G_point.
   * Otherwise, encode effective_low as a 32-byte big-endian scalar and
   * compute the starting point via scalar multiplication. */
  secp256k1_pubkey current_M;
  if (effective_low == 1)
  {
    current_M = G_point;
  }
  else
  {
    unsigned char start_scalar[kMPT_SCALAR_SIZE] = {0};
    uint64_t tmp = effective_low;
    for (int k = 0; k < 8; k++)
    {
      start_scalar[kMPT_SCALAR_SIZE - 1 - k] = (unsigned char)(tmp & 0xFF);
      tmp >>= 8;
    }
    int ok = secp256k1_ec_pubkey_create(ctx, &current_M, start_scalar);
    OPENSSL_cleanse(start_scalar, kMPT_SCALAR_SIZE);
    if (!ok)
    {
      OPENSSL_cleanse(one, kMPT_SCALAR_SIZE);
      return 0;
    }
  }

  secp256k1_pubkey next_M;
  const secp256k1_pubkey *pts[2];
  unsigned char current_M_ser[33];

  uint64_t found_amount = 0;
  uint64_t is_found = 0;
  unsigned char global_ser_error = 0;

  for (uint64_t i = effective_low; i <= range_high; ++i)
  {
    /* Serialize current_M.  Use a fallback buffer so a libsecp failure
     * cannot leak data through the comparison below. */
    size_t ser_len = 33;
    unsigned char temp_ser[33] = {0};
    int ser_ok = secp256k1_ec_pubkey_serialize(
        ctx, temp_ser, &ser_len, &current_M, SECP256K1_EC_COMPRESSED);

    /* Branchless: ser_mask = 0xFF iff ser_ok==1, else 0x00. */
    unsigned char ser_mask = (unsigned char)(0 - ser_ok);
    for (int j = 0; j < 33; j++)
      current_M_ser[j] = temp_ser[j] & ser_mask;

    /* Track any serialization anomaly across all iterations; an outer
     * check turns the result into a failure if anything went wrong. */
    global_ser_error |= (unsigned char)(ser_ok ^ 1);
    global_ser_error |= (unsigned char)(ser_len ^ 33);

    /* Constant-time byte-by-byte comparison: accumulate OR of XORs. */
    unsigned char match_diff = 0;
    for (int j = 0; j < 33; j++)
      match_diff |= current_M_ser[j] ^ target_ser[j];

    /* Mix in serialization status: a failed iteration must never match. */
    match_diff |= (unsigned char)(ser_ok ^ 1);
    match_diff |= (unsigned char)(ser_len ^ 33);

    /* Saturate diff to a 1-bit match flag (1 iff match_diff==0). */
    uint64_t diff64 = (uint64_t)match_diff;
    uint64_t match = 1 ^ (((diff64 | (~diff64 + 1)) >> 63) & 1);

    /* Constant-time conditional move: when `match` is 1, overwrite
     * `found_amount` with `i`; otherwise leave it unchanged. */
    uint64_t match_mask = ~(match - 1);
    found_amount ^= (found_amount ^ i) & match_mask;
    is_found |= match;

    /* current_M += G  (always executed; result placed via byte-level cmov). */
    pts[0] = &current_M;
    pts[1] = &G_point;
    int combine_ok = secp256k1_ec_pubkey_combine(ctx, &next_M, pts, 2);
    unsigned char combine_mask = (unsigned char)(0 - combine_ok);
    unsigned char *curr_ptr = (unsigned char *)&current_M;
    unsigned char *next_ptr = (unsigned char *)&next_M;
    for (size_t b = 0; b < sizeof(secp256k1_pubkey); b++)
      curr_ptr[b] =
          (curr_ptr[b] & ~combine_mask) | (next_ptr[b] & combine_mask);

    global_ser_error |= (unsigned char)(combine_ok ^ 1);
  }

  OPENSSL_cleanse(current_M_ser, 33);
  OPENSSL_cleanse(one, kMPT_SCALAR_SIZE);

  if (global_ser_error != 0)
  {
    *out_amount = 0;
    *out_is_found = 0;
    return 0;
  }

  *out_amount = found_amount;
  *out_is_found = is_found;
  return 1;
}

int secp256k1_elgamal_decrypt(const secp256k1_context *ctx, uint64_t *amount,
                              const secp256k1_pubkey *c1,
                              const secp256k1_pubkey *c2,
                              const unsigned char *privkey, uint64_t range_low,
                              uint64_t range_high)
{
  MPT_ARG_CHECK(ctx != NULL);
  MPT_ARG_CHECK(amount != NULL);
  MPT_ARG_CHECK(c1 != NULL);
  MPT_ARG_CHECK(c2 != NULL);
  MPT_ARG_CHECK(privkey != NULL);

  /* Validate range */
  if (range_low > range_high)
    return 0;

  secp256k1_pubkey S, M_target_sum, neg_S;
  const secp256k1_pubkey *pts[2];
  unsigned char c2_ser[33], S_ser[33], M_target_ser[33];
  size_t ser_len;

  /* 1. Recover Shared Secret: S = privkey * c1. */
  S = *c1;
  if (!mpt_ct_pubkey_tweak_mul(ctx, &S, privkey))
    return 0;

  /* Serialize c2 and S once up front; the loop never serializes the
   * input ciphertext side, only candidate points i*G. */
  ser_len = 33;
  if (!secp256k1_ec_pubkey_serialize(ctx, c2_ser, &ser_len, c2,
                                     SECP256K1_EC_COMPRESSED) ||
      ser_len != 33)
    return 0;
  ser_len = 33;
  if (!secp256k1_ec_pubkey_serialize(ctx, S_ser, &ser_len, &S,
                                     SECP256K1_EC_COMPRESSED) ||
      ser_len != 33)
  {
    OPENSSL_cleanse(c2_ser, 33);
    return 0;
  }

  /* 2. Constant-time check for amount=0 (c2 == S).  No early return: we
   * run the full DLP loop unconditionally so an outside observer cannot
   * distinguish the m=0 path from the m>0 path by timing. */
  unsigned char zero_diff_u8 = 0;
  for (int j = 0; j < 33; j++)
    zero_diff_u8 |= c2_ser[j] ^ S_ser[j];
  uint64_t zero_diff64 = (uint64_t)zero_diff_u8;
  uint64_t match_zero = 1 ^ (((zero_diff64 | (~zero_diff64 + 1)) >> 63) & 1);

  /* Only accept zero match if 0 is within [range_low, range_high]. */
  uint64_t zero_in_range = (range_low == 0) ? (uint64_t)1 : (uint64_t)0;
  uint64_t effective_match_zero = match_zero & (~(zero_in_range - 1));

  /* 3. Compute M_target_sum = c2 - S = c2 + (-S).  If this fails (point
   * at infinity, which is exactly the m=0 case), we leave M_target_ser
   * as the constant zero buffer so the loop simply never matches. */
  neg_S = S;
  if (!secp256k1_ec_pubkey_negate(ctx, &neg_S))
  {
    OPENSSL_cleanse(S_ser, 33);
    OPENSSL_cleanse(c2_ser, 33);
    return 0;
  }
  pts[0] = c2;
  pts[1] = &neg_S;
  memset(M_target_ser, 0, 33);
  if (secp256k1_ec_pubkey_combine(ctx, &M_target_sum, pts, 2))
  {
    ser_len = 33;
    unsigned char tmp[33];
    if (secp256k1_ec_pubkey_serialize(ctx, tmp, &ser_len, &M_target_sum,
                                      SECP256K1_EC_COMPRESSED) &&
        ser_len == 33)
      memcpy(M_target_ser, tmp, 33);
    OPENSSL_cleanse(tmp, 33);
  }

  /* 4. Fixed-iteration DLP search over [range_low, range_high]. */
  uint64_t loop_amount = 0;
  uint64_t match_loop = 0;
  int solver_ok = secp256k1_solve_dlp_small_range_fixed(
      ctx, &loop_amount, &match_loop, M_target_ser, range_low, range_high);

  /* 5. Constant-time resolution: prefer the m=0 path if it matched. */
  uint64_t is_found = effective_match_zero | match_loop;
  uint64_t zero_mask = ~(effective_match_zero - 1);
  *amount = (loop_amount & ~zero_mask); /* loop_amount when match_zero=0 */
  /* zero_mask=all-ones if match_zero=1 — *amount stays 0 in that case. */

  /* 6. Scrub sensitive intermediates. */
  OPENSSL_cleanse(S_ser, 33);
  OPENSSL_cleanse(c2_ser, 33);
  OPENSSL_cleanse(M_target_ser, 33);

  if (!solver_ok)
    return 0;
  return (int)is_found;
}

/* --- Homomorphic Operations --- */

int secp256k1_elgamal_add(const secp256k1_context *ctx,
                          secp256k1_pubkey *sum_c1, secp256k1_pubkey *sum_c2,
                          const secp256k1_pubkey *a_c1,
                          const secp256k1_pubkey *a_c2,
                          const secp256k1_pubkey *b_c1,
                          const secp256k1_pubkey *b_c2)
{
  MPT_ARG_CHECK(ctx != NULL);
  MPT_ARG_CHECK(sum_c1 != NULL);
  MPT_ARG_CHECK(sum_c2 != NULL);
  MPT_ARG_CHECK(a_c1 != NULL);
  MPT_ARG_CHECK(a_c2 != NULL);
  MPT_ARG_CHECK(b_c1 != NULL);
  MPT_ARG_CHECK(b_c2 != NULL);

  const secp256k1_pubkey *pts[2];

  pts[0] = a_c1;
  pts[1] = b_c1;
  if (!secp256k1_ec_pubkey_combine(ctx, sum_c1, pts, 2))
    return 0;

  pts[0] = a_c2;
  pts[1] = b_c2;
  if (!secp256k1_ec_pubkey_combine(ctx, sum_c2, pts, 2))
    return 0;

  return 1;
}

int secp256k1_elgamal_subtract(const secp256k1_context *ctx,
                               secp256k1_pubkey *diff_c1,
                               secp256k1_pubkey *diff_c2,
                               const secp256k1_pubkey *a_c1,
                               const secp256k1_pubkey *a_c2,
                               const secp256k1_pubkey *b_c1,
                               const secp256k1_pubkey *b_c2)
{
  MPT_ARG_CHECK(ctx != NULL);
  MPT_ARG_CHECK(diff_c1 != NULL);
  MPT_ARG_CHECK(diff_c2 != NULL);
  MPT_ARG_CHECK(a_c1 != NULL);
  MPT_ARG_CHECK(a_c2 != NULL);
  MPT_ARG_CHECK(b_c1 != NULL);
  MPT_ARG_CHECK(b_c2 != NULL);

  secp256k1_pubkey neg_b_c1 = *b_c1;
  secp256k1_pubkey neg_b_c2 = *b_c2;
  const secp256k1_pubkey *pts[2];

  if (!secp256k1_ec_pubkey_negate(ctx, &neg_b_c1))
    return 0;
  if (!secp256k1_ec_pubkey_negate(ctx, &neg_b_c2))
    return 0;

  pts[0] = a_c1;
  pts[1] = &neg_b_c1;
  if (!secp256k1_ec_pubkey_combine(ctx, diff_c1, pts, 2))
    return 0;

  pts[0] = a_c2;
  pts[1] = &neg_b_c2;
  if (!secp256k1_ec_pubkey_combine(ctx, diff_c2, pts, 2))
    return 0;

  return 1;
}

/* --- Canonical Encrypted Zero --- */

int generate_canonical_encrypted_zero(
    const secp256k1_context *ctx, secp256k1_pubkey *enc_zero_c1,
    secp256k1_pubkey *enc_zero_c2, const secp256k1_pubkey *pubkey,
    const unsigned char *account_id,     // 20 bytes
    const unsigned char *mpt_issuance_id // 24 bytes
)
{
  MPT_ARG_CHECK(ctx != NULL);
  MPT_ARG_CHECK(enc_zero_c1 != NULL);
  MPT_ARG_CHECK(enc_zero_c2 != NULL);
  MPT_ARG_CHECK(pubkey != NULL);
  MPT_ARG_CHECK(account_id != NULL);
  MPT_ARG_CHECK(mpt_issuance_id != NULL);

  unsigned char deterministic_scalar[kMPT_SCALAR_SIZE];
  unsigned char hash_input[51]; // 7 ("EncZero") + 20 + 24
  const char *domain = "EncZero";
  int ret;

  // Build static buffer part
  memcpy(hash_input, domain, 7);
  memcpy(hash_input + 7, account_id, 20);
  memcpy(hash_input + 27, mpt_issuance_id, 24);

  /* Initial hash of the domain-tagged input. */
  unsigned int md_len = kMPT_HALF_SHA_SIZE;
  if (EVP_Digest(hash_input, 51, deterministic_scalar, &md_len, EVP_sha256(),
                 NULL) != 1)
    return 0;

  /* Rejection sampling: chain-hash the 32-byte previous output until it is a
   * valid secp256k1 scalar. The probability of needing more than one iteration
   * is ~2^-128, so in practice the loop body executes zero times. */
  while (!secp256k1_ec_seckey_verify(ctx, deterministic_scalar))
  {
    if (EVP_Digest(deterministic_scalar, kMPT_HALF_SHA_SIZE,
                   deterministic_scalar, &md_len, EVP_sha256(), NULL) != 1)
      return 0;
  }

  ret = secp256k1_elgamal_encrypt(ctx, enc_zero_c1, enc_zero_c2, pubkey, 0,
                                  deterministic_scalar);

  OPENSSL_cleanse(deterministic_scalar, kMPT_SCALAR_SIZE);
  return ret;
}

/* --- Direct Verification (Convert) --- */

int secp256k1_elgamal_verify_encryption(const secp256k1_context *ctx,
                                        const secp256k1_pubkey *c1,
                                        const secp256k1_pubkey *c2,
                                        const secp256k1_pubkey *pubkey_Q,
                                        uint64_t amount,
                                        const unsigned char *blinding_factor)
{
  MPT_ARG_CHECK(ctx != NULL);
  MPT_ARG_CHECK(c1 != NULL);
  MPT_ARG_CHECK(c2 != NULL);
  MPT_ARG_CHECK(pubkey_Q != NULL);
  MPT_ARG_CHECK(blinding_factor != NULL);

  secp256k1_pubkey expected_c1, expected_c2, mG, S;
  const secp256k1_pubkey *pts[2];

  /* 1. Verify C1 == r * G */
  if (!secp256k1_ec_pubkey_create(ctx, &expected_c1, blinding_factor))
    return 0;
  if (!pubkey_equal(ctx, c1, &expected_c1))
    return 0;

  /* 2. Verify C2 == r*Q + m*G */

  // S = r * Q
  S = *pubkey_Q;
  if (!secp256k1_ec_pubkey_tweak_mul(ctx, &S, blinding_factor))
    return 0;

  if (amount == 0)
  {
    expected_c2 = S;
  }
  else
  {
    if (!compute_amount_point(ctx, &mG, amount))
      return 0;
    pts[0] = &mG;
    pts[1] = &S;
    if (!secp256k1_ec_pubkey_combine(ctx, &expected_c2, pts, 2))
      return 0;
  }

  if (!pubkey_equal(ctx, c2, &expected_c2))
    return 0;

  return 1;
}
