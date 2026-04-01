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
#include "secp256k1_mpt.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>

/* --- Internal Helpers --- */

static int pubkey_equal(const secp256k1_context *ctx,
                        const secp256k1_pubkey *pk1,
                        const secp256k1_pubkey *pk2)
{
  return secp256k1_ec_pubkey_cmp(ctx, pk1, pk2) == 0;
}

static int compute_amount_point(const secp256k1_context *ctx,
                                secp256k1_pubkey *mG, uint64_t amount)
{
  unsigned char amount_scalar[32] = {0};
  int ret;
  for (int i = 0; i < 8; ++i)
  {
    amount_scalar[31 - i] = (amount >> (i * 8)) & 0xFF;
  }
  ret = secp256k1_ec_pubkey_create(ctx, mG, amount_scalar);
  OPENSSL_cleanse(amount_scalar, 32); // Wipe scalar after use
  return ret;
}

/* --- Key Generation --- */

int secp256k1_elgamal_generate_keypair(const secp256k1_context *ctx,
                                       unsigned char *privkey,
                                       secp256k1_pubkey *pubkey)
{
  do
  {
    if (RAND_bytes(privkey, 32) != 1)
      return 0;
  } while (!secp256k1_ec_seckey_verify(ctx, privkey));

  if (!secp256k1_ec_pubkey_create(ctx, pubkey, privkey))
  {
    OPENSSL_cleanse(privkey, 32); // Cleanup on failure
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
  secp256k1_pubkey S, mG;
  const secp256k1_pubkey *pts[2];

  /* 1. C1 = r * G */
  if (!secp256k1_ec_pubkey_create(ctx, c1, blinding_factor))
    return 0;

  /* 2. S = r * Q (Shared Secret) */
  S = *pubkey_Q;
  if (!secp256k1_ec_pubkey_tweak_mul(ctx, &S, blinding_factor))
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
static int secp256k1_solve_dlp_small_range_fixed(
    const secp256k1_context *ctx, uint64_t *out_amount, uint64_t *out_is_found,
    const unsigned char *target_ser, uint64_t max_range)
{
  if (max_range == 0)
  {
    *out_amount = 0;
    *out_is_found = 0;
    return 1;
  }

  secp256k1_pubkey current_M, G_point, next_M;
  const secp256k1_pubkey *pts[2];
  unsigned char one[32] = {0};
  one[31] = 1;
  unsigned char current_M_ser[33];
  size_t ser_len;

  uint64_t found_amount = 0;
  uint64_t is_found = 0;

  if (!secp256k1_ec_pubkey_create(ctx, &G_point, one))
  {
    OPENSSL_cleanse(one, 32);
    return 0;
  }
  current_M = G_point;

  unsigned char global_ser_error = 0;
  for (uint64_t i = 1; i <= max_range; ++i)
  {
    ser_len = 33;
    unsigned char temp_ser[33] = {0};
    int ser_ok = secp256k1_ec_pubkey_serialize(
        ctx, temp_ser, &ser_len, &current_M, SECP256K1_EC_COMPRESSED);

    /* 1. Branchless Serialization Fallback
     * If ser_ok == 1, ser_mask is 0xFF. If ser_ok == 0, ser_mask is 0x00.
     */
    unsigned char ser_mask = (unsigned char)(0 - ser_ok);
    for (int j = 0; j < 33; j++)
    {
      current_M_ser[j] = temp_ser[j] & ser_mask;
    }

    /* Track any global serialization failures across the 1M iterations */
    global_ser_error |= (unsigned char)(ser_ok ^ 1);
    global_ser_error |= (unsigned char)(ser_len ^ 33);

    /* Accumulate differences using an explicit 8-bit accumulator */
    unsigned char match_diff = 0;
    for (int j = 0; j < 33; j++)
    {
      match_diff |= current_M_ser[j] ^ target_ser[j];
    }

    /* Mix serialization success into the match diff to prevent false positives
     */
    match_diff |= (unsigned char)(ser_ok ^ 1);
    match_diff |= (unsigned char)(ser_len ^ 33);

    /* Expand to 64-bit before the idiom to make width explicit.
     * Nonzero detection: if diff64 != 0, saturate bit 63. */
    uint64_t diff64 = (uint64_t)match_diff;
    uint64_t match = 1 ^ (((diff64 | (~diff64 + 1)) >> 63) & 1);

    /* Constant-time assignment mask */
    uint64_t mask = ~(match - 1);
    found_amount ^= (found_amount ^ i) & mask;
    is_found |= match;

    /* Increment for next loop */
    pts[0] = &current_M;
    pts[1] = &G_point;
    int combine_ok = secp256k1_ec_pubkey_combine(ctx, &next_M, pts, 2);

    /* 2. Branchless Conditional Move for Point Addition
     * If combine_ok == 1, combine_mask is 0xFF. If combine_ok == 0, it is 0x00.
     */
    unsigned char combine_mask = (unsigned char)(0 - combine_ok);
    unsigned char *curr_ptr = (unsigned char *)&current_M;
    unsigned char *next_ptr = (unsigned char *)&next_M;

    for (size_t b = 0; b < sizeof(secp256k1_pubkey); b++)
    {
      curr_ptr[b] =
          (curr_ptr[b] & ~combine_mask) | (next_ptr[b] & combine_mask);
    }
  }

  /* If any serialization failed during the loop, invalidate the result */
  if (global_ser_error != 0)
  {
    *out_is_found = 0;
    return 0;
  }

  *out_amount = found_amount;
  *out_is_found = is_found;

  /* Scrub sensitive local intermediate data */
  OPENSSL_cleanse(current_M_ser, 33);
  OPENSSL_cleanse(one, 32);

  return 1;
}

int secp256k1_elgamal_decrypt(const secp256k1_context *ctx, uint64_t *amount,
                              const secp256k1_pubkey *c1,
                              const secp256k1_pubkey *c2,
                              const unsigned char *privkey)
{
  if (!ctx || !amount || !c1 || !c2 || !privkey)
    return 0;

  secp256k1_pubkey S, M_target_sum, neg_S;
  const secp256k1_pubkey *pts[2];
  unsigned char c2_ser[33], S_ser[33], M_target_ser[33];
  size_t ser_len;

  /* 1. Recover Shared Secret: S = privkey * c1 */
  S = *c1;
  if (!secp256k1_ec_pubkey_tweak_mul(ctx, &S, privkey))
    return 0;

  ser_len = 33;
  if (!secp256k1_ec_pubkey_serialize(ctx, c2_ser, &ser_len, c2,
                                     SECP256K1_EC_COMPRESSED) ||
      ser_len != 33)
    return 0;
  ser_len = 33;
  if (!secp256k1_ec_pubkey_serialize(ctx, S_ser, &ser_len, &S,
                                     SECP256K1_EC_COMPRESSED) ||
      ser_len != 33)
    return 0;

  /* 2. Inline Constant-Time Check for Amount = 0 (c2 == S) */
  unsigned char zero_diff_u8 = 0;
  for (int j = 0; j < 33; j++)
  {
    zero_diff_u8 |= c2_ser[j] ^ S_ser[j];
  }
  uint64_t zero_diff64 = (uint64_t)zero_diff_u8;
  uint64_t match_zero = 1 ^ (((zero_diff64 | (~zero_diff64 + 1)) >> 63) & 1);

  /* 3. Point Subtraction: M_target_sum = c2 - S */
  neg_S = S;
  if (!secp256k1_ec_pubkey_negate(ctx, &neg_S))
  {
    OPENSSL_cleanse(S_ser, 33);
    OPENSSL_cleanse(c2_ser, 33);
    return 0;
  }

  pts[0] = c2;
  pts[1] = &neg_S;

  if (secp256k1_ec_pubkey_combine(ctx, &M_target_sum, pts, 2))
  {
    ser_len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, M_target_ser, &ser_len,
                                       &M_target_sum,
                                       SECP256K1_EC_COMPRESSED) ||
        ser_len != 33)
    {
      memset(M_target_ser, 0, 33);
    }
  }
  else
  {
    memset(M_target_ser, 0, 33); /* Fails safely if point at infinity */
  }

  /* 4. Call the Modular DLP Solver */
  uint64_t loop_amount = 0;
  uint64_t match_loop = 0;

  if (!secp256k1_solve_dlp_small_range_fixed(ctx, &loop_amount, &match_loop,
                                             M_target_ser, 1000000))
  {
    OPENSSL_cleanse(S_ser, 33);
    OPENSSL_cleanse(c2_ser, 33);
    OPENSSL_cleanse(M_target_ser, 33);
    return 0;
  }

  /* 5. Constant-Time Resolution */
  uint64_t is_found = match_zero | match_loop;
  uint64_t zero_mask = ~(match_zero - 1);
  *amount = (0 & zero_mask) | (loop_amount & ~zero_mask);

  /* 6. Scrub sensitive intermediate data */
  OPENSSL_cleanse(S_ser, 33);
  OPENSSL_cleanse(c2_ser, 33);
  OPENSSL_cleanse(M_target_ser, 33);

  /* Note: return value distinguishes success/failure but not the amount itself.
   */
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
  unsigned char deterministic_scalar[32];
  unsigned char hash_input[51]; // 7 ("EncZero") + 20 + 24
  const char *domain = "EncZero";
  int ret;
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

  if (!mdctx)
    return 0;

  memcpy(hash_input, domain, 7);
  memcpy(hash_input + 7, account_id, 20);
  memcpy(hash_input + 27, mpt_issuance_id, 24);

  do
  {
    EVP_MD_CTX_reset(mdctx);
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1)
    {
      EVP_MD_CTX_free(mdctx);
      return 0;
    }
    if (EVP_DigestUpdate(mdctx, hash_input, 51) != 1)
    {
      EVP_MD_CTX_free(mdctx);
      return 0;
    }
    if (EVP_DigestFinal_ex(mdctx, deterministic_scalar, NULL) != 1)
    {
      EVP_MD_CTX_free(mdctx);
      return 0;
    }

    if (secp256k1_ec_seckey_verify(ctx, deterministic_scalar))
      break;

    memcpy(hash_input, deterministic_scalar, 32);

  } while (1);

  EVP_MD_CTX_free(mdctx);

  ret = secp256k1_elgamal_encrypt(ctx, enc_zero_c1, enc_zero_c2, pubkey, 0,
                                  deterministic_scalar);

  OPENSSL_cleanse(deterministic_scalar, 32);
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
