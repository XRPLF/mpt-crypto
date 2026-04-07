/**
 * @file proof_compact_convert.c
 * @brief Compact-form sigma protocol for Convert / Clawback transactions.
 *
 * @note OPTIONAL MODULE — In production, Convert and Clawback transactions
 * disclose the encryption randomness r on-chain as the BlindingFactor
 * field.  The verifier checks C1 == r*G and C2 == m*G + r*P_A
 * deterministically, with no ZKP required.  This module provides a
 * sigma proof for contexts preferring cryptographic binding over
 * deterministic verification (auditing, testing, etc.).
 *
 * Language L_convert:
 *   exists r in Z_q such that:
 *     C1 = r*G
 *     C2 = m*G + r*P_A
 *
 * Compact proof: (e, z_r) in Z_q^2 = 64 bytes.
 *
 * Verification reconstructs commitments:
 *   T1 = z_r*G - e*C1
 *   T2 = z_r*P_A - e*(C2 - m*G)
 * then recomputes the hash and checks e' == e.
 */
#include "mpt_internal.h"
#include "secp256k1_mpt.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>

static const char DOMAIN_COMPACT_CONVERT[] = "CMPT_CONVERT_COMPACT";

static void compute_compact_convert_challenge(
    const secp256k1_context *ctx, unsigned char *e_out,
    const secp256k1_pubkey *pk_A, const secp256k1_pubkey *C1,
    const secp256k1_pubkey *C2, const unsigned char *m_scalar,
    const secp256k1_pubkey *T1, const secp256k1_pubkey *T2,
    const unsigned char *context_id)
{
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  unsigned char buf[33];
  unsigned char h[32];
  size_t len;

  if (!mdctx)
    return;

  if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1)
    goto cleanup;
  if (EVP_DigestUpdate(mdctx, DOMAIN_COMPACT_CONVERT,
                       strlen(DOMAIN_COMPACT_CONVERT)) != 1)
    goto cleanup;

#define SER(pk_ptr)                                                            \
  do                                                                           \
  {                                                                            \
    len = 33;                                                                  \
    if (!secp256k1_ec_pubkey_serialize(ctx, buf, &len, pk_ptr,                 \
                                       SECP256K1_EC_COMPRESSED) ||             \
        len != 33)                                                             \
      goto cleanup;                                                            \
    if (EVP_DigestUpdate(mdctx, buf, 33) != 1)                                 \
      goto cleanup;                                                            \
  } while (0)

  /* Statement */
  SER(pk_A);
  SER(C1);
  SER(C2);
  if (EVP_DigestUpdate(mdctx, m_scalar, 32) != 1)
    goto cleanup;

  /* Commitments */
  SER(T1);
  SER(T2);

#undef SER

  if (context_id)
  {
    if (EVP_DigestUpdate(mdctx, context_id, 32) != 1)
      goto cleanup;
  }

  if (EVP_DigestFinal_ex(mdctx, h, NULL) != 1)
    goto cleanup;
  secp256k1_mpt_scalar_reduce32(e_out, h);

cleanup:
  EVP_MD_CTX_free(mdctx);
}

/* --- Prover --- */

int secp256k1_compact_convert_prove(const secp256k1_context *ctx,
                                    unsigned char *proof_out, uint64_t amount,
                                    const unsigned char *r,
                                    const secp256k1_pubkey *C1,
                                    const secp256k1_pubkey *C2,
                                    const secp256k1_pubkey *pk_A,
                                    const unsigned char *context_id)
{
  MPT_ARG_CHECK(ctx != NULL);
  MPT_ARG_CHECK(proof_out != NULL);
  MPT_ARG_CHECK(r != NULL);
  MPT_ARG_CHECK(C1 != NULL);
  MPT_ARG_CHECK(C2 != NULL);
  MPT_ARG_CHECK(pk_A != NULL);

  unsigned char t_r[32], m_scalar[32];
  unsigned char e[32], z_r[32];
  secp256k1_pubkey T1, T2;
  int ok = 0;

  if (!secp256k1_ec_seckey_verify(ctx, r))
    return 0;

  mpt_uint64_to_scalar(m_scalar, amount);

  /* 1. Sample nonce */
  if (!generate_random_scalar(ctx, t_r))
    goto cleanup;

  /* 2. Compute commitments */

  /* T1 = t_r*G */
  if (!secp256k1_ec_pubkey_create(ctx, &T1, t_r))
    goto cleanup;

  /* T2 = t_r*P_A */
  T2 = *pk_A;
  if (!secp256k1_ec_pubkey_tweak_mul(ctx, &T2, t_r))
    goto cleanup;

  /* 3. Challenge */
  compute_compact_convert_challenge(ctx, e, pk_A, C1, C2, m_scalar, &T1, &T2,
                                    context_id);

  /* 4. Response: z_r = t_r + e*r */
  if (!compute_sigma_response(ctx, z_r, t_r, e, r))
    goto cleanup;

  /* 5. Serialize: e || z_r */
  memcpy(proof_out, e, 32);
  memcpy(proof_out + 32, z_r, 32);

  ok = 1;

cleanup:
  OPENSSL_cleanse(t_r, 32);
  OPENSSL_cleanse(m_scalar, 32);
  OPENSSL_cleanse(e, 32);
  OPENSSL_cleanse(z_r, 32);
  return ok;
}

/* --- Verifier --- */

int secp256k1_compact_convert_verify(
    const secp256k1_context *ctx, const unsigned char *proof, uint64_t amount,
    const secp256k1_pubkey *C1, const secp256k1_pubkey *C2,
    const secp256k1_pubkey *pk_A, const unsigned char *context_id)
{
  MPT_ARG_CHECK(ctx != NULL);
  MPT_ARG_CHECK(proof != NULL);
  MPT_ARG_CHECK(C1 != NULL);
  MPT_ARG_CHECK(C2 != NULL);
  MPT_ARG_CHECK(pk_A != NULL);

  unsigned char e[32], z_r[32], e_prime[32], neg_e[32], m_scalar[32];
  secp256k1_pubkey T1, T2;

  /* 1. Deserialize */
  memcpy(e, proof, 32);
  memcpy(z_r, proof + 32, 32);

  if (!secp256k1_ec_seckey_verify(ctx, e))
    return 0;
  if (!secp256k1_ec_seckey_verify(ctx, z_r))
    return 0;

  mpt_uint64_to_scalar(m_scalar, amount);
  secp256k1_mpt_scalar_negate(neg_e, e);

  /* 2. Reconstruct commitments */

  /* T1 = z_r*G - e*C1 */
  {
    secp256k1_pubkey zrG, eC1;
    if (!secp256k1_ec_pubkey_create(ctx, &zrG, z_r))
      return 0;
    eC1 = *C1;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &eC1, neg_e))
      return 0;
    const secp256k1_pubkey *pts[2] = {&zrG, &eC1};
    if (!secp256k1_ec_pubkey_combine(ctx, &T1, pts, 2))
      return 0;
  }

  /* T2 = z_r*P_A - e*(C2 - m*G) */
  {
    secp256k1_pubkey zrPA, eTarget, mG;
    /* Compute C2 - m*G */
    if (!secp256k1_ec_pubkey_create(ctx, &mG, m_scalar))
      return 0;
    unsigned char neg_one[32];
    unsigned char one[32] = {0};
    one[31] = 1;
    secp256k1_mpt_scalar_negate(neg_one, one);
    secp256k1_pubkey neg_mG = mG;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &neg_mG, neg_one))
      return 0;
    secp256k1_pubkey C2_minus_mG;
    const secp256k1_pubkey *sub_pts[2] = {C2, &neg_mG};
    if (!secp256k1_ec_pubkey_combine(ctx, &C2_minus_mG, sub_pts, 2))
      return 0;

    zrPA = *pk_A;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &zrPA, z_r))
      return 0;
    eTarget = C2_minus_mG;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &eTarget, neg_e))
      return 0;
    const secp256k1_pubkey *pts[2] = {&zrPA, &eTarget};
    if (!secp256k1_ec_pubkey_combine(ctx, &T2, pts, 2))
      return 0;
  }

  /* 3. Recompute challenge */
  compute_compact_convert_challenge(ctx, e_prime, pk_A, C1, C2, m_scalar, &T1,
                                    &T2, context_id);

  /* 4. Accept iff e' == e */
  return CRYPTO_memcmp(e, e_prime, 32) == 0;
}
