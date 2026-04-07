/**
 * @file proof_compact_clawback.c
 * @brief Compact-form sigma protocol for Clawback transactions.
 *
 * The issuer decrypts its mirror ciphertext (C1, C2) to learn the
 * holder's balance m, then proves consistency with the on-ledger
 * ciphertext using knowledge of sk_iss.
 *
 * Language L_clawback (spec Section 4.4, Eq. 68):
 *   exists sk_iss in Z_q such that:
 *     P_iss         = sk_iss * G
 *     C2 - m*G      = sk_iss * C1
 *
 * Compact proof: (e, z_sk) in Z_q^2 = 64 bytes.
 *
 * Fiat-Shamir hash (spec Eq. 71):
 *   e = H("CMPT_CLAWBACK_SIGMA" || P_iss || C1 || C2 || m*G ||
 *         T1 || T2 || TransactionContextID)
 *
 * Note: m*G is hashed as a 33-byte compressed point, not as a scalar.
 *
 * Verification reconstructs commitments (spec Eqs. 74-75):
 *   T1 = z_sk*G    - e*P_iss
 *   T2 = z_sk*C1   - e*(C2 - m*G)
 * then recomputes the hash and checks e' == e.
 */
#include "mpt_internal.h"
#include "secp256k1_mpt.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>

static const char DOMAIN_COMPACT_CLAWBACK[] = "CMPT_CLAWBACK_SIGMA";

static int compute_compact_clawback_challenge(
    const secp256k1_context *ctx, unsigned char *e_out,
    const secp256k1_pubkey *P_iss, const secp256k1_pubkey *C1,
    const secp256k1_pubkey *C2, const secp256k1_pubkey *mG,
    const secp256k1_pubkey *T1, const secp256k1_pubkey *T2,
    const unsigned char *context_id)
{
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  unsigned char buf[33];
  unsigned char h[32];
  size_t len;
  int ok = 0;

  if (!mdctx)
    return 0;

  if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1)
    goto cleanup;
  if (EVP_DigestUpdate(mdctx, DOMAIN_COMPACT_CLAWBACK,
                       strlen(DOMAIN_COMPACT_CLAWBACK)) != 1)
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

  /* Statement: P_iss || C1 || C2 || m*G */
  SER(P_iss);
  SER(C1);
  SER(C2);
  SER(mG);

  /* Commitments: T1 || T2 */
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
  ok = 1;

cleanup:
  EVP_MD_CTX_free(mdctx);
  return ok;
}

/* --- Prover --- */

int secp256k1_compact_clawback_prove(const secp256k1_context *ctx,
                                     unsigned char *proof_out, uint64_t amount,
                                     const unsigned char *sk_iss,
                                     const secp256k1_pubkey *P_iss,
                                     const secp256k1_pubkey *C1,
                                     const secp256k1_pubkey *C2,
                                     const unsigned char *context_id)
{
  MPT_ARG_CHECK(ctx != NULL);
  MPT_ARG_CHECK(proof_out != NULL);
  MPT_ARG_CHECK(sk_iss != NULL);
  MPT_ARG_CHECK(P_iss != NULL);
  MPT_ARG_CHECK(C1 != NULL);
  MPT_ARG_CHECK(C2 != NULL);

  unsigned char t_sk[32], m_scalar[32];
  unsigned char e[32], z_sk[32];
  secp256k1_pubkey mG, T1, T2;
  int ok = 0;

  if (!secp256k1_ec_seckey_verify(ctx, sk_iss))
    return 0;

  /* Compute m*G as a group element */
  mpt_uint64_to_scalar(m_scalar, amount);
  if (!secp256k1_ec_pubkey_create(ctx, &mG, m_scalar))
    goto cleanup;

  /* 1. Deterministic nonce */
  {
    unsigned char witness_buf[32];
    memcpy(witness_buf, sk_iss, 32);

    unsigned char stmt_hash[32];
    {
      EVP_MD_CTX *sh = EVP_MD_CTX_new();
      unsigned char sbuf[33];
      size_t slen;
      if (!sh)
      {
        OPENSSL_cleanse(witness_buf, sizeof(witness_buf));
        goto cleanup;
      }
      if (EVP_DigestInit_ex(sh, EVP_sha256(), NULL) != 1)
      {
        EVP_MD_CTX_free(sh);
        OPENSSL_cleanse(witness_buf, sizeof(witness_buf));
        goto cleanup;
      }
#define SHASH(pk_ptr)                                                          \
  do                                                                           \
  {                                                                            \
    slen = 33;                                                                 \
    if (!secp256k1_ec_pubkey_serialize(ctx, sbuf, &slen, pk_ptr,               \
                                       SECP256K1_EC_COMPRESSED) ||             \
        slen != 33)                                                            \
    {                                                                          \
      EVP_MD_CTX_free(sh);                                                     \
      OPENSSL_cleanse(witness_buf, sizeof(witness_buf));                       \
      goto cleanup;                                                            \
    }                                                                          \
    if (EVP_DigestUpdate(sh, sbuf, 33) != 1)                                   \
    {                                                                          \
      EVP_MD_CTX_free(sh);                                                     \
      OPENSSL_cleanse(witness_buf, sizeof(witness_buf));                       \
      goto cleanup;                                                            \
    }                                                                          \
  } while (0)
      SHASH(P_iss);
      SHASH(C1);
      SHASH(C2);
      SHASH(&mG);
      if (context_id)
      {
        if (EVP_DigestUpdate(sh, context_id, 32) != 1)
        {
          EVP_MD_CTX_free(sh);
          OPENSSL_cleanse(witness_buf, sizeof(witness_buf));
          goto cleanup;
        }
      }
      EVP_DigestFinal_ex(sh, stmt_hash, NULL);
      EVP_MD_CTX_free(sh);
#undef SHASH
    }

    unsigned char nonces[32];
    if (!generate_deterministic_nonces(
            ctx, nonces, 1, witness_buf, sizeof(witness_buf), stmt_hash,
            DOMAIN_COMPACT_CLAWBACK, strlen(DOMAIN_COMPACT_CLAWBACK)))
    {
      OPENSSL_cleanse(witness_buf, sizeof(witness_buf));
      goto cleanup;
    }
    memcpy(t_sk, nonces, 32);
    OPENSSL_cleanse(witness_buf, sizeof(witness_buf));
    OPENSSL_cleanse(nonces, sizeof(nonces));
  }

  /* 2. Commitments: T1 = t_sk*G, T2 = t_sk*C1 */
  if (!secp256k1_ec_pubkey_create(ctx, &T1, t_sk))
    goto cleanup;

  T2 = *C1;
  if (!secp256k1_ec_pubkey_tweak_mul(ctx, &T2, t_sk))
    goto cleanup;

  /* 3. Challenge */
  if (!compute_compact_clawback_challenge(ctx, e, P_iss, C1, C2, &mG, &T1, &T2,
                                          context_id))
    goto cleanup;

  /* 4. Response: z_sk = t_sk + e*sk_iss */
  if (!compute_sigma_response(ctx, z_sk, t_sk, e, sk_iss))
    goto cleanup;

  /* 5. Serialize: e || z_sk */
  memcpy(proof_out, e, 32);
  memcpy(proof_out + 32, z_sk, 32);

  ok = 1;

cleanup:
  OPENSSL_cleanse(t_sk, 32);
  OPENSSL_cleanse(m_scalar, 32);
  OPENSSL_cleanse(e, 32);
  OPENSSL_cleanse(z_sk, 32);
  return ok;
}

/* --- Verifier --- */

int secp256k1_compact_clawback_verify(
    const secp256k1_context *ctx, const unsigned char *proof, uint64_t amount,
    const secp256k1_pubkey *P_iss, const secp256k1_pubkey *C1,
    const secp256k1_pubkey *C2, const unsigned char *context_id)
{
  MPT_ARG_CHECK(ctx != NULL);
  MPT_ARG_CHECK(proof != NULL);
  MPT_ARG_CHECK(P_iss != NULL);
  MPT_ARG_CHECK(C1 != NULL);
  MPT_ARG_CHECK(C2 != NULL);

  unsigned char e[32], z_sk[32], e_prime[32], neg_e[32], m_scalar[32];
  secp256k1_pubkey mG, T1, T2;

  /* 1. Deserialize: e || z_sk */
  memcpy(e, proof, 32);
  memcpy(z_sk, proof + 32, 32);

  if (!secp256k1_ec_seckey_verify(ctx, e))
    return 0;
  if (!secp256k1_ec_seckey_verify(ctx, z_sk))
    return 0;

  /* Compute m*G as a group element */
  mpt_uint64_to_scalar(m_scalar, amount);
  if (!secp256k1_ec_pubkey_create(ctx, &mG, m_scalar))
    return 0;

  secp256k1_mpt_scalar_negate(neg_e, e);

  /* 2. Reconstruct commitments */

  /* T1 = z_sk*G - e*P_iss */
  {
    secp256k1_pubkey zskG, ePiss;
    if (!secp256k1_ec_pubkey_create(ctx, &zskG, z_sk))
      return 0;
    ePiss = *P_iss;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &ePiss, neg_e))
      return 0;
    const secp256k1_pubkey *pts[2] = {&zskG, &ePiss};
    if (!secp256k1_ec_pubkey_combine(ctx, &T1, pts, 2))
      return 0;
  }

  /* T2 = z_sk*C1 - e*(C2 - m*G) */
  {
    secp256k1_pubkey zskC1, eTarget;
    /* Compute C2 - m*G */
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

    zskC1 = *C1;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &zskC1, z_sk))
      return 0;
    eTarget = C2_minus_mG;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &eTarget, neg_e))
      return 0;
    const secp256k1_pubkey *pts[2] = {&zskC1, &eTarget};
    if (!secp256k1_ec_pubkey_combine(ctx, &T2, pts, 2))
      return 0;
  }

  /* 3. Recompute challenge */
  if (!compute_compact_clawback_challenge(ctx, e_prime, P_iss, C1, C2, &mG, &T1,
                                          &T2, context_id))
    return 0;

  /* 4. Accept iff e' == e */
  return CRYPTO_memcmp(e, e_prime, 32) == 0;
}
