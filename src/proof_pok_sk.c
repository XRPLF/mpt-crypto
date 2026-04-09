/**
 * @file proof_pok_sk.c
 * @brief Compact Schnorr Proof of Knowledge for secret key registration.
 *
 * Proves knowledge of sk such that pk = sk*G (Schnorr identification,
 * Fiat-Shamir transformed).
 *
 * Compact proof: (e, s) in Z_q^2 = 64 bytes.
 * Fiat-Shamir domain: "CMPT_POK_SK_REGISTER"
 *
 * Verification reconstructs T = s*G - e*pk, recomputes challenge, checks
 * e' == e.
 *
 * Used during ConfidentialMPTConvert key registration (spec Section 1.4).
 */
#include "mpt_internal.h"
#include "secp256k1_mpt.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>

static const char DOMAIN_POK_SK[] = "CMPT_POK_SK_REGISTER";

static int build_pok_challenge(const secp256k1_context *ctx,
                               unsigned char *e_out, const secp256k1_pubkey *pk,
                               const secp256k1_pubkey *T,
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
  if (EVP_DigestUpdate(mdctx, DOMAIN_POK_SK, strlen(DOMAIN_POK_SK)) != 1)
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

  SER(pk);
  SER(T);

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

int secp256k1_mpt_pok_sk_prove(const secp256k1_context *ctx,
                               unsigned char *proof_out,
                               const secp256k1_pubkey *pk,
                               const unsigned char *sk,
                               const unsigned char *context_id)
{
  MPT_ARG_CHECK(ctx != NULL);
  MPT_ARG_CHECK(proof_out != NULL);
  MPT_ARG_CHECK(pk != NULL);
  MPT_ARG_CHECK(sk != NULL);
  /* context_id is optional */

  unsigned char k[32];
  unsigned char e[32], s[32];
  secp256k1_pubkey T;
  int ok = 0;

  if (!secp256k1_ec_seckey_verify(ctx, sk))
    return 0;

  /* 1. Deterministic nonce */
  {
    unsigned char stmt_hash[32];
    {
      EVP_MD_CTX *sh = EVP_MD_CTX_new();
      unsigned char sbuf[33];
      size_t slen;
      if (!sh)
        goto cleanup;
      if (EVP_DigestInit_ex(sh, EVP_sha256(), NULL) != 1)
      {
        EVP_MD_CTX_free(sh);
        goto cleanup;
      }
      slen = 33;
      if (!secp256k1_ec_pubkey_serialize(ctx, sbuf, &slen, pk,
                                         SECP256K1_EC_COMPRESSED) ||
          slen != 33)
      {
        EVP_MD_CTX_free(sh);
        goto cleanup;
      }
      if (EVP_DigestUpdate(sh, sbuf, 33) != 1)
      {
        EVP_MD_CTX_free(sh);
        goto cleanup;
      }
      if (context_id)
      {
        if (EVP_DigestUpdate(sh, context_id, 32) != 1)
        {
          EVP_MD_CTX_free(sh);
          goto cleanup;
        }
      }
      EVP_DigestFinal_ex(sh, stmt_hash, NULL);
      EVP_MD_CTX_free(sh);
    }

    unsigned char nonces[32];
    if (!generate_deterministic_nonces(ctx, nonces, 1, sk, 32, stmt_hash,
                                       DOMAIN_POK_SK, strlen(DOMAIN_POK_SK)))
      goto cleanup;
    memcpy(k, nonces, 32);
    OPENSSL_cleanse(nonces, sizeof(nonces));
  }

  /* 2. Commitment: T = k*G */
  if (!secp256k1_ec_pubkey_create(ctx, &T, k))
    goto cleanup;

  /* 3. Challenge */
  if (!build_pok_challenge(ctx, e, pk, &T, context_id))
    goto cleanup;

  /* 4. Response: s = k + e*sk */
  if (!compute_sigma_response(ctx, s, k, e, sk))
    goto cleanup;

  /* 5. Serialize: e || s */
  memcpy(proof_out, e, 32);
  memcpy(proof_out + 32, s, 32);

  ok = 1;

cleanup:
  OPENSSL_cleanse(k, 32);
  OPENSSL_cleanse(e, 32);
  OPENSSL_cleanse(s, 32);
  return ok;
}

/* --- Verifier --- */

int secp256k1_mpt_pok_sk_verify(const secp256k1_context *ctx,
                                const unsigned char *proof,
                                const secp256k1_pubkey *pk,
                                const unsigned char *context_id)
{
  MPT_ARG_CHECK(ctx != NULL);
  MPT_ARG_CHECK(proof != NULL);
  MPT_ARG_CHECK(pk != NULL);
  /* context_id is optional */

  unsigned char e[32], s[32], e_prime[32], neg_e[32];
  secp256k1_pubkey T;

  /* 1. Deserialize: e || s */
  memcpy(e, proof, 32);
  memcpy(s, proof + 32, 32);

  if (!secp256k1_ec_seckey_verify(ctx, e))
    return 0;
  if (!secp256k1_ec_seckey_verify(ctx, s))
    return 0;

  secp256k1_mpt_scalar_negate(neg_e, e);

  /* 2. Reconstruct T = s*G - e*pk */
  {
    secp256k1_pubkey sG, ePk;
    if (!secp256k1_ec_pubkey_create(ctx, &sG, s))
      return 0;
    ePk = *pk;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &ePk, neg_e))
      return 0;
    const secp256k1_pubkey *pts[2] = {&sG, &ePk};
    if (!secp256k1_ec_pubkey_combine(ctx, &T, pts, 2))
      return 0;
  }

  /* 3. Recompute challenge */
  if (!build_pok_challenge(ctx, e_prime, pk, &T, context_id))
    return 0;

  /* 4. Accept iff e' == e */
  return CRYPTO_memcmp(e, e_prime, 32) == 0;
}
