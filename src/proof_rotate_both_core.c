/**
 * @file proof_rotate_both_core.c
 * @brief AND-composed re-encryption sigma core for the two "both mirrors"
 * key-rotation flows. See proof_rotate_both_core.h for the language, the
 * instantiations, and the reconstruction equations.
 */
#include "proof_rotate_both_core.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>

/* Wire order follows the tuple as written in the specification:
 *   (e, z_b, z_sk, z_r) */
#define OFF_E 0
#define OFF_ZB (1 * kMPT_SCALAR_SIZE)
#define OFF_ZSK (2 * kMPT_SCALAR_SIZE)
#define OFF_ZR (3 * kMPT_SCALAR_SIZE)

static int compute_both_core_challenge(
    secp256k1_context const *ctx, unsigned char *e_out,
    secp256k1_pubkey const *pk_anchor, secp256k1_pubkey const *C1,
    secp256k1_pubkey const *C2, secp256k1_pubkey const *pk_target1,
    secp256k1_pubkey const *pk_target2, secp256k1_pubkey const *D1_1,
    secp256k1_pubkey const *D2_1, secp256k1_pubkey const *D1_2,
    secp256k1_pubkey const *D2_2, secp256k1_pubkey const *T1,
    secp256k1_pubkey const *T2, secp256k1_pubkey const *T3,
    secp256k1_pubkey const *T4, secp256k1_pubkey const *T6, char const *domain,
    size_t domain_len, unsigned char const *context_id)
{
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  unsigned char buf[kMPT_PUBKEY_SIZE];
  unsigned char h[kMPT_HALF_SHA_SIZE];
  size_t len;
  int ok = 0;

  if (!mdctx)
    return 0;

  if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1)
    goto cleanup;
  if (EVP_DigestUpdate(mdctx, domain, domain_len) != 1)
    goto cleanup;

#define SER(pk_ptr)                                                            \
  do                                                                           \
  {                                                                            \
    len = kMPT_PUBKEY_SIZE;                                                    \
    if (!secp256k1_ec_pubkey_serialize(ctx, buf, &len, pk_ptr,                 \
                                       SECP256K1_EC_COMPRESSED) ||             \
        len != kMPT_PUBKEY_SIZE)                                               \
      goto cleanup;                                                            \
    if (EVP_DigestUpdate(mdctx, buf, kMPT_PUBKEY_SIZE) != 1)                   \
      goto cleanup;                                                            \
  } while (0)

  /* Statement -- includes D1_2 even though no reconstruction equation names
   * it, per the fix for Finding f:mhaud. */
  SER(pk_anchor);
  SER(pk_target1);
  SER(pk_target2);
  SER(C1);
  SER(C2);
  SER(D1_1);
  SER(D2_1);
  SER(D1_2);
  SER(D2_2);

  /* Commitments */
  SER(T1);
  SER(T2);
  SER(T3);
  SER(T4);
  SER(T6);

#undef SER

  if (context_id)
  {
    if (EVP_DigestUpdate(mdctx, context_id, kMPT_HALF_SHA_SIZE) != 1)
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

/* Statement digest for nonce derivation. Distinct from the Fiat-Shamir
 * transcript above: the commitments do not exist yet at this point. */
static int compute_both_core_stmt_hash(
    secp256k1_context const *ctx, unsigned char *out,
    secp256k1_pubkey const *pk_anchor, secp256k1_pubkey const *C1,
    secp256k1_pubkey const *C2, secp256k1_pubkey const *pk_target1,
    secp256k1_pubkey const *pk_target2, secp256k1_pubkey const *D1_1,
    secp256k1_pubkey const *D2_1, secp256k1_pubkey const *D1_2,
    secp256k1_pubkey const *D2_2, unsigned char const *context_id)
{
  EVP_MD_CTX *sh = EVP_MD_CTX_new();
  unsigned char sbuf[kMPT_PUBKEY_SIZE];
  size_t slen;
  int ok = 0;

  if (!sh)
    return 0;
  if (EVP_DigestInit_ex(sh, EVP_sha256(), NULL) != 1)
    goto cleanup;

#define SHASH(pk_ptr)                                                          \
  do                                                                           \
  {                                                                            \
    slen = kMPT_PUBKEY_SIZE;                                                   \
    if (!secp256k1_ec_pubkey_serialize(ctx, sbuf, &slen, pk_ptr,               \
                                       SECP256K1_EC_COMPRESSED) ||             \
        slen != kMPT_PUBKEY_SIZE)                                              \
      goto cleanup;                                                            \
    if (EVP_DigestUpdate(sh, sbuf, kMPT_PUBKEY_SIZE) != 1)                     \
      goto cleanup;                                                            \
  } while (0)

  SHASH(pk_anchor);
  SHASH(pk_target1);
  SHASH(pk_target2);
  SHASH(C1);
  SHASH(C2);
  SHASH(D1_1);
  SHASH(D2_1);
  SHASH(D1_2);
  SHASH(D2_2);

#undef SHASH

  if (context_id)
  {
    if (EVP_DigestUpdate(sh, context_id, kMPT_HALF_SHA_SIZE) != 1)
      goto cleanup;
  }
  if (EVP_DigestFinal_ex(sh, out, NULL) != 1)
    goto cleanup;
  ok = 1;

cleanup:
  EVP_MD_CTX_free(sh);
  return ok;
}

/* --- Prover --- */

int mpt_rotate_both_core_prove(
    secp256k1_context const *ctx, unsigned char *proof_out, uint64_t balance,
    unsigned char const *sk_anchor, unsigned char const *r_new,
    secp256k1_pubkey const *pk_anchor, secp256k1_pubkey const *C1,
    secp256k1_pubkey const *C2, secp256k1_pubkey const *pk_target1,
    secp256k1_pubkey const *pk_target2, secp256k1_pubkey const *D1_1,
    secp256k1_pubkey const *D2_1, secp256k1_pubkey const *D1_2,
    secp256k1_pubkey const *D2_2, char const *domain, size_t domain_len,
    unsigned char const *context_id)
{
  MPT_ARG_CHECK(ctx != NULL);
  MPT_ARG_CHECK(proof_out != NULL);
  MPT_ARG_CHECK(sk_anchor != NULL);
  MPT_ARG_CHECK(r_new != NULL);
  MPT_ARG_CHECK(pk_anchor != NULL);
  MPT_ARG_CHECK(C1 != NULL);
  MPT_ARG_CHECK(C2 != NULL);
  MPT_ARG_CHECK(pk_target1 != NULL);
  MPT_ARG_CHECK(pk_target2 != NULL);
  MPT_ARG_CHECK(D1_1 != NULL);
  MPT_ARG_CHECK(D2_1 != NULL);
  MPT_ARG_CHECK(D1_2 != NULL);
  MPT_ARG_CHECK(D2_2 != NULL);
  MPT_ARG_CHECK(domain != NULL);
  MPT_ARG_CHECK(domain_len > 0);

  /* An honest prover only ever constructs D1_2 == D1_1 (same r_new for both
   * new ciphertexts); this is not itself part of the language the sigma
   * proof establishes; it is the caller's job to construct honest
   * ciphertexts, and the verifier's job (mandatory, see .h) to check it. */

  unsigned char t_b[kMPT_SCALAR_SIZE], t_sk[kMPT_SCALAR_SIZE];
  unsigned char t_r[kMPT_SCALAR_SIZE];
  unsigned char b_scalar[kMPT_SCALAR_SIZE];
  unsigned char e[kMPT_SCALAR_SIZE], z_b[kMPT_SCALAR_SIZE];
  unsigned char z_sk[kMPT_SCALAR_SIZE], z_r[kMPT_SCALAR_SIZE];
  secp256k1_pubkey T1, T2, T3, T4, T6;
  int ok = 0;

  if (!secp256k1_ec_seckey_verify(ctx, sk_anchor))
    return 0;
  if (!secp256k1_ec_seckey_verify(ctx, r_new))
    return 0;

  mpt_uint64_to_scalar(b_scalar, balance);

  /* 1. Deterministic nonces (witness || statement || fresh entropy) */
  {
    unsigned char witness_buf[3 * kMPT_SCALAR_SIZE];
    unsigned char stmt_hash[kMPT_HALF_SHA_SIZE];
    unsigned char nonces[3 * kMPT_SCALAR_SIZE];

    memcpy(witness_buf, b_scalar, kMPT_SCALAR_SIZE);
    memcpy(witness_buf + kMPT_SCALAR_SIZE, sk_anchor, kMPT_SCALAR_SIZE);
    memcpy(witness_buf + 2 * kMPT_SCALAR_SIZE, r_new, kMPT_SCALAR_SIZE);

    if (!compute_both_core_stmt_hash(ctx, stmt_hash, pk_anchor, C1, C2,
                                     pk_target1, pk_target2, D1_1, D2_1, D1_2,
                                     D2_2, context_id))
    {
      OPENSSL_cleanse(witness_buf, sizeof(witness_buf));
      goto cleanup;
    }

    if (!generate_deterministic_nonces(ctx, nonces, 3, witness_buf,
                                       sizeof(witness_buf), stmt_hash, domain,
                                       domain_len))
    {
      OPENSSL_cleanse(witness_buf, sizeof(witness_buf));
      goto cleanup;
    }

    memcpy(t_b, nonces, kMPT_SCALAR_SIZE);
    memcpy(t_sk, nonces + kMPT_SCALAR_SIZE, kMPT_SCALAR_SIZE);
    memcpy(t_r, nonces + 2 * kMPT_SCALAR_SIZE, kMPT_SCALAR_SIZE);
    OPENSSL_cleanse(witness_buf, sizeof(witness_buf));
    OPENSSL_cleanse(nonces, sizeof(nonces));
  }

  /* 2. Commitments */

  /* T1 = t_sk*G */
  if (!secp256k1_ec_pubkey_create(ctx, &T1, t_sk))
    goto cleanup;

  /* T2 = t_b*G + t_sk*C1 */
  {
    secp256k1_pubkey tbG, tskC1;
    if (!secp256k1_ec_pubkey_create(ctx, &tbG, t_b))
      goto cleanup;
    tskC1 = *C1;
    if (!mpt_ct_pubkey_tweak_mul(ctx, &tskC1, t_sk))
      goto cleanup;
    secp256k1_pubkey const *pts[2] = {&tbG, &tskC1};
    if (!secp256k1_ec_pubkey_combine(ctx, &T2, pts, 2))
      goto cleanup;
  }

  /* T3 = t_r*G */
  if (!secp256k1_ec_pubkey_create(ctx, &T3, t_r))
    goto cleanup;

  /* T4 = t_b*G + t_r*pk_target1 */
  {
    secp256k1_pubkey tbG, trPk;
    if (!secp256k1_ec_pubkey_create(ctx, &tbG, t_b))
      goto cleanup;
    trPk = *pk_target1;
    if (!mpt_ct_pubkey_tweak_mul(ctx, &trPk, t_r))
      goto cleanup;
    secp256k1_pubkey const *pts[2] = {&tbG, &trPk};
    if (!secp256k1_ec_pubkey_combine(ctx, &T4, pts, 2))
      goto cleanup;
  }

  /* T6 = t_b*G + t_r*pk_target2 */
  {
    secp256k1_pubkey tbG, trPk;
    if (!secp256k1_ec_pubkey_create(ctx, &tbG, t_b))
      goto cleanup;
    trPk = *pk_target2;
    if (!mpt_ct_pubkey_tweak_mul(ctx, &trPk, t_r))
      goto cleanup;
    secp256k1_pubkey const *pts[2] = {&tbG, &trPk};
    if (!secp256k1_ec_pubkey_combine(ctx, &T6, pts, 2))
      goto cleanup;
  }

  /* 3. Challenge */
  if (!compute_both_core_challenge(
          ctx, e, pk_anchor, C1, C2, pk_target1, pk_target2, D1_1, D2_1, D1_2,
          D2_2, &T1, &T2, &T3, &T4, &T6, domain, domain_len, context_id))
    goto cleanup;

  /* 4. Responses */
  compute_sigma_response(z_b, t_b, e, b_scalar);
  compute_sigma_response(z_sk, t_sk, e, sk_anchor);
  compute_sigma_response(z_r, t_r, e, r_new);

  /* 5. Serialize: e || z_b || z_sk || z_r */
  memcpy(proof_out + OFF_E, e, kMPT_SCALAR_SIZE);
  memcpy(proof_out + OFF_ZB, z_b, kMPT_SCALAR_SIZE);
  memcpy(proof_out + OFF_ZSK, z_sk, kMPT_SCALAR_SIZE);
  memcpy(proof_out + OFF_ZR, z_r, kMPT_SCALAR_SIZE);

  ok = 1;

cleanup:
  OPENSSL_cleanse(t_b, kMPT_SCALAR_SIZE);
  OPENSSL_cleanse(t_sk, kMPT_SCALAR_SIZE);
  OPENSSL_cleanse(t_r, kMPT_SCALAR_SIZE);
  OPENSSL_cleanse(b_scalar, kMPT_SCALAR_SIZE);
  OPENSSL_cleanse(e, kMPT_SCALAR_SIZE);
  OPENSSL_cleanse(z_b, kMPT_SCALAR_SIZE);
  OPENSSL_cleanse(z_sk, kMPT_SCALAR_SIZE);
  OPENSSL_cleanse(z_r, kMPT_SCALAR_SIZE);
  return ok;
}

/* --- Verifier --- */

int mpt_rotate_both_core_verify(
    secp256k1_context const *ctx, unsigned char const *proof,
    secp256k1_pubkey const *pk_anchor, secp256k1_pubkey const *C1,
    secp256k1_pubkey const *C2, secp256k1_pubkey const *pk_target1,
    secp256k1_pubkey const *pk_target2, secp256k1_pubkey const *D1_1,
    secp256k1_pubkey const *D2_1, secp256k1_pubkey const *D1_2,
    secp256k1_pubkey const *D2_2, char const *domain, size_t domain_len,
    unsigned char const *context_id)
{
  MPT_ARG_CHECK(ctx != NULL);
  MPT_ARG_CHECK(proof != NULL);
  MPT_ARG_CHECK(pk_anchor != NULL);
  MPT_ARG_CHECK(C1 != NULL);
  MPT_ARG_CHECK(C2 != NULL);
  MPT_ARG_CHECK(pk_target1 != NULL);
  MPT_ARG_CHECK(pk_target2 != NULL);
  MPT_ARG_CHECK(D1_1 != NULL);
  MPT_ARG_CHECK(D2_1 != NULL);
  MPT_ARG_CHECK(D1_2 != NULL);
  MPT_ARG_CHECK(D2_2 != NULL);
  MPT_ARG_CHECK(domain != NULL);
  MPT_ARG_CHECK(domain_len > 0);

  /* Mandatory shared-randomness equality check (fix for Finding f:mhaud).
   * This is NOT implied by the sigma proof below: D1_2 enters the challenge
   * preimage but no reconstruction equation names it, so nothing in the
   * algebra binds it without this explicit comparison. */
  if (!pubkey_equal(ctx, D1_1, D1_2))
    return 0;

  unsigned char e[kMPT_SCALAR_SIZE], z_b[kMPT_SCALAR_SIZE];
  unsigned char z_sk[kMPT_SCALAR_SIZE], z_r[kMPT_SCALAR_SIZE];
  unsigned char e_prime[kMPT_SCALAR_SIZE], neg_e[kMPT_SCALAR_SIZE];
  secp256k1_pubkey T1, T2, T3, T4, T6;

  /* 1. Deserialize: e || z_b || z_sk || z_r */
  memcpy(e, proof + OFF_E, kMPT_SCALAR_SIZE);
  memcpy(z_b, proof + OFF_ZB, kMPT_SCALAR_SIZE);
  memcpy(z_sk, proof + OFF_ZSK, kMPT_SCALAR_SIZE);
  memcpy(z_r, proof + OFF_ZR, kMPT_SCALAR_SIZE);

  if (!secp256k1_ec_seckey_verify(ctx, e))
    return 0;
  if (!secp256k1_ec_seckey_verify(ctx, z_b))
    return 0;
  if (!secp256k1_ec_seckey_verify(ctx, z_sk))
    return 0;
  if (!secp256k1_ec_seckey_verify(ctx, z_r))
    return 0;

  secp256k1_mpt_scalar_negate(neg_e, e);

  /* 2. Reconstruct commitments. All inputs are public: variable-time tweaks
   * are appropriate here. */

  /* T1 = z_sk*G - e*pk_anchor */
  {
    secp256k1_pubkey zskG, ePk;
    if (!secp256k1_ec_pubkey_create(ctx, &zskG, z_sk))
      return 0;
    ePk = *pk_anchor;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &ePk, neg_e))
      return 0;
    secp256k1_pubkey const *pts[2] = {&zskG, &ePk};
    if (!secp256k1_ec_pubkey_combine(ctx, &T1, pts, 2))
      return 0;
  }

  /* T2 = z_b*G + z_sk*C1 - e*C2 */
  {
    secp256k1_pubkey zbG, zskC1, eC2;
    if (!secp256k1_ec_pubkey_create(ctx, &zbG, z_b))
      return 0;
    zskC1 = *C1;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &zskC1, z_sk))
      return 0;
    eC2 = *C2;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &eC2, neg_e))
      return 0;
    secp256k1_pubkey const *pts[3] = {&zbG, &zskC1, &eC2};
    if (!secp256k1_ec_pubkey_combine(ctx, &T2, pts, 3))
      return 0;
  }

  /* T3 = z_r*G - e*D1_1 */
  {
    secp256k1_pubkey zrG, eD1;
    if (!secp256k1_ec_pubkey_create(ctx, &zrG, z_r))
      return 0;
    eD1 = *D1_1;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &eD1, neg_e))
      return 0;
    secp256k1_pubkey const *pts[2] = {&zrG, &eD1};
    if (!secp256k1_ec_pubkey_combine(ctx, &T3, pts, 2))
      return 0;
  }

  /* T4 = z_b*G + z_r*pk_target1 - e*D2_1 */
  {
    secp256k1_pubkey zbG, zrPk, eD2;
    if (!secp256k1_ec_pubkey_create(ctx, &zbG, z_b))
      return 0;
    zrPk = *pk_target1;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &zrPk, z_r))
      return 0;
    eD2 = *D2_1;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &eD2, neg_e))
      return 0;
    secp256k1_pubkey const *pts[3] = {&zbG, &zrPk, &eD2};
    if (!secp256k1_ec_pubkey_combine(ctx, &T4, pts, 3))
      return 0;
  }

  /* T6 = z_b*G + z_r*pk_target2 - e*D2_2 */
  {
    secp256k1_pubkey zbG, zrPk, eD2;
    if (!secp256k1_ec_pubkey_create(ctx, &zbG, z_b))
      return 0;
    zrPk = *pk_target2;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &zrPk, z_r))
      return 0;
    eD2 = *D2_2;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &eD2, neg_e))
      return 0;
    secp256k1_pubkey const *pts[3] = {&zbG, &zrPk, &eD2};
    if (!secp256k1_ec_pubkey_combine(ctx, &T6, pts, 3))
      return 0;
  }

  /* 3. Recompute challenge */
  if (!compute_both_core_challenge(
          ctx, e_prime, pk_anchor, C1, C2, pk_target1, pk_target2, D1_1, D2_1,
          D1_2, D2_2, &T1, &T2, &T3, &T4, &T6, domain, domain_len, context_id))
    return 0;

  /* 4. Accept iff e' == e */
  return CRYPTO_memcmp(e, e_prime, kMPT_SCALAR_SIZE) == 0;
}
