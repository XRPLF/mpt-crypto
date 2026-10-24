/**
 * @file proof_rotate_holder_rotate.c
 * @brief pi_hr - holder voluntary key rotation (spending balance + inbox).
 *
 * Language L_hr, per the key-rotation proof review's fold-in decision
 * (option (b): extend the relation to close Finding f:inbox rather than add
 * a ledger precondition):
 *
 *   exists (b, sk_H, r_s', sk_H', b_in, r_i') in Z_q^6 such that:
 *     pk_H  = sk_H*G
 *     S2 - sk_H*S1   = b*G        (holder decrypts CBS under the old key)
 *     S1'            = r_s'*G
 *     S2'            = b*G + r_s'*pk_H'
 *     pk_H'          = sk_H'*G    (PoK of the freshly rotated-to key)
 *     I2 - sk_H*I1   = b_in*G     (holder decrypts CBIN under the old key)
 *     I1'            = r_i'*G
 *     I2'            = b_in*G + r_i'*pk_H'
 *
 * The first five conjuncts are the original single-mirror relation; the last
 * three were added to bind the new inbox ciphertext into the transcript
 * (mpt-crypto PR review, Finding f:inbox), since the amendment writes the
 * new CBIN as a required field and MergeInbox later folds it into spending
 * unproven otherwise. sk_H is reused across the CBS and CBIN branches (one
 * nonce, alpha_sk, serves both T1 and T6), and pk_H' is reused as the
 * re-encryption target of both the CBS' and CBIN' branches.
 *
 * Unlike the shared re-encryption core (proof_rotate_core.h), this relation
 * needs its own transcript: it has six nonces, not four, and a PoK conjunct
 * (pk_H' = sk_H'*G) that the core does not model. It is not a plain
 * instantiation of L_reencrypt.
 *
 * Compact proof: (e, z_b, z_sk, z_rs, z_sk2, z_bin, z_ri) in Z_q^7 = 224
 * bytes.
 */
#include "mpt_internal.h"
#include "secp256k1_mpt.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>

static const char DOMAIN_ROTATE_HOLDER_ROTATE[] =
    "CMPT_KEY_ROTATION_HOLDER_ROTATE";

/* Wire order follows the witness tuple as written in the specification:
 *   (e, z_b, z_sk, z_rs, z_sk2, z_bin, z_ri) */
#define OFF_E (0 * kMPT_SCALAR_SIZE)
#define OFF_ZB (1 * kMPT_SCALAR_SIZE)
#define OFF_ZSK (2 * kMPT_SCALAR_SIZE)
#define OFF_ZRS (3 * kMPT_SCALAR_SIZE)
#define OFF_ZSK2 (4 * kMPT_SCALAR_SIZE)
#define OFF_ZBIN (5 * kMPT_SCALAR_SIZE)
#define OFF_ZRI (6 * kMPT_SCALAR_SIZE)

static int compute_hr_challenge(
    secp256k1_context const *ctx, unsigned char *e_out,
    secp256k1_pubkey const *pk_H, secp256k1_pubkey const *pk_H_new,
    secp256k1_pubkey const *S1, secp256k1_pubkey const *S2,
    secp256k1_pubkey const *S1_new, secp256k1_pubkey const *S2_new,
    secp256k1_pubkey const *I1, secp256k1_pubkey const *I2,
    secp256k1_pubkey const *I1_new, secp256k1_pubkey const *I2_new,
    secp256k1_pubkey const *T1, secp256k1_pubkey const *T2,
    secp256k1_pubkey const *T3, secp256k1_pubkey const *T4,
    secp256k1_pubkey const *T5, secp256k1_pubkey const *T6,
    secp256k1_pubkey const *T7, secp256k1_pubkey const *T8,
    unsigned char const *context_id)
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
  if (EVP_DigestUpdate(mdctx, DOMAIN_ROTATE_HOLDER_ROTATE,
                       strlen(DOMAIN_ROTATE_HOLDER_ROTATE)) != 1)
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

  /* Statement */
  SER(pk_H);
  SER(pk_H_new);
  SER(S1);
  SER(S2);
  SER(S1_new);
  SER(S2_new);
  SER(I1);
  SER(I2);
  SER(I1_new);
  SER(I2_new);

  /* Commitments */
  SER(T1);
  SER(T2);
  SER(T3);
  SER(T4);
  SER(T5);
  SER(T6);
  SER(T7);
  SER(T8);

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
static int compute_hr_stmt_hash(
    secp256k1_context const *ctx, unsigned char *out,
    secp256k1_pubkey const *pk_H, secp256k1_pubkey const *pk_H_new,
    secp256k1_pubkey const *S1, secp256k1_pubkey const *S2,
    secp256k1_pubkey const *S1_new, secp256k1_pubkey const *S2_new,
    secp256k1_pubkey const *I1, secp256k1_pubkey const *I2,
    secp256k1_pubkey const *I1_new, secp256k1_pubkey const *I2_new,
    unsigned char const *context_id)
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

  SHASH(pk_H);
  SHASH(pk_H_new);
  SHASH(S1);
  SHASH(S2);
  SHASH(S1_new);
  SHASH(S2_new);
  SHASH(I1);
  SHASH(I2);
  SHASH(I1_new);
  SHASH(I2_new);

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

int secp256k1_rotate_holder_rotate_prove(
    secp256k1_context const *ctx, unsigned char *proof_out, uint64_t balance,
    uint64_t inbox_balance, unsigned char const *sk_H,
    unsigned char const *r_s_new, unsigned char const *sk_H_new,
    unsigned char const *r_i_new, secp256k1_pubkey const *pk_H,
    secp256k1_pubkey const *pk_H_new, secp256k1_pubkey const *S1,
    secp256k1_pubkey const *S2, secp256k1_pubkey const *S1_new,
    secp256k1_pubkey const *S2_new, secp256k1_pubkey const *I1,
    secp256k1_pubkey const *I2, secp256k1_pubkey const *I1_new,
    secp256k1_pubkey const *I2_new, unsigned char const *context_id)
{
  MPT_ARG_CHECK(ctx != NULL);
  MPT_ARG_CHECK(proof_out != NULL);
  MPT_ARG_CHECK(sk_H != NULL);
  MPT_ARG_CHECK(r_s_new != NULL);
  MPT_ARG_CHECK(sk_H_new != NULL);
  MPT_ARG_CHECK(r_i_new != NULL);
  MPT_ARG_CHECK(pk_H != NULL);
  MPT_ARG_CHECK(pk_H_new != NULL);
  MPT_ARG_CHECK(S1 != NULL);
  MPT_ARG_CHECK(S2 != NULL);
  MPT_ARG_CHECK(S1_new != NULL);
  MPT_ARG_CHECK(S2_new != NULL);
  MPT_ARG_CHECK(I1 != NULL);
  MPT_ARG_CHECK(I2 != NULL);
  MPT_ARG_CHECK(I1_new != NULL);
  MPT_ARG_CHECK(I2_new != NULL);

  if (!secp256k1_ec_seckey_verify(ctx, sk_H))
    return 0;
  if (!secp256k1_ec_seckey_verify(ctx, r_s_new))
    return 0;
  if (!secp256k1_ec_seckey_verify(ctx, sk_H_new))
    return 0;
  if (!secp256k1_ec_seckey_verify(ctx, r_i_new))
    return 0;

  unsigned char t_b[kMPT_SCALAR_SIZE], t_sk[kMPT_SCALAR_SIZE];
  unsigned char t_rs[kMPT_SCALAR_SIZE], t_sk2[kMPT_SCALAR_SIZE];
  unsigned char t_bin[kMPT_SCALAR_SIZE], t_ri[kMPT_SCALAR_SIZE];
  unsigned char b_scalar[kMPT_SCALAR_SIZE], bin_scalar[kMPT_SCALAR_SIZE];
  unsigned char e[kMPT_SCALAR_SIZE];
  unsigned char z_b[kMPT_SCALAR_SIZE], z_sk[kMPT_SCALAR_SIZE];
  unsigned char z_rs[kMPT_SCALAR_SIZE], z_sk2[kMPT_SCALAR_SIZE];
  unsigned char z_bin[kMPT_SCALAR_SIZE], z_ri[kMPT_SCALAR_SIZE];
  secp256k1_pubkey T1, T2, T3, T4, T5, T6, T7, T8;
  int ok = 0;

  mpt_uint64_to_scalar(b_scalar, balance);
  mpt_uint64_to_scalar(bin_scalar, inbox_balance);

  /* 1. Deterministic nonces (witness || statement || fresh entropy).
   * Witness in canonical order: b, sk_H, r_s', sk_H', b_in, r_i'. */
  {
    unsigned char witness_buf[6 * kMPT_SCALAR_SIZE];
    unsigned char stmt_hash[kMPT_HALF_SHA_SIZE];
    unsigned char nonces[6 * kMPT_SCALAR_SIZE];

    memcpy(witness_buf, b_scalar, kMPT_SCALAR_SIZE);
    memcpy(witness_buf + kMPT_SCALAR_SIZE, sk_H, kMPT_SCALAR_SIZE);
    memcpy(witness_buf + 2 * kMPT_SCALAR_SIZE, r_s_new, kMPT_SCALAR_SIZE);
    memcpy(witness_buf + 3 * kMPT_SCALAR_SIZE, sk_H_new, kMPT_SCALAR_SIZE);
    memcpy(witness_buf + 4 * kMPT_SCALAR_SIZE, bin_scalar, kMPT_SCALAR_SIZE);
    memcpy(witness_buf + 5 * kMPT_SCALAR_SIZE, r_i_new, kMPT_SCALAR_SIZE);

    if (!compute_hr_stmt_hash(ctx, stmt_hash, pk_H, pk_H_new, S1, S2, S1_new,
                              S2_new, I1, I2, I1_new, I2_new, context_id))
    {
      OPENSSL_cleanse(witness_buf, sizeof(witness_buf));
      goto cleanup;
    }

    if (!generate_deterministic_nonces(
            ctx, nonces, 6, witness_buf, sizeof(witness_buf), stmt_hash,
            DOMAIN_ROTATE_HOLDER_ROTATE, strlen(DOMAIN_ROTATE_HOLDER_ROTATE)))
    {
      OPENSSL_cleanse(witness_buf, sizeof(witness_buf));
      goto cleanup;
    }

    memcpy(t_b, nonces, kMPT_SCALAR_SIZE);
    memcpy(t_sk, nonces + kMPT_SCALAR_SIZE, kMPT_SCALAR_SIZE);
    memcpy(t_rs, nonces + 2 * kMPT_SCALAR_SIZE, kMPT_SCALAR_SIZE);
    memcpy(t_sk2, nonces + 3 * kMPT_SCALAR_SIZE, kMPT_SCALAR_SIZE);
    memcpy(t_bin, nonces + 4 * kMPT_SCALAR_SIZE, kMPT_SCALAR_SIZE);
    memcpy(t_ri, nonces + 5 * kMPT_SCALAR_SIZE, kMPT_SCALAR_SIZE);
    OPENSSL_cleanse(witness_buf, sizeof(witness_buf));
    OPENSSL_cleanse(nonces, sizeof(nonces));
  }

  /* 2. Commitments */

  /* T1 = t_sk*G */
  if (!secp256k1_ec_pubkey_create(ctx, &T1, t_sk))
    goto cleanup;

  /* T2 = t_b*G + t_sk*S1 */
  {
    secp256k1_pubkey tbG, tskS1;
    if (!secp256k1_ec_pubkey_create(ctx, &tbG, t_b))
      goto cleanup;
    tskS1 = *S1;
    if (!mpt_ct_pubkey_tweak_mul(ctx, &tskS1, t_sk))
      goto cleanup;
    secp256k1_pubkey const *pts[2] = {&tbG, &tskS1};
    if (!secp256k1_ec_pubkey_combine(ctx, &T2, pts, 2))
      goto cleanup;
  }

  /* T3 = t_rs*G */
  if (!secp256k1_ec_pubkey_create(ctx, &T3, t_rs))
    goto cleanup;

  /* T4 = t_b*G + t_rs*pk_H_new */
  {
    secp256k1_pubkey tbG, trsPk;
    if (!secp256k1_ec_pubkey_create(ctx, &tbG, t_b))
      goto cleanup;
    trsPk = *pk_H_new;
    if (!mpt_ct_pubkey_tweak_mul(ctx, &trsPk, t_rs))
      goto cleanup;
    secp256k1_pubkey const *pts[2] = {&tbG, &trsPk};
    if (!secp256k1_ec_pubkey_combine(ctx, &T4, pts, 2))
      goto cleanup;
  }

  /* T5 = t_sk2*G */
  if (!secp256k1_ec_pubkey_create(ctx, &T5, t_sk2))
    goto cleanup;

  /* T6 = t_bin*G + t_sk*I1 (reuses t_sk: same sk_H in both branches) */
  {
    secp256k1_pubkey tbinG, tskI1;
    if (!secp256k1_ec_pubkey_create(ctx, &tbinG, t_bin))
      goto cleanup;
    tskI1 = *I1;
    if (!mpt_ct_pubkey_tweak_mul(ctx, &tskI1, t_sk))
      goto cleanup;
    secp256k1_pubkey const *pts[2] = {&tbinG, &tskI1};
    if (!secp256k1_ec_pubkey_combine(ctx, &T6, pts, 2))
      goto cleanup;
  }

  /* T7 = t_ri*G */
  if (!secp256k1_ec_pubkey_create(ctx, &T7, t_ri))
    goto cleanup;

  /* T8 = t_bin*G + t_ri*pk_H_new (reuses pk_H_new as re-encryption target) */
  {
    secp256k1_pubkey tbinG, triPk;
    if (!secp256k1_ec_pubkey_create(ctx, &tbinG, t_bin))
      goto cleanup;
    triPk = *pk_H_new;
    if (!mpt_ct_pubkey_tweak_mul(ctx, &triPk, t_ri))
      goto cleanup;
    secp256k1_pubkey const *pts[2] = {&tbinG, &triPk};
    if (!secp256k1_ec_pubkey_combine(ctx, &T8, pts, 2))
      goto cleanup;
  }

  /* 3. Challenge */
  if (!compute_hr_challenge(ctx, e, pk_H, pk_H_new, S1, S2, S1_new, S2_new, I1,
                            I2, I1_new, I2_new, &T1, &T2, &T3, &T4, &T5, &T6,
                            &T7, &T8, context_id))
    goto cleanup;

  /* 4. Responses */
  compute_sigma_response(z_b, t_b, e, b_scalar);
  compute_sigma_response(z_sk, t_sk, e, sk_H);
  compute_sigma_response(z_rs, t_rs, e, r_s_new);
  compute_sigma_response(z_sk2, t_sk2, e, sk_H_new);
  compute_sigma_response(z_bin, t_bin, e, bin_scalar);
  compute_sigma_response(z_ri, t_ri, e, r_i_new);

  /* 5. Serialize: e || z_b || z_sk || z_rs || z_sk2 || z_bin || z_ri */
  memcpy(proof_out + OFF_E, e, kMPT_SCALAR_SIZE);
  memcpy(proof_out + OFF_ZB, z_b, kMPT_SCALAR_SIZE);
  memcpy(proof_out + OFF_ZSK, z_sk, kMPT_SCALAR_SIZE);
  memcpy(proof_out + OFF_ZRS, z_rs, kMPT_SCALAR_SIZE);
  memcpy(proof_out + OFF_ZSK2, z_sk2, kMPT_SCALAR_SIZE);
  memcpy(proof_out + OFF_ZBIN, z_bin, kMPT_SCALAR_SIZE);
  memcpy(proof_out + OFF_ZRI, z_ri, kMPT_SCALAR_SIZE);

  ok = 1;

cleanup:
  OPENSSL_cleanse(t_b, kMPT_SCALAR_SIZE);
  OPENSSL_cleanse(t_sk, kMPT_SCALAR_SIZE);
  OPENSSL_cleanse(t_rs, kMPT_SCALAR_SIZE);
  OPENSSL_cleanse(t_sk2, kMPT_SCALAR_SIZE);
  OPENSSL_cleanse(t_bin, kMPT_SCALAR_SIZE);
  OPENSSL_cleanse(t_ri, kMPT_SCALAR_SIZE);
  OPENSSL_cleanse(b_scalar, kMPT_SCALAR_SIZE);
  OPENSSL_cleanse(bin_scalar, kMPT_SCALAR_SIZE);
  OPENSSL_cleanse(e, kMPT_SCALAR_SIZE);
  OPENSSL_cleanse(z_b, kMPT_SCALAR_SIZE);
  OPENSSL_cleanse(z_sk, kMPT_SCALAR_SIZE);
  OPENSSL_cleanse(z_rs, kMPT_SCALAR_SIZE);
  OPENSSL_cleanse(z_sk2, kMPT_SCALAR_SIZE);
  OPENSSL_cleanse(z_bin, kMPT_SCALAR_SIZE);
  OPENSSL_cleanse(z_ri, kMPT_SCALAR_SIZE);
  return ok;
}

/* --- Verifier --- */

int secp256k1_rotate_holder_rotate_verify(
    secp256k1_context const *ctx, unsigned char const *proof,
    secp256k1_pubkey const *pk_H, secp256k1_pubkey const *pk_H_new,
    secp256k1_pubkey const *S1, secp256k1_pubkey const *S2,
    secp256k1_pubkey const *S1_new, secp256k1_pubkey const *S2_new,
    secp256k1_pubkey const *I1, secp256k1_pubkey const *I2,
    secp256k1_pubkey const *I1_new, secp256k1_pubkey const *I2_new,
    unsigned char const *context_id)
{
  MPT_ARG_CHECK(ctx != NULL);
  MPT_ARG_CHECK(proof != NULL);
  MPT_ARG_CHECK(pk_H != NULL);
  MPT_ARG_CHECK(pk_H_new != NULL);
  MPT_ARG_CHECK(S1 != NULL);
  MPT_ARG_CHECK(S2 != NULL);
  MPT_ARG_CHECK(S1_new != NULL);
  MPT_ARG_CHECK(S2_new != NULL);
  MPT_ARG_CHECK(I1 != NULL);
  MPT_ARG_CHECK(I2 != NULL);
  MPT_ARG_CHECK(I1_new != NULL);
  MPT_ARG_CHECK(I2_new != NULL);

  unsigned char e[kMPT_SCALAR_SIZE], z_b[kMPT_SCALAR_SIZE];
  unsigned char z_sk[kMPT_SCALAR_SIZE], z_rs[kMPT_SCALAR_SIZE];
  unsigned char z_sk2[kMPT_SCALAR_SIZE], z_bin[kMPT_SCALAR_SIZE];
  unsigned char z_ri[kMPT_SCALAR_SIZE];
  unsigned char e_prime[kMPT_SCALAR_SIZE], neg_e[kMPT_SCALAR_SIZE];
  secp256k1_pubkey T1, T2, T3, T4, T5, T6, T7, T8;

  /* 1. Deserialize */
  memcpy(e, proof + OFF_E, kMPT_SCALAR_SIZE);
  memcpy(z_b, proof + OFF_ZB, kMPT_SCALAR_SIZE);
  memcpy(z_sk, proof + OFF_ZSK, kMPT_SCALAR_SIZE);
  memcpy(z_rs, proof + OFF_ZRS, kMPT_SCALAR_SIZE);
  memcpy(z_sk2, proof + OFF_ZSK2, kMPT_SCALAR_SIZE);
  memcpy(z_bin, proof + OFF_ZBIN, kMPT_SCALAR_SIZE);
  memcpy(z_ri, proof + OFF_ZRI, kMPT_SCALAR_SIZE);

  /* Rejects 0 and >= n, matching every other compact verifier here. */
  if (!secp256k1_ec_seckey_verify(ctx, e))
    return 0;
  if (!secp256k1_ec_seckey_verify(ctx, z_b))
    return 0;
  if (!secp256k1_ec_seckey_verify(ctx, z_sk))
    return 0;
  if (!secp256k1_ec_seckey_verify(ctx, z_rs))
    return 0;
  if (!secp256k1_ec_seckey_verify(ctx, z_sk2))
    return 0;
  if (!secp256k1_ec_seckey_verify(ctx, z_bin))
    return 0;
  if (!secp256k1_ec_seckey_verify(ctx, z_ri))
    return 0;

  secp256k1_mpt_scalar_negate(neg_e, e);

  /* 2. Reconstruct commitments. All inputs are public: variable-time tweaks
   * are appropriate here. */

  /* T1 = z_sk*G - e*pk_H */
  {
    secp256k1_pubkey zskG, ePk;
    if (!secp256k1_ec_pubkey_create(ctx, &zskG, z_sk))
      return 0;
    ePk = *pk_H;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &ePk, neg_e))
      return 0;
    secp256k1_pubkey const *pts[2] = {&zskG, &ePk};
    if (!secp256k1_ec_pubkey_combine(ctx, &T1, pts, 2))
      return 0;
  }

  /* T2 = z_b*G + z_sk*S1 - e*S2 */
  {
    secp256k1_pubkey zbG, zskS1, eS2;
    if (!secp256k1_ec_pubkey_create(ctx, &zbG, z_b))
      return 0;
    zskS1 = *S1;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &zskS1, z_sk))
      return 0;
    eS2 = *S2;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &eS2, neg_e))
      return 0;
    secp256k1_pubkey const *pts[3] = {&zbG, &zskS1, &eS2};
    if (!secp256k1_ec_pubkey_combine(ctx, &T2, pts, 3))
      return 0;
  }

  /* T3 = z_rs*G - e*S1' */
  {
    secp256k1_pubkey zrsG, eS1n;
    if (!secp256k1_ec_pubkey_create(ctx, &zrsG, z_rs))
      return 0;
    eS1n = *S1_new;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &eS1n, neg_e))
      return 0;
    secp256k1_pubkey const *pts[2] = {&zrsG, &eS1n};
    if (!secp256k1_ec_pubkey_combine(ctx, &T3, pts, 2))
      return 0;
  }

  /* T4 = z_b*G + z_rs*pk_H_new - e*S2' */
  {
    secp256k1_pubkey zbG, zrsPk, eS2n;
    if (!secp256k1_ec_pubkey_create(ctx, &zbG, z_b))
      return 0;
    zrsPk = *pk_H_new;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &zrsPk, z_rs))
      return 0;
    eS2n = *S2_new;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &eS2n, neg_e))
      return 0;
    secp256k1_pubkey const *pts[3] = {&zbG, &zrsPk, &eS2n};
    if (!secp256k1_ec_pubkey_combine(ctx, &T4, pts, 3))
      return 0;
  }

  /* T5 = z_sk2*G - e*pk_H_new */
  {
    secp256k1_pubkey zsk2G, ePkNew;
    if (!secp256k1_ec_pubkey_create(ctx, &zsk2G, z_sk2))
      return 0;
    ePkNew = *pk_H_new;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &ePkNew, neg_e))
      return 0;
    secp256k1_pubkey const *pts[2] = {&zsk2G, &ePkNew};
    if (!secp256k1_ec_pubkey_combine(ctx, &T5, pts, 2))
      return 0;
  }

  /* T6 = z_bin*G + z_sk*I1 - e*I2 */
  {
    secp256k1_pubkey zbinG, zskI1, eI2;
    if (!secp256k1_ec_pubkey_create(ctx, &zbinG, z_bin))
      return 0;
    zskI1 = *I1;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &zskI1, z_sk))
      return 0;
    eI2 = *I2;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &eI2, neg_e))
      return 0;
    secp256k1_pubkey const *pts[3] = {&zbinG, &zskI1, &eI2};
    if (!secp256k1_ec_pubkey_combine(ctx, &T6, pts, 3))
      return 0;
  }

  /* T7 = z_ri*G - e*I1' */
  {
    secp256k1_pubkey zriG, eI1n;
    if (!secp256k1_ec_pubkey_create(ctx, &zriG, z_ri))
      return 0;
    eI1n = *I1_new;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &eI1n, neg_e))
      return 0;
    secp256k1_pubkey const *pts[2] = {&zriG, &eI1n};
    if (!secp256k1_ec_pubkey_combine(ctx, &T7, pts, 2))
      return 0;
  }

  /* T8 = z_bin*G + z_ri*pk_H_new - e*I2' */
  {
    secp256k1_pubkey zbinG, zriPk, eI2n;
    if (!secp256k1_ec_pubkey_create(ctx, &zbinG, z_bin))
      return 0;
    zriPk = *pk_H_new;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &zriPk, z_ri))
      return 0;
    eI2n = *I2_new;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &eI2n, neg_e))
      return 0;
    secp256k1_pubkey const *pts[3] = {&zbinG, &zriPk, &eI2n};
    if (!secp256k1_ec_pubkey_combine(ctx, &T8, pts, 3))
      return 0;
  }

  /* 3. Recompute challenge */
  if (!compute_hr_challenge(ctx, e_prime, pk_H, pk_H_new, S1, S2, S1_new,
                            S2_new, I1, I2, I1_new, I2_new, &T1, &T2, &T3, &T4,
                            &T5, &T6, &T7, &T8, context_id))
    return 0;

  /* 4. Accept iff e' == e */
  return CRYPTO_memcmp(e, e_prime, kMPT_SCALAR_SIZE) == 0;
}
