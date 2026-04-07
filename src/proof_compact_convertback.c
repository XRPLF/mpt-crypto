/**
 * @file proof_compact_convertback.c
 * @brief AND-composed compact-form sigma protocol for ConvertBack transactions.
 *
 * In ConvertBack the withdrawal encryption randomness r_w is publicly
 * disclosed via the BlindingFactor field and verified deterministically
 * by the verifier (C1_w == r_w*G and C2_w == m*G + r_w*P_A).  The
 * sigma proof therefore covers only the balance-related relations.
 *
 * Language L_convertback:
 *   exists (b, sk_A, rho) in Z_q^3 such that:
 *     P_A         = sk_A*G
 *     B2 - b*G    = sk_A*B1
 *     PC_b        = b*G + rho*H
 *
 * Compact proof: (e, z_b, z_rho, z_sk) in Z_q^4 = 128 bytes.
 *
 * Verification reconstructs commitments:
 *   T_{sk,1}= z_sk*G - e*P_A           (recon-cb-tsk1)
 *   T_{sk,2}= z_b*G + z_sk*B1 - e*B2   (recon-cb-tsk2)
 *   T_b     = z_b*G + z_rho*H - e*PC_b (recon-cb-tb)
 * then recomputes the hash and checks e' == e.
 */
#include "mpt_internal.h"
#include "secp256k1_mpt.h"
#include <openssl/crypto.h>
#include <openssl/sha.h>

static const char DOMAIN_COMPACT_CONVERTBACK[] = "CMPT_CONVERTBACK_SIGMA";

static void compute_compact_convertback_challenge(
    const secp256k1_context *ctx, unsigned char *e_out,
    const secp256k1_pubkey *pk_A, const secp256k1_pubkey *B1,
    const secp256k1_pubkey *B2, const secp256k1_pubkey *PC_b,
    const secp256k1_pubkey *T_sk1, const secp256k1_pubkey *T_sk2,
    const secp256k1_pubkey *T_b, const unsigned char *context_id)
{
  SHA256_CTX sha;
  unsigned char buf[33];
  unsigned char h[32];
  size_t len;

#define SER(pk_ptr)                                                            \
  do                                                                           \
  {                                                                            \
    len = 33;                                                                  \
    secp256k1_ec_pubkey_serialize(ctx, buf, &len, pk_ptr,                      \
                                  SECP256K1_EC_COMPRESSED);                    \
    SHA256_Update(&sha, buf, 33);                                              \
  } while (0)

  SHA256_Init(&sha);
  SHA256_Update(&sha, DOMAIN_COMPACT_CONVERTBACK,
                strlen(DOMAIN_COMPACT_CONVERTBACK));

  /* Statement */
  SER(pk_A);
  SER(B1);
  SER(B2);
  SER(PC_b);

  /* Commitments */
  SER(T_sk1);
  SER(T_sk2);
  SER(T_b);

#undef SER

  if (context_id)
    SHA256_Update(&sha, context_id, 32);

  SHA256_Final(h, &sha);
  secp256k1_mpt_scalar_reduce32(e_out, h);
}

/* --- Prover --- */

int secp256k1_compact_convertback_prove(
    const secp256k1_context *ctx, unsigned char *proof_out, uint64_t balance,
    const unsigned char *sk_A, const unsigned char *rho,
    const secp256k1_pubkey *pk_A, const secp256k1_pubkey *B1,
    const secp256k1_pubkey *B2, const secp256k1_pubkey *PC_b,
    const unsigned char *context_id)
{
  /* Guards */
  if (!ctx || !proof_out || !sk_A || !rho || !pk_A || !B1 || !B2 || !PC_b)
    return 0;

  unsigned char t_b[32], t_sk[32], t_rho[32];
  unsigned char b_scalar[32];
  unsigned char e[32], z_b[32], z_sk[32], z_rho[32];
  secp256k1_pubkey T_sk1, T_sk2, T_b;
  secp256k1_pubkey H;
  int ok = 0;

  if (!secp256k1_ec_seckey_verify(ctx, sk_A))
    return 0;
  if (!secp256k1_ec_seckey_verify(ctx, rho))
    return 0;

  mpt_uint64_to_scalar(b_scalar, balance);

  if (!secp256k1_mpt_get_h_generator(ctx, &H))
    goto cleanup;

  /* 1. Deterministic nonces (witness || statement || fresh entropy) */
  {
    /* Witness in canonical order: b, rho, sk_A */
    unsigned char witness_buf[3 * 32];
    memcpy(witness_buf, b_scalar, 32);
    memcpy(witness_buf + 32, rho, 32);
    memcpy(witness_buf + 64, sk_A, 32);

    /* Hash public statement elements */
    unsigned char stmt_hash[32];
    {
      SHA256_CTX sh;
      unsigned char sbuf[33];
      size_t slen;
#define SHASH(pk_ptr)                                                          \
  do                                                                           \
  {                                                                            \
    slen = 33;                                                                 \
    secp256k1_ec_pubkey_serialize(ctx, sbuf, &slen, pk_ptr,                    \
                                  SECP256K1_EC_COMPRESSED);                    \
    SHA256_Update(&sh, sbuf, 33);                                              \
  } while (0)
      SHA256_Init(&sh);
      SHASH(pk_A);
      SHASH(B1);
      SHASH(B2);
      SHASH(PC_b);
      if (context_id)
        SHA256_Update(&sh, context_id, 32);
      SHA256_Final(stmt_hash, &sh);
#undef SHASH
    }

    unsigned char nonces[3 * 32];
    if (!generate_deterministic_nonces(
            ctx, nonces, 3, witness_buf, sizeof(witness_buf), stmt_hash,
            DOMAIN_COMPACT_CONVERTBACK, strlen(DOMAIN_COMPACT_CONVERTBACK)))
    {
      OPENSSL_cleanse(witness_buf, sizeof(witness_buf));
      goto cleanup;
    }
    memcpy(t_b, nonces, 32);
    memcpy(t_sk, nonces + 32, 32);
    memcpy(t_rho, nonces + 64, 32);
    OPENSSL_cleanse(witness_buf, sizeof(witness_buf));
    OPENSSL_cleanse(nonces, sizeof(nonces));
  }

  /* 2. Compute commitments */

  /* T_{sk,1} = t_sk*G */
  if (!secp256k1_ec_pubkey_create(ctx, &T_sk1, t_sk))
    goto cleanup;

  /* T_{sk,2} = t_b*G + t_sk*B1 */
  {
    secp256k1_pubkey tbG, tskB1;
    if (!secp256k1_ec_pubkey_create(ctx, &tbG, t_b))
      goto cleanup;
    tskB1 = *B1;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &tskB1, t_sk))
      goto cleanup;
    const secp256k1_pubkey *pts[2] = {&tbG, &tskB1};
    if (!secp256k1_ec_pubkey_combine(ctx, &T_sk2, pts, 2))
      goto cleanup;
  }

  /* T_b = t_b*G + t_rho*H */
  {
    secp256k1_pubkey tbG, trH;
    if (!secp256k1_ec_pubkey_create(ctx, &tbG, t_b))
      goto cleanup;
    trH = H;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &trH, t_rho))
      goto cleanup;
    const secp256k1_pubkey *pts[2] = {&tbG, &trH};
    if (!secp256k1_ec_pubkey_combine(ctx, &T_b, pts, 2))
      goto cleanup;
  }

  /* 3. Challenge */
  compute_compact_convertback_challenge(ctx, e, pk_A, B1, B2, PC_b, &T_sk1,
                                        &T_sk2, &T_b, context_id);

  /* 4. Responses */
  if (!compute_sigma_response(ctx, z_b, t_b, e, b_scalar))
    goto cleanup;
  if (!compute_sigma_response(ctx, z_sk, t_sk, e, sk_A))
    goto cleanup;
  if (!compute_sigma_response(ctx, z_rho, t_rho, e, rho))
    goto cleanup;

  /* 5. Serialize: e || z_b || z_rho || z_sk */
  memcpy(proof_out, e, 32);
  memcpy(proof_out + 32, z_b, 32);
  memcpy(proof_out + 64, z_rho, 32);
  memcpy(proof_out + 96, z_sk, 32);

  ok = 1;

cleanup:
  OPENSSL_cleanse(t_b, 32);
  OPENSSL_cleanse(t_sk, 32);
  OPENSSL_cleanse(t_rho, 32);
  OPENSSL_cleanse(b_scalar, 32);
  OPENSSL_cleanse(e, 32);
  OPENSSL_cleanse(z_b, 32);
  OPENSSL_cleanse(z_sk, 32);
  OPENSSL_cleanse(z_rho, 32);
  return ok;
}

/* --- Verifier --- */

int secp256k1_compact_convertback_verify(const secp256k1_context *ctx,
                                         const unsigned char *proof,
                                         const secp256k1_pubkey *pk_A,
                                         const secp256k1_pubkey *B1,
                                         const secp256k1_pubkey *B2,
                                         const secp256k1_pubkey *PC_b,
                                         const unsigned char *context_id)
{
  /* Guards */
  if (!ctx || !proof || !pk_A || !B1 || !B2 || !PC_b)
    return 0;

  unsigned char e[32], z_b[32], z_sk[32], z_rho[32];
  unsigned char e_prime[32], neg_e[32];
  secp256k1_pubkey T_sk1, T_sk2, T_b;
  secp256k1_pubkey H;

  /* 1. Deserialize: e || z_b || z_rho || z_sk */
  memcpy(e, proof, 32);
  memcpy(z_b, proof + 32, 32);
  memcpy(z_rho, proof + 64, 32);
  memcpy(z_sk, proof + 96, 32);

  if (!secp256k1_ec_seckey_verify(ctx, e))
    return 0;
  if (!secp256k1_ec_seckey_verify(ctx, z_b))
    return 0;
  if (!secp256k1_ec_seckey_verify(ctx, z_sk))
    return 0;
  if (!secp256k1_ec_seckey_verify(ctx, z_rho))
    return 0;

  if (!secp256k1_mpt_get_h_generator(ctx, &H))
    return 0;

  secp256k1_mpt_scalar_negate(neg_e, e);

  /* 2. Reconstruct commitments */

  /* T_sk1 = z_sk*G - e*P_A */
  {
    secp256k1_pubkey zskG, ePA;
    if (!secp256k1_ec_pubkey_create(ctx, &zskG, z_sk))
      return 0;
    ePA = *pk_A;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &ePA, neg_e))
      return 0;
    const secp256k1_pubkey *pts[2] = {&zskG, &ePA};
    if (!secp256k1_ec_pubkey_combine(ctx, &T_sk1, pts, 2))
      return 0;
  }

  /* T_sk2 = z_b*G + z_sk*B1 - e*B2 */
  {
    secp256k1_pubkey zbG, zskB1, eB2;
    if (!secp256k1_ec_pubkey_create(ctx, &zbG, z_b))
      return 0;
    zskB1 = *B1;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &zskB1, z_sk))
      return 0;
    eB2 = *B2;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &eB2, neg_e))
      return 0;
    const secp256k1_pubkey *pts[3] = {&zbG, &zskB1, &eB2};
    if (!secp256k1_ec_pubkey_combine(ctx, &T_sk2, pts, 3))
      return 0;
  }

  /* T_b = z_b*G + z_rho*H - e*PC_b */
  {
    secp256k1_pubkey zbG, zrH, ePCb;
    if (!secp256k1_ec_pubkey_create(ctx, &zbG, z_b))
      return 0;
    zrH = H;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &zrH, z_rho))
      return 0;
    ePCb = *PC_b;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &ePCb, neg_e))
      return 0;
    const secp256k1_pubkey *pts[3] = {&zbG, &zrH, &ePCb};
    if (!secp256k1_ec_pubkey_combine(ctx, &T_b, pts, 3))
      return 0;
  }

  /* 3. Recompute challenge */
  compute_compact_convertback_challenge(ctx, e_prime, pk_A, B1, B2, PC_b,
                                        &T_sk1, &T_sk2, &T_b, context_id);

  /* 4. Accept iff e' == e */
  return CRYPTO_memcmp(e, e_prime, 32) == 0;
}
