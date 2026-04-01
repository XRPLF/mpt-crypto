/**
 * @file proof_compact_convertback.c
 * @brief AND-composed compact-form sigma protocol for ConvertBack transactions.
 *
 * Proves knowledge of (r_w, b, sk_A, rho) for a withdrawal of publicly known
 * amount m, combining withdrawal ciphertext correctness, key ownership,
 * balance decryption linkage, and balance Pedersen commitment.
 *
 * Language L_convertback:
 *   exists (r_w, b, sk_A, rho) in Z_q^4 such that:
 *     C1_w        = r_w*G
 *     C2_w        = m*G + r_w*P_A
 *     P_A         = sk_A*G
 *     B2 - b*G    = sk_A*B1
 *     PC_b        = b*G + rho*H
 *
 * Compact proof: (e, z_rw, z_b, z_sk, z_rho) in Z_q^5 = 160 bytes.
 *
 * Verification reconstructs commitments:
 *   T_1     = z_rw*G - e*C1_w           (recon-cb-t1)
 *   T_2     = z_rw*P_A - e*(C2_w-m*G)  (recon-cb-t2)
 *   T_{sk,1}= z_sk*G - e*P_A           (recon-cb-tsk1)
 *   T_{sk,2}= z_b*G + z_sk*B1 - e*B2   (recon-cb-tsk2)
 *   T_b     = z_b*G + z_rho*H - e*PC_b (recon-cb-tb)
 * then recomputes the hash and checks e' == e.
 */
#include "mpt_internal.h"
#include "secp256k1_mpt.h"
#include <openssl/crypto.h>
#include <openssl/sha.h>

static const char DOMAIN_COMPACT_CONVERTBACK[] = "CMPT_CONVERTBACK_COMPACT";

static void compute_compact_convertback_challenge(
    const secp256k1_context *ctx, unsigned char *e_out,
    const secp256k1_pubkey *pk_A, const secp256k1_pubkey *C1_w,
    const secp256k1_pubkey *C2_w, const unsigned char *m_scalar,
    const secp256k1_pubkey *B1, const secp256k1_pubkey *B2,
    const secp256k1_pubkey *PC_b, const secp256k1_pubkey *T1,
    const secp256k1_pubkey *T2, const secp256k1_pubkey *T_sk1,
    const secp256k1_pubkey *T_sk2, const secp256k1_pubkey *T_b,
    const unsigned char *context_id)
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
  SER(C1_w);
  SER(C2_w);
  SHA256_Update(&sha, m_scalar, 32);
  SER(B1);
  SER(B2);
  SER(PC_b);

  /* Commitments */
  SER(T1);
  SER(T2);
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
    const secp256k1_context *ctx, unsigned char *proof_out, uint64_t amount,
    uint64_t balance, const unsigned char *r_w, const unsigned char *sk_A,
    const unsigned char *rho, const secp256k1_pubkey *C1_w,
    const secp256k1_pubkey *C2_w, const secp256k1_pubkey *pk_A,
    const secp256k1_pubkey *B1, const secp256k1_pubkey *B2,
    const secp256k1_pubkey *PC_b, const unsigned char *context_id)
{
  unsigned char t_rw[32], t_b[32], t_sk[32], t_rho[32];
  unsigned char m_scalar[32], b_scalar[32];
  unsigned char e[32], z_rw[32], z_b[32], z_sk[32], z_rho[32];
  secp256k1_pubkey T1, T2, T_sk1, T_sk2, T_b;
  secp256k1_pubkey H;
  int ok = 0;

  if (!secp256k1_ec_seckey_verify(ctx, r_w))
    return 0;
  if (!secp256k1_ec_seckey_verify(ctx, sk_A))
    return 0;
  if (!secp256k1_ec_seckey_verify(ctx, rho))
    return 0;

  mpt_uint64_to_scalar(m_scalar, amount);
  mpt_uint64_to_scalar(b_scalar, balance);

  if (!secp256k1_mpt_get_h_generator(ctx, &H))
    goto cleanup;

  /* 1. Sample nonces */
  if (!generate_random_scalar(ctx, t_rw))
    goto cleanup;
  if (!generate_random_scalar(ctx, t_b))
    goto cleanup;
  if (!generate_random_scalar(ctx, t_sk))
    goto cleanup;
  if (!generate_random_scalar(ctx, t_rho))
    goto cleanup;

  /* 2. Compute commitments */

  /* T1 = t_rw*G */
  if (!secp256k1_ec_pubkey_create(ctx, &T1, t_rw))
    goto cleanup;

  /* T2 = t_rw*P_A */
  T2 = *pk_A;
  if (!secp256k1_ec_pubkey_tweak_mul(ctx, &T2, t_rw))
    goto cleanup;

  /* T_{sk,1} = t_sk*G  [spec eq. recon-cb-tsk1] */
  if (!secp256k1_ec_pubkey_create(ctx, &T_sk1, t_sk))
    goto cleanup;

  /* T_{sk,2} = t_b*G + t_sk*B1  [spec eq. recon-cb-tsk2] */
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

  /* T_b = t_b*G + t_rho*H  [spec eq. recon-cb-tb] */
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
  compute_compact_convertback_challenge(ctx, e, pk_A, C1_w, C2_w, m_scalar, B1,
                                        B2, PC_b, &T1, &T2, &T_sk1, &T_sk2,
                                        &T_b, context_id);

  /* 4. Responses */
  if (!compute_sigma_response(ctx, z_rw, t_rw, e, r_w))
    goto cleanup;
  if (!compute_sigma_response(ctx, z_b, t_b, e, b_scalar))
    goto cleanup;
  if (!compute_sigma_response(ctx, z_sk, t_sk, e, sk_A))
    goto cleanup;
  if (!compute_sigma_response(ctx, z_rho, t_rho, e, rho))
    goto cleanup;

  /* 5. Serialize: e || z_rw || z_b || z_sk || z_rho */
  memcpy(proof_out, e, 32);
  memcpy(proof_out + 32, z_rw, 32);
  memcpy(proof_out + 64, z_b, 32);
  memcpy(proof_out + 96, z_sk, 32);
  memcpy(proof_out + 128, z_rho, 32);

  ok = 1;

cleanup:
  OPENSSL_cleanse(t_rw, 32);
  OPENSSL_cleanse(t_b, 32);
  OPENSSL_cleanse(t_sk, 32);
  OPENSSL_cleanse(t_rho, 32);
  OPENSSL_cleanse(m_scalar, 32);
  OPENSSL_cleanse(b_scalar, 32);
  OPENSSL_cleanse(e, 32);
  OPENSSL_cleanse(z_rw, 32);
  OPENSSL_cleanse(z_b, 32);
  OPENSSL_cleanse(z_sk, 32);
  OPENSSL_cleanse(z_rho, 32);
  return ok;
}

/* --- Verifier --- */

int secp256k1_compact_convertback_verify(
    const secp256k1_context *ctx, const unsigned char *proof, uint64_t amount,
    const secp256k1_pubkey *C1_w, const secp256k1_pubkey *C2_w,
    const secp256k1_pubkey *pk_A, const secp256k1_pubkey *B1,
    const secp256k1_pubkey *B2, const secp256k1_pubkey *PC_b,
    const unsigned char *context_id)
{
  unsigned char e[32], z_rw[32], z_b[32], z_sk[32], z_rho[32];
  unsigned char e_prime[32], neg_e[32], m_scalar[32];
  secp256k1_pubkey T1, T2, T_sk1, T_sk2, T_b;
  secp256k1_pubkey H;

  /* 1. Deserialize */
  memcpy(e, proof, 32);
  memcpy(z_rw, proof + 32, 32);
  memcpy(z_b, proof + 64, 32);
  memcpy(z_sk, proof + 96, 32);
  memcpy(z_rho, proof + 128, 32);

  if (!secp256k1_ec_seckey_verify(ctx, e))
    return 0;
  if (!secp256k1_ec_seckey_verify(ctx, z_rw))
    return 0;
  if (!secp256k1_ec_seckey_verify(ctx, z_b))
    return 0;
  if (!secp256k1_ec_seckey_verify(ctx, z_sk))
    return 0;
  if (!secp256k1_ec_seckey_verify(ctx, z_rho))
    return 0;

  mpt_uint64_to_scalar(m_scalar, amount);

  if (!secp256k1_mpt_get_h_generator(ctx, &H))
    return 0;

  secp256k1_mpt_scalar_negate(neg_e, e);

  /* 2. Reconstruct commitments */

  /* T1 = z_rw*G - e*C1_w */
  {
    secp256k1_pubkey zrwG, eC1w;
    if (!secp256k1_ec_pubkey_create(ctx, &zrwG, z_rw))
      return 0;
    eC1w = *C1_w;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &eC1w, neg_e))
      return 0;
    const secp256k1_pubkey *pts[2] = {&zrwG, &eC1w};
    if (!secp256k1_ec_pubkey_combine(ctx, &T1, pts, 2))
      return 0;
  }

  /* T2 = z_rw*P_A - e*(C2_w - m*G) */
  {
    secp256k1_pubkey zrwPA, eTarget, mG;
    if (!secp256k1_ec_pubkey_create(ctx, &mG, m_scalar))
      return 0;
    unsigned char neg_one[32];
    unsigned char one[32] = {0};
    one[31] = 1;
    secp256k1_mpt_scalar_negate(neg_one, one);
    secp256k1_pubkey neg_mG = mG;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &neg_mG, neg_one))
      return 0;
    secp256k1_pubkey C2w_minus_mG;
    const secp256k1_pubkey *sub_pts[2] = {C2_w, &neg_mG};
    if (!secp256k1_ec_pubkey_combine(ctx, &C2w_minus_mG, sub_pts, 2))
      return 0;

    zrwPA = *pk_A;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &zrwPA, z_rw))
      return 0;
    eTarget = C2w_minus_mG;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &eTarget, neg_e))
      return 0;
    const secp256k1_pubkey *pts[2] = {&zrwPA, &eTarget};
    if (!secp256k1_ec_pubkey_combine(ctx, &T2, pts, 2))
      return 0;
  }

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
  compute_compact_convertback_challenge(ctx, e_prime, pk_A, C1_w, C2_w,
                                        m_scalar, B1, B2, PC_b, &T1, &T2,
                                        &T_sk1, &T_sk2, &T_b, context_id);

  /* 4. Accept iff e' == e */
  return CRYPTO_memcmp(e, e_prime, 32) == 0;
}
