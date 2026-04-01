/**
 * @file proof_compact_standard.c
 * @brief AND-composed compact-form sigma protocol for standard EC-ElGamal.
 *
 * Combines all standard EG proof obligations (ciphertext equality,
 * Pedersen linkage, and balance verification) into a single sigma protocol
 * under a shared Fiat-Shamir challenge, in compact form.
 *
 * Language L_comb,std^(n):
 *   exists (r, m, sk_A, r_b, v) in Z_q^5 such that:
 *     C1          = r*G
 *     C_{2,i}     = r*pk_i + m*G        for i = 1..n
 *     PC_m        = m*G + r*H
 *     pk_A        = sk_A*G
 *     PC_b        = v*G + r_b*H
 *     sk_A*C1_rem + v*G = C2_rem
 *
 * Compact proof: (e, z_r, z_m, z_sk, z_rb, z_v) in Z_q^6 = 192 bytes.
 *
 * Verification reconstructs commitments:
 *   T1         = z_r*G - e*C1
 *   T_{2,i}    = z_r*pk_i + z_m*G - e*C_{2,i}
 *   T_PCm      = z_m*G + z_r*H - e*PC_m
 *   K1         = z_sk*G - e*pk_A
 *   T_PCb      = z_v*G + z_rb*H - e*PC_b
 *   K2         = z_sk*C1_rem + z_v*G - e*C2_rem
 * then recomputes the hash and checks e' == e.
 */
#include "mpt_internal.h"
#include "secp256k1_mpt.h"
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <stdlib.h>

static const char DOMAIN_COMPACT_STANDARD[] = "CMPT_COMBINED_STD_PROOF";

/**
 * Compute the Fiat-Shamir challenge.
 *
 * Hash input:
 *   domain || pk_1..pk_n || C1 || C_{2,1}..C_{2,n} || PC_m
 *          || pk_A || PC_b || C1_rem || C2_rem
 *          || T1 || T_{2,1}..T_{2,n} || T_PCm || K1 || T_PCb || K2
 *          || context_id
 */
static void compute_compact_std_challenge(
    const secp256k1_context *ctx, unsigned char *e_out, size_t n,
    const secp256k1_pubkey *Pk_vec, const secp256k1_pubkey *C1,
    const secp256k1_pubkey *C2_vec, const secp256k1_pubkey *PC_m,
    const secp256k1_pubkey *pk_A, const secp256k1_pubkey *PC_b,
    const secp256k1_pubkey *C1_rem, const secp256k1_pubkey *C2_rem,
    const secp256k1_pubkey *T1, const secp256k1_pubkey *T2_vec,
    const secp256k1_pubkey *T_PCm, const secp256k1_pubkey *K1,
    const secp256k1_pubkey *T_PCb, const secp256k1_pubkey *K2,
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
  SHA256_Update(&sha, DOMAIN_COMPACT_STANDARD, strlen(DOMAIN_COMPACT_STANDARD));

  /* Statement */
  for (size_t i = 0; i < n; i++)
    SER(&Pk_vec[i]);
  SER(C1);
  for (size_t i = 0; i < n; i++)
    SER(&C2_vec[i]);
  SER(PC_m);
  SER(pk_A);
  SER(PC_b);
  SER(C1_rem);
  SER(C2_rem);

  /* Commitments */
  SER(T1);
  for (size_t i = 0; i < n; i++)
    SER(&T2_vec[i]);
  SER(T_PCm);
  SER(K1);
  SER(T_PCb);
  SER(K2);

#undef SER

  if (context_id)
    SHA256_Update(&sha, context_id, 32);

  SHA256_Final(h, &sha);
  secp256k1_mpt_scalar_reduce32(e_out, h);
}

/* --- Prover --- */

int secp256k1_compact_standard_prove(
    const secp256k1_context *ctx, unsigned char *proof_out, uint64_t amount,
    uint64_t remainder, const unsigned char *r_shared,
    const unsigned char *sk_A, const unsigned char *r_b, size_t n,
    const secp256k1_pubkey *C1, const secp256k1_pubkey *C2_vec,
    const secp256k1_pubkey *Pk_vec, const secp256k1_pubkey *PC_m,
    const secp256k1_pubkey *pk_A, const secp256k1_pubkey *PC_b,
    const secp256k1_pubkey *C1_rem, const secp256k1_pubkey *C2_rem,
    const unsigned char *context_id)
{
  /* Nonces: alpha(r), beta(m), gamma(sk_A), delta(r_b), epsilon(v) */
  unsigned char alpha[32], beta[32], gamma[32], delta[32], epsilon[32];
  unsigned char m_scalar[32], v_scalar[32];
  unsigned char e[32], z_r[32], z_m[32], z_sk[32], z_rb[32], z_v[32];
  secp256k1_pubkey T1, T_PCm, K1, T_PCb, K2;
  secp256k1_pubkey *T2_vec = NULL;
  secp256k1_pubkey H;
  int ok = 0;

  if (!secp256k1_ec_seckey_verify(ctx, r_shared))
    return 0;
  if (!secp256k1_ec_seckey_verify(ctx, sk_A))
    return 0;
  if (!secp256k1_ec_seckey_verify(ctx, r_b))
    return 0;

  if (n > 0)
  {
    T2_vec = (secp256k1_pubkey *)malloc(sizeof(secp256k1_pubkey) * n);
    if (!T2_vec)
      return 0;
  }

  mpt_uint64_to_scalar(m_scalar, amount);
  mpt_uint64_to_scalar(v_scalar, remainder);

  if (!secp256k1_mpt_get_h_generator(ctx, &H))
    goto cleanup;

  /* 1. Sample nonces */
  if (!generate_random_scalar(ctx, alpha))
    goto cleanup;
  if (!generate_random_scalar(ctx, beta))
    goto cleanup;
  if (!generate_random_scalar(ctx, gamma))
    goto cleanup;
  if (!generate_random_scalar(ctx, delta))
    goto cleanup;
  if (!generate_random_scalar(ctx, epsilon))
    goto cleanup;

  /* 2. Compute commitments */

  /* T1 = alpha*G */
  if (!secp256k1_ec_pubkey_create(ctx, &T1, alpha))
    goto cleanup;

  /* T_{2,i} = alpha*pk_i + beta*G */
  {
    secp256k1_pubkey betaG;
    if (!secp256k1_ec_pubkey_create(ctx, &betaG, beta))
      goto cleanup;
    for (size_t i = 0; i < n; i++)
    {
      secp256k1_pubkey aPk = Pk_vec[i];
      if (!secp256k1_ec_pubkey_tweak_mul(ctx, &aPk, alpha))
        goto cleanup;
      const secp256k1_pubkey *pts[2] = {&aPk, &betaG};
      if (!secp256k1_ec_pubkey_combine(ctx, &T2_vec[i], pts, 2))
        goto cleanup;
    }
  }

  /* T_PCm = beta*G + alpha*H  (paper: m-nonce on G, r-nonce on H) */
  {
    secp256k1_pubkey betaG, alphaH;
    if (!secp256k1_ec_pubkey_create(ctx, &betaG, beta))
      goto cleanup;
    alphaH = H;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &alphaH, alpha))
      goto cleanup;
    const secp256k1_pubkey *pts[2] = {&betaG, &alphaH};
    if (!secp256k1_ec_pubkey_combine(ctx, &T_PCm, pts, 2))
      goto cleanup;
  }

  /* K1 = gamma*G */
  if (!secp256k1_ec_pubkey_create(ctx, &K1, gamma))
    goto cleanup;

  /* T_PCb = epsilon*G + delta*H  (paper: v-nonce on G, r_b-nonce on H) */
  {
    secp256k1_pubkey epsG, deltaH;
    if (!secp256k1_ec_pubkey_create(ctx, &epsG, epsilon))
      goto cleanup;
    deltaH = H;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &deltaH, delta))
      goto cleanup;
    const secp256k1_pubkey *pts[2] = {&epsG, &deltaH};
    if (!secp256k1_ec_pubkey_combine(ctx, &T_PCb, pts, 2))
      goto cleanup;
  }

  /* K2 = gamma*C1_rem + epsilon*G */
  {
    secp256k1_pubkey gC1r, epsG;
    gC1r = *C1_rem;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &gC1r, gamma))
      goto cleanup;
    if (!secp256k1_ec_pubkey_create(ctx, &epsG, epsilon))
      goto cleanup;
    const secp256k1_pubkey *pts[2] = {&gC1r, &epsG};
    if (!secp256k1_ec_pubkey_combine(ctx, &K2, pts, 2))
      goto cleanup;
  }

  /* 3. Challenge */
  compute_compact_std_challenge(ctx, e, n, Pk_vec, C1, C2_vec, PC_m, pk_A, PC_b,
                                C1_rem, C2_rem, &T1, T2_vec, &T_PCm, &K1,
                                &T_PCb, &K2, context_id);

  /* 4. Responses */

  /* z_r = alpha + e*r */
  if (!compute_sigma_response(ctx, z_r, alpha, e, r_shared))
    goto cleanup;
  /* z_m = beta + e*m */
  if (!compute_sigma_response(ctx, z_m, beta, e, m_scalar))
    goto cleanup;
  /* z_sk = gamma + e*sk_A */
  if (!compute_sigma_response(ctx, z_sk, gamma, e, sk_A))
    goto cleanup;
  /* z_rb = delta + e*r_b */
  if (!compute_sigma_response(ctx, z_rb, delta, e, r_b))
    goto cleanup;
  /* z_v = epsilon + e*v */
  if (!compute_sigma_response(ctx, z_v, epsilon, e, v_scalar))
    goto cleanup;

  /* 5. Serialize compact proof: e || z_r || z_m || z_sk || z_rb || z_v */
  memcpy(proof_out, e, 32);
  memcpy(proof_out + 32, z_r, 32);
  memcpy(proof_out + 64, z_m, 32);
  memcpy(proof_out + 96, z_sk, 32);
  memcpy(proof_out + 128, z_rb, 32);
  memcpy(proof_out + 160, z_v, 32);

  ok = 1;

cleanup:
  OPENSSL_cleanse(alpha, 32);
  OPENSSL_cleanse(beta, 32);
  OPENSSL_cleanse(gamma, 32);
  OPENSSL_cleanse(delta, 32);
  OPENSSL_cleanse(epsilon, 32);
  OPENSSL_cleanse(m_scalar, 32);
  OPENSSL_cleanse(v_scalar, 32);
  OPENSSL_cleanse(e, 32);
  OPENSSL_cleanse(z_r, 32);
  OPENSSL_cleanse(z_m, 32);
  OPENSSL_cleanse(z_sk, 32);
  OPENSSL_cleanse(z_rb, 32);
  OPENSSL_cleanse(z_v, 32);
  if (T2_vec)
    free(T2_vec);
  return ok;
}

/* --- Verifier --- */

int secp256k1_compact_standard_verify(
    const secp256k1_context *ctx, const unsigned char *proof, size_t n,
    const secp256k1_pubkey *C1, const secp256k1_pubkey *C2_vec,
    const secp256k1_pubkey *Pk_vec, const secp256k1_pubkey *PC_m,
    const secp256k1_pubkey *pk_A, const secp256k1_pubkey *PC_b,
    const secp256k1_pubkey *C1_rem, const secp256k1_pubkey *C2_rem,
    const unsigned char *context_id)
{
  unsigned char e[32], z_r[32], z_m[32], z_sk[32], z_rb[32], z_v[32];
  unsigned char e_prime[32], neg_e[32];
  secp256k1_pubkey T1, T_PCm, K1, T_PCb, K2;
  secp256k1_pubkey *T2_vec = NULL;
  secp256k1_pubkey H;
  int ok = 0;

  /* 1. Deserialize */
  memcpy(e, proof, 32);
  memcpy(z_r, proof + 32, 32);
  memcpy(z_m, proof + 64, 32);
  memcpy(z_sk, proof + 96, 32);
  memcpy(z_rb, proof + 128, 32);
  memcpy(z_v, proof + 160, 32);

  if (!secp256k1_ec_seckey_verify(ctx, e))
    return 0;
  if (!secp256k1_ec_seckey_verify(ctx, z_r))
    return 0;
  if (!secp256k1_ec_seckey_verify(ctx, z_m))
    return 0;
  if (!secp256k1_ec_seckey_verify(ctx, z_sk))
    return 0;
  if (!secp256k1_ec_seckey_verify(ctx, z_rb))
    return 0;
  if (!secp256k1_ec_seckey_verify(ctx, z_v))
    return 0;

  if (n > 0)
  {
    T2_vec = (secp256k1_pubkey *)malloc(sizeof(secp256k1_pubkey) * n);
    if (!T2_vec)
      return 0;
  }

  if (!secp256k1_mpt_get_h_generator(ctx, &H))
    goto cleanup;

  secp256k1_mpt_scalar_negate(neg_e, e);

  /* 2. Reconstruct commitments */

  /* T1 = z_r*G - e*C1 */
  {
    secp256k1_pubkey zrG, eC1;
    if (!secp256k1_ec_pubkey_create(ctx, &zrG, z_r))
      goto cleanup;
    eC1 = *C1;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &eC1, neg_e))
      goto cleanup;
    const secp256k1_pubkey *pts[2] = {&zrG, &eC1};
    if (!secp256k1_ec_pubkey_combine(ctx, &T1, pts, 2))
      goto cleanup;
  }

  /* T_{2,i} = z_r*pk_i + z_m*G - e*C_{2,i} */
  {
    secp256k1_pubkey zmG;
    if (!secp256k1_ec_pubkey_create(ctx, &zmG, z_m))
      goto cleanup;
    for (size_t i = 0; i < n; i++)
    {
      secp256k1_pubkey zrPk, eC2;
      zrPk = Pk_vec[i];
      if (!secp256k1_ec_pubkey_tweak_mul(ctx, &zrPk, z_r))
        goto cleanup;
      eC2 = C2_vec[i];
      if (!secp256k1_ec_pubkey_tweak_mul(ctx, &eC2, neg_e))
        goto cleanup;
      const secp256k1_pubkey *pts[3] = {&zrPk, &zmG, &eC2};
      if (!secp256k1_ec_pubkey_combine(ctx, &T2_vec[i], pts, 3))
        goto cleanup;
    }
  }

  /* T_PCm = z_m*G + z_r*H - e*PC_m */
  {
    secp256k1_pubkey zmG, zrH, ePCm;
    if (!secp256k1_ec_pubkey_create(ctx, &zmG, z_m))
      goto cleanup;
    zrH = H;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &zrH, z_r))
      goto cleanup;
    ePCm = *PC_m;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &ePCm, neg_e))
      goto cleanup;
    const secp256k1_pubkey *pts[3] = {&zmG, &zrH, &ePCm};
    if (!secp256k1_ec_pubkey_combine(ctx, &T_PCm, pts, 3))
      goto cleanup;
  }

  /* K1 = z_sk*G - e*pk_A */
  {
    secp256k1_pubkey zskG, ePk;
    if (!secp256k1_ec_pubkey_create(ctx, &zskG, z_sk))
      goto cleanup;
    ePk = *pk_A;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &ePk, neg_e))
      goto cleanup;
    const secp256k1_pubkey *pts[2] = {&zskG, &ePk};
    if (!secp256k1_ec_pubkey_combine(ctx, &K1, pts, 2))
      goto cleanup;
  }

  /* T_PCb = z_v*G + z_rb*H - e*PC_b */
  {
    secp256k1_pubkey zvG, zrbH, ePCb;
    if (!secp256k1_ec_pubkey_create(ctx, &zvG, z_v))
      goto cleanup;
    zrbH = H;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &zrbH, z_rb))
      goto cleanup;
    ePCb = *PC_b;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &ePCb, neg_e))
      goto cleanup;
    const secp256k1_pubkey *pts[3] = {&zvG, &zrbH, &ePCb};
    if (!secp256k1_ec_pubkey_combine(ctx, &T_PCb, pts, 3))
      goto cleanup;
  }

  /* K2 = z_sk*C1_rem + z_v*G - e*C2_rem */
  {
    secp256k1_pubkey zskC1r, zvG, eC2r;
    zskC1r = *C1_rem;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &zskC1r, z_sk))
      goto cleanup;
    if (!secp256k1_ec_pubkey_create(ctx, &zvG, z_v))
      goto cleanup;
    eC2r = *C2_rem;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &eC2r, neg_e))
      goto cleanup;
    const secp256k1_pubkey *pts[3] = {&zskC1r, &zvG, &eC2r};
    if (!secp256k1_ec_pubkey_combine(ctx, &K2, pts, 3))
      goto cleanup;
  }

  /* 3. Recompute challenge */
  compute_compact_std_challenge(ctx, e_prime, n, Pk_vec, C1, C2_vec, PC_m, pk_A,
                                PC_b, C1_rem, C2_rem, &T1, T2_vec, &T_PCm, &K1,
                                &T_PCb, &K2, context_id);

  /* 4. Accept iff e' == e (constant-time comparison) */
  if (CRYPTO_memcmp(e, e_prime, 32) == 0)
    ok = 1;

cleanup:
  if (T2_vec)
    free(T2_vec);
  return ok;
}
