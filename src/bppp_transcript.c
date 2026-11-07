#include "bppp_transcript.h"

#include "mpt_internal.h"
#include "mpt_protocol.h"

#include <openssl/evp.h>
#include <string.h>

/* ---- hashing helpers: every input is D || ... ---- */

static int bppp_hash_begin(EVP_MD_CTX *mdctx)
{
  return EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) == 1 &&
         EVP_DigestUpdate(mdctx, kBPPP_DOMAIN, kBPPP_DOMAIN_LEN) == 1;
}

static int bppp_hash_label(EVP_MD_CTX *mdctx, const char *label)
{
  size_t n = strlen(label);
  unsigned char len_byte;
  if (n == 0 || n > 255)
    return 0;
  len_byte = (unsigned char)n;
  return EVP_DigestUpdate(mdctx, &len_byte, 1) == 1 &&
         EVP_DigestUpdate(mdctx, label, n) == 1;
}

static int bppp_hash_u32(EVP_MD_CTX *mdctx, uint32_t v)
{
  unsigned char be[4];
  be[0] = (unsigned char)(v >> 24);
  be[1] = (unsigned char)(v >> 16);
  be[2] = (unsigned char)(v >> 8);
  be[3] = (unsigned char)v;
  return EVP_DigestUpdate(mdctx, be, 4) == 1;
}

static int bppp_hash_point(const secp256k1_context *ctx, EVP_MD_CTX *mdctx,
                           const secp256k1_pubkey *P)
{
  unsigned char ser[kMPT_PUBKEY_SIZE];
  size_t len = kMPT_PUBKEY_SIZE;
  if (!P)
    return 0;
  if (!secp256k1_ec_pubkey_serialize(ctx, ser, &len, P,
                                     SECP256K1_EC_COMPRESSED) ||
      len != kMPT_PUBKEY_SIZE)
    return 0;
  return EVP_DigestUpdate(mdctx, ser, kMPT_PUBKEY_SIZE) == 1;
}

static int bppp_hash_end(EVP_MD_CTX *mdctx, unsigned char out32[32])
{
  unsigned int len = 0;
  return EVP_DigestFinal_ex(mdctx, out32, &len) == 1 && len == 32;
}

/* Ch(state, label): H(D || Lbl("chal") || Lbl(label) || state) mod q, nonzero.
 */
static int bppp_challenge(const secp256k1_context *ctx,
                          const unsigned char state[32], const char *label,
                          unsigned char out32[32])
{
  unsigned char h[32];
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  int ok = 0;
  if (!mdctx)
    return 0;
  if (!bppp_hash_begin(mdctx) || !bppp_hash_label(mdctx, "chal") ||
      !bppp_hash_label(mdctx, label) ||
      EVP_DigestUpdate(mdctx, state, 32) != 1 || !bppp_hash_end(mdctx, h))
    goto cleanup;
  secp256k1_mpt_scalar_reduce32(out32, h);
  /* nonzero and canonical */
  if (secp256k1_ec_seckey_verify(ctx, out32) != 1)
    goto cleanup;
  ok = 1;
cleanup:
  EVP_MD_CTX_free(mdctx);
  return ok;
}

/* alpha + t != 0 for t = 1..b-1 (t = 0 is the nonzero check above). */
static int bppp_alpha_valid(const secp256k1_context *ctx,
                            const unsigned char alpha[32], uint32_t base)
{
  uint32_t t;
  for (t = 1; t < base; t++)
  {
    unsigned char sum[32];
    unsigned char tweak[32] = {0};
    tweak[28] = (unsigned char)(t >> 24);
    tweak[29] = (unsigned char)(t >> 16);
    tweak[30] = (unsigned char)(t >> 8);
    tweak[31] = (unsigned char)t;
    memcpy(sum, alpha, 32);
    /* tweak_add returns 0 when the result is zero (or the tweak invalid) */
    if (secp256k1_ec_seckey_tweak_add(ctx, sum, tweak) != 1)
      return 0;
  }
  return 1;
}

/* ---- public API ---- */

int secp256k1_bppp_params_digest(const secp256k1_context *ctx,
                                 unsigned char pp32[32], uint32_t k,
                                 uint32_t n_bits, uint32_t base,
                                 const secp256k1_pubkey *G,
                                 const secp256k1_pubkey *G_vec, uint32_t n_n,
                                 const secp256k1_pubkey *H_vec, uint32_t n_h)
{
  const unsigned char version = kBPPP_CIRCUIT_VERSION;
  EVP_MD_CTX *mdctx;
  uint32_t i;
  int ok = 0;

  if (!ctx || !pp32 || !G || !G_vec || !H_vec || k == 0 || n_n == 0 || n_h == 0)
    return 0;
  mdctx = EVP_MD_CTX_new();
  if (!mdctx)
    return 0;
  if (!bppp_hash_begin(mdctx) || !bppp_hash_label(mdctx, "params") ||
      EVP_DigestUpdate(mdctx, &version, 1) != 1 || !bppp_hash_u32(mdctx, k) ||
      !bppp_hash_u32(mdctx, n_bits) || !bppp_hash_u32(mdctx, base) ||
      !bppp_hash_u32(mdctx, n_n) || !bppp_hash_u32(mdctx, n_h) ||
      !bppp_hash_point(ctx, mdctx, G))
    goto cleanup;
  for (i = 0; i < n_n; i++)
    if (!bppp_hash_point(ctx, mdctx, &G_vec[i]))
      goto cleanup;
  for (i = 0; i < n_h; i++)
    if (!bppp_hash_point(ctx, mdctx, &H_vec[i]))
      goto cleanup;
  if (!bppp_hash_end(mdctx, pp32))
    goto cleanup;
  ok = 1;
cleanup:
  EVP_MD_CTX_free(mdctx);
  return ok;
}

int secp256k1_bppp_transcript_init(const secp256k1_context *ctx,
                                   secp256k1_bppp_transcript *t,
                                   const unsigned char pp32[32],
                                   const unsigned char context32[32],
                                   uint32_t base, const secp256k1_pubkey *V,
                                   size_t k)
{
  EVP_MD_CTX *mdctx;
  size_t i;
  int ok = 0;

  if (!ctx || !t || !pp32 || !context32 || !V || k == 0 || base < 2)
    return 0;
  memset(t, 0, sizeof(*t));
  mdctx = EVP_MD_CTX_new();
  if (!mdctx)
    return 0;
  if (!bppp_hash_begin(mdctx) || !bppp_hash_label(mdctx, "statement") ||
      EVP_DigestUpdate(mdctx, pp32, 32) != 1 ||
      EVP_DigestUpdate(mdctx, context32, 32) != 1)
    goto cleanup;
  for (i = 0; i < k; i++)
    if (!bppp_hash_point(ctx, mdctx, &V[i]))
      goto cleanup;
  if (!bppp_hash_end(mdctx, t->state))
    goto cleanup;
  t->round = 0;
  t->base = base;
  ok = 1;
cleanup:
  EVP_MD_CTX_free(mdctx);
  if (!ok)
    memset(t, 0, sizeof(*t));
  return ok;
}

/* s_{round+1} = H(D || Lbl(label) [|| u32(j)] || s_round || points...) */
static int bppp_advance(const secp256k1_context *ctx,
                        secp256k1_bppp_transcript *t, uint32_t expect_round,
                        const char *label, int with_j, uint32_t j,
                        const secp256k1_pubkey *P1, const secp256k1_pubkey *P2)
{
  unsigned char next[32];
  EVP_MD_CTX *mdctx;
  int ok = 0;

  if (!ctx || !t || t->round != expect_round)
    return 0;
  mdctx = EVP_MD_CTX_new();
  if (!mdctx)
    return 0;
  if (!bppp_hash_begin(mdctx) || !bppp_hash_label(mdctx, label))
    goto cleanup;
  if (with_j && !bppp_hash_u32(mdctx, j))
    goto cleanup;
  if (EVP_DigestUpdate(mdctx, t->state, 32) != 1)
    goto cleanup;
  if (!bppp_hash_point(ctx, mdctx, P1))
    goto cleanup;
  if (P2 && !bppp_hash_point(ctx, mdctx, P2))
    goto cleanup;
  if (!bppp_hash_end(mdctx, next))
    goto cleanup;
  memcpy(t->state, next, 32);
  t->round = expect_round + 1;
  ok = 1;
cleanup:
  EVP_MD_CTX_free(mdctx);
  return ok;
}

int secp256k1_bppp_transcript_round1(const secp256k1_context *ctx,
                                     secp256k1_bppp_transcript *t,
                                     const secp256k1_pubkey *C_L,
                                     const secp256k1_pubkey *C_O,
                                     unsigned char alpha[32])
{
  if (!alpha || !C_O)
    return 0;
  if (!bppp_advance(ctx, t, 0, "round1", 0, 0, C_L, C_O))
    return 0;
  if (!bppp_challenge(ctx, t->state, "alpha", alpha))
    return 0;
  return bppp_alpha_valid(ctx, alpha, t->base);
}

int secp256k1_bppp_transcript_round2(
    const secp256k1_context *ctx, secp256k1_bppp_transcript *t,
    const secp256k1_pubkey *C_R, unsigned char rho[32],
    unsigned char lambda[32], unsigned char beta[32], unsigned char delta[32])
{
  if (!rho || !lambda || !beta || !delta)
    return 0;
  if (!bppp_advance(ctx, t, 1, "round2", 0, 0, C_R, NULL))
    return 0;
  return bppp_challenge(ctx, t->state, "rho", rho) &&
         bppp_challenge(ctx, t->state, "lambda", lambda) &&
         bppp_challenge(ctx, t->state, "beta", beta) &&
         bppp_challenge(ctx, t->state, "delta", delta);
}

int secp256k1_bppp_transcript_round3(const secp256k1_context *ctx,
                                     secp256k1_bppp_transcript *t,
                                     const secp256k1_pubkey *C_S,
                                     unsigned char tau[32])
{
  if (!tau)
    return 0;
  if (!bppp_advance(ctx, t, 2, "round3", 0, 0, C_S, NULL))
    return 0;
  return bppp_challenge(ctx, t->state, "tau", tau);
}

int secp256k1_bppp_transcript_nla_round(const secp256k1_context *ctx,
                                        secp256k1_bppp_transcript *t,
                                        uint32_t j, const secp256k1_pubkey *X,
                                        const secp256k1_pubkey *R,
                                        unsigned char gamma[32])
{
  if (!gamma || !R || j == 0 || j > UINT32_MAX - 3)
    return 0;
  if (!bppp_advance(ctx, t, 2 + j, "nla", 1, j, X, R))
    return 0;
  return bppp_challenge(ctx, t->state, "gamma", gamma);
}
