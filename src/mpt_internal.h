/**
 * @file mpt_internal.h
 * @brief Shared internal helpers for mpt-crypto source files.
 *
 * These are `static inline` utilities used across multiple translation units.
 * They are NOT part of the public API.
 */
#ifndef MPT_INTERNAL_H
#define MPT_INTERNAL_H

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <stdint.h>
#include <string.h>

/**
 * Argument validation macro, following the secp256k1 ARG_CHECK pattern.
 * Returns 0 from the calling function if the condition is false.
 */
#define MPT_ARG_CHECK(cond) \
    do                      \
    {                       \
        if (!(cond))        \
            return 0;       \
    } while (0)

/* Forward-declare secp256k1_mpt scalar helpers. */
void
secp256k1_mpt_scalar_reduce32(unsigned char out32[32], unsigned char const in32[32]);
void
secp256k1_mpt_scalar_add(unsigned char* res, unsigned char const* a, unsigned char const* b);
void
secp256k1_mpt_scalar_mul(unsigned char* res, unsigned char const* a, unsigned char const* b);

/** Returns 1 if pk1 == pk2, 0 otherwise. */
static inline int
pubkey_equal(secp256k1_context const* ctx, secp256k1_pubkey const* pk1, secp256k1_pubkey const* pk2)
{
    return secp256k1_ec_pubkey_cmp(ctx, pk1, pk2) == 0;
}

/** ECDH hash callback that copies the raw uncompressed point bytes
 *  (0x04 || x32 || y32) into the 65-byte output buffer. Used by
 *  mpt_ct_pubkey_tweak_mul below. */
static inline int
mpt_raw_point_copy_hashfn(
    unsigned char* output,
    unsigned char const* x32,
    unsigned char const* y32,
    void* data)
{
    (void)data;
    output[0] = 0x04;
    memcpy(output + 1, x32, 32);
    memcpy(output + 33, y32, 32);
    return 1;
}

/** Constant-time replacement for secp256k1_ec_pubkey_tweak_mul on a secret scalar.
 *
 *  secp256k1_ec_pubkey_tweak_mul dispatches through secp256k1_ecmult ->
 *  secp256k1_ecmult_strauss_wnaf, which uses the explicitly variable-time ops
 *  secp256k1_gej_double_var / secp256k1_gej_add_ge_var. The scalar's wNAF
 *  representation gates branches and memory accesses, leaking Hamming-weight
 *  statistics through timing.
 *
 *  secp256k1_ecdh dispatches through secp256k1_ecmult_const, which uses
 *  constant-time scalar recoding and constant-time gej_double / gej_add_ge.
 *  By passing a custom hash callback that simply copies the raw (x, y)
 *  coordinates, we recover the multiplication result as a serialized point
 *  rather than the default SHA256-of-x.
 *
 *  Behaviour matches tweak_mul on the inputs callers care about: returns 1
 *  with `*point := scalar * (*point)` on a valid in-range scalar, returns 0
 *  on zero / overflow scalar (in which case `*point` is unchanged: ecdh's
 *  output goes to the raw buffer, which is cleansed before return, and
 *  pubkey_parse is skipped).
 *
 *  Caller must ensure `point` is initialized; on success it is overwritten
 *  with the new point. The 65-byte intermediate is cleansed unconditionally. */
static inline int
mpt_ct_pubkey_tweak_mul(
    secp256k1_context const* ctx,
    secp256k1_pubkey* point,
    unsigned char const* secret_scalar)
{
    unsigned char raw[65];
    int ok = 0;

    if (secp256k1_ecdh(ctx, raw, point, secret_scalar, mpt_raw_point_copy_hashfn, NULL) == 1)
    {
        ok = secp256k1_ec_pubkey_parse(ctx, point, raw, 65);
    }
    OPENSSL_cleanse(raw, sizeof(raw));
    return ok;
}

/** Generates a random valid secp256k1 scalar (0 < scalar < order).
 *  Returns 1 on success, 0 on RNG failure. */
static inline int
generate_random_scalar(secp256k1_context const* ctx, unsigned char* scalar)
{
    do
    {
        if (RAND_bytes(scalar, 32) != 1)
            return 0;
    } while (!secp256k1_ec_seckey_verify(ctx, scalar));
    return 1;
}

/** Encodes a uint64 amount as a 32-byte big-endian scalar. */
static inline void
mpt_uint64_to_scalar(unsigned char out[32], uint64_t v)
{
    memset(out, 0, 32);
    for (int i = 0; i < 8; ++i)
        out[31 - i] = (v >> (i * 8)) & 0xFF;
}

/**
 * Computes the elliptic curve point mG = amount * G.
 *
 * Returns 0 for amount == 0.  libsecp256k1 cannot represent the
 * point at infinity, so callers must handle the zero case themselves
 * (typically by skipping the G term).  Returning 0 here rather than
 * forwarding to secp256k1_ec_pubkey_create makes the failure mode
 * explicit and avoids a subtle dependency on libsecp internals.
 *
 * The intermediate scalar is wiped with OPENSSL_cleanse after use.
 * On the prover side the amount is a witness; on the verifier side
 * it is public input.  We cleanse unconditionally for simplicity.
 */
static inline int
compute_amount_point(secp256k1_context const* ctx, secp256k1_pubkey* mG, uint64_t amount)
{
    unsigned char amount_scalar[32];
    int ret;
    if (amount == 0)
        return 0;
    mpt_uint64_to_scalar(amount_scalar, amount);
    ret = secp256k1_ec_pubkey_create(ctx, mG, amount_scalar);
    OPENSSL_cleanse(amount_scalar, 32);
    return ret;
}

/** Compute a sigma-protocol response: z = nonce + e * secret (mod order).
 *
 *  Uses direct scalar-field arithmetic rather than
 *  secp256k1_ec_seckey_tweak_mul/add, which reject zero operands via
 *  seckey_verify. Zero secrets occur with probability 1 in legitimate
 *  states (e.g. amount=0 or balance=0 inputs to compact sigma proofs),
 *  so the sigma-response computation must not abort on them.
 *
 *  The output z is a response scalar (nonce + e*secret) that is
 *  transmitted in the proof; 0 is a cryptographically negligible output
 *  given random nonce. Hence no failure mode: the function is void.
 *
 *  Cleanses the intermediate product. */
static inline void
compute_sigma_response(
    unsigned char* z_out,
    unsigned char const* nonce,
    unsigned char const* e,
    unsigned char const* secret)
{
    unsigned char term[32];
    secp256k1_mpt_scalar_mul(term, e, secret);
    secp256k1_mpt_scalar_add(z_out, nonce, term);
    OPENSSL_cleanse(term, 32);
}

/**
 * Generate k deterministic nonces via HMAC-SHA256 (synthetic RFC 6979 style).
 *
 * IKM = witness || statement_hash || domain
 * PRK = HMAC-SHA256(salt, IKM)                             [Extract]
 * nonce_i = HMAC-SHA256(PRK, prev || i)                    [Expand]
 *
 * salt = 32 bytes of fresh randomness (defense-in-depth).
 * Each output is reduced mod secp256k1 order; if zero, the function fails.
 *
 * @param[in]  ctx             secp256k1 context (for seckey_verify).
 * @param[out] nonces_out      Buffer of k*32 bytes to receive nonces.
 * @param[in]  k               Number of nonces to generate (max 8).
 * @param[in]  witness         Concatenated witness scalars.
 * @param[in]  witness_len     Length of witness buffer.
 * @param[in]  statement_hash  32-byte hash of all public statement elements.
 * @param[in]  domain          Domain separation tag string.
 * @param[in]  domain_len      Length of domain string.
 * @return 1 on success, 0 on failure.
 */
static inline int
generate_deterministic_nonces(
    secp256k1_context const* ctx,
    unsigned char* nonces_out,
    size_t k,
    unsigned char const* witness,
    size_t witness_len,
    unsigned char const* statement_hash,
    char const* domain,
    size_t domain_len)
{
    unsigned char salt[32];
    unsigned char prk[32];

    if (k == 0 || k > 8)
        return 0;

    /* Fresh entropy for defense-in-depth */
    if (RAND_bytes(salt, 32) != 1)
        return 0;

    /* Extract: PRK = HMAC-SHA256(salt, witness || statement_hash || domain) */
    {
        EVP_MAC* mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
        if (!mac)
        {
            OPENSSL_cleanse(salt, 32);
            return 0;
        }
        EVP_MAC_CTX* mctx = EVP_MAC_CTX_new(mac);
        if (!mctx)
        {
            EVP_MAC_free(mac);
            OPENSSL_cleanse(salt, 32);
            return 0;
        }
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0), OSSL_PARAM_construct_end()};
        size_t mac_len = 32;
        if (!EVP_MAC_init(mctx, salt, 32, params) || !EVP_MAC_update(mctx, witness, witness_len) ||
            !EVP_MAC_update(mctx, statement_hash, 32) ||
            !EVP_MAC_update(mctx, (unsigned char const*)domain, domain_len) ||
            !EVP_MAC_final(mctx, prk, &mac_len, 32))
        {
            EVP_MAC_CTX_free(mctx);
            EVP_MAC_free(mac);
            OPENSSL_cleanse(salt, 32);
            OPENSSL_cleanse(prk, 32);
            return 0;
        }
        EVP_MAC_CTX_free(mctx);
        EVP_MAC_free(mac);
    }

    /* Expand: nonce_i = HMAC-SHA256(PRK, prev || counter [|| sub_counter])
     *
     * If the reduced output happens to be 0 mod n (negligible ~1/2^256), retry
     * by appending an extra sub_counter byte to the MAC input and re-deriving.
     * sub_counter == 0 skips the extra update so the no-retry path is byte-
     * identical to the prior derivation. Cap retries at 256 (~1/2^65536) before
     * giving up. */
    {
        unsigned char prev[32];
        memset(prev, 0, 32);

        for (size_t i = 0; i < k; i++)
        {
            unsigned char counter = (unsigned char)(i + 1);
            unsigned char out[32];
            int sub_counter;
            int accepted = 0;

            for (sub_counter = 0; sub_counter < 256; sub_counter++)
            {
                EVP_MAC* mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
                if (!mac)
                {
                    OPENSSL_cleanse(prev, 32);
                    OPENSSL_cleanse(prk, 32);
                    OPENSSL_cleanse(nonces_out, k * 32);
                    return 0;
                }
                EVP_MAC_CTX* mctx = EVP_MAC_CTX_new(mac);
                if (!mctx)
                {
                    EVP_MAC_free(mac);
                    OPENSSL_cleanse(prev, 32);
                    OPENSSL_cleanse(prk, 32);
                    OPENSSL_cleanse(nonces_out, k * 32);
                    return 0;
                }
                OSSL_PARAM params[] = {
                    OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
                    OSSL_PARAM_construct_end()};
                size_t mac_len = 32;
                unsigned char sub = (unsigned char)sub_counter;
                if (!EVP_MAC_init(mctx, prk, 32, params) ||
                    (i > 0 && !EVP_MAC_update(mctx, prev, 32)) ||
                    !EVP_MAC_update(mctx, &counter, 1) ||
                    (sub_counter > 0 && !EVP_MAC_update(mctx, &sub, 1)) ||
                    !EVP_MAC_final(mctx, out, &mac_len, 32))
                {
                    EVP_MAC_CTX_free(mctx);
                    EVP_MAC_free(mac);
                    OPENSSL_cleanse(out, 32);
                    OPENSSL_cleanse(prev, 32);
                    OPENSSL_cleanse(prk, 32);
                    OPENSSL_cleanse(nonces_out, k * 32);
                    return 0;
                }
                EVP_MAC_CTX_free(mctx);
                EVP_MAC_free(mac);

                secp256k1_mpt_scalar_reduce32(out, out);
                if (secp256k1_ec_seckey_verify(ctx, out))
                {
                    accepted = 1;
                    break;
                }
            }

            if (!accepted)
            {
                OPENSSL_cleanse(out, 32);
                OPENSSL_cleanse(prev, 32);
                OPENSSL_cleanse(prk, 32);
                OPENSSL_cleanse(nonces_out, k * 32);
                return 0;
            }

            memcpy(nonces_out + i * 32, out, 32);
            memcpy(prev, out, 32);
            OPENSSL_cleanse(out, 32);
        }

        OPENSSL_cleanse(prev, 32);
    }

    OPENSSL_cleanse(salt, 32);
    OPENSSL_cleanse(prk, 32);
    return 1;
}

#endif /* MPT_INTERNAL_H */
