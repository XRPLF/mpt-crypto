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

/* Forward-declare secp256k1_mpt helpers used in nonce generation. */
void
secp256k1_mpt_scalar_reduce32(unsigned char out32[32], unsigned char const in32[32]);

/** Returns 1 if pk1 == pk2, 0 otherwise. */
static inline int
pubkey_equal(secp256k1_context const* ctx, secp256k1_pubkey const* pk1, secp256k1_pubkey const* pk2)
{
    return secp256k1_ec_pubkey_cmp(ctx, pk1, pk2) == 0;
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
 *  Cleanses the intermediate product. Returns 1 on success, 0 on failure. */
static inline int
compute_sigma_response(
    secp256k1_context const* ctx,
    unsigned char* z_out,
    unsigned char const* nonce,
    unsigned char const* e,
    unsigned char const* secret)
{
    unsigned char term[32];
    memcpy(z_out, nonce, 32);
    memcpy(term, secret, 32);
    if (!secp256k1_ec_seckey_tweak_mul(ctx, term, e))
    {
        OPENSSL_cleanse(term, 32);
        return 0;
    }
    if (!secp256k1_ec_seckey_tweak_add(ctx, z_out, term))
    {
        OPENSSL_cleanse(term, 32);
        return 0;
    }
    OPENSSL_cleanse(term, 32);
    return 1;
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
    unsigned int prk_len = 32;

    if (k == 0 || k > 8)
        return 0;

    /* Fresh entropy for defense-in-depth */
    if (RAND_bytes(salt, 32) != 1)
        return 0;

    /* Extract: PRK = HMAC-SHA256(salt, witness || statement_hash || domain) */
    {
        EVP_MAC* mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
        if (!mac)
            return 0;
        EVP_MAC_CTX* mctx = EVP_MAC_CTX_new(mac);
        if (!mctx)
        {
            EVP_MAC_free(mac);
            return 0;
        }
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0), OSSL_PARAM_construct_end()};
        if (!EVP_MAC_init(mctx, salt, 32, params))
        {
            EVP_MAC_CTX_free(mctx);
            EVP_MAC_free(mac);
            return 0;
        }
        EVP_MAC_update(mctx, witness, witness_len);
        EVP_MAC_update(mctx, statement_hash, 32);
        EVP_MAC_update(mctx, (unsigned char const*)domain, domain_len);
        size_t mac_len = 32;
        EVP_MAC_final(mctx, prk, &mac_len, 32);
        EVP_MAC_CTX_free(mctx);
        EVP_MAC_free(mac);
    }

    /* Expand: nonce_i = HMAC-SHA256(PRK, prev || counter) */
    {
        unsigned char prev[32];
        memset(prev, 0, 32);

        for (size_t i = 0; i < k; i++)
        {
            unsigned char counter = (unsigned char)(i + 1);
            unsigned char out[32];

            EVP_MAC* mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
            if (!mac)
            {
                OPENSSL_cleanse(prk, 32);
                OPENSSL_cleanse(nonces_out, k * 32);
                return 0;
            }
            EVP_MAC_CTX* mctx = EVP_MAC_CTX_new(mac);
            if (!mctx)
            {
                EVP_MAC_free(mac);
                OPENSSL_cleanse(prk, 32);
                OPENSSL_cleanse(nonces_out, k * 32);
                return 0;
            }
            OSSL_PARAM params[] = {
                OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
                OSSL_PARAM_construct_end()};
            EVP_MAC_init(mctx, prk, 32, params);
            if (i > 0)
                EVP_MAC_update(mctx, prev, 32);
            EVP_MAC_update(mctx, &counter, 1);
            size_t mac_len = 32;
            EVP_MAC_final(mctx, out, &mac_len, 32);
            EVP_MAC_CTX_free(mctx);
            EVP_MAC_free(mac);

            secp256k1_mpt_scalar_reduce32(out, out);
            if (!secp256k1_ec_seckey_verify(ctx, out))
            {
                OPENSSL_cleanse(prk, 32);
                OPENSSL_cleanse(nonces_out, k * 32);
                return 0;
            }
            memcpy(nonces_out + i * 32, out, 32);
            memcpy(prev, out, 32);
            OPENSSL_cleanse(out, 32);
        }
    }

    OPENSSL_cleanse(salt, 32);
    OPENSSL_cleanse(prk, 32);
    return 1;
}

#endif /* MPT_INTERNAL_H */
