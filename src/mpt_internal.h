/**
 * @file mpt_internal.h
 * @brief Shared internal helpers for mpt-crypto source files.
 *
 * These are `static inline` utilities used across multiple translation units.
 * They are NOT part of the public API.
 */
#ifndef MPT_INTERNAL_H
#define MPT_INTERNAL_H

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <secp256k1.h>
#include <stdint.h>
#include <string.h>

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

#endif /* MPT_INTERNAL_H */
