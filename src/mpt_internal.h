/**
 * @file mpt_internal.h
 * @brief Shared internal helpers for mpt-crypto source files.
 *
 * These are `static inline` utilities used across multiple translation units.
 * They are NOT part of the public API.
 */
#ifndef MPT_INTERNAL_H
#define MPT_INTERNAL_H

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

#endif /* MPT_INTERNAL_H */
