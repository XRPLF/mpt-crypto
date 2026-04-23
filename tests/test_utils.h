#ifndef MPT_TEST_UTILS_H
#define MPT_TEST_UTILS_H

#include <openssl/rand.h>
#include <openssl/sha.h>

#include <secp256k1.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* --- Macro: Persistent Assertion --- */
/* Ensures checks run in both Debug and Release modes */
#define EXPECT(condition)                                                          \
    do                                                                             \
    {                                                                              \
        if (!(condition))                                                          \
        {                                                                          \
            fprintf(stderr, "TEST FAILED: %s at line %d\n", #condition, __LINE__); \
            abort();                                                               \
        }                                                                          \
    } while (0)

/* Helper: Generate 32 raw random bytes (for seeds, IDs, etc.) */
static inline void
random_bytes(unsigned char* out)
{
    EXPECT(RAND_bytes(out, 32) == 1);
}

/* Helper: Generate a valid random scalar using OpenSSL RNG. */
static inline void
random_scalar(secp256k1_context const* ctx, unsigned char* out)
{
    do
    {
        EXPECT(RAND_bytes(out, 32) == 1);
    } while (!secp256k1_ec_seckey_verify(ctx, out));
}

/* Helper: Encode uint64 as 32-byte big-endian scalar. */
static inline void
uint64_to_scalar32(unsigned char out[32], uint64_t v)
{
    memset(out, 0, 32);
    for (int i = 0; i < 8; i++)
        out[31 - i] = (v >> (i * 8)) & 0xFF;
}

/* Helper: Compute v*G. Returns 1 and writes *out on success; returns 0
 * when v == 0 (libsecp256k1's public API cannot emit the point at
 * infinity, so callers must skip the v*G term themselves). */
static inline int
value_times_g(secp256k1_context const* ctx, secp256k1_pubkey* out, uint64_t v)
{
    if (v == 0)
        return 0;
    unsigned char s[32];
    uint64_to_scalar32(s, v);
    int ok = secp256k1_ec_pubkey_create(ctx, out, s);
    memset(s, 0, sizeof(s));
    return ok;
}
#endif  // MPT_TEST_UTILS_H
