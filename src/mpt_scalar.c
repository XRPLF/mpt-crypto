#include "secp256k1_mpt.h"
#include <string.h>

/* 1. Backend Configuration Definitions */
#ifndef USE_SCALAR_8X32
#define USE_SCALAR_8X32
#endif
#ifndef USE_FIELD_10X26
#define USE_FIELD_10X26
#endif

/* 2. Include low-level utilities first.
      On ARM64/Apple Silicon, the scalar math depends on 128-bit
      integer helpers defined in these headers. */
#include "util.h"
#include "int128.h"
#include "int128_impl.h"

/* 3. Include the actual scalar implementations */
#include "scalar.h"
#include "scalar_impl.h"

/* --- Implementation --- */

void secp256k1_mpt_scalar_add(unsigned char *res, const unsigned char *a, const unsigned char *b) {
    secp256k1_scalar s_res, s_a, s_b;
    secp256k1_scalar_set_b32(&s_a, a, NULL);
    secp256k1_scalar_set_b32(&s_b, b, NULL);
    secp256k1_scalar_add(&s_res, &s_a, &s_b);
    secp256k1_scalar_get_b32(res, &s_res);
}

void secp256k1_mpt_scalar_mul(unsigned char *res, const unsigned char *a, const unsigned char *b) {
    secp256k1_scalar s_res, s_a, s_b;
    secp256k1_scalar_set_b32(&s_a, a, NULL);
    secp256k1_scalar_set_b32(&s_b, b, NULL);
    secp256k1_scalar_mul(&s_res, &s_a, &s_b);
    secp256k1_scalar_get_b32(res, &s_res);
}

void secp256k1_mpt_scalar_inverse(unsigned char *res, const unsigned char *in) {
    secp256k1_scalar s;
    secp256k1_scalar_set_b32(&s, in, NULL);
    secp256k1_scalar_inverse(&s, &s);
    secp256k1_scalar_get_b32(res, &s);
}

void secp256k1_mpt_scalar_negate(unsigned char *res, const unsigned char *in) {
    secp256k1_scalar s;
    secp256k1_scalar_set_b32(&s, in, NULL);
    secp256k1_scalar_negate(&s, &s);
    secp256k1_scalar_get_b32(res, &s);
}

void secp256k1_mpt_scalar_reduce32(unsigned char out32[32], const unsigned char in32[32]) {
    secp256k1_scalar s;
    secp256k1_scalar_set_b32(&s, in32, NULL);
    secp256k1_scalar_get_b32(out32, &s);
}
