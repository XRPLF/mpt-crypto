/* SPDX-License-Identifier: MIT
 *
 * mpt_msm.c -- wrapper translation unit for the vendored
 * libsecp256k1 multi-scalar multiplication.
 *
 * This TU includes the vendored upstream headers (which contain
 * `static` definitions of the MSM and its supporting machinery)
 * and exposes a single external entry point: mpt_msm_variable_time.
 *
 * Because all upstream functions are file-local (static), the
 * vendored sources do not collide with any symbols in the linked
 * libsecp256k1 binary that the rest of mpt-crypto uses for the
 * public-API surface (tweak_mul, pubkey_combine, ecdh, etc.).
 *
 * See PROVENANCE for upstream version + commit hash and the
 * README for the threat model and design rationale.
 */

#define SECP256K1_BUILD

/* libsecp256k1 build-time configuration. The upstream library
 * picks the wide-multiplication strategy at compile time. We
 * mirror what its CMake build does: prefer __int128 if the
 * compiler supports it, otherwise fall back to 64x64->128
 * struct emulation. */
#if defined(__SIZEOF_INT128__)
#define SECP256K1_WIDEMUL_INT128 1
#else
#define SECP256K1_WIDEMUL_INT64 1
#endif

/* Disable runtime assertion macros that are normally driven by
 * libsecp256k1's autoconf. We treat the vendored MSM as a
 * release build. (VERIFY/CHECK still work for our internal use.) */
#define USE_NUM_NONE 1
#define USE_FIELD_INV_BUILTIN 1
#define USE_SCALAR_INV_BUILTIN 1

/* Match upstream's secp256k1.c include order. Order is significant:
 * ecmult_impl.h uses identifiers defined in group_impl.h, etc. Do
 * not let an autoformatter alphabetize this block. */
/* clang-format off */
#include <secp256k1.h>
#include "assumptions.h"
#include "checkmem.h"
#include "util.h"
#include "field_impl.h"
#include "scalar_impl.h"
#include "group_impl.h"
#include "int128_impl.h"
#include "ecmult_impl.h"
#include "scratch_impl.h"
/* clang-format on */

/* Public API. */
#include "mpt_msm.h"

/* ----- mpt_msm_variable_time -------------------------------- */

typedef struct
{
  mpt_msm_callback user_cb;
  void *user_data;
} mpt_msm_cb_state;

/* Adapter: parse SEC1-compressed bytes to internal secp256k1_ge,
 * and parse a 32-byte BE buffer to secp256k1_scalar. */

static int mpt_msm_parse_point(secp256k1_ge *elem,
                               unsigned char const sec1_33[33])
{
  secp256k1_fe x;
  if (sec1_33[0] != 0x02 && sec1_33[0] != 0x03)
    return 0;
  if (!secp256k1_fe_set_b32_limit(&x, sec1_33 + 1))
    return 0;
  return secp256k1_ge_set_xo_var(elem, &x, sec1_33[0] == 0x03);
}

static void mpt_msm_serialize_point(unsigned char out_sec1_33[33],
                                    secp256k1_ge const *elem)
{
  if (secp256k1_ge_is_infinity(elem))
  {
    memset(out_sec1_33, 0, 33);
    return;
  }
  secp256k1_fe x = elem->x;
  secp256k1_fe y = elem->y;
  secp256k1_fe_normalize_var(&x);
  secp256k1_fe_normalize_var(&y);
  out_sec1_33[0] = 0x02 | (secp256k1_fe_is_odd(&y) ? 1u : 0u);
  secp256k1_fe_get_b32(out_sec1_33 + 1, &x);
}

/* Adapter callback: pulls bytes from the user callback, parses to
 * internal types, and hands them to secp256k1_ecmult_multi_var. */
static int mpt_msm_internal_cb(secp256k1_scalar *sc, secp256k1_ge *pt,
                               size_t idx, void *data)
{
  mpt_msm_cb_state *state = (mpt_msm_cb_state *)data;
  unsigned char scalar_be32[32];
  unsigned char point_sec1_33[33];

  if (!state->user_cb(scalar_be32, point_sec1_33, idx, state->user_data))
  {
    return 0;
  }
  /* secp256k1_scalar_set_b32 sets *sc = bytes mod n; sets the
   * "overflow" flag if bytes >= n. We don't care about the flag
   * here -- we accept any 256-bit value as a valid scalar. */
  int overflow = 0;
  secp256k1_scalar_set_b32(sc, scalar_be32, &overflow);
  (void)overflow;

  if (!mpt_msm_parse_point(pt, point_sec1_33))
  {
    return 0;
  }
  return 1;
}

/* Default error callback for libsecp256k1 routines that take one. */
static void mpt_msm_default_error_cb(char const *str, void *data)
{
  (void)str;
  (void)data;
  /* Caller paths in libsecp256k1's MSM only invoke this on
   * out-of-memory inside scratch allocation; we surface as
   * a return value from mpt_msm_variable_time(). */
}
static const secp256k1_callback mpt_msm_error_cb = {mpt_msm_default_error_cb,
                                                    NULL};

SECP256K1_API int mpt_msm_variable_time(secp256k1_context const *ctx,
                                        unsigned char r_sec1_33[33],
                                        unsigned char const inp_g_sc_be32[32],
                                        mpt_msm_callback cb, void *cbdata,
                                        size_t n)
{
  (void)ctx; /* The vendored MSM doesn't need a context for the
              * variable-time path; it only reads precomputed
              * tables that live in static storage. We accept
              * the context for API parity with other mpt
              * functions. */

  if (r_sec1_33 == NULL)
    return 0;
  if (cb == NULL && n > 0)
    return 0;

  /* Allocate a scratch space sized for n points. The 100MB ceiling
   * is upstream's recommended cap for ecmult_multi_var; in
   * practice, the algorithm dynamically batches if scratch
   * is smaller than n. */
  size_t scratch_size =
      secp256k1_strauss_scratch_size(n) + STRAUSS_SCRATCH_OBJECTS * 16;
  /* Cap the scratch size; the algorithm will batch internally. */
  if (scratch_size > 100 * 1024 * 1024)
    scratch_size = 100 * 1024 * 1024;

  secp256k1_scratch *scratch =
      secp256k1_scratch_create(&mpt_msm_error_cb, scratch_size);
  if (scratch == NULL)
    return 0;

  /* Optional G coefficient. */
  secp256k1_scalar g_sc;
  secp256k1_scalar *g_sc_ptr = NULL;
  if (inp_g_sc_be32 != NULL)
  {
    int overflow = 0;
    secp256k1_scalar_set_b32(&g_sc, inp_g_sc_be32, &overflow);
    (void)overflow;
    g_sc_ptr = &g_sc;
  }

  mpt_msm_cb_state state = {cb, cbdata};

  secp256k1_gej r_jacobian;
  int ok = secp256k1_ecmult_multi_var(&mpt_msm_error_cb, scratch, &r_jacobian,
                                      g_sc_ptr, mpt_msm_internal_cb, &state, n);

  secp256k1_scratch_destroy(&mpt_msm_error_cb, scratch);

  if (!ok)
    return 0;

  /* Convert from Jacobian to affine and serialize. */
  secp256k1_ge r_affine;
  secp256k1_ge_set_gej(&r_affine, &r_jacobian);
  mpt_msm_serialize_point(r_sec1_33, &r_affine);

  return 1;
}
