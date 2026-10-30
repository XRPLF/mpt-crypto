/* SPDX-License-Identifier: MIT
 *
 * mpt_msm.c -- wrapper around libsecp256k1's internal
 * multi-scalar multiplication (secp256k1_ecmult_multi_var).
 *
 * The MSM and its supporting machinery come from the internal
 * headers that the secp256k1 conan package exports under private/,
 * the same way mpt_scalar.c and bsgs_dlp.c use them. All upstream
 * functions are static, so the only external symbol here is
 * mpt_msm_variable_time.
 *
 * The G term reads the library's own precomputed tables
 * (secp256k1_pre_g, secp256k1_pre_g_128). These are hidden-visibility
 * symbols, so libsecp256k1 must be linked statically (the package
 * default).
 */

/* Must not exceed the window libsecp256k1 was built with, since the
 * precomputed G tables are sized by it. 15 is upstream's default and
 * the conan recipe does not override it. */
#define ECMULT_WINDOW_SIZE 15

/* Include order matches mpt_scalar.c and bsgs_dlp.c: low-level
 * utilities first. ecmult_impl.h uses identifiers from group_impl.h,
 * so do not let an autoformatter reorder this block. */
/* clang-format off */
#include <private/int128.h>
#include <private/int128_impl.h>
#include <private/util.h>
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
#endif
#include <private/field.h>
#include <private/field_impl.h>
#include <private/scalar.h>
#include <private/scalar_impl.h>
#include <private/group.h>
#include <private/group_impl.h>
#include <private/ecmult.h>
#include <private/ecmult_impl.h>
#include <private/scratch.h>
#include <private/scratch_impl.h>
#if defined(__clang__)
#pragma clang diagnostic pop
#endif
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
