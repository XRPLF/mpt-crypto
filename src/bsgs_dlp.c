/**
 * @file bsgs_dlp.c
 * @brief Baby-Step Giant-Step discrete logarithm solver for EC-ElGamal
 * decryption.
 *
 * Implements secp256k1_elgamal_decrypt_bsgs() and the associated context
 * lifecycle. The algorithm is a standard BSGS with:
 *   - A cuckoo hash (k=3 sections) baby table for O(1) lookups, following
 *     Tang et al. (ePrint 2022/1573, https://eprint.iacr.org/2022/1573),
 *     who use a cuckoo hash (k=3) with Montgomery batch inversion.
 *   - A windowed variant of Montgomery batch inversion (TreeMon) to
 *     amortize field inversions across W giant steps, reducing cost from
 *     1 inversion/step to 1/W (our addition).
 *   - Jacobian arithmetic throughout the giant-step loop to avoid per-step
 *     affine normalization (our addition).
 *
 * Internal secp256k1 headers are included following the pattern established
 * in mpt_scalar.c. This is the only translation unit that includes them;
 * do not include group_impl.h or field_impl.h elsewhere in mpt-crypto to
 * avoid duplicate symbol errors.
 *
 * @see include/bsgs_dlp.h for the public API and parameter documentation.
 */

#include "bsgs_dlp.h"
#include "mpt_internal.h"

#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* =========================================================================
 * Internal secp256k1 headers
 *
 * Required for Jacobian arithmetic (secp256k1_gej, secp256k1_ge) and
 * field operations (secp256k1_fe) used in the giant-step loop.
 * Include order matches mpt_scalar.c: low-level utilities first.
 * ========================================================================= */
#include <private/int128.h>
#include <private/int128_impl.h>
#include <private/util.h>
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
#endif
#include <private/field.h>
#include <private/field_impl.h>
#include <private/group.h>
#include <private/group_impl.h>
#if defined(__clang__)
#pragma clang diagnostic pop
#endif

/* =========================================================================
 * Jacobian / affine helpers
 *
 * Thin wrappers over libsecp256k1's internal field/group primitives. They
 * are static — not exported — so there is no symbol conflict with any other
 * translation unit.
 * ========================================================================= */

/* Load a secp256k1_pubkey into an affine secp256k1_ge.
 * Mirrors libsecp256k1's internal pubkey_load(). */
static void pubkey_to_ge(const secp256k1_pubkey *pk, secp256k1_ge *ge)
{
  if (sizeof(secp256k1_ge_storage) == 64)
  {
    secp256k1_ge_storage s;
    memcpy(&s, &pk->data[0], sizeof(s));
    secp256k1_ge_from_storage(ge, &s);
  }
  else
  {
    secp256k1_fe x, y;
    secp256k1_fe_set_b32_mod(&x, pk->data);
    secp256k1_fe_set_b32_mod(&y, pk->data + 32);
    secp256k1_ge_set_xy(ge, &x, &y);
  }
}

/* Load a secp256k1_pubkey as a Jacobian point with z=1. */
static void pubkey_to_gej(const secp256k1_pubkey *pk, secp256k1_gej *gej)
{
  secp256k1_ge ge;
  pubkey_to_ge(pk, &ge);
  secp256k1_gej_set_ge(gej, &ge);
}

/* Negate an affine point in-place (flip y). */
static void ge_negate(secp256k1_ge *out, const secp256k1_ge *in)
{
  *out = *in;
  secp256k1_fe_negate(&out->y, &out->y, 1);
  secp256k1_fe_normalize_var(&out->y);
}

/* Extract the full 32-byte x-coordinate (big-endian) from an affine point. */
static void ge_xb32(const secp256k1_ge *ge, unsigned char buf[32])
{
  secp256k1_fe x = ge->x;
  secp256k1_fe_normalize_var(&x);
  secp256k1_fe_get_b32(buf, &x);
}

/*
 * Check Jacobian point a == affine point b WITHOUT field inversion.
 *
 * a = (X:Y:Z) Jacobian, b = (x,y) affine.
 * Equal iff X == x*Z^2  AND  Y == y*Z^3  (mod p).
 * Cost: 1 sqr + 2 mul + 2 normalise + 2 compare.
 */
static int gej_eq_ge(const secp256k1_gej *a, const secp256k1_ge *b)
{
  secp256k1_fe z2, z3, u, s, ax, ay;
  if (a->infinity)
    return b->infinity;
  if (b->infinity)
    return 0;

  secp256k1_fe_sqr(&z2, &a->z);
  secp256k1_fe_mul(&z3, &z2, &a->z);

  secp256k1_fe_mul(&u, &b->x, &z2);
  ax = a->x;
  secp256k1_fe_normalize_var(&ax);
  secp256k1_fe_normalize_var(&u);
  if (!secp256k1_fe_equal(&ax, &u))
    return 0;

  secp256k1_fe_mul(&s, &b->y, &z3);
  ay = a->y;
  secp256k1_fe_normalize_var(&ay);
  secp256k1_fe_normalize_var(&s);
  return secp256k1_fe_equal(&ay, &s);
}

/* =========================================================================
 * Windowed TreeMon batch inversion
 *
 * fe_batch_invert_tree(): inverts n field elements using
 *   1 inversion + 3(n-1) multiplications (Montgomery's trick, tree form).
 *   n must be a power of 2.
 *   bt1/bt2 are level-order binary trees of size 2n
 *   (bt1[n..2n-1] = inputs; bt2[n..2n-1] = 1/inputs after the call).
 *
 * gej_xb32_from_zinv(): extract the affine x-coordinate as 32 bytes from
 *   a Jacobian point given its precomputed Z-inverse. No inversion needed —
 *   1 sqr + 1 mul.
 * ========================================================================= */

static void fe_batch_invert_tree(secp256k1_fe *bt1, secp256k1_fe *bt2, size_t n)
{
  for (size_t i = n - 1; i >= 1; i--)
    secp256k1_fe_mul(&bt1[i], &bt1[2 * i], &bt1[2 * i + 1]);
  secp256k1_fe_inv(&bt2[1], &bt1[1]);
  for (size_t i = 1; i < n; i++)
  {
    secp256k1_fe_mul(&bt2[2 * i], &bt1[2 * i + 1], &bt2[i]);
    secp256k1_fe_mul(&bt2[2 * i + 1], &bt1[2 * i], &bt2[i]);
  }
}

static void gej_xb32_from_zinv(const secp256k1_gej *pt,
                               const secp256k1_fe *z_inv, unsigned char buf[32])
{
  secp256k1_fe z2, x;
  secp256k1_fe_sqr(&z2, z_inv);
  secp256k1_fe_mul(&x, &pt->x, &z2);
  secp256k1_fe_normalize_var(&x);
  secp256k1_fe_get_b32(buf, &x);
}

/* =========================================================================
 * Cuckoo hash table (k=3 sections, load factor ~1.3×)
 *
 * Design (Tang et al., "Solving Hard Problems in BSGS Using Windowed
 * Cuckoo Hashing", ePrint 2022/1573, https://eprint.iacr.org/2022/1573):
 *   - 3 hash functions map the x-coordinate into 3 disjoint sections.
 *   - Each section uses an independent 8-byte window of the x-coordinate:
 *       4 bytes for the bin position, 4 bytes as a per-section fingerprint.
 *   - Lookup: exactly 3 probes + stash scan — O(1) worst case.
 *   - Build: two-pass (positions first, keys second) using a 12-byte
 *     build_entry that compacts to an 8-byte entry_packed after build.
 *
 * False-positive probability per probe: 1/2^32.
 * map_get_all() collects ALL matching candidates to handle false positives
 * correctly; verify_candidate() does the definitive check.
 * ========================================================================= */

#define CUCKOO_K 3
#define CUCKOO_MAX_RELOC 512
#define CUCKOO_STASH_SZ 16

/* 8-byte lookup entry kept in memory after build. */
typedef struct
{
  uint32_t key; /* per-section 4-byte fingerprint */
  uint32_t val; /* i value; 0 = empty             */
} entry_packed;

/* 12-byte build entry used only during table construction.
 * Keys are NOT stored here; they are filled in a second pass after
 * compaction by re-walking the i*G sequence. */
typedef struct
{
  uint32_t pos[3]; /* position within each section (offset from section base) */
  uint32_t val;    /* i value; 0 = empty */
} build_entry;

/* Cuckoo map (lookup phase, after compaction). */
typedef struct
{
  entry_packed *tab;
  size_t section_size;
  size_t total_bins;
  size_t size;
  unsigned char stash_xb[CUCKOO_STASH_SZ][32];
  uint32_t stash_val[CUCKOO_STASH_SZ];
  int stash_count;
} cuckoo_map;

/* ---- hash helpers ---- */

static inline uint32_t u32be(const unsigned char *b)
{
  return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
         ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}

/* Bin position within section sec for a given x-coordinate. */
static inline size_t cpos(int sec, const unsigned char xb[32], size_t s)
{
  uint32_t h = u32be(xb + sec * 8);
#if defined(__SIZEOF_INT128__)
  return (size_t)((__uint128_t)h * (__uint128_t)s >> 32) + (size_t)sec * s;
#else
  /* Portable 32x64 multiply: floor(h * s / 2^32) without __uint128_t. */
  uint64_t lo = (uint64_t)h * (uint64_t)(uint32_t)s;
  uint64_t hi = (uint64_t)h * (uint64_t)(uint32_t)(s >> 32);
  return (size_t)((lo >> 32) + hi) + (size_t)sec * s;
#endif
}

/* Per-section fingerprint key. */
static inline uint32_t ckey(int sec, const unsigned char xb[32])
{
  return u32be(xb + sec * 8 + 4);
}

/* ---- lookup ---- */

/*
 * Collect ALL candidates matching xb across the 3 sections and stash.
 * Returns the number of candidates found (0 = definite miss).
 * out[] must have room for at least (3 + CUCKOO_STASH_SZ) uint32_t.
 */
static int map_get_all(const cuckoo_map *m, const unsigned char xb[32],
                       uint32_t *out)
{
  size_t s = m->section_size;
  int n = 0;

  const entry_packed *e;
  e = &m->tab[cpos(0, xb, s)];
  if (e->val && e->key == ckey(0, xb))
    out[n++] = e->val;
  e = &m->tab[cpos(1, xb, s)];
  if (e->val && e->key == ckey(1, xb))
    out[n++] = e->val;
  e = &m->tab[cpos(2, xb, s)];
  if (e->val && e->key == ckey(2, xb))
    out[n++] = e->val;

  for (int i = 0; i < m->stash_count; i++)
    if (memcmp(m->stash_xb[i], xb, 32) == 0)
      out[n++] = m->stash_val[i];

  return n;
}

/* ---- build ---- */

static int cuckoo_insert_build(build_entry *btab, size_t s, cuckoo_map *m,
                               const unsigned char xb[32], uint32_t val)
{
  build_entry cur;
  for (int k = 0; k < CUCKOO_K; k++)
    cur.pos[k] = (uint32_t)(cpos(k, xb, s) - (size_t)k * s);
  cur.val = val;
  int sec = 0;

  for (int iter = 0; iter < CUCKOO_MAX_RELOC; iter++)
  {
    size_t pos = (size_t)cur.pos[sec] + (size_t)sec * s;
    if (btab[pos].val == 0)
    {
      btab[pos] = cur;
      m->size++;
      return 1;
    }
    build_entry ev = btab[pos];
    btab[pos] = cur;
    cur = ev;
    sec = (sec + 1) % CUCKOO_K;
  }

  /* Eviction chain too long — fall back to stash. */
  if (m->stash_count < CUCKOO_STASH_SZ)
  {
    memset(m->stash_xb[m->stash_count], 0, 32);
    m->stash_val[m->stash_count] = cur.val;
    m->stash_count++;
    m->size++;
    return 1;
  }
  return 0;
}

static build_entry *cuckoo_alloc_build(cuckoo_map *m, size_t n)
{
  memset(m, 0, sizeof(*m));
  size_t s = (n * 13 + 29) / 30 + 2; /* ceil(1.3n/3) */
  size_t total = CUCKOO_K * s;

  build_entry *btab = (build_entry *)calloc(total, sizeof(build_entry));
  if (!btab)
    return NULL;

  m->section_size = s;
  m->total_bins = total;
  return btab;
}

static int cuckoo_compact(cuckoo_map *m, build_entry *btab)
{
  size_t total = m->total_bins;
  m->tab = (entry_packed *)calloc(total, sizeof(entry_packed));
  if (!m->tab)
  {
    free(btab);
    return 0;
  }
  for (size_t i = 0; i < total; i++)
    m->tab[i].val = btab[i].val;
  free(btab);
  return 1;
}

static void cuckoo_map_free(cuckoo_map *m)
{
  free(m->tab);
  memset(m, 0, sizeof(*m));
}

/* =========================================================================
 * Baby table cache file I/O
 * ========================================================================= */

#define BABY_MAGIC 0x4B43554B4F4F4355ULL /* "UCOOKUCK" — cuckoo format v4 */
#define BABY_VERSION 4

typedef struct
{
  uint64_t magic;
  uint32_t version;
  uint32_t l1;
  uint64_t section_size;
  uint64_t used_count;
  int32_t stash_count;
  uint32_t _pad;
} baby_hdr;

static int baby_save(const char *path, int l1, const cuckoo_map *baby)
{
  FILE *f = fopen(path, "wb");
  if (!f)
    return 0;

  baby_hdr hdr;
  memset(&hdr, 0, sizeof(hdr));
  hdr.magic = BABY_MAGIC;
  hdr.version = BABY_VERSION;
  hdr.l1 = (uint32_t)l1;
  hdr.section_size = (uint64_t)baby->section_size;
  hdr.used_count = (uint64_t)baby->size;
  hdr.stash_count = (int32_t)baby->stash_count;

  int ok = (fwrite(&hdr, sizeof(hdr), 1, f) == 1);
  ok &= (fwrite(baby->stash_xb, sizeof(baby->stash_xb), 1, f) == 1);
  ok &= (fwrite(baby->stash_val, sizeof(baby->stash_val), 1, f) == 1);
  ok &= (fwrite(baby->tab, sizeof(entry_packed), baby->total_bins, f) ==
         baby->total_bins);

  fclose(f);
  return ok;
}

static int baby_load(const char *path, int expected_l1, cuckoo_map *baby_out)
{
  FILE *f = fopen(path, "rb");
  if (!f)
    return 0;

  baby_hdr hdr;
  if (fread(&hdr, sizeof(hdr), 1, f) != 1)
  {
    fclose(f);
    return 0;
  }

  /* Reject a header whose stash_count is out of range: it is read from an
   * untrusted file and later used as the bound of a loop over the fixed-size
   * stash_xb[CUCKOO_STASH_SZ] / stash_val[CUCKOO_STASH_SZ] arrays, so a value
   * above CUCKOO_STASH_SZ (or negative) would cause an out-of-bounds read. */
  if (hdr.magic != BABY_MAGIC || hdr.version != BABY_VERSION ||
      (int)hdr.l1 != expected_l1 || hdr.section_size == 0 ||
      hdr.stash_count < 0 || hdr.stash_count > CUCKOO_STASH_SZ)
  {
    fclose(f);
    return 0;
  }

  memset(baby_out, 0, sizeof(*baby_out));
  baby_out->section_size = (size_t)hdr.section_size;
  baby_out->total_bins = CUCKOO_K * (size_t)hdr.section_size;
  baby_out->size = (size_t)hdr.used_count;
  baby_out->stash_count = (int)hdr.stash_count;

  if (fread(baby_out->stash_xb, sizeof(baby_out->stash_xb), 1, f) != 1 ||
      fread(baby_out->stash_val, sizeof(baby_out->stash_val), 1, f) != 1)
  {
    fclose(f);
    return 0;
  }

  baby_out->tab =
      (entry_packed *)calloc(baby_out->total_bins, sizeof(entry_packed));
  if (!baby_out->tab)
  {
    fclose(f);
    return 0;
  }

  if (fread(baby_out->tab, sizeof(entry_packed), baby_out->total_bins, f) !=
      baby_out->total_bins)
  {
    free(baby_out->tab);
    baby_out->tab = NULL;
    fclose(f);
    return 0;
  }

  fclose(f);
  return 1;
}

/* =========================================================================
 * BSGS context (concrete definition — opaque in the public header)
 * ========================================================================= */

struct secp256k1_elgamal_bsgs_ctx
{
  const secp256k1_context *ctx; /* non-owning; caller manages lifetime */
  int bits_total;
  int l1;
  uint64_t M;     /* baby-step stride: 2^l1          */
  uint64_t Mhalf; /* baby table size:  2^(l1-1)      */
  uint64_t J;     /* giant-step count: 2^(bits-l1)   */

  secp256k1_pubkey G;     /* generator point        */
  secp256k1_pubkey MG;    /* M*G = stride point     */
  secp256k1_ge MG_ge;     /* affine form of M*G     */
  secp256k1_ge neg_MG_ge; /* affine form of -(M*G)  */

  cuckoo_map baby; /* baby-step hash table   */
};

/* =========================================================================
 * Candidate verification
 *
 * Recomputes m*G from scratch and compares to the serialized target.
 * Called at most once per solve on a true match (or a false positive).
 * ========================================================================= */

static int verify_candidate(const secp256k1_context *ctx, uint64_t m,
                            const unsigned char target33[33])
{
  if (m == 0)
    return 0;

  unsigned char sc[32];
  mpt_uint64_to_scalar(sc, m);

  secp256k1_pubkey chk;
  if (!secp256k1_ec_pubkey_create(ctx, &chk, sc))
  {
    OPENSSL_cleanse(sc, sizeof(sc));
    return 0;
  }
  OPENSSL_cleanse(sc, sizeof(sc));

  unsigned char c33[33];
  size_t len = 33;
  if (!secp256k1_ec_pubkey_serialize(ctx, c33, &len, &chk,
                                     SECP256K1_EC_COMPRESSED) ||
      len != 33)
    return 0;

  return CRYPTO_memcmp(c33, target33, 33) == 0;
}

/* =========================================================================
 * Public API — context lifecycle
 * ========================================================================= */

secp256k1_elgamal_bsgs_ctx *
secp256k1_elgamal_bsgs_ctx_create(const secp256k1_context *ctx, int bits_total,
                                  int l1, const char *cache_path)
{
  if (!ctx)
    return NULL;
  if (bits_total <= 0 || bits_total > 63)
    return NULL;
  if (l1 <= 0 || l1 >= bits_total)
    return NULL;
  /* Baby values i in [1, 2^(l1-1)] are stored in a uint32_t; l1 > 32 would
   * overflow that field (2^32 wraps to 0, the empty-slot sentinel). Such a
   * table would also require >32 GB, but reject explicitly rather than rely
   * on the allocation failing. */
  if (l1 > 32)
    return NULL;

  secp256k1_elgamal_bsgs_ctx *b =
      (secp256k1_elgamal_bsgs_ctx *)calloc(1, sizeof(*b));
  if (!b)
    return NULL;

  b->ctx = ctx;
  b->bits_total = bits_total;
  b->l1 = l1;
  b->M = 1ULL << l1;
  b->Mhalf = 1ULL << (l1 - 1);
  b->J = 1ULL << (bits_total - l1);

  /* Compute G (1*G) */
  unsigned char one[32] = {0};
  one[31] = 1;
  if (!secp256k1_ec_pubkey_create(ctx, &b->G, one))
    goto fail;

  /* Compute MG (M*G = stride point for giant steps) */
  unsigned char Msc[32];
  mpt_uint64_to_scalar(Msc, b->M);
  if (!secp256k1_ec_pubkey_create(ctx, &b->MG, Msc))
  {
    OPENSSL_cleanse(Msc, sizeof(Msc));
    goto fail;
  }
  OPENSSL_cleanse(Msc, sizeof(Msc));

  pubkey_to_ge(&b->MG, &b->MG_ge);
  ge_negate(&b->neg_MG_ge, &b->MG_ge);

  /* Try loading baby table from cache */
  if (cache_path && baby_load(cache_path, l1, &b->baby))
    return b;

  /* Build baby table — two-pass cuckoo construction.
   *
   * Pass 1: walk i*G for i in [1, Mhalf], insert (positions, val=i)
   *         into the 12-byte build table. Keys not stored yet.
   * Compact: allocate 8-byte packed table, copy vals only.
   * Pass 2: re-walk i*G, fill per-section fingerprint keys and stash xb[].
   *
   * The range is inclusive of Mhalf. With giant stride M = 2*Mhalf and the
   * negation shortcut, giant step j covers [j*M - i, j*M + i] for baby i.
   * Stopping at i = Mhalf-1 leaves each window one short of the midpoint
   * j*M + Mhalf, so every odd multiple of Mhalf would be unrecoverable.
   * Including i = Mhalf makes adjacent windows meet at those midpoints.
   */
  {
    size_t n = (size_t)b->Mhalf;
    build_entry *btab = cuckoo_alloc_build(&b->baby, n);
    if (!btab)
      goto fail;

    size_t s = b->baby.section_size;
    secp256k1_pubkey cur = b->G;
    unsigned char ser[33];
    size_t ser_len;

    /* Pass 1 */
    for (uint64_t i = 1; i <= b->Mhalf; i++)
    {
      ser_len = 33;
      if (!secp256k1_ec_pubkey_serialize(ctx, ser, &ser_len, &cur,
                                         SECP256K1_EC_COMPRESSED) ||
          ser_len != 33)
      {
        free(btab);
        goto fail;
      }

      unsigned char xb[32];
      memcpy(xb, ser + 1, 32);

      if (!cuckoo_insert_build(btab, s, &b->baby, xb, (uint32_t)i))
      {
        free(btab);
        goto fail;
      }

      if (i + 1 <= b->Mhalf)
      {
        const secp256k1_pubkey *pts[2] = {&cur, &b->G};
        secp256k1_pubkey nxt;
        if (!secp256k1_ec_pubkey_combine(ctx, &nxt, pts, 2))
        {
          free(btab);
          goto fail;
        }
        cur = nxt;
      }
    }

    /* Compact: vals only; keys filled in Pass 2 */
    if (!cuckoo_compact(&b->baby, btab))
      goto fail;

    /* Pass 2 */
    cur = b->G;
    for (uint64_t i = 1; i <= b->Mhalf; i++)
    {
      ser_len = 33;
      if (!secp256k1_ec_pubkey_serialize(ctx, ser, &ser_len, &cur,
                                         SECP256K1_EC_COMPRESSED) ||
          ser_len != 33)
        goto fail;

      unsigned char xb[32];
      memcpy(xb, ser + 1, 32);

      for (int sec = 0; sec < CUCKOO_K; sec++)
      {
        size_t pos = cpos(sec, xb, s);
        if (b->baby.tab[pos].val == (uint32_t)i)
          b->baby.tab[pos].key = ckey(sec, xb);
      }
      for (int si = 0; si < b->baby.stash_count; si++)
      {
        if (b->baby.stash_val[si] == (uint32_t)i)
          memcpy(b->baby.stash_xb[si], xb, 32);
      }

      if (i + 1 <= b->Mhalf)
      {
        const secp256k1_pubkey *pts[2] = {&cur, &b->G};
        secp256k1_pubkey nxt;
        if (!secp256k1_ec_pubkey_combine(ctx, &nxt, pts, 2))
          goto fail;
        cur = nxt;
      }
    }
  }

  /* Save to cache if a path was provided */
  if (cache_path)
    baby_save(cache_path, l1, &b->baby); /* non-fatal on failure */

  return b;

fail:
  cuckoo_map_free(&b->baby);
  free(b);
  return NULL;
}

void secp256k1_elgamal_bsgs_ctx_destroy(secp256k1_elgamal_bsgs_ctx *bsgs_ctx)
{
  if (!bsgs_ctx)
    return;
  cuckoo_map_free(&bsgs_ctx->baby);
  memset(bsgs_ctx, 0, sizeof(*bsgs_ctx));
  free(bsgs_ctx);
}

/* =========================================================================
 * Single-threaded BSGS solver
 *
 * 3-phase windowed loop:
 *   Phase 1: accumulate W Jacobian Q points, check direct j*MG == target
 *            — 0 inversions.
 *   Phase 2: batch invert W Z-coordinates via TreeMon — 1 inversion total.
 *   Phase 3: extract x64 from z_inv, cuckoo lookup, verify candidates
 *            — 0 inversions.
 *
 * Inversions per step: 1/W  (vs 1 per step without TreeMon).
 *
 * Giant step Q = target - j*MG.  A match occurs when Q == i*G for some
 * baby i, giving m = j*M + i  (or j*M - i for the negation shortcut).
 * ========================================================================= */

static int bsgs_solve(const secp256k1_elgamal_bsgs_ctx *b,
                      const secp256k1_pubkey *target_pm, int window,
                      uint64_t *out_m)
{
  const secp256k1_context *ctx = b->ctx;

  /* Serialize target once for verify_candidate() calls. */
  unsigned char t33[33];
  size_t t33_len = 33;
  if (!secp256k1_ec_pubkey_serialize(ctx, t33, &t33_len, target_pm,
                                     SECP256K1_EC_COMPRESSED) ||
      t33_len != 33)
    return 0;

  /* j=0 check: target itself is a baby entry (m = i, giant step = 0). */
  {
    unsigned char txb[32];
    memcpy(txb, t33 + 1, 32);
    uint32_t cands[CUCKOO_K + CUCKOO_STASH_SZ];
    int nc = map_get_all(&b->baby, txb, cands);
    for (int ci = 0; ci < nc; ci++)
    {
      if (verify_candidate(ctx, (uint64_t)cands[ci], t33))
      {
        *out_m = (uint64_t)cands[ci];
        return 1;
      }
    }
  }

  secp256k1_ge target_ge;
  pubkey_to_ge(target_pm, &target_ge);

  /* Qj = target - 1*MG (Q for first giant step j=1) */
  secp256k1_gej Qj;
  pubkey_to_gej(target_pm, &Qj);
  secp256k1_gej_add_ge(&Qj, &Qj, &b->neg_MG_ge);

  /* jMGj tracks j*MG in Jacobian for the direct equality check. */
  secp256k1_gej jMGj;
  secp256k1_gej_set_ge(&jMGj, &b->MG_ge);

  /* Ensure window is at least 1 and a power of 2. */
  size_t W = (size_t)(window < 1 ? 1 : window);
  {
    size_t w = 1;
    while (w < W)
      w <<= 1;
    W = w;
  }

  secp256k1_gej *Q_win = (secp256k1_gej *)malloc(W * sizeof(secp256k1_gej));
  uint64_t *j_win = (uint64_t *)malloc(W * sizeof(uint64_t));
  secp256k1_fe *bt1 = (secp256k1_fe *)malloc(2 * W * sizeof(secp256k1_fe));
  secp256k1_fe *bt2 = (secp256k1_fe *)malloc(2 * W * sizeof(secp256k1_fe));

  if (!Q_win || !j_win || !bt1 || !bt2)
  {
    free(Q_win);
    free(j_win);
    free(bt1);
    free(bt2);
    return 0;
  }

  uint64_t max_m =
      (b->bits_total < 64) ? ((1ULL << b->bits_total) - 1) : UINT64_MAX;
  int result = 0;
  uint64_t j = 1;

  /* Windowed main loop — full W-sized batches. */
  while (j + (uint64_t)W <= b->J + 1 && !result)
  {
    for (size_t w = 0; w < W; w++)
    {
      /* Direct check: j*MG == target → m = j*M (baby i = 0). A direct hit
       * uniquely determines m; Qj is the point at infinity here and must not
       * reach batch inversion, so resolve the range check and return now.
       * m = j*M out of range (only possible at j = J, m = 2^bits_total)
       * means the plaintext is out of range: report not-found. */
      if (gej_eq_ge(&jMGj, &target_ge))
      {
        uint64_t cand = (j + (uint64_t)w) * b->M;
        if (cand <= max_m)
        {
          *out_m = cand;
          result = 1;
        }
        free(Q_win);
        free(j_win);
        free(bt1);
        free(bt2);
        return result;
      }
      Q_win[w] = Qj;
      j_win[w] = j + (uint64_t)w;
      secp256k1_gej_add_ge(&Qj, &Qj, &b->neg_MG_ge);
      secp256k1_gej_add_ge(&jMGj, &jMGj, &b->MG_ge);
    }
    j += (uint64_t)W;

    /* Batch invert W Z-coordinates. */
    for (size_t w = 0; w < W; w++)
    {
      bt1[W + w] = Q_win[w].z;
      secp256k1_fe_normalize_var(&bt1[W + w]);
    }
    fe_batch_invert_tree(bt1, bt2, W);

    /* Lookup phase. */
    for (size_t w = 0; w < W && !result; w++)
    {
      unsigned char qxb[32];
      gej_xb32_from_zinv(&Q_win[w], &bt2[W + w], qxb);

      uint32_t cands[CUCKOO_K + CUCKOO_STASH_SZ];
      int nc = map_get_all(&b->baby, qxb, cands);
      for (int ci = 0; ci < nc && !result; ci++)
      {
        uint64_t m1 = j_win[w] * b->M + (uint64_t)cands[ci];
        uint64_t m2 = j_win[w] * b->M - (uint64_t)cands[ci];
        if (m1 <= max_m && verify_candidate(ctx, m1, t33))
        {
          *out_m = m1;
          result = 1;
        }
        else if (m2 >= 1 && m2 <= max_m && verify_candidate(ctx, m2, t33))
        {
          *out_m = m2;
          result = 1;
        }
      }
    }
  }

  /* Tail loop — remaining steps that don't fill a full window. */
  for (; j <= b->J && !result; j++)
  {
    if (gej_eq_ge(&jMGj, &target_ge))
    {
      uint64_t cand = j * b->M;
      if (cand <= max_m)
      {
        *out_m = cand;
        result = 1;
      }
      break;
    }

    secp256k1_ge Q_ge;
    secp256k1_ge_set_gej(&Q_ge, &Qj);

    unsigned char qxb[32];
    ge_xb32(&Q_ge, qxb);

    uint32_t cands[CUCKOO_K + CUCKOO_STASH_SZ];
    int nc = map_get_all(&b->baby, qxb, cands);
    for (int ci = 0; ci < nc && !result; ci++)
    {
      uint64_t m1 = j * b->M + (uint64_t)cands[ci];
      uint64_t m2 = j * b->M - (uint64_t)cands[ci];
      if (m1 <= max_m && verify_candidate(ctx, m1, t33))
      {
        *out_m = m1;
        result = 1;
      }
      else if (m2 >= 1 && m2 <= max_m && verify_candidate(ctx, m2, t33))
      {
        *out_m = m2;
        result = 1;
      }
    }

    if (!result)
    {
      secp256k1_gej_add_ge(&Qj, &Qj, &b->neg_MG_ge);
      secp256k1_gej_add_ge(&jMGj, &jMGj, &b->MG_ge);
    }
  }

  free(Q_win);
  free(j_win);
  free(bt1);
  free(bt2);
  return result;
}

/* =========================================================================
 * Public API — decrypt
 * ========================================================================= */

int secp256k1_elgamal_decrypt_bsgs(const secp256k1_context *ctx,
                                   const secp256k1_elgamal_bsgs_ctx *bsgs_ctx,
                                   uint64_t *amount, const secp256k1_pubkey *c1,
                                   const secp256k1_pubkey *c2,
                                   const unsigned char *privkey, int window)
{
  MPT_ARG_CHECK(ctx != NULL);
  MPT_ARG_CHECK(bsgs_ctx != NULL);
  MPT_ARG_CHECK(amount != NULL);
  MPT_ARG_CHECK(c1 != NULL);
  MPT_ARG_CHECK(c2 != NULL);
  MPT_ARG_CHECK(privkey != NULL);

  /* Validate window before the solver allocates O(window) points/field
   * elements. Reject non-positive values (previously silently clamped to 1)
   * and values above MPT_BSGS_MAX_WINDOW (which would risk overflow in the
   * allocation-size computation). */
  if (window < 1 || window > MPT_BSGS_MAX_WINDOW)
    return 0;

  if (!secp256k1_ec_seckey_verify(ctx, privkey))
    return 0;

  /* 1. Recover shared secret S = privkey * C1. */
  secp256k1_pubkey S = *c1;
  if (!mpt_ct_pubkey_tweak_mul(ctx, &S, privkey))
    return 0;

  /* 2. Constant-time check for m=0: C2 == S means C2 - S = infinity.
   *    The BSGS solver cannot accept the point at infinity as input,
   *    so we must detect and handle this case before calling it. */
  unsigned char c2_ser[33], S_ser[33];
  size_t ser_len = 33;

  if (!secp256k1_ec_pubkey_serialize(ctx, c2_ser, &ser_len, c2,
                                     SECP256K1_EC_COMPRESSED) ||
      ser_len != 33)
    return 0;

  ser_len = 33;
  if (!secp256k1_ec_pubkey_serialize(ctx, S_ser, &ser_len, &S,
                                     SECP256K1_EC_COMPRESSED) ||
      ser_len != 33)
  {
    OPENSSL_cleanse(c2_ser, sizeof(c2_ser));
    return 0;
  }

  if (CRYPTO_memcmp(c2_ser, S_ser, 33) == 0)
  {
    *amount = 0;
    OPENSSL_cleanse(c2_ser, sizeof(c2_ser));
    OPENSSL_cleanse(S_ser, sizeof(S_ser));
    return 1;
  }

  OPENSSL_cleanse(c2_ser, sizeof(c2_ser));
  OPENSSL_cleanse(S_ser, sizeof(S_ser));

  /* 3. Compute M = C2 - S = C2 + (-S). */
  secp256k1_pubkey neg_S = S;
  if (!secp256k1_ec_pubkey_negate(ctx, &neg_S))
    return 0;

  secp256k1_pubkey M_target;
  const secp256k1_pubkey *pts[2] = {c2, &neg_S};
  if (!secp256k1_ec_pubkey_combine(ctx, &M_target, pts, 2))
    return 0;

  /* 4. Solve M = m*G via BSGS. */
  uint64_t recovered = 0;
  int found = bsgs_solve(bsgs_ctx, &M_target, window, &recovered);

  if (found)
    *amount = recovered;

  return found;
}
