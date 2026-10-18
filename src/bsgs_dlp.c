/**
 * @file bsgs_dlp.c
 * @brief Baby-Step Giant-Step discrete logarithm solver for EC-ElGamal
 * decryption.
 *
 * Implements secp256k1_elgamal_decrypt_bsgs(),
 * secp256k1_elgamal_decrypt_bsgs_parallel(), and the associated context
 * lifecycle. The algorithm is a standard BSGS with:
 *   - A cuckoo hash (k=3 sections) baby table for O(1) lookups, following
 *     Tang et al. (ePrint 2022/1573, https://eprint.iacr.org/2022/1573),
 *     who use a cuckoo hash (k=3) with Montgomery batch inversion.
 *   - A windowed variant of Montgomery batch inversion (TreeMon) to
 *     amortize field inversions across W giant steps, reducing cost from
 *     1 inversion/step to 1/W (our addition).
 *
 *   - Jacobian arithmetic throughout the giant-step loop to avoid per-step
 *     affine normalization (our addition).
 *   - Parallel giant-step search across T threads for faster decryption
 *     at larger bit sizes (our addition).
 *
 * Algorithm reference:
 *   Cenk, ElSheikh, Keskinkurt Paksoy, Hasan. "Scalable Small ECDLP Solver
 *   via Windowed-Batch Inversion for Additively Homomorphic Encryption."
 *   IACR ePrint 2026/2102. https://eprint.iacr.org/2026/2102
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
#include <pthread.h>
#include <stdatomic.h>
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
 * Mirrors libsecp256k1's internal pubkey_load().
 *
 * The sizeof(secp256k1_ge_storage) == 64 branch memcpy's pk->data directly into
 * a secp256k1_ge_storage, which assumes secp256k1_pubkey stores a ge_storage in
 * that layout — true for the pinned secp256k1 0.7.1 recipe. The assertion below
 * pins that assumption so a future secp bump changing either layout fails to
 * compile rather than silently corrupting points; the else branch remains a
 * portable fallback.
 *
 * Gated on a C11 or GNU-compatible compiler: MSVC's C mode does not recognise
 * the _Static_assert keyword. The pinned secp layout is identical across
 * platforms, so the clang/gcc CI builds enforce this for every target; MSVC
 * simply skips the compile-time check. */
#if (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) ||              \
    defined(__GNUC__)
_Static_assert(sizeof(secp256k1_ge_storage) != 64 ||
                   sizeof(secp256k1_pubkey) == 64,
               "secp256k1_pubkey vs ge_storage layout assumption broken "
               "(see pubkey_to_ge)");
#endif
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

/* =========================================================================
 * Windowed batch inversion
 *
 * fe_batch_invert_skewed_tree(): inverts n field elements using
 *   1 inversion + 3(n-1) multiplications (Montgomery's trick, tree form).
 *   Works for any arbitrary n >= 1.
 *
 * gej_xb32_from_zinv(): extract the affine x-coordinate as 32 bytes from
 *   a Jacobian point given its precomputed Z-inverse. No inversion needed —
 *   1 sqr + 1 mul.
 * ========================================================================= */

static void fe_batch_invert_skewed_tree(secp256k1_fe* z_inv,
                                   const secp256k1_fe* z,
                                   secp256k1_fe* scratch,
                                   size_t n) 
  {
    /* 1. Forward pass: scratch[i] = z[0] * ... * z[i] */
    scratch[0] = z[0];
    for (size_t i = 1; i < n; i++) 
    {
      secp256k1_fe_mul(&scratch[i], &scratch[i - 1], &z[i]);
    }

    /* 2. Single field inversion of the total product */
    secp256k1_fe acc;
    secp256k1_fe_inv(&acc, &scratch[n - 1]);

    /* 3. Backward pass: compute inverses and unwind accumulator */
    for (size_t i = n - 1; i > 0; i--) 
    {
      secp256k1_fe_mul(&z_inv[i], &scratch[i - 1], &acc);
      secp256k1_fe_mul(&acc, &acc, &z[i]);
    }

    /* Handle the first element */
    z_inv[0] = acc;
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
 *
 * The on-disk format is host-endian and struct-layout dependent — the header
 * fields and each entry_packed are written in native byte order — so cache
 * files are NOT portable across architectures or compilers. This is
 * intentional for the local single-machine use case. baby_load validates the
 * magic, version, and l1-derived section_size; any mismatch fails closed (the
 * table is rebuilt), so a foreign or corrupt cache never yields a wrong answer.
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

  /* Recompute the expected per-section size from l1 so a
   * corrupt-but-allocatable section_size that is inconsistent with l1 is
   * rejected, rather than loading a bogus table that causes silent decrypt
   * misses until the cache is rebuilt (never a wrong answer — verify_candidate
   * fails closed). Matches the derivation in cuckoo_alloc_build: ceil(1.3n/3) +
   * 2 with n = Mhalf = 2^(l1-1). s_expected stays 0 for an out-of-range l1,
   * which the check below rejects (also guarding the shift against a corrupt
   * header value). */
  uint64_t s_expected = 0;
  if (expected_l1 >= 1 && expected_l1 <= 32)
  {
    uint64_t n_expected = 1ULL << (expected_l1 - 1);
    s_expected = (n_expected * 13 + 29) / 30 + 2;
  }

  /* Reject a header whose stash_count is out of range: it is read from an
   * untrusted file and later used as the bound of a loop over the fixed-size
   * stash_xb[CUCKOO_STASH_SZ] / stash_val[CUCKOO_STASH_SZ] arrays, so a value
   * above CUCKOO_STASH_SZ (or negative) would cause an out-of-bounds read.
   * section_size must equal the value derived from l1 (this subsumes the old
   * section_size == 0 check). */
  if (hdr.magic != BABY_MAGIC || hdr.version != BABY_VERSION ||
      (int)hdr.l1 != expected_l1 || s_expected == 0 ||
      hdr.section_size != s_expected || hdr.stash_count < 0 ||
      hdr.stash_count > CUCKOO_STASH_SZ)
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
  /* Defensive / intentionally redundant: every caller already excludes m == 0
   * (the m1/m2 candidate checks in bsgs_solve require m in [1, max_m], and the
   * m == 0 plaintext is handled before the solver runs). Kept as a cheap guard
   * — m == 0 would make secp256k1_ec_pubkey_create fail regardless. */
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
 * Multi-threaded BSGS solver
 *
 * Runs the same giant-step search as bsgs_solve() (see its comment for the
 * 3-phase windowed loop and the m = j*M +/- i scheme) but splits the work
 * across N worker threads:
 *
 *   - j=0 is handled once, up front, on the calling thread: a direct baby
 *     lookup for Pm = i*G. Only the j >= 1 range is parallelized.
 *   - The giant-step range [1, J] is partitioned into N contiguous chunks
 *     (remainder spread one-per-thread across the first few workers). Each
 *     worker owns [j_start, j_end) and recomputes its own starting point
 *     Q = Pm - j_start*M*G, so the threads share no mutable solver state.
 *   - The baby table (b->baby) is read-only after context creation and is
 *     shared across all workers; the secp256k1 context is likewise shared.
 *     Each worker allocates its own O(W) Jacobian/field scratch buffers.
 *   - A shared atomic `found` flag gives early exit: every worker polls it
 *     and stops once any thread has a hit. The first writer wins under
 *     `found_mu`; because different j-chunks map to disjoint plaintexts there
 *     is at most one true solution, so the mutex only orders the store, it
 *     does not pick between competing answers.
 *
 * Falls back to bsgs_solve() when threads <= 1.
 * ========================================================================= */

typedef struct
{
  const secp256k1_elgamal_bsgs_ctx *b;
  secp256k1_pubkey targetPm;
  unsigned char target33[33];
  secp256k1_ge target_ge;
  uint64_t j_start;
  uint64_t j_end;
  int window;
  atomic_int *found;
  uint64_t *found_m;
  pthread_mutex_t *found_mu;
} bsgs_worker_args;


static inline void process_window(const secp256k1_context * restrict ctx, 
                                   size_t w_count, uint64_t max_m,
                                   uint64_t j_start, secp256k1_gej * restrict Qj,
                                   const secp256k1_elgamal_bsgs_ctx * restrict b,
                                   bsgs_worker_args * restrict a,
                                   secp256k1_gej * restrict Q_win,
                                   secp256k1_fe * restrict z,
                                   secp256k1_fe * restrict z_inv,
                                   secp256k1_fe * restrict scratch)
{
  for (size_t w = 0; w < w_count; w++) 
  {
    /* If Qj = Pm - jMG is the point at infinity, then Pm = jMG.
      * To avoid running batch inversion on the point at infinity,
      * compute m = j * M and return immediately. */
    if (secp256k1_gej_is_infinity(Qj)) 
    {
      uint64_t cand = (j_start + (uint64_t)w) * b->M;
      if (cand <= max_m)
      {
        pthread_mutex_lock(a->found_mu);
        if (!atomic_load_explicit(a->found, memory_order_relaxed)) 
        {
          *a->found_m = cand;
          atomic_store_explicit(a->found, 1, memory_order_relaxed);
        }
        pthread_mutex_unlock(a->found_mu);
        return;                           /* skip invert/lookup entirely */
      }                                   
    }
    Q_win[w] = *Qj;
    secp256k1_gej_add_ge_var(Qj, Qj, &b->neg_MG_ge, NULL);
  }

  for (size_t w = 0; w < w_count; w++) 
  {
    z[w] = Q_win[w].z;
    secp256k1_fe_normalize_var(&z[w]);
  }
  fe_batch_invert_skewed_tree(z_inv, z, scratch, w_count);

  for (size_t w = 0; w < w_count; w++) 
  {
    if (atomic_load_explicit(a->found, memory_order_relaxed)) return;

    uint64_t jM = (j_start + (uint64_t)w) * b->M;
    unsigned char qxb[32];
    gej_xb32_from_zinv(&Q_win[w], &z_inv[w], qxb);
    uint32_t cands[3 + CUCKOO_STASH_SZ];
    int nc = map_get_all(&b->baby, qxb, cands);
    for (int ci = 0; ci < nc; ci++) 
    {
      uint64_t m1 = jM + (uint64_t)cands[ci];
      uint64_t m2 = jM - (uint64_t)cands[ci];
      if (m1 <= max_m && verify_candidate(ctx, m1, a->target33))
      {
        pthread_mutex_lock(a->found_mu);
        if (!atomic_load_explicit(a->found, memory_order_relaxed))
        {
          *a->found_m = m1;
          atomic_store_explicit(a->found, 1, memory_order_relaxed);
        }
        pthread_mutex_unlock(a->found_mu);
        return;
      }
      else if (m2 >= 1 && m2 <= max_m &&
            verify_candidate(ctx, m2, a->target33))
      {
        pthread_mutex_lock(a->found_mu);
        if (!atomic_load_explicit(a->found, memory_order_relaxed))
        {
          *a->found_m = m2;
          atomic_store_explicit(a->found, 1, memory_order_relaxed);
        }
        pthread_mutex_unlock(a->found_mu);
        return;
      }            
    }
  }
}

static void *bsgs_worker_thread(void *argp)
{
  bsgs_worker_args *a = (bsgs_worker_args *)argp;
  const secp256k1_elgamal_bsgs_ctx *b = a->b;
  size_t W = (size_t)a->window; /* No power-of-2 constraint on W */
  const secp256k1_context *ctx = b->ctx;

  secp256k1_gej* Q_win   = (secp256k1_gej*)malloc(W * sizeof(secp256k1_gej));
  secp256k1_fe*  z       = (secp256k1_fe*) malloc(W * sizeof(secp256k1_fe));
  secp256k1_fe*  z_inv   = (secp256k1_fe*) malloc(W * sizeof(secp256k1_fe));
  secp256k1_fe*  scratch = (secp256k1_fe*) malloc(W * sizeof(secp256k1_fe));

  if (!Q_win || !z || !z_inv || !scratch)
  {
    free(Q_win);
    free(z);
    free(z_inv);
    free(scratch);
    return NULL;
  }

  uint64_t j = a->j_start;
  uint64_t total_steps = (a->j_end > j) ? (a->j_end - j) : 0;
  uint64_t full_loops  = total_steps / (uint64_t)W;
  size_t   rem         = (size_t)(total_steps % (uint64_t)W);
  
  /* Compute starting point: Q = Pm - j_start * M * G */
  unsigned char jm_sc[32];
  mpt_uint64_to_scalar(jm_sc, j * b->M);
  secp256k1_pubkey jMG_pub;
  if (!secp256k1_ec_pubkey_create(ctx, &jMG_pub, jm_sc))
  {
    free(Q_win);
    free(z);
    free(z_inv);
    free(scratch);
    return NULL;
  }

  secp256k1_ge jMG_ge, neg_jMG_ge;
  pubkey_to_ge(&jMG_pub, &jMG_ge);
  ge_negate(&neg_jMG_ge, &jMG_ge);

  secp256k1_gej Qj;
  pubkey_to_gej(&a->targetPm, &Qj);
  secp256k1_gej_add_ge_var(&Qj, &Qj, &neg_jMG_ge, NULL);

  uint64_t max_m =
      (b->bits_total < 64) ? ((1ULL << b->bits_total) - 1) : UINT64_MAX;

  /* ---- windowed main loop ---- */
  for (uint64_t l = 0; l < full_loops; l++) {
      if (atomic_load_explicit(a->found, memory_order_relaxed)) break;
      process_window(ctx, W, max_m, j, &Qj, b, a, Q_win, z, z_inv, scratch);
      j += (uint64_t)W;
  }
  /* ---- remaining steps (< W) ---- */
  if (rem > 0 && !atomic_load_explicit(a->found, memory_order_relaxed)) {
      process_window(ctx, rem, max_m, j, &Qj, b, a, Q_win, z, z_inv, scratch);
      j += (uint64_t)rem;
  }

  free(Q_win);
  free(z);
  free(z_inv);
  free(scratch);
  return NULL;
}
/* Forward declaration for bsgs_solve_parallel */
static int bsgs_solve(const secp256k1_elgamal_bsgs_ctx *b,
                      const secp256k1_pubkey *target_pm, int window,
                      uint64_t *out_m);

static int bsgs_solve_parallel(const secp256k1_elgamal_bsgs_ctx *b,
                               const secp256k1_pubkey *target_pm, int window,
                               int nthreads, uint64_t *out_m)
{
  if (nthreads <= 1)
    return bsgs_solve(b, target_pm, window, out_m);

  const secp256k1_context *ctx = b->ctx;

  /* Serialize target once */
  unsigned char t33[33];
  size_t t33_len = 33;
  if (!secp256k1_ec_pubkey_serialize(ctx, t33, &t33_len, target_pm,
                                     SECP256K1_EC_COMPRESSED) ||
      t33_len != 33)
    return 0;

  /* j=0: direct baby lookup for Pm = i*G */
  unsigned char txb[32];
  memcpy(txb, t33 + 1, 32);
  uint32_t cands[3 + CUCKOO_STASH_SZ];
  int nc = map_get_all(&b->baby, txb, cands);
  for (int ci = 0; ci < nc; ci++){
    if (verify_candidate(ctx, (uint64_t)cands[ci], t33))
    {
      *out_m = (uint64_t)cands[ci];
      return 1;
    }
  }

  uint64_t J = b->J;
  if (J <= 1)
    return 0;
  if ((uint64_t)nthreads > (J))
    nthreads = (int)(J);

  pthread_t *tids = (pthread_t *)calloc((size_t)nthreads, sizeof(pthread_t));
  bsgs_worker_args *args =
      (bsgs_worker_args *)calloc((size_t)nthreads, sizeof(bsgs_worker_args));
  if (!tids || !args)
  {
    free(tids);
    free(args);
    return 0;
  }

  atomic_int found = 0;
  uint64_t found_m = 0;
  pthread_mutex_t found_mu;
  pthread_mutex_init(&found_mu, NULL);

  secp256k1_ge target_ge;
  pubkey_to_ge(target_pm, &target_ge);

  uint64_t chunk = (J + (uint64_t)nthreads - 1)/(uint64_t)nthreads;
  uint64_t jcur = 1;

  for (int t = 0; t < nthreads; t++)
  {
    args[t].b = b;
    args[t].targetPm = *target_pm;
    memcpy(args[t].target33, t33, 33);
    args[t].target_ge = target_ge;
    args[t].j_start = jcur;
    args[t].j_end = jcur + chunk < J + 1 ?
                    jcur + chunk : J + 1 ; /* j_end is not included */
    args[t].window = window;
    args[t].found = &found;
    args[t].found_m = &found_m;
    args[t].found_mu = &found_mu;
    jcur += chunk;
    pthread_create(&tids[t], NULL, bsgs_worker_thread, &args[t]);
  }

  for (int t = 0; t < nthreads; t++)
    pthread_join(tids[t], NULL);

  int ok = atomic_load_explicit(&found, memory_order_relaxed);
  if (ok)
    *out_m = found_m;

  pthread_mutex_destroy(&found_mu);
  free(tids);
  free(args);
  return ok;
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

static inline void process_window_single_thread( size_t w_count, uint64_t max_m,
                                   uint64_t j_start, secp256k1_gej * restrict Qj,
                                   const secp256k1_elgamal_bsgs_ctx * restrict b,
                                   const unsigned char * restrict target33,
                                   int * restrict found,
                                   uint64_t* restrict out_m,
                                   secp256k1_gej * restrict Q_win,
                                   secp256k1_fe * restrict z,
                                   secp256k1_fe * restrict z_inv,
                                   secp256k1_fe * restrict scratch)
{
  for (size_t w = 0; w < w_count; w++) 
  {
    /* If Qj = Pm - jMG is the point at infinity, then Pm = jMG.
      * To avoid running batch inversion on the point at infinity,
      * compute m = j * M and return immediately. */
    if (secp256k1_gej_is_infinity(Qj)) 
    {
      uint64_t cand = (j_start + (uint64_t)w) * b->M;
      if (cand <= max_m)
      {
        *out_m = cand;
        *found = 1;
        return;     /* skip invert/lookup entirely */
      }                                 
    }
    Q_win[w] = *Qj;
    secp256k1_gej_add_ge_var(Qj, Qj, &b->neg_MG_ge, NULL);
  }

  for (size_t w = 0; w < w_count; w++) 
  {
    z[w] = Q_win[w].z;
    secp256k1_fe_normalize_var(&z[w]);
  }

  fe_batch_invert_skewed_tree(z_inv, z, scratch, w_count);

  for (size_t w = 0; w < w_count; w++) 
  {
    uint64_t jM = (j_start + (uint64_t)w) * b->M;
    unsigned char qxb[32];
    gej_xb32_from_zinv(&Q_win[w], &z_inv[w], qxb);
    uint32_t cands[3 + CUCKOO_STASH_SZ];
    int nc = map_get_all(&b->baby, qxb, cands);
    for (int ci = 0; ci < nc; ci++) 
    {
      uint64_t m1 = jM + (uint64_t)cands[ci];
      uint64_t m2 = jM - (uint64_t)cands[ci];
      if (m1 <= max_m && verify_candidate(b->ctx, m1, target33)) 
      { 
        *out_m = m1; 
        *found = 1; 
        return; 
      }
      else if (m2 >= 1 && m2 <= max_m && verify_candidate(b->ctx, m2, target33))
      { 
        *out_m = m2; 
        *found = 1; 
        return; 
      }
    }
  }
}

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
  secp256k1_gej_add_ge_var(&Qj, &Qj, &b->neg_MG_ge, NULL);

  /* No power-of-2 constraint on W */
  size_t W = (size_t)(window);

  secp256k1_gej* Q_win   = (secp256k1_gej*)malloc(W * sizeof(secp256k1_gej));
  secp256k1_fe*  z       = (secp256k1_fe*) malloc(W * sizeof(secp256k1_fe));
  secp256k1_fe*  z_inv   = (secp256k1_fe*) malloc(W * sizeof(secp256k1_fe));
  secp256k1_fe*  scratch = (secp256k1_fe*) malloc(W * sizeof(secp256k1_fe));


  if (!Q_win || !z || !z_inv || !scratch)
  {
    free(Q_win);
    free(z);
    free(z_inv);
    free(scratch);
    return 0;
  }

  uint64_t max_m =
      (b->bits_total < 64) ? ((1ULL << b->bits_total) - 1) : UINT64_MAX;
  
  uint64_t j = 1;
  uint64_t total_steps = b->J;
  uint64_t full_loops  = total_steps / (uint64_t)W;
  size_t   rem         = (size_t)(total_steps % (uint64_t)W);
  
  int found = 0;

  /* ---- windowed main loop ---- */
  for (uint64_t l = 0; l < full_loops; l++) {
      if (found) break;
      process_window_single_thread(W, max_m, j, &Qj, b, t33, &found, out_m, Q_win, z, z_inv, scratch);
      j += (uint64_t)W;
  }
  /* ---- remaining steps (< W) ---- */
  if (rem > 0 && !found) {
      process_window_single_thread(rem, max_m, j, &Qj, b, t33, &found, out_m, Q_win, z, z_inv, scratch);
      j += (uint64_t)rem;
  }

  free(Q_win);
  free(z);
  free(z_inv);
  free(scratch);
  return found;
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
/* =========================================================================
 * Public API — parallel decrypt
 * ========================================================================= */

int secp256k1_elgamal_decrypt_bsgs_parallel(
    const secp256k1_context *ctx, const secp256k1_elgamal_bsgs_ctx *bsgs_ctx,
    uint64_t *amount, const secp256k1_pubkey *c1, const secp256k1_pubkey *c2,
    const unsigned char *privkey, int window, int threads)
{
  MPT_ARG_CHECK(ctx != NULL);
  MPT_ARG_CHECK(bsgs_ctx != NULL);
  MPT_ARG_CHECK(amount != NULL);
  MPT_ARG_CHECK(c1 != NULL);
  MPT_ARG_CHECK(c2 != NULL);
  MPT_ARG_CHECK(privkey != NULL);

  if (window < 1 || window > MPT_BSGS_MAX_WINDOW)
    return 0;
  if (threads < 1)
    threads = 1;

  /* 1. Compute S = sk * C1. */
  secp256k1_pubkey S = *c1;
  if (!secp256k1_ec_pubkey_tweak_mul(ctx, &S, privkey))
    return 0;

  /* 2. Constant-time check for m=0: C2 == S means C2 - S = infinity. */
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

  /* 4. Solve M = m*G via parallel BSGS. */
  uint64_t recovered = 0;
  int found =
      bsgs_solve_parallel(bsgs_ctx, &M_target, window, threads, &recovered);

  if (found)
    *amount = recovered;

  return found;
}
