/**
 * @file test_bsgs_dlp.c
 * @brief Tests for secp256k1_elgamal_decrypt_bsgs and the BSGS context
 * lifecycle.
 *
 * Test coverage:
 *   1. Context creation and destruction (no cache)
 *   2. Decrypt m=0 (constant-time early-exit path)
 *   3. Decrypt m=1 (first baby step, j=0 path)
 *   4. Decrypt a value within the first giant step (small i, j=0)
 *   5. Decrypt a value requiring giant steps (j > 0)
 *   6. Decrypt the maximum value for bits_total=28 (boundary)
 *   7. Decrypt fails gracefully for a value outside bits_total=28 range
 *   8. Round-trip: encrypt then decrypt_bsgs, verify recovered == original
 *   9. Cache save and load round-trip (baby table persists across contexts)
 *  10. NULL argument rejection
 *  11. Exhaustive coverage sweep over a small range (regression guard for
 *      baby-step index off-by-ones that drop odd multiples of 2^(l1-1))
 */
#include "bsgs_dlp.h"
#include "secp256k1_mpt.h"
#include "test_utils.h"
#include <secp256k1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Use small parameters so the test suite runs quickly.
 * bits_total=28, l1=15: baby table = 2^14 = 16384 entries (~128 KB),
 * giant steps = 2^13 = 8192. Covers amounts up to 2^28 = 268,435,456. */
#define TEST_BITS 28
#define TEST_L1 15
#define TEST_WINDOW MPT_BSGS_DEFAULT_WINDOW

/* Temporary cache path for the cache round-trip test. */
#define TEST_CACHE_PATH "/tmp/test_bsgs_baby_cache.bin"

/* Forward declarations */
static void test_ctx_create_destroy(const secp256k1_context *ctx);
static void test_decrypt_zero(const secp256k1_context *ctx,
                              secp256k1_elgamal_bsgs_ctx *bsgs);
static void test_decrypt_one(const secp256k1_context *ctx,
                             secp256k1_elgamal_bsgs_ctx *bsgs);
static void test_decrypt_small(const secp256k1_context *ctx,
                               secp256k1_elgamal_bsgs_ctx *bsgs);
static void test_decrypt_giant_step(const secp256k1_context *ctx,
                                    secp256k1_elgamal_bsgs_ctx *bsgs);
static void test_decrypt_boundary(const secp256k1_context *ctx,
                                  secp256k1_elgamal_bsgs_ctx *bsgs);
static void test_decrypt_out_of_range(const secp256k1_context *ctx,
                                      secp256k1_elgamal_bsgs_ctx *bsgs);
static void test_roundtrip(const secp256k1_context *ctx,
                           secp256k1_elgamal_bsgs_ctx *bsgs);
static void test_cache_roundtrip(const secp256k1_context *ctx);
static void test_null_rejection(const secp256k1_context *ctx,
                                secp256k1_elgamal_bsgs_ctx *bsgs);
static void test_decrypt_full_coverage(const secp256k1_context *ctx);

/* --- helpers --- */

static void encrypt_amount(const secp256k1_context *ctx, uint64_t amount,
                           const secp256k1_pubkey *pubkey, secp256k1_pubkey *c1,
                           secp256k1_pubkey *c2)
{
  unsigned char r[32];
  random_scalar(ctx, r);
  EXPECT(secp256k1_elgamal_encrypt(ctx, c1, c2, pubkey, amount, r) == 1);
}

/* --- main --- */

int main(void)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                    SECP256K1_CONTEXT_VERIFY);
  EXPECT(ctx != NULL);

  unsigned char seed[32];
  random_bytes(seed);
  EXPECT(secp256k1_context_randomize(ctx, seed) == 1);

  /* Tests that don't need a shared bsgs_ctx */
  test_ctx_create_destroy(ctx);
  test_cache_roundtrip(ctx);

  /* Build one shared context for the remaining tests — amortizes the
   * baby table build cost across all decrypt tests. */
  printf("Building BSGS context (bits=%d, l1=%d)...\n", TEST_BITS, TEST_L1);
  secp256k1_elgamal_bsgs_ctx *bsgs =
      secp256k1_elgamal_bsgs_ctx_create(ctx, TEST_BITS, TEST_L1, NULL);
  EXPECT(bsgs != NULL);
  printf("BSGS context ready.\n");

  test_null_rejection(ctx, bsgs);
  test_decrypt_zero(ctx, bsgs);
  test_decrypt_one(ctx, bsgs);
  test_decrypt_small(ctx, bsgs);
  test_decrypt_giant_step(ctx, bsgs);
  test_decrypt_boundary(ctx, bsgs);
  test_decrypt_out_of_range(ctx, bsgs);
  test_roundtrip(ctx, bsgs);
  test_decrypt_full_coverage(ctx);

  secp256k1_elgamal_bsgs_ctx_destroy(bsgs);
  secp256k1_context_destroy(ctx);

  printf("ALL TESTS PASSED\n");
  return 0;
}

/* --- test implementations --- */

static void test_ctx_create_destroy(const secp256k1_context *ctx)
{
  printf("Running test: context create/destroy...\n");

  /* Valid parameters */
  secp256k1_elgamal_bsgs_ctx *b =
      secp256k1_elgamal_bsgs_ctx_create(ctx, TEST_BITS, TEST_L1, NULL);
  EXPECT(b != NULL);
  secp256k1_elgamal_bsgs_ctx_destroy(b);

  /* NULL destroy is safe */
  secp256k1_elgamal_bsgs_ctx_destroy(NULL);

  /* Invalid parameters must return NULL */
  EXPECT(secp256k1_elgamal_bsgs_ctx_create(NULL, TEST_BITS, TEST_L1, NULL) ==
         NULL);
  EXPECT(secp256k1_elgamal_bsgs_ctx_create(ctx, 0, TEST_L1, NULL) == NULL);
  EXPECT(secp256k1_elgamal_bsgs_ctx_create(ctx, 64, TEST_L1, NULL) == NULL);
  EXPECT(secp256k1_elgamal_bsgs_ctx_create(ctx, TEST_BITS, 0, NULL) == NULL);
  EXPECT(secp256k1_elgamal_bsgs_ctx_create(ctx, TEST_BITS, TEST_BITS, NULL) ==
         NULL);

  printf("Test passed!\n");
}

static void test_decrypt_zero(const secp256k1_context *ctx,
                              secp256k1_elgamal_bsgs_ctx *bsgs)
{
  printf("Running test: decrypt m=0 (early-exit path)...\n");

  unsigned char privkey[32];
  secp256k1_pubkey pubkey, c1, c2;
  EXPECT(secp256k1_elgamal_generate_keypair(ctx, privkey, &pubkey) == 1);

  encrypt_amount(ctx, 0, &pubkey, &c1, &c2);

  uint64_t recovered = 0xDEADBEEFu;
  EXPECT(secp256k1_elgamal_decrypt_bsgs(ctx, bsgs, &recovered, &c1, &c2,
                                        privkey, TEST_WINDOW) == 1);
  EXPECT(recovered == 0);

  printf("Test passed!\n");
}

static void test_decrypt_one(const secp256k1_context *ctx,
                             secp256k1_elgamal_bsgs_ctx *bsgs)
{
  printf("Running test: decrypt m=1 (first baby step)...\n");

  unsigned char privkey[32];
  secp256k1_pubkey pubkey, c1, c2;
  EXPECT(secp256k1_elgamal_generate_keypair(ctx, privkey, &pubkey) == 1);

  encrypt_amount(ctx, 1, &pubkey, &c1, &c2);

  uint64_t recovered = 0xDEADBEEFu;
  EXPECT(secp256k1_elgamal_decrypt_bsgs(ctx, bsgs, &recovered, &c1, &c2,
                                        privkey, TEST_WINDOW) == 1);
  EXPECT(recovered == 1);

  printf("Test passed!\n");
}

static void test_decrypt_small(const secp256k1_context *ctx,
                               secp256k1_elgamal_bsgs_ctx *bsgs)
{
  printf("Running test: decrypt small values (j=0 giant step)...\n");

  unsigned char privkey[32];
  secp256k1_pubkey pubkey, c1, c2;
  EXPECT(secp256k1_elgamal_generate_keypair(ctx, privkey, &pubkey) == 1);

  /* Several values within the first giant step (< M = 2^l1) */
  uint64_t amounts[] = {2, 100, 1000, 10000, 100000};
  for (size_t i = 0; i < sizeof(amounts) / sizeof(amounts[0]); i++)
  {
    encrypt_amount(ctx, amounts[i], &pubkey, &c1, &c2);
    uint64_t recovered = 0xDEADBEEFu;
    EXPECT(secp256k1_elgamal_decrypt_bsgs(ctx, bsgs, &recovered, &c1, &c2,
                                          privkey, TEST_WINDOW) == 1);
    EXPECT(recovered == amounts[i]);
  }

  printf("Test passed!\n");
}

static void test_decrypt_giant_step(const secp256k1_context *ctx,
                                    secp256k1_elgamal_bsgs_ctx *bsgs)
{
  printf("Running test: decrypt values requiring giant steps (j > 0)...\n");

  unsigned char privkey[32];
  secp256k1_pubkey pubkey, c1, c2;
  EXPECT(secp256k1_elgamal_generate_keypair(ctx, privkey, &pubkey) == 1);

  /* Values well above M = 2^TEST_L1 = 32768 — must exercise j > 0 path */
  uint64_t amounts[] = {
      (1ULL << TEST_L1) + 1,         /* j=1, i=1   */
      (1ULL << TEST_L1) * 3 + 7,     /* j=3, i=7   */
      (1ULL << TEST_L1) * 100 + 999, /* j=100      */
      (1ULL << (TEST_BITS - 2)),     /* mid-range  */
  };

  for (size_t i = 0; i < sizeof(amounts) / sizeof(amounts[0]); i++)
  {
    encrypt_amount(ctx, amounts[i], &pubkey, &c1, &c2);
    uint64_t recovered = 0xDEADBEEFu;
    EXPECT(secp256k1_elgamal_decrypt_bsgs(ctx, bsgs, &recovered, &c1, &c2,
                                          privkey, TEST_WINDOW) == 1);
    EXPECT(recovered == amounts[i]);
  }

  printf("Test passed!\n");
}

static void test_decrypt_boundary(const secp256k1_context *ctx,
                                  secp256k1_elgamal_bsgs_ctx *bsgs)
{
  printf("Running test: decrypt at maximum range boundary (2^%d - 1)...\n",
         TEST_BITS);

  unsigned char privkey[32];
  secp256k1_pubkey pubkey, c1, c2;
  EXPECT(secp256k1_elgamal_generate_keypair(ctx, privkey, &pubkey) == 1);

  uint64_t max_amount = (1ULL << TEST_BITS) - 1;
  encrypt_amount(ctx, max_amount, &pubkey, &c1, &c2);

  uint64_t recovered = 0xDEADBEEFu;
  EXPECT(secp256k1_elgamal_decrypt_bsgs(ctx, bsgs, &recovered, &c1, &c2,
                                        privkey, TEST_WINDOW) == 1);
  EXPECT(recovered == max_amount);

  printf("Test passed!\n");
}

static void test_decrypt_out_of_range(const secp256k1_context *ctx,
                                      secp256k1_elgamal_bsgs_ctx *bsgs)
{
  printf("Running test: decrypt out-of-range value fails gracefully...\n");

  unsigned char privkey[32];
  secp256k1_pubkey pubkey, c1, c2;
  EXPECT(secp256k1_elgamal_generate_keypair(ctx, privkey, &pubkey) == 1);

  /* Encrypt a value just outside bits_total range */
  uint64_t out_of_range = (1ULL << TEST_BITS) + 1;
  encrypt_amount(ctx, out_of_range, &pubkey, &c1, &c2);

  uint64_t recovered = 0xDEADBEEFu;
  EXPECT(secp256k1_elgamal_decrypt_bsgs(ctx, bsgs, &recovered, &c1, &c2,
                                        privkey, TEST_WINDOW) == 0);

  /* m = 2^bits_total = J*M lands exactly on the i=0 direct-hit path at j=J;
   * it is one past the range and must be rejected, not reported as found. */
  uint64_t direct_oor = (1ULL << TEST_BITS);
  encrypt_amount(ctx, direct_oor, &pubkey, &c1, &c2);
  recovered = 0xDEADBEEFu;
  EXPECT(secp256k1_elgamal_decrypt_bsgs(ctx, bsgs, &recovered, &c1, &c2,
                                        privkey, TEST_WINDOW) == 0);

  printf("Test passed!\n");
}

static void test_roundtrip(const secp256k1_context *ctx,
                           secp256k1_elgamal_bsgs_ctx *bsgs)
{
  printf("Running test: encrypt/decrypt_bsgs round-trip (random amounts)...\n");

  unsigned char privkey[32];
  secp256k1_pubkey pubkey, c1, c2;
  EXPECT(secp256k1_elgamal_generate_keypair(ctx, privkey, &pubkey) == 1);

  /* A spread of random-ish values across the range */
  uint64_t amounts[] = {
      1, 42, 1337, 999999, (1ULL << 20) + 13, (1ULL << 24) - 1,
  };

  for (size_t i = 0; i < sizeof(amounts) / sizeof(amounts[0]); i++)
  {
    encrypt_amount(ctx, amounts[i], &pubkey, &c1, &c2);
    uint64_t recovered = 0xDEADBEEFu;
    EXPECT(secp256k1_elgamal_decrypt_bsgs(ctx, bsgs, &recovered, &c1, &c2,
                                          privkey, TEST_WINDOW) == 1);
    EXPECT(recovered == amounts[i]);
  }

  printf("Test passed!\n");
}

static void test_cache_roundtrip(const secp256k1_context *ctx)
{
  printf("Running test: baby table cache save/load round-trip...\n");

  /* Remove any stale cache file */
  remove(TEST_CACHE_PATH);

  /* Build and save */
  secp256k1_elgamal_bsgs_ctx *b1 = secp256k1_elgamal_bsgs_ctx_create(
      ctx, TEST_BITS, TEST_L1, TEST_CACHE_PATH);
  EXPECT(b1 != NULL);

  /* Encrypt and decrypt with the freshly built context */
  unsigned char privkey[32];
  secp256k1_pubkey pubkey, c1, c2;
  EXPECT(secp256k1_elgamal_generate_keypair(ctx, privkey, &pubkey) == 1);
  uint64_t amount = 12345;
  encrypt_amount(ctx, amount, &pubkey, &c1, &c2);
  uint64_t recovered = 0;
  EXPECT(secp256k1_elgamal_decrypt_bsgs(ctx, b1, &recovered, &c1, &c2, privkey,
                                        TEST_WINDOW) == 1);
  EXPECT(recovered == amount);
  secp256k1_elgamal_bsgs_ctx_destroy(b1);

  /* Load from cache */
  secp256k1_elgamal_bsgs_ctx *b2 = secp256k1_elgamal_bsgs_ctx_create(
      ctx, TEST_BITS, TEST_L1, TEST_CACHE_PATH);
  EXPECT(b2 != NULL);

  /* Decrypt the same ciphertext with the loaded context */
  recovered = 0xDEADBEEFu;
  EXPECT(secp256k1_elgamal_decrypt_bsgs(ctx, b2, &recovered, &c1, &c2, privkey,
                                        TEST_WINDOW) == 1);
  EXPECT(recovered == amount);
  secp256k1_elgamal_bsgs_ctx_destroy(b2);

  /* Clean up cache file */
  remove(TEST_CACHE_PATH);

  printf("Test passed!\n");
}

/* Exhaustively decrypt every m in [0, 2^SWEEP_BITS) with a small dedicated
 * context. Guards against coverage gaps in the baby-step/giant-step index
 * scheme. A prior off-by-one (baby range [1, Mhalf) instead of [1, Mhalf])
 * left every odd multiple of Mhalf = 2^(l1-1) unrecoverable; a hand-picked
 * value list missed it, but a full sweep cannot.
 *
 * Mhalf = 2^(SWEEP_L1-1) = 32, so odd multiples 32, 96, ... fall in range;
 * J = 2^(SWEEP_BITS-SWEEP_L1) = 64 giant steps.
 *
 * The sweep is repeated across several window sizes. This matters because
 * the solver takes different code paths depending on W vs J:
 *   - W >= J  (e.g. the default 128): windowed loop never fires, tail only.
 *   - W <  J  (e.g. 8): full windowed batches exercise fe_batch_invert_tree.
 *   - W == 1: single-element batch-inversion tree (degenerate edge case).
 * Without the small-window passes the windowed TreeMon path is untested. */
#define SWEEP_BITS 12
#define SWEEP_L1 6
static void test_decrypt_full_coverage(const secp256k1_context *ctx)
{
  printf("Running test: exhaustive coverage sweep [0, 2^%d)...\n", SWEEP_BITS);

  secp256k1_elgamal_bsgs_ctx *b =
      secp256k1_elgamal_bsgs_ctx_create(ctx, SWEEP_BITS, SWEEP_L1, NULL);
  EXPECT(b != NULL);

  unsigned char privkey[32];
  secp256k1_pubkey pubkey, c1, c2;
  EXPECT(secp256k1_elgamal_generate_keypair(ctx, privkey, &pubkey) == 1);

  /* J = 2^(SWEEP_BITS-SWEEP_L1) = 64; windows below/at/above J cover all
   * paths (tail-only, windowed, and the W=1 single-element tree). */
  int windows[] = {MPT_BSGS_DEFAULT_WINDOW, 8, 1};
  uint64_t limit = 1ULL << SWEEP_BITS;

  for (size_t wi = 0; wi < sizeof(windows) / sizeof(windows[0]); wi++)
  {
    int window = windows[wi];
    printf("  window=%d...\n", window);
    for (uint64_t m = 0; m < limit; m++)
    {
      encrypt_amount(ctx, m, &pubkey, &c1, &c2);
      uint64_t recovered = 0xDEADBEEFu;
      int ok = secp256k1_elgamal_decrypt_bsgs(ctx, b, &recovered, &c1, &c2,
                                              privkey, window);
      if (ok != 1 || recovered != m)
      {
        printf("  FAILED at m=%llu (window=%d): ok=%d recovered=%llu\n",
               (unsigned long long)m, window, ok,
               (unsigned long long)recovered);
        EXPECT(0);
      }
    }
  }

  secp256k1_elgamal_bsgs_ctx_destroy(b);
  printf("Test passed!\n");
}

static void test_null_rejection(const secp256k1_context *ctx,
                                secp256k1_elgamal_bsgs_ctx *bsgs)
{
  printf("Running test: NULL argument rejection...\n");

  unsigned char privkey[32];
  secp256k1_pubkey pubkey, c1, c2;
  EXPECT(secp256k1_elgamal_generate_keypair(ctx, privkey, &pubkey) == 1);
  encrypt_amount(ctx, 1, &pubkey, &c1, &c2);

  uint64_t out = 0;

  EXPECT(secp256k1_elgamal_decrypt_bsgs(NULL, bsgs, &out, &c1, &c2, privkey,
                                        TEST_WINDOW) == 0);
  EXPECT(secp256k1_elgamal_decrypt_bsgs(ctx, NULL, &out, &c1, &c2, privkey,
                                        TEST_WINDOW) == 0);
  EXPECT(secp256k1_elgamal_decrypt_bsgs(ctx, bsgs, NULL, &c1, &c2, privkey,
                                        TEST_WINDOW) == 0);
  EXPECT(secp256k1_elgamal_decrypt_bsgs(ctx, bsgs, &out, NULL, &c2, privkey,
                                        TEST_WINDOW) == 0);
  EXPECT(secp256k1_elgamal_decrypt_bsgs(ctx, bsgs, &out, &c1, NULL, privkey,
                                        TEST_WINDOW) == 0);
  EXPECT(secp256k1_elgamal_decrypt_bsgs(ctx, bsgs, &out, &c1, &c2, NULL,
                                        TEST_WINDOW) == 0);

  printf("Test passed!\n");
}
