#include "secp256k1_mpt.h"
#include "test_utils.h"
#include <secp256k1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Forward declarations for all test functions
static void test_key_generation(const secp256k1_context *ctx);
static void test_encryption(const secp256k1_context *ctx);
static void test_encryption_decryption_roundtrip(const secp256k1_context *ctx);
static void test_homomorphic_operations(const secp256k1_context *ctx);
static void test_zero_encryption(const secp256k1_context *ctx);
static void test_canonical_zero(const secp256k1_context *ctx);
static void test_verify_encryption(const secp256k1_context *ctx);
static void test_decryption_boundaries(const secp256k1_context *ctx);

// Main test runner
int main(void)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                    SECP256K1_CONTEXT_VERIFY);
  EXPECT(ctx != NULL);

  unsigned char seed[32];
  EXPECT(RAND_bytes(seed, sizeof(seed)) == 1);
  EXPECT(secp256k1_context_randomize(ctx, seed) == 1);

  test_key_generation(ctx);
  test_encryption(ctx);
  test_encryption_decryption_roundtrip(ctx);
  test_homomorphic_operations(ctx);
  test_zero_encryption(ctx);
  test_canonical_zero(ctx);
  test_verify_encryption(ctx);
  test_decryption_boundaries(ctx);

  secp256k1_context_destroy(ctx);
  printf("ALL TESTS PASSED\n");
  return 0;
}

// --- Test Implementations ---

static void test_key_generation(const secp256k1_context *ctx)
{
  unsigned char privkey[32];
  secp256k1_pubkey pubkey;
  printf("Running test: secp256k1_elgamal_generate_keypair...\n");
  EXPECT(secp256k1_elgamal_generate_keypair(ctx, privkey, &pubkey) == 1);
  printf("Test passed!\n");
}

static void test_encryption(const secp256k1_context *ctx)
{
  unsigned char privkey[32], blinding_factor[32];
  secp256k1_pubkey pubkey, c1, c2, temp_pubkey;
  printf("Running test: secp256k1_elgamal_encrypt (smoke test)...\n");
  EXPECT(secp256k1_elgamal_generate_keypair(ctx, privkey, &pubkey) == 1);
  EXPECT(secp256k1_elgamal_generate_keypair(ctx, blinding_factor,
                                            &temp_pubkey) == 1);
  EXPECT(secp256k1_elgamal_encrypt(ctx, &c1, &c2, &pubkey, 12345,
                                   blinding_factor) == 1);
  printf("Test passed!\n");
}

static void test_encryption_decryption_roundtrip(const secp256k1_context *ctx)
{
  unsigned char privkey[32], blinding_factor[32];
  secp256k1_pubkey pubkey, c1, c2, temp_pubkey;
  uint64_t original_amount = 1001;
  uint64_t decrypted_amount = 0;
  printf("Running test: encryption-decryption round trip...\n");
  EXPECT(secp256k1_elgamal_generate_keypair(ctx, privkey, &pubkey) == 1);
  EXPECT(secp256k1_elgamal_generate_keypair(ctx, blinding_factor,
                                            &temp_pubkey) == 1);
  EXPECT(secp256k1_elgamal_encrypt(ctx, &c1, &c2, &pubkey, original_amount,
                                   blinding_factor) == 1);
  EXPECT(secp256k1_elgamal_decrypt(ctx, &decrypted_amount, &c1, &c2, privkey, 0,
                                   2000) == 1);
  EXPECT(original_amount == decrypted_amount);
  printf("Test passed!\n");
}

static void test_homomorphic_operations(const secp256k1_context *ctx)
{
  unsigned char privkey[32];
  secp256k1_pubkey pubkey;
  uint64_t amount_a = 1000, amount_b = 500;
  secp256k1_pubkey a_c1, a_c2, b_c1, b_c2, result_c1, result_c2;
  uint64_t decrypted_result;

  printf("Running test: homomorphic operations...\n");
  EXPECT(secp256k1_elgamal_generate_keypair(ctx, privkey, &pubkey) == 1);

  {
    unsigned char k_a[32];
    secp256k1_pubkey temp_pubkey;
    EXPECT(secp256k1_elgamal_generate_keypair(ctx, k_a, &temp_pubkey) == 1);
    EXPECT(secp256k1_elgamal_encrypt(ctx, &a_c1, &a_c2, &pubkey, amount_a,
                                     k_a) == 1);
  }
  {
    unsigned char k_b[32];
    secp256k1_pubkey temp_pubkey;
    EXPECT(secp256k1_elgamal_generate_keypair(ctx, k_b, &temp_pubkey) == 1);
    EXPECT(secp256k1_elgamal_encrypt(ctx, &b_c1, &b_c2, &pubkey, amount_b,
                                     k_b) == 1);
  }

  EXPECT(secp256k1_elgamal_add(ctx, &result_c1, &result_c2, &a_c1, &a_c2, &b_c1,
                               &b_c2) == 1);
  EXPECT(secp256k1_elgamal_decrypt(ctx, &decrypted_result, &result_c1,
                                   &result_c2, privkey, 0, 2000) == 1);
  EXPECT(decrypted_result == amount_a + amount_b);

  EXPECT(secp256k1_elgamal_subtract(ctx, &result_c1, &result_c2, &a_c1, &a_c2,
                                    &b_c1, &b_c2) == 1);
  EXPECT(secp256k1_elgamal_decrypt(ctx, &decrypted_result, &result_c1,
                                   &result_c2, privkey, 0, 2000) == 1);
  EXPECT(decrypted_result == amount_a - amount_b);
  printf("Test passed!\n");
}

static void test_zero_encryption(const secp256k1_context *ctx)
{
  unsigned char privkey[32], blinding_factor[32];
  secp256k1_pubkey pubkey, c1, c2, temp_pubkey;
  uint64_t original_amount = 0;
  uint64_t decrypted_amount = 999;
  printf("Running test: encrypting a random zero...\n");
  EXPECT(secp256k1_elgamal_generate_keypair(ctx, privkey, &pubkey) == 1);
  EXPECT(secp256k1_elgamal_generate_keypair(ctx, blinding_factor,
                                            &temp_pubkey) == 1);
  EXPECT(secp256k1_elgamal_encrypt(ctx, &c1, &c2, &pubkey, original_amount,
                                   blinding_factor) == 1);
  EXPECT(secp256k1_elgamal_decrypt(ctx, &decrypted_amount, &c1, &c2, privkey, 0,
                                   2000) == 1);
  EXPECT(original_amount == decrypted_amount);
  printf("Test passed!\n");
}

static void test_canonical_zero(const secp256k1_context *ctx)
{
  unsigned char privkey[32];
  secp256k1_pubkey pubkey;
  secp256k1_pubkey c1_a, c2_a, c1_b, c2_b;
  uint64_t decrypted_amount = 999;

  unsigned char account_id[20] = {1};
  unsigned char issuance_id[24] = {2};

  printf("Running test: canonical encrypted zero...\n");
  EXPECT(secp256k1_elgamal_generate_keypair(ctx, privkey, &pubkey) == 1);

  EXPECT(generate_canonical_encrypted_zero(ctx, &c1_a, &c2_a, &pubkey,
                                           account_id, issuance_id) == 1);
  EXPECT(generate_canonical_encrypted_zero(ctx, &c1_b, &c2_b, &pubkey,
                                           account_id, issuance_id) == 1);

  /* 1. Verify that it decrypts to zero */
  EXPECT(secp256k1_elgamal_decrypt(ctx, &decrypted_amount, &c1_a, &c2_a,
                                   privkey, 0, 2000) == 1);
  EXPECT(decrypted_amount == 0);

  /* 2. Verify determinism */
  EXPECT(memcmp(&c1_a, &c1_b, sizeof(c1_a)) == 0);
  EXPECT(memcmp(&c2_a, &c2_b, sizeof(c2_a)) == 0);

  printf("Test passed!\n");
}

static void test_verify_encryption(const secp256k1_context *ctx)
{
  unsigned char privkey[32], blinding_factor[32];
  secp256k1_pubkey pubkey, c1, c2, temp_pubkey;
  uint64_t amount = 1500;
  uint64_t zero_amount = 0;

  printf("Running test: secp256k1_elgamal_verify_encryption...\n");
  EXPECT(secp256k1_elgamal_generate_keypair(ctx, privkey, &pubkey) == 1);
  EXPECT(secp256k1_elgamal_generate_keypair(ctx, blinding_factor,
                                            &temp_pubkey) == 1);

  /* 1. Test standard encryption verification */
  EXPECT(secp256k1_elgamal_encrypt(ctx, &c1, &c2, &pubkey, amount,
                                   blinding_factor) == 1);
  EXPECT(secp256k1_elgamal_verify_encryption(ctx, &c1, &c2, &pubkey, amount,
                                             blinding_factor) == 1);

  /* 2. Test zero-value encryption verification */
  EXPECT(secp256k1_elgamal_encrypt(ctx, &c1, &c2, &pubkey, zero_amount,
                                   blinding_factor) == 1);
  EXPECT(secp256k1_elgamal_verify_encryption(
             ctx, &c1, &c2, &pubkey, zero_amount, blinding_factor) == 1);

  /* 3. Test detection of incorrect amount */
  EXPECT(secp256k1_elgamal_verify_encryption(ctx, &c1, &c2, &pubkey, amount + 1,
                                             blinding_factor) == 0);

  /* 4. Test detection of tampered ciphertext */
  c2 = c1;
  EXPECT(secp256k1_elgamal_verify_encryption(
             ctx, &c1, &c2, &pubkey, zero_amount, blinding_factor) == 0);

  printf("Test passed!\n");
}

static void test_decryption_boundaries(const secp256k1_context *ctx)
{
  unsigned char privkey[32], blinding_factor[32];
  secp256k1_pubkey pubkey, c1, c2, temp_pubkey;
  uint64_t decrypted_amount = 0;

  printf("Running test: decryption boundary limits with [range_low, "
         "range_high]...\n");
  EXPECT(secp256k1_elgamal_generate_keypair(ctx, privkey, &pubkey) == 1);
  EXPECT(secp256k1_elgamal_generate_keypair(ctx, blinding_factor,
                                            &temp_pubkey) == 1);

  /* --- Default range [0, 2000] tests --- */

  /* amount = 0: must succeed with range [0, 2000]. */
  decrypted_amount = 0xDEADBEEFu;
  EXPECT(secp256k1_elgamal_encrypt(ctx, &c1, &c2, &pubkey, 0,
                                   blinding_factor) == 1);
  EXPECT(secp256k1_elgamal_decrypt(ctx, &decrypted_amount, &c1, &c2, privkey, 0,
                                   2000) == 1);
  EXPECT(decrypted_amount == 0);

  /* amount = 1: smallest positive value. */
  decrypted_amount = 0xDEADBEEFu;
  EXPECT(secp256k1_elgamal_encrypt(ctx, &c1, &c2, &pubkey, 1,
                                   blinding_factor) == 1);
  EXPECT(secp256k1_elgamal_decrypt(ctx, &decrypted_amount, &c1, &c2, privkey, 0,
                                   2000) == 1);
  EXPECT(decrypted_amount == 1);

  /* amount = 2000: exact upper boundary with [0, 2000]. */
  decrypted_amount = 0xDEADBEEFu;
  EXPECT(secp256k1_elgamal_encrypt(ctx, &c1, &c2, &pubkey, 2000,
                                   blinding_factor) == 1);
  EXPECT(secp256k1_elgamal_decrypt(ctx, &decrypted_amount, &c1, &c2, privkey, 0,
                                   2000) == 1);
  EXPECT(decrypted_amount == 2000);

  /* amount = 2001: just outside [0, 2000], must fail. */
  EXPECT(secp256k1_elgamal_encrypt(ctx, &c1, &c2, &pubkey, 2001,
                                   blinding_factor) == 1);
  EXPECT(secp256k1_elgamal_decrypt(ctx, &decrypted_amount, &c1, &c2, privkey, 0,
                                   2000) == 0);

  /* --- Custom range [500, 1500] tests --- */

  /* amount = 1000: within [500, 1500], must succeed. */
  decrypted_amount = 0xDEADBEEFu;
  EXPECT(secp256k1_elgamal_encrypt(ctx, &c1, &c2, &pubkey, 1000,
                                   blinding_factor) == 1);
  EXPECT(secp256k1_elgamal_decrypt(ctx, &decrypted_amount, &c1, &c2, privkey,
                                   500, 1500) == 1);
  EXPECT(decrypted_amount == 1000);

  /* amount = 200: below [500, 1500], must fail. */
  EXPECT(secp256k1_elgamal_encrypt(ctx, &c1, &c2, &pubkey, 200,
                                   blinding_factor) == 1);
  EXPECT(secp256k1_elgamal_decrypt(ctx, &decrypted_amount, &c1, &c2, privkey,
                                   500, 1500) == 0);

  /* amount = 2000: above [500, 1500], must fail. */
  EXPECT(secp256k1_elgamal_encrypt(ctx, &c1, &c2, &pubkey, 2000,
                                   blinding_factor) == 1);
  EXPECT(secp256k1_elgamal_decrypt(ctx, &decrypted_amount, &c1, &c2, privkey,
                                   500, 1500) == 0);

  /* --- Invalid range tests --- */

  /* range_low > range_high: must fail immediately. */
  EXPECT(secp256k1_elgamal_encrypt(ctx, &c1, &c2, &pubkey, 100,
                                   blinding_factor) == 1);
  EXPECT(secp256k1_elgamal_decrypt(ctx, &decrypted_amount, &c1, &c2, privkey,
                                   1000, 500) == 0);

  /* range_high == UINT64_MAX: must fail immediately (would be ~2^64 iterations
   * and cause unsigned wraparound in the loop counter). */
  EXPECT(secp256k1_elgamal_encrypt(ctx, &c1, &c2, &pubkey, 100,
                                   blinding_factor) == 1);
  EXPECT(secp256k1_elgamal_decrypt(ctx, &decrypted_amount, &c1, &c2, privkey, 0,
                                   UINT64_MAX) == 0);

  /* --- Zero exclusion test --- */

  /* amount = 0 with range_low > 0: must fail (zero excluded from range). */
  EXPECT(secp256k1_elgamal_encrypt(ctx, &c1, &c2, &pubkey, 0,
                                   blinding_factor) == 1);
  EXPECT(secp256k1_elgamal_decrypt(ctx, &decrypted_amount, &c1, &c2, privkey, 1,
                                   2000) == 0);

  printf("Test passed!\n");
}
