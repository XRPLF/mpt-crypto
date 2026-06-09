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
static void
test_homomorphic_add_point_at_infinity(const secp256k1_context *ctx);
static void
test_homomorphic_add_post_mergeinbox_attack(const secp256k1_context *ctx);

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
  test_homomorphic_add_point_at_infinity(ctx);
  test_homomorphic_add_post_mergeinbox_attack(ctx);

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
  uint64_t original_amount = 10001;
  uint64_t decrypted_amount = 0;
  printf("Running test: encryption-decryption round trip...\n");
  EXPECT(secp256k1_elgamal_generate_keypair(ctx, privkey, &pubkey) == 1);
  EXPECT(secp256k1_elgamal_generate_keypair(ctx, blinding_factor,
                                            &temp_pubkey) == 1);
  EXPECT(secp256k1_elgamal_encrypt(ctx, &c1, &c2, &pubkey, original_amount,
                                   blinding_factor) == 1);
  EXPECT(secp256k1_elgamal_decrypt(ctx, &decrypted_amount, &c1, &c2, privkey) ==
         1);
  EXPECT(original_amount == decrypted_amount);
  printf("Test passed!\n");
}

static void test_homomorphic_operations(const secp256k1_context *ctx)
{
  unsigned char privkey[32];
  secp256k1_pubkey pubkey;
  uint64_t amount_a = 5000, amount_b = 1234;
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
                                   &result_c2, privkey) == 1);
  EXPECT(decrypted_result == amount_a + amount_b);

  EXPECT(secp256k1_elgamal_subtract(ctx, &result_c1, &result_c2, &a_c1, &a_c2,
                                    &b_c1, &b_c2) == 1);
  EXPECT(secp256k1_elgamal_decrypt(ctx, &decrypted_result, &result_c1,
                                   &result_c2, privkey) == 1);
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
  EXPECT(secp256k1_elgamal_decrypt(ctx, &decrypted_amount, &c1, &c2, privkey) ==
         1);
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

  EXPECT(secp256k1_elgamal_decrypt(ctx, &decrypted_amount, &c1_a, &c2_a,
                                   privkey) == 1);
  EXPECT(decrypted_amount == 0);

  EXPECT(memcmp(&c1_a, &c1_b, sizeof(c1_a)) == 0);
  EXPECT(memcmp(&c2_a, &c2_b, sizeof(c2_a)) == 0);

  printf("Test passed!\n");
}

static void test_verify_encryption(const secp256k1_context *ctx)
{
  unsigned char privkey[32], blinding_factor[32];
  secp256k1_pubkey pubkey, c1, c2, temp_pubkey;
  uint64_t amount = 5000;
  uint64_t zero_amount = 0;

  printf("Running test: secp256k1_elgamal_verify_encryption...\n");
  EXPECT(secp256k1_elgamal_generate_keypair(ctx, privkey, &pubkey) == 1);
  EXPECT(secp256k1_elgamal_generate_keypair(ctx, blinding_factor,
                                            &temp_pubkey) == 1);

  EXPECT(secp256k1_elgamal_encrypt(ctx, &c1, &c2, &pubkey, amount,
                                   blinding_factor) == 1);
  EXPECT(secp256k1_elgamal_verify_encryption(ctx, &c1, &c2, &pubkey, amount,
                                             blinding_factor) == 1);

  EXPECT(secp256k1_elgamal_encrypt(ctx, &c1, &c2, &pubkey, zero_amount,
                                   blinding_factor) == 1);
  EXPECT(secp256k1_elgamal_verify_encryption(
             ctx, &c1, &c2, &pubkey, zero_amount, blinding_factor) == 1);

  EXPECT(secp256k1_elgamal_verify_encryption(ctx, &c1, &c2, &pubkey, amount + 1,
                                             blinding_factor) == 0);

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

  printf("Running test: decryption boundary limits (1,000,000)...\n");
  EXPECT(secp256k1_elgamal_generate_keypair(ctx, privkey, &pubkey) == 1);
  EXPECT(secp256k1_elgamal_generate_keypair(ctx, blinding_factor,
                                            &temp_pubkey) == 1);

  EXPECT(secp256k1_elgamal_encrypt(ctx, &c1, &c2, &pubkey, 1000000,
                                   blinding_factor) == 1);
  EXPECT(secp256k1_elgamal_decrypt(ctx, &decrypted_amount, &c1, &c2, privkey) ==
         1);
  EXPECT(decrypted_amount == 1000000);

  EXPECT(secp256k1_elgamal_encrypt(ctx, &c1, &c2, &pubkey, 1000001,
                                   blinding_factor) == 1);
  EXPECT(secp256k1_elgamal_decrypt(ctx, &decrypted_amount, &c1, &c2, privkey) ==
         0);

  printf("Test passed!\n");
}

/*
 * Test: Homomorphic addition produces point at infinity
 *
 * This test verifies that secp256k1_elgamal_add correctly returns 0 (failure)
 * when the resulting C1 component is the point at infinity. This occurs when
 * two ciphertexts with equal and opposite randomness are added homomorphically:
 * C1_result = r*G + (-r)*G = point at infinity.
 *
 * secp256k1_ec_pubkey_combine returns 0 for point at infinity, so
 * secp256k1_elgamal_add must propagate this failure by also returning 0.
 *
 * This is the core library behavior that protects against TOB-RIPCTXR-5.
 */
static void test_homomorphic_add_point_at_infinity(const secp256k1_context *ctx)
{
  unsigned char privkey[32], r[32];
  secp256k1_pubkey pubkey, temp_pubkey;
  secp256k1_pubkey c1_a, c2_a; /* Enc(m; r)  */
  secp256k1_pubkey c1_b, c2_b; /* Enc(x; -r) */
  secp256k1_pubkey result_c1, result_c2;
  unsigned char neg_r[32];
  uint64_t amount_a = 1000, amount_b = 500;
  int ret;

  printf("Running test: homomorphic add produces point at infinity...\n");

  EXPECT(secp256k1_elgamal_generate_keypair(ctx, privkey, &pubkey) == 1);

  /* Generate random scalar r */
  EXPECT(secp256k1_elgamal_generate_keypair(ctx, r, &temp_pubkey) == 1);

  /* Compute -r mod q */
  memcpy(neg_r, r, 32);
  EXPECT(secp256k1_ec_seckey_negate(ctx, neg_r) == 1);

  /* Encrypt amount_a with randomness r: Enc(amount_a; r) */
  EXPECT(secp256k1_elgamal_encrypt(ctx, &c1_a, &c2_a, &pubkey, amount_a, r) ==
         1);

  /* Encrypt amount_b with randomness -r: Enc(amount_b; -r) */
  EXPECT(secp256k1_elgamal_encrypt(ctx, &c1_b, &c2_b, &pubkey, amount_b,
                                   neg_r) == 1);

  /*
   * Homomorphic addition:
   * C1_result = r*G + (-r)*G = point at infinity
   * secp256k1_elgamal_add must return 0 (failure).
   */
  ret = secp256k1_elgamal_add(ctx, &result_c1, &result_c2, &c1_a, &c2_a, &c1_b,
                              &c2_b);

  printf("  secp256k1_elgamal_add returned: %d (expected 0 = failure)\n", ret);
  EXPECT(ret == 0);

  printf("Test passed! Point at infinity correctly rejected.\n");
}

/*
 * Test: Post-MergeInbox inbox locking attack (TOB-RIPCTXR-5 variant)
 *
 * After MergeInbox, CB_IN resets to canonical zero Enc(0; r0_A) with
 * publicly known randomness r0_A. A malicious sender can craft a Send
 * with r_send = -r0_A so that:
 *   CB_IN_new = Enc(0; r0_A) + Enc(m*; -r0_A) = Enc(m*; 0)
 * where C1 = point at infinity.
 *
 * The homomorphic addition should FAIL (return 0), meaning the malicious
 * Send is rejected and CB_IN is never updated with an invalid ciphertext.
 *
 * This test verifies that the library correctly rejects the malicious Send
 * at the homomorphic addition level. Our fix (Enc(0; r_fresh) in first
 * Convert and every Clawback) is sufficient when combined with correct
 * return value checking (TOB-RIPCTXR-14).
 *
 * If this test FAILS (ret == 1), the library allowed the point at infinity
 * and a stronger fix would be needed.
 */
static void
test_homomorphic_add_post_mergeinbox_attack(const secp256k1_context *ctx)
{
  unsigned char privkey[32];
  secp256k1_pubkey pubkey;
  unsigned char account_id[20] = {1};
  unsigned char issuance_id[24] = {2};
  secp256k1_pubkey cb_in_c1, cb_in_c2; /* CB_IN = canonical zero Enc(0; r0_A) */
  secp256k1_pubkey send_c1, send_c2;   /* Malicious Send: Enc(m*; -r0_A)      */
  secp256k1_pubkey result_c1, result_c2; /* Result of homomorphic addition */
  uint64_t malicious_amount = 999;
  int ret;

  /* Recompute r0_A as the library would — same deterministic scalar */
  unsigned char r0_A[32];
  unsigned char hash_input[51];
  const char *domain = "EncZero";
  unsigned int md_len = 32;
  unsigned char neg_r0_A[32];

  printf("Running test: post-MergeInbox inbox locking attack (TOB-RIPCTXR-5 "
         "variant)...\n");

  EXPECT(secp256k1_elgamal_generate_keypair(ctx, privkey, &pubkey) == 1);

  /*
   * Step 1: Simulate CB_IN after MergeInbox = canonical zero Enc(0; r0_A)
   * with publicly known r0_A.
   */
  EXPECT(generate_canonical_encrypted_zero(ctx, &cb_in_c1, &cb_in_c2, &pubkey,
                                           account_id, issuance_id) == 1);

  /*
   * Step 2: Derive r0_A from public information
   * (same computation as generate_canonical_encrypted_zero).
   */
  memcpy(hash_input, domain, 7);
  memcpy(hash_input + 7, account_id, 20);
  memcpy(hash_input + 27, issuance_id, 24);
  EXPECT(EVP_Digest(hash_input, 51, r0_A, &md_len, EVP_sha256(), NULL) == 1);
  EXPECT(secp256k1_ec_seckey_verify(ctx, r0_A) == 1);

  /*
   * Step 3: Compute -r0_A and craft Enc(m*; -r0_A).
   * The malicious Send ciphertext itself is valid (C1 = -r0_A*G != infinity).
   */
  memcpy(neg_r0_A, r0_A, 32);
  EXPECT(secp256k1_ec_seckey_negate(ctx, neg_r0_A) == 1);
  EXPECT(secp256k1_elgamal_encrypt(ctx, &send_c1, &send_c2, &pubkey,
                                   malicious_amount, neg_r0_A) == 1);
  printf("  Malicious Send ciphertext is valid (C1 != infinity): OK\n");

  /*
   * Step 4: Ledger tries to update CB_IN by homomorphic addition:
   * CB_IN_new = Enc(0; r0_A) + Enc(m*; -r0_A) = Enc(m*; 0)
   * C1_new = r0_A*G + (-r0_A)*G = point at infinity
   *
   * secp256k1_elgamal_add must return 0 (failure).
   * If it returns 1, the malicious Send was accepted with an invalid
   * CB_IN stored on ledger, and the next MergeInbox would fail with
   * tecINTERNAL — funds are locked.
   */
  ret = secp256k1_elgamal_add(ctx, &result_c1, &result_c2, &cb_in_c1, &cb_in_c2,
                              &send_c1, &send_c2);

  printf("  Homomorphic add (CB_IN + malicious Send) returned: %d\n", ret);
  printf(
      "  Expected: 0 (failure — malicious Send rejected at library level)\n");
  printf("  If 1: attack succeeds — CB_IN would store point at infinity\n");

  /*
   * If ret == 0: the malicious Send is blocked at the library level.
   * Our fix (Enc(0; r_fresh) in first Convert + every Clawback) is
   * sufficient when combined with correct return value checking
   * (TOB-RIPCTXR-14).
   *
   * If ret == 1: the attack succeeds and a stronger fix is needed —
   * either re-randomization during Send (Option 2) or Enc(0; r_fresh)
   * in MergeInbox.
   */
  EXPECT(ret == 0);

  printf("Test passed! Malicious Send correctly rejected at library level.\n");
  printf("  Our fix combined with TOB-RIPCTXR-14 is sufficient.\n");
}
