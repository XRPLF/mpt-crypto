#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "secp256k1_mpt.h"
#include <openssl/rand.h>

void test_pedersen_commitment_basic() {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    uint64_t amount = 1000;
    unsigned char rho[32];
    secp256k1_pubkey pc1, pc2;
    unsigned char ser1[33], ser2[33];
    size_t len = 33;

    printf("DEBUG: Starting Pedersen Commitment basic tests...\n");

    // Generate random blinding factor
    RAND_bytes(rho, 32);

    // 1. Test Consistency: PC(m, rho) should always produce the same result
    assert(secp256k1_mpt_pedersen_commit(ctx, &pc1, amount, rho) == 1);
    assert(secp256k1_mpt_pedersen_commit(ctx, &pc2, amount, rho) == 1);

    secp256k1_ec_pubkey_serialize(ctx, ser1, &len, &pc1, SECP256K1_EC_COMPRESSED);
    len = 33;
    secp256k1_ec_pubkey_serialize(ctx, ser2, &len, &pc2, SECP256K1_EC_COMPRESSED);

    assert(memcmp(ser1, ser2, 33) == 0);
    printf("SUCCESS: Deterministic commitment verified.\n");

    // 2. Test Binding: Changing amount should change commitment
    assert(secp256k1_mpt_pedersen_commit(ctx, &pc2, amount + 1, rho) == 1);
    len = 33;
    secp256k1_ec_pubkey_serialize(ctx, ser2, &len, &pc2, SECP256K1_EC_COMPRESSED);
    assert(memcmp(ser1, ser2, 33) != 0);
    printf("SUCCESS: Binding property (amount) verified.\n");

    secp256k1_context_destroy(ctx);
}

void test_pedersen_homomorphic_property() {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    uint64_t m1 = 500, m2 = 300;
    unsigned char r1[32], r2[32], r_sum[32];
    secp256k1_pubkey pc1, pc2, pc_sum_manual, pc_sum_computed;

    printf("DEBUG: Starting Pedersen Homomorphic property test...\n");

    // Generate random blinding factors
    RAND_bytes(r1, 32);
    RAND_bytes(r2, 32);

    // Compute PC1 = PC(m1, r1) and PC2 = PC(m2, r2)
    assert(secp256k1_mpt_pedersen_commit(ctx, &pc1, m1, r1) == 1);
    assert(secp256k1_mpt_pedersen_commit(ctx, &pc2, m2, r2) == 1);

    // Manual sum of points: PC1 + PC2
    const secp256k1_pubkey* points[2] = {&pc1, &pc2};
    assert(secp256k1_ec_pubkey_combine(ctx, &pc_sum_manual, points, 2) == 1);

    // Compute scalar sum of blinding factors: r_sum = r1 + r2 (mod n)
    memcpy(r_sum, r1, 32);
    assert(secp256k1_ec_seckey_tweak_add(ctx, r_sum, r2) == 1);

    // Compute PC(m1 + m2, r1 + r2)
    assert(secp256k1_mpt_pedersen_commit(ctx, &pc_sum_computed, m1 + m2, r_sum) == 1);

    // Compare
    unsigned char ser1[33], ser2[33];
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(ctx, ser1, &len, &pc_sum_manual, SECP256K1_EC_COMPRESSED);
    len = 33;
    secp256k1_ec_pubkey_serialize(ctx, ser2, &len, &pc_sum_computed, SECP256K1_EC_COMPRESSED);

    assert(memcmp(ser1, ser2, 33) == 0);
    printf("SUCCESS: Homomorphic property (PC(m1,r1) + PC(m2,r2) == PC(m1+m2, r1+r2)) verified.\n");

    secp256k1_context_destroy(ctx);
}

int main() {
    test_pedersen_commitment_basic();
    test_pedersen_homomorphic_property();
    printf("DEBUG: All Pedersen Commitment tests passed!\n");
    return 0;
}