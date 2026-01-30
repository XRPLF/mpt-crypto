#include "secp256k1_mpt.h"
#include <string.h>
#include <openssl/sha.h>

/* --- Internal Helpers --- */

/**
 * @brief Deterministically derives a NUMS (Nothing-Up-My-Sleeve) generator point.
 * * Uses SHA-256 try-and-increment to find an x-coordinate. This ensures the
 * discrete logarithm of the resulting point is unknown, which is a core
 * security requirement for Bulletproof binding and vector commitments.
 *
 * @param ctx       secp256k1 context (VERIFY flag required).
 * @param out       The derived public key generator.
 * @param label     Domain/vector label (e.g., "G" or "H").
 * @param index     Vector index (enforced Big-Endian).
 * @return 1 on success, 0 on failure.
 */
int secp256k1_mpt_hash_to_point_nums(
        const secp256k1_context* ctx,
        secp256k1_pubkey* out,
        const unsigned char* label,
        size_t label_len,
        uint32_t index
) {
    unsigned char hash[32];
    unsigned char compressed[33];
    uint32_t ctr = 0;

    unsigned char idx_be[4] = {
            (unsigned char)(index >> 24), (unsigned char)(index >> 16),
            (unsigned char)(index >> 8),  (unsigned char)(index & 0xFF)
    };

    while (ctr < 0xFFFFFFFFu) {
        unsigned char ctr_be[4] = {
                (unsigned char)(ctr >> 24), (unsigned char)(ctr >> 16),
                (unsigned char)(ctr >> 8),  (unsigned char)(ctr & 0xFF)
        };

        SHA256_CTX sha;
        SHA256_Init(&sha);
        SHA256_Update(&sha, "MPT_BULLETPROOF_V1_NUMS", 23);
        SHA256_Update(&sha, "secp256k1", 9);

        if (label && label_len > 0) {
            SHA256_Update(&sha, label, label_len);
        }

        SHA256_Update(&sha, idx_be, 4);
        SHA256_Update(&sha, ctr_be, 4);
        SHA256_Final(hash, &sha);

        compressed[0] = 0x02; /* even Y */
        memcpy(&compressed[1], hash, 32);

        if (secp256k1_ec_pubkey_parse(ctx, out, compressed, 33) == 1) {
            return 1;
        }
        ctr++;
    }
    return 0;
}

/**
 * @brief Derives the secondary base point (H) for Pedersen commitments.
 * * This derives a NUMS point using the label "H" at index 0. This H is
 * used alongside the standard generator G to form the commitment
 * C = vG + rH. Using a NUMS point ensures that the discrete logarithm
 * of H with respect to G is unknown.
 *
 * @param ctx  secp256k1 context.
 * @param h    The resulting H generator public key.
 * @return 1 on success, 0 on failure.
 */
int secp256k1_mpt_get_h_generator(const secp256k1_context* ctx, secp256k1_pubkey* h) {
    return secp256k1_mpt_hash_to_point_nums(ctx, h, (const unsigned char*)"H", 1, 0);
}

/**
 * @brief Generates a vector of N independent NUMS generators.
 * * Used to populate the G_i and H_i vectors for Bulletproofs. Each point
 * is derived deterministically from the provided label and its index.
 *
 * @param ctx       secp256k1 context.
 * @param vec       Array to store the resulting generators.
 * @param n         Number of generators to derive (usually 64).
 * @param label     The label string ("G" or "H").
 * @param label_len Length of the label string.
 * @return 1 on success, 0 on failure.
 */
int secp256k1_mpt_get_generator_vector(
        const secp256k1_context* ctx,
        secp256k1_pubkey* vec,
        size_t n,
        const unsigned char* label,
        size_t label_len
) {
    for (uint32_t i = 0; i < (uint32_t)n; i++) {
        /* Call our deterministic NUMS function for each index i */
        if (!secp256k1_mpt_hash_to_point_nums(ctx, &vec[i], label, label_len, i)) {
            return 0;
        }
    }
    return 1;
}


/* --- Public API --- */

int secp256k1_mpt_pedersen_commit(
        const secp256k1_context* ctx,
        secp256k1_pubkey* commitment,
        uint64_t amount,
        const unsigned char* rho
) {
    secp256k1_pubkey mG, rH, H;
    unsigned char m_scalar[32] = {0};

    // 1. m*G
    for (int i = 0; i < 8; i++) m_scalar[31-i] = (amount >> (i*8)) & 0xFF;
    if (!secp256k1_ec_pubkey_create(ctx, &mG, m_scalar)) return 0;

    // 2. rho*H (Using the new NUMS H)
    if (!secp256k1_mpt_get_h_generator(ctx, &H)) return 0;
    rH = H;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &rH, rho)) return 0;

    // 3. mG + rH
    const secp256k1_pubkey* points[2] = {&mG, &rH};
    return secp256k1_ec_pubkey_combine(ctx, commitment, points, 2);
}