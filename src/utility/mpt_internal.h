#ifndef MPT_INTERNAL_H
#define MPT_INTERNAL_H

#include <secp256k1.h>
#include <stdint.h>

/**
 * This header bridges the C math implementation (elgamal.c, etc.)
 * with the C++ utility wrapper (mpt_utility.cpp).
 * This is a private header and should not be under include folder.
 */

#ifdef __cplusplus
extern "C" {
#endif

int secp256k1_elgamal_generate_keypair(
    const secp256k1_context* ctx, 
    uint8_t* priv, 
    uint8_t* pub
);

int secp256k1_elgamal_encrypt(
        const secp256k1_context* ctx,
        secp256k1_pubkey* c1,
        secp256k1_pubkey* c2,
        const secp256k1_pubkey* pubkey_Q,
        uint64_t amount,
        const unsigned char* blinding_factor
);

int secp256k1_elgamal_decrypt(
        const secp256k1_context* ctx,
        uint64_t* amount,
        const secp256k1_pubkey* c1,
        const secp256k1_pubkey* c2,
        const unsigned char* privkey
);

int secp256k1_mpt_pok_sk_prove(
    const secp256k1_context* ctx,
    uint8_t* proof_out,
    const uint8_t* pubkey,
    const uint8_t* privkey,
    const uint8_t* msg32
);

int secp256k1_mpt_pedersen_commit(
    const secp256k1_context* ctx,
    secp256k1_pubkey* commitment_out,
    uint64_t amount,
    const uint8_t* blinding_factor
);

int secp256k1_elgamal_pedersen_link_prove(
        const secp256k1_context* ctx,
        unsigned char* proof,
        const secp256k1_pubkey* c1,
        const secp256k1_pubkey* c2,
        const secp256k1_pubkey* pk,
        const secp256k1_pubkey* pcm,
        uint64_t amount,
        const unsigned char* r,
        const unsigned char* rho,
        const unsigned char* context_id);

size_t secp256k1_mpt_prove_same_plaintext_multi_size(size_t n_recipients);

int secp256k1_mpt_prove_same_plaintext_multi(
    const secp256k1_context* ctx,
    uint8_t* proof_out,
    size_t* proof_len,
    uint64_t amount,
    size_t n_recipients,
    const secp256k1_pubkey* r,
    const secp256k1_pubkey* s,
    const secp256k1_pubkey* pk,
    const uint8_t* blinding_factors,
    const uint8_t* msg32
);

#ifdef __cplusplus
}
#endif

#endif // MPT_INTERNAL_H