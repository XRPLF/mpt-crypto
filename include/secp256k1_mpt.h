#ifndef SECP256K1_MPT_H
#define SECP256K1_MPT_H

#include <secp256k1.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Generates a new secp256k1 key pair.
 */
SECP256K1_API int
secp256k1_elgamal_generate_keypair(
    secp256k1_context const* ctx,
    unsigned char* privkey,
    secp256k1_pubkey* pubkey);

/**
 * @brief Encrypts a 64-bit amount using ElGamal.
 */
SECP256K1_API int
secp256k1_elgamal_encrypt(
    secp256k1_context const* ctx,
    secp256k1_pubkey* c1,
    secp256k1_pubkey* c2,
    secp256k1_pubkey const* pubkey_Q,
    uint64_t amount,
    unsigned char const* blinding_factor);

/**
 * @brief Decrypts an ElGamal ciphertext to recover the amount.
 * Due to the use of a linear discrete logarithm search, this function can
 * only successfully recover plaintext amounts between 0 and 1,000,000 (inclusive).
 * If the ciphertext encrypts a value greater than 1,000,000, the search will
 * exhaust its range and the function will safely return 0 (failure).
 * * NOTE: To mitigate timing side-channels, this search executes with a fixed
 * iteration count (always looping to the maximum limit). However, because the
 * underlying libsecp256k1 curve operations are inherently variable-time, this
 * function does NOT provide a strict constant-time guarantee.
 * * Architectural Note:
 * On-chain validators and verifiers never need to perform decryption; this
 * function is provided primarily for testing and basic client-side operations.
 * Off-chain applications (like wallets) requiring decryption of larger balances
 * should implement more efficient discrete logarithm algorithms, such as
 * Baby-Step Giant-Step (BSGS) or Pollard's kangaroo method.
 */
SECP256K1_API int
secp256k1_elgamal_decrypt(
    secp256k1_context const* ctx,
    uint64_t* amount,
    secp256k1_pubkey const* c1,
    secp256k1_pubkey const* c2,
    unsigned char const* privkey);

/**
 * @brief Homomorphically adds two ElGamal ciphertexts.
 */
SECP256K1_API int
secp256k1_elgamal_add(
    secp256k1_context const* ctx,
    secp256k1_pubkey* sum_c1,
    secp256k1_pubkey* sum_c2,
    secp256k1_pubkey const* a_c1,
    secp256k1_pubkey const* a_c2,
    secp256k1_pubkey const* b_c1,
    secp256k1_pubkey const* b_c2);

/**
 * @brief Homomorphically subtracts two ElGamal ciphertexts.
 */
SECP256K1_API int
secp256k1_elgamal_subtract(
    secp256k1_context const* ctx,
    secp256k1_pubkey* diff_c1,
    secp256k1_pubkey* diff_c2,
    secp256k1_pubkey const* a_c1,
    secp256k1_pubkey const* a_c2,
    secp256k1_pubkey const* b_c1,
    secp256k1_pubkey const* b_c2);

/**
 * @brief Generates the canonical encrypted zero for a given MPT token instance.
 *
 * This ciphertext represents a zero balance for a specific account's holding
 * of a token defined by its MPTokenIssuanceID.
 *
 * @param[in]   ctx             A pointer to a valid secp256k1 context.
 * @param[out]  enc_zero_c1     The C1 component of the canonical ciphertext.
 * @param[out]  enc_zero_c2     The C2 component of the canonical ciphertext.
 * @param[in]   pubkey          The ElGamal public key of the account holder.
 * @param[in]   account_id      A pointer to the 20-byte AccountID.
 * @param[in]   mpt_issuance_id A pointer to the 24-byte MPTokenIssuanceID.
 *
 * @return 1 on success, 0 on failure.
 */
SECP256K1_API int
generate_canonical_encrypted_zero(
    secp256k1_context const* ctx,
    secp256k1_pubkey* enc_zero_c1,
    secp256k1_pubkey* enc_zero_c2,
    secp256k1_pubkey const* pubkey,
    unsigned char const* account_id,      // 20 bytes
    unsigned char const* mpt_issuance_id  // 24 bytes
);

// ... (includes and previous ElGamal declarations) ...

/*
================================================================================
|                                                                              |
|           PROOF OF KNOWLEDGE OF PLAINTEXT AND RANDOMNESS                     |
|                (Chaum-Pedersen Equality Proof)                               |
================================================================================
*/

/**
 * @brief Generates a proof that an ElGamal ciphertext correctly encrypts a
 * known plaintext `m` and that the prover knows the randomness `r`.
 *
 * @param[in]   ctx             A pointer to a valid secp256k1 context object,
 * initialized for signing.
 * @param[out]  proof           A pointer to a 98-byte buffer to store the proof
 * (T1 [33 bytes] || T2 [33 bytes] || s [32 bytes]).
 * @param[in]   c1              The C1 component of the ciphertext (r*G).
 * @param[in]   c2              The C2 component of the ciphertext (m*G + r*Pk).
 * @param[in]   pk_recipient    The public key used for encryption.
 * @param[in]   amount          The known plaintext value `m`.
 * @param[in]   randomness_r    The 32-byte secret random scalar `r` used in encryption.
 * @param[in]   tx_context_id   A 32-byte unique identifier for the transaction context.
 *
 * @return 1 on success, 0 on failure.
 */
SECP256K1_API int
secp256k1_equality_plaintext_prove(
    secp256k1_context const* ctx,
    unsigned char* proof,  // Output: 98 bytes
    secp256k1_pubkey const* c1,
    secp256k1_pubkey const* c2,
    secp256k1_pubkey const* pk_recipient,
    uint64_t amount,
    unsigned char const* randomness_r,  // Secret input
    unsigned char const* tx_context_id  // 32 bytes
);

/**
 * @brief Verifies a proof of knowledge of plaintext and randomness.
 *
 * Checks if the proof correctly demonstrates that (C1, C2) encrypts `m`
 * under `pk_recipient`.
 *
 * @param[in]   ctx             A pointer to a valid secp256k1 context object,
 * initialized for verification.
 * @param[in]   proof           A pointer to the 98-byte proof to verify.
 * @param[in]   c1              The C1 component of the ciphertext.
 * @param[in]   c2              The C2 component of the ciphertext.
 * @param[in]   pk_recipient    The public key used for encryption.
 * @param[in]   amount          The known plaintext value `m`.
 * @param[in]   tx_context_id   A 32-byte unique identifier for the transaction context.
 *
 * @return 1 if the proof is valid, 0 otherwise.
 */
SECP256K1_API int
secp256k1_equality_plaintext_verify(
    secp256k1_context const* ctx,
    unsigned char const* proof,  // Input: 98 bytes
    secp256k1_pubkey const* c1,
    secp256k1_pubkey const* c2,
    secp256k1_pubkey const* pk_recipient,
    uint64_t amount,
    unsigned char const* tx_context_id  // 32 bytes
);

// ... (rest of header, #endif etc.)

/*
================================================================================
|                                                                              |
|           PROOF OF EQUALITY OF SECRET PLAINTEXTS                             |
|                (Multi-Statement Chaum-Pedersen)                              |
================================================================================
*/

/**
 * @brief Computes a Pedersen Commitment: C = value*G + blinding_factor*Pk_base.
 *
 * This function creates the commitment point (C) that the Bulletproof proves
 * the range of. Pk_base is the dynamic secondary generator (H).
 *
 * @param[in]   ctx             A pointer to the context.
 * @param[out]  commitment_C    The resulting commitment point C.
 * @param[in]   value           The secret amount v (uint64_t).
 * @param[in]   blinding_factor The secret randomness r (32 bytes).
 * @param[in]   pk_base         The recipient's public key (used as the H generator).
 *
 * @return 1 on success, 0 on failure.
 */
SECP256K1_API int
secp256k1_bulletproof_create_commitment(
    secp256k1_context const* ctx,
    secp256k1_pubkey* commitment_C,
    uint64_t value,
    unsigned char const* blinding_factor,
    secp256k1_pubkey const* pk_base);

int
secp256k1_bulletproof_prove(
    secp256k1_context const* ctx,
    unsigned char* proof_out,
    size_t* proof_len,
    uint64_t value,
    unsigned char const* blinding_factor,
    secp256k1_pubkey const* pk_base,
    unsigned char const* context_id, /* <--- AND HERE */
    unsigned int proof_type);

int
secp256k1_bulletproof_verify(
    secp256k1_context const* ctx,
    secp256k1_pubkey const* G_vec,
    secp256k1_pubkey const* H_vec,
    unsigned char const* proof,
    size_t proof_len,
    secp256k1_pubkey const* commitment_C,
    secp256k1_pubkey const* pk_base, /* This is generator H */
    unsigned char const* context_id);
/**
 * @brief Proves the link between an ElGamal ciphertext and a Pedersen commitment.
 * * Formal Statement: Knowledge of (m, r, rho) such that:
 * C1 = r*G, C2 = m*G + r*Pk, and PCm = m*G + rho*H.
 * * @param ctx         Pointer to a secp256k1 context object.
 * @param proof       [OUT] Pointer to 195-byte buffer for the proof output.
 * @param c1          Pointer to the ElGamal C1 point (r*G).
 * @param c2          Pointer to the ElGamal C2 point (m*G + r*Pk).
 * @param pk          Pointer to the recipient's public key.
 * @param pcm         Pointer to the Pedersen Commitment (m*G + rho*H).
 * @param amount      The plaintext amount (m).
 * @param r           The 32-byte secret ElGamal blinding factor.
 * @param rho         The 32-byte secret Pedersen blinding factor.
 * @param context_id  32-byte unique transaction context identifier.
 * @return 1 on success, 0 on failure.
 */
int
secp256k1_elgamal_pedersen_link_prove(
    secp256k1_context const* ctx,
    unsigned char* proof,
    secp256k1_pubkey const* c1,
    secp256k1_pubkey const* c2,
    secp256k1_pubkey const* pk,
    secp256k1_pubkey const* pcm,
    uint64_t amount,
    unsigned char const* r,
    unsigned char const* rho,
    unsigned char const* context_id);

/**
 * @brief Verifies the link proof between ElGamal and Pedersen commitments.
 * * @return 1 if the proof is valid, 0 otherwise.
 */
int
secp256k1_elgamal_pedersen_link_verify(
    secp256k1_context const* ctx,
    unsigned char const* proof,
    secp256k1_pubkey const* c1,
    secp256k1_pubkey const* c2,
    secp256k1_pubkey const* pk,
    secp256k1_pubkey const* pcm,
    unsigned char const* context_id);

/**
 * Verifies that (c1, c2) is a valid ElGamal encryption of 'amount'
 * for 'pubkey_Q' using the revealed 'blinding_factor'.
 */
int
secp256k1_elgamal_verify_encryption(
    secp256k1_context const* ctx,
    secp256k1_pubkey const* c1,
    secp256k1_pubkey const* c2,
    secp256k1_pubkey const* pubkey_Q,
    uint64_t amount,
    unsigned char const* blinding_factor);

/** Proof of Knowledge of Secret Key for Registration */
int
secp256k1_mpt_pok_sk_prove(
    secp256k1_context const* ctx,
    unsigned char* proof, /* Expected size: 65 bytes */
    secp256k1_pubkey const* pk,
    unsigned char const* sk,
    unsigned char const* context_id);

int
secp256k1_mpt_pok_sk_verify(
    secp256k1_context const* ctx,
    unsigned char const* proof, /* Expected size: 65 bytes */
    secp256k1_pubkey const* pk,
    unsigned char const* context_id);

/**
 * Compute a Pedersen Commitment: PC = m*G + rho*H
 * Returns 1 on success, 0 on failure.
 */
int
secp256k1_mpt_pedersen_commit(
    secp256k1_context const* ctx,
    secp256k1_pubkey* commitment,
    uint64_t amount,
    unsigned char const* blinding_factor_rho /* 32 bytes */
);

/** Get the standardized H generator for Pedersen Commitments */
int
secp256k1_mpt_get_h_generator(secp256k1_context const* ctx, secp256k1_pubkey* h);

/**
 * @brief Generates a vector of N independent NUMS generators.
 */
int
secp256k1_mpt_get_generator_vector(
    secp256k1_context const* ctx,
    secp256k1_pubkey* vec,
    size_t n,
    unsigned char const* label,
    size_t label_len);

void
secp256k1_mpt_scalar_add(unsigned char* res, unsigned char const* a, unsigned char const* b);
void
secp256k1_mpt_scalar_mul(unsigned char* res, unsigned char const* a, unsigned char const* b);
void
secp256k1_mpt_scalar_inverse(unsigned char* res, unsigned char const* in);
void
secp256k1_mpt_scalar_negate(unsigned char* res, unsigned char const* in);
void
secp256k1_mpt_scalar_reduce32(unsigned char out32[32], unsigned char const in32[32]);

/**
 * Returns the size of the serialized proof for N recipients.
 * Size: (1 + N) * 33 bytes for points + 2 * 32 bytes for scalars.
 */
size_t
secp256k1_mpt_proof_equality_shared_r_size(size_t n);

/**
 * Generates a proof that multiple ciphertexts encrypt the same amount m
 * using the SAME shared randomness r.
 *
 * n must satisfy 1 <= n <= 4 (Sender, Receiver, Issuer, Auditor).
 * Returns 0 if n is out of range.
 */
int
secp256k1_mpt_prove_equality_shared_r(
    secp256k1_context const* ctx,
    unsigned char* proof_out,
    uint64_t amount,
    unsigned char const* r_shared,
    size_t n,
    secp256k1_pubkey const* C1,
    secp256k1_pubkey const* C2_vec,
    secp256k1_pubkey const* Pk_vec,
    unsigned char const* context_id);

/**
 * Verifies the proof of equality with shared randomness.
 *
 * n must satisfy 1 <= n <= 4.
 * Returns 0 if n is out of range.
 */
int
secp256k1_mpt_verify_equality_shared_r(
    secp256k1_context const* ctx,
    unsigned char const* proof,
    size_t n,
    secp256k1_pubkey const* C1,
    secp256k1_pubkey const* C2_vec,
    secp256k1_pubkey const* Pk_vec,
    unsigned char const* context_id);

/**
 * Generates an aggregated Bulletproof range proof for m values.
 *
 * m must satisfy 1 <= m <= 4 and be a power of two.
 * Returns 0 if m is out of range.
 */
int
secp256k1_bulletproof_prove_agg(
    secp256k1_context const* ctx,
    unsigned char* proof_out,
    size_t* proof_len,
    uint64_t const* values,
    unsigned char const* blindings_flat,
    size_t m,
    secp256k1_pubkey const* pk_base,
    unsigned char const* context_id);

/**
 * Verifies an aggregated Bulletproof range proof for m values.
 *
 * m must satisfy 1 <= m <= 4 and be a power of two.
 * Returns 0 if m is out of range.
 */
int
secp256k1_bulletproof_verify_agg(
    secp256k1_context const* ctx,
    secp256k1_pubkey const* G_vec, /* length n = 64*m */
    secp256k1_pubkey const* H_vec, /* length n = 64*m */
    unsigned char const* proof,
    size_t proof_len,
    secp256k1_pubkey const* commitment_C_vec, /* length m */
    size_t m,
    secp256k1_pubkey const* pk_base,
    unsigned char const* context_id);

#ifdef __cplusplus
}
#endif

#endif  // SECP256K1_MPT_H
