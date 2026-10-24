/**
 * @file proof_pok_sk.h
 * @brief Shared Schnorr proof of knowledge of a discrete logarithm.
 *
 * Language L_pok, parameterised only by the domain separation tag:
 *   exists sk in Z_q such that pk = sk*G
 *
 * Instantiations:
 *   pok_sk   key registration during ConfidentialMPTConvert
 *   pi_rec   RecoveryKey registration, ConfidentialMPTHolderKeyUpdate
 *            in recovery mode (see the key rotation proof specification)
 *
 * The two differ in nothing but the tag and the transaction context digest, so
 * they share this implementation rather than forking a near-copy.  The tag also
 * personalises the deterministic nonce derivation, so the same (pk, sk) under
 * two tags never reuses a nonce.
 *
 * Compact proof: (e, s) in Z_q^2 = 64 bytes.
 *
 * Verification reconstructs T = s*G - e*pk, recomputes the challenge and checks
 * e' == e.
 */
#ifndef MPT_PROOF_POK_SK_H
#define MPT_PROOF_POK_SK_H

#include "mpt_internal.h"
#include "secp256k1_mpt.h"

/** Compact proof size for every instantiation: 2 scalars. */
#define kMPT_POK_SK_PROOF_SIZE (2 * kMPT_SCALAR_SIZE)

/**
 * @brief Prove L_pok.
 *
 * @param proof_out  caller-allocated, exactly kMPT_POK_SK_PROOF_SIZE
 * @param sk         witness; must be a valid seckey
 * @param domain     domain separation tag, ASCII, not NUL-terminated in the hash
 * @param context_id 32-byte transaction context digest, may be NULL
 * @return 1 on success, 0 on failure
 */
int
mpt_pok_sk_prove_tagged(
    secp256k1_context const* ctx,
    unsigned char* proof_out,
    secp256k1_pubkey const* pk,
    unsigned char const* sk,
    char const* domain,
    size_t domain_len,
    unsigned char const* context_id);

/**
 * @brief Verify L_pok.  Returns 1 on accept, 0 on reject or bad argument.
 */
int
mpt_pok_sk_verify_tagged(
    secp256k1_context const* ctx,
    unsigned char const* proof,
    secp256k1_pubkey const* pk,
    char const* domain,
    size_t domain_len,
    unsigned char const* context_id);

#endif /* MPT_PROOF_POK_SK_H */
