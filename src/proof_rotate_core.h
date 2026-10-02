/**
 * @file proof_rotate_core.h
 * @brief Shared re-encryption sigma core for the ElGamal key rotation proofs.
 *
 * Five of the key rotation proof variants are the same relation with different
 * slots filled.  Rather than nine near-identical transcript implementations,
 * they share this core and differ only in which ciphertext plays the
 * decryption side, which public key plays the re-encryption target, and the
 * domain separation tag.
 *
 * Language L_reencrypt, parameterised by (pk_old, C1, C2, pk_target, D1, D2):
 *   exists (b, sk, r) in Z_q^3 such that:
 *     pk_old      = sk*G
 *     C2 - sk*C1  = b*G
 *     D1          = r*G
 *     D2          = b*G + r*pk_target
 *
 * Instantiations (see the key rotation proof specification):
 *   pi_mi      IEB  under pk_I -> IEB' under pk_I'      (issuer mirror)
 *   pi_ma      IEB  under pk_I -> AEB' under pk_A'      (auditor mirror, issuer-anchored)
 *   pi_mh      CBS  under pk_H -> IEB' under pk_I'      (issuer mirror, holder-anchored)
 *   pi_mha     CBS  under pk_H -> AEB' under pk_A'      (auditor mirror, holder-anchored)
 *   pi_recbal  IEB  under pk_I -> CBS' under pk_H'      (balance recovery)
 *
 * Compact proof: (e, z_b, z_sk, z_r) in Z_q^4 = 128 bytes.
 *
 * Verification reconstructs:
 *   T1 = z_sk*G - e*pk_old
 *   T2 = z_b*G + z_sk*C1 - e*C2
 *   T3 = z_r*G - e*D1
 *   T4 = z_b*G + z_r*pk_target - e*D2
 * then recomputes the challenge and checks e' == e.
 *
 * The balance b is a uint64 and may legitimately be zero, so it is converted
 * with mpt_uint64_to_scalar and deliberately not passed through
 * secp256k1_ec_seckey_verify.  No public b*G term enters the transcript, so
 * the point-at-infinity substitution used by the clawback proof is not needed
 * here.
 */
#ifndef MPT_PROOF_ROTATE_CORE_H
#define MPT_PROOF_ROTATE_CORE_H

#include "mpt_internal.h"
#include "secp256k1_mpt.h"

/** Compact proof size for every instantiation of the core: 4 scalars. */
#define kMPT_ROTATE_CORE_PROOF_SIZE (4 * kMPT_SCALAR_SIZE)

/**
 * @brief Prove L_reencrypt.
 *
 * @param proof_out  caller-allocated, exactly kMPT_ROTATE_CORE_PROOF_SIZE
 * @param balance    plaintext b; zero is legal
 * @param sk_old     decryption witness for (C1, C2); must be a valid seckey
 * @param r_new      fresh randomness for (D1, D2); must be a valid seckey, and
 *                   must not be reused across transactions or holders
 * @param domain     domain separation tag, ASCII, not NUL-terminated in the hash
 * @param context_id 32-byte transaction context digest, may be NULL
 * @return 1 on success, 0 on failure
 */
int
mpt_rotate_core_prove(
    secp256k1_context const* ctx,
    unsigned char* proof_out,
    uint64_t balance,
    unsigned char const* sk_old,
    unsigned char const* r_new,
    secp256k1_pubkey const* pk_old,
    secp256k1_pubkey const* C1,
    secp256k1_pubkey const* C2,
    secp256k1_pubkey const* pk_target,
    secp256k1_pubkey const* D1,
    secp256k1_pubkey const* D2,
    char const* domain,
    size_t domain_len,
    unsigned char const* context_id);

/**
 * @brief Verify L_reencrypt.  Returns 1 on accept, 0 on reject or bad argument.
 */
int
mpt_rotate_core_verify(
    secp256k1_context const* ctx,
    unsigned char const* proof,
    secp256k1_pubkey const* pk_old,
    secp256k1_pubkey const* C1,
    secp256k1_pubkey const* C2,
    secp256k1_pubkey const* pk_target,
    secp256k1_pubkey const* D1,
    secp256k1_pubkey const* D2,
    char const* domain,
    size_t domain_len,
    unsigned char const* context_id);

#endif /* MPT_PROOF_ROTATE_CORE_H */
