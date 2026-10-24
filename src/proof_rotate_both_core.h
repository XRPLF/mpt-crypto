/**
 * @file proof_rotate_both_core.h
 * @brief Shared AND-composed re-encryption sigma core: one decryption anchor,
 * two simultaneous re-encryption targets sharing a single randomness value.
 *
 * Covers the two "both mirrors" key-rotation flows (issuer-anchored and
 * holder-anchored), per the key rotation proof review's fix for Finding
 * f:mhaud: the holder-anchored variant was originally prose-only, with its
 * shared-randomness equality check stated as something validators "may"
 * perform rather than as a mandatory verifier step -- the exact gap that let
 * a prover submit a mismatched auditor first component undetected. The fix
 * promotes it to a full relation matching the issuer-anchored analogue,
 * with that equality as a mandatory check.
 *
 * Language L_reencrypt_both, parameterised by (pk_anchor, C1, C2, pk_target1,
 * pk_target2, D1_1, D2_1, D1_2, D2_2):
 *   exists (b, sk, r) in Z_q^3 such that:
 *     pk_anchor    = sk*G
 *     C2 - sk*C1   = b*G
 *     D1_1         = r*G
 *     D2_1         = b*G + r*pk_target1
 *     D1_2        == D1_1                      (mandatory, not a sigma conjunct)
 *     D2_2         = b*G + r*pk_target2
 *
 * D1_1 and D1_2 are the transmitted first components of the two new
 * ciphertexts (one per target). The relation reuses a single randomness r
 * for both re-encryptions -- this is what keeps the proof at 4 scalars
 * rather than needing a second (D1, D2) pair -- but nothing in the sigma
 * algebra itself constrains D1_2: it does not appear in any reconstruction
 * equation. The D1_2 == D1_1 check MUST be performed by the verifier as an
 * unconditional precondition, not treated as implied by the proof.
 *
 * Instantiations:
 *   both-issuer  IEB  under pk_I -> IEB' under pk_I' AND AEB' under pk_A'
 *   both-holder  CBS  under pk_H -> IEB' under pk_I' AND AEB' under pk_A'
 *
 * Compact proof: (e, z_b, z_sk, z_r) in Z_q^4 = 128 bytes.
 *
 * Verification reconstructs:
 *   T1 = z_sk*G - e*pk_anchor
 *   T2 = z_b*G + z_sk*C1 - e*C2
 *   T3 = z_r*G - e*D1_1
 *   T4 = z_b*G + z_r*pk_target1 - e*D2_1
 *   T6 = z_b*G + z_r*pk_target2 - e*D2_2
 * (T5 is reserved for the D1_2 == D1_1 mandatory check, which is not itself
 * a reconstruction equation) then recomputes the challenge over the full
 * statement -- including D1_2, per the review's fix -- and checks e' == e.
 *
 * The balance b is a uint64 and may legitimately be zero; see
 * proof_rotate_core.h for the same convention and rationale.
 */
#ifndef MPT_PROOF_ROTATE_BOTH_CORE_H
#define MPT_PROOF_ROTATE_BOTH_CORE_H

#include "mpt_internal.h"
#include "secp256k1_mpt.h"

/** Compact proof size for every instantiation of the core: 4 scalars. */
#define kMPT_ROTATE_BOTH_CORE_PROOF_SIZE (4 * kMPT_SCALAR_SIZE)

/**
 * @brief Prove L_reencrypt_both.
 *
 * @param proof_out  caller-allocated, exactly kMPT_ROTATE_BOTH_CORE_PROOF_SIZE
 * @param balance    plaintext b; zero is legal
 * @param sk_anchor  decryption witness for (C1, C2); must be a valid seckey
 * @param r_new      fresh randomness shared by both new ciphertexts; must be
 *                   a valid seckey, and must not be reused across
 *                   transactions or holders
 * @param D1_1       first component of the new ciphertext under pk_target1
 * @param D2_1       second component of the new ciphertext under pk_target1
 * @param D1_2       first component of the new ciphertext under pk_target2;
 *                   MUST equal D1_1 -- the caller constructs both new
 *                   ciphertexts from the same r_new
 * @param D2_2       second component of the new ciphertext under pk_target2
 * @param domain     domain separation tag, ASCII, not NUL-terminated in hash
 * @param context_id 32-byte transaction context digest, may be NULL
 * @return 1 on success, 0 on failure
 */
int
mpt_rotate_both_core_prove(
    secp256k1_context const* ctx,
    unsigned char* proof_out,
    uint64_t balance,
    unsigned char const* sk_anchor,
    unsigned char const* r_new,
    secp256k1_pubkey const* pk_anchor,
    secp256k1_pubkey const* C1,
    secp256k1_pubkey const* C2,
    secp256k1_pubkey const* pk_target1,
    secp256k1_pubkey const* pk_target2,
    secp256k1_pubkey const* D1_1,
    secp256k1_pubkey const* D2_1,
    secp256k1_pubkey const* D1_2,
    secp256k1_pubkey const* D2_2,
    char const* domain,
    size_t domain_len,
    unsigned char const* context_id);

/**
 * @brief Verify L_reencrypt_both.  Returns 1 on accept, 0 on reject or bad
 * argument. Unconditionally rejects if D1_2 != D1_1, independent of the
 * sigma proof -- this check is the fix for Finding f:mhaud and MUST NOT be
 * skipped or treated as implied by proof acceptance.
 */
int
mpt_rotate_both_core_verify(
    secp256k1_context const* ctx,
    unsigned char const* proof,
    secp256k1_pubkey const* pk_anchor,
    secp256k1_pubkey const* C1,
    secp256k1_pubkey const* C2,
    secp256k1_pubkey const* pk_target1,
    secp256k1_pubkey const* pk_target2,
    secp256k1_pubkey const* D1_1,
    secp256k1_pubkey const* D2_1,
    secp256k1_pubkey const* D1_2,
    secp256k1_pubkey const* D2_2,
    char const* domain,
    size_t domain_len,
    unsigned char const* context_id);

#endif /* MPT_PROOF_ROTATE_BOTH_CORE_H */
