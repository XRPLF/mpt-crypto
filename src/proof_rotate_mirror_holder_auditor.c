/**
 * @file proof_rotate_mirror_holder_auditor.c
 * @brief pi_mha - holder self-migration of the auditor mirror.
 *
 * Language L_mha (an instantiation of L_reencrypt, see proof_rotate_core.h):
 *   exists (b, sk_H, r_a') in Z_q^3 such that:
 *     pk_H  = sk_H*G
 *     S2 - sk_H*S1 = b*G          (holder decrypts their own CBS)
 *     F1'   = r_a'*G
 *     F2'   = b*G + r_a'*pk_A'
 *
 * Compact proof: (e, z_b, z_sk, z_r) in Z_q^4 = 128 bytes.
 *
 * Structurally identical to pi_mh (proof_rotate_mirror_holder.c) with the
 * auditor mirror in place of the issuer mirror as re-encryption target; a
 * distinct domain tag keeps the two from being interchangeable, since a
 * holder proof migrating the auditor mirror must not verify as one that
 * migrated the issuer mirror.
 *
 * Preconditions enforced by the ledger, not by this proof:
 * ConfidentialBalanceInbox must be canonical encrypted zero, and pk_H / (S1,
 * S2) / pk_A' are read from authenticated ledger state rather than supplied
 * by the transaction.
 */
#include "proof_rotate_core.h"

/* The _ONLY suffix keeps the tag set prefix-free: without it this tag would
 * be a suffix-extension of CMPT_KEY_ROTATION_MIRROR_HOLDER_ONLY (this tag
 * begins with that string plus "_AUDITOR_ONLY"), and tags are hashed with
 * strlen and no length prefix. See the prefix-free remark in the
 * specification and proof_rotate_mirror_holder.c. */
static const char DOMAIN_ROTATE_MIRROR_HOLDER_AUDITOR[] =
    "CMPT_KEY_ROTATION_MIRROR_HOLDER_AUDITOR_ONLY";

int secp256k1_rotate_mirror_holder_auditor_prove(
    secp256k1_context const *ctx, unsigned char *proof_out, uint64_t balance,
    unsigned char const *sk_H, unsigned char const *r_new,
    secp256k1_pubkey const *pk_H, secp256k1_pubkey const *S1,
    secp256k1_pubkey const *S2, secp256k1_pubkey const *pk_A_new,
    secp256k1_pubkey const *F1_new, secp256k1_pubkey const *F2_new,
    unsigned char const *context_id)
{
  return mpt_rotate_core_prove(
      ctx, proof_out, balance, sk_H, r_new, pk_H, S1, S2, pk_A_new, F1_new,
      F2_new, DOMAIN_ROTATE_MIRROR_HOLDER_AUDITOR,
      strlen(DOMAIN_ROTATE_MIRROR_HOLDER_AUDITOR), context_id);
}

int secp256k1_rotate_mirror_holder_auditor_verify(
    secp256k1_context const *ctx, unsigned char const *proof,
    secp256k1_pubkey const *pk_H, secp256k1_pubkey const *S1,
    secp256k1_pubkey const *S2, secp256k1_pubkey const *pk_A_new,
    secp256k1_pubkey const *F1_new, secp256k1_pubkey const *F2_new,
    unsigned char const *context_id)
{
  return mpt_rotate_core_verify(ctx, proof, pk_H, S1, S2, pk_A_new, F1_new,
                                F2_new, DOMAIN_ROTATE_MIRROR_HOLDER_AUDITOR,
                                strlen(DOMAIN_ROTATE_MIRROR_HOLDER_AUDITOR),
                                context_id);
}
