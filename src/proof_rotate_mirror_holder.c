/**
 * @file proof_rotate_mirror_holder.c
 * @brief pi_mh - holder self-migration of the issuer mirror.
 *
 * Language L_mh (an instantiation of L_reencrypt, see proof_rotate_core.h):
 *   exists (b, sk_H, r_e') in Z_q^3 such that:
 *     pk_H        = sk_H*G
 *     S2 - sk_H*S1= b*G          (holder decrypts their own CBS)
 *     E1'         = r_e'*G
 *     E2'         = b*G + r_e'*pk_I'
 *
 * Compact proof: (e, z_b, z_sk, z_r) in Z_q^4 = 128 bytes.
 *
 * Preconditions enforced by the ledger, not by this proof:
 * ConfidentialBalanceInbox must be canonical encrypted zero, and pk_H / (S1,S2)
 * / pk_I' are read from authenticated ledger state rather than supplied by the
 * transaction.
 */
#include "proof_rotate_core.h"

/* The _ONLY suffix keeps the tag set prefix-free: without it this tag would be
 * a prefix of CMPT_KEY_ROTATION_MIRROR_HOLDER_AUDITOR_ONLY, and tags are hashed
 * with strlen and no length prefix.  See the prefix-free remark in the
 * specification. */
static const char DOMAIN_ROTATE_MIRROR_HOLDER[] =
    "CMPT_KEY_ROTATION_MIRROR_HOLDER_ONLY";

int secp256k1_rotate_mirror_holder_prove(
    secp256k1_context const *ctx, unsigned char *proof_out, uint64_t balance,
    unsigned char const *sk_H, unsigned char const *r_new,
    secp256k1_pubkey const *pk_H, secp256k1_pubkey const *S1,
    secp256k1_pubkey const *S2, secp256k1_pubkey const *pk_I_new,
    secp256k1_pubkey const *E1_new, secp256k1_pubkey const *E2_new,
    unsigned char const *context_id)
{
  return mpt_rotate_core_prove(ctx, proof_out, balance, sk_H, r_new, pk_H, S1,
                               S2, pk_I_new, E1_new, E2_new,
                               DOMAIN_ROTATE_MIRROR_HOLDER,
                               strlen(DOMAIN_ROTATE_MIRROR_HOLDER), context_id);
}

int secp256k1_rotate_mirror_holder_verify(
    secp256k1_context const *ctx, unsigned char const *proof,
    secp256k1_pubkey const *pk_H, secp256k1_pubkey const *S1,
    secp256k1_pubkey const *S2, secp256k1_pubkey const *pk_I_new,
    secp256k1_pubkey const *E1_new, secp256k1_pubkey const *E2_new,
    unsigned char const *context_id)
{
  return mpt_rotate_core_verify(ctx, proof, pk_H, S1, S2, pk_I_new, E1_new,
                                E2_new, DOMAIN_ROTATE_MIRROR_HOLDER,
                                strlen(DOMAIN_ROTATE_MIRROR_HOLDER),
                                context_id);
}
