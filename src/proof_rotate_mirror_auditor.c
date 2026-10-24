/**
 * @file proof_rotate_mirror_auditor.c
 * @brief pi_ma - issuer-anchored migration of the auditor mirror.
 *
 * Language L_ma (an instantiation of L_reencrypt, see proof_rotate_core.h):
 *   exists (b, sk_I, r_a') in Z_q^3 such that:
 *     pk_I  = sk_I*G
 *     E2 - sk_I*E1 = b*G          (issuer decrypts the issuer mirror)
 *     F1'   = r_a'*G
 *     F2'   = b*G + r_a'*pk_A'
 *
 * Compact proof: (e, z_b, z_sk, z_r) in Z_q^4 = 128 bytes.
 *
 * Covers both auditor rotation (flow 2, stale auditor mirror) and auditor
 * late registration (flow 4, absent auditor mirror): the ledger-state
 * precondition differs between the two, the relation does not.  pk_I and
 * (E1, E2) are the current on-ledger issuer key and issuer mirror; no
 * previous-key field is required, since the issuer does not hold the
 * auditor secret and the balance necessarily comes from the issuer mirror.
 */
#include "proof_rotate_core.h"

/* Prefix-free against every other CMPT_KEY_ROTATION_* tag: differs from
 * MIRROR_HOLDER_ONLY / MIRROR_HOLDER_AUDITOR_ONLY at the third component
 * (AUDITOR vs HOLDER), and from the (reserved, not yet implemented)
 * MIRROR_ISSUER_ONLY tag at the same position. */
static const char DOMAIN_ROTATE_MIRROR_AUDITOR[] =
    "CMPT_KEY_ROTATION_MIRROR_AUDITOR_ONLY";

int secp256k1_rotate_mirror_auditor_prove(
    secp256k1_context const *ctx, unsigned char *proof_out, uint64_t balance,
    unsigned char const *sk_I, unsigned char const *r_new,
    secp256k1_pubkey const *pk_I, secp256k1_pubkey const *E1,
    secp256k1_pubkey const *E2, secp256k1_pubkey const *pk_A_new,
    secp256k1_pubkey const *F1_new, secp256k1_pubkey const *F2_new,
    unsigned char const *context_id)
{
  return mpt_rotate_core_prove(
      ctx, proof_out, balance, sk_I, r_new, pk_I, E1, E2, pk_A_new, F1_new,
      F2_new, DOMAIN_ROTATE_MIRROR_AUDITOR,
      strlen(DOMAIN_ROTATE_MIRROR_AUDITOR), context_id);
}

int secp256k1_rotate_mirror_auditor_verify(
    secp256k1_context const *ctx, unsigned char const *proof,
    secp256k1_pubkey const *pk_I, secp256k1_pubkey const *E1,
    secp256k1_pubkey const *E2, secp256k1_pubkey const *pk_A_new,
    secp256k1_pubkey const *F1_new, secp256k1_pubkey const *F2_new,
    unsigned char const *context_id)
{
  return mpt_rotate_core_verify(ctx, proof, pk_I, E1, E2, pk_A_new, F1_new,
                                F2_new, DOMAIN_ROTATE_MIRROR_AUDITOR,
                                strlen(DOMAIN_ROTATE_MIRROR_AUDITOR),
                                context_id);
}
