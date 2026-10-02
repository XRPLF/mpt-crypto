/**
 * @file proof_rotate_mirror_issuer.c
 * @brief pi_mi - issuer-anchored migration of the issuer mirror.
 *
 * Language L_mi (an instantiation of L_reencrypt, see proof_rotate_core.h):
 *   exists (b, sk_I, r_e') in Z_q^3 such that:
 *     pk_I  = sk_I*G
 *     E2 - sk_I*E1 = b*G          (issuer decrypts the current issuer mirror)
 *     E1'  = r_e'*G
 *     E2'  = b*G + r_e'*pk_I'
 *
 * Compact proof: (e, z_b, z_sk, z_r) in Z_q^4 = 128 bytes.
 *
 * pk_I here is the *current* (pre-rotation) on-ledger issuer key and (E1, E2)
 * the current issuer mirror. Both are resolved entirely from ledger state,
 * per XLS-99's fix for the review's Finding f:pki: preferentially
 * IssuerMirrorEncryptionKey on the holder's MPToken, falling back to
 * InitialIssuerEncryptionKey on the MPTokenIssuance, falling back to the
 * currently registered IssuerEncryptionKey when the mirror has never lagged
 * a rotation. There is no submitter-chosen previous-key transaction field.
 */
#include "proof_rotate_core.h"

/* Prefix-free against every other CMPT_KEY_ROTATION_* tag: differs from
 * MIRROR_AUDITOR_ONLY / MIRROR_HOLDER_ONLY / MIRROR_HOLDER_AUDITOR_ONLY at
 * the third component (ISSUER vs AUDITOR/HOLDER). */
static const char DOMAIN_ROTATE_MIRROR_ISSUER[] =
    "CMPT_KEY_ROTATION_MIRROR_ISSUER_ONLY";

int secp256k1_rotate_mirror_issuer_prove(
    secp256k1_context const *ctx, unsigned char *proof_out, uint64_t balance,
    unsigned char const *sk_I, unsigned char const *r_new,
    secp256k1_pubkey const *pk_I, secp256k1_pubkey const *E1,
    secp256k1_pubkey const *E2, secp256k1_pubkey const *pk_I_new,
    secp256k1_pubkey const *E1_new, secp256k1_pubkey const *E2_new,
    unsigned char const *context_id)
{
  return mpt_rotate_core_prove(ctx, proof_out, balance, sk_I, r_new, pk_I, E1,
                               E2, pk_I_new, E1_new, E2_new,
                               DOMAIN_ROTATE_MIRROR_ISSUER,
                               strlen(DOMAIN_ROTATE_MIRROR_ISSUER), context_id);
}

int secp256k1_rotate_mirror_issuer_verify(
    secp256k1_context const *ctx, unsigned char const *proof,
    secp256k1_pubkey const *pk_I, secp256k1_pubkey const *E1,
    secp256k1_pubkey const *E2, secp256k1_pubkey const *pk_I_new,
    secp256k1_pubkey const *E1_new, secp256k1_pubkey const *E2_new,
    unsigned char const *context_id)
{
  return mpt_rotate_core_verify(ctx, proof, pk_I, E1, E2, pk_I_new, E1_new,
                                E2_new, DOMAIN_ROTATE_MIRROR_ISSUER,
                                strlen(DOMAIN_ROTATE_MIRROR_ISSUER),
                                context_id);
}
