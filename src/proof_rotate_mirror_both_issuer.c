/**
 * @file proof_rotate_mirror_both_issuer.c
 * @brief Issuer-anchored AND-composed migration of both mirrors at once.
 *
 * Decrypts the current issuer mirror (E1, E2) under the current pk_I, and
 * simultaneously re-encrypts to a new issuer mirror (E1', E2') under pk_I'
 * and a new auditor mirror (F1', F2') under pk_A', sharing one randomness
 * value across both new ciphertexts (see proof_rotate_both_core.h).
 *
 * pk_I and (E1, E2) are resolved from ledger state exactly as in pi_mi
 * (proof_rotate_mirror_issuer.c) -- no submitter-chosen previous-key field.
 */
#include "proof_rotate_both_core.h"

/* Prefix-free against every other CMPT_KEY_ROTATION_* tag: shares the
 * "CMPT_KEY_ROTATION_MIRROR_ISSUER_" prefix with MIRROR_ISSUER_ONLY but
 * diverges immediately after ("AND" vs "ONLY"). */
static const char DOMAIN_ROTATE_MIRROR_BOTH_ISSUER[] =
    "CMPT_KEY_ROTATION_MIRROR_ISSUER_AND_AUDITOR";

int secp256k1_rotate_mirror_both_issuer_prove(
    secp256k1_context const *ctx, unsigned char *proof_out, uint64_t balance,
    unsigned char const *sk_I, unsigned char const *r_new,
    secp256k1_pubkey const *pk_I, secp256k1_pubkey const *E1,
    secp256k1_pubkey const *E2, secp256k1_pubkey const *pk_I_new,
    secp256k1_pubkey const *pk_A_new, secp256k1_pubkey const *E1_new,
    secp256k1_pubkey const *E2_new, secp256k1_pubkey const *F1_new,
    secp256k1_pubkey const *F2_new, unsigned char const *context_id)
{
  return mpt_rotate_both_core_prove(
      ctx, proof_out, balance, sk_I, r_new, pk_I, E1, E2, pk_I_new, pk_A_new,
      E1_new, E2_new, F1_new, F2_new, DOMAIN_ROTATE_MIRROR_BOTH_ISSUER,
      strlen(DOMAIN_ROTATE_MIRROR_BOTH_ISSUER), context_id);
}

int secp256k1_rotate_mirror_both_issuer_verify(
    secp256k1_context const *ctx, unsigned char const *proof,
    secp256k1_pubkey const *pk_I, secp256k1_pubkey const *E1,
    secp256k1_pubkey const *E2, secp256k1_pubkey const *pk_I_new,
    secp256k1_pubkey const *pk_A_new, secp256k1_pubkey const *E1_new,
    secp256k1_pubkey const *E2_new, secp256k1_pubkey const *F1_new,
    secp256k1_pubkey const *F2_new, unsigned char const *context_id)
{
  return mpt_rotate_both_core_verify(
      ctx, proof, pk_I, E1, E2, pk_I_new, pk_A_new, E1_new, E2_new, F1_new,
      F2_new, DOMAIN_ROTATE_MIRROR_BOTH_ISSUER,
      strlen(DOMAIN_ROTATE_MIRROR_BOTH_ISSUER), context_id);
}
