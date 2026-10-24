/**
 * @file proof_rotate_mirror_both_holder.c
 * @brief Holder-anchored AND-composed migration of both mirrors at once.
 *
 * Decrypts the holder's own ConfidentialBalanceSpending (S1, S2) under
 * pk_H, and simultaneously re-encrypts to a new issuer mirror (E1', E2')
 * under pk_I' and a new auditor mirror (F1', F2') under pk_A', sharing one
 * randomness value across both new ciphertexts (see
 * proof_rotate_both_core.h).
 *
 * This is the review's fix for Finding f:mhaud: the original specification
 * gave this variant in prose only, with the shared-randomness equality
 * check (E1' == F1') stated as something validators "may" perform rather
 * than mandatory -- so nothing bound the auditor first component and a
 * prover could submit a mismatched one undetected. Promoted here to a full
 * relation matching the issuer-anchored analogue, with that equality
 * enforced unconditionally by mpt_rotate_both_core_verify.
 *
 * Ledger precondition, not proven here: ConfidentialBalanceInbox == EncZero.
 */
#include "proof_rotate_both_core.h"

/* Prefix-free against every other CMPT_KEY_ROTATION_* tag: shares the
 * "CMPT_KEY_ROTATION_MIRROR_HOLDER_" prefix with MIRROR_HOLDER_ONLY and
 * MIRROR_HOLDER_AUDITOR_ONLY but diverges immediately after ("AND" vs "ONLY"
 * / "AUDITOR"). */
static const char DOMAIN_ROTATE_MIRROR_BOTH_HOLDER[] =
    "CMPT_KEY_ROTATION_MIRROR_HOLDER_AND_AUDITOR";

int secp256k1_rotate_mirror_both_holder_prove(
    secp256k1_context const *ctx, unsigned char *proof_out, uint64_t balance,
    unsigned char const *sk_H, unsigned char const *r_new,
    secp256k1_pubkey const *pk_H, secp256k1_pubkey const *S1,
    secp256k1_pubkey const *S2, secp256k1_pubkey const *pk_I_new,
    secp256k1_pubkey const *pk_A_new, secp256k1_pubkey const *E1_new,
    secp256k1_pubkey const *E2_new, secp256k1_pubkey const *F1_new,
    secp256k1_pubkey const *F2_new, unsigned char const *context_id)
{
  return mpt_rotate_both_core_prove(
      ctx, proof_out, balance, sk_H, r_new, pk_H, S1, S2, pk_I_new, pk_A_new,
      E1_new, E2_new, F1_new, F2_new, DOMAIN_ROTATE_MIRROR_BOTH_HOLDER,
      strlen(DOMAIN_ROTATE_MIRROR_BOTH_HOLDER), context_id);
}

int secp256k1_rotate_mirror_both_holder_verify(
    secp256k1_context const *ctx, unsigned char const *proof,
    secp256k1_pubkey const *pk_H, secp256k1_pubkey const *S1,
    secp256k1_pubkey const *S2, secp256k1_pubkey const *pk_I_new,
    secp256k1_pubkey const *pk_A_new, secp256k1_pubkey const *E1_new,
    secp256k1_pubkey const *E2_new, secp256k1_pubkey const *F1_new,
    secp256k1_pubkey const *F2_new, unsigned char const *context_id)
{
  return mpt_rotate_both_core_verify(
      ctx, proof, pk_H, S1, S2, pk_I_new, pk_A_new, E1_new, E2_new, F1_new,
      F2_new, DOMAIN_ROTATE_MIRROR_BOTH_HOLDER,
      strlen(DOMAIN_ROTATE_MIRROR_BOTH_HOLDER), context_id);
}
