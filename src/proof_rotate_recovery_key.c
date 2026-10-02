/**
 * @file proof_rotate_recovery_key.c
 * @brief pi_rec - holder registers a RecoveryKey after losing sk_H.
 *
 * Language L_rec (an instantiation of L_pok, see proof_pok_sk.h):
 *   exists sk_H' in Z_q such that:
 *     pk_H' = sk_H'*G
 *
 * Compact proof: (e, s) in Z_q^2 = 64 bytes.
 *
 * A holder who has lost sk_H can produce no balance-related witness, so this
 * proves possession of the new key and nothing else.  It reveals no balance
 * information; its sole job is to stop registration of a RecoveryKey the
 * holder does not control.  The balance itself is moved later, by the issuer,
 * via ConfidentialMPTRecoverBalance (pi_recbal).
 *
 * The relation is identical to that of key registration (proof_pok_sk.c) and
 * differs only in the domain tag, so the two share an implementation.  Note
 * that the transaction context digest for this mode carries an empty
 * TxSpecific field: there is no balance state to bind to.
 */
#include "proof_pok_sk.h"

static const char DOMAIN_ROTATE_RECOVERY_KEY[] =
    "CMPT_KEY_ROTATION_HOLDER_RECOVERY";

int secp256k1_rotate_recovery_key_prove(secp256k1_context const *ctx,
                                        unsigned char *proof_out,
                                        unsigned char const *sk_H_recovery,
                                        secp256k1_pubkey const *pk_H_recovery,
                                        unsigned char const *context_id)
{
  return mpt_pok_sk_prove_tagged(
      ctx, proof_out, pk_H_recovery, sk_H_recovery, DOMAIN_ROTATE_RECOVERY_KEY,
      strlen(DOMAIN_ROTATE_RECOVERY_KEY), context_id);
}

int secp256k1_rotate_recovery_key_verify(secp256k1_context const *ctx,
                                         unsigned char const *proof,
                                         secp256k1_pubkey const *pk_H_recovery,
                                         unsigned char const *context_id)
{
  return mpt_pok_sk_verify_tagged(
      ctx, proof, pk_H_recovery, DOMAIN_ROTATE_RECOVERY_KEY,
      strlen(DOMAIN_ROTATE_RECOVERY_KEY), context_id);
}
