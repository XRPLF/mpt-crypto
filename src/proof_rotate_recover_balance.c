/**
 * @file proof_rotate_recover_balance.c
 * @brief pi_recbal - issuer completes holder key-loss recovery.
 *
 * Language L_recbal (an instantiation of L_reencrypt, see proof_rotate_core.h):
 *   exists (b, sk_I, r_s') in Z_q^3 such that:
 *     pk_I        = sk_I*G
 *     E2 - sk_I*E1= b*G          (issuer decrypts the issuer mirror)
 *     S1'         = r_s'*G
 *     S2'         = b*G + r_s'*pk_H'
 *
 * Compact proof: (e, z_b, z_sk, z_r) in Z_q^4 = 128 bytes.
 *
 * Preconditions enforced by the ledger: the issuer mirror must already sit at
 * the current issuer key epoch, and pk_H' must be the RecoveryKey registered
 * earlier by the holder.  pk_I here is the current IssuerEncryptionKey read
 * from state.
 */
#include "proof_rotate_core.h"

static const char DOMAIN_ROTATE_RECOVER_BALANCE[] =
    "CMPT_KEY_ROTATION_RECOVER_BALANCE";

int secp256k1_rotate_recover_balance_prove(
    secp256k1_context const *ctx, unsigned char *proof_out, uint64_t balance,
    unsigned char const *sk_I, unsigned char const *r_new,
    secp256k1_pubkey const *pk_I, secp256k1_pubkey const *E1,
    secp256k1_pubkey const *E2, secp256k1_pubkey const *pk_H_recovery,
    secp256k1_pubkey const *S1_new, secp256k1_pubkey const *S2_new,
    unsigned char const *context_id)
{
  return mpt_rotate_core_prove(
      ctx, proof_out, balance, sk_I, r_new, pk_I, E1, E2, pk_H_recovery, S1_new,
      S2_new, DOMAIN_ROTATE_RECOVER_BALANCE,
      strlen(DOMAIN_ROTATE_RECOVER_BALANCE), context_id);
}

int secp256k1_rotate_recover_balance_verify(
    secp256k1_context const *ctx, unsigned char const *proof,
    secp256k1_pubkey const *pk_I, secp256k1_pubkey const *E1,
    secp256k1_pubkey const *E2, secp256k1_pubkey const *pk_H_recovery,
    secp256k1_pubkey const *S1_new, secp256k1_pubkey const *S2_new,
    unsigned char const *context_id)
{
  return mpt_rotate_core_verify(ctx, proof, pk_I, E1, E2, pk_H_recovery, S1_new,
                                S2_new, DOMAIN_ROTATE_RECOVER_BALANCE,
                                strlen(DOMAIN_ROTATE_RECOVER_BALANCE),
                                context_id);
}
