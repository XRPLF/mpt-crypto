/* Round-trip and negative tests for the shared key-rotation re-encryption core,
 * exercised through both public wrappers (pi_mh and pi_recbal).
 *
 * Relation under test:
 *   pk_old      = sk*G
 *   C2 - sk*C1  = b*G
 *   D1          = r*G
 *   D2          = b*G + r*pk_target
 *
 * Balance 0 is a legitimate state, so it is covered explicitly: no public b*G
 * enters the transcript, so unlike the clawback proof there is no point-at-
 * infinity substitution to exercise, but the zero witness must still
 * round-trip.
 */
#include "secp256k1_mpt.h"
#include "test_utils.h"
#include <secp256k1.h>
#include <stdio.h>
#include <string.h>

/* Build an EC-ElGamal ciphertext (r*G, b*G + r*pk), skipping b*G when b == 0.
 */
static void make_ct(secp256k1_context const *ctx, secp256k1_pubkey *c1,
                    secp256k1_pubkey *c2, uint64_t b, unsigned char const *r,
                    secp256k1_pubkey const *pk)
{
  EXPECT(secp256k1_ec_pubkey_create(ctx, c1, r));
  secp256k1_pubkey rpk = *pk;
  EXPECT(secp256k1_ec_pubkey_tweak_mul(ctx, &rpk, r));
  secp256k1_pubkey bG;
  if (value_times_g(ctx, &bG, b))
  {
    secp256k1_pubkey const *pts[2] = {&bG, &rpk};
    EXPECT(secp256k1_ec_pubkey_combine(ctx, c2, pts, 2));
  }
  else
  {
    *c2 = rpk;
  }
}

static void run_holder_case(secp256k1_context const *ctx, uint64_t balance,
                            int negatives, char const *label)
{
  printf("\n--- pi_mh %s (balance=%llu) ---\n", label,
         (unsigned long long)balance);

  unsigned char sk_H[32], r_old[32], r_new[32], sk_I_new[32], context_id[32];
  secp256k1_pubkey pk_H, pk_I_new, S1, S2, E1_new, E2_new;
  unsigned char proof[SECP256K1_ROTATE_REENCRYPT_PROOF_SIZE];

  random_scalar(ctx, sk_H);
  random_scalar(ctx, r_old);
  random_scalar(ctx, r_new);
  random_scalar(ctx, sk_I_new);
  random_bytes(context_id);

  EXPECT(secp256k1_ec_pubkey_create(ctx, &pk_H, sk_H));
  EXPECT(secp256k1_ec_pubkey_create(ctx, &pk_I_new, sk_I_new));

  /* CBS under the holder's key, with accumulated randomness the prover does
   * not know; the proof uses sk_H as the decryption witness instead. */
  make_ct(ctx, &S1, &S2, balance, r_old, &pk_H);
  /* New issuer mirror under the post-rotation issuer key. */
  make_ct(ctx, &E1_new, &E2_new, balance, r_new, &pk_I_new);

  EXPECT(secp256k1_rotate_mirror_holder_prove(ctx, proof, balance, sk_H, r_new,
                                              &pk_H, &S1, &S2, &pk_I_new,
                                              &E1_new, &E2_new, context_id));
  EXPECT(secp256k1_rotate_mirror_holder_verify(
      ctx, proof, &pk_H, &S1, &S2, &pk_I_new, &E1_new, &E2_new, context_id));
  printf("  round-trip OK\n");

  if (!negatives)
    return;

  /* Each response scalar tampered. */
  for (int off = 0; off < SECP256K1_ROTATE_REENCRYPT_PROOF_SIZE; off += 32)
  {
    unsigned char bad[SECP256K1_ROTATE_REENCRYPT_PROOF_SIZE];
    memcpy(bad, proof, sizeof(bad));
    bad[off + 31] ^= 0x01;
    EXPECT(!secp256k1_rotate_mirror_holder_verify(
        ctx, bad, &pk_H, &S1, &S2, &pk_I_new, &E1_new, &E2_new, context_id));
  }
  printf("  tampered scalars rejected (4/4)\n");

  /* Wrong context id. */
  {
    unsigned char other[32];
    random_bytes(other);
    EXPECT(!secp256k1_rotate_mirror_holder_verify(
        ctx, proof, &pk_H, &S1, &S2, &pk_I_new, &E1_new, &E2_new, other));
    /* NULL context is a distinct transcript, not "no binding". */
    EXPECT(!secp256k1_rotate_mirror_holder_verify(
        ctx, proof, &pk_H, &S1, &S2, &pk_I_new, &E1_new, &E2_new, NULL));
  }
  printf("  wrong / absent context_id rejected\n");

  /* Each statement point swapped for an unrelated valid point. */
  {
    unsigned char junk[32];
    secp256k1_pubkey J;
    random_scalar(ctx, junk);
    EXPECT(secp256k1_ec_pubkey_create(ctx, &J, junk));
    EXPECT(!secp256k1_rotate_mirror_holder_verify(
        ctx, proof, &J, &S1, &S2, &pk_I_new, &E1_new, &E2_new, context_id));
    EXPECT(!secp256k1_rotate_mirror_holder_verify(
        ctx, proof, &pk_H, &J, &S2, &pk_I_new, &E1_new, &E2_new, context_id));
    EXPECT(!secp256k1_rotate_mirror_holder_verify(
        ctx, proof, &pk_H, &S1, &J, &pk_I_new, &E1_new, &E2_new, context_id));
    EXPECT(!secp256k1_rotate_mirror_holder_verify(
        ctx, proof, &pk_H, &S1, &S2, &J, &E1_new, &E2_new, context_id));
    EXPECT(!secp256k1_rotate_mirror_holder_verify(
        ctx, proof, &pk_H, &S1, &S2, &pk_I_new, &J, &E2_new, context_id));
    EXPECT(!secp256k1_rotate_mirror_holder_verify(
        ctx, proof, &pk_H, &S1, &S2, &pk_I_new, &E1_new, &J, context_id));
  }
  printf("  substituted statement points rejected (6/6)\n");

  /* A prover claiming a balance it cannot decrypt to must fail. */
  {
    unsigned char bad_proof[SECP256K1_ROTATE_REENCRYPT_PROOF_SIZE];
    secp256k1_pubkey F1, F2;
    make_ct(ctx, &F1, &F2, balance + 1, r_new, &pk_I_new);
    /* Honest prover on a mismatched balance: the new ciphertext encodes
     * balance+1 while CBS still encodes balance. */
    if (secp256k1_rotate_mirror_holder_prove(ctx, bad_proof, balance + 1, sk_H,
                                             r_new, &pk_H, &S1, &S2, &pk_I_new,
                                             &F1, &F2, context_id))
    {
      EXPECT(!secp256k1_rotate_mirror_holder_verify(
          ctx, bad_proof, &pk_H, &S1, &S2, &pk_I_new, &F1, &F2, context_id));
    }
  }
  printf("  mismatched balance rejected\n");
}

static void run_recbal_case(secp256k1_context const *ctx, uint64_t balance)
{
  printf("\n--- pi_recbal (balance=%llu) ---\n", (unsigned long long)balance);

  unsigned char sk_I[32], r_old[32], r_new[32], sk_H_rec[32], context_id[32];
  secp256k1_pubkey pk_I, pk_H_rec, E1, E2, S1_new, S2_new;
  unsigned char proof[SECP256K1_ROTATE_REENCRYPT_PROOF_SIZE];

  random_scalar(ctx, sk_I);
  random_scalar(ctx, r_old);
  random_scalar(ctx, r_new);
  random_scalar(ctx, sk_H_rec);
  random_bytes(context_id);

  EXPECT(secp256k1_ec_pubkey_create(ctx, &pk_I, sk_I));
  EXPECT(secp256k1_ec_pubkey_create(ctx, &pk_H_rec, sk_H_rec));

  make_ct(ctx, &E1, &E2, balance, r_old, &pk_I);
  make_ct(ctx, &S1_new, &S2_new, balance, r_new, &pk_H_rec);

  EXPECT(secp256k1_rotate_recover_balance_prove(
      ctx, proof, balance, sk_I, r_new, &pk_I, &E1, &E2, &pk_H_rec, &S1_new,
      &S2_new, context_id));
  EXPECT(secp256k1_rotate_recover_balance_verify(
      ctx, proof, &pk_I, &E1, &E2, &pk_H_rec, &S1_new, &S2_new, context_id));
  printf("  round-trip OK\n");

  /* Domain separation: a pi_recbal proof must not verify as pi_mh on a
   * statement of the same shape, and vice versa. */
  EXPECT(!secp256k1_rotate_mirror_holder_verify(
      ctx, proof, &pk_I, &E1, &E2, &pk_H_rec, &S1_new, &S2_new, context_id));
  printf("  cross-variant substitution rejected\n");
}

static void run_mirror_issuer_case(secp256k1_context const *ctx,
                                   uint64_t balance)
{
  printf("\n--- pi_mi (balance=%llu) ---\n", (unsigned long long)balance);

  unsigned char sk_I[32], r_old[32], r_new[32], sk_I_new[32], context_id[32];
  secp256k1_pubkey pk_I, pk_I_new, E1, E2, E1_new, E2_new;
  unsigned char proof[SECP256K1_ROTATE_REENCRYPT_PROOF_SIZE];

  random_scalar(ctx, sk_I);
  random_scalar(ctx, r_old);
  random_scalar(ctx, r_new);
  random_scalar(ctx, sk_I_new);
  random_bytes(context_id);

  EXPECT(secp256k1_ec_pubkey_create(ctx, &pk_I, sk_I));
  EXPECT(secp256k1_ec_pubkey_create(ctx, &pk_I_new, sk_I_new));

  /* Current issuer mirror, decrypted by the issuer. */
  make_ct(ctx, &E1, &E2, balance, r_old, &pk_I);
  /* New issuer mirror under the post-rotation issuer key. */
  make_ct(ctx, &E1_new, &E2_new, balance, r_new, &pk_I_new);

  EXPECT(secp256k1_rotate_mirror_issuer_prove(ctx, proof, balance, sk_I, r_new,
                                              &pk_I, &E1, &E2, &pk_I_new,
                                              &E1_new, &E2_new, context_id));
  EXPECT(secp256k1_rotate_mirror_issuer_verify(
      ctx, proof, &pk_I, &E1, &E2, &pk_I_new, &E1_new, &E2_new, context_id));
  printf("  round-trip OK\n");

  /* Domain separation: same statement shape as pi_mh/pi_recbal (issuer
   * mirror to issuer mirror is structurally identical to holder-anchored
   * migration), so the tag alone must carry the distinction. */
  EXPECT(!secp256k1_rotate_mirror_holder_verify(
      ctx, proof, &pk_I, &E1, &E2, &pk_I_new, &E1_new, &E2_new, context_id));
  printf("  cross-variant substitution rejected\n");
}

static void run_mirror_auditor_case(secp256k1_context const *ctx,
                                    uint64_t balance)
{
  printf("\n--- pi_ma (balance=%llu) ---\n", (unsigned long long)balance);

  unsigned char sk_I[32], r_old[32], r_new[32], sk_A_new[32], context_id[32];
  secp256k1_pubkey pk_I, pk_A_new, E1, E2, F1_new, F2_new;
  unsigned char proof[SECP256K1_ROTATE_REENCRYPT_PROOF_SIZE];

  random_scalar(ctx, sk_I);
  random_scalar(ctx, r_old);
  random_scalar(ctx, r_new);
  random_scalar(ctx, sk_A_new);
  random_bytes(context_id);

  EXPECT(secp256k1_ec_pubkey_create(ctx, &pk_I, sk_I));
  EXPECT(secp256k1_ec_pubkey_create(ctx, &pk_A_new, sk_A_new));

  /* Current issuer mirror, decrypted by the issuer. */
  make_ct(ctx, &E1, &E2, balance, r_old, &pk_I);
  /* New auditor mirror under the post-rotation auditor key. */
  make_ct(ctx, &F1_new, &F2_new, balance, r_new, &pk_A_new);

  EXPECT(secp256k1_rotate_mirror_auditor_prove(ctx, proof, balance, sk_I, r_new,
                                               &pk_I, &E1, &E2, &pk_A_new,
                                               &F1_new, &F2_new, context_id));
  EXPECT(secp256k1_rotate_mirror_auditor_verify(
      ctx, proof, &pk_I, &E1, &E2, &pk_A_new, &F1_new, &F2_new, context_id));
  printf("  round-trip OK\n");

  /* Domain separation: must not cross-verify against pi_mi's shape (same
   * statement layout, different tag) via any other implemented variant. */
  EXPECT(!secp256k1_rotate_mirror_holder_verify(
      ctx, proof, &pk_I, &E1, &E2, &pk_A_new, &F1_new, &F2_new, context_id));
  printf("  cross-variant substitution rejected\n");
}

static void run_mirror_holder_auditor_case(secp256k1_context const *ctx,
                                           uint64_t balance)
{
  printf("\n--- pi_mha (balance=%llu) ---\n", (unsigned long long)balance);

  unsigned char sk_H[32], r_old[32], r_new[32], sk_A_new[32], context_id[32];
  secp256k1_pubkey pk_H, pk_A_new, S1, S2, F1_new, F2_new;
  unsigned char proof[SECP256K1_ROTATE_REENCRYPT_PROOF_SIZE];

  random_scalar(ctx, sk_H);
  random_scalar(ctx, r_old);
  random_scalar(ctx, r_new);
  random_scalar(ctx, sk_A_new);
  random_bytes(context_id);

  EXPECT(secp256k1_ec_pubkey_create(ctx, &pk_H, sk_H));
  EXPECT(secp256k1_ec_pubkey_create(ctx, &pk_A_new, sk_A_new));

  /* CBS under the holder's key. */
  make_ct(ctx, &S1, &S2, balance, r_old, &pk_H);
  /* New auditor mirror under the post-rotation auditor key. */
  make_ct(ctx, &F1_new, &F2_new, balance, r_new, &pk_A_new);

  EXPECT(secp256k1_rotate_mirror_holder_auditor_prove(
      ctx, proof, balance, sk_H, r_new, &pk_H, &S1, &S2, &pk_A_new, &F1_new,
      &F2_new, context_id));
  EXPECT(secp256k1_rotate_mirror_holder_auditor_verify(
      ctx, proof, &pk_H, &S1, &S2, &pk_A_new, &F1_new, &F2_new, context_id));
  printf("  round-trip OK\n");

  /* Domain separation from pi_mh: same statement shape (CBS anchor), the new
   * mirror target differs only by which key it names, so the tag alone must
   * carry the distinction. */
  EXPECT(!secp256k1_rotate_mirror_holder_verify(
      ctx, proof, &pk_H, &S1, &S2, &pk_A_new, &F1_new, &F2_new, context_id));
  printf("  cross-variant substitution rejected (pi_mh)\n");
}

int main(void)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                    SECP256K1_CONTEXT_VERIFY);
  EXPECT(ctx != NULL);

  printf("=== key rotation re-encryption core ===\n");

  run_holder_case(ctx, 1234567, 1, "typical balance");
  run_holder_case(ctx, 0, 1, "zero balance");
  run_holder_case(ctx, UINT64_MAX, 0, "max balance");

  run_recbal_case(ctx, 987654);
  run_recbal_case(ctx, 0);

  run_mirror_issuer_case(ctx, 4443210);
  run_mirror_issuer_case(ctx, 0);

  run_mirror_auditor_case(ctx, 5551234);
  run_mirror_auditor_case(ctx, 0);

  run_mirror_holder_auditor_case(ctx, 4242424);
  run_mirror_holder_auditor_case(ctx, 0);

  /* NULL context_id must round-trip on its own terms. */
  {
    unsigned char sk[32], r[32], skt[32];
    secp256k1_pubkey pk, pkt, C1, C2, D1, D2;
    unsigned char proof[SECP256K1_ROTATE_REENCRYPT_PROOF_SIZE];
    random_scalar(ctx, sk);
    random_scalar(ctx, r);
    random_scalar(ctx, skt);
    EXPECT(secp256k1_ec_pubkey_create(ctx, &pk, sk));
    EXPECT(secp256k1_ec_pubkey_create(ctx, &pkt, skt));
    make_ct(ctx, &C1, &C2, 42, r, &pk);
    make_ct(ctx, &D1, &D2, 42, r, &pkt);
    EXPECT(secp256k1_rotate_mirror_holder_prove(ctx, proof, 42, sk, r, &pk, &C1,
                                                &C2, &pkt, &D1, &D2, NULL));
    EXPECT(secp256k1_rotate_mirror_holder_verify(ctx, proof, &pk, &C1, &C2,
                                                 &pkt, &D1, &D2, NULL));
    printf("\n--- NULL context_id round-trip OK ---\n");
  }

  secp256k1_context_destroy(ctx);
  printf("\nAll key-rotation re-encryption tests passed.\n");
  return 0;
}
