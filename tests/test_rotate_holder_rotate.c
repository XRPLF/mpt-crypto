/* Round-trip and negative tests for pi_hr, holder voluntary key rotation.
 *
 * Relation under test:
 *   pk_H  = sk_H*G
 *   S2 - sk_H*S1   = b*G
 *   S1'            = r_s'*G
 *   S2'            = b*G + r_s'*pk_H'
 *   pk_H'          = sk_H'*G
 *   I2 - sk_H*I1   = b_in*G
 *   I1'            = r_i'*G
 *   I2'            = b_in*G + r_i'*pk_H'
 *
 * Both balance and inbox_balance may legitimately be zero, so both are
 * covered explicitly.
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

typedef struct
{
  unsigned char sk_H[32], r_s_old[32], r_s_new[32], sk_H_new[32];
  unsigned char r_i_old[32], r_i_new[32], context_id[32];
  secp256k1_pubkey pk_H, pk_H_new;
  secp256k1_pubkey S1, S2, S1_new, S2_new;
  secp256k1_pubkey I1, I2, I1_new, I2_new;
} hr_case;

static void build_case(secp256k1_context const *ctx, hr_case *c,
                       uint64_t balance, uint64_t inbox_balance)
{
  random_scalar(ctx, c->sk_H);
  random_scalar(ctx, c->r_s_old);
  random_scalar(ctx, c->r_s_new);
  random_scalar(ctx, c->sk_H_new);
  random_scalar(ctx, c->r_i_old);
  random_scalar(ctx, c->r_i_new);
  random_bytes(c->context_id);

  EXPECT(secp256k1_ec_pubkey_create(ctx, &c->pk_H, c->sk_H));
  EXPECT(secp256k1_ec_pubkey_create(ctx, &c->pk_H_new, c->sk_H_new));

  make_ct(ctx, &c->S1, &c->S2, balance, c->r_s_old, &c->pk_H);
  make_ct(ctx, &c->S1_new, &c->S2_new, balance, c->r_s_new, &c->pk_H_new);
  make_ct(ctx, &c->I1, &c->I2, inbox_balance, c->r_i_old, &c->pk_H);
  make_ct(ctx, &c->I1_new, &c->I2_new, inbox_balance, c->r_i_new, &c->pk_H_new);
}

static void run_case(secp256k1_context const *ctx, uint64_t balance,
                     uint64_t inbox_balance, int negatives, char const *label)
{
  printf("\n--- pi_hr %s (balance=%llu, inbox=%llu) ---\n", label,
         (unsigned long long)balance, (unsigned long long)inbox_balance);

  hr_case c;
  build_case(ctx, &c, balance, inbox_balance);
  unsigned char proof[SECP256K1_ROTATE_HOLDER_ROTATE_PROOF_SIZE];

  EXPECT(secp256k1_rotate_holder_rotate_prove(
      ctx, proof, balance, inbox_balance, c.sk_H, c.r_s_new, c.sk_H_new,
      c.r_i_new, &c.pk_H, &c.pk_H_new, &c.S1, &c.S2, &c.S1_new, &c.S2_new,
      &c.I1, &c.I2, &c.I1_new, &c.I2_new, c.context_id));
  EXPECT(secp256k1_rotate_holder_rotate_verify(
      ctx, proof, &c.pk_H, &c.pk_H_new, &c.S1, &c.S2, &c.S1_new, &c.S2_new,
      &c.I1, &c.I2, &c.I1_new, &c.I2_new, c.context_id));
  printf("  round-trip OK\n");

  if (!negatives)
    return;

  /* Each response scalar tampered. */
  for (int off = 0; off < SECP256K1_ROTATE_HOLDER_ROTATE_PROOF_SIZE; off += 32)
  {
    unsigned char bad[SECP256K1_ROTATE_HOLDER_ROTATE_PROOF_SIZE];
    memcpy(bad, proof, sizeof(bad));
    bad[off + 31] ^= 0x01;
    EXPECT(!secp256k1_rotate_holder_rotate_verify(
        ctx, bad, &c.pk_H, &c.pk_H_new, &c.S1, &c.S2, &c.S1_new, &c.S2_new,
        &c.I1, &c.I2, &c.I1_new, &c.I2_new, c.context_id));
  }
  printf("  tampered scalars rejected (7/7)\n");

  /* Wrong / absent context id. */
  {
    unsigned char other[32];
    random_bytes(other);
    EXPECT(!secp256k1_rotate_holder_rotate_verify(
        ctx, proof, &c.pk_H, &c.pk_H_new, &c.S1, &c.S2, &c.S1_new, &c.S2_new,
        &c.I1, &c.I2, &c.I1_new, &c.I2_new, other));
    EXPECT(!secp256k1_rotate_holder_rotate_verify(
        ctx, proof, &c.pk_H, &c.pk_H_new, &c.S1, &c.S2, &c.S1_new, &c.S2_new,
        &c.I1, &c.I2, &c.I1_new, &c.I2_new, NULL));
  }
  printf("  wrong / absent context_id rejected\n");

  /* Each statement point swapped for an unrelated valid point. */
  {
    unsigned char junk[32];
    secp256k1_pubkey J;
    random_scalar(ctx, junk);
    EXPECT(secp256k1_ec_pubkey_create(ctx, &J, junk));

    EXPECT(!secp256k1_rotate_holder_rotate_verify(
        ctx, proof, &J, &c.pk_H_new, &c.S1, &c.S2, &c.S1_new, &c.S2_new, &c.I1,
        &c.I2, &c.I1_new, &c.I2_new, c.context_id));
    EXPECT(!secp256k1_rotate_holder_rotate_verify(
        ctx, proof, &c.pk_H, &J, &c.S1, &c.S2, &c.S1_new, &c.S2_new, &c.I1,
        &c.I2, &c.I1_new, &c.I2_new, c.context_id));
    EXPECT(!secp256k1_rotate_holder_rotate_verify(
        ctx, proof, &c.pk_H, &c.pk_H_new, &J, &c.S2, &c.S1_new, &c.S2_new,
        &c.I1, &c.I2, &c.I1_new, &c.I2_new, c.context_id));
    EXPECT(!secp256k1_rotate_holder_rotate_verify(
        ctx, proof, &c.pk_H, &c.pk_H_new, &c.S1, &J, &c.S1_new, &c.S2_new,
        &c.I1, &c.I2, &c.I1_new, &c.I2_new, c.context_id));
    EXPECT(!secp256k1_rotate_holder_rotate_verify(
        ctx, proof, &c.pk_H, &c.pk_H_new, &c.S1, &c.S2, &J, &c.S2_new, &c.I1,
        &c.I2, &c.I1_new, &c.I2_new, c.context_id));
    EXPECT(!secp256k1_rotate_holder_rotate_verify(
        ctx, proof, &c.pk_H, &c.pk_H_new, &c.S1, &c.S2, &c.S1_new, &J, &c.I1,
        &c.I2, &c.I1_new, &c.I2_new, c.context_id));
    EXPECT(!secp256k1_rotate_holder_rotate_verify(
        ctx, proof, &c.pk_H, &c.pk_H_new, &c.S1, &c.S2, &c.S1_new, &c.S2_new,
        &J, &c.I2, &c.I1_new, &c.I2_new, c.context_id));
    EXPECT(!secp256k1_rotate_holder_rotate_verify(
        ctx, proof, &c.pk_H, &c.pk_H_new, &c.S1, &c.S2, &c.S1_new, &c.S2_new,
        &c.I1, &J, &c.I1_new, &c.I2_new, c.context_id));
    EXPECT(!secp256k1_rotate_holder_rotate_verify(
        ctx, proof, &c.pk_H, &c.pk_H_new, &c.S1, &c.S2, &c.S1_new, &c.S2_new,
        &c.I1, &c.I2, &J, &c.I2_new, c.context_id));
    EXPECT(!secp256k1_rotate_holder_rotate_verify(
        ctx, proof, &c.pk_H, &c.pk_H_new, &c.S1, &c.S2, &c.S1_new, &c.S2_new,
        &c.I1, &c.I2, &c.I1_new, &J, c.context_id));
  }
  printf("  substituted statement points rejected (10/10)\n");

  /* A prover claiming an inbox balance it cannot decrypt to must fail: the
   * whole point of the fix is that a mismatched CBIN is now caught. */
  {
    unsigned char bad_proof[SECP256K1_ROTATE_HOLDER_ROTATE_PROOF_SIZE];
    secp256k1_pubkey J1, J2;
    make_ct(ctx, &J1, &J2, inbox_balance + 1, c.r_i_new, &c.pk_H_new);
    if (secp256k1_rotate_holder_rotate_prove(
            ctx, bad_proof, balance, inbox_balance + 1, c.sk_H, c.r_s_new,
            c.sk_H_new, c.r_i_new, &c.pk_H, &c.pk_H_new, &c.S1, &c.S2,
            &c.S1_new, &c.S2_new, &c.I1, &c.I2, &J1, &J2, c.context_id))
    {
      EXPECT(!secp256k1_rotate_holder_rotate_verify(
          ctx, bad_proof, &c.pk_H, &c.pk_H_new, &c.S1, &c.S2, &c.S1_new,
          &c.S2_new, &c.I1, &c.I2, &J1, &J2, c.context_id));
    }
  }
  printf("  mismatched inbox balance rejected\n");

  /* A prover who does not know sk_H' for the claimed new key must fail. */
  {
    unsigned char proof2[SECP256K1_ROTATE_HOLDER_ROTATE_PROOF_SIZE];
    unsigned char wrong_sk[32];
    random_scalar(ctx, wrong_sk);
    if (secp256k1_rotate_holder_rotate_prove(
            ctx, proof2, balance, inbox_balance, c.sk_H, c.r_s_new, wrong_sk,
            c.r_i_new, &c.pk_H, &c.pk_H_new, &c.S1, &c.S2, &c.S1_new, &c.S2_new,
            &c.I1, &c.I2, &c.I1_new, &c.I2_new, c.context_id))
    {
      EXPECT(!secp256k1_rotate_holder_rotate_verify(
          ctx, proof2, &c.pk_H, &c.pk_H_new, &c.S1, &c.S2, &c.S1_new, &c.S2_new,
          &c.I1, &c.I2, &c.I1_new, &c.I2_new, c.context_id));
    }
  }
  printf("  new-key possession mismatch rejected\n");
}

int main(void)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                    SECP256K1_CONTEXT_VERIFY);
  EXPECT(ctx != NULL);

  printf("=== pi_hr: holder key rotation (spending + inbox) ===\n");

  run_case(ctx, 1234567, 42, 1, "typical balances");
  run_case(ctx, 0, 0, 1, "zero balances");
  run_case(ctx, UINT64_MAX, 0, 0, "max spending balance");
  run_case(ctx, 0, UINT64_MAX, 0, "max inbox balance");

  secp256k1_context_destroy(ctx);
  printf("\nAll pi_hr tests passed.\n");
  return 0;
}
