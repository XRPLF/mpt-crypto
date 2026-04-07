#include <openssl/rand.h>
#include <openssl/sha.h>
#include <utility/mpt_utility.h>

#include <secp256k1_mpt.h>

#include <cstring>
#include <iostream>
#include <vector>

// Platform endianness support for serialization
#if defined(_WIN32) || defined(_WIN64)
#include <stdlib.h>
#define MPT_HTOBE16(x) _byteswap_ushort(static_cast<uint16_t>(x))
#define MPT_HTOBE32(x) _byteswap_ulong(static_cast<uint32_t>(x))
#define MPT_HTOBE64(x) _byteswap_uint64(static_cast<uint64_t>(x))

#elif defined(__APPLE__)
#include <libkern/OSByteOrder.h>
#define MPT_HTOBE16(x) OSSwapHostToBigInt16(x)
#define MPT_HTOBE32(x) OSSwapHostToBigInt32(x)
#define MPT_HTOBE64(x) OSSwapHostToBigInt64(x)

#else
#include <endian.h>
#define MPT_HTOBE16(x) htobe16(x)
#define MPT_HTOBE32(x) htobe32(x)
#define MPT_HTOBE64(x) htobe64(x)
#endif

extern "C" {
/**
 * Context for secp256k1 operations.
 * Initialized once and reused across all operations to optimize performance
 */
secp256k1_context*
mpt_secp256k1_context()
{
    struct ContextHolder
    {
        secp256k1_context* ctx;

        ContextHolder()
        {
            ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

            if (ctx)
            {
                unsigned char seed[kMPT_BLINDING_FACTOR_SIZE];

                if (RAND_bytes(seed, kMPT_BLINDING_FACTOR_SIZE) != 1)
                {
                    secp256k1_context_destroy(ctx);
                    ctx = nullptr;
                    return;
                }

                if (secp256k1_context_randomize(ctx, seed) != 1)
                {
                    secp256k1_context_destroy(ctx);
                    ctx = nullptr;
                }
            }
        }

        ~ContextHolder()
        {
            if (ctx)
                secp256k1_context_destroy(ctx);
        }
    };

    static ContextHolder holder;
    return holder.ctx;
}
}  // extern "C"

/**
 * @internal
 * Private helper to generate aggregated bulletproofs
 */
static int
mpt_get_bulletproof_agg(
    uint64_t const* values,
    uint8_t const* const* blinding_ptrs,
    size_t m,
    uint8_t const context_hash[kMPT_HALF_SHA_SIZE],
    uint8_t* out_proof,
    size_t* out_len)
{
    if ((m != 1 && m != 2) || !values || !blinding_ptrs || !out_proof || !out_len)
        return -1;

    secp256k1_context const* ctx = mpt_secp256k1_context();

    uint8_t blindings_flat[64];
    for (size_t i = 0; i < m; ++i)
    {
        if (!blinding_ptrs[i])
            return -1;
        std::memcpy(blindings_flat + (i * 32), blinding_ptrs[i], 32);
    }

    secp256k1_pubkey pk_base;
    if (secp256k1_mpt_get_h_generator(ctx, &pk_base) != 1)
        return -1;

    if (secp256k1_bulletproof_prove_agg(
            ctx, out_proof, out_len, values, blindings_flat, m, &pk_base, context_hash) != 1)
    {
        return -1;
    }

    size_t const expected = (m == 1) ? kMPT_SINGLE_BULLETPROOF_SIZE : kMPT_DOUBLE_BULLETPROOF_SIZE;
    if (*out_len != expected)
        return -1;

    return 0;
}

/**
 * Lightweight serializer.
 * Replicates the behavior of rippled's Serializer without the overhead.
 */
struct Serializer
{
    uint8_t* buffer;
    size_t capacity;
    size_t offset = 0;
    bool overflow = false;

    Serializer(uint8_t* buf, size_t cap) : buffer(buf), capacity(cap)
    {
    }

    // User should check isValid() after serialization to ensure no overflow occurred
    bool
    isValid() const
    {
        return !overflow;
    }

    void
    add16(uint16_t val)
    {
        if (overflow || offset + sizeof(val) > capacity)
        {
            overflow = true;
            return;
        }

        uint16_t n = MPT_HTOBE16(val);
        memcpy(buffer + offset, &n, sizeof(val));
        offset += sizeof(val);
    }

    void
    add32(uint32_t val)
    {
        if (overflow || offset + sizeof(val) > capacity)
        {
            overflow = true;
            return;
        }

        uint32_t n = MPT_HTOBE32(val);
        memcpy(buffer + offset, &n, sizeof(val));
        offset += sizeof(val);
    }

    void
    add64(uint64_t val)
    {
        if (overflow || offset + sizeof(val) > capacity)
        {
            overflow = true;
            return;
        }

        uint64_t n = MPT_HTOBE64(val);
        memcpy(buffer + offset, &n, sizeof(val));
        offset += sizeof(val);
    }

    void
    addRaw(uint8_t const* data, size_t len)
    {
        if (overflow || offset + len > capacity)
        {
            overflow = true;
            return;
        }

        memcpy(buffer + offset, data, len);
        offset += len;
    }
};

void
sha512_half(uint8_t const* data, size_t len, uint8_t* out)
{
    uint8_t full_hash[SHA512_DIGEST_LENGTH];
    SHA512(data, len, full_hash);
    memcpy(out, full_hash, SHA512_DIGEST_LENGTH / 2);
}

void
mpt_add_common_zkp_fields(
    Serializer& s,
    uint16_t txType,
    account_id acc,
    mpt_issuance_id iss,
    uint32_t seq)
{
    s.add16(txType);
    s.addRaw(acc.bytes, sizeof(acc.bytes));
    s.addRaw(iss.bytes, sizeof(iss.bytes));
    s.add32(seq);
}

extern "C" {
size_t
get_confidential_send_proof_size(size_t n_recipients)
{
    (void)n_recipients;
    return kMPT_COMPACT_SEND_PROOF_SIZE + kMPT_DOUBLE_BULLETPROOF_SIZE;
}

bool
mpt_make_ec_pair(
    uint8_t const buffer[kMPT_ELGAMAL_TOTAL_SIZE],
    secp256k1_pubkey* out1,
    secp256k1_pubkey* out2)
{
    if (!out1 || !out2)
        return false;

    secp256k1_context const* ctx = mpt_secp256k1_context();
    if (!ctx)
        return false;

    int ret1 = secp256k1_ec_pubkey_parse(ctx, out1, buffer, kMPT_ELGAMAL_CIPHER_SIZE);

    int ret2 = secp256k1_ec_pubkey_parse(
        ctx, out2, buffer + kMPT_ELGAMAL_CIPHER_SIZE, kMPT_ELGAMAL_CIPHER_SIZE);

    return (ret1 == 1 && ret2 == 1);
}

bool
mpt_serialize_ec_pair(
    secp256k1_pubkey const* in1,
    secp256k1_pubkey const* in2,
    uint8_t out[kMPT_ELGAMAL_TOTAL_SIZE])
{
    if (!in1 || !in2 || !out)
        return false;

    secp256k1_context const* ctx = mpt_secp256k1_context();
    if (!ctx)
        return false;

    size_t len = kMPT_ELGAMAL_CIPHER_SIZE;

    if (secp256k1_ec_pubkey_serialize(ctx, out, &len, in1, SECP256K1_EC_COMPRESSED) != 1)
        return false;

    len = kMPT_ELGAMAL_CIPHER_SIZE;
    if (secp256k1_ec_pubkey_serialize(
            ctx, out + kMPT_ELGAMAL_CIPHER_SIZE, &len, in2, SECP256K1_EC_COMPRESSED) != 1)
        return false;

    return true;
}

int
mpt_get_convert_context_hash(
    account_id acc,
    mpt_issuance_id iss,
    uint32_t seq,
    uint8_t out_hash[kMPT_HALF_SHA_SIZE])
{
    uint8_t buf[kMPT_ZKP_CONTEXT_HASH_SIZE];
    Serializer s(buf, kMPT_ZKP_CONTEXT_HASH_SIZE);

    mpt_add_common_zkp_fields(s, ttCONFIDENTIAL_MPT_CONVERT, acc, iss, seq);
    s.addRaw(acc.bytes, sizeof(acc.bytes));
    s.add32(0);

    if (!s.isValid())
        return -1;

    sha512_half(buf, s.offset, out_hash);
    return 0;
}

int
mpt_get_convert_back_context_hash(
    account_id acc,
    mpt_issuance_id iss,
    uint32_t seq,
    uint32_t ver,
    uint8_t out_hash[kMPT_HALF_SHA_SIZE])
{
    uint8_t buf[kMPT_ZKP_CONTEXT_HASH_SIZE];
    Serializer s(buf, kMPT_ZKP_CONTEXT_HASH_SIZE);

    mpt_add_common_zkp_fields(s, ttCONFIDENTIAL_MPT_CONVERT_BACK, acc, iss, seq);
    s.addRaw(acc.bytes, sizeof(acc.bytes));
    s.add32(ver);

    if (!s.isValid())
        return -1;

    sha512_half(buf, s.offset, out_hash);
    return 0;
}

int
mpt_get_send_context_hash(
    account_id acc,
    mpt_issuance_id iss,
    uint32_t seq,
    account_id dest,
    uint32_t ver,
    uint8_t out_hash[kMPT_HALF_SHA_SIZE])
{
    uint8_t buf[kMPT_ZKP_CONTEXT_HASH_SIZE];
    Serializer s(buf, kMPT_ZKP_CONTEXT_HASH_SIZE);

    mpt_add_common_zkp_fields(s, ttCONFIDENTIAL_MPT_SEND, acc, iss, seq);
    s.addRaw(dest.bytes, sizeof(dest.bytes));
    s.add32(ver);

    if (!s.isValid())
        return -1;

    sha512_half(buf, s.offset, out_hash);
    return 0;
}

int
mpt_get_clawback_context_hash(
    account_id acc,
    mpt_issuance_id iss,
    uint32_t seq,
    account_id holder,
    uint8_t out_hash[kMPT_HALF_SHA_SIZE])
{
    uint8_t buf[kMPT_ZKP_CONTEXT_HASH_SIZE];
    Serializer s(buf, kMPT_ZKP_CONTEXT_HASH_SIZE);

    mpt_add_common_zkp_fields(s, ttCONFIDENTIAL_MPT_CLAWBACK, acc, iss, seq);
    s.addRaw(holder.bytes, sizeof(holder.bytes));
    s.add32(0);

    if (!s.isValid())
        return -1;

    sha512_half(buf, s.offset, out_hash);
    return 0;
}

int
mpt_generate_keypair(uint8_t* out_privkey, uint8_t* out_pubkey)
{
    secp256k1_context const* ctx = mpt_secp256k1_context();
    if (!ctx)
        return -1;

    secp256k1_pubkey pub;
    if (secp256k1_elgamal_generate_keypair(ctx, out_privkey, &pub) != 1)
        return -1;

    size_t output_len = kMPT_PUBKEY_SIZE;
    if (secp256k1_ec_pubkey_serialize(
            ctx, out_pubkey, &output_len, &pub, SECP256K1_EC_COMPRESSED) != 1)
        return -1;

    return 0;
}

int
mpt_generate_blinding_factor(uint8_t out_factor[kMPT_BLINDING_FACTOR_SIZE])
{
    if (!out_factor)
        return -1;

    secp256k1_context const* ctx = mpt_secp256k1_context();
    if (!ctx)
        return -1;

    do
    {
        if (RAND_bytes(out_factor, kMPT_BLINDING_FACTOR_SIZE) != 1)
            return -1;
    } while (secp256k1_ec_seckey_verify(ctx, out_factor) != 1);

    return 0;
}

int
mpt_encrypt_amount(
    uint64_t amount,
    uint8_t const pubkey[kMPT_PUBKEY_SIZE],
    uint8_t const blinding_factor[kMPT_BLINDING_FACTOR_SIZE],
    uint8_t out_ciphertext[kMPT_ELGAMAL_TOTAL_SIZE])
{
    if (!pubkey || !blinding_factor || !out_ciphertext)
        return -1;

    secp256k1_context const* ctx = mpt_secp256k1_context();
    if (!ctx)
        return -1;

    secp256k1_pubkey c1, c2, pk;
    if (secp256k1_ec_pubkey_parse(ctx, &pk, pubkey, kMPT_PUBKEY_SIZE) != 1)
        return -1;

    if (!secp256k1_elgamal_encrypt(ctx, &c1, &c2, &pk, amount, blinding_factor))
        return -1;

    if (!mpt_serialize_ec_pair(&c1, &c2, out_ciphertext))
        return -1;

    return 0;
}

int
mpt_decrypt_amount(
    uint8_t const in_ciphertext[kMPT_ELGAMAL_TOTAL_SIZE],
    uint8_t const privkey[kMPT_PRIVKEY_SIZE],
    uint64_t* out_amount)
{
    if (!in_ciphertext || !privkey || !out_amount)
        return -1;

    secp256k1_context const* ctx = mpt_secp256k1_context();
    if (!ctx)
        return -1;

    secp256k1_pubkey c1, c2;
    if (!mpt_make_ec_pair(in_ciphertext, &c1, &c2))
        return -1;

    if (secp256k1_elgamal_decrypt(ctx, out_amount, &c1, &c2, privkey) != 1)
        return -1;

    return 0;
}

int
mpt_get_convert_proof(
    uint8_t const pubkey[kMPT_PUBKEY_SIZE],
    uint8_t const privkey[kMPT_PRIVKEY_SIZE],
    uint8_t const ctx_hash[kMPT_HALF_SHA_SIZE],
    uint8_t out_proof[kMPT_SCHNORR_PROOF_SIZE])
{
    if (!pubkey || !privkey || !ctx_hash || !out_proof)
        return -1;

    secp256k1_context const* ctx = mpt_secp256k1_context();
    if (!ctx)
        return -1;

    secp256k1_pubkey pk;
    if (secp256k1_ec_pubkey_parse(ctx, &pk, pubkey, kMPT_PUBKEY_SIZE) != 1)
        return -1;

    if (secp256k1_mpt_pok_sk_prove(ctx, out_proof, &pk, privkey, ctx_hash) != 1)
        return -1;

    return 0;
}

int
mpt_get_pedersen_commitment(
    uint64_t amount,
    uint8_t const blinding_factor[kMPT_BLINDING_FACTOR_SIZE],
    uint8_t out_commitment[kMPT_PEDERSEN_COMMIT_SIZE])
{
    if (!blinding_factor || !out_commitment)
        return -1;

    secp256k1_context const* ctx = mpt_secp256k1_context();
    if (!ctx)
        return -1;

    secp256k1_pubkey commitment;
    if (secp256k1_mpt_pedersen_commit(ctx, &commitment, amount, blinding_factor) != 1)
        return -1;

    size_t output_len = kMPT_PEDERSEN_COMMIT_SIZE;
    if (secp256k1_ec_pubkey_serialize(
            ctx, out_commitment, &output_len, &commitment, SECP256K1_EC_COMPRESSED) != 1)
        return -1;

    return 0;
}

int
mpt_get_confidential_send_proof(
    uint8_t const priv[kMPT_PRIVKEY_SIZE],
    uint64_t amount,
    mpt_confidential_participant const* recipients,
    size_t n_recipients,
    uint8_t const tx_blinding_factor[kMPT_BLINDING_FACTOR_SIZE],
    uint8_t const context_hash[kMPT_HALF_SHA_SIZE],
    mpt_pedersen_proof_params const* amount_params,
    mpt_pedersen_proof_params const* balance_params,
    uint8_t* out_proof,
    size_t* out_len)
{
    if (!priv || !recipients || !tx_blinding_factor || !context_hash || !amount_params ||
        !balance_params || !out_proof || !out_len)
        return -1;

    if (n_recipients != 3 && n_recipients != 4)
        return -1;

    secp256k1_context const* ctx = mpt_secp256k1_context();
    if (!ctx)
        return -1;

    size_t const totalRequired = kMPT_COMPACT_SEND_PROOF_SIZE + kMPT_DOUBLE_BULLETPROOF_SIZE;
    if (*out_len < totalRequired)
        return -1;

    // Parse participants into c1, c2_vec, pk_vec
    secp256k1_pubkey c1;
    std::vector<secp256k1_pubkey> c2_vec(n_recipients);
    std::vector<secp256k1_pubkey> pk_vec(n_recipients);

    for (size_t i = 0; i < n_recipients; ++i)
    {
        auto const& rec = recipients[i];

        if (i == 0)
        {
            if (secp256k1_ec_pubkey_parse(ctx, &c1, rec.ciphertext, kMPT_ELGAMAL_CIPHER_SIZE) != 1)
                return -1;
        }
        else
        {
            // All participant's ciphertext must have the same C1.
            if (!std::equal(
                    rec.ciphertext,
                    rec.ciphertext + kMPT_ELGAMAL_CIPHER_SIZE,
                    recipients[0].ciphertext))
                return -1;
        }

        if (secp256k1_ec_pubkey_parse(
                ctx,
                &c2_vec[i],
                rec.ciphertext + kMPT_ELGAMAL_CIPHER_SIZE,
                kMPT_ELGAMAL_CIPHER_SIZE) != 1)
            return -1;

        if (secp256k1_ec_pubkey_parse(ctx, &pk_vec[i], rec.pubkey, kMPT_PUBKEY_SIZE) != 1)
            return -1;
    }

    // Prevent underflow
    if (amount > balance_params->amount)
        return -1;
    uint64_t const remainder = balance_params->amount - amount;

    // Construct PC_m = amount*G + tx_blinding_factor*H
    // (Pedersen commitment to the send amount using the shared ElGamal r as blinding)
    secp256k1_pubkey PC_m;
    if (secp256k1_mpt_pedersen_commit(ctx, &PC_m, amount, tx_blinding_factor) != 1)
        return -1;

    // Derive sender's public key from private key
    secp256k1_pubkey pk_A;
    if (secp256k1_ec_pubkey_create(ctx, &pk_A, priv) != 1)
        return -1;

    // Compute rho_rem = balance_bf - amount_bf (blinding for remainder commitment)
    uint8_t rho_rem[32];
    uint8_t neg_rho_m[32];
    secp256k1_mpt_scalar_negate(neg_rho_m, amount_params->blinding_factor);
    secp256k1_mpt_scalar_add(rho_rem, balance_params->blinding_factor, neg_rho_m);

    // Construct PC_b = remainder*G + rho_rem*H
    secp256k1_pubkey PC_b;
    if (secp256k1_mpt_pedersen_commit(ctx, &PC_b, remainder, rho_rem) != 1)
        return -1;

    // Compute remainder ciphertext: C_rem = balance_ct - send_ct
    // C1_rem = C1_bal - C1_send = C1_bal - C1 (same C1 since shared r)
    // But balance was encrypted with different r, so:
    // C1_rem = C1_bal - C1_send, C2_rem = C2_bal - C2_send[0]
    secp256k1_pubkey C1_bal, C2_bal;
    if (!mpt_make_ec_pair(balance_params->ciphertext, &C1_bal, &C2_bal))
        return -1;

    // C2_send[0] is in c2_vec[0], C1_send is c1
    secp256k1_pubkey C1_rem, C2_rem;
    if (secp256k1_elgamal_subtract(ctx, &C1_rem, &C2_rem, &C1_bal, &C2_bal, &c1, &c2_vec[0]) != 1)
        return -1;

    // Generate compact standard sigma proof
    if (secp256k1_compact_standard_prove(
            ctx,
            out_proof,
            amount,
            remainder,
            tx_blinding_factor,
            priv,
            rho_rem,
            n_recipients,
            &c1,
            c2_vec.data(),
            pk_vec.data(),
            &PC_m,
            &pk_A,
            &PC_b,
            &C1_rem,
            &C2_rem,
            context_hash) != 1)
    {
        return -1;
    }

    // Bulletproof range proof: [amount, remainder]
    // Blinding factors for bulletproof: [tx_blinding_factor for amount, rho_rem for remainder]
    uint8_t* bp_ptr = out_proof + kMPT_COMPACT_SEND_PROOF_SIZE;
    uint64_t bp_values[2] = {amount, remainder};
    uint8_t const* bp_blinding_ptrs[2] = {tx_blinding_factor, rho_rem};
    size_t actual_bp_len = kMPT_DOUBLE_BULLETPROOF_SIZE;

    if (mpt_get_bulletproof_agg(
            bp_values, bp_blinding_ptrs, 2, context_hash, bp_ptr, &actual_bp_len) != 0)
        return -1;

    *out_len = kMPT_COMPACT_SEND_PROOF_SIZE + actual_bp_len;

    return 0;
}

int
mpt_get_convert_back_proof(
    uint8_t const priv[kMPT_PRIVKEY_SIZE],
    uint8_t const pub[kMPT_PUBKEY_SIZE],
    uint8_t const context_hash[kMPT_HALF_SHA_SIZE],
    uint64_t const amount,
    mpt_pedersen_proof_params const* params,
    uint8_t out_proof[kMPT_COMPACT_CONVERTBACK_PROOF_SIZE + kMPT_SINGLE_BULLETPROOF_SIZE])
{
    if (!priv || !pub || !context_hash || !params || !out_proof)
        return -1;

    secp256k1_context const* ctx = mpt_secp256k1_context();
    if (!ctx)
        return -1;

    // Parse the sender's public key
    secp256k1_pubkey pk_A;
    if (secp256k1_ec_pubkey_parse(ctx, &pk_A, pub, kMPT_PUBKEY_SIZE) != 1)
        return -1;

    // Parse the balance ciphertext into (B1, B2)
    secp256k1_pubkey B1, B2;
    if (!mpt_make_ec_pair(params->ciphertext, &B1, &B2))
        return -1;

    // Parse the Pedersen commitment to the balance
    secp256k1_pubkey PC_b;
    if (secp256k1_ec_pubkey_parse(
            ctx, &PC_b, params->pedersen_commitment, kMPT_PEDERSEN_COMMIT_SIZE) != 1)
        return -1;

    // Generate compact convertback sigma proof
    if (secp256k1_compact_convertback_prove(
            ctx,
            out_proof,
            params->amount,
            priv,
            params->blinding_factor,
            &pk_A,
            &B1,
            &B2,
            &PC_b,
            context_hash) != 1)
    {
        return -1;
    }

    if (amount > params->amount)
        return -1;

    uint64_t const remaining_balance = params->amount - amount;
    uint8_t* bulletproof_ptr = out_proof + kMPT_COMPACT_CONVERTBACK_PROOF_SIZE;
    size_t proof_len = kMPT_SINGLE_BULLETPROOF_SIZE;

    uint8_t const* blinding_ptrs[1] = {params->blinding_factor};

    return mpt_get_bulletproof_agg(
        &remaining_balance, blinding_ptrs, 1, context_hash, bulletproof_ptr, &proof_len);
}

int
mpt_get_clawback_proof(
    uint8_t const priv[kMPT_PRIVKEY_SIZE],
    uint8_t const pub[kMPT_PUBKEY_SIZE],
    uint8_t const context_hash[kMPT_HALF_SHA_SIZE],
    uint64_t const amount,
    uint8_t const ciphertext[kMPT_ELGAMAL_TOTAL_SIZE],
    uint8_t out_proof[kMPT_COMPACT_CLAWBACK_PROOF_SIZE])
{
    if (!priv || !pub || !context_hash || !ciphertext || !out_proof)
        return -1;

    secp256k1_context const* ctx = mpt_secp256k1_context();
    if (!ctx)
        return -1;

    secp256k1_pubkey pk;
    if (secp256k1_ec_pubkey_parse(ctx, &pk, pub, kMPT_PUBKEY_SIZE) != 1)
        return -1;

    secp256k1_pubkey c1, c2;
    if (!mpt_make_ec_pair(ciphertext, &c1, &c2))
        return -1;

    if (secp256k1_compact_clawback_prove(
            ctx, out_proof, amount, priv, &pk, &c1, &c2, context_hash) != 1)
    {
        return -1;
    }

    return 0;
}

static int
mpt_internal_verify_single(
    secp256k1_context* ctx,
    uint64_t amount,
    uint8_t const bf[kMPT_BLINDING_FACTOR_SIZE],
    mpt_confidential_participant const* recipient)
{
    secp256k1_pubkey pk, c1, c2;

    if (secp256k1_ec_pubkey_parse(ctx, &pk, recipient->pubkey, kMPT_PUBKEY_SIZE) != 1)
        return 1;

    if (!mpt_make_ec_pair(recipient->ciphertext, &c1, &c2))
        return 1;

    if (secp256k1_elgamal_verify_encryption(ctx, &c1, &c2, &pk, amount, bf) != 1)
        return 1;

    return 0;
}

int
mpt_verify_revealed_amount(
    uint64_t const amount,
    uint8_t const blinding_factor[kMPT_BLINDING_FACTOR_SIZE],
    mpt_confidential_participant const* holder,
    mpt_confidential_participant const* issuer,
    mpt_confidential_participant const* auditor)
{
    if (!blinding_factor || !holder || !issuer)
        return -1;

    secp256k1_context* ctx = mpt_secp256k1_context();
    if (!ctx)
        return -1;

    int status = 0;

    status |= mpt_internal_verify_single(ctx, amount, blinding_factor, holder);

    status |= mpt_internal_verify_single(ctx, amount, blinding_factor, issuer);

    if (auditor)
    {
        status |= mpt_internal_verify_single(ctx, amount, blinding_factor, auditor);
    }

    return (status == 0) ? 0 : -1;
}

int
mpt_verify_convert_proof(
    uint8_t const proof[kMPT_SCHNORR_PROOF_SIZE],
    uint8_t const pubkey[kMPT_PUBKEY_SIZE],
    uint8_t const context_hash[kMPT_HALF_SHA_SIZE])
{
    if (!pubkey || !context_hash || !proof)
        return -1;

    secp256k1_context* ctx = mpt_secp256k1_context();
    if (!ctx)
        return -1;

    secp256k1_pubkey pk;
    if (secp256k1_ec_pubkey_parse(ctx, &pk, pubkey, kMPT_PUBKEY_SIZE) != 1)
    {
        return -1;
    }

    if (secp256k1_mpt_pok_sk_verify(ctx, proof, &pk, context_hash) != 1)
    {
        return -1;
    }

    return 0;
}

int
mpt_compute_convert_back_remainder(
    uint8_t const commitment_in[kMPT_PEDERSEN_COMMIT_SIZE],
    uint64_t amount,
    uint8_t remainder[kMPT_PEDERSEN_COMMIT_SIZE])
{
    if (!commitment_in || !remainder)
        return -1;

    // Subtracting zero leaves the commitment unchanged
    if (amount == 0)
    {
        std::memcpy(remainder, commitment_in, kMPT_PEDERSEN_COMMIT_SIZE);
        return 0;
    }

    secp256k1_context const* ctx = mpt_secp256k1_context();
    if (!ctx)
        return -1;

    secp256k1_pubkey pc_balance;
    if (secp256k1_ec_pubkey_parse(ctx, &pc_balance, commitment_in, kMPT_PEDERSEN_COMMIT_SIZE) != 1)
        return -1;

    // Convert amount to 32-byte big-endian scalar
    uint8_t scalar[32] = {0};
    for (int i = 0; i < 8; ++i)
    {
        scalar[31 - i] = static_cast<uint8_t>(amount >> (i * 8));
    }

    // Calculate mG and negate it to get -mG
    secp256k1_pubkey mG;
    if (secp256k1_ec_pubkey_create(ctx, &mG, scalar) != 1)
        return -1;

    if (secp256k1_ec_pubkey_negate(ctx, &mG) != 1)
        return -1;

    // Calculate pc_rem = pc_balance - mG
    secp256k1_pubkey const* summands[2] = {&pc_balance, &mG};
    secp256k1_pubkey pc_rem;
    if (secp256k1_ec_pubkey_combine(ctx, &pc_rem, summands, 2) != 1)
        return -1;

    size_t out_len = kMPT_PEDERSEN_COMMIT_SIZE;
    return (secp256k1_ec_pubkey_serialize(
                ctx, remainder, &out_len, &pc_rem, SECP256K1_EC_COMPRESSED) == 1)
        ? 0
        : -1;
}

int
mpt_verify_aggregated_bulletproof(
    uint8_t const* proof,
    size_t proof_len,
    uint8_t const** compressed_commitments,  // Pointer to array of pointers
    size_t m,
    uint8_t const context_hash[kMPT_HALF_SHA_SIZE])
{
    if (!proof || !compressed_commitments || !context_hash)
        return -1;

    // m must be power of 2, in our case, it is either 1 or 2.
    if (m != 1 && m != 2)
        return -1;

    secp256k1_context const* ctx = mpt_secp256k1_context();
    if (!ctx)
        return -1;

    std::vector<secp256k1_pubkey> commitments(m);
    for (size_t i = 0; i < m; ++i)
    {
        if (secp256k1_ec_pubkey_parse(
                ctx, &commitments[i], compressed_commitments[i], kMPT_PEDERSEN_COMMIT_SIZE) != 1)
            return -1;
    }

    size_t const n = 64 * m;
    std::vector<secp256k1_pubkey> G_vec(n);
    std::vector<secp256k1_pubkey> H_vec(n);

    if (secp256k1_mpt_get_generator_vector(ctx, G_vec.data(), n, (unsigned char const*)"G", 1) != 1)
        return -1;

    if (secp256k1_mpt_get_generator_vector(ctx, H_vec.data(), n, (unsigned char const*)"H", 1) != 1)
        return -1;

    secp256k1_pubkey pk_base;
    if (secp256k1_mpt_get_h_generator(ctx, &pk_base) != 1)
        return -1;

    if (secp256k1_bulletproof_verify_agg(
            ctx,
            G_vec.data(),
            H_vec.data(),
            proof,
            proof_len,
            commitments.data(),
            m,
            &pk_base,
            context_hash) != 1)
    {
        return -1;
    }

    return 0;
}

int
mpt_verify_convert_back_proof(
    uint8_t const proof[kMPT_COMPACT_CONVERTBACK_PROOF_SIZE + kMPT_SINGLE_BULLETPROOF_SIZE],
    uint8_t const pubkey[kMPT_PUBKEY_SIZE],
    uint8_t const ciphertext[kMPT_ELGAMAL_TOTAL_SIZE],
    uint8_t const balance_commitment[kMPT_PEDERSEN_COMMIT_SIZE],
    uint64_t const amount,
    uint8_t const context_hash[kMPT_HALF_SHA_SIZE])
{
    if (!context_hash || !pubkey || !ciphertext || !balance_commitment || !proof)
        return -1;

    secp256k1_context* ctx = mpt_secp256k1_context();
    if (!ctx)
        return -1;

    // Parse inputs
    secp256k1_pubkey pk_A;
    if (secp256k1_ec_pubkey_parse(ctx, &pk_A, pubkey, kMPT_PUBKEY_SIZE) != 1)
        return -1;

    secp256k1_pubkey B1, B2;
    if (!mpt_make_ec_pair(ciphertext, &B1, &B2))
        return -1;

    secp256k1_pubkey PC_b;
    if (secp256k1_ec_pubkey_parse(ctx, &PC_b, balance_commitment, kMPT_PEDERSEN_COMMIT_SIZE) != 1)
        return -1;

    // Verify compact convertback sigma proof
    if (secp256k1_compact_convertback_verify(ctx, proof, &pk_A, &B1, &B2, &PC_b, context_hash) != 1)
    {
        return -1;
    }

    // Verify range proof for remaining balance
    uint8_t pc_rem[kMPT_PEDERSEN_COMMIT_SIZE];
    if (mpt_compute_convert_back_remainder(balance_commitment, amount, pc_rem) != 0)
        return -1;

    uint8_t const* bulletproof_ptr = proof + kMPT_COMPACT_CONVERTBACK_PROOF_SIZE;
    uint8_t const* commitments_array[1] = {pc_rem};

    return mpt_verify_aggregated_bulletproof(
        bulletproof_ptr, kMPT_SINGLE_BULLETPROOF_SIZE, commitments_array, 1, context_hash);
}

int
mpt_verify_send_range_proof(
    secp256k1_context const* ctx,
    uint8_t const proof[kMPT_DOUBLE_BULLETPROOF_SIZE],
    uint8_t const amount_commitment[kMPT_PEDERSEN_COMMIT_SIZE],
    uint8_t const balance_commitment[kMPT_PEDERSEN_COMMIT_SIZE],
    uint8_t const context_hash[kMPT_HALF_SHA_SIZE])
{
    if (!proof || !amount_commitment || !balance_commitment || !context_hash)
        return -1;

    secp256k1_pubkey pc_amount, pc_balance;
    if (secp256k1_ec_pubkey_parse(ctx, &pc_amount, amount_commitment, kMPT_PEDERSEN_COMMIT_SIZE) !=
        1)
        return -1;

    if (secp256k1_ec_pubkey_parse(
            ctx, &pc_balance, balance_commitment, kMPT_PEDERSEN_COMMIT_SIZE) != 1)
        return -1;

    // Negate PC_amount point to get -PC_amount
    if (secp256k1_ec_pubkey_negate(ctx, &pc_amount) != 1)
        return -1;

    // Compute pc_rem = pc_balance + (-pc_amount)
    secp256k1_pubkey pc_rem;
    secp256k1_pubkey const* summands[2] = {&pc_balance, &pc_amount};
    if (secp256k1_ec_pubkey_combine(ctx, &pc_rem, summands, 2) != 1)
        return -1;

    uint8_t remainder_commitment[kMPT_PEDERSEN_COMMIT_SIZE];
    size_t out_len = kMPT_PEDERSEN_COMMIT_SIZE;
    if (secp256k1_ec_pubkey_serialize(
            ctx, remainder_commitment, &out_len, &pc_rem, SECP256K1_EC_COMPRESSED) != 1)
        return -1;

    uint8_t const* commitments[2] = {amount_commitment, remainder_commitment};

    if (mpt_verify_aggregated_bulletproof(
            proof, kMPT_DOUBLE_BULLETPROOF_SIZE, commitments, 2, context_hash) != 0)
    {
        return -1;
    }

    return 0;
}

int
mpt_verify_send_proof(
    uint8_t const* proof,
    size_t const proof_len,
    mpt_confidential_participant const* participants,
    uint8_t const n_participants,
    uint8_t const sender_spending_ciphertext[kMPT_ELGAMAL_TOTAL_SIZE],
    uint8_t const amount_commitment[kMPT_PEDERSEN_COMMIT_SIZE],
    uint8_t const balance_commitment[kMPT_PEDERSEN_COMMIT_SIZE],
    uint8_t const context_hash[kMPT_HALF_SHA_SIZE])
{
    if (!proof || proof_len == 0 || !participants || !context_hash)
        return -1;

    if (n_participants != 3 && n_participants != 4)
        return -1;

    secp256k1_context* ctx = mpt_secp256k1_context();
    if (!ctx)
        return -1;

    // Verify the length of the proof
    size_t const total_required = kMPT_COMPACT_SEND_PROOF_SIZE + kMPT_DOUBLE_BULLETPROOF_SIZE;
    if (proof_len != total_required)
        return -1;

    // Parse participants into c1, c2_vec, pk_vec
    secp256k1_pubkey c1;
    std::vector<secp256k1_pubkey> c2_vec(n_participants);
    std::vector<secp256k1_pubkey> pk_vec(n_participants);

    for (uint8_t i = 0; i < n_participants; ++i)
    {
        if (i == 0)
        {
            if (secp256k1_ec_pubkey_parse(
                    ctx, &c1, participants[i].ciphertext, kMPT_ELGAMAL_CIPHER_SIZE) != 1)
                return -1;
        }
        else
        {
            // All participants must share the exact same C1 bytes
            if (!std::equal(
                    participants[i].ciphertext,
                    participants[i].ciphertext + kMPT_ELGAMAL_CIPHER_SIZE,
                    participants[0].ciphertext))
            {
                return -1;
            }
        }

        if (secp256k1_ec_pubkey_parse(
                ctx,
                &c2_vec[i],
                participants[i].ciphertext + kMPT_ELGAMAL_CIPHER_SIZE,
                kMPT_ELGAMAL_CIPHER_SIZE) != 1)
            return -1;

        if (secp256k1_ec_pubkey_parse(ctx, &pk_vec[i], participants[i].pubkey, kMPT_PUBKEY_SIZE) !=
            1)
            return -1;
    }

    // Parse amount Pedersen commitment: PC_m = amount*G + r*H
    secp256k1_pubkey PC_m;
    if (secp256k1_ec_pubkey_parse(ctx, &PC_m, amount_commitment, kMPT_PEDERSEN_COMMIT_SIZE) != 1)
        return -1;

    // Derive sender's public key from participants[0]
    secp256k1_pubkey pk_A;
    if (secp256k1_ec_pubkey_parse(ctx, &pk_A, participants[0].pubkey, kMPT_PUBKEY_SIZE) != 1)
        return -1;

    // Compute PC_b = PC_balance - PC_amount (remainder commitment = balance - amount)
    // PC_balance = balance*G + rho_bal*H, PC_amount = amount*G + r*H
    // PC_b = (balance - amount)*G + (rho_bal - r)*H = remainder*G + rho_rem*H
    secp256k1_pubkey PC_balance, PC_amount_neg;
    if (secp256k1_ec_pubkey_parse(
            ctx, &PC_balance, balance_commitment, kMPT_PEDERSEN_COMMIT_SIZE) != 1)
        return -1;
    PC_amount_neg = PC_m;
    if (secp256k1_ec_pubkey_negate(ctx, &PC_amount_neg) != 1)
        return -1;
    secp256k1_pubkey PC_b;
    secp256k1_pubkey const* pc_summands[2] = {&PC_balance, &PC_amount_neg};
    if (secp256k1_ec_pubkey_combine(ctx, &PC_b, pc_summands, 2) != 1)
        return -1;

    // Compute remainder ciphertext: C_rem = balance_ct - send_ct
    secp256k1_pubkey C1_bal, C2_bal;
    if (!mpt_make_ec_pair(sender_spending_ciphertext, &C1_bal, &C2_bal))
        return -1;

    secp256k1_pubkey C1_rem, C2_rem;
    if (secp256k1_elgamal_subtract(ctx, &C1_rem, &C2_rem, &C1_bal, &C2_bal, &c1, &c2_vec[0]) != 1)
        return -1;

    // Track validity via a boolean flag to avoid timing side-channels
    bool valid = true;

    // Verify compact standard sigma proof
    if (secp256k1_compact_standard_verify(
            ctx,
            proof,
            n_participants,
            &c1,
            c2_vec.data(),
            pk_vec.data(),
            &PC_m,
            &pk_A,
            &PC_b,
            &C1_rem,
            &C2_rem,
            context_hash) != 1)
    {
        valid = false;
    }

    // Verify range proof: commitments are PC_m (amount) and PC_b (remainder)
    // mpt_verify_send_range_proof computes PC_b internally as PC_balance - PC_m,
    // which matches how we constructed PC_b above.
    if (mpt_verify_send_range_proof(
            ctx,
            proof + kMPT_COMPACT_SEND_PROOF_SIZE,
            amount_commitment,
            balance_commitment,
            context_hash) != 0)
    {
        valid = false;
    }

    return valid ? 0 : -1;
}

int
mpt_verify_clawback_proof(
    uint8_t const proof[kMPT_COMPACT_CLAWBACK_PROOF_SIZE],
    uint64_t const amount,
    uint8_t const pubkey[kMPT_PUBKEY_SIZE],
    uint8_t const ciphertext[kMPT_ELGAMAL_TOTAL_SIZE],
    uint8_t const context_hash[kMPT_HALF_SHA_SIZE])
{
    if (!proof || !pubkey || !ciphertext || !context_hash)
        return -1;

    secp256k1_context* ctx = mpt_secp256k1_context();
    if (!ctx)
        return -1;

    secp256k1_pubkey c1, c2;
    if (!mpt_make_ec_pair(ciphertext, &c1, &c2))
        return -1;

    secp256k1_pubkey pk;
    if (secp256k1_ec_pubkey_parse(ctx, &pk, pubkey, kMPT_PUBKEY_SIZE) != 1)
        return -1;

    if (secp256k1_compact_clawback_verify(ctx, proof, amount, &pk, &c1, &c2, context_hash) != 1)
    {
        return -1;
    }

    return 0;
}
}
