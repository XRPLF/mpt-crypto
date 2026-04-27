#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <utility/mpt_utility.h>

#include <secp256k1_mpt.h>

#include <cstring>
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
    int rc = -1;

    for (size_t i = 0; i < m; ++i)
    {
        if (!blinding_ptrs[i])
            goto bp_cleanup;
        std::memcpy(blindings_flat + (i * 32), blinding_ptrs[i], 32);
    }

    {
        secp256k1_pubkey pk_base;
        if (secp256k1_mpt_get_h_generator(ctx, &pk_base) != 1)
            goto bp_cleanup;

        if (secp256k1_bulletproof_prove_agg(
                ctx, out_proof, out_len, values, blindings_flat, m, &pk_base, context_hash) != 1)
            goto bp_cleanup;

        size_t const expected =
            (m == 1) ? kMPT_SINGLE_BULLETPROOF_SIZE : kMPT_DOUBLE_BULLETPROOF_SIZE;
        if (*out_len != expected)
            goto bp_cleanup;

        rc = 0;
    }

bp_cleanup:
    OPENSSL_cleanse(blindings_flat, sizeof(blindings_flat));
    return rc;
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

static int
sha512_half(uint8_t const* data, size_t len, uint8_t* out)
{
    uint8_t full_hash[64];
    unsigned int digest_len = 0;
    if (EVP_Digest(data, len, full_hash, &digest_len, EVP_sha512(), NULL) != 1)
        return -1;
    memcpy(out, full_hash, 32);
    OPENSSL_cleanse(full_hash, sizeof(full_hash));
    return 0;
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

    return sha512_half(buf, s.offset, out_hash);
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

    return sha512_half(buf, s.offset, out_hash);
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

    return sha512_half(buf, s.offset, out_hash);
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

    return sha512_half(buf, s.offset, out_hash);
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

static int
mpt_internal_verify_single(
    secp256k1_context* ctx,
    uint64_t amount,
    uint8_t const bf[kMPT_BLINDING_FACTOR_SIZE],
    mpt_confidential_participant const* recipient)
{
    if (!ctx)
        return -1;
    secp256k1_pubkey pk, c1, c2;

    if (secp256k1_ec_pubkey_parse(ctx, &pk, recipient->pubkey, kMPT_PUBKEY_SIZE) != 1)
        return -1;

    if (!mpt_make_ec_pair(recipient->ciphertext, &c1, &c2))
        return -1;

    if (secp256k1_elgamal_verify_encryption(ctx, &c1, &c2, &pk, amount, bf) != 1)
        return -1;

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
    uint8_t const pub[kMPT_PUBKEY_SIZE],
    uint64_t amount,
    mpt_confidential_participant const* participants,
    size_t n_participants,
    uint8_t const tx_blinding_factor[kMPT_BLINDING_FACTOR_SIZE],
    uint8_t const context_hash[kMPT_HALF_SHA_SIZE],
    uint8_t const amount_commitment[kMPT_PEDERSEN_COMMIT_SIZE],
    mpt_pedersen_proof_params const* balance_params,
    uint8_t* out_proof,
    size_t* out_len)
{
    if (!priv || !pub || !participants || !tx_blinding_factor || !context_hash ||
        !amount_commitment || !balance_params || !out_proof || !out_len)
        return -1;

    if (n_participants != 3 && n_participants != 4)
        return -1;

    secp256k1_context const* ctx = mpt_secp256k1_context();
    if (!ctx)
        return -1;

    size_t const total_required =
        SECP256K1_COMPACT_STANDARD_PROOF_SIZE + kMPT_DOUBLE_BULLETPROOF_SIZE;
    if (*out_len < total_required)
        return -1;

    secp256k1_pubkey c1;
    std::vector<secp256k1_pubkey> c2_vec(n_participants);
    std::vector<secp256k1_pubkey> pk_vec(n_participants);

    for (size_t i = 0; i < n_participants; ++i)
    {
        auto const& rec = participants[i];

        if (i == 0)
        {
            if (secp256k1_ec_pubkey_parse(ctx, &c1, rec.ciphertext, kMPT_ELGAMAL_CIPHER_SIZE) != 1)
                return -1;
        }
        else
        {
            if (!std::equal(
                    rec.ciphertext,
                    rec.ciphertext + kMPT_ELGAMAL_CIPHER_SIZE,
                    participants[0].ciphertext))
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

    // Parse sender's public key from ledger.
    secp256k1_pubkey pk;
    if (secp256k1_ec_pubkey_parse(ctx, &pk, pub, kMPT_PUBKEY_SIZE) != 1)
        return -1;

    secp256k1_pubkey pc_m;
    if (secp256k1_ec_pubkey_parse(ctx, &pc_m, amount_commitment, kMPT_PEDERSEN_COMMIT_SIZE) != 1)
        return -1;

    secp256k1_pubkey pc_b;
    if (secp256k1_ec_pubkey_parse(
            ctx, &pc_b, balance_params->pedersen_commitment, kMPT_PEDERSEN_COMMIT_SIZE) != 1)
        return -1;

    secp256k1_pubkey b1, b2;
    if (!mpt_make_ec_pair(balance_params->ciphertext, &b1, &b2))
        return -1;

    if (secp256k1_compact_standard_prove(
            ctx,
            out_proof,
            amount,
            balance_params->amount,
            tx_blinding_factor,
            priv,
            balance_params->blinding_factor,
            n_participants,
            &c1,
            c2_vec.data(),
            pk_vec.data(),
            &pc_m,
            &pk,
            &pc_b,
            &b1,
            &b2,
            context_hash) != 1)
    {
        return -1;
    }

    if (amount > balance_params->amount)
        return -1;  // prevent underflow

    uint64_t const remaining_balance = balance_params->amount - amount;
    uint64_t const bp_values[2] = {amount, remaining_balance};

    uint8_t neg_r[32];
    uint8_t rho_rem[32];
    int rc = -1;

    secp256k1_mpt_scalar_negate(neg_r, tx_blinding_factor);
    secp256k1_mpt_scalar_add(rho_rem, balance_params->blinding_factor, neg_r);

    {
        uint8_t const* bp_blinding_ptrs[2] = {tx_blinding_factor, rho_rem};
        uint8_t* bp_ptr = out_proof + SECP256K1_COMPACT_STANDARD_PROOF_SIZE;
        size_t actual_bp_len = kMPT_DOUBLE_BULLETPROOF_SIZE;

        if (mpt_get_bulletproof_agg(
                bp_values, bp_blinding_ptrs, 2, context_hash, bp_ptr, &actual_bp_len) != 0)
            goto send_cleanup;

        *out_len = SECP256K1_COMPACT_STANDARD_PROOF_SIZE + actual_bp_len;
        rc = 0;
    }

send_cleanup:
    OPENSSL_cleanse(neg_r, sizeof(neg_r));
    OPENSSL_cleanse(rho_rem, sizeof(rho_rem));
    return rc;
}

int
mpt_get_convert_back_proof(
    uint8_t const priv[kMPT_PRIVKEY_SIZE],
    uint8_t const pub[kMPT_PUBKEY_SIZE],
    uint8_t const context_hash[kMPT_HALF_SHA_SIZE],
    uint64_t const amount,
    mpt_pedersen_proof_params const* params,
    uint8_t out_proof[SECP256K1_COMPACT_CONVERTBACK_PROOF_SIZE + kMPT_SINGLE_BULLETPROOF_SIZE])
{
    if (!priv || !pub || !context_hash || !params || !out_proof)
        return -1;

    if (amount > params->amount)
        return -1;

    secp256k1_context const* ctx = mpt_secp256k1_context();
    if (!ctx)
        return -1;

    secp256k1_pubkey pk;
    if (secp256k1_ec_pubkey_parse(ctx, &pk, pub, kMPT_PUBKEY_SIZE) != 1)
        return -1;

    secp256k1_pubkey b1, b2;
    if (!mpt_make_ec_pair(params->ciphertext, &b1, &b2))
        return -1;

    secp256k1_pubkey pc_b;
    if (secp256k1_ec_pubkey_parse(
            ctx, &pc_b, params->pedersen_commitment, kMPT_PEDERSEN_COMMIT_SIZE) != 1)
        return -1;

    if (secp256k1_compact_convertback_prove(
            ctx,
            out_proof,
            params->amount,
            priv,
            params->blinding_factor,
            &pk,
            &b1,
            &b2,
            &pc_b,
            context_hash) != 1)
    {
        return -1;
    }

    uint64_t const remaining_balance = params->amount - amount;
    uint8_t* bp_ptr = out_proof + SECP256K1_COMPACT_CONVERTBACK_PROOF_SIZE;
    size_t bp_len = kMPT_SINGLE_BULLETPROOF_SIZE;
    uint8_t const* blinding_ptrs[1] = {params->blinding_factor};

    return mpt_get_bulletproof_agg(
        &remaining_balance, blinding_ptrs, 1, context_hash, bp_ptr, &bp_len);
}

int
mpt_get_clawback_proof(
    uint8_t const priv[kMPT_PRIVKEY_SIZE],
    uint8_t const pub[kMPT_PUBKEY_SIZE],
    uint8_t const context_hash[kMPT_HALF_SHA_SIZE],
    uint64_t const amount,
    uint8_t const ciphertext[kMPT_ELGAMAL_TOTAL_SIZE],
    uint8_t out_proof[SECP256K1_COMPACT_CLAWBACK_PROOF_SIZE])
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
    uint8_t const proof[SECP256K1_COMPACT_CONVERTBACK_PROOF_SIZE + kMPT_SINGLE_BULLETPROOF_SIZE],
    uint8_t const pubkey[kMPT_PUBKEY_SIZE],
    uint8_t const ciphertext[kMPT_ELGAMAL_TOTAL_SIZE],
    uint8_t const balance_commitment[kMPT_PEDERSEN_COMMIT_SIZE],
    uint64_t const amount,
    uint8_t const context_hash[kMPT_HALF_SHA_SIZE])
{
    if (!proof || !pubkey || !ciphertext || !balance_commitment || !context_hash)
        return -1;

    secp256k1_context* ctx = mpt_secp256k1_context();
    if (!ctx)
        return -1;

    secp256k1_pubkey pk;
    if (secp256k1_ec_pubkey_parse(ctx, &pk, pubkey, kMPT_PUBKEY_SIZE) != 1)
        return -1;

    secp256k1_pubkey b1, b2;
    if (!mpt_make_ec_pair(ciphertext, &b1, &b2))
        return -1;

    secp256k1_pubkey pc_b;
    if (secp256k1_ec_pubkey_parse(ctx, &pc_b, balance_commitment, kMPT_PEDERSEN_COMMIT_SIZE) != 1)
        return -1;

    // Accumulate validity to avoid leaking which proof component failed
    bool valid = true;

    // Verify compact sigma proof (first 128 bytes)
    if (secp256k1_compact_convertback_verify(ctx, proof, &pk, &b1, &b2, &pc_b, context_hash) != 1)
    {
        valid = false;
    }

    // Verify range proof (next 688 bytes) over pc_rem = pc_b - m*G
    uint8_t pc_rem[kMPT_PEDERSEN_COMMIT_SIZE];
    if (mpt_compute_convert_back_remainder(balance_commitment, amount, pc_rem) != 0)
        return -1;

    uint8_t const* bp_ptr = proof + SECP256K1_COMPACT_CONVERTBACK_PROOF_SIZE;
    uint8_t const* commitments_array[1] = {pc_rem};
    if (mpt_verify_aggregated_bulletproof(
            bp_ptr, kMPT_SINGLE_BULLETPROOF_SIZE, commitments_array, 1, context_hash) != 0)
    {
        valid = false;
    }

    return valid ? 0 : -1;
}

int
mpt_verify_send_range_proof(
    uint8_t const proof[kMPT_DOUBLE_BULLETPROOF_SIZE],
    uint8_t const amount_commitment[kMPT_PEDERSEN_COMMIT_SIZE],
    uint8_t const balance_commitment[kMPT_PEDERSEN_COMMIT_SIZE],
    uint8_t const context_hash[kMPT_HALF_SHA_SIZE])
{
    if (!proof || !amount_commitment || !balance_commitment || !context_hash)
        return -1;

    secp256k1_context const* ctx = mpt_secp256k1_context();
    if (!ctx)
        return -1;

    secp256k1_pubkey pc_amount, pc_balance;
    if (secp256k1_ec_pubkey_parse(ctx, &pc_amount, amount_commitment, kMPT_PEDERSEN_COMMIT_SIZE) !=
        1)
        return -1;

    if (secp256k1_ec_pubkey_parse(
            ctx, &pc_balance, balance_commitment, kMPT_PEDERSEN_COMMIT_SIZE) != 1)
        return -1;

    // Negate pc_amount point to get -pc_amount
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
    mpt_confidential_participant const* participants,
    uint8_t const n_participants,
    uint8_t const sender_spending_ciphertext[kMPT_ELGAMAL_TOTAL_SIZE],
    uint8_t const amount_commitment[kMPT_PEDERSEN_COMMIT_SIZE],
    uint8_t const balance_commitment[kMPT_PEDERSEN_COMMIT_SIZE],
    uint8_t const context_hash[kMPT_HALF_SHA_SIZE])
{
    if (!proof || !participants || !sender_spending_ciphertext || !amount_commitment ||
        !balance_commitment || !context_hash)
        return -1;

    if (n_participants != 3 && n_participants != 4)
        return -1;

    secp256k1_context* ctx = mpt_secp256k1_context();
    if (!ctx)
        return -1;

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
            // All participants must share the same c1 bytes.
            if (!std::equal(
                    participants[i].ciphertext,
                    participants[i].ciphertext + kMPT_ELGAMAL_CIPHER_SIZE,
                    participants[0].ciphertext))
                return -1;
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

    secp256k1_pubkey pc_m;
    if (secp256k1_ec_pubkey_parse(ctx, &pc_m, amount_commitment, kMPT_PEDERSEN_COMMIT_SIZE) != 1)
        return -1;

    secp256k1_pubkey pc_b;
    if (secp256k1_ec_pubkey_parse(ctx, &pc_b, balance_commitment, kMPT_PEDERSEN_COMMIT_SIZE) != 1)
        return -1;

    secp256k1_pubkey b1, b2;
    if (!mpt_make_ec_pair(sender_spending_ciphertext, &b1, &b2))
        return -1;

    // Accumulate validity to avoid leaking which proof component failed
    bool valid = true;

    if (secp256k1_compact_standard_verify(
            ctx,
            proof,
            n_participants,
            &c1,
            c2_vec.data(),
            pk_vec.data(),
            &pc_m,
            &pk_vec[0],
            &pc_b,
            &b1,
            &b2,
            context_hash) != 1)
    {
        valid = false;
    }

    if (mpt_verify_send_range_proof(
            proof + SECP256K1_COMPACT_STANDARD_PROOF_SIZE,
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
    uint8_t const proof[SECP256K1_COMPACT_CLAWBACK_PROOF_SIZE],
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

    secp256k1_pubkey pk;
    if (secp256k1_ec_pubkey_parse(ctx, &pk, pubkey, kMPT_PUBKEY_SIZE) != 1)
        return -1;

    secp256k1_pubkey c1, c2;
    if (!mpt_make_ec_pair(ciphertext, &c1, &c2))
        return -1;

    bool valid = true;

    if (secp256k1_compact_clawback_verify(ctx, proof, amount, &pk, &c1, &c2, context_hash) != 1)
        valid = false;

    return valid ? 0 : -1;
}
}
