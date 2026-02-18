#include <arpa/inet.h>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <secp256k1_mpt.h>
#include <span>
#include <sstream>
#include <string.h>
#include <utility/mpt_utility.h>

// Platform endianness support for serialization
#if defined(__APPLE__)
#include <libkern/OSByteOrder.h>
#define htobe64(x) OSSwapHostToBigInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)

#elif defined(__linux__) || defined(__CYGWIN__)
#include <endian.h>
#ifndef htobe64
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define htobe64(x) __builtin_bswap64(x)
#define be64toh(x) __builtin_bswap64(x)
#else
#define htobe64(x) (x)
#define be64toh(x) (x)
#endif
#endif

#elif defined(_WIN32)
#include <stdlib.h>
#define htobe64(x) _byteswap_uint64(x)
#define be64toh(x) _byteswap_uint64(x)

#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <sys/endian.h>

#else
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define htobe64(x) __builtin_bswap64(x)
#define be64toh(x) __builtin_bswap64(x)
#else
#define htobe64(x) (x)
#define be64toh(x) (x)
#endif
#endif

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

/**
 * Lightweight serializer.
 * Replicates the behavior of rippled's Serializer without the overhead.
 */
struct Serializer
{
    uint8_t* buffer;
    size_t offset = 0;

    Serializer(uint8_t* buf) : buffer(buf)
    {
    }

    void
    add16(uint16_t val)
    {
        uint16_t n = htons(val);
        memcpy(buffer + offset, &n, 2);
        offset += 2;
    }

    void
    add32(uint32_t val)
    {
        uint32_t n = htonl(val);
        memcpy(buffer + offset, &n, 4);
        offset += 4;
    }

    void
    add64(uint64_t val)
    {
        uint64_t n = htobe64(val);
        memcpy(buffer + offset, &n, 8);
        offset += 8;
    }

    void
    addRaw(uint8_t const* data, size_t len)
    {
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
    uint32_t seq,
    mpt_issuance_id iss)
{
    s.add16(txType);
    s.addRaw(acc.bytes, kMPT_ACCOUNT_ID_SIZE);
    s.add32(seq);
    s.addRaw(iss.bytes, kMPT_ISSUANCE_ID_SIZE);
}

extern "C" {
size_t
get_multi_ciphertext_equality_proof_size(size_t n_recipients)
{
    return secp256k1_mpt_prove_same_plaintext_multi_size(n_recipients);
}

size_t
get_confidential_send_proof_size(size_t n_recipients)
{
    return get_multi_ciphertext_equality_proof_size(n_recipients) + (kMPT_PEDERSEN_LINK_SIZE * 2);
}

bool
mpt_make_ec_pair(
    uint8_t const buffer[kMPT_GAMAL_TOTAL_SIZE],
    secp256k1_pubkey& out1,
    secp256k1_pubkey& out2)
{
    secp256k1_context const* ctx = mpt_secp256k1_context();
    if (!ctx)
        return -1;

    int ret1 = secp256k1_ec_pubkey_parse(ctx, &out1, buffer, kMPT_GAMAL_CIPHER_SIZE);

    int ret2 = secp256k1_ec_pubkey_parse(
        ctx, &out2, buffer + kMPT_GAMAL_CIPHER_SIZE, kMPT_GAMAL_CIPHER_SIZE);

    return (ret1 == 1 && ret2 == 1);
}

bool
mpt_serialize_ec_pair(
    secp256k1_pubkey const& in1,
    secp256k1_pubkey const& in2,
    uint8_t out[kMPT_GAMAL_TOTAL_SIZE])
{
    secp256k1_context const* ctx = mpt_secp256k1_context();
    if (!ctx)
        return -1;

    size_t len = kMPT_GAMAL_CIPHER_SIZE;

    if (secp256k1_ec_pubkey_serialize(ctx, out, &len, &in1, SECP256K1_EC_COMPRESSED) != 1)
        return false;

    len = kMPT_GAMAL_CIPHER_SIZE;
    if (secp256k1_ec_pubkey_serialize(
            ctx, out + kMPT_GAMAL_CIPHER_SIZE, &len, &in2, SECP256K1_EC_COMPRESSED) != 1)
        return false;

    return true;
}

int
mpt_get_convert_context_hash(
    account_id acc,
    uint32_t seq,
    mpt_issuance_id iss,
    uint64_t amt,
    uint8_t out_hash[kMPT_HALF_SHA_SIZE])
{
    uint8_t buf[kMPT_CONVERT_HASH_SIZE];
    Serializer s(buf);

    mpt_add_common_zkp_fields(s, ttCONFIDENTIAL_MPT_CONVERT, acc, seq, iss);
    s.add64(amt);

    sha512_half(buf, s.offset, out_hash);
    return 0;
}

int
mpt_get_convert_back_context_hash(
    account_id acc,
    uint32_t seq,
    mpt_issuance_id iss,
    uint64_t amt,
    uint32_t ver,
    uint8_t out_hash[kMPT_HALF_SHA_SIZE])
{
    uint8_t buf[kMPT_CONVERT_BACK_HASH_SIZE];
    Serializer s(buf);

    mpt_add_common_zkp_fields(s, ttCONFIDENTIAL_MPT_CONVERT_BACK, acc, seq, iss);
    s.add64(amt);
    s.add32(ver);

    sha512_half(buf, s.offset, out_hash);
    return 0;
}

int
mpt_get_send_context_hash(
    account_id acc,
    uint32_t seq,
    mpt_issuance_id iss,
    account_id dest,
    uint32_t ver,
    uint8_t out_hash[kMPT_HALF_SHA_SIZE])
{
    uint8_t buf[kMPT_SEND_HASH_SIZE];
    Serializer s(buf);

    mpt_add_common_zkp_fields(s, ttCONFIDENTIAL_MPT_SEND, acc, seq, iss);
    s.addRaw(dest.bytes, kMPT_ACCOUNT_ID_SIZE);
    s.add32(ver);

    sha512_half(buf, s.offset, out_hash);
    return 0;
}

int
mpt_get_clawback_context_hash(
    account_id acc,
    uint32_t seq,
    mpt_issuance_id iss,
    uint64_t amt,
    account_id holder,
    uint8_t out_hash[kMPT_HALF_SHA_SIZE])
{
    uint8_t buf[kMPT_CLAWBACK_HASH_SIZE];
    Serializer s(buf);

    mpt_add_common_zkp_fields(s, ttCONFIDENTIAL_MPT_CLAWBACK, acc, seq, iss);
    s.add64(amt);
    s.addRaw(holder.bytes, kMPT_ACCOUNT_ID_SIZE);

    sha512_half(buf, s.offset, out_hash);
    return 0;
}

int
mpt_generate_keypair(uint8_t* out_priv, uint8_t* out_pub)
{
    secp256k1_context const* ctx = mpt_secp256k1_context();
    if (!ctx)
        return -1;

    secp256k1_pubkey pub;
    if (secp256k1_elgamal_generate_keypair(ctx, out_priv, &pub) != 1)
        return -1;

    std::memcpy(out_pub, pub.data, kMPT_PUBKEY_SIZE);

    return 0;
}

int
mpt_generate_blinding_factor(uint8_t out_factor[kMPT_BLINDING_FACTOR_SIZE])
{
    if (!out_factor)
        return -1;

    if (RAND_bytes(out_factor, kMPT_BLINDING_FACTOR_SIZE) != 1)
        return -1;

    return 0;
}

int
mpt_encrypt_amount(
    uint64_t amount,
    uint8_t const pubkey[kMPT_PUBKEY_SIZE],
    uint8_t const blinding_factor[kMPT_BLINDING_FACTOR_SIZE],
    uint8_t out_ciphertext[kMPT_GAMAL_TOTAL_SIZE])
{
    if (!pubkey || !blinding_factor || !out_ciphertext)
        return -1;

    secp256k1_context const* ctx = mpt_secp256k1_context();
    if (!ctx)
        return -1;

    secp256k1_pubkey c1, c2, pk;
    std::memcpy(pk.data, pubkey, kMPT_PUBKEY_SIZE);

    if (!secp256k1_elgamal_encrypt(ctx, &c1, &c2, &pk, amount, blinding_factor))
        return -1;

    if (!mpt_serialize_ec_pair(c1, c2, out_ciphertext))
        return -1;

    return 0;
}

int
mpt_decrypt_amount(
    uint8_t const in_ciphertext[kMPT_GAMAL_TOTAL_SIZE],
    uint8_t const privkey[kMPT_PRIVKEY_SIZE],
    uint64_t* out_amount)
{
    if (!in_ciphertext || !privkey || !out_amount)
        return -1;

    secp256k1_context const* ctx = mpt_secp256k1_context();
    if (!ctx)
        return -1;

    secp256k1_pubkey c1, c2;

    if (!mpt_make_ec_pair(in_ciphertext, c1, c2))
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
    std::memcpy(pk.data, pubkey, kMPT_PUBKEY_SIZE);

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

    // todo: zero amount
    if (amount == 0)
    {
        std::memset(out_commitment, 0, kMPT_PEDERSEN_COMMIT_SIZE);
        return 0;
    }

    secp256k1_pubkey commitment;
    if (secp256k1_mpt_pedersen_commit(ctx, &commitment, amount, blinding_factor) != 1)
        return -1;

    std::memcpy(out_commitment, commitment.data, kMPT_PEDERSEN_COMMIT_SIZE);

    return 0;
}

int
mpt_get_amount_linkage_proof(
    uint8_t const pubkey[kMPT_PUBKEY_SIZE],
    uint8_t const blinding_factor[kMPT_BLINDING_FACTOR_SIZE],
    uint8_t const context_hash[kMPT_HALF_SHA_SIZE],
    mpt_pedersen_proof_params const* params,
    uint8_t out[kMPT_PEDERSEN_LINK_SIZE])
{
    if (!pubkey || !blinding_factor || !context_hash || !out)
        return -1;

    secp256k1_context const* ctx = mpt_secp256k1_context();
    if (!ctx)
        return -1;

    secp256k1_pubkey c1, c2;
    if (!secp256k1_ec_pubkey_parse(ctx, &c1, params->encrypted_amount, kMPT_GAMAL_CIPHER_SIZE))
        return -1;

    if (!secp256k1_ec_pubkey_parse(
            ctx, &c2, params->encrypted_amount + kMPT_GAMAL_CIPHER_SIZE, kMPT_GAMAL_CIPHER_SIZE))
        return -1;

    secp256k1_pubkey pk, pcm;
    std::memcpy(pk.data, pubkey, kMPT_PUBKEY_SIZE);
    std::memcpy(pcm.data, params->pedersen_commitment, kMPT_PEDERSEN_COMMIT_SIZE);

    if (secp256k1_elgamal_pedersen_link_prove(
            ctx,
            out,
            &c1,
            &c2,
            &pk,
            &pcm,
            params->amount,
            blinding_factor,
            params->blinding_factor,
            context_hash) != 1)
    {
        return -1;
    }

    return 0;
}

int
mpt_get_balance_linkage_proof(
    uint8_t const priv[kMPT_PRIVKEY_SIZE],
    uint8_t const pub[kMPT_PUBKEY_SIZE],
    uint8_t const context_hash[kMPT_HALF_SHA_SIZE],
    mpt_pedersen_proof_params const* params,
    uint8_t out[kMPT_PEDERSEN_LINK_SIZE])
{
    if (!pub || !priv || !context_hash || !out)
        return -1;

    secp256k1_context const* ctx = mpt_secp256k1_context();
    if (!ctx)
        return -1;

    secp256k1_pubkey c1, c2;
    if (!secp256k1_ec_pubkey_parse(ctx, &c1, params->encrypted_amount, kMPT_GAMAL_CIPHER_SIZE))
        return -1;

    if (!secp256k1_ec_pubkey_parse(
            ctx, &c2, params->encrypted_amount + kMPT_GAMAL_CIPHER_SIZE, kMPT_GAMAL_CIPHER_SIZE))
        return -1;

    secp256k1_pubkey pk, pcm;
    std::memcpy(pk.data, pub, kMPT_PUBKEY_SIZE);
    std::memcpy(pcm.data, params->pedersen_commitment, kMPT_PEDERSEN_COMMIT_SIZE);

    if (secp256k1_elgamal_pedersen_link_prove(
            ctx,
            out,
            &pk,
            &c2,
            &c1,
            &pcm,
            params->amount,
            priv,
            params->blinding_factor,
            context_hash) != 1)
    {
        return -1;
    }

    return 0;
}

int
mpt_get_confidential_send_proof(
    uint8_t const priv[kMPT_PRIVKEY_SIZE],
    uint64_t amount,
    mpt_confidential_recipient const* recipients,
    size_t n_recipients,
    uint8_t const tx_blinding_factor[kMPT_BLINDING_FACTOR_SIZE],
    uint8_t const context_hash[kMPT_HALF_SHA_SIZE],
    mpt_pedersen_proof_params const* amount_params,
    mpt_pedersen_proof_params const* balance_params,
    uint8_t* out_proof,
    size_t* out_len)
{
    if (!priv || !recipients || !out_proof || !out_len)
        return -1;

    secp256k1_context const* ctx = mpt_secp256k1_context();
    if (!ctx)
        return -1;

    std::vector<secp256k1_pubkey> r(n_recipients);
    std::vector<secp256k1_pubkey> s(n_recipients);
    std::vector<secp256k1_pubkey> pk(n_recipients);

    std::vector<uint8_t> sr;
    sr.reserve(n_recipients * kMPT_BLINDING_FACTOR_SIZE);

    for (size_t i = 0; i < n_recipients; ++i)
    {
        auto const& rec = recipients[i];

        if (!secp256k1_ec_pubkey_parse(ctx, &r[i], rec.encrypted_amount, kMPT_GAMAL_CIPHER_SIZE))
            return -1;

        if (!secp256k1_ec_pubkey_parse(
                ctx, &s[i], rec.encrypted_amount + kMPT_GAMAL_CIPHER_SIZE, kMPT_GAMAL_CIPHER_SIZE))
            return -1;

        std::memcpy(pk[i].data, rec.pubkey, kMPT_PUBKEY_SIZE);
        sr.insert(sr.end(), tx_blinding_factor, tx_blinding_factor + kMPT_BLINDING_FACTOR_SIZE);
    }

    size_t size_equality = secp256k1_mpt_prove_same_plaintext_multi_size(n_recipients);
    size_t totalRequired = size_equality + kMPT_PEDERSEN_LINK_SIZE * 2;

    if (*out_len < totalRequired)
        return -1;

    // Get the multi-ciphertext equality proof
    if (secp256k1_mpt_prove_same_plaintext_multi(
            ctx,
            out_proof,
            &size_equality,
            amount,
            n_recipients,
            r.data(),
            s.data(),
            pk.data(),
            sr.data(),
            context_hash) != 1)
    {
        return -1;
    }

    // Amount Linkage Proof
    uint8_t* amt_ptr = out_proof + size_equality;
    if (mpt_get_amount_linkage_proof(
            pk[0].data, tx_blinding_factor, context_hash, amount_params, amt_ptr) != 0)
    {
        return -1;
    }

    // Balance Linkage Proof
    uint8_t* bal_ptr = amt_ptr + kMPT_PEDERSEN_LINK_SIZE;
    if (mpt_get_balance_linkage_proof(priv, pk[0].data, context_hash, balance_params, bal_ptr) != 0)
    {
        return -1;
    }

    *out_len = totalRequired;

    // todo: add range proof
    return 0;
}

int
mpt_get_convert_back_proof(
    uint8_t const priv[kMPT_PRIVKEY_SIZE],
    uint8_t const pub[kMPT_PUBKEY_SIZE],
    uint8_t const context_hash[kMPT_HALF_SHA_SIZE],
    mpt_pedersen_proof_params const* params,
    uint8_t out_proof[kMPT_PEDERSEN_LINK_SIZE])
{
    return mpt_get_balance_linkage_proof(priv, pub, context_hash, params, out_proof);

    // todo: add range proof
}

int
mpt_get_clawback_proof(
    uint8_t const priv[kMPT_PRIVKEY_SIZE],
    uint8_t const pub[kMPT_PUBKEY_SIZE],
    uint8_t const context_hash[kMPT_HALF_SHA_SIZE],
    uint64_t const amount,
    uint8_t const encrypted_amount[kMPT_GAMAL_TOTAL_SIZE],
    uint8_t out_proof[kMPT_EQUALITY_PROOF_SIZE])
{
    if (!priv || !pub || !context_hash || !encrypted_amount || !out_proof)
        return -1;

    secp256k1_context const* ctx = mpt_secp256k1_context();
    if (!ctx)
        return -1;

    secp256k1_pubkey pk;
    std::memcpy(pk.data, pub, kMPT_PUBKEY_SIZE);

    secp256k1_pubkey c1, c2;
    if (!mpt_make_ec_pair(encrypted_amount, c1, c2))
        return -1;

    if (secp256k1_equality_plaintext_prove(
            ctx, out_proof, &pk, &c2, &c1, amount, priv, context_hash) != 1)
    {
        return -1;
    }

    return 0;
}
}
