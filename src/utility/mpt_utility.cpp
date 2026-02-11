#include <utility/mpt_utility.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <string.h>
#include <span>
#include <arpa/inet.h>
#include "mpt_internal.h"
#include <iostream>
#include <iomanip>
#include <sstream>

// --- Platform Endianness Support ---
#if defined(__APPLE__)
  #include <libkern/OSByteOrder.h>
  #define htobe64(x) OSSwapHostToBigInt64(x)
#elif defined(__linux__)
  #include <endian.h>
#else
  #if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    #define htobe64(x) __builtin_bswap64(x)
  #else
    #define htobe64(x) (x)
  #endif
#endif

// Helper to convert bytes to Hex
std::string debug_hex(const uint8_t* data, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i)
        ss << std::setw(2) << static_cast<int>(data[i]);
    std::string res = ss.str();
    for (auto & c : res) c = toupper(c);
    return res;
}

/**
 * Internal Context Manager (Singleton Pattern)
 */
secp256k1_context* mpt_secp256k1_context() {
    struct ContextHolder {
        secp256k1_context* ctx;
        ContextHolder() {
            ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        }
        ~ContextHolder() {
            if (ctx) secp256k1_context_destroy(ctx);
        }
    };
    static ContextHolder holder;
    return holder.ctx;
}

/**
 * Lightweight serializer.
 * Replicates the behavior of rippled's Serializer without the overhead.
 */
struct Serializer {
    uint8_t* buffer;
    size_t offset = 0;

    Serializer(uint8_t* buf) : buffer(buf) {}

    void add16(uint16_t val) {
        uint16_t n = htons(val);
        memcpy(buffer + offset, &n, 2);
        offset += 2;
    }

    void add32(uint32_t val) {
        uint32_t n = htonl(val);
        memcpy(buffer + offset, &n, 4);
        offset += 4;
    }

    void add64(uint64_t val) {
        uint64_t n = htobe64(val);
        memcpy(buffer + offset, &n, 8);
        offset += 8;
    }

    void addRaw(const uint8_t* data, size_t len) {
        memcpy(buffer + offset, data, len);
        offset += len;
    }
};

void sha512_half(const uint8_t* data, size_t len, uint8_t* out) {
    uint8_t full_hash[64];
    SHA512(data, len, full_hash);
    memcpy(out, full_hash, 32); 
}

void mpt_add_common_zkp_fields(Serializer& s, uint16_t txType, account_id acc, uint32_t seq, mpt_issuance_id iss) {
    s.add16(txType);
    s.addRaw(acc.bytes, 20);
    s.add32(seq);
    s.addRaw(iss.bytes, 24);
}

std::size_t get_multi_ciphertext_equality_proof_size(std::size_t n_recipients)
{
    // Points (33 bytes): T_m (1) + T_rG (n_recipients) + T_rP (n_recipients)
    // Scalars (32 bytes): s_m (1) + s_r (n_recipients)
    return ((1 + (2 * n_recipients)) * 33) + ((1 + n_recipients) * 32);
}

std::size_t get_confidential_send_proof_size(std::size_t n_recipients)
{
    // Equality Proof + Amount Linkage (195) + Balance Linkage (195)
    return get_multi_ciphertext_equality_proof_size(n_recipients) + (ec_pedersen_proof_length * 2);
}

bool mpt_make_ec_pair(
    const uint8_t buffer[ec_gamal_ciphertext_total_length],
    secp256k1_pubkey& out1,
    secp256k1_pubkey& out2)
{
    const secp256k1_context* ctx = mpt_secp256k1_context();

    int ret1 = secp256k1_ec_pubkey_parse(
        ctx, 
        &out1, 
        buffer, 
        ec_gamal_ciphertext_length);

    int ret2 = secp256k1_ec_pubkey_parse(
        ctx, 
        &out2, 
        buffer + ec_gamal_ciphertext_length, 
        ec_gamal_ciphertext_length);

    return (ret1 == 1 && ret2 == 1);
}

bool mpt_serialize_ec_pair(
    const secp256k1_pubkey& in1,
    const secp256k1_pubkey& in2,
    uint8_t out[ec_gamal_ciphertext_total_length])
{
    const secp256k1_context* ctx = mpt_secp256k1_context();
    size_t len = ec_gamal_ciphertext_length;

    // Serialize C1
    if (secp256k1_ec_pubkey_serialize(ctx, out, &len, &in1, SECP256K1_EC_COMPRESSED) != 1)
        return false;

    // Serialize C2
    len = ec_gamal_ciphertext_length;
    if (secp256k1_ec_pubkey_serialize(ctx, out + ec_gamal_ciphertext_length, &len, &in2, SECP256K1_EC_COMPRESSED) != 1)
        return false;

    return true;
}

// --- PUBLIC API IMPLEMENTATION ---
extern "C" {

int mpt_get_convert_context_hash(account_id acc, uint32_t seq, mpt_issuance_id iss, uint64_t amt, uint8_t out[32]) {
    uint8_t buf[128];
    Serializer s(buf);

    mpt_add_common_zkp_fields(s, ttCONFIDENTIAL_MPT_CONVERT, acc, seq, iss);
    s.add64(amt);

    sha512_half(buf, s.offset, out);
    return 0;
}

int mpt_get_convert_back_context_hash(account_id acc, uint32_t seq, mpt_issuance_id iss, uint64_t amt, uint32_t ver, uint8_t out[32]) {
    uint8_t buf[128];
    Serializer s(buf);

    mpt_add_common_zkp_fields(s, ttCONFIDENTIAL_MPT_CONVERT_BACK, acc, seq, iss);
    s.add64(amt);
    s.add32(ver);

    sha512_half(buf, s.offset, out);
    return 0;
}

int mpt_get_send_context_hash(account_id acc, uint32_t seq, mpt_issuance_id iss, account_id dest, uint32_t ver, uint8_t out[32]) {
    uint8_t buf[128];
    Serializer s(buf);

    mpt_add_common_zkp_fields(s, ttCONFIDENTIAL_MPT_SEND, acc, seq, iss);
    s.addRaw(dest.bytes, 20);
    s.add32(ver);

    sha512_half(buf, s.offset, out);
    return 0;
}

int mpt_get_clawback_context_hash(account_id acc, uint32_t seq, mpt_issuance_id iss, uint64_t amt, account_id holder, uint8_t out[32]) {
    uint8_t buf[128];
    Serializer s(buf);

    mpt_add_common_zkp_fields(s, ttCONFIDENTIAL_MPT_CLAWBACK, acc, seq, iss);
    s.add64(amt);
    s.addRaw(holder.bytes, 20);

    sha512_half(buf, s.offset, out);
    return 0;
}

int mpt_generate_keypair(uint8_t out_privkey[ec_priv_key_length], uint8_t out_pubkey[ec_pub_key_length]) {
   if (!out_privkey || !out_pubkey) return -1;

    std::span<uint8_t, ec_priv_key_length> priv(out_privkey, ec_priv_key_length);
    std::span<uint8_t, ec_pub_key_length> pub(out_pubkey, ec_pub_key_length);

    if (!secp256k1_elgamal_generate_keypair(mpt_secp256k1_context(), priv.data(), pub.data())) {
        return -1;
    }
    return 0;
}

int mpt_generate_blinding_factor(uint8_t out_factor[ec_blinding_factor_length]) {
    if (!out_factor) return -1;
    
    if (RAND_bytes(out_factor, ec_blinding_factor_length) != 1) {
        return -1;
    }
    return 0;
}

int mpt_encrypt_amount(
    uint64_t amount,
    const uint8_t pubkey[ec_pub_key_length],
    const uint8_t blinding_factor[ec_blinding_factor_length],
    uint8_t out_ciphertext[ec_gamal_ciphertext_total_length]) 
{
    if (!pubkey || !blinding_factor || !out_ciphertext) return -1;

    secp256k1_pubkey c1, c2, pk;
    std::memcpy(pk.data, pubkey, ec_pub_key_length);

    if (!secp256k1_elgamal_encrypt(
            mpt_secp256k1_context(), 
            &c1, 
            &c2, 
            &pk, 
            amount, 
            blinding_factor)) 
    {
        return -1;
    }

    if (!mpt_serialize_ec_pair(c1, c2, out_ciphertext))
    {
        return -1;
    }

    return 0;
}

int mpt_decrypt_amount(
    const uint8_t in_ciphertext[ec_gamal_ciphertext_total_length],
    const uint8_t privkey[ec_priv_key_length],
    uint64_t* out_amount) 
{
    if (!in_ciphertext || !privkey || !out_amount) return -1;

    secp256k1_pubkey c1, c2;

    if (!mpt_make_ec_pair(in_ciphertext, c1, c2))
        return -1;

    if (secp256k1_elgamal_decrypt(
            mpt_secp256k1_context(), 
            out_amount, 
            &c1, 
            &c2, 
            privkey) != 1)
    {
        return -1;
    }

    return 0;
}

int mpt_get_convert_proof(
    const uint8_t pubkey[64],
    const uint8_t privkey[32],
    const uint8_t ctx_hash[32],
    uint8_t out_proof[65]) 
{
    if (!pubkey || !privkey || !ctx_hash || !out_proof)
        return -1;

    if (secp256k1_mpt_pok_sk_prove(
            mpt_secp256k1_context(),
            out_proof,
            pubkey,
            privkey,
            ctx_hash) != 1) 
    {
        return -1;
    }

    return 0;
}

int mpt_get_pedersen_commitment(
    uint64_t amount,
    const uint8_t blinding_factor[32],
    uint8_t out_commitment[64]) 
{
    if (!blinding_factor || !out_commitment) {
        return -1;
    }

    if (amount == 0) {
        std::memset(out_commitment, 0, 64);
        return 0;
    }

    secp256k1_pubkey commitment;
    if (secp256k1_mpt_pedersen_commit(
            mpt_secp256k1_context(),
            &commitment,
            amount,
            blinding_factor) != 1) 
    {
        return -1;
    }

    std::memcpy(out_commitment, commitment.data, 64);
    return 0;
}

int mpt_get_amount_linkage_proof(
    const uint8_t pub[64],
    const uint8_t elgamal_r[32],
    const uint8_t context_hash[32],
    const mpt_pedersen_proof_params& params,
    uint8_t out[195])
{
    const secp256k1_context* ctx = mpt_secp256k1_context();

    secp256k1_pubkey c1, c2;
    if (!secp256k1_ec_pubkey_parse(ctx, &c1, params.encrypted_amount, 33) ||
        !secp256k1_ec_pubkey_parse(ctx, &c2, params.encrypted_amount + 33, 33))
    {
        return -1;
    }

    secp256k1_pubkey pk;
    std::memcpy(pk.data, pub, 64);

    secp256k1_pubkey pcm;
    std::memcpy(pcm.data, params.pedersen_commitment, 64);

    if (secp256k1_elgamal_pedersen_link_prove(
            ctx,
            out,
            &c1,
            &c2,
            &pk,
            &pcm,
            params.amount,
            elgamal_r,
            params.blinding_factor,
            context_hash) != 1)
    {
        return -1;
    }

    return 0;
}

int mpt_get_balance_linkage_proof(
    const uint8_t priv[32],
    const uint8_t pub[64],
    const uint8_t context_hash[32],
    const mpt_pedersen_proof_params& params,
    uint8_t out[195])
{
    const secp256k1_context* ctx = mpt_secp256k1_context();

    secp256k1_pubkey c1, c2;
    if (!secp256k1_ec_pubkey_parse(ctx, &c1, params.encrypted_amount, 33) ||
        !secp256k1_ec_pubkey_parse(ctx, &c2, params.encrypted_amount + 33, 33))
    {
        return -1;
    }

    secp256k1_pubkey pk;
    std::memcpy(pk.data, pub, 64);

    secp256k1_pubkey pcm;
    std::memcpy(pcm.data, params.pedersen_commitment, 64);

    if (secp256k1_elgamal_pedersen_link_prove(
            ctx,
            out,
            &pk, 
            &c2,           
            &c1,                    
            &pcm,                  
            params.amount,          
            priv,                  
            params.blinding_factor,
            context_hash) != 1)
    {
        return -1;
    }

    return 0;
}

int mpt_get_confidential_send_proof(
    const uint8_t priv[32],
    uint64_t amount,
    const std::vector<mpt_confidential_recipient>& recipients,
    const uint8_t tx_blinding_factor[32],
    const uint8_t context_hash[32],
    const mpt_pedersen_proof_params& amount_params,
    const mpt_pedersen_proof_params& balance_params,
    uint8_t* out_proof,
    size_t* out_len)
{
    const secp256k1_context* ctx = mpt_secp256k1_context();
    size_t nRecipients = recipients.size();

    std::vector<secp256k1_pubkey> r(nRecipients);
    std::vector<secp256k1_pubkey> s(nRecipients);
    std::vector<secp256k1_pubkey> pk(nRecipients);

    std::vector<uint8_t> sr;
    sr.reserve(nRecipients * 32);

    for (size_t i = 0; i < nRecipients; ++i)
    {
        const auto& rec = recipients[i];

        std::cout << "--------222\n";

        std::cout << "DEBUG: First 33 bytes: " << debug_hex(rec.encrypted_amount, 33) << std::endl;

        if (!secp256k1_ec_pubkey_parse(ctx, &r[i], rec.encrypted_amount, 33))
            return -1;

        std::cout << "--------333\n";
        if (!secp256k1_ec_pubkey_parse(ctx, &s[i], rec.encrypted_amount + 33, 33))
            return -1;

        std::memcpy(pk[i].data, rec.pubkey, 64);
        sr.insert(sr.end(), tx_blinding_factor, tx_blinding_factor + 32);
    }

    size_t sizeEq = secp256k1_mpt_prove_same_plaintext_multi_size(nRecipients);
    
    size_t totalRequired = sizeEq + 195 * 2;
    if (*out_len < totalRequired) {
        return -1; 
    }

    std::cout << "SIZEeQ" << sizeEq << "\n";

    // Get the multi-ciphertext equality proof
    if (secp256k1_mpt_prove_same_plaintext_multi(
            ctx, out_proof, &sizeEq, amount,
            nRecipients, r.data(), s.data(), pk.data(),
            sr.data(), context_hash) != 1) {
        return -1;
    }

    // Amount Linkage Proof
    uint8_t* amt_ptr = out_proof + sizeEq;
    if (mpt_get_amount_linkage_proof(
            pk[0].data, 
            tx_blinding_factor, 
            context_hash, 
            amount_params, 
            amt_ptr) != 0) {
        return -1;
    }

    // Balance Linkage Proof
    uint8_t* bal_ptr = amt_ptr + 195;
    if (mpt_get_balance_linkage_proof(
            priv, 
            pk[0].data, 
            context_hash, 
            balance_params, 
            bal_ptr) != 0) {
        return -1;
    }

    *out_len = totalRequired;
    return 0;
}
}