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
    uint8_t full_hash[SHA512_DIGEST_LENGTH];
    SHA512(data, len, full_hash);
    memcpy(out, full_hash, SHA512_DIGEST_LENGTH / 2); 
}

void mpt_add_common_zkp_fields(Serializer& s, uint16_t txType, account_id acc, uint32_t seq, mpt_issuance_id iss) {
    s.add16(txType);
    s.addRaw(acc.bytes, size_acc);
    s.add32(seq);
    s.addRaw(iss.bytes, size_iss);
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
    return get_multi_ciphertext_equality_proof_size(n_recipients) + (size_pedersen_proof * 2);
}

bool mpt_make_ec_pair(
    const uint8_t buffer[size_gamal_ciphertext_total],
    secp256k1_pubkey& out1,
    secp256k1_pubkey& out2)
{
    const secp256k1_context* ctx = mpt_secp256k1_context();

    int ret1 = secp256k1_ec_pubkey_parse(
        ctx, 
        &out1, 
        buffer, 
        size_gamal_ciphertext);

    int ret2 = secp256k1_ec_pubkey_parse(
        ctx, 
        &out2, 
        buffer + size_gamal_ciphertext, 
        size_gamal_ciphertext);

    return (ret1 == 1 && ret2 == 1);
}

bool mpt_serialize_ec_pair(
    const secp256k1_pubkey& in1,
    const secp256k1_pubkey& in2,
    uint8_t out[size_gamal_ciphertext_total])
{
    const secp256k1_context* ctx = mpt_secp256k1_context();
    size_t len = size_gamal_ciphertext;

    // Serialize C1
    if (secp256k1_ec_pubkey_serialize(ctx, out, &len, &in1, SECP256K1_EC_COMPRESSED) != 1)
        return false;

    // Serialize C2
    len = size_gamal_ciphertext;
    if (secp256k1_ec_pubkey_serialize(ctx, out + size_gamal_ciphertext, &len, &in2, SECP256K1_EC_COMPRESSED) != 1)
        return false;

    return true;
}

// --- PUBLIC API IMPLEMENTATION ---
extern "C" {

int mpt_get_convert_context_hash(account_id acc, uint32_t seq, mpt_issuance_id iss, uint64_t amt, uint8_t out_hash[size_half_sha]) {
    uint8_t buf[mpt_convert_hash_size];
    Serializer s(buf);

    mpt_add_common_zkp_fields(s, ttCONFIDENTIAL_MPT_CONVERT, acc, seq, iss);
    s.add64(amt);

    sha512_half(buf, s.offset, out_hash);
    return 0;
}

int mpt_get_convert_back_context_hash(account_id acc, uint32_t seq, mpt_issuance_id iss, uint64_t amt, uint32_t ver, uint8_t out_hash[size_half_sha]) {
    uint8_t buf[mpt_convert_back_hash_size];
    Serializer s(buf);

    mpt_add_common_zkp_fields(s, ttCONFIDENTIAL_MPT_CONVERT_BACK, acc, seq, iss);
    s.add64(amt);
    s.add32(ver);

    sha512_half(buf, s.offset, out_hash);
    return 0;
}

int mpt_get_send_context_hash(account_id acc, uint32_t seq, mpt_issuance_id iss, account_id dest, uint32_t ver, uint8_t out_hash[size_half_sha]) {
    uint8_t buf[mpt_send_hash_size];
    Serializer s(buf);

    mpt_add_common_zkp_fields(s, ttCONFIDENTIAL_MPT_SEND, acc, seq, iss);
    s.addRaw(dest.bytes, size_acc);
    s.add32(ver);

    sha512_half(buf, s.offset, out_hash);
    return 0;
}

int mpt_get_clawback_context_hash(account_id acc, uint32_t seq, mpt_issuance_id iss, uint64_t amt, account_id holder, uint8_t out_hash[size_half_sha]) {
    uint8_t buf[mpt_clawback_hash_size];
    Serializer s(buf);

    mpt_add_common_zkp_fields(s, ttCONFIDENTIAL_MPT_CLAWBACK, acc, seq, iss);
    s.add64(amt);
    s.addRaw(holder.bytes, size_acc);

    sha512_half(buf, s.offset, out_hash);
    return 0;
}

int mpt_generate_keypair(uint8_t out_privkey[size_privkey], uint8_t out_pubkey[size_pubkey]) {
   if (!out_privkey || !out_pubkey) return -1;

    std::span<uint8_t, size_privkey> priv(out_privkey, size_privkey);
    std::span<uint8_t, size_pubkey> pub(out_pubkey, size_pubkey);

    if (!secp256k1_elgamal_generate_keypair(mpt_secp256k1_context(), priv.data(), pub.data())) {
        return -1;
    }
    return 0;
}

int mpt_generate_blinding_factor(uint8_t out_factor[size_blinding_factor]) {
    if (!out_factor) return -1;
    
    if (RAND_bytes(out_factor, size_blinding_factor) != 1) {
        return -1;
    }
    return 0;
}

int mpt_encrypt_amount(
    uint64_t amount,
    const uint8_t pubkey[size_pubkey],
    const uint8_t blinding_factor[size_blinding_factor],
    uint8_t out_ciphertext[size_gamal_ciphertext_total]) 
{
    if (!pubkey || !blinding_factor || !out_ciphertext) return -1;

    secp256k1_pubkey c1, c2, pk;
    std::memcpy(pk.data, pubkey, size_pubkey);

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
    const uint8_t in_ciphertext[size_gamal_ciphertext_total],
    const uint8_t privkey[size_privkey],
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
    const uint8_t pubkey[size_pubkey],
    const uint8_t privkey[size_privkey],
    const uint8_t ctx_hash[size_half_sha],
    uint8_t out_proof[size_schnorr_proof]) 
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
    const uint8_t blinding_factor[size_blinding_factor],
    uint8_t out_commitment[size_pedersen_commitment]) 
{
    if (!blinding_factor || !out_commitment) {
        return -1;
    }

    // todo: zero amount
    if (amount == 0) {
        std::memset(out_commitment, 0, size_pedersen_commitment);
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

    std::memcpy(out_commitment, commitment.data, size_pedersen_commitment);

    return 0;
}

int mpt_get_amount_linkage_proof(
    const uint8_t pubkey[size_pubkey],
    const uint8_t blinding_factor[size_blinding_factor],
    const uint8_t context_hash[size_half_sha],
    const mpt_pedersen_proof_params* params,
    uint8_t out[size_pedersen_proof])
{
    if (!pubkey || !blinding_factor || !context_hash || !out)
        return -1;
    
    const secp256k1_context* ctx = mpt_secp256k1_context();

    secp256k1_pubkey c1, c2;
    if (!secp256k1_ec_pubkey_parse(ctx, &c1, params->encrypted_amount, size_gamal_ciphertext))
        return -1; 

    if (!secp256k1_ec_pubkey_parse(ctx, &c2, params->encrypted_amount + size_gamal_ciphertext, size_gamal_ciphertext))
        return -1;

    secp256k1_pubkey pk, pcm;
    std::memcpy(pk.data, pubkey, size_pubkey);
    std::memcpy(pcm.data, params->pedersen_commitment, size_pedersen_commitment);

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

int mpt_get_balance_linkage_proof(
    const uint8_t priv[size_privkey],
    const uint8_t pub[size_pubkey],
    const uint8_t context_hash[size_half_sha],
    const mpt_pedersen_proof_params* params,
    uint8_t out[size_pedersen_proof])
{
    if (!pub || !priv || !context_hash || !out)
        return -1;
    
    const secp256k1_context* ctx = mpt_secp256k1_context();

    secp256k1_pubkey c1, c2;
    if (!secp256k1_ec_pubkey_parse(ctx, &c1, params->encrypted_amount, size_gamal_ciphertext))
        return -1;

    if (!secp256k1_ec_pubkey_parse(ctx, &c2, params->encrypted_amount + size_gamal_ciphertext, size_gamal_ciphertext))
        return -1;

    secp256k1_pubkey pk, pcm;
    std::memcpy(pk.data, pub, size_pubkey);
    std::memcpy(pcm.data, params->pedersen_commitment, size_pedersen_commitment);

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

int mpt_get_confidential_send_proof(
    const uint8_t priv[size_privkey],
    uint64_t amount,
    const mpt_confidential_recipient* recipients,
    size_t n_recipients,
    const uint8_t tx_blinding_factor[size_blinding_factor],
    const uint8_t context_hash[size_half_sha],
    const mpt_pedersen_proof_params* amount_params,
    const mpt_pedersen_proof_params* balance_params,
    uint8_t* out_proof,
    size_t* out_len)
{
    if (!priv || !recipients || !out_proof || !out_len) return -1;

    const secp256k1_context* ctx = mpt_secp256k1_context();
    
    std::vector<secp256k1_pubkey> r(n_recipients);
    std::vector<secp256k1_pubkey> s(n_recipients);
    std::vector<secp256k1_pubkey> pk(n_recipients);
    std::vector<uint8_t> sr;
    sr.reserve(n_recipients * size_blinding_factor);

    for (size_t i = 0; i < n_recipients; ++i)
    {
        const auto& rec = recipients[i];

        std::cout << "--------222\n";

        std::cout << "DEBUG: First 33 bytes: " << debug_hex(rec.encrypted_amount, 33) << std::endl;

        if (!secp256k1_ec_pubkey_parse(ctx, &r[i], rec.encrypted_amount, size_gamal_ciphertext))
            return -1;

        std::cout << "--------333\n";
        if (!secp256k1_ec_pubkey_parse(ctx, &s[i], rec.encrypted_amount + size_gamal_ciphertext, size_gamal_ciphertext))
            return -1;

        std::memcpy(pk[i].data, rec.pubkey, size_pubkey);
        sr.insert(sr.end(), tx_blinding_factor, tx_blinding_factor + size_blinding_factor);
    }

    size_t size_equality = secp256k1_mpt_prove_same_plaintext_multi_size(n_recipients);
    
    size_t totalRequired = size_equality + size_pedersen_proof * 2;
    
    if (*out_len < totalRequired) {
        return -1; 
    }

    std::cout << "SIZEeQ" << size_equality << "\n";

    // Get the multi-ciphertext equality proof
    if (secp256k1_mpt_prove_same_plaintext_multi(
            ctx, out_proof, &size_equality, amount,
            n_recipients, r.data(), s.data(), pk.data(),
            sr.data(), context_hash) != 1) {
        return -1;
    }

    // Amount Linkage Proof
    uint8_t* amt_ptr = out_proof + size_equality;
    if (mpt_get_amount_linkage_proof(
            pk[0].data, 
            tx_blinding_factor, 
            context_hash, 
            amount_params, 
            amt_ptr) != 0) {
        return -1;
    }

    // Balance Linkage Proof
    uint8_t* bal_ptr = amt_ptr + size_pedersen_proof;
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