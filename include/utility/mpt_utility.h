#ifndef MPT_UTILITY_H
#define MPT_UTILITY_H

#include <secp256k1.h>
#include <stdint.h>
#include <vector>

#ifdef __cplusplus
extern "C" {
#endif

// XRPL Transaction Types
#define ttCONFIDENTIAL_MPT_CONVERT       85
#define ttCONFIDENTIAL_MPT_MERGE_INBOX   86
#define ttCONFIDENTIAL_MPT_CONVERT_BACK  87
#define ttCONFIDENTIAL_MPT_SEND          88
#define ttCONFIDENTIAL_MPT_CLAWBACK      89

static constexpr std::size_t ec_pub_key_length = 64; 
static constexpr std::size_t ec_priv_key_length = 32;
static constexpr std::size_t ec_blinding_factor_length = 32;
static constexpr std::size_t ec_gamal_ciphertext_length = 33;
static constexpr std::size_t ec_gamal_ciphertext_total_length = 66;
static constexpr std::size_t ec_schnorr_proof_length = 65;
static constexpr std::size_t ec_equality_proof_length = 98;
static constexpr std::size_t ec_pedersen_commitment_length = 64;
static constexpr std::size_t ec_pedersen_proof_length = 195;

typedef struct {
    uint8_t bytes[24]; 
} mpt_issuance_id;

typedef struct {
    uint8_t bytes[20];
} account_id;

/**
 * @brief Represents a recipient in a Confidential Send transaction.
 */
struct mpt_confidential_recipient {
    uint8_t pubkey[ec_pub_key_length]; // The recipient's public key
    uint8_t encrypted_amount[ec_gamal_ciphertext_total_length]; // The C1 and C2 points (ElGamal)
};

/**
 * @brief Parameters required to generate a Pedersen Linkage Proof.
 * This links an ElGamal ciphertext to a Pedersen commitment.
 */
struct mpt_pedersen_proof_params {
    uint8_t pedersen_commitment[ec_pedersen_commitment_length]; // Pedersen Commitment
    uint64_t amount; // The amount in public format (for proof generation)
    uint8_t encrypted_amount[ec_gamal_ciphertext_total_length];   // ElGamal Ciphertext (C1, C2)
    uint8_t blinding_factor[ec_blinding_factor_length];     // The 'r' used in the commitment
};

/**
 * @brief Context Hash for CONVERT
 */
int mpt_get_convert_context_hash(
    account_id account,
    uint32_t sequence,
    mpt_issuance_id issuanceID,
    uint64_t amount,
    uint8_t out_hash[32]);

/**
 * @brief Context Hash for CONVERT_BACK
 */
int mpt_get_convert_back_context_hash(
    account_id account,
    uint32_t sequence,
    mpt_issuance_id issuanceID,
    uint64_t amount,
    uint32_t version,
    uint8_t out_hash[32]);

/**
 * @brief Context Hash for SEND
 */
int mpt_get_send_context_hash(
    account_id account,
    uint32_t sequence,
    mpt_issuance_id issuanceID,
    account_id destination,
    uint32_t version,
    uint8_t out_hash[32]);

/**
 * @brief Context Hash for CLAWBACK
 */
int mpt_get_clawback_context_hash(
    account_id account,
    uint32_t sequence,
    mpt_issuance_id issuanceID,
    uint64_t amount,
    account_id holder,
    uint8_t out_hash[32]);

/**
 * @brief Calculates the size of the Multi-Ciphertext Equality Proof.
 */
std::size_t get_multi_ciphertext_equality_proof_size(std::size_t n_recipients);

/**
 * @brief Calculates the total size for a ConfidentialMPTSend proof.
 */
std::size_t get_confidential_send_proof_size(std::size_t n_recipients);

/**
 * @brief Parses a 66-byte buffer into two internal secp256k1 public keys.
 * @param buffer [in] 66-byte buffer containing two compressed points.
 * @param out1   [out] First internal public key (C1).
 * @param out2   [out] Second internal public key (C2).
 * @return true on success, false if parsing fails.
 */
bool mpt_make_ec_pair(
    const uint8_t buffer[ec_gamal_ciphertext_total_length],
    secp256k1_pubkey& out1,
    secp256k1_pubkey& out2);

/**
 * @brief Parses a 66-byte buffer into two internal secp256k1 public keys.
 * * This is the "Inverse" of serialization. It takes a compressed 66-byte wire 
 * format ciphertext (C1 + C2) and converts it into internal structures 
 * suitable for cryptographic operations like decryption or proof generation.
 * * @param buffer [in] 66-byte buffer containing two 33-byte compressed points.
 * @param out1   [out] Decoded internal format of the first point (C1).
 * @param out2   [out] Decoded internal format of the second point (C2).
 * @return true if both points were valid and successfully parsed, false otherwise.
 */
bool mpt_serialize_ec_pair(
    const secp256k1_pubkey& in1,
    const secp256k1_pubkey& in2,
    uint8_t out[ec_gamal_ciphertext_total_length]);

/**
 * @brief Generates a new Secp256k1 ElGamal keypair.
 * @param out_privkey [out] A 32-byte buffer where the private key will be stored.
 * @param out_pubkey  [out] A 64-byte buffer where the uncompressed public key.
 * @return 0 on success, -1 on failure.
 */
int mpt_generate_keypair(uint8_t out_privkey[ec_priv_key_length], uint8_t out_pubkey[ec_pub_key_length]);

/**
 * @brief Generates a cryptographically secure 32-byte blinding factor.
 * @param out_factor [out] A 32-byte buffer where the random blinding factor 
 * will be stored.
 * @return 0 on success, -1 on failure.
 */
int mpt_generate_blinding_factor(uint8_t out_factor[ec_blinding_factor_length]);

/**
 * @brief Encrypts a uint64 amount using an ElGamal public key.
 * @param amount The value to encrypt.
 * @param pubkey 64-byte public key.
 * @param blinding_factor 32-byte random factor.
 * @param out_ciphertext 66-byte buffer to store (C1, C2).
 * @return 0 on success, -1 on failure.
 */
int mpt_encrypt_amount(
    uint64_t amount,
    const uint8_t pubkey[ec_pub_key_length],
    const uint8_t blinding_factor[ec_blinding_factor_length],
    uint8_t out_ciphertext[ec_gamal_ciphertext_total_length]);

/**
 * @brief Decrypts an MPT amount from a ciphertext pair.
 * @param ciphertext 66-byte buffer
 * @param privkey 32-byte private key.
 * @param out_amount Pointer to store the recovered uint64_t.
 * @return 0 on success, -1 on failure.
 */
int mpt_decrypt_amount(
    const uint8_t ciphertext[ec_gamal_ciphertext_total_length],
    const uint8_t privkey[ec_priv_key_length],
    uint64_t* out_amount);

/**
 * @brief Generates a Schnorr Proof of Knowledge for a Confidential MPT conversion.
 *
 * This proof is used in 'ConfidentialMPTConvert' transactions to prove the 
 * sender possesses the private key associated with the account, binding it 
 * to the specific transaction via the ctx_hash.
 *
 * @param pubkey    [in]  64-byte public key of the account.
 * @param privkey   [in]  32-byte private key of the account.
 * @param ctx_hash  [in]  32-byte hash of the transaction (challenge).
 * @param out_proof [out] 65-byte buffer to store the Schnorr proof.
 * @return 0 on success, -1 on failure.
 */
int mpt_get_convert_proof(
    const uint8_t pubkey[64],
    const uint8_t privkey[32],
    const uint8_t ctx_hash[32],
    uint8_t out_proof[65]);

/**
 * @brief Computes a Pedersen Commitment point for Confidential MPT.
 * @param amount           [in]  The 64-bit unsigned integer value to commit.
 * @param blinding_factor  [in]  A 32-byte secret scalar (rho) used to hide the amount. 
 * @param out_commitment   [out] A 64-byte buffer to store the commitment
 */
int mpt_get_pedersen_commitment(
    uint64_t amount,
    const uint8_t blinding_factor[32],
    uint8_t out_commitment[64]);

/**
 * @brief Generates a ZK linkage proof between an ElGamal ciphertext and a Pedersen commitment.
 * @param pub                 [in] 64-byte internal format of the sender's public key.
 * @param elgamal_r           [in] 32-byte blinding factor used for the ElGamal encryption.
 * @param context_hash        [in] 32-byte hash of the transaction context.
 * @param params              [in] Struct containing commitment, amount, and ciphertext.
 * @param out                 [out] Buffer of exactly 195 bytes to store the proof.
 * @return 0 on success, -1 on failure.
 */
int mpt_get_amount_linkage_proof(
    const uint8_t pub[64],
    const uint8_t elgamal_r[32],
    const uint8_t context_hash[32],
    const mpt_pedersen_proof_params& params,
    uint8_t out[195]);

/**
 * @brief Generates a ZK linkage proof for the sender's balance.
 * @param priv                [in] 32-byte private key of the sender.
 * @param pub                 [in] 64-byte internal format of the sender's public key.
 * @param context_hash        [in] 32-byte hash of the transaction context.
 * @param params              [in] Struct containing commitment, amount, and ciphertext.
 * @param out                 [out] Buffer of exactly 195 bytes to store the proof.
 * @return 0 on success, -1 on failure.
 */
int mpt_get_balance_linkage_proof(
    const uint8_t priv[32],
    const uint8_t pub[64],
    const uint8_t context_hash[32],
    const mpt_pedersen_proof_params& params,
    uint8_t out[195]);

/**
 * @brief Generates the full ConfidentialMPTSend proof and fills a provided buffer.
 * @param priv.             [in] The sender's 32-byte private key.
 * @param amount            [in] The amount being sent.
 * @param recipients        [in] List of recipients (Sender, Dest, Issuer).
 * @param tx_blinding_factor [in] The ElGamal 'r' used for the transaction.
 * @param context_hash      [in] The 32-byte context hash.
 * @param amount_params     [in] Linkage params for the transaction amount.
 * @param balance_params    [in] Linkage params for the sender's balance.
 * @param out_proof         [out] Pointer to the buffer to be filled with the hex/bytes.
 * @param out_len           [in/out] In: Size of the buffer. Out: Actual bytes written.
 * @return 0 on success, -1 on failure (e.g., buffer too small or math error).
 */
int mpt_get_confidential_send_proof(
    const uint8_t priv[32],
    uint64_t amount,
    const std::vector<mpt_confidential_recipient>& recipients,
    const uint8_t tx_blinding_factor[32],
    const uint8_t context_hash[32],
    const mpt_pedersen_proof_params& amount_params,
    const mpt_pedersen_proof_params& balance_params, uint8_t* out_proof, size_t* out_len);
#ifdef __cplusplus
}
#endif
#endif