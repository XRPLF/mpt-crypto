#ifndef MPT_PROTOCOL_H
#define MPT_PROTOCOL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// XRPL Transaction Types, the number MUST match rippled's definitions
#define ttCONFIDENTIAL_MPT_CONVERT 85
#define ttCONFIDENTIAL_MPT_MERGE_INBOX 86
#define ttCONFIDENTIAL_MPT_CONVERT_BACK 87
#define ttCONFIDENTIAL_MPT_SEND 88
#define ttCONFIDENTIAL_MPT_CLAWBACK 89

// General crypto primitive sizes in bytes
#define kMPT_HALF_SHA_SIZE 32
#define kMPT_PUBKEY_SIZE 33
#define kMPT_PRIVKEY_SIZE 32
#define kMPT_BLINDING_FACTOR_SIZE 32

// ElGamal & Pedersen primitive sizes in bytes
#define kMPT_ELGAMAL_CIPHER_SIZE 33
#define kMPT_ELGAMAL_TOTAL_SIZE 66
#define kMPT_PEDERSEN_COMMIT_SIZE 33

// Proof sizes in bytes
#define kMPT_SCHNORR_PROOF_SIZE 64
#define kMPT_SINGLE_BULLETPROOF_SIZE 688
#define kMPT_DOUBLE_BULLETPROOF_SIZE 754

// Context hash size
#define kMPT_ZKP_CONTEXT_HASH_SIZE 74

// Account ID size in bytes
#define kMPT_ACCOUNT_ID_SIZE 20

// MPTokenIssuance ID size in bytes
#define kMPT_ISSUANCE_ID_SIZE 24

/**
 * @brief Represents a unique 24-byte MPT issuance ID.
 */
typedef struct
{
    uint8_t bytes[kMPT_ISSUANCE_ID_SIZE];
} mpt_issuance_id;

/**
 * @brief Represents a 20-byte account ID.
 *
 * - bytes: Raw 20-byte array containing the AccountID.
 */
typedef struct account_id
{
    uint8_t bytes[kMPT_ACCOUNT_ID_SIZE];
} account_id;

#ifdef __cplusplus
}
#endif

#endif  // MPT_PROTOCOL_H
