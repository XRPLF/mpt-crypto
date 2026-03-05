#include "test_utils.h"

#include <algorithm>
#include <iostream>
#include <vector>
#include <secp256k1_mpt.h>
#include <utility/mpt_utility.h>

// helper to create mock accounts and issuance IDs
template <typename T>
T create_mock_id(uint8_t fill) {
    T mock;
    std::fill(std::begin(mock.bytes), std::end(mock.bytes), fill);
    return mock;
}

void
test_encryption_decryption()
{
    uint8_t priv[kMPT_PRIVKEY_SIZE];
    uint8_t pub[kMPT_PUBKEY_SIZE];
    uint8_t bf[kMPT_BLINDING_FACTOR_SIZE];
    uint8_t ciphertext[kMPT_ELGAMAL_TOTAL_SIZE];
    EXPECT(mpt_generate_keypair(priv, pub) == 0);

    std::vector<uint64_t> test_amounts = {
        0, 1, 1000,
        // todo: due to the lib's current limitation, large numbers
        // are not supported yet. We need to add them back once the limitation is fixed.
        // 123456789,
        // 10000000000ULL
    };

    for (uint64_t original_amount : test_amounts)
    {
        uint64_t decrypted_amount = 0;

        EXPECT(mpt_generate_blinding_factor(bf) == 0);
        EXPECT(mpt_encrypt_amount(original_amount, pub, bf, ciphertext) == 0);
        EXPECT(mpt_decrypt_amount(ciphertext, priv, &decrypted_amount) == 0);
        EXPECT(decrypted_amount == original_amount);
    }
}

void
test_mpt_confidential_convert()
{
    // Setup mock account, issuance and transaction details
    account_id acc = create_mock_id<account_id>(0xAA);
    mpt_issuance_id issuance = create_mock_id<mpt_issuance_id>(0xBB);
    uint32_t seq = 12345;
    uint64_t convert_amount = 750;

    uint8_t priv[kMPT_PRIVKEY_SIZE];
    uint8_t pub[kMPT_PUBKEY_SIZE];
    uint8_t bf[kMPT_BLINDING_FACTOR_SIZE];
    uint8_t ciphertext[kMPT_ELGAMAL_TOTAL_SIZE];
    uint8_t tx_hash[kMPT_HALF_SHA_SIZE];
    uint8_t proof[kMPT_SCHNORR_PROOF_SIZE];

    // Generate keypair, blinding factor and encrypt the amount
    EXPECT(mpt_generate_keypair(priv, pub) == 0);
    EXPECT(mpt_generate_blinding_factor(bf) == 0);
    EXPECT(mpt_encrypt_amount(convert_amount, pub, bf, ciphertext) == 0);

    // Generate context hash and ZKProof
    EXPECT(mpt_get_convert_context_hash(acc, seq, issuance, convert_amount, tx_hash) == 0);
    EXPECT(mpt_get_convert_proof(pub, priv, tx_hash, proof) == 0);

    // Vefify the ZKProof for convert
    EXPECT(mpt_verify_convert_proof(proof, pub, tx_hash) == 0);
}

void
test_mpt_confidential_send()
{
    // Setup mock account, issuance and transaction details
    account_id sender_acc = create_mock_id<account_id>(0x11);
    account_id dest_acc = create_mock_id<account_id>(0x22);
    mpt_issuance_id issuance = create_mock_id<mpt_issuance_id>(0xBB);
    uint32_t seq = 54321;
    uint64_t amount_to_send = 100;
    uint64_t prev_balance = 2000;
    uint32_t version = 1;

    // Generate Keypairs for all parties
    uint8_t sender_priv[kMPT_PRIVKEY_SIZE], sender_pub[kMPT_PUBKEY_SIZE];
    uint8_t dest_priv[kMPT_PRIVKEY_SIZE], dest_pub[kMPT_PUBKEY_SIZE];
    uint8_t issuer_priv[kMPT_PRIVKEY_SIZE], issuer_pub[kMPT_PUBKEY_SIZE];

    EXPECT(mpt_generate_keypair(sender_priv, sender_pub) == 0);
    EXPECT(mpt_generate_keypair(dest_priv, dest_pub) == 0);
    EXPECT(mpt_generate_keypair(issuer_priv, issuer_pub) == 0);

    // Encrypt for all recipients (using same shared blinding factor for link proof)
    uint8_t shared_bf[kMPT_BLINDING_FACTOR_SIZE];
    EXPECT(mpt_generate_blinding_factor(shared_bf) == 0);

    uint8_t sender_ct[kMPT_ELGAMAL_TOTAL_SIZE];
    uint8_t dest_ct[kMPT_ELGAMAL_TOTAL_SIZE];
    uint8_t issuer_ct[kMPT_ELGAMAL_TOTAL_SIZE];

    EXPECT(mpt_encrypt_amount(amount_to_send, sender_pub, shared_bf, sender_ct) == 0);
    EXPECT(mpt_encrypt_amount(amount_to_send, dest_pub, shared_bf, dest_ct) == 0);
    EXPECT(mpt_encrypt_amount(amount_to_send, issuer_pub, shared_bf, issuer_ct) == 0);

    // Prepare recipients that is expected by the confidential send proof function
    std::vector<mpt_confidential_participant> recipients;
    auto add_recipient = [&](uint8_t* p, uint8_t* c) {
        mpt_confidential_participant r;
        std::copy(p, p + kMPT_PUBKEY_SIZE, r.pubkey);
        std::copy(c, c + kMPT_ELGAMAL_TOTAL_SIZE, r.ciphertext);
        recipients.push_back(r);
    };
    add_recipient(sender_pub, sender_ct);
    add_recipient(dest_pub, dest_ct);
    add_recipient(issuer_pub, issuer_ct);

    // Generate pedersen commitments for amount and balance
    uint8_t amount_bf[kMPT_BLINDING_FACTOR_SIZE];
    uint8_t amount_comm[kMPT_PEDERSEN_COMMIT_SIZE];
    EXPECT(mpt_generate_blinding_factor(amount_bf) == 0);
    EXPECT(mpt_get_pedersen_commitment(amount_to_send, amount_bf, amount_comm) == 0);

    uint8_t balance_bf[kMPT_BLINDING_FACTOR_SIZE];
    uint8_t balance_comm[kMPT_PEDERSEN_COMMIT_SIZE];
    EXPECT(mpt_generate_blinding_factor(balance_bf) == 0);
    EXPECT(mpt_get_pedersen_commitment(prev_balance, balance_bf, balance_comm) == 0);

    // Generate context hash for the transaction
    uint8_t send_ctx_hash[kMPT_HALF_SHA_SIZE];
    EXPECT(
        mpt_get_send_context_hash(sender_acc, seq, issuance, dest_acc, version, send_ctx_hash) ==
        0);

    // Prepare pedersen proof params for both amount and balance linkage proofs
    mpt_pedersen_proof_params amt_params;
    amt_params.amount = amount_to_send;
    std::copy(amount_bf, amount_bf + kMPT_BLINDING_FACTOR_SIZE, amt_params.blinding_factor);
    std::copy(amount_comm, amount_comm + kMPT_PEDERSEN_COMMIT_SIZE, amt_params.pedersen_commitment);
    std::copy(sender_ct, sender_ct + kMPT_ELGAMAL_TOTAL_SIZE, amt_params.ciphertext);

    mpt_pedersen_proof_params bal_params;
    bal_params.amount = prev_balance;
    std::copy(balance_bf, balance_bf + kMPT_BLINDING_FACTOR_SIZE, bal_params.blinding_factor);
    std::copy(balance_comm, balance_comm + kMPT_PEDERSEN_COMMIT_SIZE, bal_params.pedersen_commitment);

    uint8_t prev_bal_bf[kMPT_BLINDING_FACTOR_SIZE];
    uint8_t prev_bal_ct[kMPT_ELGAMAL_TOTAL_SIZE];
    EXPECT(mpt_generate_blinding_factor(prev_bal_bf) == 0);
    EXPECT(mpt_encrypt_amount(prev_balance, sender_pub, prev_bal_bf, prev_bal_ct) == 0);
    std::copy(prev_bal_ct, prev_bal_ct + kMPT_ELGAMAL_TOTAL_SIZE, bal_params.ciphertext);

    // Generate the confidential send proof
    size_t proof_len = get_confidential_send_proof_size(recipients.size());
    std::vector<uint8_t> proof(proof_len);

    // Verify the confidential send proof
    EXPECT(mpt_get_confidential_send_proof(
        sender_priv,
        amount_to_send,
        recipients.data(),
        3,
        shared_bf,
        send_ctx_hash,
        &amt_params,
        &bal_params,
        proof.data(),
        &proof_len) == 0);
}

void
test_mpt_convert_back()
{
    // Setup mock account, issuance and transaction details
    account_id acc = create_mock_id<account_id>(0x55);
    mpt_issuance_id issuance = create_mock_id<mpt_issuance_id>(0xEE);
    uint32_t seq = 98765;
    uint64_t current_balance = 5000;
    uint64_t amount_to_convert_back = 1000;
    uint32_t version = 2;

    uint8_t priv[kMPT_PRIVKEY_SIZE], pub[kMPT_PUBKEY_SIZE];
    EXPECT(mpt_generate_keypair(priv, pub) == 0);

    // Mock spending confidential balance.
    // This is the ElGamal ciphertext currently stored on-chain.
    uint8_t bal_bf[kMPT_BLINDING_FACTOR_SIZE];
    uint8_t spending_bal_ct[kMPT_ELGAMAL_TOTAL_SIZE];
    EXPECT(mpt_generate_blinding_factor(bal_bf) == 0);
    EXPECT(mpt_encrypt_amount(current_balance, pub, bal_bf, spending_bal_ct) == 0);

    // Generate context hash
    uint8_t context_hash[kMPT_HALF_SHA_SIZE];
    EXPECT(
        mpt_get_convert_back_context_hash(
            acc, seq, issuance, amount_to_convert_back, version, context_hash) == 0);

    // Generate pedersen commitments for current balance
    uint8_t pcm_bf[kMPT_BLINDING_FACTOR_SIZE];
    uint8_t pcm_comm[kMPT_PEDERSEN_COMMIT_SIZE];
    EXPECT(mpt_generate_blinding_factor(pcm_bf) == 0);
    EXPECT(mpt_get_pedersen_commitment(current_balance, pcm_bf, pcm_comm) == 0);

    // Prepare pedersen proof params
    mpt_pedersen_proof_params pc_params;
    pc_params.amount = current_balance;
    std::copy(pcm_bf, pcm_bf + kMPT_BLINDING_FACTOR_SIZE, pc_params.blinding_factor);
    std::copy(pcm_comm, pcm_comm + kMPT_PEDERSEN_COMMIT_SIZE, pc_params.pedersen_commitment);
    std::copy(spending_bal_ct, spending_bal_ct + kMPT_ELGAMAL_TOTAL_SIZE, pc_params.ciphertext);

    // Generate convert back proof
    uint8_t proof[kMPT_PEDERSEN_LINK_SIZE + kMPT_SINGLE_BULLETPROOF_SIZE];
    EXPECT(mpt_get_convert_back_proof(priv, pub, context_hash, amount_to_convert_back, &pc_params, proof) == 0);

    // Vefify the ZKProof for convert back
    EXPECT(mpt_verify_convert_back_proof(
        proof,
        pub,
        spending_bal_ct,
        pcm_comm,
        amount_to_convert_back,
        context_hash) == 0);
}

void
test_mpt_clawback()
{
    // Setup mock account, issuance and transaction details
    account_id issuer_acc = create_mock_id<account_id>(0x11);
    account_id holder_acc = create_mock_id<account_id>(0x22);
    mpt_issuance_id issuance = create_mock_id<mpt_issuance_id>(0xCC);

    uint32_t seq = 200;
    uint64_t claw_amount = 500;

    uint8_t issuer_priv[kMPT_PRIVKEY_SIZE], issuer_pub[kMPT_PUBKEY_SIZE];
    EXPECT(mpt_generate_keypair(issuer_priv, issuer_pub) == 0);

    // Generate context hash
    uint8_t context_hash[kMPT_HALF_SHA_SIZE];
    EXPECT(
        mpt_get_clawback_context_hash(
            issuer_acc, seq, issuance, claw_amount, holder_acc, context_hash) == 0);

    // Mock holder's "sfIssuerEncryptedBalance"
    uint8_t bf[kMPT_BLINDING_FACTOR_SIZE];
    uint8_t issuer_encrypted_bal[kMPT_ELGAMAL_TOTAL_SIZE];
    EXPECT(mpt_generate_blinding_factor(bf) == 0);
    EXPECT(mpt_encrypt_amount(claw_amount, issuer_pub, bf, issuer_encrypted_bal) == 0);

    // Generate clawback proof
    uint8_t proof[kMPT_EQUALITY_PROOF_SIZE];
    EXPECT(mpt_get_clawback_proof(
        issuer_priv, issuer_pub, context_hash, claw_amount, issuer_encrypted_bal, proof) == 0);

    // Verify the clawback proof
    EXPECT(mpt_verify_clawback_proof(
        proof,
        claw_amount,
        issuer_pub,
        issuer_encrypted_bal,
        context_hash
    ) == 0);
}

int
main()
{
    test_encryption_decryption();
    test_mpt_confidential_convert();
    test_mpt_confidential_send();
    test_mpt_convert_back();
    test_mpt_clawback();

    std::cout << "\n[SUCCESS] All assertions passed!" << std::endl;

    return 0;
}
