#include <utility/mpt_utility.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <cassert>

// Helper to convert bytes to Hex
std::string to_hex(const uint8_t* data, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i)
        ss << std::setw(2) << static_cast<int>(data[i]);
    std::string res = ss.str();
    for (auto & c : res) c = toupper(c);
    return res;
}

int main() {

    // Setup
    // Mock Accounts
    account_id mock_sender_account; 
    std::fill(std::begin(mock_sender_account.bytes), std::end(mock_sender_account.bytes), 0x11);

    account_id mock_dest_account; 
    std::fill(std::begin(mock_dest_account.bytes), std::end(mock_dest_account.bytes), 0x22);
    
    // Mock MPT Issuance ID
    mpt_issuance_id mock_issuance_id;
    std::fill(std::begin(mock_issuance_id.bytes), std::end(mock_issuance_id.bytes), 0x33);
    
    // Mock Sequence
    uint32_t mock_seq = 12345;

    // 1. Generate keypair for sender
    uint8_t priv[size_privkey];
    uint8_t pub[size_pubkey];
    assert(mpt_generate_keypair(priv, pub) == 0);

    std::cout << "Private Key (" << size_privkey << "-byte Hex): " << to_hex(priv, size_privkey) << std::endl;
    std::cout << "Public Key  (" << size_pubkey << "-byte Hex): " << to_hex(pub, size_pubkey) << std::endl;

    // 2. Encrypt an amount (500)
    uint8_t bf[size_blinding_factor];
    uint64_t amount_to_encrypt = 500;
    uint8_t ciphertext[size_gamal_ciphertext_total];
    assert(mpt_generate_blinding_factor(bf) == 0);
    std::cout << "Blinding Factor (" << size_blinding_factor << "-byte Hex): " << to_hex(bf, size_blinding_factor) << std::endl;
    assert(mpt_encrypt_amount(amount_to_encrypt, pub, bf, ciphertext) == 0);
    std::cout << "Encrypting Amount: " << amount_to_encrypt << " Ciphertext (" << size_gamal_ciphertext_total << "-byte Hex): " << to_hex(ciphertext, size_gamal_ciphertext_total) << std::endl;

    // 3. Decrypt to verify the Ciphertext is 500
    uint64_t decrypted_amount = 0;
    assert(mpt_decrypt_amount(ciphertext, priv, &decrypted_amount) == 0);
    assert(decrypted_amount == amount_to_encrypt);
    
    // 4. Generate proof for ConfidentialMPTConvert
    uint8_t tx_hash[32];
    assert(mpt_get_convert_context_hash(
        mock_sender_account, 
        mock_seq, 
        mock_issuance_id, 
        amount_to_encrypt, 
        tx_hash) == 0);

    uint8_t proof[size_schnorr_proof];
    assert(mpt_get_convert_proof(pub, priv, tx_hash, proof) == 0);
    std::cout << "ConfidentialMPTConvert Proof (" << size_schnorr_proof << "-byte Hex): " << to_hex(proof, size_schnorr_proof) << std::endl;

    /*
    // 5. Generate proof for ConfidentialMPTSend
    // Assume we are sending 100 from sender to dest
    uint64_t amount_to_send = 100;

    // 5(a) Generate blinding factor for ConfidentialMPTSend
    uint8_t send_bf[32];
    assert(mpt_generate_blinding_factor(send_bf) == 0);
    std::cout << "Send Blinding Factor (32-byte Hex): " << to_hex(send_bf, 32) << std::endl;

    // 5(b) Generate amount blinding factor and generate amount pedersen commitment.
    uint8_t amount_bf[32];
    assert(mpt_generate_blinding_factor(amount_bf) == 0);
    std::cout << "Amount Blinding Factor (32-byte Hex): " << to_hex(amount_bf, 32) << std::endl;

    uint8_t amount_commitment[64];
    assert(mpt_get_pedersen_commitment(amount_to_send, amount_bf, amount_commitment) == 0);
    std::cout << "Amount Pedersen Commitment (64-byte Hex): " << to_hex(amount_commitment, 64) << std::endl;

    // 5(c) Generate amount blinding factor and generate balance pedersen commitment.
    uint8_t balance_bf[32];
    assert(mpt_generate_blinding_factor(balance_bf) == 0);
    std::cout << "Balance Blinding Factor (32-byte Hex): " << to_hex(balance_bf, 32) << std::endl;

    // Let's assume the previous balance was 2000 (mock), this value MUST be exactly the same as
    // the sender's spending balance, you can track the spending balance internally in your code 
    // or use mpt_decrypt_amount to get it before generating the commitment.
    uint64_t mock_prev_balance = 2000;
    uint8_t balance_commitment[64];
    assert(mpt_get_pedersen_commitment(mock_prev_balance, balance_bf, balance_commitment) == 0);
    std::cout << "Balance Pedersen Commitment (64-byte Hex): " << to_hex(balance_commitment, 64) << std::endl;

    // 5(d) Generate context hash for ConfidentialMPTSend
    // This is just mock sequence, you should use the sequence for your sender account
    mock_seq += 1;  
    uint8_t send_ctx_hash[32];
    assert(mpt_get_send_context_hash(
        mock_sender_account, 
        mock_seq, 
        mock_issuance_id, 
        mock_dest_account, 
        1, // version
        send_ctx_hash) == 0);

    // 5(e) Prepare the ciphertext, if you have auditor, you need to prepare auditor ciphertext as well.
    // 5(e)(i) encrypt using sender pub key
    uint8_t sender_ciphertext[66];
    assert(mpt_encrypt_amount(amount_to_send, pub, send_bf, sender_ciphertext) == 0);
    std::cout << "Sender Ciphertext (66-byte Hex): " << to_hex(sender_ciphertext, 66) << std::endl;

    // 5(e)(ii) encryt using dest pub key
    uint8_t dest_priv[32];
    uint8_t dest_pub[64];
    uint8_t dest_ciphertext[66];
    assert(mpt_generate_keypair(dest_priv, dest_pub) == 0);
    assert(mpt_encrypt_amount(amount_to_send, dest_pub, send_bf, dest_ciphertext) == 0);
    std::cout << "Dest Ciphertext (66-byte Hex): " << to_hex(dest_ciphertext, 66) << std::endl;

    // 5(e)(iii) Encrypt using Issuer pub key
    uint8_t issuer_priv[32];
    uint8_t issuer_pub[64];
    uint8_t issuer_ciphertext[66];
    assert(mpt_generate_keypair(issuer_priv, issuer_pub) == 0);
    assert(mpt_encrypt_amount(amount_to_send, issuer_pub, send_bf, issuer_ciphertext) == 0);
    std::cout << "Issuer Ciphertext (66-byte Hex): " << to_hex(issuer_ciphertext, 66) << std::endl;

    // 5(f) Bundle everything into the recipients vector
    // If you have auditor, add auditor as well.
    std::vector<mpt_confidential_recipient> recipients;
    
    mpt_confidential_recipient r_sender;
    std::memcpy(r_sender.pubkey, pub, size_pubkey);
    std::memcpy(r_sender.encrypted_amount, sender_ciphertext, size_gamal_ciphertext);
    recipients.push_back(r_sender);

    mpt_confidential_recipient r_dest;
    std::memcpy(r_dest.pubkey, dest_pub, size_pubkey);
    std::memcpy(r_dest.encrypted_amount, dest_ciphertext, size_gamal_ciphertext);
    recipients.push_back(r_dest);

    mpt_confidential_recipient r_issuer;
    std::memcpy(r_issuer.pubkey, issuer_pub, size_pubkey);
    std::memcpy(r_issuer.encrypted_amount, issuer_ciphertext, size_gamal_ciphertext);
    recipients.push_back(r_issuer);

    // 5(g) Prepare the pedersen params.
    // 5(g)(i) Prepare pedersen amount params.
    mpt_pedersen_proof_params amt_params;
    amt_params.amount = amount_to_send;
    std::memcpy(amt_params.pedersen_commitment, amount_commitment, 64);
    std::memcpy(amt_params.encrypted_amount, sender_ciphertext, size_gamal_ciphertext);
    std::memcpy(amt_params.blinding_factor, amount_bf, 32);

    // 5(g)(ii) Prepare pedersen balance params.
    // mock_prev_balance = 2000, so we will have the corresponding encrypted amount.
    // You should read from ledger in real case. This is just a test, so we will encrypt 2000 here,
    // pretending we retrieve the sender spending balance from ledger.
    uint8_t mock_bf[32];
    uint8_t mock_prev_balance_ciphertext[128];
    assert(mpt_generate_blinding_factor(mock_bf) == 0);
    assert(mpt_encrypt_amount(mock_prev_balance, pub, mock_bf, mock_prev_balance_ciphertext) == 0);

    mpt_pedersen_proof_params bal_params;
    bal_params.amount = mock_prev_balance;
    std::memcpy(bal_params.pedersen_commitment, balance_commitment, 64);
    std::memcpy(bal_params.encrypted_amount, mock_prev_balance_ciphertext, 128);
    std::memcpy(bal_params.blinding_factor, balance_bf, 32);

    // 5(h) Generate the ConfidentialMPTSend proof
    size_t proof_len = get_confidential_send_proof_size(recipients.size());
    std::vector<uint8_t> final_proof_vec(proof_len);
    uint8_t* final_proof = final_proof_vec.data();

    int proof_res = mpt_get_confidential_send_proof(
        priv, 
        amount_to_send, 
        recipients, 
        send_bf, 
        send_ctx_hash, 
        amt_params, 
        bal_params, 
        final_proof, 
        &proof_len
    );

    assert(proof_res == 0);
    std::cout << "ConfidentialMPTSend Proof (" << proof_len << "-byte Hex): " 
              << to_hex(final_proof, proof_len) << std::endl;
    */
    std::cout << "\n[SUCCESS] All assertions passed!" << std::endl;

    return 0;
}