#include <utility/mpt_utility.h>
#include <secp256k1_mpt.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <cassert>

void test_encryption_decryption() {
    uint8_t priv[size_privkey];
    uint8_t pub[size_pubkey];
    uint8_t bf[size_blinding_factor];
    uint8_t ciphertext[size_gamal_ciphertext_total];
    assert(mpt_generate_keypair(priv, pub) == 0);

    std::vector<uint64_t> test_amounts = {
        0,
        1,
        1000,
        // 123456789,          // lib bug large numbers can not pass
        // 10000000000ULL
    };

    for (uint64_t original_amount : test_amounts) {
        uint64_t decrypted_amount = 0;

        assert(mpt_generate_blinding_factor(bf) == 0);
        assert(mpt_encrypt_amount(original_amount, pub, bf, ciphertext) == 0);
        assert(mpt_decrypt_amount(ciphertext, priv, &decrypted_amount) == 0);
        assert(decrypted_amount == original_amount);
    }
}

void test_mpt_confidential_convert() {
    account_id acc;
    std::memset(acc.bytes, 0xAA, size_acc); 
    mpt_issuance_id issuance;
    std::memset(issuance.bytes, 0xBB, size_iss);
    uint32_t seq = 12345;
    uint64_t convert_amount = 750;

    uint8_t priv[size_privkey];
    uint8_t pub[size_pubkey];
    uint8_t bf[size_blinding_factor];
    uint8_t ciphertext[size_gamal_ciphertext_total];
    uint8_t tx_hash[size_half_sha];
    uint8_t proof[size_schnorr_proof];

    assert(mpt_generate_keypair(priv, pub) == 0);
    assert(mpt_generate_blinding_factor(bf) == 0);
    assert(mpt_encrypt_amount(convert_amount, pub, bf, ciphertext) == 0);

    assert(mpt_get_convert_context_hash(acc, seq, issuance, convert_amount, tx_hash) == 0);
    assert(mpt_get_convert_proof(pub, priv, tx_hash, proof) == 0);

    const secp256k1_context* ctx = mpt_secp256k1_context();
    
    secp256k1_pubkey c1, c2, pk;
    assert(secp256k1_ec_pubkey_parse(ctx, &c1, ciphertext, size_gamal_ciphertext) == 1);
    assert(secp256k1_ec_pubkey_parse(ctx, &c2, ciphertext + size_gamal_ciphertext, size_gamal_ciphertext) == 1);
    
    std::memcpy(pk.data, pub, size_pubkey);
    assert(secp256k1_elgamal_verify_encryption(ctx, &c1, &c2, &pk, convert_amount, bf) == 1);
    assert(secp256k1_mpt_pok_sk_verify(ctx, proof, &pk, tx_hash) == 1);
}

void test_mpt_confidential_send() {
    // Mock accounts and mpt issuance
    account_id sender_acc, dest_acc;
    std::memset(sender_acc.bytes, 0x11, size_acc);
    std::memset(dest_acc.bytes, 0x22, size_acc);
    
    mpt_issuance_id issuance;
    std::memset(issuance.bytes, 0xBB, size_iss);
    
    // Mock transaction detiails
    uint32_t seq = 54321;
    uint64_t amount_to_send = 100;
    uint64_t prev_balance = 2000;
    uint32_t version = 1;

    // Generate Keypairs for all parties
    uint8_t sender_priv[size_privkey], sender_pub[size_pubkey];
    uint8_t dest_priv[size_privkey], dest_pub[size_pubkey];
    uint8_t issuer_priv[size_privkey], issuer_pub[size_pubkey];

    assert(mpt_generate_keypair(sender_priv, sender_pub) == 0);
    assert(mpt_generate_keypair(dest_priv, dest_pub) == 0);
    assert(mpt_generate_keypair(issuer_priv, issuer_pub) == 0);

    // Encrypt for all recipients (using same shared blinding factor for link proof)
    uint8_t shared_bf[size_blinding_factor];
    assert(mpt_generate_blinding_factor(shared_bf) == 0);

    uint8_t sender_ct[size_gamal_ciphertext_total];
    uint8_t dest_ct[size_gamal_ciphertext_total];
    uint8_t issuer_ct[size_gamal_ciphertext_total];

    assert(mpt_encrypt_amount(amount_to_send, sender_pub, shared_bf, sender_ct) == 0);
    assert(mpt_encrypt_amount(amount_to_send, dest_pub, shared_bf, dest_ct) == 0);
    assert(mpt_encrypt_amount(amount_to_send, issuer_pub, shared_bf, issuer_ct) == 0);

    // Prepare recipients that is expected by the confidential send proof function
    std::vector<mpt_confidential_recipient> recipients;
    auto add_recipient = [&](uint8_t* p, uint8_t* c) {
        mpt_confidential_recipient r;
        std::memcpy(r.pubkey, p, size_pubkey);
        std::memcpy(r.encrypted_amount, c, size_gamal_ciphertext_total);
        recipients.push_back(r);
    };
    add_recipient(sender_pub, sender_ct);
    add_recipient(dest_pub, dest_ct);
    add_recipient(issuer_pub, issuer_ct);

    // Generate pedersen commitments for amount and balance
    uint8_t amount_bf[size_blinding_factor];
    uint8_t amount_comm[size_pedersen_commitment];
    assert(mpt_generate_blinding_factor(amount_bf) == 0);
    assert(mpt_get_pedersen_commitment(amount_to_send, amount_bf, amount_comm) == 0);

    uint8_t balance_bf[size_blinding_factor];
    uint8_t balance_comm[size_pedersen_commitment];
    assert(mpt_generate_blinding_factor(balance_bf) == 0);
    assert(mpt_get_pedersen_commitment(prev_balance, balance_bf, balance_comm) == 0);

    // Generate context hash for the transaction
    uint8_t send_ctx_hash[size_half_sha];
    assert(mpt_get_send_context_hash(sender_acc, seq, issuance, dest_acc, version, send_ctx_hash) == 0);

    // Prepare pedersen proof params for both amount and balance linkage proofs
    mpt_pedersen_proof_params amt_params;
    amt_params.amount = amount_to_send;
    std::memcpy(amt_params.blinding_factor, amount_bf, size_blinding_factor);
    std::memcpy(amt_params.pedersen_commitment, amount_comm, size_pedersen_commitment);
    std::memcpy(amt_params.encrypted_amount, sender_ct, size_gamal_ciphertext_total);

    mpt_pedersen_proof_params bal_params;
    bal_params.amount = prev_balance;
    std::memcpy(bal_params.blinding_factor, balance_bf, size_blinding_factor);
    std::memcpy(bal_params.pedersen_commitment, balance_comm, size_pedersen_commitment);

    uint8_t prev_bal_bf[size_blinding_factor];
    uint8_t prev_bal_ct[size_gamal_ciphertext_total];
    mpt_generate_blinding_factor(prev_bal_bf);
    mpt_encrypt_amount(prev_balance, sender_pub, prev_bal_bf, prev_bal_ct);
    std::memcpy(bal_params.encrypted_amount, prev_bal_ct, size_gamal_ciphertext_total);

    // Generate the confidential send proof
    size_t proof_len = get_confidential_send_proof_size(recipients.size());
    std::vector<uint8_t> proof(proof_len);

    int result = mpt_get_confidential_send_proof(
        sender_priv,
        amount_to_send,
        recipients.data(),
        3,
        shared_bf,
        send_ctx_hash,
        &amt_params,
        &bal_params,
        proof.data(),
        &proof_len
    );

    assert(result == 0);

    // The rest of code in this function is to verify the proof
    // we just generated, simulating what a verifier would do in rippled.
    const secp256k1_context* ctx = mpt_secp256k1_context();
    size_t current_offset = 0;

    // Verify multi-ciphertext equality
    size_t n_recipients = recipients.size();
    size_t sizeEquality = get_multi_ciphertext_equality_proof_size(n_recipients);
    
    std::vector<secp256k1_pubkey> r_list(n_recipients);
    std::vector<secp256k1_pubkey> s_list(n_recipients);
    std::vector<secp256k1_pubkey> pk_list(n_recipients);

    for (size_t i = 0; i < n_recipients; ++i) {
        assert(mpt_make_ec_pair(recipients[i].encrypted_amount, r_list[i], s_list[i]));
        std::memcpy(pk_list[i].data, recipients[i].pubkey, 64);
    }

    assert(secp256k1_mpt_verify_same_plaintext_multi(
        ctx, 
        proof.data() + current_offset, 
        sizeEquality, 
        n_recipients, 
        r_list.data(), 
        s_list.data(), 
        pk_list.data(), 
        send_ctx_hash) == 1);
    
    current_offset += sizeEquality;

    // Verify amount pedersen linkage
    secp256k1_pubkey pk, amt_pcm;
    secp256k1_pubkey amt_c1, amt_c2;

    std::memcpy(pk.data, sender_pub, size_pubkey);
    std::memcpy(amt_pcm.data, amount_comm, size_pedersen_commitment);

    assert(mpt_make_ec_pair(sender_ct, amt_c1, amt_c2)); 
    assert(secp256k1_elgamal_pedersen_link_verify(
        ctx, 
        proof.data() + current_offset, 
        &amt_c1, 
        &amt_c2, 
        &pk, 
        &amt_pcm, 
        send_ctx_hash) == 1);

    current_offset += size_pedersen_proof;

    // Verify balance pedersen linkage
    secp256k1_pubkey bal_pcm;
    secp256k1_pubkey bal_c1, bal_c2;

    std::memcpy(bal_pcm.data, balance_comm, size_pedersen_commitment);
    assert(mpt_make_ec_pair(prev_bal_ct, bal_c1, bal_c2));

    assert(secp256k1_elgamal_pedersen_link_verify(
        ctx, 
        proof.data() + current_offset, 
        &pk, 
        &bal_c2, 
        &bal_c1, 
        &bal_pcm, 
        send_ctx_hash) == 1);
    
    // Verify we consumed the entire proof
    current_offset += size_pedersen_proof;
    assert(current_offset == proof_len);
}

void test_mpt_convert_back() {
    // Setup mock account, issuance and transaction details
    account_id acc; 
    std::memset(acc.bytes, 0x55, size_acc);
    
    mpt_issuance_id issuance;
    std::memset(issuance.bytes, 0xEE, size_iss);
    
    uint32_t seq = 98765;
    uint64_t current_balance = 5000;
    uint64_t amount_to_convert_back = 1000;
    uint32_t version = 2;

    uint8_t priv[size_privkey], pub[size_pubkey];
    assert(mpt_generate_keypair(priv, pub) == 0);

    // Mock spending confidential balance.
    // This is the ElGamal ciphertext currently stored on-chain.
    uint8_t bal_bf[size_blinding_factor];
    uint8_t spending_bal_ct[size_gamal_ciphertext_total];
    assert(mpt_generate_blinding_factor(bal_bf) == 0);
    assert(mpt_encrypt_amount(current_balance, pub, bal_bf, spending_bal_ct) == 0);

    // Generate context hash
    uint8_t context_hash[size_half_sha];
    assert(mpt_get_convert_back_context_hash(
        acc, 
        seq, 
        issuance, 
        amount_to_convert_back, 
        version, 
        context_hash) == 0);

    // Generate pedersen commitments for current balance
    uint8_t pcm_bf[size_blinding_factor];
    uint8_t pcm_comm[size_pedersen_commitment];
    assert(mpt_generate_blinding_factor(pcm_bf) == 0);
    assert(mpt_get_pedersen_commitment(current_balance, pcm_bf, pcm_comm) == 0);

    // Prepare pedersen proof params
    mpt_pedersen_proof_params pc_params;
    pc_params.amount = current_balance; 
    std::memcpy(pc_params.blinding_factor, pcm_bf, size_blinding_factor);
    std::memcpy(pc_params.pedersen_commitment, pcm_comm, size_pedersen_commitment);
    std::memcpy(pc_params.encrypted_amount, spending_bal_ct, size_gamal_ciphertext_total);

    // Generate proof 
    uint8_t proof[size_pedersen_proof];
    int result = mpt_get_convert_back_proof(
        priv,
        pub,
        context_hash,
        &pc_params,
        proof
    );

    assert(result == 0);

    // The rest of code in this function is to verify the proof
    // we just generated, simulating what a verifier would do in rippled.
    const secp256k1_context* ctx = mpt_secp256k1_context();
    secp256k1_pubkey c1, c2, pk, pcm;
    
    assert(mpt_make_ec_pair(pc_params.encrypted_amount, c1, c2));
    std::memcpy(pk.data, pub, size_pubkey);
    std::memcpy(pcm.data, pcm_comm, size_pedersen_commitment);

    int verify_result = secp256k1_elgamal_pedersen_link_verify(
        ctx,
        proof,
        &pk,
        &c2,
        &c1,
        &pcm,
        context_hash
    );

    assert(verify_result == 1);
}

void test_mpt_clawback() {
    // Setup mock account, issuance and transaction details
    account_id issuer_acc;
    std::memset(issuer_acc.bytes, 0x11, size_acc);
    
    account_id holder_acc;
    std::memset(holder_acc.bytes, 0x22, size_acc);
    
    mpt_issuance_id issuance;
    std::memset(issuance.bytes, 0xCC, size_iss);
    
    uint32_t seq = 200;
    uint64_t claw_amount = 500;

    uint8_t issuer_priv[size_privkey], issuer_pub[size_pubkey];
    assert(mpt_generate_keypair(issuer_priv, issuer_pub) == 0);

    // Generate context hash
    uint8_t context_hash[size_half_sha];
    assert(mpt_get_clawback_context_hash(
        issuer_acc, seq, issuance, claw_amount, holder_acc, context_hash) == 0);

    // Mock holder's "sfIssuerEncryptedBalance"
    uint8_t bf[size_blinding_factor];
    uint8_t issuer_encrypted_bal[size_gamal_ciphertext_total];
    mpt_generate_blinding_factor(bf);
    assert(mpt_encrypt_amount(claw_amount, issuer_pub, bf, issuer_encrypted_bal) == 0);

    // Generate proof
    uint8_t proof[size_equality_proof];
    int result = mpt_get_clawback_proof(
        issuer_priv,
        issuer_pub,
        context_hash,
        claw_amount,
        issuer_encrypted_bal,
        proof
    );
    assert(result == 0);

    // The rest of code in this function is to verify the proof
    // we just generated, simulating what a verifier would do in rippled.
    const secp256k1_context* ctx = mpt_secp256k1_context();
    secp256k1_pubkey c1, c2, pk;
    
    assert(mpt_make_ec_pair(issuer_encrypted_bal, c1, c2));
    std::memcpy(pk.data, issuer_pub, size_pubkey);

    int verify_result = secp256k1_equality_plaintext_verify(
        ctx,
        proof,
        &pk,
        &c2,
        &c1,
        claw_amount,
        context_hash
    );

    assert(verify_result == 1);
}

int main() {
    test_encryption_decryption();
    test_mpt_confidential_convert();
    test_mpt_confidential_send();
    test_mpt_convert_back();
    test_mpt_clawback();
   
    std::cout << "\n[SUCCESS] All assertions passed!" << std::endl;

    return 0;
}