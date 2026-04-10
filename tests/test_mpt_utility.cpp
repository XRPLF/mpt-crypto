#include <utility/mpt_utility.h>

#include "test_utils.h"
#include <secp256k1_mpt.h>

#include <cstring>
#include <iostream>
#include <vector>

// helper to create mock accounts and issuance IDs
template <typename T>
T
create_mock_id(uint8_t fill)
{
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
        0,
        1,
        1000,
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
    EXPECT(mpt_get_convert_context_hash(acc, issuance, seq, tx_hash) == 0);
    EXPECT(mpt_get_convert_proof(pub, priv, tx_hash, proof) == 0);

    // Verify the ZKProof for convert
    EXPECT(mpt_verify_convert_proof(proof, pub, tx_hash) == 0);
}

// Helper: build a fully-initialised set of send fixtures and return the proof.
// Callers may mutate the returned proof or parameters to exercise rejection paths.
struct SendFixture
{
    // Participants
    uint8_t sender_priv[kMPT_PRIVKEY_SIZE];
    uint8_t sender_pub[kMPT_PUBKEY_SIZE];
    uint8_t dest_pub[kMPT_PUBKEY_SIZE];
    uint8_t issuer_pub[kMPT_PUBKEY_SIZE];
    uint8_t auditor_pub[kMPT_PUBKEY_SIZE];

    // Transaction ciphertexts (shared r)
    uint8_t shared_bf[kMPT_BLINDING_FACTOR_SIZE];
    uint8_t sender_ct[kMPT_ELGAMAL_TOTAL_SIZE];
    uint8_t dest_ct[kMPT_ELGAMAL_TOTAL_SIZE];
    uint8_t issuer_ct[kMPT_ELGAMAL_TOTAL_SIZE];
    uint8_t auditor_ct[kMPT_ELGAMAL_TOTAL_SIZE];

    // Commitments
    uint8_t amount_comm[kMPT_PEDERSEN_COMMIT_SIZE];   // PC_m = m*G + r*H
    uint8_t balance_comm[kMPT_PEDERSEN_COMMIT_SIZE];  // PC_b = b*G + rho*H
    uint8_t balance_bf[kMPT_BLINDING_FACTOR_SIZE];
    uint8_t bal_ct[kMPT_ELGAMAL_TOTAL_SIZE];  // sender's spending-balance ciphertext (B1||B2)

    // Context
    uint8_t ctx_hash[kMPT_HALF_SHA_SIZE];

    // Proof params
    mpt_pedersen_proof_params amt_params;
    mpt_pedersen_proof_params bal_params;

    // Participants list (n=4: sender, dest, issuer, auditor)
    std::vector<mpt_confidential_participant> participants;

    // Generated proof
    std::vector<uint8_t> proof;
    size_t proof_len = 0;
};

static SendFixture
make_send_fixture(size_t n_recipients = 3)
{
    SendFixture f;

    uint64_t amount_to_send = 100;
    uint64_t prev_balance = 2000;

    account_id sender_acc = create_mock_id<account_id>(0x11);
    account_id dest_acc = create_mock_id<account_id>(0x22);
    mpt_issuance_id issuance = create_mock_id<mpt_issuance_id>(0xBB);
    uint32_t seq = 54321;
    uint32_t version = 1;

    // Keypairs — only the sender's private key is needed by the prover
    uint8_t tmp_priv[kMPT_PRIVKEY_SIZE];
    EXPECT(mpt_generate_keypair(f.sender_priv, f.sender_pub) == 0);
    EXPECT(mpt_generate_keypair(tmp_priv, f.dest_pub) == 0);
    EXPECT(mpt_generate_keypair(tmp_priv, f.issuer_pub) == 0);
    EXPECT(mpt_generate_keypair(tmp_priv, f.auditor_pub) == 0);

    // Shared ciphertext randomness r — also used as PC_m blinding factor (spec §3.3)
    EXPECT(mpt_generate_blinding_factor(f.shared_bf) == 0);
    EXPECT(mpt_encrypt_amount(amount_to_send, f.sender_pub, f.shared_bf, f.sender_ct) == 0);
    EXPECT(mpt_encrypt_amount(amount_to_send, f.dest_pub, f.shared_bf, f.dest_ct) == 0);
    EXPECT(mpt_encrypt_amount(amount_to_send, f.issuer_pub, f.shared_bf, f.issuer_ct) == 0);
    EXPECT(mpt_encrypt_amount(amount_to_send, f.auditor_pub, f.shared_bf, f.auditor_ct) == 0);

    // PC_m = m*G + r*H  (r == shared_bf, per spec §3.3)
    EXPECT(mpt_get_pedersen_commitment(amount_to_send, f.shared_bf, f.amount_comm) == 0);

    // PC_b = b*G + rho*H  (independent blinding factor)
    EXPECT(mpt_generate_blinding_factor(f.balance_bf) == 0);
    EXPECT(mpt_get_pedersen_commitment(prev_balance, f.balance_bf, f.balance_comm) == 0);

    // Sender's on-ledger spending-balance ciphertext (B1||B2)
    uint8_t bal_bf[kMPT_BLINDING_FACTOR_SIZE];
    EXPECT(mpt_generate_blinding_factor(bal_bf) == 0);
    EXPECT(mpt_encrypt_amount(prev_balance, f.sender_pub, bal_bf, f.bal_ct) == 0);

    // Context hash
    EXPECT(
        mpt_get_send_context_hash(sender_acc, issuance, seq, dest_acc, version, f.ctx_hash) == 0);

    // Amount params — only pedersen_commitment (PC_m) is read by the new compact prover
    f.amt_params.amount = amount_to_send;
    std::memcpy(f.amt_params.blinding_factor, f.shared_bf, kMPT_BLINDING_FACTOR_SIZE);
    std::memcpy(f.amt_params.pedersen_commitment, f.amount_comm, kMPT_PEDERSEN_COMMIT_SIZE);
    std::memcpy(f.amt_params.ciphertext, f.sender_ct, kMPT_ELGAMAL_TOTAL_SIZE);

    // Balance params
    f.bal_params.amount = prev_balance;
    std::memcpy(f.bal_params.blinding_factor, f.balance_bf, kMPT_BLINDING_FACTOR_SIZE);
    std::memcpy(f.bal_params.pedersen_commitment, f.balance_comm, kMPT_PEDERSEN_COMMIT_SIZE);
    std::memcpy(f.bal_params.ciphertext, f.bal_ct, kMPT_ELGAMAL_TOTAL_SIZE);

    // Build participant list
    auto add = [&](uint8_t* pub, uint8_t* ct) {
        mpt_confidential_participant p;
        std::memcpy(p.pubkey, pub, kMPT_PUBKEY_SIZE);
        std::memcpy(p.ciphertext, ct, kMPT_ELGAMAL_TOTAL_SIZE);
        f.participants.push_back(p);
    };
    add(f.sender_pub, f.sender_ct);
    add(f.dest_pub, f.dest_ct);
    add(f.issuer_pub, f.issuer_ct);
    if (n_recipients == 4)
        add(f.auditor_pub, f.auditor_ct);

    // Generate proof
    f.proof_len = get_confidential_send_proof_size(n_recipients);
    f.proof.resize(f.proof_len);
    EXPECT(
        mpt_get_confidential_send_proof(
            f.sender_priv,
            amount_to_send,
            f.participants.data(),
            n_recipients,
            f.shared_bf,
            f.ctx_hash,
            &f.amt_params,
            &f.bal_params,
            f.proof.data(),
            &f.proof_len) == 0);

    return f;
}

void
test_mpt_confidential_send_integrate()
{
    account_id sender_acc = create_mock_id<account_id>(0x11);
    account_id dest_acc = create_mock_id<account_id>(0x22);
    mpt_issuance_id issuance = create_mock_id<mpt_issuance_id>(0xBB);
    uint32_t seq = 54321;
    uint64_t amount_to_send = 100;
    uint64_t prev_balance = 2000;
    uint32_t version = 1;

    // Keypairs
    uint8_t sender_priv[kMPT_PRIVKEY_SIZE], sender_pub[kMPT_PUBKEY_SIZE];
    uint8_t dest_pub[kMPT_PUBKEY_SIZE], issuer_pub[kMPT_PUBKEY_SIZE];
    uint8_t tmp_priv[kMPT_PRIVKEY_SIZE];
    EXPECT(mpt_generate_keypair(sender_priv, sender_pub) == 0);
    EXPECT(mpt_generate_keypair(tmp_priv, dest_pub) == 0);
    EXPECT(mpt_generate_keypair(tmp_priv, issuer_pub) == 0);

    // Transaction ciphertexts — all encrypted with the same shared r
    uint8_t shared_bf[kMPT_BLINDING_FACTOR_SIZE];
    EXPECT(mpt_generate_blinding_factor(shared_bf) == 0);

    uint8_t sender_ct[kMPT_ELGAMAL_TOTAL_SIZE];
    uint8_t dest_ct[kMPT_ELGAMAL_TOTAL_SIZE];
    uint8_t issuer_ct[kMPT_ELGAMAL_TOTAL_SIZE];
    EXPECT(mpt_encrypt_amount(amount_to_send, sender_pub, shared_bf, sender_ct) == 0);
    EXPECT(mpt_encrypt_amount(amount_to_send, dest_pub, shared_bf, dest_ct) == 0);
    EXPECT(mpt_encrypt_amount(amount_to_send, issuer_pub, shared_bf, issuer_ct) == 0);

    // Participants list (sender first)
    std::vector<mpt_confidential_participant> participants;
    auto add_participant = [&](uint8_t* p, uint8_t* c) {
        mpt_confidential_participant r;
        std::memcpy(r.pubkey, p, kMPT_PUBKEY_SIZE);
        std::memcpy(r.ciphertext, c, kMPT_ELGAMAL_TOTAL_SIZE);
        participants.push_back(r);
    };
    add_participant(sender_pub, sender_ct);
    add_participant(dest_pub, dest_ct);
    add_participant(issuer_pub, issuer_ct);

    // PC_m = m*G + r*H — reuses shared_bf (= r) as blinding factor (spec §3.3)
    uint8_t amount_comm[kMPT_PEDERSEN_COMMIT_SIZE];
    EXPECT(mpt_get_pedersen_commitment(amount_to_send, shared_bf, amount_comm) == 0);

    // PC_b = b*G + rho*H — independent blinding factor for the balance commitment
    uint8_t balance_bf[kMPT_BLINDING_FACTOR_SIZE];
    uint8_t balance_comm[kMPT_PEDERSEN_COMMIT_SIZE];
    EXPECT(mpt_generate_blinding_factor(balance_bf) == 0);
    EXPECT(mpt_get_pedersen_commitment(prev_balance, balance_bf, balance_comm) == 0);

    // Sender's on-ledger spending-balance ciphertext (B1||B2)
    uint8_t prev_bal_bf[kMPT_BLINDING_FACTOR_SIZE];
    uint8_t prev_bal_ct[kMPT_ELGAMAL_TOTAL_SIZE];
    EXPECT(mpt_generate_blinding_factor(prev_bal_bf) == 0);
    EXPECT(mpt_encrypt_amount(prev_balance, sender_pub, prev_bal_bf, prev_bal_ct) == 0);

    // Context hash
    uint8_t send_ctx_hash[kMPT_HALF_SHA_SIZE];
    EXPECT(
        mpt_get_send_context_hash(sender_acc, issuance, seq, dest_acc, version, send_ctx_hash) ==
        0);

    // Pedersen proof params
    mpt_pedersen_proof_params amt_params;
    amt_params.amount = amount_to_send;
    std::memcpy(amt_params.blinding_factor, shared_bf, kMPT_BLINDING_FACTOR_SIZE);
    std::memcpy(amt_params.pedersen_commitment, amount_comm, kMPT_PEDERSEN_COMMIT_SIZE);
    std::memcpy(amt_params.ciphertext, sender_ct, kMPT_ELGAMAL_TOTAL_SIZE);

    mpt_pedersen_proof_params bal_params;
    bal_params.amount = prev_balance;
    std::memcpy(bal_params.blinding_factor, balance_bf, kMPT_BLINDING_FACTOR_SIZE);
    std::memcpy(bal_params.pedersen_commitment, balance_comm, kMPT_PEDERSEN_COMMIT_SIZE);
    std::memcpy(bal_params.ciphertext, prev_bal_ct, kMPT_ELGAMAL_TOTAL_SIZE);

    // Prove
    size_t proof_len = get_confidential_send_proof_size(participants.size());
    std::vector<uint8_t> proof(proof_len);
    EXPECT(
        mpt_get_confidential_send_proof(
            sender_priv,
            amount_to_send,
            participants.data(),
            3,
            shared_bf,
            send_ctx_hash,
            &amt_params,
            &bal_params,
            proof.data(),
            &proof_len) == 0);

    // Verify
    EXPECT(
        mpt_verify_send_proof(
            proof.data(),
            proof_len,
            participants.data(),
            static_cast<uint8_t>(participants.size()),
            bal_params.ciphertext,
            amt_params.pedersen_commitment,
            bal_params.pedersen_commitment,
            send_ctx_hash) == 0);
}

void
test_mpt_confidential_send()
{
    // Valid: n=3 (sender, dest, issuer)
    {
        SendFixture f = make_send_fixture(3);

        // Proof size must be exactly 192 (compact sigma) + 754 (bulletproof)
        EXPECT(f.proof_len == SECP256K1_COMPACT_STANDARD_PROOF_SIZE + kMPT_DOUBLE_BULLETPROOF_SIZE);

        EXPECT(
            mpt_verify_send_proof(
                f.proof.data(),
                f.proof_len,
                f.participants.data(),
                static_cast<uint8_t>(f.participants.size()),
                f.bal_ct,
                f.amount_comm,
                f.balance_comm,
                f.ctx_hash) == 0);
    }

    // Valid: n=4 (sender, dest, issuer, auditor)
    {
        SendFixture f = make_send_fixture(4);
        EXPECT(f.proof_len == SECP256K1_COMPACT_STANDARD_PROOF_SIZE + kMPT_DOUBLE_BULLETPROOF_SIZE);

        EXPECT(
            mpt_verify_send_proof(
                f.proof.data(),
                f.proof_len,
                f.participants.data(),
                static_cast<uint8_t>(f.participants.size()),
                f.bal_ct,
                f.amount_comm,
                f.balance_comm,
                f.ctx_hash) == 0);
    }

    // Invalid: corrupted proof byte
    {
        SendFixture f = make_send_fixture(3);
        f.proof[0] ^= 0xFF;
        EXPECT(
            mpt_verify_send_proof(
                f.proof.data(),
                f.proof_len,
                f.participants.data(),
                static_cast<uint8_t>(f.participants.size()),
                f.bal_ct,
                f.amount_comm,
                f.balance_comm,
                f.ctx_hash) != 0);
    }

    // Invalid: wrong context hash
    {
        SendFixture f = make_send_fixture(3);
        uint8_t bad_ctx[kMPT_HALF_SHA_SIZE] = {0};
        EXPECT(
            mpt_verify_send_proof(
                f.proof.data(),
                f.proof_len,
                f.participants.data(),
                static_cast<uint8_t>(f.participants.size()),
                f.bal_ct,
                f.amount_comm,
                f.balance_comm,
                bad_ctx) != 0);
    }

    // Invalid: wrong amount commitment (PC_m mismatch)
    {
        SendFixture f = make_send_fixture(3);
        uint8_t bad_amt_comm[kMPT_PEDERSEN_COMMIT_SIZE];
        uint8_t bad_bf[kMPT_BLINDING_FACTOR_SIZE];
        EXPECT(mpt_generate_blinding_factor(bad_bf) == 0);
        EXPECT(mpt_get_pedersen_commitment(f.amt_params.amount, bad_bf, bad_amt_comm) == 0);
        EXPECT(
            mpt_verify_send_proof(
                f.proof.data(),
                f.proof_len,
                f.participants.data(),
                static_cast<uint8_t>(f.participants.size()),
                f.bal_ct,
                bad_amt_comm,
                f.balance_comm,
                f.ctx_hash) != 0);
    }

    // Invalid: wrong balance ciphertext (B1/B2 mismatch)
    {
        SendFixture f = make_send_fixture(3);
        uint8_t bad_bal_ct[kMPT_ELGAMAL_TOTAL_SIZE];
        uint8_t bad_bf[kMPT_BLINDING_FACTOR_SIZE];
        EXPECT(mpt_generate_blinding_factor(bad_bf) == 0);
        EXPECT(mpt_encrypt_amount(f.bal_params.amount, f.sender_pub, bad_bf, bad_bal_ct) == 0);
        EXPECT(
            mpt_verify_send_proof(
                f.proof.data(),
                f.proof_len,
                f.participants.data(),
                static_cast<uint8_t>(f.participants.size()),
                bad_bal_ct,
                f.amount_comm,
                f.balance_comm,
                f.ctx_hash) != 0);
    }

    // Invalid: wrong balance commitment (PC_b mismatch)
    {
        SendFixture f = make_send_fixture(3);
        uint8_t bad_bal_comm[kMPT_PEDERSEN_COMMIT_SIZE];
        uint8_t bad_bf[kMPT_BLINDING_FACTOR_SIZE];
        EXPECT(mpt_generate_blinding_factor(bad_bf) == 0);
        EXPECT(mpt_get_pedersen_commitment(f.bal_params.amount, bad_bf, bad_bal_comm) == 0);
        EXPECT(
            mpt_verify_send_proof(
                f.proof.data(),
                f.proof_len,
                f.participants.data(),
                static_cast<uint8_t>(f.participants.size()),
                f.bal_ct,
                f.amount_comm,
                bad_bal_comm,
                f.ctx_hash) != 0);
    }

    // Invalid: wrong proof length
    {
        SendFixture f = make_send_fixture(3);
        EXPECT(
            mpt_verify_send_proof(
                f.proof.data(),
                f.proof_len - 1,
                f.participants.data(),
                static_cast<uint8_t>(f.participants.size()),
                f.bal_ct,
                f.amount_comm,
                f.balance_comm,
                f.ctx_hash) != 0);
    }
}

void
test_mpt_convert_back_integrate()
{
    account_id acc = create_mock_id<account_id>(0x55);
    mpt_issuance_id issuance = create_mock_id<mpt_issuance_id>(0xEE);
    uint32_t seq = 98765;
    uint64_t current_balance = 5000;
    uint64_t amount_to_convert_back = 1000;
    uint32_t version = 2;

    uint8_t priv[kMPT_PRIVKEY_SIZE], pub[kMPT_PUBKEY_SIZE];
    EXPECT(mpt_generate_keypair(priv, pub) == 0);

    // Sender's on-ledger spending-balance ciphertext (B1||B2)
    uint8_t bal_bf[kMPT_BLINDING_FACTOR_SIZE];
    uint8_t spending_bal_ct[kMPT_ELGAMAL_TOTAL_SIZE];
    EXPECT(mpt_generate_blinding_factor(bal_bf) == 0);
    EXPECT(mpt_encrypt_amount(current_balance, pub, bal_bf, spending_bal_ct) == 0);

    // Context hash
    uint8_t context_hash[kMPT_HALF_SHA_SIZE];
    EXPECT(mpt_get_convert_back_context_hash(acc, issuance, seq, version, context_hash) == 0);

    // PC_b = b*G + rho*H
    uint8_t pcb_bf[kMPT_BLINDING_FACTOR_SIZE];
    uint8_t pcb_comm[kMPT_PEDERSEN_COMMIT_SIZE];
    EXPECT(mpt_generate_blinding_factor(pcb_bf) == 0);
    EXPECT(mpt_get_pedersen_commitment(current_balance, pcb_bf, pcb_comm) == 0);

    // Pedersen proof params
    mpt_pedersen_proof_params pc_params;
    pc_params.amount = current_balance;
    std::memcpy(pc_params.blinding_factor, pcb_bf, kMPT_BLINDING_FACTOR_SIZE);
    std::memcpy(pc_params.pedersen_commitment, pcb_comm, kMPT_PEDERSEN_COMMIT_SIZE);
    std::memcpy(pc_params.ciphertext, spending_bal_ct, kMPT_ELGAMAL_TOTAL_SIZE);

    // Prove
    uint8_t proof[SECP256K1_COMPACT_CONVERTBACK_PROOF_SIZE + kMPT_SINGLE_BULLETPROOF_SIZE];
    EXPECT(
        mpt_get_convert_back_proof(
            priv, pub, context_hash, amount_to_convert_back, &pc_params, proof) == 0);

    // Verify
    EXPECT(
        mpt_verify_convert_back_proof(
            proof, pub, spending_bal_ct, pcb_comm, amount_to_convert_back, context_hash) == 0);
}

void
test_mpt_convert_back()
{
    // Valid: prove and verify convert back
    {
        account_id acc = create_mock_id<account_id>(0x55);
        mpt_issuance_id issuance = create_mock_id<mpt_issuance_id>(0xEE);
        uint32_t seq = 98765;
        uint64_t current_balance = 5000;
        uint64_t amount_to_convert_back = 1000;
        uint32_t version = 2;

        uint8_t priv[kMPT_PRIVKEY_SIZE], pub[kMPT_PUBKEY_SIZE];
        EXPECT(mpt_generate_keypair(priv, pub) == 0);

        uint8_t bal_bf[kMPT_BLINDING_FACTOR_SIZE];
        uint8_t spending_bal_ct[kMPT_ELGAMAL_TOTAL_SIZE];
        EXPECT(mpt_generate_blinding_factor(bal_bf) == 0);
        EXPECT(mpt_encrypt_amount(current_balance, pub, bal_bf, spending_bal_ct) == 0);

        uint8_t context_hash[kMPT_HALF_SHA_SIZE];
        EXPECT(mpt_get_convert_back_context_hash(acc, issuance, seq, version, context_hash) == 0);

        uint8_t pcb_bf[kMPT_BLINDING_FACTOR_SIZE];
        uint8_t pcb_comm[kMPT_PEDERSEN_COMMIT_SIZE];
        EXPECT(mpt_generate_blinding_factor(pcb_bf) == 0);
        EXPECT(mpt_get_pedersen_commitment(current_balance, pcb_bf, pcb_comm) == 0);

        mpt_pedersen_proof_params pc_params;
        pc_params.amount = current_balance;
        std::memcpy(pc_params.blinding_factor, pcb_bf, kMPT_BLINDING_FACTOR_SIZE);
        std::memcpy(pc_params.pedersen_commitment, pcb_comm, kMPT_PEDERSEN_COMMIT_SIZE);
        std::memcpy(pc_params.ciphertext, spending_bal_ct, kMPT_ELGAMAL_TOTAL_SIZE);

        // Proof size: 128 (compact sigma) + 688 (bulletproof) = 816 bytes
        uint8_t proof[SECP256K1_COMPACT_CONVERTBACK_PROOF_SIZE + kMPT_SINGLE_BULLETPROOF_SIZE];
        EXPECT(
            mpt_get_convert_back_proof(
                priv, pub, context_hash, amount_to_convert_back, &pc_params, proof) == 0);

        EXPECT(
            mpt_verify_convert_back_proof(
                proof, pub, spending_bal_ct, pcb_comm, amount_to_convert_back, context_hash) == 0);
    }

    // Invalid: corrupted proof byte
    {
        account_id acc = create_mock_id<account_id>(0x55);
        mpt_issuance_id issuance = create_mock_id<mpt_issuance_id>(0xEE);
        uint8_t priv[kMPT_PRIVKEY_SIZE], pub[kMPT_PUBKEY_SIZE];
        EXPECT(mpt_generate_keypair(priv, pub) == 0);
        uint8_t bal_bf[kMPT_BLINDING_FACTOR_SIZE], spending_bal_ct[kMPT_ELGAMAL_TOTAL_SIZE];
        EXPECT(mpt_generate_blinding_factor(bal_bf) == 0);
        EXPECT(mpt_encrypt_amount(5000, pub, bal_bf, spending_bal_ct) == 0);
        uint8_t ctx[kMPT_HALF_SHA_SIZE];
        EXPECT(mpt_get_convert_back_context_hash(acc, issuance, 1, 1, ctx) == 0);
        uint8_t pcb_bf[kMPT_BLINDING_FACTOR_SIZE], pcb_comm[kMPT_PEDERSEN_COMMIT_SIZE];
        EXPECT(mpt_generate_blinding_factor(pcb_bf) == 0);
        EXPECT(mpt_get_pedersen_commitment(5000, pcb_bf, pcb_comm) == 0);
        mpt_pedersen_proof_params pc_params;
        pc_params.amount = 5000;
        std::memcpy(pc_params.blinding_factor, pcb_bf, kMPT_BLINDING_FACTOR_SIZE);
        std::memcpy(pc_params.pedersen_commitment, pcb_comm, kMPT_PEDERSEN_COMMIT_SIZE);
        std::memcpy(pc_params.ciphertext, spending_bal_ct, kMPT_ELGAMAL_TOTAL_SIZE);
        uint8_t proof[SECP256K1_COMPACT_CONVERTBACK_PROOF_SIZE + kMPT_SINGLE_BULLETPROOF_SIZE];
        EXPECT(mpt_get_convert_back_proof(priv, pub, ctx, 1000, &pc_params, proof) == 0);
        proof[0] ^= 0xFF;
        EXPECT(
            mpt_verify_convert_back_proof(proof, pub, spending_bal_ct, pcb_comm, 1000, ctx) != 0);
    }

    // Invalid: wrong context hash
    {
        account_id acc = create_mock_id<account_id>(0x55);
        mpt_issuance_id issuance = create_mock_id<mpt_issuance_id>(0xEE);
        uint8_t priv[kMPT_PRIVKEY_SIZE], pub[kMPT_PUBKEY_SIZE];
        EXPECT(mpt_generate_keypair(priv, pub) == 0);
        uint8_t bal_bf[kMPT_BLINDING_FACTOR_SIZE], spending_bal_ct[kMPT_ELGAMAL_TOTAL_SIZE];
        EXPECT(mpt_generate_blinding_factor(bal_bf) == 0);
        EXPECT(mpt_encrypt_amount(5000, pub, bal_bf, spending_bal_ct) == 0);
        uint8_t ctx[kMPT_HALF_SHA_SIZE];
        EXPECT(mpt_get_convert_back_context_hash(acc, issuance, 1, 1, ctx) == 0);
        uint8_t pcb_bf[kMPT_BLINDING_FACTOR_SIZE], pcb_comm[kMPT_PEDERSEN_COMMIT_SIZE];
        EXPECT(mpt_generate_blinding_factor(pcb_bf) == 0);
        EXPECT(mpt_get_pedersen_commitment(5000, pcb_bf, pcb_comm) == 0);
        mpt_pedersen_proof_params pc_params;
        pc_params.amount = 5000;
        std::memcpy(pc_params.blinding_factor, pcb_bf, kMPT_BLINDING_FACTOR_SIZE);
        std::memcpy(pc_params.pedersen_commitment, pcb_comm, kMPT_PEDERSEN_COMMIT_SIZE);
        std::memcpy(pc_params.ciphertext, spending_bal_ct, kMPT_ELGAMAL_TOTAL_SIZE);
        uint8_t proof[SECP256K1_COMPACT_CONVERTBACK_PROOF_SIZE + kMPT_SINGLE_BULLETPROOF_SIZE];
        EXPECT(mpt_get_convert_back_proof(priv, pub, ctx, 1000, &pc_params, proof) == 0);
        uint8_t bad_ctx[kMPT_HALF_SHA_SIZE] = {0};
        EXPECT(
            mpt_verify_convert_back_proof(proof, pub, spending_bal_ct, pcb_comm, 1000, bad_ctx) !=
            0);
    }

    // Invalid: wrong balance commitment (PC_b mismatch)
    {
        account_id acc = create_mock_id<account_id>(0x55);
        mpt_issuance_id issuance = create_mock_id<mpt_issuance_id>(0xEE);
        uint8_t priv[kMPT_PRIVKEY_SIZE], pub[kMPT_PUBKEY_SIZE];
        EXPECT(mpt_generate_keypair(priv, pub) == 0);
        uint8_t bal_bf[kMPT_BLINDING_FACTOR_SIZE], spending_bal_ct[kMPT_ELGAMAL_TOTAL_SIZE];
        EXPECT(mpt_generate_blinding_factor(bal_bf) == 0);
        EXPECT(mpt_encrypt_amount(5000, pub, bal_bf, spending_bal_ct) == 0);
        uint8_t ctx[kMPT_HALF_SHA_SIZE];
        EXPECT(mpt_get_convert_back_context_hash(acc, issuance, 1, 1, ctx) == 0);
        uint8_t pcb_bf[kMPT_BLINDING_FACTOR_SIZE], pcb_comm[kMPT_PEDERSEN_COMMIT_SIZE];
        EXPECT(mpt_generate_blinding_factor(pcb_bf) == 0);
        EXPECT(mpt_get_pedersen_commitment(5000, pcb_bf, pcb_comm) == 0);
        mpt_pedersen_proof_params pc_params;
        pc_params.amount = 5000;
        std::memcpy(pc_params.blinding_factor, pcb_bf, kMPT_BLINDING_FACTOR_SIZE);
        std::memcpy(pc_params.pedersen_commitment, pcb_comm, kMPT_PEDERSEN_COMMIT_SIZE);
        std::memcpy(pc_params.ciphertext, spending_bal_ct, kMPT_ELGAMAL_TOTAL_SIZE);
        uint8_t proof[SECP256K1_COMPACT_CONVERTBACK_PROOF_SIZE + kMPT_SINGLE_BULLETPROOF_SIZE];
        EXPECT(mpt_get_convert_back_proof(priv, pub, ctx, 1000, &pc_params, proof) == 0);
        uint8_t bad_bf[kMPT_BLINDING_FACTOR_SIZE], bad_comm[kMPT_PEDERSEN_COMMIT_SIZE];
        EXPECT(mpt_generate_blinding_factor(bad_bf) == 0);
        EXPECT(mpt_get_pedersen_commitment(5000, bad_bf, bad_comm) == 0);
        EXPECT(
            mpt_verify_convert_back_proof(proof, pub, spending_bal_ct, bad_comm, 1000, ctx) != 0);
    }

    // Invalid: wrong balance ciphertext (B1/B2 mismatch)
    {
        account_id acc = create_mock_id<account_id>(0x55);
        mpt_issuance_id issuance = create_mock_id<mpt_issuance_id>(0xEE);
        uint8_t priv[kMPT_PRIVKEY_SIZE], pub[kMPT_PUBKEY_SIZE];
        EXPECT(mpt_generate_keypair(priv, pub) == 0);
        uint8_t bal_bf[kMPT_BLINDING_FACTOR_SIZE], spending_bal_ct[kMPT_ELGAMAL_TOTAL_SIZE];
        EXPECT(mpt_generate_blinding_factor(bal_bf) == 0);
        EXPECT(mpt_encrypt_amount(5000, pub, bal_bf, spending_bal_ct) == 0);
        uint8_t ctx[kMPT_HALF_SHA_SIZE];
        EXPECT(mpt_get_convert_back_context_hash(acc, issuance, 1, 1, ctx) == 0);
        uint8_t pcb_bf[kMPT_BLINDING_FACTOR_SIZE], pcb_comm[kMPT_PEDERSEN_COMMIT_SIZE];
        EXPECT(mpt_generate_blinding_factor(pcb_bf) == 0);
        EXPECT(mpt_get_pedersen_commitment(5000, pcb_bf, pcb_comm) == 0);
        mpt_pedersen_proof_params pc_params;
        pc_params.amount = 5000;
        std::memcpy(pc_params.blinding_factor, pcb_bf, kMPT_BLINDING_FACTOR_SIZE);
        std::memcpy(pc_params.pedersen_commitment, pcb_comm, kMPT_PEDERSEN_COMMIT_SIZE);
        std::memcpy(pc_params.ciphertext, spending_bal_ct, kMPT_ELGAMAL_TOTAL_SIZE);
        uint8_t proof[SECP256K1_COMPACT_CONVERTBACK_PROOF_SIZE + kMPT_SINGLE_BULLETPROOF_SIZE];
        EXPECT(mpt_get_convert_back_proof(priv, pub, ctx, 1000, &pc_params, proof) == 0);
        uint8_t bad_bf[kMPT_BLINDING_FACTOR_SIZE], bad_ct[kMPT_ELGAMAL_TOTAL_SIZE];
        EXPECT(mpt_generate_blinding_factor(bad_bf) == 0);
        EXPECT(mpt_encrypt_amount(5000, pub, bad_bf, bad_ct) == 0);
        EXPECT(mpt_verify_convert_back_proof(proof, pub, bad_ct, pcb_comm, 1000, ctx) != 0);
    }
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
    EXPECT(mpt_get_clawback_context_hash(issuer_acc, issuance, seq, holder_acc, context_hash) == 0);

    // Mock holder's "sfIssuerEncryptedBalance"
    uint8_t bf[kMPT_BLINDING_FACTOR_SIZE];
    uint8_t issuer_encrypted_bal[kMPT_ELGAMAL_TOTAL_SIZE];
    EXPECT(mpt_generate_blinding_factor(bf) == 0);
    EXPECT(mpt_encrypt_amount(claw_amount, issuer_pub, bf, issuer_encrypted_bal) == 0);

    // Generate clawback proof
    uint8_t proof[kMPT_EQUALITY_PROOF_SIZE];
    EXPECT(
        mpt_get_clawback_proof(
            issuer_priv, issuer_pub, context_hash, claw_amount, issuer_encrypted_bal, proof) == 0);

    // Verify the clawback proof
    EXPECT(
        mpt_verify_clawback_proof(
            proof, claw_amount, issuer_pub, issuer_encrypted_bal, context_hash) == 0);
}

int
main()
{
    test_encryption_decryption();
    test_mpt_confidential_convert();
    test_mpt_confidential_send_integrate();
    test_mpt_confidential_send();
    test_mpt_convert_back_integrate();
    test_mpt_convert_back();
    test_mpt_clawback();

    std::cout << "\n[SUCCESS] All assertions passed!" << std::endl;

    return 0;
}
