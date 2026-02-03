add_executable(test_elgamal test_elgamal.c)

# Link the test against our library and its dependencies
target_link_libraries(test_elgamal PRIVATE mpt-crypto)

# Add the test to CTest
add_test(NAME ElGamalTests COMMAND test_elgamal)

# Add the Equality Proof tests
add_executable(test_equality_proof test_equality_proof.c)
target_link_libraries(test_equality_proof PRIVATE mpt-crypto)
add_test(NAME EqualityProofTests COMMAND test_equality_proof)

# Add the Same Plaintext Proof tests
add_executable(test_same_plaintext test_same_plaintext.c)
target_link_libraries(test_same_plaintext PRIVATE mpt-crypto)
add_test(NAME SamePlaintextProofTests COMMAND test_same_plaintext)


# Add the new Multi-Same-Plaintext Proof tests
add_executable(test_same_plaintext_multi test_same_plaintext_multi.c)
target_link_libraries(test_same_plaintext_multi PRIVATE mpt-crypto)
add_test(NAME SamePlaintextMultiTests COMMAND test_same_plaintext_multi)

# Add the test executable
add_executable(test_link_proof tests test_link_proof.c)
target_link_libraries(test_link_proof mpt-crypto secp256k1 OpenSSL::Crypto)
add_test(NAME LinkProofTests COMMAND test_link_proof)

#ElGamal Reveal Verification (The one we just wrote)
add_executable(test_elgamal_verify tests test_elgamal_verify.c)
target_link_libraries(test_elgamal_verify mpt-crypto secp256k1 mpt-crypto)
add_test(NAME ElGamalRevealVerify COMMAND test_elgamal_verify)

#Proof of knowledge of secret key
add_executable(test_pok_sk tests test_pok_sk.c)
target_link_libraries(test_pok_sk mpt-crypto secp256k1 mpt-crypto)
add_test(NAME POK_SK COMMAND test_pok_sk)

# The Pedersen Commitment tests
add_executable(test_commitments test_commitments.c)
target_link_libraries(test_commitments PRIVATE mpt-crypto secp256k1 mpt-crypto)
add_test(NAME PedersenCommitmentTests COMMAND test_commitments)

#Add the IPA standalone test
add_executable(test_ipa tests test_ipa.c)
target_link_libraries(test_ipa PRIVATE mpt-crypto secp256k1 mpt-crypto)
add_test(NAME test_ipa COMMAND test_ipa)

# Add the new test executable
add_executable(test_same_plaintext_multi_shared_r tests test_same_plaintext_multi_shared_r.c)
target_link_libraries(test_same_plaintext_multi_shared_r mpt-crypto secp256k1)
add_test(NAME SamePlaintextMultiSharedR COMMAND test_same_plaintext_multi_shared_r)


# Bulletproof Aggregation

add_executable(test_bulletproof_agg test_bulletproof_agg.c)
target_link_libraries(test_bulletproof_agg PRIVATE mpt-crypto secp256k1)
add_test(NAME BulletproofAggregationTests COMMAND test_bulletproof_agg)
