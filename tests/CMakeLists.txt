# Enable CTest
enable_testing()

# --------------------------------------------------------------------
# Helper function for defining MPT tests
#   - add_executable
#   - target_link_libraries
#   - add_test
#
# Usage:
#   add_mpt_test(test_name source.c DEPENDENCIES lib1 lib2 ...)
# --------------------------------------------------------------------
function(add_mpt_test TEST_NAME TEST_SOURCE)
    set(options "")
    set(oneValueArgs "")
    set(multiValueArgs DEPENDENCIES)

    cmake_parse_arguments(
        ARG
        "${options}"
        "${oneValueArgs}"
        "${multiValueArgs}"
        ${ARGN}
    )

    add_executable(${TEST_NAME} ${TEST_SOURCE})
    target_link_libraries(${TEST_NAME} PRIVATE ${ARG_DEPENDENCIES})
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
endfunction()

# --------------------------------------------------------------------
# Test definitions
# --------------------------------------------------------------------

add_mpt_test(test_elgamal test_elgamal.c DEPENDENCIES mpt-crypto)

add_mpt_test(test_equality_proof test_equality_proof.c DEPENDENCIES mpt-crypto)

add_mpt_test(
    test_link_proof
    test_link_proof.c
    DEPENDENCIES mpt-crypto secp256k1 OpenSSL::Crypto
)

add_mpt_test(
    test_elgamal_verify
    test_elgamal_verify.c
    DEPENDENCIES mpt-crypto secp256k1
)

add_mpt_test(test_pok_sk test_pok_sk.c DEPENDENCIES mpt-crypto secp256k1)

add_mpt_test(
    test_commitments
    test_commitments.c
    DEPENDENCIES mpt-crypto secp256k1
)

add_mpt_test(test_ipa test_ipa.c DEPENDENCIES mpt-crypto secp256k1)

add_mpt_test(
    test_same_plaintext_multi_shared_r
    test_same_plaintext_multi_shared_r.c
    DEPENDENCIES mpt-crypto secp256k1
)

add_mpt_test(
    test_bulletproof_agg
    test_bulletproof_agg.c
    DEPENDENCIES mpt-crypto secp256k1
)

add_mpt_test(
    test_mpt_utility
    test_mpt_utility.cpp
    DEPENDENCIES mpt-crypto secp256k1 OpenSSL::Crypto
)

add_mpt_test(
    test_compact_standard
    test_compact_standard.c
    DEPENDENCIES mpt-crypto secp256k1
)
