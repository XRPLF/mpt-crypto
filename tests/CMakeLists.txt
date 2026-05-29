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

add_mpt_test(
    test_elgamal_verify
    test_elgamal_verify.c
    DEPENDENCIES mpt-crypto secp256k1::secp256k1
)

add_mpt_test(
    test_pok_sk
    test_pok_sk.c
    DEPENDENCIES mpt-crypto secp256k1::secp256k1
)

add_mpt_test(
    test_commitments
    test_commitments.c
    DEPENDENCIES mpt-crypto secp256k1::secp256k1
)

add_mpt_test(test_ipa test_ipa.c DEPENDENCIES mpt-crypto secp256k1::secp256k1)

add_mpt_test(
    test_bulletproof_agg
    test_bulletproof_agg.c
    DEPENDENCIES mpt-crypto secp256k1::secp256k1
)

add_mpt_test(
    test_mpt_utility
    test_mpt_utility.cpp
    DEPENDENCIES mpt-crypto secp256k1::secp256k1 OpenSSL::Crypto
)

add_mpt_test(
    test_compact_standard
    test_compact_standard.c
    DEPENDENCIES mpt-crypto secp256k1::secp256k1
)

add_mpt_test(
    test_compact_clawback
    test_compact_clawback.c
    DEPENDENCIES mpt-crypto secp256k1::secp256k1
)

add_mpt_test(
    test_compact_convertback
    test_compact_convertback.c
    DEPENDENCIES mpt-crypto secp256k1::secp256k1
)

# Calibration test for the vendored Pippenger/Straus MSM:
# verifies bit-identical output against a public-API reference.
add_mpt_test(
    test_mpt_msm
    test_mpt_msm.c
    DEPENDENCIES mpt-crypto secp256k1::secp256k1
)

# Batched aggregated-BP verifier (issue #88): RLC stacking across proofs.
add_mpt_test(
    test_bulletproof_batch
    test_bulletproof_batch.c
    DEPENDENCIES mpt-crypto secp256k1::secp256k1
)

# Microbench for the four compact-sigma verifiers (issue #88, sigma side).
# Not registered as a ctest; build with --target bench_compact_sigma.
add_executable(bench_compact_sigma bench_compact_sigma.c)
target_link_libraries(
    bench_compact_sigma
    PRIVATE mpt-crypto secp256k1::secp256k1
)
