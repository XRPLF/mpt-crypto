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

    # Static variant: links the static `mpt-crypto` target.
    add_executable(${TEST_NAME} ${TEST_SOURCE})
    target_link_libraries(${TEST_NAME} PRIVATE ${ARG_DEPENDENCIES})
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})

    # Shared variant: when the shared library is also built (MPT_CRYPTO_BUILD_SHARED),
    # run the SAME test against it, so both link forms are exercised by ctest.
    # Swap the static `mpt-crypto` dep for `mpt-crypto-shared`; keep the rest.
    if(MPT_CRYPTO_BUILD_SHARED AND TARGET mpt-crypto-shared)
        set(_shared_deps "")
        foreach(_dep IN LISTS ARG_DEPENDENCIES)
            if(_dep STREQUAL "mpt-crypto")
                list(APPEND _shared_deps mpt-crypto-shared)
            else()
                list(APPEND _shared_deps ${_dep})
            endif()
        endforeach()
        add_executable(${TEST_NAME}_shared ${TEST_SOURCE})
        target_link_libraries(${TEST_NAME}_shared PRIVATE ${_shared_deps})
        add_test(NAME ${TEST_NAME}_shared COMMAND ${TEST_NAME}_shared)

        # Windows has no rpath, so the shared-variant .exe can't find the DLL
        # (which lives in the shared/ output dir) at runtime — it would abort
        # with STATUS_DLL_NOT_FOUND (0xC0000135). Copy mpt-crypto.dll next to the
        # test executable. On ELF/Mach-O the build rpath already handles this.
        if(WIN32)
            add_custom_command(
                TARGET ${TEST_NAME}_shared
                POST_BUILD
                COMMAND
                    ${CMAKE_COMMAND} -E copy_if_different
                    $<TARGET_FILE:mpt-crypto-shared>
                    $<TARGET_FILE_DIR:${TEST_NAME}_shared>
                VERBATIM
            )
        endif()
    endif()
endfunction()

# --------------------------------------------------------------------
# Test definitions
# --------------------------------------------------------------------

add_mpt_test(test_elgamal test_elgamal.c DEPENDENCIES mpt-crypto)

add_mpt_test(
    test_rotate_reencrypt
    test_rotate_reencrypt.c
    DEPENDENCIES mpt-crypto secp256k1::secp256k1
)

add_mpt_test(
    test_rotate_recovery_key
    test_rotate_recovery_key.c
    DEPENDENCIES mpt-crypto secp256k1::secp256k1
)

add_mpt_test(
    test_rotate_holder_rotate
    test_rotate_holder_rotate.c
    DEPENDENCIES mpt-crypto secp256k1::secp256k1
)

add_mpt_test(
    test_rotate_mirror_both
    test_rotate_mirror_both.c
    DEPENDENCIES mpt-crypto secp256k1::secp256k1
)

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

add_mpt_test(
    test_ct_tweak_mul
    test_ct_tweak_mul.c
    DEPENDENCIES mpt-crypto secp256k1::secp256k1 OpenSSL::Crypto
)
add_mpt_test(
    test_bsgs_dlp
    test_bsgs_dlp.c
    DEPENDENCIES mpt-crypto secp256k1::secp256k1
)
