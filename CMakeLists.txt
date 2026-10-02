cmake_minimum_required(VERSION 3.16)
project(mpt-crypto C CXX)

# --- Find Dependencies ---
find_package(OpenSSL REQUIRED)
find_package(secp256k1 REQUIRED)

# --- Add common options ---
# -Werror is on by default for our own builds/CI, but consumers (e.g. rippled
# via Conan) can disable it: third-party toolchains may inject flags that emit
# warnings outside our control (e.g. -Wunused-command-line-argument).
option(MPT_CRYPTO_WERROR "Treat compiler warnings as errors" ON)
add_library(common INTERFACE)
if(NOT MSVC)
    target_compile_options(common INTERFACE -Wall -Wextra -Wpedantic)
    if(MPT_CRYPTO_WERROR)
        target_compile_options(common INTERFACE -Werror)
    endif()
endif()
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# --- Define The Library ---
# Sources are shared between the static library and the optional shared library
# (see MPT_CRYPTO_BUILD_SHARED below), so both are produced from one configure.
set(MPT_CRYPTO_SOURCES
    src/bulletproof_aggregated.c
    src/commitments.c
    src/elgamal.c
    src/bsgs_dlp.c
    src/mpt_scalar.c
    src/proof_pok_sk.c
    src/proof_compact_standard.c
    src/proof_compact_clawback.c
    src/proof_compact_convertback.c
    src/proof_rotate_both_core.c
    src/proof_rotate_core.c
    src/proof_rotate_holder_rotate.c
    src/proof_rotate_mirror_auditor.c
    src/proof_rotate_mirror_both_holder.c
    src/proof_rotate_mirror_both_issuer.c
    src/proof_rotate_mirror_holder.c
    src/proof_rotate_mirror_holder_auditor.c
    src/proof_rotate_mirror_issuer.c
    src/proof_rotate_recover_balance.c
    src/proof_rotate_recovery_key.c
    src/utility/mpt_utility.cpp
)
add_library(mpt-crypto ${MPT_CRYPTO_SOURCES})

# --- Set Include Directories ---
target_include_directories(mpt-crypto PUBLIC include)

# --- Link Common Options ---
target_link_libraries(mpt-crypto PUBLIC common)

# --- Set Compile Definitions ---
include(CheckTypeSize)
# Check if the compiler supports __int128 (required for the optimized 64-bit code)
check_type_size("__int128" HAVE___INT128)

if(HAVE___INT128)
    message(STATUS "Build: Detected 128-bit integer support.")
    set(MPT_CRYPTO_WIDEMUL SECP256K1_WIDEMUL_INT128)
else()
    message(STATUS "Build: No 128-bit support detected.")
    set(MPT_CRYPTO_WIDEMUL SECP256K1_WIDEMUL_INT64)
endif()
target_compile_definitions(mpt-crypto PRIVATE ${MPT_CRYPTO_WIDEMUL})

# --- Link Dependencies ---
target_link_libraries(mpt-crypto PUBLIC secp256k1::secp256k1 OpenSSL::Crypto)

# --- Self-contained static archive ---
# When building the static library, optionally bundle secp256k1 + OpenSSL's
# libcrypto INTO a single self-contained archive so downstream consumers (e.g.
# the mpt-crypto-sys Rust crate) can statically link one file. See
# cmake/BundleStatic.cmake for the mechanics and the OpenSSL symbol-hiding
# rationale. No-op for shared builds (the .so already folds the deps in).
option(
    MPT_CRYPTO_BUNDLE_STATIC
    "Bundle static deps into one self-contained archive"
    OFF
)
if(MPT_CRYPTO_BUNDLE_STATIC AND NOT BUILD_SHARED_LIBS)
    # Resolve the concrete secp256k1 / libcrypto archive files. The Conan
    # CMakeDeps targets (secp256k1::secp256k1, OpenSSL::Crypto) are INTERFACE
    # aggregators, so $<TARGET_FILE:> can't be used; instead look up the real
    # `.a`/`.lib` inside the Conan-provided package lib dirs (NO_DEFAULT_PATH so
    # we never pick up a system OpenSSL by mistake).
    if(
        NOT DEFINED secp256k1_LIB_DIRS_RELEASE
        OR NOT DEFINED openssl_LIB_DIRS_RELEASE
    )
        message(
            FATAL_ERROR
            "MPT_CRYPTO_BUNDLE_STATIC: Conan lib-dir variables not found — this "
            "path expects the CMakeDeps toolchain (see build-native-libs.sh)."
        )
    endif()
    find_library(
        MPT_CRYPTO_SECP256K1_ARCHIVE
        NAMES secp256k1 libsecp256k1
        PATHS ${secp256k1_LIB_DIRS_RELEASE}
        NO_DEFAULT_PATH
        REQUIRED
    )
    find_library(
        MPT_CRYPTO_CRYPTO_ARCHIVE
        NAMES crypto libcrypto
        PATHS ${openssl_LIB_DIRS_RELEASE}
        NO_DEFAULT_PATH
        REQUIRED
    )

    if(WIN32)
        set(_bundled_name "mpt-crypto-bundled.lib")
    else()
        set(_bundled_name "libmpt-crypto-bundled.a")
    endif()
    set(MPT_CRYPTO_BUNDLED_ARCHIVE
        "${CMAKE_BINARY_DIR}/${_bundled_name}"
        CACHE FILEPATH
        "Path to the bundled self-contained static archive"
    )
    add_custom_command(
        TARGET mpt-crypto
        POST_BUILD
        COMMAND
            "${CMAKE_COMMAND}" "-DMPT_LIB=$<TARGET_FILE:mpt-crypto>"
            "-DSECP_LIB=${MPT_CRYPTO_SECP256K1_ARCHIVE}"
            "-DCRYPTO_LIB=${MPT_CRYPTO_CRYPTO_ARCHIVE}"
            "-DOUT_LIB=${MPT_CRYPTO_BUNDLED_ARCHIVE}"
            "-DTARGET_OS=${CMAKE_SYSTEM_NAME}" -P
            "${CMAKE_CURRENT_SOURCE_DIR}/cmake/BundleStatic.cmake"
        BYPRODUCTS "${MPT_CRYPTO_BUNDLED_ARCHIVE}"
        VERBATIM
        COMMENT "Bundling self-contained static archive → ${_bundled_name}"
    )
endif()

# --- Optional shared library ---
# Build libmpt-crypto.{so,dylib,dll} from the SAME sources + the SAME Conan
# static deps, in this one configure — so runtime-loading consumers (e.g. xrpl4j
# via JNA) are served WITHOUT a second dependency build. secp256k1 + OpenSSL are
# folded in exactly as for the static bundle above. Outputs go to a `shared/`
# subdir so the Windows import library (mpt-crypto.lib) does not collide with the
# static library's own mpt-crypto.lib.
option(
    MPT_CRYPTO_BUILD_SHARED
    "Also build a shared library from the same sources"
    OFF
)
if(MPT_CRYPTO_BUILD_SHARED)
    add_library(mpt-crypto-shared SHARED ${MPT_CRYPTO_SOURCES})
    target_include_directories(mpt-crypto-shared PUBLIC include)
    target_link_libraries(
        mpt-crypto-shared
        PUBLIC common secp256k1::secp256k1 OpenSSL::Crypto
    )
    target_compile_definitions(mpt-crypto-shared PRIVATE ${MPT_CRYPTO_WIDEMUL})
    set_target_properties(
        mpt-crypto-shared
        PROPERTIES
            OUTPUT_NAME mpt-crypto
            # Export the C API from the DLL (matches the previous shared build);
            # harmless on ELF/Mach-O.
            WINDOWS_EXPORT_ALL_SYMBOLS ON
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/shared"
            LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/shared"
            ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/shared"
    )
endif()

# --- Testing ---
option(ENABLE_TESTS "Enable building tests" ON)
if(ENABLE_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
