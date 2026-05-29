cmake_minimum_required(VERSION 3.16)
project(mpt-crypto C CXX)

# --- Find Dependencies ---
find_package(OpenSSL REQUIRED)
find_package(secp256k1 REQUIRED)

# --- Add common options ---
add_library(common INTERFACE)
if(NOT MSVC)
    target_compile_options(common INTERFACE -Wall -Wextra -Wpedantic -Werror)
endif()
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# --- Vendored MSM (libsecp256k1 ecmult_multi_var) ---
# See third_party/secp256k1-msm/README.md for design rationale.
# Self-contained vendor; not a dependency on the linked libsecp256k1
# binary's internal types. Variable-time; verifier path only.
add_library(
    mpt-crypto-msm-vendor
    OBJECT
    third_party/secp256k1-msm/mpt_msm.c
    third_party/secp256k1-msm/precomputed_ecmult.c
)
target_include_directories(
    mpt-crypto-msm-vendor
    PRIVATE third_party/secp256k1-msm include
)
target_link_libraries(mpt-crypto-msm-vendor PRIVATE secp256k1::secp256k1)
# Rename the precomputed generator-table symbols so the vendored
# copy never collides with the corresponding symbols inside the
# linked libsecp256k1 binary. The vendored MSM uses these tables
# internally; renaming via compile-time -D applies the rewrite
# uniformly across the declaration (precomputed_ecmult.h), the
# definition (precomputed_ecmult.c), and all use sites
# (ecmult_impl.h, scratch_impl.h). The linked libsecp256k1
# continues to use its own un-renamed copies; the two never meet.
target_compile_definitions(
    mpt-crypto-msm-vendor
    PRIVATE
        secp256k1_pre_g=mpt_secp256k1_pre_g
        secp256k1_pre_g_128=mpt_secp256k1_pre_g_128
)
# Suppress -Wpedantic for the vendored TU: upstream libsecp256k1
# uses extensions (variadic macros, designated initialisers, etc.)
# that pedantic flags occasionally complain about.
if(NOT MSVC)
    target_compile_options(mpt-crypto-msm-vendor PRIVATE -Wno-pedantic)
endif()

# --- Define The Library ---
add_library(
    mpt-crypto
    src/bulletproof_aggregated.c
    src/commitments.c
    src/elgamal.c
    src/mpt_scalar.c
    src/proof_pok_sk.c
    src/proof_compact_standard.c
    src/proof_compact_clawback.c
    src/proof_compact_convertback.c
    src/utility/mpt_utility.cpp
    $<TARGET_OBJECTS:mpt-crypto-msm-vendor>
)

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
    target_compile_definitions(mpt-crypto PRIVATE SECP256K1_WIDEMUL_INT128)
else()
    message(STATUS "Build: No 128-bit support detected.")
    target_compile_definitions(mpt-crypto PRIVATE SECP256K1_WIDEMUL_INT64)
endif()

# --- Link Dependencies ---
target_link_libraries(mpt-crypto PUBLIC secp256k1::secp256k1 OpenSSL::Crypto)

# --- Testing ---
option(ENABLE_TESTS "Enable building tests" ON)
if(ENABLE_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
