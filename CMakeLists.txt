cmake_minimum_required(VERSION 3.16)
project(mpt-crypto C CXX)

# --- 1. Global Architecture Detection ---
include(CheckTypeSize)
check_type_size("unsigned __int128" HAVE_INT128_T)

if (HAVE_INT128_T OR CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "arm64"
    OR CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
    message(STATUS "Build: Detected 64-bit system. Enforcing 64-bit arithmetic globally.")
    add_compile_definitions(USE_SCALAR_4X64 USE_FIELD_5X52 HAVE___INT128)
else ()
    message(STATUS "Build: Detected 32-bit system. Enforcing generic arithmetic globally.")
    add_compile_definitions(USE_SCALAR_8X32 USE_FIELD_10X26)
endif ()

# --- Find Dependencies (Maintainer's Way) ---
find_package(OpenSSL REQUIRED)
find_package(secp256k1 REQUIRED)

# --- Define The Library ---
add_library(mpt-crypto
            src/bulletproof_aggregated.c
            src/commitments.c
            src/elgamal.c
            src/equality_proof.c
            src/mpt_scalar.c
            src/proof_link.c
            src/proof_pok_sk.c
            src/proof_same_plaintext.c
            src/proof_same_plaintext_multi.c
            src/proof_same_plaintext_multi_shared_r.c)

# --- Set Include Directories ---
target_include_directories(mpt-crypto PUBLIC include)

# --- Set Compile Definitions ---
target_compile_definitions(mpt-crypto PRIVATE ECMULT_WINDOW_SIZE=15 ECMULT_GEN_PREC_BITS=4)

# --- Link Dependencies ---
target_link_libraries(mpt-crypto PUBLIC secp256k1::secp256k1 PUBLIC OpenSSL::Crypto)

# --- Testing ---
option(ENABLE_TESTS "Enable building tests" ON)
if (ENABLE_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif ()
