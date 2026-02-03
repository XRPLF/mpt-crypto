cmake_minimum_required(VERSION 3.16)
project(mpt-crypto C CXX)

# --- Find Dependencies ---
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
target_compile_definitions(mpt-crypto PRIVATE USE_SCALAR_8X32 USE_FIELD_10X26 ECMULT_WINDOW_SIZE=15
                                              ECMULT_GEN_PREC_BITS=4)

# --- Link Dependencies ---
target_link_libraries(mpt-crypto PUBLIC secp256k1::secp256k1 PUBLIC OpenSSL::Crypto)

# --- Testing ---
option(ENABLE_TESTS "Enable building tests" ON)
if (ENABLE_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif ()
