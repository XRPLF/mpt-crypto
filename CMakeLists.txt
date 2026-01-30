cmake_minimum_required(VERSION 3.10)
project(mpt-crypto C CXX)

# --- Find Dependencies ---
find_package(OpenSSL REQUIRED)

# --- Add libsecp256k1 as a Peer Dependency ---
# Using "../secp256k1" makes it work regardless of which machine it's on
set(SECP256K1_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../secp256k1" CACHE PATH "Path to secp256k1 source directory")

if(NOT EXISTS ${SECP256K1_SOURCE_DIR}/CMakeLists.txt)
    message(FATAL_ERROR "Could not find libsecp256k1 source directory at ${SECP256K1_SOURCE_DIR}.
    Ensure it is located at the same level as the mpt-crypto directory.")
endif()

# Configure libsecp256k1 build options
set(SECP256K1_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_BENCHMARKS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF CACHE BOOL "" FORCE)

# Add libsecp256k1 as a sub-project (it's now a peer, but CMake treats it as a sub-project here)
# We provide a binary dir name since it's outside our current source tree
add_subdirectory(${SECP256K1_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}/secp256k1_build)

# --- Define The Library ---
add_library(mpt-crypto
        src/elgamal.c
        src/equality_proof.c
        src/proof_same_plaintext.c
        src/proof_same_plaintext_multi.c
        src/bulletproof.c
        src/proof_link.c
        src/proof_pok_sk.c
        src/commitments.c
        src/mpt_scalar.c
        src/proof_same_plaintext_multi_shared_r.c
        )

# --- Set Include Directories ---
target_include_directories(mpt-crypto
        PUBLIC include
        PRIVATE ${SECP256K1_SOURCE_DIR}/include
        PRIVATE ${SECP256K1_SOURCE_DIR}/src
        )

# --- Set Compile Definitions ---
target_compile_definitions(mpt-crypto PRIVATE
        USE_SCALAR_8X32
        USE_FIELD_10X26
        ECMULT_WINDOW_SIZE=15
        ECMULT_GEN_PREC_BITS=4
        )

# --- Link Dependencies ---
target_link_libraries(mpt-crypto
        PUBLIC secp256k1
        PUBLIC OpenSSL::Crypto
        )

# --- Testing ---
enable_testing()
add_subdirectory(tests)

# --- Utility Tool ---
add_executable(confidential_utility tools/confidential_utility.cpp)
target_include_directories(confidential_utility PUBLIC include)
target_link_libraries(confidential_utility PUBLIC mpt-crypto)