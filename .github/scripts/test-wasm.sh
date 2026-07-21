#!/usr/bin/env bash
# test-wasm.sh — Validate the mpt-crypto WASM build.
#
# Compiles the C/C++ crypto test suite to wasm32 (emcmake + CMake) and runs each
# test under Node via ctest, so the crypto is exercised on the wasm target.
#
# Requires .github/scripts/build-wasm.sh to have run first: it REUSES the
# wasm-target secp256k1 + OpenSSL builds and the private-header symlinks that
# build-wasm.sh produced under emcc_build/ (same versions, same forced
# SECP256K1_WIDEMUL_INT64), so the tests link the exact field arithmetic that
# ships. This is the WASM analog of the `ctest` step in build-shared-lib.sh.
#
# Prerequisites: Emscripten SDK (emcc/em++/emcmake), Node, and cmake on PATH.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${ROOT_DIR}"

BUILD_DIR="${ROOT_DIR}/emcc_build"
SECP256K1_LIB="${BUILD_DIR}/secp256k1/build/lib/libsecp256k1.a"
if [[ ! -f "${SECP256K1_LIB}" ]]; then
  echo "ERROR: wasm dependencies not found under ${BUILD_DIR}." >&2
  echo "       Run ./.github/scripts/build-wasm.sh first." >&2
  exit 1
fi

SECP256K1_INC="${BUILD_DIR}/secp256k1/include"
# build-wasm.sh symlinks secp256k1's private src/ headers under obj/private/;
# mpt_scalar.c includes them as <private/...>, so this dir must be on -I.
PRIVATE_INC="${BUILD_DIR}/obj"
OPENSSL_DIR="$(dirname "$(find "${BUILD_DIR}" -maxdepth 2 -name libcrypto.a | head -n1)")"

TEST_BUILD="${BUILD_DIR}/wasm-tests"
DEPS_DIR="${BUILD_DIR}/wasm-deps"
rm -rf "${TEST_BUILD}"
mkdir -p "${DEPS_DIR}"

# build-wasm.sh builds secp256k1 but does not `install` it, so there is no
# find_package config. Provide a minimal one pointing at the prebuilt archive.
cat > "${DEPS_DIR}/secp256k1-config.cmake" <<EOF
if(NOT TARGET secp256k1::secp256k1)
  add_library(secp256k1::secp256k1 STATIC IMPORTED)
  set_target_properties(secp256k1::secp256k1 PROPERTIES
    IMPORTED_LOCATION "${SECP256K1_LIB}"
    INTERFACE_INCLUDE_DIRECTORIES "${SECP256K1_INC}")
endif()
set(secp256k1_FOUND TRUE)
EOF

# HAVE___INT128=FALSE forces SECP256K1_WIDEMUL_INT64 to match the prebuilt
# secp256k1 (a mismatch changes secp256k1's internal struct layout -> ABI break).
# CMAKE_FIND_ROOT_PATH_MODE_*=BOTH lets find_package see the host-path deps
# under the Emscripten (cross-compile) toolchain.
emcmake cmake -S "${ROOT_DIR}" -B "${TEST_BUILD}" \
  -G "Unix Makefiles" \
  -DENABLE_TESTS=ON \
  -DMPT_CRYPTO_WERROR=OFF \
  -DHAVE___INT128=FALSE \
  -Dsecp256k1_DIR="${DEPS_DIR}" \
  -DOPENSSL_USE_STATIC_LIBS=ON \
  -DOPENSSL_CRYPTO_LIBRARY="${OPENSSL_DIR}/libcrypto.a" \
  -DOPENSSL_INCLUDE_DIR="${OPENSSL_DIR}/include" \
  -DCMAKE_C_FLAGS="-I${PRIVATE_INC}" \
  -DCMAKE_CXX_FLAGS="-I${PRIVATE_INC}" \
  -DCMAKE_FIND_ROOT_PATH_MODE_PACKAGE=BOTH \
  -DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=BOTH \
  -DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=BOTH \
  -DCMAKE_CROSSCOMPILING_EMULATOR="$(command -v node)"

cmake --build "${TEST_BUILD}" -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)"

# Each test executable is a wasm module; ctest runs it as `node test_*.js`.
cd "${TEST_BUILD}"
ctest --output-on-failure
