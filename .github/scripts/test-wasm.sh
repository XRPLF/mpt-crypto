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
# ships. This is the WASM analog of the `ctest` step in build-native-libs.sh.
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
# Guard the find like the secp256k1 check above: an empty result would make
# dirname yield "." and fail far later as a confusing cmake error; a leftover
# openssl-<old>/ after a version bump would also make the pick arbitrary.
OPENSSL_LIB="$(find "${BUILD_DIR}" -maxdepth 2 -name libcrypto.a | head -n1)"
if [[ -z "${OPENSSL_LIB}" ]]; then
  echo "ERROR: OpenSSL libcrypto.a not found under ${BUILD_DIR}." >&2
  echo "       Run ./.github/scripts/build-wasm.sh first." >&2
  exit 1
fi
OPENSSL_DIR="$(dirname "${OPENSSL_LIB}")"

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

# Non-obvious flags below:
#  - HAVE___INT128=FALSE forces SECP256K1_WIDEMUL_INT64 to match the prebuilt
#    secp256k1 from build-wasm.sh (a mismatch changes secp256k1's internal struct
#    layout -> ABI break). This mirrors build-wasm.sh's -DSECP256K1_WIDEMUL_INT64.
#  - CMAKE_FIND_ROOT_PATH_MODE_*=BOTH lets find_package see the host-path deps
#    (our prebuilt archives) under the Emscripten cross-compile toolchain, which
#    otherwise only searches the emscripten sysroot.
#  - CMAKE_CROSSCOMPILING_EMULATOR=node makes ctest run each wasm test as
#    `node test_*.js` (the test binaries are wasm, not native executables).
#  - -G "Unix Makefiles" pins the generator so CI doesn't pick up Ninja/Xcode.
#  - MPT_CRYPTO_WERROR=OFF: wasm/toolchain warnings shouldn't fail the test build.
#  - OPENSSL_USE_STATIC_LIBS + explicit CRYPTO_LIBRARY/INCLUDE_DIR point at the
#    stripped libcrypto.a from build-wasm.sh, never a system OpenSSL.
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
  -DCMAKE_EXE_LINKER_FLAGS="-sALLOW_MEMORY_GROWTH=1 -sMAXIMUM_MEMORY=134217728" \
  -DCMAKE_FIND_ROOT_PATH_MODE_PACKAGE=BOTH \
  -DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=BOTH \
  -DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=BOTH \
  -DCMAKE_CROSSCOMPILING_EMULATOR="$(command -v node)"

cmake --build "${TEST_BUILD}" -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)"

# Each test executable is a wasm module; ctest runs it as `node test_*.js`.
cd "${TEST_BUILD}"
ctest --output-on-failure

# ---------------------------------------------------------------------------
# Smoke-test the shipped glue
# ---------------------------------------------------------------------------
# ctest above validates the crypto on its own test binaries; it never loads the
# glue build-wasm.sh ships. Load each and exercise the marshalling contract the
# wrapper needs: instantiate, init the secp256k1 context, and run one malloc+HEAPU8
# export. A bad -s flag fails here instead of downstream. (Crypto correctness is
# ctest's job — this only guards the glue/ABI.)
#
# mpt_crypto.js/.mjs load the wasm themselves (require / import). mpt_crypto.web.mjs
# is the browser glue (ENVIRONMENT=web,worker): no Node loader — it fetches the wasm
# in a browser — so here we instantiate it ourselves via the `instantiateWasm` hook
# (which createWasm honors before any fetch), smoke-testing that it instantiates and
# its ABI works. Its real fetch path is covered by downstream browser tests.
#
# GLUE_DIR defaults to emcc_out (the freshly built tree) for local runs. CI
# overrides it to the STAGED bundle dir so this validates exactly what ships —
# a file dropped from the bundle fails here instead of shipping green.
GLUE_DIR="${GLUE_DIR:-${ROOT_DIR}/emcc_out}"
echo "Smoke-testing the CJS + ESM + browser glue..."
node --input-type=module -e "
import { createRequire } from 'module'
const require = createRequire(import.meta.url)
async function check(label, factory) {
  const m = await factory()
  if (m._mpt_secp256k1_context() === 0) throw new Error(label + ': context init failed')
  const ptr = m._malloc(32)
  const rc = m._mpt_generate_blinding_factor(ptr)
  const written = m.HEAPU8.slice(ptr, ptr + 32).some(b => b !== 0)
  m._free(ptr)
  if (rc !== 0 || !written) throw new Error(label + ': marshalling path failed')
  console.log('  ' + label + ' OK')
}
await check('mpt_crypto.js  (CJS)', require('${GLUE_DIR}/mpt_crypto.js'))
await check('mpt_crypto.mjs (ESM)', (await import('${GLUE_DIR}/mpt_crypto.mjs')).default)
// Browser glue: no Node loader (it fetches in a browser), so instantiate the wasm
// ourselves via the instantiateWasm hook — createWasm honors it before any fetch.
await check('mpt_crypto.web.mjs (web)', async () => {
  const { default: factory } = await import('${GLUE_DIR}/mpt_crypto.web.mjs')
  const wasmBinary = require('fs').readFileSync('${GLUE_DIR}/mpt_crypto.wasm')
  return factory({
    instantiateWasm: (imports, done) => {
      done(new WebAssembly.Instance(new WebAssembly.Module(wasmBinary), imports))
    },
  })
})
"
