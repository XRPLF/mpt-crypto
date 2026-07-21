#!/usr/bin/env bash
# build-wasm.sh — Build the shipped mpt-crypto WebAssembly module.
#
# Produces the single JS-consumable artifact that downstream JS/TS libraries
# (e.g. xrpl.js) vendor:
#   emcc_out/mpt_crypto.js    (Emscripten MODULARIZE glue / loader)
#   emcc_out/mpt_crypto.wasm  (the compiled module, curated exports)
#
# Builds ONLY the module (not tests) — the companion test-wasm.sh validates it
# by running the crypto suite under Node; the CI workflow runs both in order.
# It has a dedicated emcc link (rather than CMake, like the native shared lib)
# because the wasm module needs MODULARIZE/exports/WASM_BIGINT.
#
# As a side effect it builds the wasm-target secp256k1 + OpenSSL static libs
# into emcc_build/, which test-wasm.sh reuses.
#
# Prerequisites: Emscripten SDK (emcc, em++, emcmake, emmake) on PATH.
#
# Usage (paths resolve to the repo root, so run from anywhere):
#   ./.github/scripts/build-wasm.sh          # full build (deps + module)
#   ./.github/scripts/build-wasm.sh --clean  # remove build artifacts and rebuild

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
BUILD_DIR="${ROOT_DIR}/emcc_build"
OUT_DIR="${ROOT_DIR}/emcc_out"
CONAN_LOCK="${ROOT_DIR}/conan.lock"

# Pin dependency versions to conan.lock so this WASM build always matches the
# Conan package rippled consumes — drift here can silently break proof interop.
# secp256k1 drives the curve math (version-critical); OpenSSL is only SHA-2 +
# RAND, but we track it too to avoid surprises.
if [[ ! -f "${CONAN_LOCK}" ]]; then
    echo "ERROR: ${CONAN_LOCK} not found" >&2
    exit 1
fi
lock_version() {
    sed -nE "s|.*\"$1/([0-9][^#\"]*)#.*|\1|p" "${CONAN_LOCK}" | head -n1
}

# secp256k1's git tag is "v0.7.1"; conan.lock stores "0.7.1", so prefix "v".
SECP256K1_VERSION="v$(lock_version secp256k1)"
OPENSSL_VERSION="$(lock_version openssl)"

if [[ "${SECP256K1_VERSION}" == "v" || -z "${OPENSSL_VERSION}" ]]; then
    echo "ERROR: could not read secp256k1/openssl versions from ${CONAN_LOCK}" >&2
    exit 1
fi

# Integrity pins for the directly-fetched sources. This WASM path fetches deps
# outside Conan (git tag / release tarball), so verify them the way Conan does
# from conan.lock. Update these together with the versions above.
SECP256K1_COMMIT="1a53f4961f337b4d166c25fce72ef0dc88806618"                       # tag v0.7.1
OPENSSL_SHA256="aaf51a1fe064384f811daeaeb4ec4dce7340ec8bd893027eee676af31e83a04f" # openssl-3.6.2.tar.gz

# Portable sha256 (Linux coreutils sha256sum; macOS shasum).
sha256_of() {
    if command -v sha256sum &>/dev/null; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

SECP256K1_SRC="${BUILD_DIR}/secp256k1"
SECP256K1_BUILD="${BUILD_DIR}/secp256k1/build"
OPENSSL_SRC="${BUILD_DIR}/openssl-${OPENSSL_VERSION}"
OBJ_DIR="${BUILD_DIR}/obj"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log() { echo "==> $*"; }
require_cmd() {
    if ! command -v "$1" &>/dev/null; then
        echo "ERROR: $1 not found. Install Emscripten SDK and add to PATH." >&2
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Argument handling
# ---------------------------------------------------------------------------
if [[ "${1:-}" == "--clean" ]]; then
    log "Cleaning build artifacts"
    rm -rf "${BUILD_DIR}" "${OUT_DIR}"
fi

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------
require_cmd emcc
require_cmd em++
require_cmd emcmake
require_cmd emmake

mkdir -p "${BUILD_DIR}" "${OUT_DIR}" "${OBJ_DIR}"

log "Dependencies (from conan.lock): secp256k1 ${SECP256K1_VERSION}, openssl ${OPENSSL_VERSION}"

# ---------------------------------------------------------------------------
# 1. Build secp256k1
# ---------------------------------------------------------------------------
if [[ ! -f "${SECP256K1_BUILD}/lib/libsecp256k1.a" ]]; then
    log "Building secp256k1 ${SECP256K1_VERSION}"

    if [[ ! -f "${SECP256K1_SRC}/CMakeLists.txt" ]]; then
        git clone --depth 1 --branch "${SECP256K1_VERSION}" \
            https://github.com/bitcoin-core/secp256k1.git "${SECP256K1_SRC}"
    fi

    # A git tag is mutable (can be force-pushed); the commit it resolves to is
    # not. Verify the checked-out commit against the pin.
    actual_sha="$(git -C "${SECP256K1_SRC}" rev-parse HEAD)"
    if [[ "${actual_sha}" != "${SECP256K1_COMMIT}" ]]; then
        echo "ERROR: secp256k1 ${SECP256K1_VERSION} is ${actual_sha}, expected ${SECP256K1_COMMIT}" >&2
        exit 1
    fi

    mkdir -p "${SECP256K1_BUILD}"
    cd "${SECP256K1_BUILD}"

    emcmake cmake .. \
        -DCMAKE_C_FLAGS="-DSECP256K1_WIDEMUL_INT64" \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=OFF \
        -DSECP256K1_BUILD_TESTS=OFF \
        -DSECP256K1_BUILD_BENCHMARK=OFF \
        -DSECP256K1_BUILD_CTIME_TESTS=OFF \
        -DSECP256K1_BUILD_EXAMPLES=OFF \
        -DSECP256K1_ENABLE_MODULE_ECDH=ON \
        -DSECP256K1_ENABLE_MODULE_RECOVERY=OFF \
        -DSECP256K1_ENABLE_MODULE_EXTRAKEYS=OFF \
        -DSECP256K1_ENABLE_MODULE_SCHNORRSIG=OFF \
        -DSECP256K1_ENABLE_MODULE_MUSIG=OFF \
        -DSECP256K1_ENABLE_MODULE_ELLSWIFT=OFF \
        -DSECP256K1_ECMULT_WINDOW_SIZE=15 \
        -DSECP256K1_ECMULT_GEN_KB=86

    emmake make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)"

    cd "${ROOT_DIR}"
    log "secp256k1 built: $(wc -c < "${SECP256K1_BUILD}/lib/libsecp256k1.a") bytes"
else
    log "secp256k1 already built — skipping"
fi

# ---------------------------------------------------------------------------
# 2. Build OpenSSL (stripped for SHA-256/512 + RAND_bytes only)
# ---------------------------------------------------------------------------
if [[ ! -f "${OPENSSL_SRC}/libcrypto.a" ]]; then
    log "Building OpenSSL ${OPENSSL_VERSION}"

    if [[ ! -d "${OPENSSL_SRC}" ]]; then
        cd "${BUILD_DIR}"
        openssl_tarball="openssl-${OPENSSL_VERSION}.tar.gz"
        curl -sL "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/${openssl_tarball}" \
            -o "${openssl_tarball}"
        got="$(sha256_of "${openssl_tarball}")"
        if [[ "${got}" != "${OPENSSL_SHA256}" ]]; then
            echo "ERROR: ${openssl_tarball} sha256 ${got}, expected ${OPENSSL_SHA256}" >&2
            exit 1
        fi
        tar xzf "${openssl_tarball}"
        rm -f "${openssl_tarball}"
        cd "${ROOT_DIR}"
    fi

    cd "${OPENSSL_SRC}"

    # Heavily stripped configure — only SHA-256, SHA-512, RAND_bytes, OPENSSL_cleanse
    perl Configure linux-generic32 \
        --cross-compile-prefix= \
        CC=emcc AR=emar RANLIB=emranlib \
        no-asm no-threads no-shared no-dso no-engine no-async \
        no-ssl no-tls no-dtls no-cms no-comp no-ct no-ts no-srp no-srtp \
        no-ocsp no-cmp no-fips no-legacy no-tests no-ui-console no-stdio \
        no-err no-autoerrinit no-autoalginit \
        no-des no-rc2 no-rc4 no-idea no-seed no-bf no-cast no-camellia no-aria \
        no-sm2 no-sm3 no-sm4 no-whirlpool no-rmd160 no-mdc2 no-blake2 \
        no-siphash no-poly1305 no-chacha \
        no-dh no-dsa no-ec no-ecdh no-ecdsa \
        no-psk no-gost \
        no-cmac no-scrypt \
        no-sock no-dgram \
        no-http no-posix-io no-deprecated no-cached-fetch no-atexit \
        no-apps no-module no-autoload-config \
        -Oz -flto \
        -DOPENSSL_NO_SECURE_MEMORY

    emmake make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)" build_libs

    cd "${ROOT_DIR}"
    log "OpenSSL built: $(wc -c < "${OPENSSL_SRC}/libcrypto.a") bytes"
else
    log "OpenSSL already built — skipping"
fi

# ---------------------------------------------------------------------------
# 3. Set up secp256k1 private headers (for mpt_scalar.c)
# ---------------------------------------------------------------------------
log "Setting up secp256k1 private header symlink"
mkdir -p "${OBJ_DIR}/private"
ln -sf "${SECP256K1_SRC}/src"/* "${OBJ_DIR}/private/" 2>/dev/null || true

# ---------------------------------------------------------------------------
# 4. Compile mpt-crypto sources
# ---------------------------------------------------------------------------
log "Compiling mpt-crypto sources"

CFLAGS="-Oz -flto \
    -I${ROOT_DIR}/include \
    -I${SECP256K1_SRC}/include \
    -I${OPENSSL_SRC}/include \
    -I${OBJ_DIR} \
    -DSECP256K1_WIDEMUL_INT64"

for f in "${ROOT_DIR}"/src/*.c; do
    name="$(basename "$f" .c)"
    if [[ "$f" -nt "${OBJ_DIR}/${name}.o" ]]; then
        echo "  CC  ${name}.c"
        emcc ${CFLAGS} -c "$f" -o "${OBJ_DIR}/${name}.o"
    fi
done

name="mpt_utility"
if [[ "${ROOT_DIR}/src/utility/${name}.cpp" -nt "${OBJ_DIR}/${name}.o" ]]; then
    echo "  CXX ${name}.cpp"
    em++ ${CFLAGS} -std=c++17 -c "${ROOT_DIR}/src/utility/${name}.cpp" -o "${OBJ_DIR}/${name}.o"
fi

# ---------------------------------------------------------------------------
# 5. Link final WASM
# ---------------------------------------------------------------------------
log "Linking mpt_crypto.wasm"

EXPORTS="_malloc,_free"
EXPORTS="${EXPORTS},_mpt_secp256k1_context"
# _mpt_generate_keypair intentionally NOT exported: ElGamal keys come from
# ripple-keypairs (a separate secp256k1 seed), not the WASM CSPRNG.
EXPORTS="${EXPORTS},_mpt_generate_blinding_factor"
EXPORTS="${EXPORTS},_mpt_encrypt_amount,_mpt_decrypt_amount"
EXPORTS="${EXPORTS},_mpt_get_pedersen_commitment"
EXPORTS="${EXPORTS},_mpt_get_convert_context_hash,_mpt_get_convert_proof,_mpt_verify_convert_proof"
EXPORTS="${EXPORTS},_mpt_get_clawback_context_hash,_mpt_get_clawback_proof,_mpt_verify_clawback_proof"
EXPORTS="${EXPORTS},_mpt_get_convert_back_context_hash,_mpt_get_convert_back_proof,_mpt_verify_convert_back_proof"
EXPORTS="${EXPORTS},_mpt_get_send_context_hash,_mpt_get_confidential_send_proof,_mpt_verify_send_proof"
EXPORTS="${EXPORTS},_mpt_verify_revealed_amount"
EXPORTS="${EXPORTS},_mpt_verify_send_range_proof"
EXPORTS="${EXPORTS},_mpt_verify_aggregated_bulletproof"
EXPORTS="${EXPORTS},_mpt_make_ec_pair,_mpt_serialize_ec_pair"
EXPORTS="${EXPORTS},_mpt_compute_convert_back_remainder"

emcc -Oz -flto \
    "${OBJ_DIR}"/*.o \
    "${SECP256K1_BUILD}/lib/libsecp256k1.a" \
    "${OPENSSL_SRC}/libcrypto.a" \
    -sMODULARIZE=1 \
    -sEXPORT_NAME=MptCrypto \
    -sWASM_BIGINT=1 \
    -sALLOW_MEMORY_GROWTH=1 \
    -sEXPORTED_FUNCTIONS="${EXPORTS}" \
    '-sEXPORTED_RUNTIME_METHODS=["ccall","cwrap","HEAPU8"]' \
    -sENVIRONMENT=web,node \
    -o "${OUT_DIR}/mpt_crypto.js"

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
JS_SIZE=$(wc -c < "${OUT_DIR}/mpt_crypto.js")
WASM_SIZE=$(wc -c < "${OUT_DIR}/mpt_crypto.wasm")
log "Done!"
log "  ${OUT_DIR}/mpt_crypto.js   (${JS_SIZE} bytes)"
log "  ${OUT_DIR}/mpt_crypto.wasm (${WASM_SIZE} bytes)"
