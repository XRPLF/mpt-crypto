#!/usr/bin/env bash
# build-wasm.sh — Build the shipped mpt-crypto WebAssembly module.
#
# Produces the JS-consumable artifacts that downstream JS/TS libraries
# (e.g. xrpl.js) vendor:
#   emcc_out/mpt_crypto.js      (MODULARIZE CommonJS glue — Node require)
#   emcc_out/mpt_crypto.mjs     (EXPORT_ES6 ESM glue, web+node — Node import)
#   emcc_out/mpt_crypto.web.mjs (EXPORT_ES6 ESM glue, web only — bundlers/browsers)
#   emcc_out/mpt_crypto.wasm    (the compiled module, curated exports)
#
# Builds ONLY the module (not tests) — the companion test-wasm.sh validates it
# by running the crypto suite under Node; the CI workflow runs both in order.
# It has a dedicated emcc link (rather than CMake) because the wasm module needs
# MODULARIZE/exports/WASM_BIGINT.
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
        echo "ERROR: secp256k1 ${SECP256K1_VERSION} is ${actual_sha}, expected ${SECP256K1_COMMIT}." >&2
        echo "       If conan.lock bumped secp256k1, update SECP256K1_COMMIT in this script." >&2
        exit 1
    fi

    mkdir -p "${SECP256K1_BUILD}"
    cd "${SECP256K1_BUILD}"

    # The non-obvious flags below:
    #  - SECP256K1_WIDEMUL_INT64: wasm32 has no native 128-bit integer, so force
    #    the 64-bit field backend. This MUST match the mpt-crypto sources (step 4)
    #    and the test build (test-wasm.sh's HAVE___INT128=FALSE) — the widemul
    #    choice changes secp256k1's internal struct layout, so any mismatch is a
    #    silent ABI break at link time.
    #  - BUILD_SHARED_LIBS=OFF: force a static libsecp256k1.a. Some CI runners
    #    default this ON, which builds a .so instead and makes the final emcc link
    #    (step 5) fail with "libsecp256k1.a: No such file or directory".
    #  - Only the ECDH module is enabled — the one curve op mpt-crypto needs; the
    #    rest stay off to keep the wasm small.
    #  - ECMULT_WINDOW_SIZE / ECMULT_GEN_KB size the precomputed tables: a
    #    speed-vs-binary-size tradeoff only. They do NOT change results, so they
    #    have no bearing on proof interop with rippled.
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
        # --fail so an HTTP error (e.g. 404) aborts here with a clear status,
        # rather than saving the error body and surfacing as a hash mismatch.
        curl -fsSL "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/${openssl_tarball}" \
            -o "${openssl_tarball}"
        got="$(sha256_of "${openssl_tarball}")"
        if [[ "${got}" != "${OPENSSL_SHA256}" ]]; then
            echo "ERROR: ${openssl_tarball} sha256 ${got}, expected ${OPENSSL_SHA256}." >&2
            echo "       If conan.lock bumped openssl, update OPENSSL_SHA256 in this script." >&2
            exit 1
        fi
        tar xzf "${openssl_tarball}"
        rm -f "${openssl_tarball}"
        cd "${ROOT_DIR}"
    fi

    cd "${OPENSSL_SRC}"

    # Heavily stripped configure — mpt-crypto only needs SHA-256/512, RAND_bytes,
    # and OPENSSL_cleanse, so everything else is disabled both to shrink the wasm
    # and to drop code that needs syscalls Emscripten can't provide. Key choices:
    #  - linux-generic32: a portable, asm-free 32-bit C target (wasm32 is 32-bit).
    #    CC=emcc does the actual compile, so --cross-compile-prefix stays empty.
    #  - OPENSSL_NO_SECURE_MEMORY: the secure heap relies on mmap/madvise, which
    #    aren't available under wasm.
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

    # build_libs (not the default target) builds only libcrypto/libssl — we never
    # need the openssl apps or test binaries.
    emmake make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)" build_libs

    cd "${ROOT_DIR}"
    log "OpenSSL built: $(wc -c < "${OPENSSL_SRC}/libcrypto.a") bytes"
else
    log "OpenSSL already built — skipping"
fi

# ---------------------------------------------------------------------------
# 3. Set up secp256k1 private headers (for mpt_scalar.c)
# ---------------------------------------------------------------------------
# mpt_scalar.c reuses secp256k1's internal field/scalar arithmetic, which lives
# in secp256k1's src/ (not its public include/) and is pulled in as <private/...>.
# Symlink that src/ tree under obj/private/ so -I${OBJ_DIR} resolves those
# includes. test-wasm.sh reuses the same symlinks (it puts ${OBJ_DIR} on -I too).
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

# Collect the objects for THIS source set explicitly and link that list (not a
# ${OBJ_DIR}/*.o glob), so a renamed or deleted source can't leave a stale .o
# behind for the link to silently pick up. Caveat: the -nt check compares only
# the source's mtime, not its headers — after editing a header, rebuild with
# --clean (or delete emcc_build/obj) to force recompilation.
OBJECTS=()
for f in "${ROOT_DIR}"/src/*.c; do
    name="$(basename "$f" .c)"
    obj="${OBJ_DIR}/${name}.o"
    OBJECTS+=("${obj}")
    if [[ "$f" -nt "${obj}" ]]; then
        echo "  CC  ${name}.c"
        emcc ${CFLAGS} -c "$f" -o "${obj}"
    fi
done

name="mpt_utility"
obj="${OBJ_DIR}/${name}.o"
OBJECTS+=("${obj}")
if [[ "${ROOT_DIR}/src/utility/${name}.cpp" -nt "${obj}" ]]; then
    echo "  CXX ${name}.cpp"
    em++ ${CFLAGS} -std=c++17 -c "${ROOT_DIR}/src/utility/${name}.cpp" -o "${obj}"
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
# Per-transaction context-hash + proof entries. On each line the get_*_context_hash
# and get_*_proof (generator) symbols ARE called by the @xrplf/mpt-crypto TS
# wrapper; the paired _mpt_verify_* symbols are NOT — the wrapper only generates
# proofs, never verifies. The verifiers (here and the standalone group below) are
# kept for consumers that verify client-side; they're safe to drop if you want a
# smaller module. Keep this list in sync with
# @xrplf/mpt-crypto's index.ts (unexported symbols get dead-stripped downstream).
EXPORTS="${EXPORTS},_mpt_get_convert_context_hash,_mpt_get_convert_proof,_mpt_verify_convert_proof"
EXPORTS="${EXPORTS},_mpt_get_clawback_context_hash,_mpt_get_clawback_proof,_mpt_verify_clawback_proof"
EXPORTS="${EXPORTS},_mpt_get_convert_back_context_hash,_mpt_get_convert_back_proof,_mpt_verify_convert_back_proof"
EXPORTS="${EXPORTS},_mpt_get_send_context_hash,_mpt_get_confidential_send_proof,_mpt_verify_send_proof"
# Standalone verifiers + low-level helpers — none used by the TS wrapper today
# (see the note above); exported for client-side verification.
EXPORTS="${EXPORTS},_mpt_verify_revealed_amount"
EXPORTS="${EXPORTS},_mpt_verify_send_range_proof"
EXPORTS="${EXPORTS},_mpt_verify_aggregated_bulletproof"
EXPORTS="${EXPORTS},_mpt_make_ec_pair,_mpt_serialize_ec_pair"
EXPORTS="${EXPORTS},_mpt_compute_convert_back_remainder"
# Homomorphic ElGamal ciphertext add/subtract (secp256k1_pubkey in/out, defined in
# src/elgamal.c, return 1 on success). Not used by the single-transaction builders,
# but batching multiple balance-mutating Confidential MPT transactions for one
# (account, token) requires predicting the post-inner spending balance client-side
# (CB_S' = CB_S -/+ the encrypted amount) so each chained proof binds to it. The TS
# wrapper marshals bytes<->secp256k1_pubkey via _mpt_make_ec_pair/_mpt_serialize_ec_pair.
EXPORTS="${EXPORTS},_secp256k1_elgamal_add,_secp256k1_elgamal_subtract"
# Canonical encrypted zero (secp256k1_pubkey out, defined in src/elgamal.c).
# Not used by the proof builders, but XLS-0096 section 9.4 makes the canonical
# zero a deliberately public property: anyone holding the ledger's public data
# (holder encryption key, account ID, issuance ID) can recompute EncZero and
# byte-compare it against a stored ciphertext to learn that a balance is exactly
# 0. Exporting it keeps observers (explorers, compliance tooling, a wallet
# auditing its own exposure) on the same deterministic derivation validators
# use, instead of reimplementing the hash-and-rejection-sample outside the
# library where a drift would fail silently. Marshals via
# _mpt_make_ec_pair/_mpt_serialize_ec_pair like the two above.
EXPORTS="${EXPORTS},_generate_canonical_encrypted_zero"

# Why these -s link flags (they define the JS-facing contract, so don't drop them
# without checking the @xrplf/mpt-crypto TS wrapper):
#  - MODULARIZE + EXPORT_NAME: emit a factory `MptCrypto()` instead of a global,
#    so the module can be require()'d / imported and loaded lazily.
#  - WASM_BIGINT: marshal i64 <-> JS BigInt directly — mpt amounts are uint64_t.
#  - ALLOW_MEMORY_GROWTH: let the heap grow on demand instead of reserving a fixed
#    block up front.
#  - GROWABLE_ARRAYBUFFERS=0: emsdk 6.x defaults this to 1, which grows the heap in
#    place backed by a RESIZABLE ArrayBuffer. A subarray of a resizable buffer makes
#    TextDecoder.decode throw in Chrome ("ArrayBuffer must not be resizable"), which
#    breaks the xrpl.js browser tests. Setting 0 keeps growth but reallocates a plain
#    (non-resizable) buffer on each grow — browser-safe, and no fixed memory cap.
#  - MAXIMUM_MEMORY=128MB: a defense-in-depth ceiling. The real working set is small
#    and stable — dominated by secp256k1's static tables, with per-op allocations
#    freed and reused, so it does not grow over time — and stays far below this cap.
#    The ceiling just bounds a hypothetical runaway well under the 2GB default.
#  - EXPORTED_RUNTIME_METHODS: the TS marshalling layer needs HEAPU8 + ccall/cwrap.
#  - ENVIRONMENT=web,node: the base .js/.mjs glues run under Node; a dedicated
#    browser glue is re-linked below as web,worker (no Node branch) — see the links.
LINK_FLAGS=(
    -Oz -flto
    "${OBJECTS[@]}"
    "${SECP256K1_BUILD}/lib/libsecp256k1.a"
    "${OPENSSL_SRC}/libcrypto.a"
    -sMODULARIZE=1
    -sEXPORT_NAME=MptCrypto
    -sWASM_BIGINT=1
    -sALLOW_MEMORY_GROWTH=1
    -sGROWABLE_ARRAYBUFFERS=0
    -sMAXIMUM_MEMORY=134217728
    -sEXPORTED_FUNCTIONS="${EXPORTS}"
    '-sEXPORTED_RUNTIME_METHODS=["ccall","cwrap","HEAPU8"]'
    -sENVIRONMENT=web,node
)

# @xrplf/mpt-crypto ships dual CJS+ESM so the same package works under Node
# `require`/Jest AND under bundlers/browsers via `import`. Emit THREE Emscripten
# glues from the identical objects — they all wrap the SAME mpt_crypto.wasm:
#   - mpt_crypto.js      : MODULARIZE CommonJS   (require()'d by the CJS build / Node)
#   - mpt_crypto.mjs     : EXPORT_ES6, web+node  (Node `import`; its Node branch runs
#                          `await import("node:module")` to read the .wasm from disk)
#   - mpt_crypto.web.mjs : EXPORT_ES6, web only  (bundlers/browsers) — the same glue
#                          built with ENVIRONMENT=web,worker instead of web,node, so it
#                          carries NO Node branch and thus no `node:` imports. Browser
#                          bundlers reject the `node:` URI scheme at build time even
#                          though that code is dead in a browser, so the package's
#                          `browser` export must point here, not at mpt_crypto.mjs.
# Both ESM glues use `new URL('mpt_crypto.wasm', import.meta.url)` so bundlers
# auto-emit the .wasm as an asset instead of a runtime read. Keep the three links in
# lockstep — they must wrap the byte-identical module.
emcc "${LINK_FLAGS[@]}" -o "${OUT_DIR}/mpt_crypto.js"
wasm_sha_cjs="$(sha256_of "${OUT_DIR}/mpt_crypto.wasm")"
emcc "${LINK_FLAGS[@]}" -sEXPORT_ES6=1 -o "${OUT_DIR}/mpt_crypto.mjs"
wasm_sha_esm="$(sha256_of "${OUT_DIR}/mpt_crypto.wasm")"
# Browser-only glue. -sENVIRONMENT=web,worker (overriding web,node) drops the Node
# code path and its `node:` imports. Emscripten names the .wasm after the -o basename,
# so link under the shared `mpt_crypto` name in a temp dir — the glue then references
# `mpt_crypto.wasm`, the one we ship — and move just the glue out. Linking straight to
# mpt_crypto.web.mjs would emit and reference a separate mpt_crypto.web.wasm.
web_tmp="$(mktemp -d)"
trap 'rm -rf "${web_tmp}"' EXIT
emcc "${LINK_FLAGS[@]}" -sEXPORT_ES6=1 -sENVIRONMENT=web,worker -o "${web_tmp}/mpt_crypto.mjs"
wasm_sha_web="$(sha256_of "${web_tmp}/mpt_crypto.wasm")"
mv "${web_tmp}/mpt_crypto.mjs" "${OUT_DIR}/mpt_crypto.web.mjs"

# The browser glue exists precisely so browser bundlers never see a `node:` import; the
# Node smoke test can't catch a regression (Node resolves node:module fine), so assert
# the invariant at build time. Matches emscripten's dynamic `import("node:…")` and any
# static `from "node:…"`, but not the benign `{…,node:…}` FS object literals.
if grep -Eq 'import\(["'"'"']node:|from[[:space:]]*["'"'"']node:' "${OUT_DIR}/mpt_crypto.web.mjs"; then
    echo "ERROR: mpt_crypto.web.mjs leaked a node: import — browser bundlers will reject it" >&2
    exit 1
fi

# The .js/.mjs links overwrite the OUT_DIR .wasm in place; the browser link builds its
# own in a temp dir. All three must wrap the byte-identical module (the browser glue
# references the shipped mpt_crypto.wasm), so enforce it.
if [[ "${wasm_sha_cjs}" != "${wasm_sha_esm}" || "${wasm_sha_cjs}" != "${wasm_sha_web}" ]]; then
    echo "ERROR: the CJS / ESM / web links produced different mpt_crypto.wasm" >&2
    echo "       (cjs=${wasm_sha_cjs} esm=${wasm_sha_esm} web=${wasm_sha_web})" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
JS_SIZE=$(wc -c < "${OUT_DIR}/mpt_crypto.js")
MJS_SIZE=$(wc -c < "${OUT_DIR}/mpt_crypto.mjs")
WEB_MJS_SIZE=$(wc -c < "${OUT_DIR}/mpt_crypto.web.mjs")
WASM_SIZE=$(wc -c < "${OUT_DIR}/mpt_crypto.wasm")
log "Done!"
log "  ${OUT_DIR}/mpt_crypto.js      (${JS_SIZE} bytes)"
log "  ${OUT_DIR}/mpt_crypto.mjs     (${MJS_SIZE} bytes)"
log "  ${OUT_DIR}/mpt_crypto.web.mjs (${WEB_MJS_SIZE} bytes)"
log "  ${OUT_DIR}/mpt_crypto.wasm    (${WASM_SIZE} bytes)"
