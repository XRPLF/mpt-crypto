#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# build-native-libs.sh — build ALL of mpt-crypto's native libraries for one
# platform from a SINGLE dependency build.
#
# One `conan install` (static secp256k1 + OpenSSL) + one CMake configure produces
# BOTH:
#   • the self-contained STATIC bundle (libmpt-crypto.a / mpt-crypto-static.lib,
#     secp256k1 + OpenSSL merged in; see cmake/BundleStatic.cmake), and
#   • the SHARED library (libmpt-crypto.{so,dylib,dll}), built as a sibling target
#     from the same objects + the same static deps.
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

conan profile detect --force
conan remote add --index 0 --force xrplf https://conan.xrplf.org/repository/conan/

CONAN_ARGS=(
  -of build
  --build=missing
  # Retry recipe source downloads (e.g. secp256k1's tarball from github.com),
  # which get rate-limited / 503 in bursts. ~2.5 min total window (5 × 30s) rides
  # out a typical rate-limit reset; bounded so a genuine outage still fails in a
  # few minutes rather than hanging. Retries only cost time when a download
  # actually fails, so this is free on healthy runs.
  -c tools.files.download:retry=5
  -c tools.files.download:retry_wait=30
  -s build_type=Release
  -o "&:shared=False"
  -o "&:tests=True"
  -o "secp256k1/*:shared=False"
  -o "openssl/*:shared=False"
  # Drop OpenSSL's optional zlib support: it makes libcrypto.a reference external
  # deflate/inflate, which would leak out of the "self-contained" archive and
  # force every consumer to also link -lz. mpt-crypto uses no compression.
  -o "openssl/*:no_zlib=True"
)
if [[ "${RUNNER_OS:-Linux}" != "Windows" ]]; then
  CONAN_ARGS+=(-o "secp256k1/*:fPIC=True" -o "openssl/*:fPIC=True")
else
  # Build against the DYNAMIC MSVC runtime (/MD). The static archive gets linked
  # into consumers that use the dynamic CRT — the Python .pyd (extensions match
  # the CPython DLL's /MD) and the Rust MSVC target (dynamic CRT by default). A
  # static-CRT (/MT) build would mismatch and fail with LNK4098 + unresolved
  # __imp_* CRT symbols. `shared=False` (a static .lib) is orthogonal to the CRT
  # model — we want static libs that use the dynamic CRT.
  CONAN_ARGS+=(-s "compiler.runtime=dynamic")
fi
conan install . "${CONAN_ARGS[@]}"

# Conan's generator subfolder nests differently across versions/layouts; locate
# the toolchain rather than hardcoding a path.
TOOLCHAIN="$(find build -name conan_toolchain.cmake -print -quit)"
[[ -n "$TOOLCHAIN" ]] || { echo "ERROR: conan_toolchain.cmake not found under build/"; exit 1; }

CMAKE_ARGS=(
  -B build
  -S .
  -DCMAKE_TOOLCHAIN_FILE:FILEPATH="${TOOLCHAIN}"
  -DMPT_CRYPTO_BUNDLE_STATIC=ON
  -DMPT_CRYPTO_BUILD_SHARED=ON
  # PIC so the static objects can seed the shared library AND so the static
  # bundle links into a Python .pyd (extensions must be position-independent).
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON
)
if [[ "${RUNNER_OS:-Linux}" == "Windows" ]]; then
  CMAKE_ARGS+=(
    -G "Visual Studio 17 2022"
    -A x64
  )
else
  CMAKE_ARGS+=(
    -G Ninja
    -DCMAKE_BUILD_TYPE=Release
  )
fi
cmake "${CMAKE_ARGS[@]}"

cmake --build build --config Release

# ctest runs each test against the static target and — since MPT_CRYPTO_BUILD_SHARED
# is on — a `*_shared` variant against the shared library, validating both forms.
pushd build > /dev/null
CTEST_ARGS=(--output-on-failure)
if [[ "${RUNNER_OS:-Linux}" == "Windows" ]]; then
  export PATH="$(pwd)/Release:${PATH}"
  CTEST_ARGS+=(-C Release)
fi
ctest "${CTEST_ARGS[@]}"
popd > /dev/null

# ── Verify the bundled archive is self-contained & correctly scoped ──────────
# Resolve the bundle path and the platform's REQUIRED extra link libraries. The
# self-contained archive still needs the C++ runtime (mpt_utility.cpp) + OpenSSL's
# OS-level deps — the same libs the shared library leaves dynamic. A consumer that
# static-links the bundle MUST also link these; we emit them as a manifest below
# so the Rust / Python builds don't have to rediscover them.
if [[ "${RUNNER_OS:-Linux}" == "Windows" ]]; then
  BUNDLED="build/mpt-crypto-bundled.lib"
  # OpenSSL 3.x's Win32 system deps (RAND/bcrypt, WinCrypt, sockets, UI), plus
  # legacy_stdio_definitions for OpenSSL's inline stdio (__imp_* stdio symbols
  # that live there under the dynamic UCRT).
  SYS_LIBS=(crypt32 ws2_32 advapi32 user32 gdi32 bcrypt legacy_stdio_definitions)
elif [[ "$(uname -s)" == "Darwin" ]]; then
  BUNDLED="build/libmpt-crypto-bundled.a"
  SYS_LIBS=(c++)
else
  BUNDLED="build/libmpt-crypto-bundled.a"
  # dl: OpenSSL 3.x provider loading (dlopen/dlsym). m/pthread: libcrypto.
  SYS_LIBS=(stdc++ pthread dl m)
fi
[[ -f "$BUNDLED" ]] || { echo "ERROR: bundled archive not produced at $BUNDLED"; exit 1; }
echo "Bundled archive: $BUNDLED ($(du -h "$BUNDLED" | cut -f1))"

# ── Emit the required-system-libs manifest next to the archive ───────────────
MANIFEST="$(dirname "$BUNDLED")/mpt-crypto-static.link-libs.txt"
{
  echo "# System libraries a consumer must link ALONGSIDE the self-contained"
  echo "# mpt-crypto static archive (C++ runtime + OpenSSL's OS deps). These are"
  echo "# the same libs the shared library leaves dynamic. One name per line,"
  echo "# no -l prefix / no .lib suffix."
  for l in "${SYS_LIBS[@]}"; do echo "$l"; done
} > "$MANIFEST"
echo "Required system libs (also staged as $(basename "$MANIFEST")): ${SYS_LIBS[*]}"

# ── (1) Authoritative self-containment: link a small program against ONLY the
#        bundle + the platform system libs (no -lcrypto/-lssl/-lsecp256k1/-lz).
#        It calls several entry points AND takes the address of the heavy
#        bulletproof/proof members, so the linker must pull + resolve those
#        members too — a member whose deps didn't fold in can't slip through by
#        going unreferenced. Then it runs. ────────────────────────────────────
TESTDIR="$(mktemp -d)"
cat > "${TESTDIR}/linktest.c" <<'EOF'
#include <stdint.h>
#include <stdio.h>

/* Called with valid inputs: exercise RNG + secp256k1 + ElGamal + commitments,
   which between them reference the OpenSSL-heavy and secp256k1-heavy members. */
int mpt_generate_keypair(uint8_t* sk, uint8_t* pk);
int mpt_generate_blinding_factor(uint8_t factor[32]);
int mpt_encrypt_amount(uint64_t amount, const uint8_t pk[33],
                       const uint8_t blinding[32], uint8_t out_ct[66]);
int mpt_get_pedersen_commitment(uint64_t amount, const uint8_t blinding[32],
                                uint8_t out[33]);

/* Reference-only (not called — awkward signatures): asserts these public
   symbols exist. NOTE: these names are load-bearing — they must track the
   library's exported API; if a symbol is renamed or the bulletproof module is
   configured out, this test fails to LINK (a build error, not a hiding error).
   Member inclusion itself is guaranteed by the whole-archive link above. */
extern int secp256k1_bulletproof_prove_agg(void);
extern int secp256k1_bulletproof_verify_agg(void);
extern int mpt_get_confidential_send_proof(void);
extern int mpt_get_clawback_proof(void);

int main(int argc, char** argv) {
    (void)argv;
    uint8_t sk[32] = {0}, pk[33] = {0}, bf[32] = {0}, ct[66] = {0}, com[33] = {0};

    if (mpt_generate_keypair(sk, pk) != 0) return 1;
    if (!(pk[0] == 0x02 || pk[0] == 0x03)) return 1;   /* valid compressed pubkey */
    if (mpt_generate_blinding_factor(bf) != 0) return 2;
    if (mpt_encrypt_amount(42, pk, bf, ct) != 0) return 3;
    if (mpt_get_pedersen_commitment(42, bf, com) != 0) return 4;

    /* Keep the heavy references live so the optimizer cannot drop them. */
    void* refs[] = {
        (void*)&secp256k1_bulletproof_prove_agg,
        (void*)&secp256k1_bulletproof_verify_agg,
        (void*)&mpt_get_confidential_send_proof,
        (void*)&mpt_get_clawback_proof,
    };
    volatile void* keep = refs[(unsigned)argc % 4];
    if (keep == 0) return 5;

    printf("linktest OK: keypair+blinding+encrypt+commitment ran; "
           "bulletproof/proof members linked\n");
    return 0;
}
EOF

if [[ "${RUNNER_OS:-Linux}" == "Windows" ]]; then
  # MSVC: use the DYNAMIC CRT (-MD) to match the bundle, which is built with
  # compiler.runtime=dynamic. cl.exe defaults to /MT (static CRT) when no
  # runtime flag is given, which would clash with the bundle's /MD objects
  # (LNK4098 + unresolved __imp_* CRT symbols). Dash-form flags (-nologo -MD)
  # avoid MSYS/git-bash rewriting a leading '/' into a path.
  BUNDLED_ABS="$(pwd -W 2>/dev/null || pwd)/$BUNDLED"
  WIN_LIBS=(); for l in "${SYS_LIBS[@]}"; do WIN_LIBS+=("${l}.lib"); done
  (
    cd "$TESTDIR"
    cl -nologo -MD linktest.c "$BUNDLED_ABS" "${WIN_LIBS[@]}"
  ) || { echo "ERROR: Windows bundle is NOT self-contained — cl link failed."; exit 1; }
  "${TESTDIR}/linktest.exe" || { echo "ERROR: linked program did not run cleanly."; exit 1; }
  echo "OK: links + runs standalone on Windows (self-contained)."
else
  LINK_LIBS=(); for l in "${SYS_LIBS[@]}"; do LINK_LIBS+=("-l${l}"); done
  # Force EVERY archive member into the link (macOS -force_load / GNU
  # --whole-archive), so the self-containment check is COMPLETE: every member's
  # external references must resolve against SYS_LIBS alone. A normal (on-demand)
  # link would only pull the members reachable from the symbols referenced below,
  # leaving other members' deps unverified.
  if [[ "$(uname -s)" == "Darwin" ]]; then
    CC_BIN="${CC:-clang}"
    WHOLE=(-Wl,-force_load,"$BUNDLED")
  else
    CC_BIN="${CC:-cc}"
    WHOLE=(-Wl,--whole-archive "$BUNDLED" -Wl,--no-whole-archive)
  fi
  if ! "${CC_BIN}" "${TESTDIR}/linktest.c" "${WHOLE[@]}" "${LINK_LIBS[@]}" -o "${TESTDIR}/linktest"; then
    echo "ERROR: bundled archive is NOT self-contained — whole-archive link failed."
    exit 1
  fi
  "${TESTDIR}/linktest" || { echo "ERROR: linked program did not run cleanly."; exit 1; }
  echo "OK: whole-archive links + runs standalone (self-contained)."
fi
rm -rf "${TESTDIR}"

# ── (2) Symbol visibility (nm — skipped on Windows, which lacks it here) ──────
if command -v nm > /dev/null 2>&1 && [[ "${RUNNER_OS:-Linux}" != "Windows" ]]; then
  # (a) API present: mpt-crypto + secp256k1 public symbols must stay global.
  #     (macOS prefixes symbols with a leading underscore, hence _?.)
  for sym in mpt_encrypt_amount secp256k1_ec_pubkey_create; do
    found="$(nm -g --defined-only "$BUNDLED" 2>/dev/null | grep -E " _?${sym}\$" || true)"
    if [[ -z "$found" ]]; then
      echo "ERROR: expected global API symbol '$sym' is missing/hidden."
      exit 1
    fi
  done
  echo "OK: mpt-crypto + secp256k1 API symbols are global."

  # (b) OpenSSL hidden (ELF/Linux only — macOS keeps them, which is fine there).
  #     ALLOWLIST check: the only global defined symbols permitted are the kept
  #     API that BundleStatic localized against (keep-global.txt = mpt_* +
  #     secp256k1_*). ANY other global is a hiding failure — and OpenSSL 3.x's
  #     surface is far larger than a handful of prefixes (EVP_/BN_/EC_/RSA_/
  #     ossl_*/ASN1_/sha256_block_data_order/…), so a denylist would silently
  #     miss a real leak. Comparing against the exact keep-list catches all of it.
  if [[ "$(uname -s)" == "Linux" ]]; then
    KEEP="$(dirname "$BUNDLED")/keep-global.txt"
    [[ -f "$KEEP" ]] || { echo "ERROR: keep-global.txt not found ($KEEP) — cannot verify symbol hiding."; exit 1; }
    globals="$(nm -g --defined-only "$BUNDLED" 2>/dev/null \
                 | awk 'NF==3 && $2 ~ /^[A-Za-z]$/ {print $3}' | sort -u)"
    # No `|| true` here: this is a security-relevant gate, so a pipeline failure
    # (e.g. nm erroring) must abort under `set -o pipefail`, not silently pass.
    leaked="$(comm -23 <(printf '%s\n' "$globals") <(sort -u "$KEEP"))"
    if [[ -n "$leaked" ]]; then
      echo "ERROR: non-API global symbols leaked (OpenSSL hiding failed):"
      printf '%s\n' "$leaked" | head -20
      exit 1
    fi
    echo "OK: only the kept API (mpt_* + secp256k1_*) is global; OpenSSL hidden."
  fi
fi

echo "Static bundle verification passed."

# ── (3) Verify the shared library was produced and exports the C API ─────────
if [[ "${RUNNER_OS:-Linux}" == "Windows" ]]; then
  SHARED="build/shared/Release/mpt-crypto.dll"
elif [[ "$(uname -s)" == "Darwin" ]]; then
  SHARED="build/shared/libmpt-crypto.dylib"
else
  SHARED="build/shared/libmpt-crypto.so"
fi
[[ -f "$SHARED" ]] || { echo "ERROR: shared library not produced at $SHARED"; exit 1; }
echo "Shared library: $SHARED ($(du -h "$SHARED" | cut -f1))"

# On unix, confirm the C API is exported (dynamic symbol table). Windows export
# checking needs dumpbin; the CMake WINDOWS_EXPORT_ALL_SYMBOLS build is the
# guarantee there.
if [[ "${RUNNER_OS:-Linux}" != "Windows" ]] && command -v nm > /dev/null 2>&1; then
  if [[ "$(uname -s)" == "Darwin" ]]; then
    exported="$(nm -gU "$SHARED" 2>/dev/null | grep -E ' _?mpt_generate_keypair$' || true)"
  else
    exported="$(nm -D --defined-only "$SHARED" 2>/dev/null | grep -E ' mpt_generate_keypair$' || true)"
  fi
  [[ -n "$exported" ]] || { echo "ERROR: shared library does not export the mpt-crypto C API."; exit 1; }
  echo "OK: shared library exports the mpt-crypto C API."
fi

echo "Native library build complete (static bundle + shared library)."
