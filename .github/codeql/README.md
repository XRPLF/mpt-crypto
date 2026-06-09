# Custom CodeQL queries for mpt-crypto

This directory holds project-specific CodeQL queries used to flag
crypto-sensitive patterns that the standard query packs do not cover.

## Queries

### `queries/uncleansed-sensitive-data.ql`

Detects stack variables that hold sensitive data (either directly
cleansed somewhere in the function, or copied from a variable that is)
and reports paths where a write reaches a function return without an
intervening `OPENSSL_cleanse` barrier.

Authored by Trail of Bits as part of the TOB-RIPCTXR revision audit
(June 5, 2026 final report, Appendix H, figure H.1). The rule surfaced
TOB-RIPCTXR-6 — an uncleansed `prev` nonce buffer in
`generate_deterministic_nonces` that could expose proof witnesses and
secret keys via post-compromise memory disclosure. The underlying code
fix landed in PR #74.

## Running locally

The audit's recommended invocation is captured in Appendix G (pp. 76–79
of the final report). Briefly:

```sh
# Build a CodeQL database from a clean CMake build.
conan install . \
  --output-folder build-codeql \
  --build missing \
  --settings build_type=Debug

cmake -S . -B build-codeql \
  -DCMAKE_TOOLCHAIN_FILE=build-codeql/build/generators/conan_toolchain.cmake \
  -DCMAKE_BUILD_TYPE=Debug \
  -Dtests=ON

codeql database create codeql.db \
  --language=cpp \
  --source-root=. \
  --command='cmake --build build-codeql'

# Run only this query.
codeql database analyze codeql.db \
  .github/codeql/queries/uncleansed-sensitive-data.ql \
  --format=sarif-latest \
  --output=uncleansed-sensitive-data.sarif
```

The SARIF output can be viewed in VS Code via the
[SARIF Viewer](https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer)
extension or piped through `jq` for command-line inspection.

## CI integration

Not yet wired into CI; see issue #122 for context. A standalone CodeQL
workflow will land separately once the broader static-analysis CI
posture (including the ASAN/LSAN job tracked in #121) is settled.

## Extending the sensitive-output sink set

The rule's `scalarHelper` and `firstArgumentOutput` predicates enumerate
helpers whose first output argument receives data derived from a
sensitive scalar or pubkey. When adding a new sensitive-output API in
`include/secp256k1_mpt.h` or `src/`, add the function name to one of
those predicates so the rule continues to track its outputs.
