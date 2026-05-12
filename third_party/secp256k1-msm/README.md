# `secp256k1-msm` — vendored Pippenger/Straus MSM

Self-contained copy of the multi-scalar-multiplication (MSM) primitive
from [`bitcoin-core/secp256k1`](https://github.com/bitcoin-core/secp256k1),
specifically `secp256k1_ecmult_multi_var` and its supporting machinery.
Used internally by `mpt-crypto`'s batch-verification entry points.

See `PROVENANCE` for upstream version, commit hash, and licence.

## Why this exists

`libsecp256k1`'s public API exposes only single-point operations
(`secp256k1_ec_pubkey_tweak_mul`, `secp256k1_ec_pubkey_combine`).
Its internal Pippenger/Straus MSM
(`secp256k1_ecmult_multi_var` in `src/ecmult_impl.h`) is not
callable from outside the library — even though it is exactly
what `libsecp256k1` itself uses for Schnorr batch verification.

`mpt-crypto`'s upcoming `*_verify_batch` API needs the same
primitive: an MSM-backed batch verifier delivers $2$–$4\times$
throughput on the validator path versus a per-proof loop, on
both the compact AND-composed sigma family (via shared-CMPT-
generator amortisation) and aggregated Bulletproofs (via BBB+18
§6.1 generator stacking).

Vendoring is the cleanest way to expose this primitive without
either taking a dependency on the unrelated modules in
`secp256k1-zkp` or waiting for the still-experimental upstream
PR `bitcoin-core/secp256k1#1134`.

## Why self-contained

The vendor includes not just `ecmult_impl.h` plus WNAF helpers,
but also the dependent internal types
(`secp256k1_gej`, `secp256k1_scalar`, `secp256k1_fe`, scratch-
space layouts) and the curve-arithmetic primitives the MSM uses.

This matters because `mpt-crypto` continues to link against a
Conan-pinned `libsecp256k1` for the public-API surface. If the
vendored MSM shared internal types with that linked binary, a
Conan version bump that touched any of those private types
(rare but it happens — e.g. the 0.5.x scratch-space refactor)
would create undefined behaviour in the vendored module.

By vendoring the dependent types alongside the MSM, the
vendored module's correctness becomes independent of the linked-
binary version. This PR does **not** change the existing
`libsecp256k1` Conan pin; that is a pre-existing dependency-
management decision, out of scope here.

## Threat model

The vendored MSM is **variable-time**. It is exposed only as
`mpt_msm_variable_time` and is intended **only for the validator
path (D4)**, where the verifier has no secret inputs and a
constant-time MSM is not a confidentiality requirement.

A separate `mpt_msm_constant_time` profile exists for the
prover path (loop-based or always-touch-every-bucket Pippenger);
this is documented in the public header and enforced by
naming convention. **Never** route prover-side MSMs through
`mpt_msm_variable_time`.

See `cmpt-ct-and-batch.tex` (`internal-ripplex-research`,
`proposed-changes-writeup` branch) for the full threat-model
treatment.

## Single-TU strategy (minimal symbol rename)

All upstream functions in the vendored headers are declared
`static`. A single wrapper translation unit, `mpt_msm.c`,
includes the vendored headers and exposes one external symbol:
`mpt_msm_variable_time`. Every other upstream function is
file-local to `mpt_msm.c` and cannot collide with any symbol
in the linked `libsecp256k1` binary that the rest of
`mpt-crypto` uses for the public-API surface.

The exception is `precomputed_ecmult.c`, which exports the
generator-table data symbols `secp256k1_pre_g` and
`secp256k1_pre_g_128` so that `mpt_msm.c` can link against
them. The linked `libsecp256k1` binary also exports these
symbols (since it uses the same internal tables for its own
ecmult routines), so we rename our vendored copies at compile
time via `-Dsecp256k1_pre_g=mpt_secp256k1_pre_g` and
`-Dsecp256k1_pre_g_128=mpt_secp256k1_pre_g_128`. The `-D` flag
applies uniformly to the declaration (in `precomputed_ecmult.h`),
the definition (in `precomputed_ecmult.c`), and the use sites
inside `ecmult_impl.h`, so no source edits to the vendored
files are required.

This is the only symbol rename. All other upstream identifiers
remain unchanged, so future re-syncs against newer upstream tags
apply as plain file diffs.

Public entry point:

```c
/* see ../../include/mpt_msm.h for the full API */
int mpt_msm_variable_time(
    /* outputs, scalars, points, n */
);
```

## Sync procedure

See `PROVENANCE` for the step-by-step procedure to re-sync
against a newer upstream tag. We follow the same deliberate-update
model as the Conan lockfile in `conan/lockfile/`: re-sync when
motivated (security fix, performance gain) rather than on an
automated schedule. No drift-detection tripwire — same as for
Conan-managed dependencies.

## File list (in-progress)

The vendoring boundary is the transitive closure of `#include`s
rooted at `secp256k1_ecmult_multi_var`. As of the initial vendor
this is approximately 25 files; the precise list is maintained
in `PROVENANCE`.

Categories (all paths relative to `src/` in the upstream tree):

| Category                 | Files                                                            |
| ------------------------ | ---------------------------------------------------------------- |
| Top-level utilities      | `util.h`, `assumptions.h`, `util_local_visibility.h`             |
| Field arithmetic         | `field.h`, `field_impl.h`, `field_5x52*.h`, `field_10x26*.h`     |
| Scalar arithmetic        | `scalar.h`, `scalar_impl.h`, `scalar_4x64*.h`, `scalar_8x32*.h`  |
| Group arithmetic         | `group.h`, `group_impl.h`                                        |
| 128-bit integer support  | `int128.h`, `int128_native*.h`, `int128_struct*.h`               |
| Modular inverse          | `modinv32.h`, `modinv32_impl.h`, `modinv64.h`, `modinv64_impl.h` |
| MSM proper               | `ecmult.h`, `ecmult_impl.h`                                      |
| Generator precomputation | `precomputed_ecmult.h`, `precomputed_ecmult.c`                   |
| Scratch-space allocator  | `scratch.h`, `scratch_impl.h`                                    |

`hash.h`/`hash_impl.h` may be required for blinding randomness
inside `secp256k1_ecmult_multi_var`; this will be confirmed
during the vendoring step.
