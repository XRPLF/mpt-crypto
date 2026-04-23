#!/usr/bin/env bash
# .github/scripts/build-shared-lib.sh
#
# Builds libmpt-crypto as a shared library with tests, via Conan + CMake.
# Invoked by .github/workflows/build-shared-libs.yml — either directly on
# a GitHub-hosted runner (Linux / macOS / Windows) or inside a
# --platform linux/<arch> Docker container for platforms without native
# runners (currently s390x via QEMU user-mode emulation).
#
# Preconditions: python3, conan, cmake, ninja (and MSVC on Windows) are
# on PATH, and the cwd is the repo root. RUNNER_OS is read to decide
# Windows-vs-POSIX behaviour; it's unset inside emulated containers, so
# we default to Linux.
set -euo pipefail

conan profile detect --force
conan remote add --index 0 --force xrplf https://conan.ripplex.io

# fPIC is a POSIX-only concept; MSVC rejects it.
CONAN_ARGS=(
  -of build
  --build=missing
  -s build_type=Release
  -o "&:shared=True"
  -o "&:tests=True"
  -o "secp256k1/*:shared=False"
  -o "openssl/*:shared=False"
)
if [[ "${RUNNER_OS:-Linux}" != "Windows" ]]; then
  CONAN_ARGS+=(-o "secp256k1/*:fPIC=True" -o "openssl/*:fPIC=True")
fi
conan install . "${CONAN_ARGS[@]}"

# Windows uses the Visual Studio multi-config generator; everything else
# uses Ninja (single-config, so CMAKE_BUILD_TYPE is baked in here).
CMAKE_ARGS=(
  -B build
  -S .
  -DCMAKE_TOOLCHAIN_FILE:FILEPATH=build/generators/conan_toolchain.cmake
)
if [[ "${RUNNER_OS:-Linux}" == "Windows" ]]; then
  CMAKE_ARGS+=(
    -G "Visual Studio 17 2022"
    -A x64
    -DCMAKE_WINDOWS_EXPORT_ALL_SYMBOLS=ON
  )
else
  CMAKE_ARGS+=(
    -G Ninja
    -DCMAKE_BUILD_TYPE=Release
  )
fi
cmake "${CMAKE_ARGS[@]}"

cmake --build build --config Release

# Windows has no rpath — test executables need the DLL's directory on
# PATH. With the VS generator the DLL lands at build/Release/, so prepend
# that. -C Release selects the VS multi-config build.
pushd build > /dev/null
CTEST_ARGS=(--output-on-failure)
if [[ "${RUNNER_OS:-Linux}" == "Windows" ]]; then
  export PATH="$(pwd)/Release:${PATH}"
  CTEST_ARGS+=(-C Release)
fi
ctest "${CTEST_ARGS[@]}"
popd > /dev/null
