#!/usr/bin/env bash
set -euo pipefail

conan profile detect --force
conan remote add --index 0 --force xrplf https://conan.ripplex.io

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

pushd build > /dev/null
CTEST_ARGS=(--output-on-failure)
if [[ "${RUNNER_OS:-Linux}" == "Windows" ]]; then
  export PATH="$(pwd)/Release:${PATH}"
  CTEST_ARGS+=(-C Release)
fi
ctest "${CTEST_ARGS[@]}"
popd > /dev/null
