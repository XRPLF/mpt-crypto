#!/usr/bin/env bash

set -ex

TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

echo "Using temporary CONAN_HOME: $TEMP_DIR"

# We use a temporary Conan home to avoid polluting the user's existing Conan
# configuration and to not use local cache (which leads to non-reproducible lockfiles).
export CONAN_HOME="$TEMP_DIR"

# Ensure that the xrplf remote is the first to be consulted, so any recipes we
# patched are used. We also add it there to not create a huge diff when the
# official Conan Center Index is updated.
conan remote add --force --index 0 xrplf https://conan.ripplex.io

# Delete any existing lockfile.
rm -f conan.lock

# Create a new lockfile.  The lockfile pins recipe revisions, which for our
# pure-C dependencies (`openssl`, `secp256k1`) are platform-independent, so
# a single profile captures the full dependency graph.  `tests=True` is the
# build configuration used by CI; setting it here ensures any test-only
# transitive deps are captured.
conan lock create . \
    --options '&:tests=True' \
    --profile:all=conan/lockfile/windows.profile
