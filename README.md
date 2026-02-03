# MPT-Crypto: Cryptographic Primitives for Confidential Assets

## Overview

**MPT-Crypto** is a specialized C library implementing the cryptographic building blocks for
**Confidential Multi-Purpose Tokens (MPT)** on the XRP Ledger. It provides implementations of homomorphic encryption, aggregated range proofs, and specialized zero-knowledge proofs.
The library is built on top of `libsecp256k1` for elliptic curve arithmetic and OpenSSL for hashing and randomness.
## Features

### 1. Confidential Balances (EC-ElGamal)
* **Additive Homomorphic Encryption:** Enables the ledger to aggregate encrypted balances (e.g., `Enc(A) + Enc(B) = Enc(A+B)`) without decryption.
* **Canonical Zero:** Deterministic encryption of zero balances to prevent ledger state bloat and ensure consistency.

### 2. Range Proofs (Bulletproofs)
* **Aggregated Proofs:** Supports proving that $m$ values are within the range $[0, 2^{64})$ in a single proof with logarithmic size $\mathcal{O}(\log n)$.
* **Inner Product Argument (IPA):** Implements the standard Bulletproofs IPA for succinct verification.
* **Fiat-Shamir:** Secure non-interactive challenge generation with strict domain separation.

### 3. Zero-Knowledge Proofs (Sigma Protocols)
* **Plaintext Equality:** Proves two or more ciphertexts encrypt the same amount under different keys.
* **Linkage Proof:** Proves consistency between an ElGamal ciphertext (used for transfer) and a Pedersen Commitment (used for the range proof).
* **Proof of Knowledge (PoK):** Proves ownership of the secret key during account registration to prevent rogue key attacks.

## Building and Testing

### Prerequisites

Before building, ensure you have the following installed:

- **CMake** (version 3.10 or higher)
- **C Compiler** (GCC, Clang, or AppleClang)
- **OpenSSL 3.x** (development headers and libraries)

On macOS with Homebrew:
```bash
brew install cmake openssl@3
```

On Ubuntu/Debian:
```bash
sudo apt-get install cmake libssl-dev build-essential
```

### Dependency Setup

This library requires `libsecp256k1` as a sibling directory. Clone it from the bitcoin-core repository:

```bash
# From the parent directory of mpt-crypto
cd ..
git clone https://github.com/bitcoin-core/secp256k1.git
```

Your directory structure should look like:
```
Projects/
├── mpt-crypto/
└── secp256k1/
```

### Build Instructions

1. **Create the build directory and configure:**
   ```bash
   cd mpt-crypto
   mkdir -p build && cd build
   cmake ..
   ```

2. **Build the library and tests:**
   ```bash
   make -j4
   ```

#### Platform-Specific Notes

**macOS (Apple Silicon):** If you encounter architecture mismatch errors with OpenSSL, explicitly set the architecture:
```bash
cmake -DCMAKE_OSX_ARCHITECTURES=arm64 ..
```

**macOS (Intel):** Use `x86_64` instead:
```bash
cmake -DCMAKE_OSX_ARCHITECTURES=x86_64 ..
```

### Running Tests

After building, run the test suite using CTest:

```bash
cd build
ctest --output-on-failure
```

Or run individual tests directly:
```bash
./tests/test_elgamal
./tests/test_bulletproof_agg
./tests/test_commitments
```

### Expected Results

The following tests should pass:
- `test_bulletproof_agg` - Aggregated Bulletproof range proofs
- `test_commitments` - Pedersen commitments
- `test_elgamal` - ElGamal encryption/decryption
- `test_elgamal_verify` - ElGamal verification
- `test_equality_proof` - Equality proofs
- `test_ipa` - Inner Product Argument (IPA) Core Logic
- `test_link_proof` - Linkage proofs
- `test_pok_sk` - Proof of knowledge of secret key
- `test_same_plaintext` - Same plaintext proofs
- `test_same_plaintext_multi` - Multi-recipient same plaintext proofs
- `test_same_plaintext_multi_shared_r` - Shared randomness variant

**Note:** `test_bulletproof.c` is excluded from the build because the aggregated implementation (bulletproof_aggregated.c) is fully general; verifying the m=1 case is now covered by test_bulletproof_agg.c.
