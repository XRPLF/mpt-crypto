# MPT-Crypto: Cryptographic Primitives for Confidential Assets

## Overview

**MPT-Crypto** is a specialized C library implementing the cryptographic building blocks for **Confidential Multi-Purpose Tokens (MPT)** on the XRP Ledger. It provides high-performance, audit-ready implementations of homomorphic encryption, aggregated range proofs, and specialized zero-knowledge proofs required for privacy-preserving financial transactions.

The library is built on top of `libsecp256k1` for elliptic curve arithmetic and OpenSSL for hashing and randomness, designed with a focus on security, determinism, and constant-time execution.

## Features

### 1. Confidential Balances (EC-ElGamal)
* **Additive Homomorphic Encryption:** Enables the ledger to aggregate encrypted balances (e.g., `Enc(A) + Enc(B) = Enc(A+B)`) without decryption.
* **Exponential ElGamal:** Values are encoded in the exponent ($m \cdot G$), optimized for 64-bit financial amounts.
* **Canonical Zero:** Deterministic encryption of zero balances to prevent ledger state bloat and ensure consistency.

### 2. Range Proofs (Bulletproofs)
* **Aggregated Proofs:** Supports proving that $m$ values are within the range $[0, 2^{64})$ in a single proof with logarithmic size $\mathcal{O}(\log n)$.
* **Inner Product Argument (IPA):** Implements the standard Bulletproofs IPA for succinct verification.
* **Fiat-Shamir:** Secure non-interactive challenge generation with strict domain separation.

### 3. Zero-Knowledge Proofs (Sigma Protocols)
* **Plaintext Equality:** Proves two ciphertexts encrypt the same amount under different keys (1-to-1 and 1-to-N variants).
* **Linkage Proof:** Proves consistency between an ElGamal ciphertext (used for transfer) and a Pedersen Commitment (used for the range proof).
* **Proof of Knowledge (PoK):** Proves ownership of the secret key during account registration to prevent rogue key attacks.

### 4. Commitments
* **Pedersen Commitments:** Perfectly hiding and computationally binding commitments ($C = vG + rH$).
* **NUMS Generators:** Secondary generators ($H$, $\mathbf{G}$, $\mathbf{H}$) are derived deterministically ("Nothing-Up-My-Sleeve") using SHA-256 to ensure transparency.

## Directory Structure

```text
mpt-crypto/
├── include/
│   └── secp256k1_mpt.h                   # Public API header
├── src/
│   ├── bulletproof_aggregated.c          # Aggregated Range Proofs implementation
│   ├── commitments.c                     # Pedersen commitments & generator derivation
│   ├── elgamal.c                         # Encryption, Decryption, Homomorphic ops
│   ├── equality_proof.c                  # 1-to-1 Plaintext Equality ZK Proofs
│   ├── proof_link.c                      # ElGamal-Pedersen Linkage Proofs
│   ├── proof_pok_sk.c                    # Secret Key Knowledge Proofs
│   ├── proof_same_plaintext_multi.c      # 1-to-N Equality (General)
│   ├── proof_same_plaintext_multi_shared_r.c # 1-to-N Equality (Shared Randomness)
│   ├── mpt_scalar.c                      # Internal scalar arithmetic wrappers
│   └── ...
├── docs/                                 # Documentation output (Doxygen)
└── README.md                             # This file