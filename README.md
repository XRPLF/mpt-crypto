# mpt-crypto

This document outlines the mpt-crypto library, a cryptographic toolkit specifically designed to enable confidential Multi-Purpose Token (MPT) transactions on the XRP Ledger. 

It details the implementation of core cryptographic primitives, including:
* **ElGamal encryption** for confidential amounts.
* **Schnorr-based zero-knowledge proofs** for equality and correct encryption.
* **Bulletproofs** for efficient range proofs.

All operations leverage the **libsecp256k1** framework. The library provides the foundational cryptographic operations necessary for managing private balances and ensuring the integrity of confidential ledger state transitions.
