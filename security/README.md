# HHH SecureLog — Security & Cryptography Module

> **Phase 1: Core Cryptographic Primitives — COMPLETE**  
> **Phase 2: Merkle Tree, Ed25519 Key Management & Signed Checkpoints — COMPLETE**

## Purpose

This module owns the **Security + Blockchain** responsibilities for HHH SecureLog, a blockchain-powered tamper-evident digital forensics platform.

Phase 1 established the canonical hashing and per-event hash chain layer (`LOGN-HASH-v1`).  
Phase 2 establishes the Merkle tree engine, persistent encrypted Ed25519 key management, signed checkpoint generation, and independent forensic verification.

---

## Module Status

| Phase | Capability | Status |
|-------|-----------|--------|
| **1** | Canonical JSON serialization (LOGN-HASH-v1) | ✅ Complete |
| **1** | SHA-256 hashing (`sha256hex`, `hashLogEvent`) | ✅ Complete |
| **1** | Hash chain construction (`buildChain`) | ✅ Complete |
| **1** | Hash chain verification (`verifyHashChain`) | ✅ Complete |
| **2** | Merkle tree construction and inclusion proofs | ✅ Complete |
| **2** | Ed25519 key management and persistent encrypted storage | ✅ Complete |
| **2** | Key rotation with historical public key registry | ✅ Complete |
| **2** | Signed checkpoint creation (`createCheckpoint`) | ✅ Complete |
| **2** | Independent verification engine (`verifyCheckpoint`, `verifyEventsAgainstCheckpoint`) | ✅ Complete |
| **3** | Solidity `SecureLogAnchor` smart contract | 🔲 Planned |
| **3** | ethers.js v6 `BlockchainService` | 🔲 Planned |
| **4** | On-chain end-to-end audit and automated anchoring pipeline | 🔲 Planned |

---

## Prerequisites

- **Node.js ≥ 18.0.0** (tested on Node.js v24.17.0)
- Built entirely with Node.js standard libraries (`node:crypto`, `node:test`, `node:assert`, `node:fs`, `node:path`)
- **Zero third-party runtime or test dependencies**

---

## Installation

```bash
cd security
# No npm dependencies required for Phase 1 or Phase 2
```

---

## Running Tests

Run the complete test suite (Phase 1 + Phase 2):

```bash
cd security
npm test
```

Or run test files directly:

```bash
node --test tests/canonicalJson.test.js \
            tests/hashing.test.js \
            tests/hashChain.test.js \
            tests/merkleTree.test.js \
            tests/keyManager.test.js \
            tests/checkpointService.test.js \
            tests/verifier.test.js
```

Current test status: **65 tests pass, 0 fail**.

---

## Architecture & Documentation

- [docs/security-architecture.md](docs/security-architecture.md) — Comprehensive security and integration architecture.
- [docs/threat-model.md](docs/threat-model.md) — Threat analysis, adversary models, and system boundaries.
- [docs/merkle-tree.md](docs/merkle-tree.md) — Merkle tree specification, domain separation, and inclusion proofs.
- [docs/key-management.md](docs/key-management.md) — Persistent Ed25519 key storage, AES-GCM envelope, scrypt KDF, and rotation.
- [docs/checkpoints.md](docs/checkpoints.md) — Checkpoint schema, canonical signing payload, and verification workflow.

---

## Directory Structure

```
security/
├── src/
│   ├── crypto/
│   │   ├── canonicalJson.js    ← LOGN-HASH-v1 deterministic serializer
│   │   ├── hashing.js          ← SHA-256, hashLogEvent, GENESIS_HASH
│   │   └── hashChain.js        ← buildChain, verifyHashChain
│   ├── merkle/
│   │   └── merkleTree.js       ← buildMerkleTree, proofs, domain separation
│   ├── keys/
│   │   └── keyManager.js       ← Ed25519 key lifecycle, AES-GCM at rest, rotation
│   ├── checkpoints/
│   │   └── checkpointService.js← createCheckpoint, verifyCheckpoint
│   ├── verification/
│   │   └── verifier.js         ← Unified end-to-end verification engine
│   ├── blockchain/             ← Phase 3: Smart contract integration & ethers.js
│   └── index.js                ← Main module exports
├── tests/
│   ├── canonicalJson.test.js   ← 13 serializer tests
│   ├── hashing.test.js         ← 11 hashing tests
│   ├── hashChain.test.js       ← 10 chain tests
│   ├── merkleTree.test.js      ← 11 Merkle tree tests
│   ├── keyManager.test.js      ← 9 key management tests
│   ├── checkpointService.test.js← 8 checkpoint tests
│   └── verifier.test.js        ← 3 comprehensive verification tests
├── docs/
│   ├── security-architecture.md
│   ├── threat-model.md
│   ├── merkle-tree.md
│   ├── key-management.md
│   └── checkpoints.md
├── .gitignore
├── package.json
└── README.md
```

---

## Phase 2 Cryptographic Invariants

1. **Deterministic Merkle Root**:
   - Leaf domain prefix `0x00`, internal node prefix `0x01` (prevents second-preimage attacks).
   - Unpaired nodes duplicated per Bitcoin standard.
   - Empty trees evaluate to SHA-256(0x00) sentinel.
2. **Key Security at Rest**:
   - Private key seeds stored in `signing_key.enc` encrypted with AES-256-GCM.
   - Keys derived via scrypt ($N=32768, r=8, p=1$).
   - Never committed to Git (`.gitignore` protects `*.enc`, `*.key`).
   - File permissions restricted to mode `0600` on creation.
3. **Canonical Signing Payload**:
   - Checkpoint signatures cover the canonical serialization of the document excluding `"signature"` and `"blockchain"`.
   - Modifying sequence ranges, timestamps, or Merkle roots invalidates the signature.
4. **Historical Verifiability**:
   - Key rotation generates a new key pair while recording past public keys in `key_registry.json`.
   - Checkpoints signed with older keys remain verifiable against their historical key IDs.

---

## Limitations (Phase 2)

- **Smart Contract Anchoring (Phase 3)**: Checkpoints in Phase 2 have `blockchain: null`. On-chain anchoring into EVM smart contracts will be implemented in Phase 3.
- **Hardware Security Modules (HSM)**: For the hackathon MVP, keys are encrypted on the local filesystem. Production deployment should migrate private keys to KMS / HSM backends.
