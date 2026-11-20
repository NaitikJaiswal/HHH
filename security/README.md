# HHH SecureLog — Security Module

> **Phase 1 of 4 — Core Cryptographic Primitives — COMPLETE**

## Purpose

This module owns the **Security + Blockchain** responsibilities for HHH SecureLog, a blockchain-powered tamper-evident digital forensics platform.

Phase 1 delivers the foundational cryptographic layer: canonical log serialization, SHA-256 hashing, and hash chain construction/verification — all implemented exactly to the [LOGN-HASH-v1 specification](../docs/technical-integration-contract.md#1-canonical-log-hashing-formula).

---

## Module Status

| Phase | Capability | Status |
|-------|-----------|--------|
| **1** | Canonical JSON serialization (LOGN-HASH-v1) | ✅ Complete |
| **1** | SHA-256 hashing (`sha256hex`, `hashLogEvent`) | ✅ Complete |
| **1** | Hash chain construction (`buildChain`) | ✅ Complete |
| **1** | Hash chain verification (`verifyHashChain`) | ✅ Complete |
| **2** | Merkle tree construction and inclusion proofs | 🔲 Planned |
| **2** | Ed25519 key management and digital signatures | 🔲 Planned |
| **2** | Signed checkpoint generation | 🔲 Planned |
| **3** | Solidity `SecureLogAnchor` smart contract | 🔲 Planned |
| **3** | ethers.js v6 `BlockchainService` | 🔲 Planned |
| **4** | End-to-end verification (signature + Merkle + on-chain) | 🔲 Planned |

---

## Prerequisites

- **Node.js ≥ 18.0.0** (uses built-in `node:crypto` and `node:test`)
- No third-party npm packages required for Phase 1

---

## Installation

```bash
cd security
# No npm install needed for Phase 1 — only Node.js built-in modules used
```

---

## Running Tests

```bash
cd security
npm test
# or directly:
node --test tests/canonicalJson.test.js tests/hashing.test.js tests/hashChain.test.js
```

Expected output: **36 tests pass, 0 fail**.

---

## Core Cryptographic Concepts

### LOGN-HASH-v1

The canonical log hash formula agreed in the [Technical Integration Contract](../docs/technical-integration-contract.md) §1.3. It defines:

- **9 exact fields** in snake_case: `event_id`, `event_time`, `event_type`, `message`, `metadata`, `previous_hash`, `sequence_number`, `severity`, `source_id`
- **Key sort order**: Unicode code point ascending (ASCII-equivalent for all field names)
- **Serialization**: no whitespace, non-ASCII characters preserved as-is (not `\uXXXX` escaped)
- **Hash algorithm**: SHA-256 of the UTF-8 encoding of the canonical JSON string
- **Output**: lowercase hex, exactly 64 characters

### Hash Chain

Each event's hash commits to all 9 fields **including `previous_hash`** (the previous event's hash). This creates a tamper-evident chain:

- Modifying any field changes that event's hash
- Because each event includes the previous hash, all subsequent events also change
- Gaps, deletions, insertions, and reordering are all detectable

**What the chain proves:** Internal consistency — no event was silently modified after the chain was built.

**What it does not prove (Phase 2+):** Authenticity. An attacker with database write access can rebuild a consistent chain. Ed25519 signatures on checkpoint Merkle roots and on-chain anchoring close this gap.

### Genesis Hash

The first event in every source has `previous_hash = "000...0"` (64 zeros), consistent with both the backend `Source.lastHash` initialization and the storage module.

---

## Directory Structure

```
security/
├── src/
│   ├── crypto/
│   │   ├── canonicalJson.js    ← LOGN-HASH-v1 deterministic serializer
│   │   ├── hashing.js          ← SHA-256, hashLogEvent, GENESIS_HASH
│   │   └── hashChain.js        ← buildChain, verifyHashChain
│   ├── merkle/                 ← Phase 2: Merkle tree and proofs
│   ├── keys/                   ← Phase 2: Ed25519 key management
│   ├── checkpoints/            ← Phase 2: Checkpoint service
│   ├── blockchain/             ← Phase 3: ethers.js BlockchainService
│   └── verification/           ← Phase 4: End-to-end verifier
├── tests/
│   ├── canonicalJson.test.js   ← 13 serializer tests
│   ├── hashing.test.js         ← 11 hashing tests
│   └── hashChain.test.js       ← 10 chain tests (36 total)
├── docs/
│   ├── security-architecture.md
│   └── threat-model.md
├── keys/                       ← Phase 2: encrypted key storage (gitignored)
├── .gitignore
├── package.json
└── README.md
```

---

## Limitations (Phase 1)

- **No Merkle tree** — Merkle root computation and inclusion proofs are Phase 2.
- **No digital signatures** — Ed25519 key management and signing are Phase 2.
- **No smart contracts** — Solidity `SecureLogAnchor` is Phase 3.
- **No blockchain transactions** — `BlockchainService` is Phase 3.
- **No end-to-end verification** — The full pipeline (signature + Merkle + on-chain) is Phase 4.
- The hash chain proves **internal consistency only**. It is NOT a proof of authenticity without signatures and on-chain anchoring.

---

## Contributing

All changes to this module must comply with the [Technical Integration Contract](../docs/technical-integration-contract.md). Key rules:

1. Never silently change the LOGN-HASH-v1 field set or serialization rules.
2. Never commit private keys — `security/keys/signing_key.enc` is gitignored.
3. Changes affecting the Backend or Storage hash formula require cross-module integration PRs.
4. All new functionality must have tests in `tests/` before merging.
