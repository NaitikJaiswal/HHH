# Security Module Architecture

> **HHH SecureLog — Security + Blockchain Module**<br>
> **Reference:** `docs/technical-integration-contract.md` §§1–9<br>
> **Status:** All Phases (1 through 5) Implemented & Verified

---

## Overview

The Security module implements the cryptographic backbone of the HHH SecureLog platform. Its responsibilities span five sequential phases, each building on the previous:

| Phase | Capability | Status |
|---|---|---|
| **Phase 1** | Canonical serialization, SHA-256 hashing, hash chain | Complete |
| **Phase 2** | Merkle tree, Ed25519 key management, signed checkpoints | Complete |
| **Phase 3A** | Solidity `SecureLogAnchor` smart contract & Hardhat environment | Complete |
| **Phase 3B** | `BlockchainService` client using ethers.js v6 | Complete |
| **Phase 4A** | `BackendAdapter` for backend integration and error normalization | Complete |
| **Phase 4B** | End-to-end integration validation & cross-module testing | Complete |
| **Phase 5** | Adversarial security testing, performance benchmarking & demo | Complete |

---

## 1. Canonical Serialization (§1.3)

### Determinism Requirement
A cryptographic hash is only reproducible if the input bytes are identical. For structured data (JSON objects), field insertion order, whitespace, and character encoding can all vary between implementations. Without a canonical form, the same logical event will produce different hashes in Node.js, Python, and Solidity — making cross-module verification impossible.

### LOGN-HASH-v1 Field Set
```
event_id, event_time, event_type, message, metadata,
previous_hash, sequence_number, severity, source_id
```
9 fields, snake_case, exactly these names. No other fields enter the hash.

### Serialization Rules
1. Sort all top-level keys by Unicode code point (ascending)
2. Sort all `metadata` keys recursively by the same rule
3. No whitespace (no spaces, no newlines)
4. Unicode characters in string values: preserved as literal UTF-8 (NOT `\uXXXX` escaped)
5. Numbers: JSON native (integer or float); no scientific notation for integers
6. `metadata` null/absent → serialize as `{}`
7. `metadata` nesting depth > 10 → replace with string `"[DEEP_OBJECT]"`

Implementation: `security/src/crypto/canonicalJson.js`.

---

## 2. SHA-256 Hashing (§1.3.2, §1.3.6)

```
canonical_string = canonicalJson(payload)       // sorted keys, no whitespace
utf8_bytes       = Buffer.from(canonical_string, 'utf8')
event_hash       = sha256(utf8_bytes).toLowerHex()  // 64 hex chars
```

The hash is computed over the **UTF-8 encoding** of the canonical JSON string using Node.js `crypto.createHash('sha256')`.

Implementation: `security/src/crypto/hashing.js`.

---

## 3. Hash Chain (§2)

### Structure
```
Event 1:  previous_hash = GENESIS_HASH (64 zeros)
          current_hash  = hashLogEvent(event1)

Event 2:  previous_hash = event1.current_hash
          current_hash  = hashLogEvent(event2)

Event N:  previous_hash = event(N-1).current_hash
          current_hash  = hashLogEvent(eventN)
```

### Authoritative Chain (§2.1)
The authoritative chain lives in MongoDB as `Log.currentHash`. The Security module queries this field to build Merkle trees. It does not maintain a competing chain tip.

### Detection Capabilities
- **Field Value Modification**: Detected immediately via hash mismatch at tampered event.
- **Event Deletion**: Detected via sequence number gap and broken previous_hash reference.
- **Event Insertion**: Detected via sequence collision and broken chain link.
- **Event Reordering**: Detected via broken previous_hash links.

Implementation: `security/src/crypto/hashChain.js`.

---

## 4. Merkle Tree & Inclusion Proofs (§3)

### Construction Rules (Domain Tags & Bitcoin Node Pairing)
To prevent second-preimage attacks:
- **Leaf Hash (RFC 6962 Domain Tag)**: `SHA256(0x00 || raw_leaf_bytes)`
- **Internal Node (RFC 6962 Domain Tag)**: `SHA256(0x01 || left_child || right_child)`
- **Odd Number of Leaves (Bitcoin Pairing Convention)**: When a layer has an odd count, the last node is duplicated (`right = left`), per Contract §6.4.
- **Root Format**: Prefixed with `0x` + 64 hex characters (32 bytes).

### Inclusion Proofs
Enables lightweight proof that a specific log hash was included in an anchored checkpoint without revealing or downloading the entire dataset:
`verifyMerkleProof(leafHash, proof, leafIndex, expectedRoot)` recomputes the root upwards and asserts equality.

Implementation: `security/src/merkle/merkleTree.js`.

---

## 5. Ed25519 Key Management & Registry (§4)

### Cryptographic Specification
- **Algorithm**: Ed25519 (RFC 8032) via Node.js native `crypto.generateKeyPairSync('ed25519')`.
- **At-Rest Protection**: Private keys are encrypted using AES-256-GCM with a key derived from a user passphrase using `scrypt` (N=32768, r=8, p=1).
- **Filesystem Permissions**: POSIX `0600` for encrypted private key files; `0700` for the key directory.
- **Key Provenance & Rotation**: Public keys are cataloged in `public-key-registry.json` with active timestamps. Forensic verifiers require that signing keys exist in this registry and were valid at the checkpoint timestamp.

Implementation: `security/src/keys/keyManager.js`.

---

## 6. Checkpoint Service (§5)

Aggregates a contiguous sequence of logs into a signed checkpoint document conforming to §5.2:

```javascript
const checkpoint = {
  checkpoint_id: uuidv4(),
  version: "1.0",
  source_id: "node-1",
  sequence_range: { start: 1, end: 100 },
  event_count: 100,
  timestamp: 1700000000,
  merkle_root: "0x3f5c...",
  merkle_leaf_hashes: ["0x...", "0x..."],
  signature: "3a01...",
  public_key: "e04b...",
  signature_algorithm: "ed25519",
  blockchain: null
};
```

Implementation: `security/src/checkpoints/checkpointService.js`.

---

## 7. Smart Contract Anchoring (`SecureLogAnchor.sol`) (§7)

### On-Chain Interface
```solidity
interface ISecureLogAnchor {
    function anchorCheckpoint(
        bytes32 checkpointId,
        bytes32 merkleRoot,
        uint32 startSequence,
        uint32 endSequence,
        uint32 eventCount,
        uint64 timestamp
    ) external;

    function getCommitment(bytes32 checkpointId) external view returns (CheckpointCommitment memory);
    function commitmentExists(bytes32 checkpointId) external view returns (bool);
    function verifyCommitment(bytes32 checkpointId, bytes32 expectedMerkleRoot) external view returns (bool);
}
```

### Security Properties
1. **Immutability**: Once written, a checkpoint ID cannot be updated or overwritten.
2. **Access Control**: Only authorized submitters registered in the `authorizedSubmitters` mapping can broadcast commitments (`onlyAuthorized` modifier). The contract owner manages submitters via `setSubmitter()`.
3. **Sequence & Count Invariant**: Requires `endSequence >= startSequence` and `eventCount == (endSequence - startSequence + 1)`.
4. **Zero Knowledge of Logs**: No plaintext logs, messages, or metadata are ever published on-chain.

Implementation: `security/contracts/SecureLogAnchor.sol`.

---

## 8. Blockchain Client & Backend Adapter (§8)

### BlockchainService
Manages ethers.js v6 provider connections, wallet signing, transaction submission, gas estimation, receipt confirmation, and error mapping (`RpcTimeoutError`, `BlockchainError`, `IdempotencyError`).

Implementation: `security/src/blockchain/blockchainService.js`.

### BackendAdapter
Provides high-level methods tailored for backend service integration:
- `anchorCheckpointForBackend(checkpoint)`
- `getAnchoringStatus(checkpointId)`
- `getTransactionMetadata(checkpointId)`
- `verifyCheckpointOnChain(checkpoint)`
- `safeRetryAnchor(checkpoint, maxRetries, baseDelayMs)`

Implementation: `security/src/adapter/backendAdapter.js`.

---

## 9. Forensic Dual Verification Pipeline (§9)

Forensic verifiers perform two independent lines of audit:

```
[Checkpoint Document]
       │
       ├─ Off-Chain Audit ────────────► 1. Verify Ed25519 Signature
       │                               2. Verify Key Provenance in Registry
       │                               3. Recompute Merkle Root from Leaves
       │                               4. Assert Recomputed == Stored Root
       │
       └─ On-Chain Audit ─────────────► 5. Query SecureLogAnchor Smart Contract
                                       6. Assert On-Chain Root == Stored Root
                                       7. Confirm Block Number & Timestamp
```

The resulting `VerificationReport` matches §9.5, detailing exact verification status and any detected anomalies.

Implementation: `security/src/verification/verifier.js`.

---

## 10. Data Flow Architecture

```
[Client / Log Source]
        │
        ▼
[Backend logService]
  ├─ Computes canonical LOGN-HASH-v1 hash
  ├─ Links sequential hash chain (previous_hash -> current_hash)
  └─ Writes Log documents to MongoDB
        │
        ▼ (Every CHECKPOINT_INTERVAL events)
[Backend checkpoint worker]
  ├─ Calls security.createCheckpoint(logs, keyManager)
  │    ├─ Verifies hash chain
  │    ├─ Computes Merkle tree & root
  │    └─ Signs checkpoint payload with Ed25519
  │
  ├─ Calls BackendAdapter.anchorCheckpointForBackend(checkpoint)
  │    ├─ Submits anchorCheckpoint transaction to EVM
  │    ├─ Awaits receipt confirmation
  │    └─ Returns blockchain transaction metadata
  │
  └─ Updates Checkpoint in MongoDB with blockchain block/tx details
        │
        ▼
[Forensic Auditor / Evidence Verifier]
  └─ Calls BackendAdapter.verifyCheckpointOnChain(checkpoint)
       ├─ Recomputes Merkle root
       ├─ Verifies Ed25519 signature
       ├─ Verifies against on-chain smart contract
       └─ Generates immutable Forensic Audit Report
```
