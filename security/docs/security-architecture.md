# Security Module Architecture

> **HHH SecureLog — Security + Blockchain Module**
> Reference: `docs/technical-integration-contract.md` §§1–9

---

## Overview

The Security module implements the cryptographic backbone of the HHH SecureLog platform. Its responsibilities span four phases, each building on the previous:

| Phase | Capability |
|-------|-----------|
| 1 | Canonical serialization, SHA-256 hashing, hash chain |
| 2 | Merkle tree, Ed25519 key management, signed checkpoints |
| 3 | Solidity smart contract anchoring, ethers.js BlockchainService |
| 4 | End-to-end verification |

---

## 1. Canonical Serialization (§1.3)

### Why Determinism Matters

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

### Implementation

`security/src/crypto/canonicalJson.js` implements a custom serializer (not `JSON.stringify`) to avoid non-ASCII escaping. It uses `Object.keys(obj).sort()` which sorts by UTF-16 code units — equivalent to Unicode code point order for all BMP characters.

---

## 2. SHA-256 Hashing (§1.3.2, §1.3.6)

```
canonical_string = canonicalJson(payload)       // sorted keys, no whitespace
utf8_bytes       = Buffer.from(canonical_string, 'utf8')
event_hash       = sha256(utf8_bytes).toLowerHex()  // 64 hex chars
```

The hash is computed over the **UTF-8 encoding** of the canonical JSON string. Node.js `crypto.createHash('sha256').update(str, 'utf8').digest('hex')` does this correctly.

### hashLogEvent(event) → hex

```
function hashLogEvent(event):
  1. Assert all 9 fields present (throw TypeError if missing)
  2. Normalize event_time → "YYYY-MM-DDTHH:MM:SSZ" (strip ms, force UTC Z)
  3. Coerce sequence_number → Math.trunc(Number(seq))
  4. Normalize metadata: null/absent → {}; sort keys recursively
  5. Build 9-field payload
  6. canonicalJson(payload) → canonical string
  7. sha256hex(canonical string) → lowercase hex 64
```

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

The authoritative chain lives in MongoDB as `Log.currentHash`. The Security module queries this field to build Merkle trees (Phase 2). It does not maintain a competing chain tip.

### What the Chain Detects

| Tamper type | Detected? | Mechanism |
|-------------|-----------|-----------|
| Field value modification | ✅ Yes | Hash mismatch at that event |
| Event deletion | ✅ Yes | Sequence number gap + broken link |
| Event insertion | ✅ Yes | Sequence number gap + broken link |
| Event reordering | ✅ Yes | Broken previous_hash link |
| Consistent chain rebuild by attacker | ❌ No (Phase 2) | Signatures + on-chain anchoring close this gap |

### Implementation

- `buildChain(events)` — attaches `previous_hash` and `current_hash` to each event in order
- `verifyHashChain(events)` — replays and validates all links, sequence gaps, and GENESIS_HASH

---

## 4. Signed Checkpoints (Phase 2 — Design)

> Not yet implemented. Specification: §3–§5 of the integration contract.

### Checkpoint Lifecycle

```
TRIGGER (Backend) → SEQUENCE RANGE SELECTION (Backend) →
MERKLE TREE CONSTRUCTION (Security) → SIGNING (Security KeyManager) →
ON-CHAIN ANCHORING (Security → BlockchainService) →
CHECKPOINT STORAGE IN MONGODB (Security) →
EVIDENCE BUNDLE STORAGE (Storage — independent)
```

### Signed Checkpoint Schema (§5)

```json
{
  "checkpoint_id":   "<source_id>-<start_seq>-<end_seq>-<timestamp_epoch>",
  "schema_version":  "checkpoint-v1",
  "source_id":       "<string>",
  "start_sequence":  <integer>,
  "end_sequence":    <integer>,
  "event_count":     <integer>,
  "merkle_root":     "<64-char hex>",
  "timestamp":       "<ISO-8601 UTC>",
  "signing_key_id":  "<UUID v4>",
  "signature":       "<128-char hex Ed25519 signature>",
  "blockchain": {
    "tx_hash":          "<0x hex>",
    "block_number":     <integer>,
    "contract_address": "<0x hex>",
    "chain_id":         <integer>
  }
}
```

---

## 5. Merkle Tree (Phase 2 — Design)

> Not yet implemented. Specification: §6 of the integration contract.

```
Leaves:         SHA-256("leaf:" + Log.currentHash)   [one per event, in sequence order]
Internal nodes: SHA-256("node:" + leftHash + rightHash)
Odd nodes:      Duplicate the last leaf (do NOT skip)
Empty tree:     merkle_root = SHA-256("empty")
Proof format:   [ { hash: "<hex>", position: "left"|"right" }, ... ]
```

The `"leaf:"` and `"node:"` domain separation prefixes prevent second-preimage attacks.

---

## 6. Ed25519 Key Management (Phase 2 — Design)

> Not yet implemented. Specification: §4 of the integration contract.

```
Key storage:  security/keys/signing_key.enc   (AES-256-GCM encrypted, gitignored)
              security/keys/signing_key.pub   (plaintext hex, committed to Git)
              security/keys/key_id.txt        (UUID v4, committed to Git)
Passphrase:   LOGN_KEY_PASSPHRASE env var (never committed)
KDF:          scrypt (N=32768, r=8, p=1)
Signing:      Ed25519 (Node.js built-in crypto.sign / crypto.verify)
Signing input: canonicalJson(checkpoint payload WITHOUT blockchain block)
Signature:    128-char hex (64 bytes Ed25519 signature)
```

---

## 7. Blockchain Anchoring (Phase 3 — Design)

> Not yet implemented. Specification: §7–§8 of the integration contract.

### SecureLogAnchor Contract Interface (§7)

```solidity
interface ISecureLogAnchor {
  function anchorCheckpoint(
    bytes32 checkpointId,
    bytes32 merkleRoot,
    uint32  startSequence,
    uint32  endSequence,
    uint32  eventCount,
    uint64  timestamp
  ) external;

  function getCheckpoint(bytes32 checkpointId)
    external view returns (CheckpointRecord memory);

  event CheckpointAnchored(
    bytes32 indexed checkpointId,
    bytes32 indexed merkleRoot,
    address indexed submitter,
    uint32  startSequence,
    uint32  endSequence,
    uint64  timestamp
  );
}
```

Access control: only the designated `ANCHOR_ROLE` address (the Security service wallet) can anchor. Duplicate `checkpointId` → revert. No raw log data or PII stored on-chain.

### BlockchainService Interface (§8)

```js
class BlockchainService {
  async anchorCheckpoint(params)      // submits tx, waits for confirmation
  async getCheckpoint(checkpointId)   // read-only view call
  async verifyCommitment(params)      // compare on-chain vs local merkle_root
}
```

Error handling: separate `PendingError`, `RevertError`, `TimeoutError` — never swallow blockchain errors silently.

---

## 8. End-to-End Verification (Phase 4 — Design)

> Not yet implemented. Specification: §9 of the integration contract.

```
Input: checkpoint document from MongoDB

Steps:
  1. Verify Ed25519 signature over canonical(checkpoint payload WITHOUT blockchain block)
  2. Query events from MongoDB for [start_sequence, end_sequence]
  3. Assert event count == (end_sequence - start_sequence + 1)
  4. Verify hash chain: each event's current_hash matches LOGN-HASH-v1 recomputation
  5. Build Merkle tree over Log.currentHash values → compute merkle_root
  6. Assert computed merkle_root == checkpoint.merkle_root
  7. Query on-chain: BlockchainService.getCheckpoint(checkpointId)
  8. Assert on-chain merkle_root == checkpoint.merkle_root
  9. Assert on-chain timestamp within acceptable skew

Output: { valid: boolean, failures: string[], onChainRecord: {...} }
```

---

## 9. Data Flow Diagram

```
Log Event arrives at Backend
       │
       ▼
Backend logService.js
  ├─ hashLogEvent(event)        ← LOGN-HASH-v1 (this module's formula)
  ├─ Log.currentHash = hash
  └─ Source.lastHash = hash
       │
       ▼ (every CHECKPOINT_INTERVAL events, or manual trigger)
Security checkpointService.js
  ├─ Query Log[startSeq..endSeq].currentHash from MongoDB
  ├─ Verify hash chain (verifyHashChain)
  ├─ Build Merkle tree over currentHash values
  ├─ Compute merkle_root
  ├─ Sign canonical(checkpoint payload) with Ed25519
  ├─ BlockchainService.anchorCheckpoint(checkpointId, merkle_root, ...)
  └─ Write Checkpoint document to MongoDB
       │
       ▼ (independent, parallel)
Storage evidence_packager.py
  └─ Packages events into evidence bundles (separate from checkpoints)
```
