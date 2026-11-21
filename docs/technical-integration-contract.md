# HHH – SecureLog: Technical Integration Contract
## Security + Blockchain Module

> **Document status:** PROPOSED — requires team ratification before any implementation begins  
> **Branch context:** `feature-security` (read-only audit completed)  
> **Prepared by:** Security + Blockchain module owner  
> **Date:** 2026-11-20  
> **Version:** 1.0-draft

---

> [!IMPORTANT]
> This is a binding interface contract, not an implementation guide. Every section marked
> **[REQUIRES TEAM APPROVAL]** must be explicitly agreed by the named module owner(s)
> before the Security team writes or modifies any code that depends on it.
> Do not treat silence as consent.

---

## Table of Contents

1. [Canonical Log Hashing Formula](#1-canonical-log-hashing-formula)
2. [Authoritative Integrity Chain](#2-authoritative-integrity-chain)
3. [Checkpoint Ownership and Lifecycle](#3-checkpoint-ownership-and-lifecycle)
4. [Persistent Ed25519 Key Management](#4-persistent-ed25519-key-management)
5. [Versioned Checkpoint JSON Schema](#5-versioned-checkpoint-json-schema)
6. [Merkle Tree Algorithm](#6-merkle-tree-algorithm)
7. [Solidity SecureLogAnchor Contract Interface](#7-solidity-secureloganchor-contract-interface)
8. [BlockchainService Interface (ethers.js v6)](#8-blockchainservice-interface-ethersjs-v6)
9. [End-to-End Verification Algorithm](#9-end-to-end-verification-algorithm)
10. [Compatibility Table](#10-compatibility-table)
11. [Open Decisions Requiring Team Approval](#11-open-decisions-requiring-team-approval)
12. [HHH Hackathon Implementation Decisions](#12-hhh-hackathon-implementation-decisions)

---

## 1. Canonical Log Hashing Formula

### 1.1 The Conflict — Exact Code Evidence

**Backend formula** (`backend/src/utils/generateHash.js`, lines confirmed by inspection):

```js
// Field set (exact, in canonical key-sort order after sorting):
const hashPayload = {
  eventId:        String(eventId),
  message:        String(message),
  metadata:       metadata || {},
  previousHash:   String(previousHash),
  sequenceNumber: Number(sequenceNumber),
  sourceId:       String(sourceId),
  timestamp:      normalizedTimestamp,   // ISO-8601 UTC string
};
// Serialization: custom RFC-8785 subset — sort keys by UTF-16 code units, recurse arrays/objects
// No whitespace, no trailing commas
const canonicalString = canonicalize(hashPayload);  // → e.g. {"eventId":"...","message":"...",...}
return crypto.createHash('sha256').update(canonicalString, 'utf8').digest('hex');
```

**Key properties of backend's `canonicalize.js`:**
- Sorts object keys **lexicographically by UTF-16 code units** (this is `String.prototype.localeCompare` default in JS)
- Handles `Date` objects → `.toISOString()`
- Skips `undefined`, `function`, `symbol` values
- Arrays: recurse, replace `undefined` elements with the string `"null"`

---

**Storage formula** (`evidence-engine/checkpoint_manager.py`, lines confirmed by inspection):

```python
def calculate_event_hash(self, prev_hash: str, event_data: dict) -> str:
    # Strip the 'integrity' block to avoid circular dependency
    clean_event = {k: v for k, v in event_data.items() if k != "integrity"}
    payload_canonical = canonical_json(clean_event)   # json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=True)
    combined = f"{prev_hash}:{payload_canonical}"     # colon delimiter, NOT part of JSON
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()

# Field set: the ENTIRE normalized event dict (minus 'integrity')
# {schema_version, event_id, source_id, sequence_number, event_time,
#  observed_at, event_type, severity, message, metadata}
```

**Key properties of Storage's `canonical_json`:**
- Python `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True)`
- `sort_keys=True` sorts by Unicode code point (Python `str` comparison — same as lexicographic for ASCII, but behaviour diverges for multi-byte chars)
- `ensure_ascii=True` escapes all non-ASCII characters to `\uXXXX` sequences

---

### 1.2 Why the Two Formulas Are Incompatible

| Dimension | Backend | Storage |
|-----------|---------|---------|
| Field set | 7 fields: `{eventId, message, metadata, previousHash, sequenceNumber, sourceId, timestamp}` | Full event: `{schema_version, event_id, source_id, sequence_number, event_time, observed_at, event_type, severity, message, metadata}` |
| Field name conventions | camelCase (`eventId`, `sourceId`, `sequenceNumber`) | snake_case (`event_id`, `source_id`, `sequence_number`) |
| Input to hash | `canonical(fieldSet)` only | `prevHash + ":" + canonical(fullEvent)` |
| Timestamp field name | `timestamp` | `event_time` and `observed_at` (two timestamps) |
| Non-ASCII handling | Characters pass through as-is in `JSON.stringify` | Force-escaped to `\uXXXX` by `ensure_ascii=True` |
| `previousHash` position | Explicit field inside the JSON object | The `prev_hash` string concatenated outside the JSON |
| Event stripped field | Nothing stripped | Strips `integrity` sub-object |

Producing the same hash from the same event using both formulas is **impossible without adopting a single specification.**

---

### 1.3 Proposed Canonical Formula — `LOGN-HASH-v1`

**[REQUIRES TEAM APPROVAL: Backend + Storage + Security]**

The proposed formula is designed to be:
- Implementable identically in both Node.js and Python
- Backward-compatible with backend's existing `Log.currentHash` values in MongoDB (see §1.4)
- Independent of transport-layer field naming conventions

#### 1.3.1 Canonical Field Set

```
LOGN-HASH-v1 field set (exact, case-sensitive):
{
  "event_id":        <string>   // UUID v4
  "source_id":       <string>
  "sequence_number": <integer>  // non-negative, monotonically increasing per source
  "event_time":      <string>   // ISO-8601 UTC: "YYYY-MM-DDTHH:MM:SSZ" (no milliseconds, always Z)
  "event_type":      <string>   // AUTHENTICATION | AUTHORIZATION | SYSTEM | ...
  "severity":        <string>   // DEBUG | INFO | WARNING | ERROR | CRITICAL
  "message":         <string>
  "metadata":        <object>   // arbitrary key-value, see §1.3.4
  "previous_hash":   <string>   // 64-char hex SHA-256, or GENESIS_HASH for first event
}
```

No other fields are included in the hash input. `schema_version`, `observed_at`, `integrity`, `bundle_id`, and any transport-layer fields are **excluded**.

#### 1.3.2 Canonical Serialization

```
LOGN-HASH-v1 serialization:
  1. Take the field set object above
  2. Sort all top-level keys lexicographically by Unicode code point (ascending)
     Sorted order: "event_id", "event_time", "event_type", "message",
                   "metadata", "previous_hash", "sequence_number",
                   "severity", "source_id"
  3. For the "metadata" value: recursively sort all object keys the same way
  4. Serialize with:
       - No whitespace (no spaces, no newlines)
       - No trailing commas
       - Unicode characters in string values: preserved as-is in UTF-8
         (do NOT apply ensure_ascii escaping)
       - Booleans: lowercase "true" / "false"
       - Null values: "null"
       - Numbers: JSON native integer or float — no scientific notation for integers
  5. Encode the resulting string to UTF-8 bytes
  6. Compute SHA-256 of the UTF-8 bytes
  7. Encode output as lowercase hex string (64 characters)

Result type: lowercase hex string, exactly 64 characters
```

#### 1.3.3 Genesis Hash

```
GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"
               (64 zero characters, the previous_hash of the first event in a source)
```

This is consistent with both existing modules (backend `Source.lastHash` and storage `GENESIS_HASH = "0" * 64`).

#### 1.3.4 Metadata Canonicalization Rules

```
metadata field rules:
  - Keys: strings only, sort lexicographically
  - Values: string | number | boolean | null | nested object | array
  - Arrays: preserve element order (do NOT sort array elements)
  - Nested objects: sort keys recursively
  - Strip no fields — the full metadata object is included as-is
  - Maximum nesting depth: 10 levels (beyond that, truncate to string "[DEEP_OBJECT]")
  - If metadata is null or absent: serialize as {}
```

#### 1.3.5 Exact Example

Given this event:
```json
{
  "event_id":        "a1b2c3d4-0000-0000-0000-000000000001",
  "source_id":       "server-alpha",
  "sequence_number": 1,
  "event_time":      "2026-11-20T11:00:00Z",
  "event_type":      "AUTHENTICATION",
  "severity":        "INFO",
  "message":         "User login successful",
  "metadata":        {"ip": "10.0.0.1", "user": "alice"},
  "previous_hash":   "0000000000000000000000000000000000000000000000000000000000000000"
}
```

Canonical string (key sort: event_id < event_time < event_type < message < metadata < previous_hash < sequence_number < severity < source_id):
```
{"event_id":"a1b2c3d4-0000-0000-0000-000000000001","event_time":"2026-11-20T11:00:00Z","event_type":"AUTHENTICATION","message":"User login successful","metadata":{"ip":"10.0.0.1","user":"alice"},"previous_hash":"0000000000000000000000000000000000000000000000000000000000000000","sequence_number":1,"severity":"INFO","source_id":"server-alpha"}
```

SHA-256 of the UTF-8 encoding of the above string is the `event_hash` for this event.

> [!NOTE]
> The team must run this exact test vector through both the Node.js and Python implementations during integration to confirm identical output. If outputs differ, the serialization is not equivalent and must be debugged before proceeding.

#### 1.3.6 Pseudocode (Language-Agnostic)

```
function computeLogHash(event, previousHash) → hex_string:
  payload = {
    "event_id":        toString(event.event_id),
    "event_time":      toUTCISO8601NoMs(event.event_time),   // "YYYY-MM-DDTHH:MM:SSZ"
    "event_type":      toString(event.event_type),
    "message":         toString(event.message),
    "metadata":        sortKeysDeep(event.metadata ?? {}),
    "previous_hash":   toString(previousHash),
    "sequence_number": toInteger(event.sequence_number),
    "severity":        toString(event.severity),
    "source_id":       toString(event.source_id),
  }
  json_str = canonicalJSON(payload)   // sorted keys, no whitespace, UTF-8 preserved
  utf8_bytes = encodeUTF8(json_str)
  return SHA256(utf8_bytes).toLowerHex()
```

---

### 1.4 Migration / Compatibility Changes Required

#### Backend `feature-backend` — **[REQUIRES BACKEND OWNER APPROVAL]**

| File | Current state | Required change |
|------|--------------|----------------|
| `src/utils/generateHash.js` | Uses camelCase field set, no `event_type`/`severity`, includes `previousHash` as a JSON field | **Replace** `generateLogHash` with `computeLogHashV1(event, previousHash)` using the LOGN-HASH-v1 field set. The function signature changes. |
| `src/utils/canonicalize.js` | UTF-16 sort, no `ensure_ascii` | The sort order is **ASCII-equivalent** for all field names and typical metadata keys. No change needed if metadata never contains non-ASCII keys. Document this assumption explicitly. |
| `src/services/logService.js` | Calls `generateLogHash({eventId, sourceId, ...})` with camelCase destructuring | Update call site to pass snake_case field set matching the new function signature |
| `src/models/Log.js` | Schema has `currentHash` field | No schema change. Field name stays `currentHash`. The value computed will differ from today's formula. |
| `src/models/Source.js` | `lastHash` initialized to 64 zeros | No change. Genesis hash is compatible. |

> [!WARNING]
> All existing `Log.currentHash` values in MongoDB were computed with the OLD backend formula.
> Any logs ingested before this contract is adopted are **not verifiable with LOGN-HASH-v1**.
> For the hackathon: use a separate test database or versioned migration with backup — never wipe production or shared data as a default step (see §12, Decision H-05).
> For production: a migration plan (re-hash all historical events with the new formula) is required — this is out of scope here.

#### Storage `feature-storage` — **[REQUIRES STORAGE OWNER APPROVAL]**

| File | Current state | Required change |
|------|--------------|----------------|
| `evidence-engine/checkpoint_manager.py` | Uses `f"{prev_hash}:{canonical_json(clean_event)}"` with full event dict | **Replace** `calculate_event_hash` to call `compute_logn_hash_v1(event, prev_hash)` using the agreed field set. The chain tip value must now equal what backend stores in `Log.currentHash`. |
| `evidence-engine/checkpoint_manager.py` | `canonical_json` uses `ensure_ascii=True` | Change to `ensure_ascii=False` for consistent UTF-8 output. The sort order is already compatible. |
| `evidence-engine/evidence_verifier.py` | `verify_event_chain` replays with the old formula | Update to use `compute_logn_hash_v1`. All existing test vectors will need regeneration. |
| `tests/test_integrity.py` | Hardcoded expected hashes based on old formula | **Regenerate** all hash test vectors using the new formula. Test logic (tamper detection) is valid; only expected values change. |

---

## 2. Authoritative Integrity Chain

### 2.1 Decision

**[REQUIRES TEAM APPROVAL: Backend + Storage + Security]**

**The authoritative per-event integrity chain is the hash chain maintained by the Backend's `logService.js` and stored in `Log.currentHash` in MongoDB.**

Rationale:
- The backend is the **single ingest point** for all events from all sources. The chain is computed at ingest time with a source-level lock preventing race conditions.
- `Log.currentHash` is **immutable after write** (the field is not updated after creation; `Log.js` schema has no post-write logic that would change it).
- The backend already has compound uniqueness index `(sourceId, sequenceNumber)` guaranteeing no gaps or duplicates from the same source.
- The Security module's Merkle tree is built over `Log.currentHash` values — it consumes the authoritative chain, not a copy.

### 2.2 Role of Storage's Hash Chain

Storage's `checkpoint_manager.py` chain (using `H_i = SHA-256(prevHash:canonical(event))`) is **the internal chain of the evidence bundle**, used exclusively for verifying the integrity of a bundle's contents after export from the backend. It is NOT the authoritative system-of-record chain.

After adopting LOGN-HASH-v1, Storage's `calculate_event_hash` will produce the **same values** as Backend's `Log.currentHash`. This means:
- Storage's evidence bundle events will have `integrity.event_hash == Log.currentHash` for the same event
- Verification can cross-reference between the two systems
- The two chains converge to one source of truth

### 2.3 Consequences

| Consequence | Owner | Action |
|------------|-------|--------|
| Storage's `EvidenceVerifier.verify_event_chain` will now validate against `Log.currentHash` values | STORAGE | Update verifier (§1.4) |
| Security's Merkle tree leaves are `Log.currentHash` values queried from MongoDB | SECURITY | Query confirmed |
| There is exactly one `previousHash` chain tip per source, stored in `Source.lastHash` | BACKEND | No change needed |
| No module independently maintains a second chain tip for the same source | ALL | Enforce by convention |

---

## 3. Checkpoint Ownership and Lifecycle

### 3.1 Lifecycle Phases

```
Phase 1: TRIGGER
  Owner: BACKEND logService.js
  Mechanism: After ingestSingleLog or ingestLogBatch, the backend calls a
             triggerCheckpointIfDue(sourceId) helper. This checks whether
             (source.lastSequenceNumber % CHECKPOINT_INTERVAL == 0).
             CHECKPOINT_INTERVAL is an environment variable (default: 100).
  Result: HTTP POST to Security's internal API route with {sourceId, startSequence, endSequence}

Phase 2: SEQUENCE RANGE SELECTION
  Owner: BACKEND (determines the range from Source.lastSequenceNumber)
  Constraint: startSequence is the sequence AFTER the last anchored checkpoint's endSequence,
              or 1 if no checkpoint exists for this source.
              endSequence is the current Source.lastSequenceNumber.
  Result: {sourceId, startSequence, endSequence} passed to Security

Phase 3: MERKLE TREE CONSTRUCTION
  Owner: SECURITY checkpointService.js
  Input: Query MongoDB for all Log records where
         { sourceId: sourceId, sequenceNumber: { $gte: startSequence, $lte: endSequence } }
         sorted ascending by sequenceNumber (critical — sort is deterministic)
  Validation: Assert the count == (endSequence - startSequence + 1). If there are gaps, ABORT.
  Result: Ordered array of Log.currentHash values → Merkle tree → merkle_root

Phase 4: SIGNING
  Owner: SECURITY checkpointService.js
  Uses: KeyManager.sign(canonicalJSON(checkpointPayload))
  Signing input: canonical serialization of the checkpoint payload WITHOUT the blockchain block
                 (see §5 for exact schema)
  Result: Ed25519 signature (hex-encoded, 128 chars)

Phase 5: ON-CHAIN ANCHORING
  Owner: SECURITY blockchainService.js
  Submits: checkpointId (bytes32), merkle_root (bytes32), startSequence, endSequence,
           eventCount, timestamp (epoch seconds)
  Result: txHash, blockNumber, contractAddress, chainId

Phase 6: CHECKPOINT STORAGE IN MONGODB
  Owner: SECURITY checkpointService.js
  Writes: Checkpoint document (§5) to MongoDB 'checkpoints' collection
  Also updates: Log.blockchainCheckpointId for all logs in [startSequence, endSequence]

Phase 7: EVIDENCE BUNDLE STORAGE (PARALLEL, INDEPENDENT)
  Owner: STORAGE evidence_packager.py
  Timing: This runs INDEPENDENTLY of the checkpoint lifecycle — it packages events
          as they arrive at the agent level, before or during backend ingest.
  Relationship: Evidence bundles are stored in the filesystem vault. They are NOT
                the same as MongoDB checkpoints. Bundle bundle_id and checkpoint_id
                are different identifiers. The Security module does not call the
                EvidencePackager. The Storage module does not call checkpointService.
```

### 3.2 Trigger Mechanism Options — **[REQUIRES TEAM DECISION]**

Three viable trigger mechanisms. The team must select exactly one:

| Option | Description | Pros | Cons |
|--------|-------------|------|------|
| **A** (Recommended) | Backend calls internal Security route after ingest when `seq % N == 0` | Deterministic, inline with ingest | Backend codebase gains a direct dependency on Security module |
| **B** | Cron job or setInterval in a separate Security process polling MongoDB | Fully decoupled | Eventual consistency; gap if cron misses; two services need coordination |
| **C** | Manual HTTP trigger only (`POST /api/security/checkpoint`) | Simplest to implement first | Not automated; requires human operator for demos |

**For hackathon:** Option C (manual trigger) first; automate only after MVP works (see §12, Decision H-02).

### 3.3 Who Does What — Single-Row Summary

| Action | BACKEND | STORAGE | SECURITY | BLOCKCHAIN |
|--------|---------|---------|----------|------------|
| Trigger checkpoint | ✅ Initiates | — | — | — |
| Select sequence range | ✅ Provides from Source model | — | — | — |
| Query logs from MongoDB | — | — | ✅ | — |
| Build Merkle tree | — | — | ✅ | — |
| Sign checkpoint | — | — | ✅ via KeyManager | — |
| Submit to EVM | — | — | Calls → | ✅ |
| Store Checkpoint in MongoDB | — | — | ✅ | — |
| Store Evidence bundle in vault | — | ✅ | — | — |
| Write Log.blockchainCheckpointId | — | — | ✅ via updateMany | — |
| Verify on-chain commitment | — | — | ✅ calls → | ✅ reads |
| Write verificationStatus back | — | — | ✅ | — |

---

## 4. Persistent Ed25519 Key Management

### 4.1 Problem Statement

Storage's `CheckpointManager` currently calls `ed25519.Ed25519PrivateKey.generate()` in `__init__` with no persistence. Every process restart generates a new key pair. Signatures from the previous session cannot be verified because the public key is gone. This breaks forensic verifiability.

### 4.2 Key Storage Specification

**[REQUIRES SECURITY OWNER IMPLEMENTATION — no other module touches keys]**

#### Key storage location

```
security/keys/
  .gitignore           ← must list: signing_key.enc, signing_key.pub, *.enc
  signing_key.enc      ← AES-256-GCM encrypted private key (see §4.3)
  signing_key.pub      ← plaintext hex-encoded Ed25519 public key (32 bytes → 64 hex chars)
  key_id.txt           ← UUID v4 string identifying this key pair
```

> [!CAUTION]
> `security/keys/signing_key.enc` **must never be committed to Git**.
> It must be listed in `.gitignore` before the directory is created.
> For the hackathon, generate the key once locally and document the passphrase in a team password manager (e.g. a shared `.env.local` file excluded from Git).

#### File permissions (Unix)

```
security/keys/signing_key.enc  → mode 0600 (owner read/write only)
security/keys/signing_key.pub  → mode 0644 (world-readable; it is a public key)
security/keys/key_id.txt       → mode 0644
security/keys/.gitignore       → mode 0644
```

#### Environment variable

```
LOGN_KEY_PASSPHRASE=<strong random string>
```

This variable is never stored in source-controlled files. It must be injected at runtime (`.env.local` or CI/CD secret). The encrypted key file is useless without it.

### 4.3 Key File Format — `signing_key.enc`

The private key file uses a self-describing JSON envelope:

```json
{
  "schema": "logn-key-v1",
  "key_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "algorithm": "Ed25519",
  "created_at": "2026-11-20T11:00:00Z",
  "kdf": "scrypt",
  "kdf_params": {
    "N": 32768,
    "r": 8,
    "p": 1,
    "salt_hex": "<32-byte random salt, hex-encoded>"
  },
  "encryption": "AES-256-GCM",
  "iv_hex": "<12-byte random IV, hex-encoded>",
  "auth_tag_hex": "<16-byte GCM auth tag, hex-encoded>",
  "ciphertext_hex": "<encrypted 32-byte Ed25519 raw private key, hex-encoded>"
}
```

The plaintext being encrypted is the **raw 32-byte Ed25519 private key** (not PKCS8, not PEM — the raw seed bytes for Ed25519). This is the format returned by Node.js `crypto.generateKeyPairSync('ed25519').privateKey.export({type:'pkcs8',format:'der'})` — specifically the last 32 bytes of the PKCS8 DER, which are the actual seed.

### 4.4 Key ID

```
key_id: UUID v4, generated once at key creation time
        Stored in: security/keys/key_id.txt (plaintext)
                   Also embedded in signing_key.enc JSON envelope
                   Also included in every Checkpoint document as signing_key_id
                   Also emitted in the CheckpointAnchored contract event (optional)

Purpose: Allows auditors to identify which key signed a checkpoint without
         reading the private key. Enables key rotation (new key_id for new key).
```

### 4.5 Public Key Distribution

```
Channels (all are acceptable for hackathon; use at least one):

1. File:    security/keys/signing_key.pub  (committed to Git — it is a PUBLIC key)
2. MongoDB: SecurityConfig collection { key_id, public_key_hex, created_at, is_active }
3. On-chain: Optionally emit public_key_hex in CheckpointAnchored event
             (allows auditors to verify without MongoDB access)
4. README:  Document the current active key_id and public_key_hex

For key rotation: the old public key is kept in the SecurityConfig collection
(is_active: false) so that historical checkpoints signed with the old key
can still be verified.
```

### 4.6 Restart Behaviour

```
On Security service startup (pseudocode):

function loadOrGenerateKey():
  if fileExists("security/keys/signing_key.enc"):
    passphrase = env("LOGN_KEY_PASSPHRASE")
    if passphrase is empty:
      ABORT with error: "LOGN_KEY_PASSPHRASE must be set to load the signing key"
    envelope = JSON.parse(readFile("security/keys/signing_key.enc"))
    kdf_key = scrypt(passphrase, envelope.kdf_params.salt, 32)
    private_key_bytes = AES_256_GCM_decrypt(
      kdf_key, envelope.iv, envelope.ciphertext, envelope.auth_tag
    )
    public_key_hex = readFile("security/keys/signing_key.pub").trim()
    key_id = readFile("security/keys/key_id.txt").trim()
    return { private_key_bytes, public_key_hex, key_id }
  else:
    // First-time setup: generate new key pair
    passphrase = env("LOGN_KEY_PASSPHRASE")
    if passphrase is empty:
      ABORT: "Cannot generate key: LOGN_KEY_PASSPHRASE must be set"
    { private_key, public_key } = crypto.generateKeyPairSync('ed25519')
    key_id = uuidv4()
    // Encrypt and persist ...
    // Write signing_key.pub, key_id.txt
    LOG "New Ed25519 key pair generated. key_id=" + key_id
    LOG "BACK UP security/keys/signing_key.enc IMMEDIATELY"
    return { private_key_bytes, public_key_hex, key_id }
```

### 4.7 Key Rotation Protocol

```
Rotation steps (manual, by Security owner):
1. Rename security/keys/signing_key.enc → security/keys/signing_key.enc.YYYYMMDD.bak
2. Rename security/keys/signing_key.pub → security/keys/signing_key_OLD_<key_id>.pub
3. Mark old key in MongoDB SecurityConfig as { is_active: false }
4. Set a new LOGN_KEY_PASSPHRASE (or reuse — the encryption envelope is new regardless)
5. Restart Security service → new key pair generated automatically
6. Register new public key in MongoDB SecurityConfig
7. Historical checkpoints signed with old key remain verifiable using the
   archived signing_key_OLD_<key_id>.pub file

[HACKATHON NOTE]: Key rotation is out of scope for the demo.
                  Document the rotation procedure but do not implement it.
```

### 4.8 Backup

```
Minimum backup requirement (hackathon):
  Copy security/keys/signing_key.enc to a team-shared secure location
  (encrypted drive, password manager attachment, or team secret manager).

Without this backup: if the key file is lost, all historical checkpoint
signatures become unverifiable. The on-chain Merkle roots remain anchored,
but Ed25519 signature verification will fail.
```

### 4.9 Storage Module — Required Change

**[REQUIRES STORAGE OWNER APPROVAL]**

Storage's `CheckpointManager` must be changed to accept an **externally injected** key pair rather than generating one internally:

```python
# CURRENT (must change):
def __init__(self, signing_key=None, initial_hash=GENESIS_HASH):
    self._private_key = signing_key or ed25519.Ed25519PrivateKey.generate()  # ← ephemeral

# PROPOSED:
def __init__(self, signing_key: ed25519.Ed25519PrivateKey, initial_hash=GENESIS_HASH):
    if signing_key is None:
        raise ValueError("signing_key must be provided explicitly. "
                         "Use KeyLoader to load from the persistent key file.")
    self._private_key = signing_key
```

The Storage module then uses a `KeyLoader` utility (to be agreed — either Security provides a shared Python key loader, or Storage loads the key from the same `signing_key.enc` file using their own Python implementation of AES-256-GCM + scrypt).

**Decision required:** Does Security provide a Python `key_loader.py` for Storage to import, or does Storage independently load keys using their own code reading the same encrypted file format?

---

## 5. Versioned Checkpoint JSON Schema

### 5.1 Schema Version Identifier

```
schema_version: "logn-checkpoint-v1"
```

This version string MUST be included in the canonical serialization for signature verification, so it cannot be silently bumped without invalidating all existing signatures.

### 5.2 Full Checkpoint JSON Schema

```json
{
  "schema_version": "logn-checkpoint-v1",
  "checkpoint_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "source_id": "server-alpha",
  "start_sequence": 1,
  "end_sequence": 100,
  "event_count": 100,
  "merkle_root": "a3f8...c291",
  "merkle_leaf_hashes": [
    "e3b0c44298fc1c149afb...",
    "2cf24dba5fb0a30e26e8..."
  ],
  "timestamp": "2026-11-20T11:00:00Z",
  "signing_key_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "signer_public_key": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
  "signature": "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
  "signature_algorithm": "Ed25519",
  "signature_input": "logn-checkpoint-v1",
  "blockchain": {
    "contract_address": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
    "tx_hash": "0xabc123...",
    "block_number": 42,
    "chain_id": 31337,
    "anchored_at": "2026-11-20T11:00:05Z"
  }
}
```

#### Field Definitions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `schema_version` | string | ✅ | Always `"logn-checkpoint-v1"` |
| `checkpoint_id` | string (UUID v4) | ✅ | Unique checkpoint identifier. Deterministically converted to `bytes32` for the contract via `keccak256(abi.encodePacked(checkpoint_id_utf8_bytes))` |
| `source_id` | string | ✅ | The log source this checkpoint covers |
| `start_sequence` | integer (≥ 1) | ✅ | First sequence number covered (inclusive) |
| `end_sequence` | integer (≥ start) | ✅ | Last sequence number covered (inclusive) |
| `event_count` | integer | ✅ | Must equal `end_sequence - start_sequence + 1` |
| `merkle_root` | string (hex-64) | ✅ | SHA-256 Merkle root over leaf hashes (§6) |
| `merkle_leaf_hashes` | array of hex-64 strings | ✅ in MongoDB | The ordered `Log.currentHash` values used as Merkle inputs. Stored in MongoDB only — never on-chain. |
| `timestamp` | string (ISO-8601 UTC) | ✅ | Checkpoint creation time: `"YYYY-MM-DDTHH:MM:SSZ"` |
| `signing_key_id` | string (UUID v4) | ✅ | Identifies which key pair produced the signature |
| `signer_public_key` | string (hex-64) | ✅ | Ed25519 public key, raw 32 bytes hex-encoded |
| `signature` | string (hex-128) | ✅ | Ed25519 signature of the canonical signing payload (§5.3) |
| `signature_algorithm` | string | ✅ | Always `"Ed25519"` |
| `signature_input` | string | ✅ | Always `"logn-checkpoint-v1"` (documents what was signed) |
| `blockchain` | object | ⬜ | Null/absent before anchoring; set after `anchorCheckpoint` returns. |
| `blockchain.contract_address` | string (EIP-55) | ✅ after anchor | Checksummed address |
| `blockchain.tx_hash` | string (hex-66) | ✅ after anchor | `0x`-prefixed 32-byte tx hash |
| `blockchain.block_number` | integer | ✅ after anchor | EVM block number |
| `blockchain.chain_id` | integer | ✅ after anchor | EIP-155 chain ID (31337 for Hardhat local) |
| `blockchain.anchored_at` | string (ISO-8601 UTC) | ✅ after anchor | Wall-clock time of tx receipt |

### 5.3 Canonical Signing Payload

The Ed25519 signature is computed over a **specific canonical serialization** of the checkpoint, excluding the `blockchain` block and the `signature` field itself.

```
Signing payload construction:
  1. Take the checkpoint object
  2. Exclude these top-level keys: "signature", "blockchain"
  3. All other fields are included as-is (including "merkle_leaf_hashes")
  4. Apply canonical JSON serialization:
       - Sort all keys lexicographically by Unicode code point
       - No whitespace, no trailing commas
       - UTF-8 preserved (no ensure_ascii escaping)
  5. Encode to UTF-8 bytes
  6. Sign with Ed25519 private key (the Ed25519 sign operation on raw bytes)
  7. Encode output signature as lowercase hex (128 chars = 64 bytes)

Verification reverses this: reconstruct the payload from stored checkpoint fields,
re-serialize canonically, verify signature against stored signer_public_key.
```

**Exact signing payload field order after key sort:**

```
checkpoint_id < event_count < merkle_leaf_hashes < merkle_root < schema_version
< signature_algorithm < signature_input < signing_key_id < signer_public_key
< source_id < start_sequence < end_sequence < timestamp
```

### 5.4 MongoDB Collection Definition

Collection name: `checkpoints`

```js
// Mongoose schema (pseudocode — not implementation, just field specification)
{
  checkpointId:        String, unique, required, indexed
  schemaVersion:       String, required, default: "logn-checkpoint-v1"
  sourceId:            String, required, indexed
  startSequence:       Number, required
  endSequence:         Number, required
  eventCount:          Number, required
  merkleRoot:          String, required             // hex-64
  merkleLeafHashes:    [String], required           // array of hex-64
  timestamp:           String, required             // ISO-8601 UTC
  signingKeyId:        String, required
  signerPublicKey:     String, required             // hex-64
  signature:           String, required             // hex-128
  signatureAlgorithm:  String, required, default: "Ed25519"
  blockchain: {
    contractAddress:   String, default: null
    txHash:            String, default: null, indexed
    blockNumber:       Number, default: null
    chainId:           Number, default: null
    anchoredAt:        String, default: null
  },
  verificationStatus:  String, enum: [PENDING, ANCHORED, VERIFIED, FAILED], default: PENDING
  createdAt:           Date (auto)
  updatedAt:           Date (auto)
}

// Compound indexes:
{ sourceId: 1, startSequence: 1, endSequence: 1 }  // unique range per source
{ verificationStatus: 1, createdAt: -1 }             // status queries
```

---

## 6. Merkle Tree Algorithm

### 6.1 Overview

```
Input:   Ordered array of Log.currentHash values for a checkpoint window
         [h_0, h_1, h_2, ..., h_{n-1}]
         where h_i = Log.currentHash of the log with sequenceNumber = startSequence + i
         (sorted ascending by sequenceNumber — this is the ONLY valid ordering)

Output:  merkle_root (hex-64 SHA-256)
         proof[i]: array of {sibling_hash: hex-64, position: "left"|"right"}
```

### 6.2 Leaf Encoding — Domain Separation

Raw leaf hashes must be domain-separated from internal nodes to prevent **second-preimage attacks** (where an internal node could be mistaken for a leaf).

```
Leaf node:     SHA-256( 0x00 || hex_to_bytes(currentHash) )
Internal node: SHA-256( 0x01 || hex_to_bytes(leftChild) || hex_to_bytes(rightChild) )

Where:
  0x00 = single byte with value 0  (leaf domain tag)
  0x01 = single byte with value 1  (internal node domain tag)
  hex_to_bytes(h) = convert 64-char hex string to 32-byte big-endian bytes
  || = byte concatenation
  Result: SHA-256 produces 32 bytes → encode as 64-char lowercase hex
```

### 6.3 Tree Construction Algorithm

```
function buildMerkleTree(currentHashes: string[]) → { root: string, layers: string[][] }:

  if currentHashes is empty:
    return { root: EMPTY_TREE_ROOT, layers: [] }
    // EMPTY_TREE_ROOT = SHA-256(0x00) = "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"

  leaves = currentHashes.map(h => leafHash(h))
  // leafHash(h) = SHA256_hex(concat(0x00, hexToBytes(h)))

  layers = [leaves]
  currentLayer = leaves

  while currentLayer.length > 1:
    nextLayer = []
    i = 0
    while i < currentLayer.length:
      left = currentLayer[i]
      if i + 1 < currentLayer.length:
        right = currentLayer[i + 1]
      else:
        right = currentLayer[i]      // ODD NODE RULE: duplicate the last node
      nextLayer.append(internalHash(left, right))
      // internalHash(l, r) = SHA256_hex(concat(0x01, hexToBytes(l), hexToBytes(r)))
      i += 2
    layers.append(nextLayer)
    currentLayer = nextLayer

  return { root: currentLayer[0], layers: layers }
```

### 6.4 Odd-Node Handling

```
When a tree level has an odd number of nodes:
  The last node is DUPLICATED (paired with itself) to form an internal node.

Example (3 leaves: A, B, C):
  Level 0 (leaves): [A, B, C]
  Level 1:          [H(A,B), H(C,C)]   ← C duplicated
  Level 2 (root):   [H(H(A,B), H(C,C))]

This is the Bitcoin Merkle tree convention. It is deterministic and reproducible.
```

### 6.5 Empty Tree Behaviour

```
If the checkpoint window has zero events (should never happen in production — checkpoint
trigger must guard against this, but handle defensively):

  merkle_root = SHA256_hex(0x00)
             = "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"

This sentinel value must NOT be submitted to the smart contract (the contract
rejects merkle_root == bytes32(0); this sentinel is non-zero so it would not be
caught by that check — the trigger layer must reject empty windows before
calling checkpointService.createCheckpoint()).
```

### 6.6 Proof Format

```json
{
  "leaf_index": 2,
  "leaf_hash": "...",
  "proof": [
    { "sibling_hash": "abc...123", "position": "left"  },
    { "sibling_hash": "def...456", "position": "right" }
  ],
  "root": "..."
}
```

**Proof verification pseudocode:**

```
function verifyMerkleProof(leaf_currentHash, proof, expected_root) → boolean:
  current = leafHash(leaf_currentHash)
  for step in proof:
    if step.position == "left":
      current = internalHash(step.sibling_hash, current)
    else:  // "right"
      current = internalHash(current, step.sibling_hash)
  return current == expected_root
```

### 6.7 Test Vectors

**Two-leaf example:**

```
Input currentHashes:
  h_0 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  (SHA-256 of empty string)
  h_1 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"  (SHA-256 of "hello")

Leaf nodes:
  L_0 = SHA-256( 0x00 || bytes(h_0) )
  L_1 = SHA-256( 0x00 || bytes(h_1) )

Root:
  ROOT = SHA-256( 0x01 || bytes(L_0) || bytes(L_1) )

Expected values: [teams compute and record during integration test]
Both Node.js and Python implementations MUST produce identical ROOT value.
```

> [!IMPORTANT]
> The team MUST run the two-leaf test vector through both Node.js (`security/src/merkle/merkleTree.js`) and Python (if Storage implements Merkle verification) during integration. Record the expected values as a shared constant in both codebases.

### 6.8 Proof Storage

Merkle proofs for all leaves are stored in MongoDB in the `checkpoints` collection or a linked `merkle_proofs` collection. Per §12 Decision H-08, proof storage is included in the MVP scope.

---

## 7. Solidity SecureLogAnchor Contract Interface

### 7.1 Design Principles

- **Minimal on-chain state.** Only the commitment is stored. No log content, no PII, no private keys.
- **Immutable anchors.** A checkpoint_id can be anchored exactly once; updates are not permitted.
- **Access-controlled writes.** Only authorized submitter addresses may call `anchorCheckpoint`.
- **World-readable reads.** `getCommitment` has no access restriction — any external auditor can verify.
- **Self-describing events.** The `CheckpointAnchored` event contains all fields an auditor needs to independently verify — no additional API call required.

### 7.2 On-Chain Data — Exact Fields

```
On-chain per commitment (storage slots):
  bytes32  checkpointId   // keccak256(abi.encodePacked(uuid_string_as_bytes))
  bytes32  merkleRoot     // 32 bytes = 1 storage slot
  uint64   startSequence  // packed with endSequence in 1 slot
  uint64   endSequence    //
  uint32   eventCount     // packed
  uint64   timestamp      // Unix epoch seconds (packed)
  address  submitter      // msg.sender at anchor time (20 bytes, 1 slot)
  uint256  blockNumber    // 1 slot
  bool     exists         // 1 byte, packed with submitter

Total: approximately 5–6 storage slots = ~160–200 bytes on-chain per checkpoint.
Gas estimate at current Hardhat defaults: ~100,000–130,000 gas per anchor call.
```

**Never on-chain:**
- Raw log messages or metadata
- Personally identifiable information
- Private keys or passwords
- Ed25519 signatures (too expensive; off-chain is sufficient)
- Individual event hashes (too voluminous)
- Evidence bundle contents

### 7.3 Contract Interface (ABI-Level)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ISecureLogAnchor {

    // ─── Data Structures ─────────────────────────────────────────────────────

    struct Commitment {
        bytes32  merkleRoot;
        uint64   startSequence;
        uint64   endSequence;
        uint32   eventCount;
        uint64   timestamp;         // Unix epoch seconds
        address  submitter;
        uint256  blockNumber;
        bool     exists;
    }

    // ─── Events ───────────────────────────────────────────────────────────────

    /// @notice Emitted when a checkpoint is successfully anchored on-chain.
    /// @dev    Indexed fields allow efficient off-chain log filtering.
    event CheckpointAnchored(
        bytes32 indexed checkpointId,
        bytes32 indexed merkleRoot,
        uint64          startSequence,
        uint64          endSequence,
        uint32          eventCount,
        address indexed submitter,
        uint256         blockNumber,
        uint64          timestamp
    );

    /// @notice Emitted when an authorized submitter is added or removed.
    event SubmitterUpdated(address indexed submitter, bool authorized);

    // ─── Write Functions ──────────────────────────────────────────────────────

    /// @notice Anchor a checkpoint commitment on-chain.
    /// @param  checkpointId   keccak256 of the UTF-8 checkpoint UUID string
    /// @param  merkleRoot     Merkle root over Log.currentHash leaves (§6)
    /// @param  startSequence  First sequence number in the checkpoint window
    /// @param  endSequence    Last sequence number in the checkpoint window
    /// @param  eventCount     Number of log events covered
    /// @param  timestamp      Unix epoch seconds of checkpoint creation
    /// @dev    Reverts if:
    ///           - caller is not authorized
    ///           - checkpointId already anchored (immutability)
    ///           - merkleRoot is bytes32(0)
    ///           - endSequence < startSequence
    function anchorCheckpoint(
        bytes32 checkpointId,
        bytes32 merkleRoot,
        uint64  startSequence,
        uint64  endSequence,
        uint32  eventCount,
        uint64  timestamp
    ) external;

    /// @notice Grant or revoke checkpoint submission rights.
    /// @dev    Only callable by contract owner.
    function setSubmitter(address submitter, bool authorized) external;

    // ─── Read Functions ───────────────────────────────────────────────────────

    /// @notice Retrieve a stored commitment. Reverts if not found.
    function getCommitment(bytes32 checkpointId)
        external view returns (Commitment memory);

    /// @notice Check whether a checkpointId has been anchored.
    function commitmentExists(bytes32 checkpointId)
        external view returns (bool);

    /// @notice Verify a merkleRoot matches the on-chain stored value.
    /// @return match True if the commitment exists and roots match.
    function verifyCommitment(bytes32 checkpointId, bytes32 expectedMerkleRoot)
        external view returns (bool match);

    /// @notice Total number of anchored checkpoints.
    function getTotalCheckpoints() external view returns (uint256);

    /// @notice Paginated checkpoint ID listing (for auditor enumeration).
    function getCheckpointIds(uint256 offset, uint256 limit)
        external view returns (bytes32[] memory);

    /// @notice Contract owner address.
    function owner() external view returns (address);

    /// @notice Check whether an address is an authorized submitter.
    function authorizedSubmitters(address submitter) external view returns (bool);
}
```

### 7.4 Access Control Model

```
Roles:
  owner          — The deploying address. Can add/remove authorized submitters.
                   For hackathon: the Hardhat default account #0.
  authorized     — Can call anchorCheckpoint(). Set by owner.
                   For hackathon: account #0 (owner) and/or a dedicated
                   Hardhat account #1 (the Security service wallet).
  public         — Can call all view/pure functions.

Threat model assumption:
  The contract owner is the Security module operator.
  If the Security service wallet is compromised, an attacker can anchor
  false commitments. The on-chain record is immutable — false anchors
  cannot be deleted. This is a known limitation.
  Mitigation: use a hardware wallet for the owner key in production.
  For hackathon: document this clearly in the demo README.
```

### 7.5 Chain and Network Identifiers

```
Development (hackathon):
  network_name: "hardhat"
  chain_id:     31337
  rpc_url:      http://127.0.0.1:8545

For demo persistence across terminal sessions:
  Run: npx hardhat node   (spawns persistent daemon)
  Then: npx hardhat run scripts/deploy.js --network localhost
  Contract address: persisted in security/deployments/localhost.json

For a public testnet (optional, not required for hackathon):
  network_name: "sepolia"
  chain_id:     11155111
  rpc_url:      infura/alchemy endpoint (from .env, never committed)
```

### 7.6 `checkpointId` Conversion

The MongoDB `checkpoint_id` is a UUID v4 string (e.g. `"f47ac10b-58cc-4372-a567-0e02b2c3d479"`). The Solidity contract uses `bytes32`. The conversion:

```
// Node.js (ethers.js v6):
const checkpointIdBytes32 = ethers.keccak256(ethers.toUtf8Bytes(checkpointId))
// This produces a deterministic bytes32 from the UUID string.
// Record this in the Checkpoint document as: checkpoint.onChainId = checkpointIdBytes32

// Reverse lookup is NOT needed: the contract emits checkpointId in events,
// and we query MongoDB by the UUID string directly.
```

---

## 8. BlockchainService Interface (ethers.js v6)

### 8.1 Configuration

```js
// Injected via environment variables — never hardcoded:
LOGN_RPC_URL=http://127.0.0.1:8545
LOGN_CHAIN_ID=31337
LOGN_CONTRACT_ADDRESS=0x5FbDB2315678afecb367f032d93F642f64180aa3  // from deployment
LOGN_SUBMITTER_PRIVATE_KEY=0x...   // Hardhat account private key — NEVER committed to Git
```

### 8.2 BlockchainService Class Interface

```js
/**
 * BlockchainService
 * Encapsulates all EVM interactions for the Security module.
 * Owns: provider, signer wallet, contract instance.
 */
class BlockchainService {

  constructor(config: {
    rpcUrl:          string,
    chainId:         number,
    contractAddress: string,
    submitterKey:    string,    // hex private key (from env)
  })

  // ─── Lifecycle ─────────────────────────────────────────────────────────────

  /**
   * Verify network connectivity and chain ID match.
   * Call once at service startup before accepting any requests.
   * Throws if RPC is unreachable or chain ID does not match config.
   */
  async init(): Promise<void>

  // ─── Write Operations ───────────────────────────────────────────────────────

  /**
   * Anchor a checkpoint commitment on-chain.
   *
   * @param params.checkpointId   UUID v4 string (converted internally to bytes32 via keccak256)
   * @param params.merkleRoot     64-char hex string (converted to bytes32)
   * @param params.startSequence  integer
   * @param params.endSequence    integer
   * @param params.eventCount     integer
   * @param params.timestamp      ISO-8601 UTC string (converted to Unix epoch seconds)
   *
   * @returns AnchorResult on success
   * @throws  BlockchainError with code REVERT | TIMEOUT | NETWORK | DUPLICATE
   */
  async anchorCheckpoint(params: AnchorParams): Promise<AnchorResult>

  // ─── Read Operations ────────────────────────────────────────────────────────

  /**
   * Retrieve a stored commitment from the contract.
   * @throws BlockchainError with code NOT_FOUND if commitment does not exist.
   */
  async getCommitment(checkpointId: string): Promise<CommitmentResult>

  /**
   * Verify an expected merkle root against the on-chain stored value.
   * Does NOT throw on mismatch — returns match: false.
   */
  async verifyOnChain(checkpointId: string, expectedMerkleRoot: string): Promise<OnChainVerifyResult>

  /**
   * Return total number of anchored checkpoints.
   */
  async getTotalCheckpoints(): Promise<number>

  /**
   * Enumerate checkpointIds (bytes32) with pagination. For auditor tools.
   */
  async listCheckpointIds(offset: number, limit: number): Promise<string[]>
}
```

### 8.3 Return Types

```typescript
interface AnchorResult {
  txHash:          string;    // "0x..." 66 chars
  blockNumber:     number;
  contractAddress: string;    // EIP-55 checksummed
  chainId:         number;
  anchoredAt:      string;    // ISO-8601 UTC of tx receipt timestamp
  gasUsed:         string;    // bigint as string (ethers v6 uses bigint)
}

interface CommitmentResult {
  merkleRoot:     string;     // hex-64
  startSequence:  number;
  endSequence:    number;
  eventCount:     number;
  timestamp:      number;     // Unix epoch seconds
  submitter:      string;     // EIP-55 address
  blockNumber:    number;
  exists:         boolean;
}

interface OnChainVerifyResult {
  match:          boolean;
  onChainRoot:    string | null;
  txHash:         string | null;    // txHash from stored CheckpointAnchored event (if available)
  blockNumber:    number | null;
}
```

### 8.4 Error Handling — All Transaction States

```typescript
enum BlockchainErrorCode {
  REVERT    = "REVERT",    // Contract reverted (duplicate, unauthorized, bad input)
  TIMEOUT   = "TIMEOUT",   // Tx submitted but not confirmed within timeout window
  NETWORK   = "NETWORK",   // RPC unreachable or JSON-RPC error
  DUPLICATE = "DUPLICATE", // Specific revert: checkpoint already anchored
  NOT_FOUND = "NOT_FOUND", // getCommitment called for non-existent checkpoint
  CHAIN_ID  = "CHAIN_ID",  // Connected network does not match configured chain_id
}

class BlockchainError extends Error {
  code:    BlockchainErrorCode;
  txHash?: string;    // set if tx was submitted before failure
  cause?:  Error;     // original ethers.js error
}
```

**Transaction lifecycle handling:**

```
anchorCheckpoint flow:

  1. Build transaction:
       const tx = await contract.anchorCheckpoint(
         checkpointIdBytes32, merkleRootBytes32,
         startSeq, endSeq, eventCount, timestampEpoch
       )
       // Returns TransactionResponse immediately (tx submitted to mempool)

  2. PENDING state:
       // Record tx.hash in MongoDB Checkpoint.blockchain.txHash immediately
       // Mark Checkpoint.verificationStatus = "PENDING"
       // If service crashes here, the tx may still confirm on-chain

  3. CONFIRMING:
       const receipt = await tx.wait(1)   // wait for 1 confirmation
       // timeout: 60 seconds (configurable via LOGN_TX_TIMEOUT_SECONDS env var)

  4a. SUCCESS (receipt.status === 1):
        return AnchorResult from receipt fields
        Update MongoDB Checkpoint with blockNumber, anchoredAt, verificationStatus = "ANCHORED"

  4b. REVERT (receipt.status === 0):
        // Tx confirmed but execution reverted
        // Parse error from receipt logs if possible
        // Check if it is a DUPLICATE error (re-query contract.commitmentExists())
        throw BlockchainError { code: REVERT | DUPLICATE, txHash: receipt.hash }
        // The tx hash is still recorded — the failed tx is evidence

  4c. TIMEOUT (tx.wait() throws after timeout):
        // Tx may still be in mempool
        // Record txHash in MongoDB; set a background retry check
        throw BlockchainError { code: TIMEOUT, txHash: tx.hash }

  4d. NETWORK error (RPC call fails before tx submission):
        throw BlockchainError { code: NETWORK }
        // No txHash available; retry anchor is safe (idempotent check: commitmentExists)

RETRY SAFETY:
  Before retrying an anchor, always call contract.commitmentExists(checkpointIdBytes32).
  If true: the tx confirmed silently. Update MongoDB and return success.
  If false: safe to re-submit.
```

### 8.5 `LOGN_SUBMITTER_PRIVATE_KEY` Security

```
This key signs EVM transactions. If compromised, an attacker can:
  - Anchor false commitments (immutable on-chain)
  - Exhaust the wallet's ETH balance (DoS on anchoring)

For hackathon:
  - Use a Hardhat local account (funded automatically, no real value)
  - Load from LOGN_SUBMITTER_PRIVATE_KEY environment variable
  - Never commit to Git (add to .gitignore and .env.example)

This is a DIFFERENT key from the Ed25519 signing key (§4).
Two separate key materials, two separate purposes.
```

---

## 9. End-to-End Verification Algorithm

### 9.1 Verification Request

```
GET /api/security/checkpoint/verify/:checkpointId

Auth: JWT Bearer (any authenticated role — auditor, security_analyst, admin)
Response: VerificationReport (§9.5)
```

### 9.2 Full Verification Pseudocode

```
function verifyCheckpoint(checkpointId: string) → VerificationReport:

  // ─── Step 1: Load checkpoint from MongoDB ────────────────────────────────
  checkpoint = Checkpoint.findOne({ checkpointId })
  if checkpoint is null:
    return VerificationReport { overallValid: false, error: "CHECKPOINT_NOT_FOUND" }

  // ─── Step 2: Load logs from MongoDB ──────────────────────────────────────
  logs = Log.find({
    sourceId: checkpoint.sourceId,
    sequenceNumber: { $gte: checkpoint.startSequence, $lte: checkpoint.endSequence }
  }).sort({ sequenceNumber: 1 })

  if logs.length != checkpoint.eventCount:
    report.gapError = {
      expected: checkpoint.eventCount,
      found: logs.length,
      message: "Log count mismatch — possible deletion or insertion"
    }
    report.merkleRootMatch = false
    // Continue to check remaining fields anyway

  // ─── Step 3: Recompute Merkle root ───────────────────────────────────────
  leafHashes = logs.map(log => log.currentHash)
  recomputedRoot = buildMerkleTree(leafHashes).root

  report.merkleRootMatch = (recomputedRoot == checkpoint.merkleRoot)
  report.recomputedRoot = recomputedRoot
  report.storedRoot = checkpoint.merkleRoot

  // ─── Step 4: Verify Ed25519 signature ────────────────────────────────────
  // Reconstruct the exact payload that was signed (§5.3)
  signingPayload = {
    schema_version:       checkpoint.schemaVersion,
    checkpoint_id:        checkpoint.checkpointId,
    source_id:            checkpoint.sourceId,
    start_sequence:       checkpoint.startSequence,
    end_sequence:         checkpoint.endSequence,
    event_count:          checkpoint.eventCount,
    merkle_root:          checkpoint.merkleRoot,
    merkle_leaf_hashes:   checkpoint.merkleLeafHashes,
    timestamp:            checkpoint.timestamp,
    signing_key_id:       checkpoint.signingKeyId,
    signer_public_key:    checkpoint.signerPublicKey,
    signature_algorithm:  checkpoint.signatureAlgorithm,
    signature_input:      checkpoint.signatureInput,
    // "signature" and "blockchain" are EXCLUDED
  }
  payloadBytes = UTF8_encode(canonicalJSON(signingPayload))

  report.signatureValid = Ed25519.verify(
    public_key = hexToBytes(checkpoint.signerPublicKey),
    signature  = hexToBytes(checkpoint.signature),
    message    = payloadBytes
  )

  // ─── Step 5: Cross-reference public key ──────────────────────────────────
  // Verify the public key in the checkpoint matches the registered key_id
  registeredKey = SecurityConfig.findOne({ keyId: checkpoint.signingKeyId })
  if registeredKey is null:
    report.keyRegistered = false
    report.keyWarning = "signing_key_id not found in SecurityConfig — unknown signer"
  else:
    report.keyRegistered = true
    report.keyActive = registeredKey.isActive
    report.keyMismatch = (registeredKey.publicKeyHex != checkpoint.signerPublicKey)

  // ─── Step 6: Verify on-chain commitment ──────────────────────────────────
  if checkpoint.blockchain is null or checkpoint.blockchain.txHash is null:
    report.onChainStatus = "NOT_ANCHORED"
    report.onChainMatch = false
  else:
    try:
      onChainResult = blockchainService.verifyOnChain(
        checkpoint.checkpointId,
        checkpoint.merkleRoot
      )
      report.onChainMatch = onChainResult.match
      report.onChainRoot = onChainResult.onChainRoot
      report.onChainBlockNumber = onChainResult.blockNumber
      report.onChainTxHash = checkpoint.blockchain.txHash
      report.onChainStatus = onChainResult.match ? "MATCH" : "MISMATCH"
    catch BlockchainError as e:
      report.onChainStatus = "ERROR"
      report.onChainError = e.code
      report.onChainMatch = false

  // ─── Step 7: Determine overall validity ──────────────────────────────────
  report.overallValid = (
    report.merkleRootMatch == true AND
    report.signatureValid == true AND
    report.onChainMatch == true AND
    report.keyMismatch != true AND
    logs.length == checkpoint.eventCount
  )

  // ─── Step 8: Write verification status back to MongoDB ───────────────────
  newStatus = report.overallValid ? "VERIFIED" : "FAILED"

  // Update checkpoint document
  Checkpoint.updateOne(
    { checkpointId },
    { verificationStatus: newStatus, lastVerifiedAt: now() }
  )

  // Update all log documents in the window
  Log.updateMany(
    {
      sourceId: checkpoint.sourceId,
      sequenceNumber: { $gte: checkpoint.startSequence, $lte: checkpoint.endSequence }
    },
    { verificationStatus: report.overallValid ? "VERIFIED" : "TAMPERED" }
  )

  return report
```

### 9.3 Hash Chain Replay (Optional — Deep Verification)

```
When query param ?deep=true is passed:

  For each log in [startSequence, endSequence] sorted ascending:
    expected = computeLogHashV1(log, previousHash)
    actual   = log.currentHash
    if expected != actual:
      report.chainBreaks.push({
        sequenceNumber: log.sequenceNumber,
        expected,
        actual,
        message: "Stored currentHash does not match recomputed LOGN-HASH-v1"
      })
    previousHash = log.currentHash

  report.chainReplayValid = (report.chainBreaks.length == 0)
  report.overallValid = report.overallValid AND report.chainReplayValid

NOTE: Deep verification is expensive (O(n) hash computations) and not suitable
for large windows on every request. Use for forensic investigation only.
```

### 9.4 What Verification Proves and Does Not Prove

| Claim | What verification proves |
|-------|-------------------------|
| ✅ The logs in MongoDB have not been modified since the checkpoint was created | Recomputed Merkle root matches stored and on-chain root |
| ✅ The checkpoint was signed by the holder of the registered Ed25519 key | Signature valid against stored public key |
| ✅ A commitment with this Merkle root was anchored at this block number | On-chain root match |
| ✅ No logs were deleted from the window | Log count matches event_count |
| ❌ The events described in the logs actually occurred | Cannot be proved cryptographically |
| ❌ The system operator did not fabricate events before anchoring | Out of scope — insider threat |
| ❌ The checkpoint is admissible as legal evidence | Legal admissibility depends on jurisdiction, chain of custody documentation, and court acceptance |
| ❌ The blockchain is immutable in absolute terms | The on-chain commitment is immutable on a local Hardhat chain only during the demo session. A real public chain provides far stronger guarantees. |

### 9.5 Verification Report JSON Schema

```json
{
  "checkpointId": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "sourceId": "server-alpha",
  "sequenceRange": { "start": 1, "end": 100 },
  "eventCount": { "expected": 100, "found": 100 },
  "merkleRootMatch": true,
  "recomputedRoot": "a3f8...c291",
  "storedRoot": "a3f8...c291",
  "signatureValid": true,
  "signingKeyId": "f47ac10b-...",
  "keyRegistered": true,
  "keyActive": true,
  "keyMismatch": false,
  "onChainStatus": "MATCH",
  "onChainMatch": true,
  "onChainRoot": "a3f8...c291",
  "onChainBlockNumber": 42,
  "onChainTxHash": "0xabc123...",
  "chainReplayValid": null,
  "chainBreaks": [],
  "logsUpdated": 100,
  "overallValid": true,
  "verifiedAt": "2026-11-20T11:05:00Z",
  "errors": [],
  "warnings": []
}
```

---

## 10. Compatibility Table

> [!NOTE]
> "Confirmed existing code" means the file was directly read during the audit.
> "Proposed change" means the Security module proposes this modification; it requires
> approval from the named owner before the Security team acts on it.

### BACKEND Module — Owner: Backend Team

| File | Existing code (confirmed) | Proposed change | Requires backend approval? |
|------|--------------------------|----------------|---------------------------|
| `src/utils/generateHash.js` | `generateLogHash(camelCase)` → SHA-256 of canonicalized 7-field set | **Replace with** `computeLogHashV1(event, previousHash)` using LOGN-HASH-v1 field set (snake_case, 9 fields including event_type and severity) | ✅ **YES — breaking change** |
| `src/utils/canonicalize.js` | UTF-16 sort, Date→ISO, skip undefined | No change to file; document that sort order is ASCII-compatible for all expected keys | No approval needed |
| `src/services/logService.js` | Calls `generateLogHash({eventId, sourceId, ...})` | Update call site to pass event fields in LOGN-HASH-v1 format; normalization of `event_time` from `timestamp` | ✅ **YES — call site changes** |
| `src/models/Log.js` | Schema: `previousHash`, `currentHash`, `verificationStatus`, `storageReference` | Add field: `blockchainCheckpointId: { type: String, default: null, index: true }` | ✅ **YES — schema addition** |
| `src/models/Source.js` | `lastHash` = 64 zeros, `lastSequenceNumber` | No change needed | No |
| `src/routes/logRoutes.js` | POST, GET routes for logs | No change to existing routes | No |
| `src/app.js` or `src/server.js` | Express app setup | Add: `import securityRoutes from '../../security/routes/securityRoutes.js'` and `app.use('/api/security', securityRoutes)` | ✅ **YES — route registration** |
| `src/controllers/logController.js` | `ingestLogs`, `getLogs`, `getLogDetails`, `getStats` | No change to existing controllers | No |
| New file (owned by Security, lives in backend) | — | `src/routes/securityRoutes.js` — Security creates this file | Routing integration requires backend approval |

### STORAGE Module — Owner: Storage Team

| File | Existing code (confirmed) | Proposed change | Requires storage approval? |
|------|--------------------------|----------------|---------------------------|
| `evidence-engine/checkpoint_manager.py` | `calculate_event_hash` = `SHA-256(prevHash + ":" + canonical(event))` | **Replace formula** with `computeLogHashV1(event, prevHash)` matching LOGN-HASH-v1 | ✅ **YES — breaking change** |
| `evidence-engine/checkpoint_manager.py` | `canonical_json` uses `ensure_ascii=True` | Change to `ensure_ascii=False` | ✅ **YES** |
| `evidence-engine/checkpoint_manager.py` | `__init__` generates ephemeral key | Accept externally injected key (see §4.9) | ✅ **YES — constructor signature change** |
| `evidence-engine/evidence_verifier.py` | `verify_event_chain` replays with old formula | Update to use `computeLogHashV1` | ✅ **YES — verification logic changes** |
| `evidence-engine/evidence_packager.py` | Creates bundles from raw events | No structural change. Bundle schema stays. The `checkpoint_manager` it uses will produce correct hashes after §4.9 fix. | Indirectly yes (depends on checkpoint_manager fix) |
| `tests/test_integrity.py` | Full test suite for chain, Ed25519, tamper | **Regenerate all test vector hash values** (test logic is correct; only expected hashes change) | ✅ **YES — test values must be recomputed** |
| `storage/storageService.js` | `storeEvidence(bundle)` + SHA-256 checksum of bundle | No change needed. Bundle storage is independent of blockchain anchoring. | No |
| `storage/multiVault.js` | Primary + secondary vault | No change | No |
| `storage/retentionManager.js` | Legal holds, purge | No change | No |
| `storage/backupService.js` | Compressed backup with checksums | No change | No |
| New file (optional, owned by Security or Storage) | — | `evidence-engine/key_loader.py` — loads persistent Ed25519 key from `signing_key.enc` for use by Storage's CheckpointManager | ✅ **YES — Storage team must accept and use this** |

### SECURITY Module — Owner: Security Team (your branch)

| File | Existing code (confirmed) | Action |
|------|--------------------------|--------|
| `README.md` | Present, content not inspected | Update with architecture overview |
| All Security module files | None — branch is empty | Create new files per folder structure in audit report |

### Cross-Module — All Owners

| Concern | Action | All owners must agree |
|---------|--------|----------------------|
| `LOGN-HASH-v1` test vector | Each module runs the two-leaf test vector; all must produce identical `merkle_root` | ✅ |
| Checkpoint trigger protocol | Backend notifies Security after every Nth log | ✅ |
| Checkpoint ID format | UUID v4, keccak256 for contract | ✅ |
| `signing_key.enc` file format | AES-256-GCM envelope (§4.3) | Storage if sharing key |
| Development database handling | Use separate test DB or versioned migration; never default-wipe shared data | ✅ |

---

## 11. Open Decisions Requiring Team Approval

The following items have no default — the team must vote and record a decision before any dependent code is written.

| # | Decision | Options | Owner(s) to approve | Blocks |
|---|----------|---------|--------------------|----|
| **D-01** | Accept LOGN-HASH-v1 as the canonical formula | ✅ Accept as specified / ❌ Propose alternative | Backend + Storage + Security | Everything |
| **D-02** | Checkpoint trigger mechanism | A: Inline in logService / B: Polling cron / C: Manual only | Backend + Security | §3 |
| **D-03** | Storage's Ed25519 key persistence | A: Security provides `key_loader.py` for Storage / B: Storage independently implements key loading / C: Both modules use separate independent keys | Storage + Security | §4.9 |
| **D-04** | Backend accepts security route registration in `app.js` | ✅ Yes — Security files integrated into backend codebase / ❌ No — Security runs as separate microservice | Backend + Security | §7, §9 |
| **D-05** | `Log.blockchainCheckpointId` schema addition | ✅ Backend adds field / ❌ Store only in Checkpoint collection (no Log backref) | Backend + Security | §5.4 |
| **D-06** | Merkle proof storage in MVP | A: Store full proofs in MongoDB / B: Store root only (proofs re-derivable) | Security | §6.6 |
| **D-07** | Development EVM network | A: Hardhat in-process (no persistence) / B: `hardhat node` daemon (persists in session) / C: Sepolia testnet | Security | §7.5 |
| **D-08** | Development database handling after hash formula change | ✅ Use separate test DB / ✅ Versioned migration with backup / ❌ Wipe dev MongoDB (not recommended) | All | D-01 |
| **D-09** | Checkpoint window size (N events per checkpoint) | 50 / 100 / 200 / time-based (every 5 min) | Backend + Security | §3.1 |
| **D-10** | Public key on-chain in `CheckpointAnchored` event | ✅ Add `signerPublicKey` bytes as event field / ❌ Omit (save gas; available in MongoDB) | Security | §7.3 |
| **D-11** | `ensure_ascii=False` change in Storage's `canonical_json` | ✅ Storage accepts the change / ❌ Propose alternative (Base64 encode all strings?) | Storage + Security | D-01 |
| **D-12** | `deep` chain replay verification feature in MVP | ✅ Include in MVP / ❌ Post-hackathon | Security | §9.3 |

---

## Appendix A: Hash Formula Cross-Reference

| Property | Backend (current) | Storage (current) | LOGN-HASH-v1 (proposed) |
|----------|------------------|------------------|------------------------|
| Field count | 7 | ~10 (full event) | 9 (fixed set) |
| Field naming | camelCase | snake_case | snake_case |
| `previousHash` position | Inside JSON object | Outside JSON (concat) | Inside JSON object |
| Serializer | Custom RFC-8785 (UTF-16 sort) | `json.dumps(sort_keys=True)` | Unicode code point sort, `ensure_ascii=False` |
| Non-ASCII handling | Pass-through | Force escape `\uXXXX` | Pass-through (UTF-8 preserved) |
| Concat prefix | None | `prevHash + ":"` | None |
| `integrity` field stripped | N/A | Yes | N/A (never included) |
| Genesis hash | 64 zeros | 64 zeros | 64 zeros ✅ (compatible) |
| Output encoding | lowercase hex-64 | lowercase hex-64 | lowercase hex-64 ✅ |

---

## Appendix B: Glossary

| Term | Definition |
|------|-----------|
| `LOGN-HASH-v1` | The canonical log event hash formula defined in §1.3 of this contract |
| `Log.currentHash` | The authoritative per-event hash stored in MongoDB by the Backend after ingest |
| `merkle_root` | SHA-256 Merkle root over leaf hashes derived from `Log.currentHash` values |
| `checkpoint_id` | UUID v4 identifying a checkpoint document in MongoDB |
| `checkpointId` (bytes32) | `keccak256(UTF-8_bytes(checkpoint_id))` — the on-chain key |
| `signing_key_id` | UUID v4 identifying the Ed25519 key pair that signed a checkpoint |
| `evidence bundle` | Storage's output from `EvidencePackager.package()` — independent of MongoDB checkpoints |
| Anchor | The act of submitting a `merkle_root` commitment to the smart contract |
| Verification | The act of confirming that stored logs, the signed checkpoint, and the on-chain root all agree |
| `verificationStatus` | Field on both `Log` and `Checkpoint` documents: PENDING → ANCHORED → VERIFIED / FAILED |
| Genesis hash | 64 zero characters — the `previous_hash` for the first event of a source |
| Domain separation | Prefixing leaf and internal nodes with different bytes (0x00/0x01) to prevent hash collision attacks |
| LOGN | Internal project name used in the existing codebase (confirmed in Storage's docstrings) |

---

*End of Technical Integration Contract v1.0-draft*  
*This document becomes effective when all [REQUIRES TEAM APPROVAL] items in §11 are resolved and recorded.*

---

## 12. HHH Hackathon Implementation Decisions

> [!NOTE]
> This section records working decisions adopted by the Security + Blockchain module owner
> for the hackathon implementation phase. These decisions are **unilateral defaults** where
> the Security owner has authority, or **proposals** where cross-module agreement is still
> needed. They do not replace the approvals listed in §11 — decisions marked
> ⚠️ **Pending cross-module validation** still require the named team owners to confirm
> before the Security team acts on them.

---

### H-01 — Hash Formula Adoption

**Decision:** Adopt `LOGN-HASH-v1` (§1.3) as the proposed canonical log hash format for the Security module's Merkle tree construction and checkpoint verification.

**Scope of this decision:** The Security module will implement `computeLogHashV1` using the specified field set, serialization, and encoding, and will use `Log.currentHash` values from MongoDB as Merkle leaf inputs. The Security module will not independently re-derive per-event hashes during normal operation — it consumes the already-committed values.

**Status:** ⚠️ **Pending cross-module validation** — Backend and Storage teams must each run the §1.3.5 test vector through their implementations and confirm identical SHA-256 output before either team modifies their hash functions. No changes to `generateHash.js` or `checkpoint_manager.py` should be made until this cross-language test passes.

**Validation gate:** Both Node.js and Python produce the same 64-character hex digest from the §1.3.5 canonical string. Record the expected digest as a shared constant.

---

### H-02 — Checkpoint Trigger Mechanism

**Decision:** Start with **manually triggered checkpoints** via `POST /api/security/checkpoint` (Option C from §3.2). Automation via inline backend trigger (Option A) will only be implemented after the MVP end-to-end flow is verified working manually.

**Rationale:** Automation before a working MVP creates debugging complexity. Manual triggering allows the Security team to validate Merkle construction, signing, anchoring, and verification independently before coupling to the backend ingest flow.

**Consequence:** During the hackathon demo, an operator will manually call the checkpoint API after a batch of logs is ingested. This is acceptable for a demo setting.

**Status:** ✅ Security module decision — does not require Backend approval for the manual trigger. Backend approval is required only when transitioning to Option A (inline trigger in `logService.js`), which is post-MVP.

---

### H-03 — Signing Key Separation Between Security and Storage

**Decision:** Security and Storage use **separate, independently managed Ed25519 signing keys and independently managed public-key verification**. The Security module's `KeyManager` (§4) manages its own keypair exclusively. Storage's `CheckpointManager` manages its own keypair independently.

**Rationale:** Shared key management introduces operational coupling that is out of scope for a hackathon. If Storage's key is ephemeral (the current bug), that affects Storage's bundle verification, not Security's checkpoint verification. The two signing contexts are independent.

**Consequence for Storage:** Storage's current ephemeral key problem (§4.1) means Storage's evidence bundle signatures cannot be verified across process restarts. This is a known issue in Storage's codebase. The Security module does not fix it — the fix is §4.9, which is Storage's responsibility pending their team's approval.

**Consequence for verification:** When verifying a checkpoint (§9), the Security module verifies only its own Ed25519 signature on the checkpoint document. It does not verify Storage's bundle signatures. These are separate forensic artefacts.

**Status:** ✅ Security module decision — does not require Storage approval for the Security module's own key. ⚠️ **Storage team should be notified** of the ephemeral key issue (§4.9) and decide independently whether to fix it.

---

### H-04 — Interface Exposure and Integration PRs

**Decision:** The Security module exposes **documented HTTP interfaces** (§9.1 and §3 trigger API). Changes required in Backend and Storage codebases are proposed through **integration pull requests** against the respective branches, not silently applied.

**Specifically:**
- Security will create `security/routes/securityRoutes.js` within its own module directory.
- An integration PR to `feature-backend` will be raised to register the security routes in `backend/src/app.js`. This PR will not be merged without Backend team review.
- Security will NOT modify `backend/src/utils/generateHash.js`, `backend/src/services/logService.js`, or any Storage files directly. Those changes are proposed via PRs to the respective branches.
- If Backend declines to integrate security routes into the backend codebase, the Security module will run as a standalone Express microservice on a separate port.

**Status:** ✅ Security module decision on its own process. ⚠️ **Pending Backend team approval** for route registration (D-04 in §11).

---

### H-05 — MongoDB Data Migration Policy

**Decision:** **Never wipe existing MongoDB data as a default migration step.** When the hash formula changes (upon adopting LOGN-HASH-v1), the Security team will use one of the following safe approaches:

1. **Preferred:** Use a separate test database (`LOGN_MONGO_URI` pointing to a dev-only instance) for all Security module integration testing. The shared development database is not touched.
2. **If a shared database must be migrated:** Create a versioned migration script that backs up the existing `logs` and `sources` collections before making any changes, runs the re-hash operation on a copy, and allows rollback.
3. **What is never acceptable:** Dropping collections or databases without a backup, or running `truncate`/`drop` commands as a default "clean start" step.

**Consequence:** Logs ingested with the old backend formula will have a `currentHash` that does not match LOGN-HASH-v1. These logs will show `merkleRootMatch: false` in verification reports. This is correct and expected behaviour — it surfaces the formula mismatch rather than hiding it.

**Status:** ✅ Security module policy. ⚠️ **Requires all-team agreement** before any database migration script is run against a shared environment (D-08 in §11).

---

### H-06 — Checkpoint Window Size

**Decision:** Begin with a **configurable checkpoint window of 100 events** per source (`CHECKPOINT_INTERVAL=100` environment variable, as already referenced in §3.1).

**Rationale:** 100 events is large enough to demonstrate meaningful Merkle tree construction (the tree will have 7 levels for 100 leaves) while being small enough to ingest quickly during a hackathon demo. The window size is a runtime configuration, not a hardcoded constant, so it can be adjusted without code changes.

**Consequence:** At 100 events per checkpoint, anchoring costs approximately 100,000–130,000 gas per checkpoint on the local Hardhat EVM. This is negligible on a local chain.

**Status:** ✅ Security module decision. ⚠️ **Requires Backend agreement** when transitioning from manual to automatic triggering (H-02), because the backend will read this environment variable to decide when to trigger.

---

### H-07 — EVM Network for Development

**Decision:** Use a **local Hardhat EVM** (`npx hardhat node` daemon, chain ID 31337) for all development and demo work. A public testnet (Sepolia) will only be considered if time permits after the full local flow is working.

**Rationale:** A local EVM requires no external accounts, no testnet ETH, and has zero network latency. It is the fastest path to a working demo. The daemon mode (`hardhat node`) persists state across terminal sessions within a single development session, which is sufficient for the hackathon.

**Contract address persistence:** The deployed contract address will be saved to `security/deployments/localhost.json` after each deployment. This file is committed to Git so all team members use the same address.

**Known limitation:** The local EVM is reset each time `hardhat node` is restarted. All on-chain commitments are lost. This must be clearly disclosed in the demo README and to judges. It does not affect off-chain evidence (MongoDB checkpoints remain).

**Status:** ✅ Security module decision — the Security team owns the blockchain deployment.

---

### H-08 — Merkle Inclusion Proofs and Deep Chain Replay

**Decision:** Implement **both** Merkle inclusion proofs and optional deep chain replay in the MVP scope.

**Merkle inclusion proofs:**
- Per-leaf proofs are computed when the Merkle tree is built (§6.6 proof format).
- Proofs are stored in the `checkpoints` MongoDB document alongside `merkleLeafHashes`.
- A `GET /api/security/checkpoint/:checkpointId/proof/:sequenceNumber` endpoint returns the proof for a specific log event, allowing per-event proof-of-inclusion verification without exposing the full leaf list.

**Deep chain replay:**
- Implemented as the `?deep=true` query parameter on the verification endpoint (§9.3).
- Not called by default — must be explicitly requested for forensic investigation.
- The Security module implements `computeLogHashV1` in its own codebase for this purpose. It does not call the Backend's `generateHash.js` directly.

**Rationale:** Proof-of-inclusion is a core value proposition of Merkle trees. Implementing it in the MVP makes the blockchain component demonstrably useful, not just decorative. Deep replay provides a secondary tamper-detection path that is independent of the on-chain anchor.

**Status:** ✅ Security module decision — both features are within the Security module's implementation scope.

---

### Summary Table

| ID | Decision | Status | Cross-module dependency |
|----|----------|--------|------------------------|
| H-01 | Adopt LOGN-HASH-v1 for Security module | ⚠️ Pending cross-module validation | Backend + Storage test vector confirmation |
| H-02 | Manual checkpoint trigger first; automate post-MVP | ✅ Security decision | Backend approval needed for Option A later |
| H-03 | Separate Ed25519 keys for Security and Storage | ✅ Security decision | Storage notified of ephemeral key bug |
| H-04 | Interface PRs; no silent cross-module changes | ✅ Security decision | Backend approval for route registration |
| H-05 | No default MongoDB wipe; use separate test DB | ✅ Security policy | All teams for shared env migration |
| H-06 | Checkpoint window = 100 events (configurable) | ✅ Security decision | Backend for automatic trigger |
| H-07 | Local Hardhat EVM; no testnet for MVP | ✅ Security decision | None |
| H-08 | Merkle proofs + deep chain replay in MVP | ✅ Security decision | None |

---

*Section §12 added by Security + Blockchain module owner, 2026-11-20.*  
*Items marked ⚠️ Pending cross-module validation are proposals, not team approvals.*  
*Do not treat this section as evidence that Backend or Storage teams have agreed to any changes in their codebases.*
