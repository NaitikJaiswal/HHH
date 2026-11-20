# Demonstration Guide: HHH SecureLog

> **HHH (Hash. Hunt. Harden.) — SecureLog Forensic Platform**  
> **Interactive Demonstration & Hackathon Showcase**  
> **Command:** `npm run demo`

---

## 1. Overview of the Demonstration

The demonstration script (`security/scripts/demo.js`) provides an end-to-end, runnable demonstration of the HHH SecureLog cryptographic pipeline. It executes two comprehensive scenarios:

1. **Scenario 1: Happy Path — End-to-End Cryptographic Evidence Pipeline**  
   Demonstrates how log events are ingested, hashed deterministically with `LOGN-HASH-v1`, chained sequentially, aggregated into a Merkle tree, signed with Ed25519, committed to the EVM smart contract, and validated via dual off-chain and on-chain verification.

2. **Scenario 2: Adversarial Attack — Tampering Detection & Forensics**  
   Simulates a malicious insider with database access modifying log records and attempting to forge an evidence trail. Demonstrates how the cryptographic chain immediately breaks and how on-chain immutability proves the tampering without revealing sensitive log content.

---

## 2. Running the Demo

Ensure your local environment has dependencies installed:

```bash
cd security
npm run demo
```

*(Note: The demo script automatically launches an embedded ephemeral in-memory Hardhat node, deploys `SecureLogAnchor`, and manages all keys and temporary directories. No manual blockchain startup is required!)*

---

## 3. Walkthrough: Scenario 1 (Valid Pipeline)

### Step 1: Log Event Ingestion & Canonical Hashing
- Generates 5 simulated digital forensics log events representing user login, access to evidence lockers, file exports, and logout.
- Calculates deterministic SHA-256 hashes using the LOGN-HASH-v1 9-field canonical schema.
- **Key Observation**: Even with unordered JSON keys or varied whitespace, the hash is strictly deterministic.

### Step 2: Sequential Hash Chain Construction
- Links each log event to the previous event's hash (`previous_hash` $\to$ `current_hash`).
- Validates that the chain is continuous starting from the 64-zero `GENESIS_HASH`.
- **Output**:
  ```
  Chain Status: VALID (5 events linked from Genesis)
  ```

### Step 3: Merkle Tree Construction & Inclusion Proofs
- Builds a binary Merkle tree over all 5 log event hashes using RFC 6962 leaf/node prefixes (`0x00` and `0x01`).
- Generates a lightweight Merkle inclusion proof for Event #3 (`EVIDENCE_EXPORT`).
- Verifies the proof against the Merkle root:
  ```
  Merkle inclusion proof verification: VERIFIED
  Proof length: 3 sibling nodes
  ```

### Step 4: Checkpoint Signing & Blockchain Anchoring
- Generates an Ed25519 digital signature over the checkpoint payload.
- Anchors the commitment (`checkpointId`, `merkleRoot`, `startSequence`, `endSequence`, `eventCount`, `timestamp`) into `SecureLogAnchor.sol`.
- **Output**:
  ```
  Transaction Hash: 0x8a7f...
  Block Number:     1
  Gas Units Used:   96412
  ```

### Step 5: Dual Verification & Forensic Audit Report
- Fetches the on-chain commitment and performs dual verification:
  1. Checks Ed25519 signature validity.
  2. Verifies public-key provenance against the key registry.
  3. Recomputes Merkle root from leaf hashes.
  4. Compares local Merkle root against on-chain smart contract state.
- **Output**:
  ```
  OVERALL VALIDITY: ✅ VERIFIED (Tamper-evident record intact)
  ```

---

## 4. Walkthrough: Scenario 2 (Tamper Detection)

### The Attack
A privileged database administrator alters Event #2 in MongoDB to conceal Alice's unauthorized vault access:
- **Original**: `"Alice accessed evidence locker vault: case/2026-904"`
- **Tampered**: `"Alice performed routine heartbeat ping"`

### Forensic Detection 1: Hash Chain Breakdown
When the forensic verifier audits the logs:
```
[!] Hash chain validation result: ❌ CORRUPT / TAMPERED
    Anomaly detected: Sequence #2 (index 1): Hash mismatch at sequence 2
    Anomaly detected: Sequence #3 (index 2): Broken chain link at sequence 3
```
- Event #2's recomputed hash no longer matches its stored `current_hash`.
- Event #3's `previous_hash` still points to the original hash of Event #2, proving that the chain was broken.

### Forensic Detection 2: Merkle Root & On-Chain Rejection
The attacker attempts to fix the leaf hash in the checkpoint:
```
Off-Chain Stored Root:  0x3f5c...
Recomputed Root:        0x7a21...
On-Chain Root:          0x3f5c...
OVERALL VALIDITY:       ❌ TAMPERED / EVIDENCE REJECTED
Detected Anomalies:
  - 🚨 Merkle root mismatch: recomputed 0x7a21... != stored 0x3f5c...
  - 🚨 Checkpoint Ed25519 signature verification failed
```
- The attacker cannot forge the Ed25519 signature without the private key.
- Even if the attacker signed a new checkpoint, the original root was already committed to the immutable blockchain, rendering retroactive log tampering mathematically impossible to conceal.

---

## 5. Benchmarking Performance

To demonstrate system throughput and latency for hackathon judges:

```bash
npm run benchmark
```

### Typical Benchmark Results
- **Canonical Serialization**: ~90,000+ operations/sec
- **LOGN-HASH-v1 Hashing**: ~47,000+ hashes/sec
- **1,000-Event Hash Chain**: Chained in ~18 ms, verified in ~20 ms
- **1,000-Leaf Merkle Tree**: Constructed in ~9 ms, inclusion proof verified in ~0.06 ms
- **Memory Footprint**: Heap delta < 1 MB for 1,000 events
