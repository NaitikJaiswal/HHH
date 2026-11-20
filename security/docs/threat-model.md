# Threat Model: HHH SecureLog Security Module

> **HHH SecureLog — Security + Blockchain Module**<br>
> **Reference Contract:** `docs/technical-integration-contract.md` §§1–9<br>
> **Status:** Full Implementation (Phases 1–5) Defense Analysis

This document analyzes the threat landscape for the Security module's cryptographic guarantees. For each threat, we describe: what the attack is, what the system detects, the mathematical mechanism of detection, and explicit limitations/boundaries.

---

## 1. Threat Matrix Summary

| Threat ID | Threat Description | Detection Mechanism | Phase Implemented |
|---|---|---|---|
| **T-01** | Silent Log Field Tampering | Deterministic LOGN-HASH-v1 Hash Mismatch | Phase 1 & 4B |
| **T-02** | Middle Log Event Deletion | Sequence Number Gap & Broken Previous Hash | Phase 1 & 4B |
| **T-03** | Tail Log Event Deletion | Sequence End Mismatch vs On-Chain Commitment | Phase 3A & 4B |
| **T-04** | Fabricated Log Event Injection | Broken Hash Chain Link & Merkle Root Mismatch | Phase 1, 2, 4B |
| **T-05** | Event Reordering Attack | Interrupted Hash Chain Pointers | Phase 1 & 4B |
| **T-06** | Merkle Leaf Hash Substitution | Recomputed Root Mismatch vs Stored/On-Chain | Phase 2, 3A, 4B |
| **T-07** | Second-Preimage / Tree Collapse | RFC 6962 Domain Separation Prefixes (`0x00`/`0x01`) | Phase 2 & 5 |
| **T-08** | Checkpoint Document Tampering | Ed25519 Digital Signature Verification Failure | Phase 2 & 4B |
| **T-09** | Unauthorized Signing Key Injection | Public Key Registry & Provenance Check | Phase 2 & 4B |
| **T-10** | At-Rest Private Key Extraction | AES-256-GCM + scrypt & POSIX 0600 Permissions | Phase 2 & 5 |
| **T-11** | On-Chain Commitment Overwrite | Smart Contract Revert on Duplicate Checkpoint ID | Phase 3A & 5 |
| **T-12** | Unauthorized Smart Contract Anchor | `authorizedSubmitters` Access Control Invariant | Phase 3A & 5 |
| **T-13** | Network Partition / RPC Timeout | Idempotent Safe Retry & On-Chain State Polling | Phase 3B & 5 |

---

## 2. Detailed Threat Analysis & Defenses

### Threat 1: Silent Log Modification After Ingestion (T-01)
- **Attack**: An attacker or rogue database administrator with direct access to MongoDB alters an event field (e.g., changes `message`, `user_id`, or `severity`) to falsify activity records.
- **Defense**:
  - The hash of every event is computed using `canonicalJson()` and `sha256hex()`.
  - In `verifyHashChain`, every event is re-hashed. If any field was modified, the recomputed hash diverges from `Log.current_hash`.
  - Even if the attacker modifies `Log.current_hash` and rebuilds the hash chain, the checkpoint's Merkle root and on-chain commitment remain tied to the original sequence, exposing the tampering immediately.

### Threat 2: Event Deletion (Interior & Tail) (T-02, T-03)
- **Attack**: An attacker deletes events to erase evidence of unauthorized actions.
- **Interior Deletion Defense**:
  - Deleting an interior event (e.g., removing Event #5 from a sequence of 10) causes a sequence gap ($4 \to 6$) and causes Event #6's `previous_hash` to point to deleted Event #5's hash. `verifyHashChain` flags both a sequence discontinuity and a broken chain link.
- **Tail Deletion Defense**:
  - If the attacker truncates the end of the log stream, the event count and `endSequence` recorded in the on-chain checkpoint will exceed the available logs in MongoDB, alerting forensic auditors to missing trailing events.

### Threat 3: Event Insertion / Log Injection (T-04)
- **Attack**: An attacker injects a fabricated log event into the sequence to manufacture an alibi.
- **Defense**:
  - Injecting an event disrupts consecutive sequence numbering ($k, k, k+1$) or breaks the `previous_hash` chain link.
  - If the attacker attempts a complete re-chaining, the recomputed Merkle root will not match the root anchored on the immutable blockchain.

### Threat 4: Merkle Tree Forgery & Second-Preimage Attacks (T-06, T-07)
- **Attack**: An attacker crafts fake internal nodes that collide with leaves, or submits an altered leaf hash.
- **Defense**:
  - In accordance with RFC 6962, leaf hashes are computed with prefix `0x00` (`SHA256(0x00 || leaf)`), while internal nodes are computed with prefix `0x01` (`SHA256(0x01 || left || right)`).
  - This domain separation prevents intermediate internal nodes from being interpreted as valid leaves.
  - Odd-numbered leaf layers duplicate the final leaf node deterministically following the Bitcoin pairing convention (Contract §6.4), preventing ambiguous tree topologies.

### Threat 5: Checkpoint Signature Tampering & Forgery (T-08, T-09)
- **Attack**: An attacker tampers with checkpoint metadata (e.g., altering `sequence_range` or `merkle_root`) or signs a fraudulent checkpoint with a newly generated rogue key.
- **Defense**:
  - Checkpoints are signed using **Ed25519**. The signature covers the canonical JSON representation of the entire checkpoint payload (excluding the signature itself and external blockchain receipts).
  - Verification requires **Key Provenance**: `verifier.js` and `KeyManager` check that the public key exists in `public-key-registry.json` and was active when the checkpoint was created. Untrusted public keys are rejected.

### Threat 6: At-Rest Private Key Compromise (T-10)
- **Attack**: An attacker reads the server filesystem to steal the Ed25519 signing key.
- **Defense**:
  - The private key is never stored in plaintext. It is encrypted using **AES-256-GCM** with a key derived via **scrypt** from a secure passphrase.
  - POSIX file permissions are enforced at `0600` (read/write by owner only); insecure permissions trigger a runtime error during key load.

### Threat 7: Blockchain Replay & Commitment Tampering (T-11, T-12)
- **Attack**: An attacker attempts to overwrite an anchored checkpoint with a forged Merkle root, or an unauthorized account calls `anchorCheckpoint`.
- **Defense**:
  - `SecureLogAnchor.sol` stores commitments in a mapping `commitments[checkpointId]`.
  - If `commitments[checkpointId].timestamp != 0`, the contract reverts with `"SecureLog: Checkpoint already anchored"`.
  - Only addresses registered in `authorizedSubmitters` can invoke `anchorCheckpoint`; unauthorized callers revert with `"SecureLogAnchor: caller is not an authorized submitter"`.

---

## 3. Security Boundaries & Honest System Limitations

While SecureLog provides mathematical guarantees of tamper evidence, certain physical and operational limits exist:

1. **Pre-Ingestion Log Manipulation**:
   - Cryptographic hashing guarantees tamper evidence *from the moment of ingestion*. If a compromised host or kernel tampers with log events *before* they are sent to the SecureLog ingestion API, the system will record and anchor the tampered data faithfully.
   - *Mitigation*: Secure syslog forwarding (mTLS), kernel auditd modules, and read-only host agents.

2. **Blockchain Finality & Chain Reorganizations**:
   - In Proof-of-Work or Proof-of-Stake environments, micro-forks and deep reorganizations can temporarily invalidate unconfirmed or weakly confirmed transactions.
   - *Mitigation*: `BlockchainService` requires block confirmations before marking a checkpoint as `CONFIRMED`.

3. **Passphrase and Host Security**:
   - If an attacker obtains root access to the security service host while memory is mapped, they could extract decrypted private keys from RAM.
   - *Mitigation*: Hardware Security Modules (HSM), AWS KMS / GCP Cloud KMS, or secure enclaves (SGX/Nitro) in enterprise deployments.

4. **Tamper Evidence vs Tamper Prevention**:
   - Cryptography cannot physically prevent a malicious user from deleting rows in MongoDB. However, it guarantees that **any deletion, modification, or reordering is immediately and mathematically detectable** against the immutable blockchain commitment.
