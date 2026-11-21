# HHH Verification CLI & Forensic Tooling Reference

## Overview

The `hhh` command-line interface provides an independent, offline cryptographic verification tool for the HHH (Hash. Hunt. Harden.) cybersecurity and digital forensics platform.

The CLI allows third-party auditors, forensic analysts, security teams, and courts of law to verify the mathematical authenticity of logs, hash chains, digital signatures, Merkle inclusion proofs, signed checkpoints, sealed evidence packages, and forensic reports without trusting the central server.

```
       ┌────────────────────────────────────────────────────────┐
       │                HHH Verification CLI                    │
       │                   (bin/hhh)                            │
       └─────────────────────────┬──────────────────────────────┘
                                 │
     ┌──────────────┬────────────┼────────────┬─────────────┐
     ▼              ▼            ▼            ▼             ▼
 verify-log   verify-chain verify-checkpoint verify-merkle verify-evidence
```

---

## Installation & Invocation

The CLI is distributed as part of the HHH platform:

```bash
# Direct binary execution
./bin/hhh <command> [target] [options]

# Node invocation
node bin/hhh <command> [target] [options]
node cli/hhh.js <command> [target] [options]
```

---

## Exit Codes

All commands return standardized process exit codes for automated CI/CD and scripting:

| Exit Code | Status Name | Description |
| :--- | :--- | :--- |
| `0` | `VALID` | All cryptographic checks passed with mathematical certainty. |
| `1` | `INVALID` | Integrity breach detected: altered payload, broken hash link, or forged signature. |
| `2` | `PARTIALLY_VERIFIED` | Some checkpoints verified, but others lacked trusted public keys. |
| `3` | `UNVERIFIABLE` | Missing public keys or required verification material. |
| `4` | `REVOKED` | Checkpoint signed in or after an epoch declared compromised. |
| `5` | `INSUFFICIENT_DATA` | Missing, empty, or unparseable input data. |

---

## Commands

### 1. `verify-log`

Independently verifies individual log event canonical hashes against the authoritative specification.

- **Supported Schemas:**
  - `LOGN-HASH-v1`: 9-field canonical RFC 8785 JSON representation.
  - Legacy 7-field format (backward compatibility with Phase 1 baseline).
- **Usage:**
  ```bash
  hhh verify-log <log-event.json>
  cat event.json | hhh verify-log -
  ```
- **Example Output:**
  ```json
  {
    "status": "VALID",
    "exitCode": 0,
    "validRecords": 1,
    "invalidRecords": 0,
    "totalExamined": 1
  }
  ```

---

### 2. `verify-chain`

Verifies the cryptographic continuity and sequence consistency of an event stream.

- **Checks Performed:**
  - Continuous `previous_hash` to `current_hash` link across records.
  - Monotonically increasing sequence numbers (detects missing gaps, insertions, duplicates).
  - Chronological timestamp monotonicity (detects backdated tampering).
- **Usage:**
  ```bash
  hhh verify-chain <events.jsonl>
  hhh verify-chain <events.json>
  ```
- **Example Output:**
  ```json
  {
    "status": "VALID",
    "exitCode": 0,
    "valid": true,
    "recordsExamined": 100,
    "errors": []
  }
  ```

---

### 3. `verify-checkpoint`

Verifies signed checkpoints under either modern Forward-Secure Signatures (FSS) or legacy Ed25519.

- **Checks Performed:**
  - Checkpoint schema structure and event boundary consistency.
  - Merkle root recalculation over `merkle_leaf_hashes`.
  - Merkle tree algorithm validation (`HHH-CONTRACT-DUP-v1` or `RFC-6962`).
  - Emergency revocation notice enforcement (flags checkpoints signed in compromised epochs).
  - Forward-secure signature verification against Master Public Key (MPK) using Merkle auth path.
- **Usage:**
  ```bash
  hhh verify-checkpoint <checkpoint.json> --mpk <master-public-key-hex>
  hhh verify-checkpoint <checkpoint.json> --key <public-key-hex>
  ```
- **Example Output:**
  ```json
  {
    "status": "VALID",
    "exitCode": 0,
    "valid": true,
    "checks": {
      "structure": true,
      "event_count": true,
      "leaf_count": true,
      "merkle_root": true,
      "signature": true
    },
    "failures": []
  }
  ```

---

### 4. `verify-merkle`

Verifies a cryptographic Merkle inclusion proof bundle connecting a specific log event to an anchored checkpoint root.

- **Supported Algorithms:**
  - `HHH-CONTRACT-DUP-v1`: Smart contract compatible odd-node duplication tree.
  - `RFC-6962`: Certificate Transparency domain-separated Merkle tree.
- **Usage:**
  ```bash
  hhh verify-merkle <proof-bundle.json> --root <expected-merkle-root>
  ```
- **Example Output:**
  ```json
  {
    "status": "VALID",
    "exitCode": 0,
    "valid": true,
    "leafIndex": 3,
    "treeSize": 50,
    "algorithm": "HHH-CONTRACT-DUP-v1"
  }
  ```

---

### 5. `verify-signature`

Verifies standalone digital signatures over arbitrary binary or JSON payloads.

- **Supported Algorithms:**
  - `Ed25519` (RFC 8032)
  - `Ed25519-MKT-FSS` (Forward-secure tree signature)
- **Usage:**
  ```bash
  hhh verify-signature <payload.txt> --signature <hex> --key <public-key-hex>
  ```

---

### 6. `verify-evidence`

Performs end-to-end cryptographic audit of a sealed evidence package exported from the Evidence Vault.

- **Checks Performed:**
  - Manifest integrity and export checksum verification.
  - Event sequence continuity and hash-chain verification.
  - Checkpoint signature and Merkle root verification.
  - Event tip alignment with anchored checkpoint roots.
  - Chain of custody log audit.
- **Usage:**
  ```bash
  hhh verify-evidence <bundle.json> --mpk <master-public-key-hex>
  ```
- **Example Output:**
  ```json
  {
    "status": "VALID",
    "exitCode": 0,
    "bundleId": "BND-1732176000-8A2F",
    "sourceId": "workstation-dc-alpha",
    "eventsChecked": 50,
    "checkpointsChecked": 1,
    "checkpointsVerified": 1,
    "rootAligned": true
  }
  ```

---

### 7. `inspect-report`

Inspects and verifies the cryptographic integrity and findings summary of a forensic incident report dossier.

- **Usage:**
  ```bash
  hhh inspect-report <report.json>
  ```
- **Example Output:**
  ```json
  {
    "status": "VALID",
    "exitCode": 0,
    "reportSummary": {
      "incidentId": "INC-2026-ALPHA",
      "overallSeverity": "CRITICAL",
      "totalEventsCollected": 50,
      "cryptographicIntegrityStatus": "VERIFIED"
    }
  }
  ```
