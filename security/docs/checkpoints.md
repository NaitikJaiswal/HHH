# Signed Checkpoints & Verification Engine

> **HHH SecureLog — Security Module (Phase 2)**  
> Reference: `docs/technical-integration-contract.md` §3, §5, §9

---

## 1. Overview & Purpose

A **Checkpoint** is a cryptographically signed commitment representing a closed batch of log events for a given source over a contiguous sequence range $[start\_sequence, end\_sequence]$.

It ties together:
1. **The Log Event Chain**: via an array of authoritative `Log.currentHash` values (`merkle_leaf_hashes`).
2. **The Merkle Tree Commitment**: via `merkle_root`.
3. **Asymmetric Authenticity**: via an Ed25519 `signature` produced by the Security service's `KeyManager`.
4. **Blockchain Anchoring (Phase 3)**: via transaction hashes and block numbers once committed to EVM smart contracts.

---

## 2. Checkpoint JSON Schema (`logn-checkpoint-v1`)

```json
{
  "schema_version": "logn-checkpoint-v1",
  "checkpoint_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "source_id": "server-alpha",
  "start_sequence": 1,
  "end_sequence": 100,
  "event_count": 100,
  "merkle_root": "a3f8b1c2...",
  "merkle_leaf_hashes": [
    "e3b0c44298fc...",
    "2cf24dba5fb0..."
  ],
  "timestamp": "2026-11-20T11:00:00Z",
  "signing_key_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "signer_public_key": "d75a980182b1...",
  "signature": "e5564300c360...",
  "signature_algorithm": "Ed25519",
  "signature_input": "logn-checkpoint-v1",
  "blockchain": null
}
```

### Key Field Requirements (§5.2)
- `schema_version`: Must strictly be `"logn-checkpoint-v1"`.
- `event_count`: Must strictly equal $end\_sequence - start\_sequence + 1$.
- `merkle_leaf_hashes`: Must be an array of length `event_count` containing the exact `Log.currentHash` values in ascending sequence order.
- `merkle_root`: The SHA-256 Merkle root computed over `merkle_leaf_hashes` per §6.
- `signature`: 128 hex chars (64 bytes) Ed25519 signature.

---

## 3. Canonical Signing Payload (§5.3)

The signature is computed over a canonical serialization of the checkpoint document:
1. **Excluded fields**: Top-level `"signature"` and `"blockchain"` fields are excluded.
2. **Included fields**: All other fields (including `merkle_leaf_hashes`, `merkle_root`, `schema_version`, etc.) are retained.
3. **Deterministic serialization**: Serialized via `canonicalJson` (Unicode code point sorted keys, no whitespace, literal UTF-8).
4. **Signature**: Ed25519 signature computed over the UTF-8 bytes of the canonical JSON string.

This ensures that:
- Any modification to sequence numbers, roots, leaf hashes, or timestamps breaks the signature.
- The `blockchain` field can be attached in Phase 3 without invalidating the Phase 2 signature.

---

## 4. Verification Workflow (§9)

The verification engine (`security/src/verification/verifier.js` and `security/src/checkpoints/checkpointService.js`) independently evaluates checkpoints.

### Verification Status Codes

| Status Code | Condition |
|-------------|-----------|
| `VERIFIED` | All structural, Merkle, key provenance, and cryptographic checks succeeded. |
| `INVALID_CHECKPOINT` | Missing required fields, invalid schema version, or sequence range inconsistency. |
| `MERKLE_MISMATCH` | Recomputing the Merkle root over `merkle_leaf_hashes` does not equal `checkpoint.merkle_root`. |
| `UNKNOWN_SIGNING_KEY` | `signing_key_id` is not recognized by KeyManager or does not match `signer_public_key`. |
| `INVALID_SIGNATURE` | The Ed25519 signature over the canonical signing payload is invalid. |
| `INVALID_PROOF` | A Merkle inclusion proof does not evaluate to `checkpoint.merkle_root`. |
| `VERIFICATION_ERROR` | An unexpected exception occurred during evaluation. |

---

## 5. Defense Against Attack Scenarios

### How Signed Checkpoints Stop Chain Rewrites
In a database-only attack, an adversary with MongoDB write access could tamper with a log and rebuild `Log.currentHash` forward to recreate an internally consistent hash chain.

**Why that fails against Checkpoints**:
- The checkpoint commits to the Merkle root of the original logs and is signed with the private key.
- The attacker cannot produce a valid Ed25519 signature for the modified Merkle root without the private key.
- Auditors comparing MongoDB logs against signed checkpoints immediately detect the tamper condition as `MERKLE_MISMATCH`.
