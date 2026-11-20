# Threat Model — HHH SecureLog Security Module

> **HHH SecureLog — Security + Blockchain Module**
> Reference: `docs/technical-integration-contract.md` §§1–9

This document analyses the threat landscape for the Security module's cryptographic guarantees.
For each threat we describe: what it is, what the system currently detects, its limitations, and
what cannot be guaranteed at each phase.

---

## Scope

This threat model covers the Security module's hash chain and (future phases) Merkle signatures
and blockchain anchoring. It does not cover network-layer threats, OS-level host compromise,
key theft via memory scraping, or supply-chain attacks on npm packages — these are out of scope
for the hackathon MVP and require infrastructure-level controls.

---

## Threat 1: Silent Log Modification After Ingest

**Description:**
An attacker (or a bug) modifies the content of a log event in MongoDB after the event was
ingested by the backend — for example, changing `message`, `severity`, `metadata`, or any other
field.

**What the system detects (Phase 1):**
Any modification to any of the 9 LOGN-HASH-v1 fields changes the event's LOGN-HASH-v1 hash.
Since `hashLogEvent` recomputes the hash deterministically, `verifyHashChain` will detect a
mismatch between the recomputed hash and `Log.currentHash` at the tampered event's index.

**Limitation:**
If the attacker also updates `Log.currentHash` and rebuilds the entire chain forward from that
point (a "consistent rewrite"), Phase 1 alone cannot detect this — both the stored and
recomputed hashes will match because the attacker controls both.

**What closes this gap (Phases 2–4):**
Ed25519 signatures on checkpoint Merkle roots (Phase 2) and on-chain anchoring (Phase 3).
The Merkle root is committed to an immutable blockchain; rebuilding the chain would require
changing the Merkle root, which cannot be changed on-chain without a new transaction
(which would be auditable).

---

## Threat 2: Event Deletion

**Description:**
An attacker deletes one or more log events from MongoDB to remove evidence of an incident.

**What the system detects (Phase 1):**
`verifyHashChain` checks that sequence numbers are strictly consecutive. A deleted event creates
a sequence number gap, which is reported as an error. The broken `previous_hash` link (the event
after the gap references the deleted event's hash) is also reported.

**Limitation:**
If the attacker deletes the most recent events (tail of the chain, after the last checkpoint),
detection requires knowing the expected final `sequence_number`. Without an external reference
(e.g., an on-chain commitment to the sequence range), the system cannot distinguish "genuine
end of sequence" from "tail deletion."

**What closes this gap (Phase 3):**
On-chain checkpoints commit to `endSequence`. An auditor can query the chain to find the
expected `endSequence` and verify the MongoDB event count matches.

---

## Threat 3: Event Insertion (Log Injection)

**Description:**
An attacker inserts a fabricated log event into the middle of the sequence to establish a false
alibi or frame an action as legitimate.

**What the system detects (Phase 1):**
Insertion shifts all subsequent sequence numbers and breaks the `previous_hash` chain link at
the insertion point. `verifyHashChain` will report both a sequence gap (or duplicate) and a
broken chain link.

**Limitation:**
If the attacker inserts the event AND renumbers and re-hashes all subsequent events (a full
consistent rewrite after the insertion point), Phase 1 cannot detect this.

**What closes this gap (Phases 2–4):**
Signed checkpoints with Merkle roots committed on-chain. The original Merkle root (anchored
before the attack) will not match the recomputed Merkle root over the modified sequence.

---

## Threat 4: Event Reordering

**Description:**
An attacker swaps the order of two or more log events to alter the apparent sequence of actions
(e.g., to make an unauthorized access appear to have preceded an authorization grant).

**What the system detects (Phase 1):**
Each event's `previous_hash` refers to the hash of the event that actually preceded it.
Swapping events breaks the `previous_hash` → `current_hash` link at the swap points.
`verifyHashChain` reports these as broken chain link errors.

**Limitation:**
Reordering AND rebuilding all hashes from the first swapped position onward is a consistent
rewrite — not detectable by Phase 1 alone.

**What closes this gap (Phases 2–4):**
On-chain Merkle root commitment. The Merkle tree is built over events in `sequence_number`
order; reordering changes the Merkle root, which cannot be retroactively changed on-chain.

---

## Threat 5: Consistent Chain Rebuild (Full Rewrite Attack)

**Description:**
An attacker with write access to MongoDB modifies any number of log events, then recomputes
and updates `Log.currentHash` for all affected events, rebuilding a fully consistent chain.
The attacker also updates `Source.lastHash` to the new chain tip. The result passes all Phase 1
checks.

**What the system detects (Phase 1):**
**Nothing.** Phase 1's hash chain only verifies internal consistency. It does not verify
authenticity or protect against an attacker who can write to both event fields and hash fields.

**What closes this gap (Phases 2–4):**
This is the primary motivation for Ed25519 signatures and on-chain anchoring:

- **Phase 2:** Each checkpoint is signed with the Security service's private Ed25519 key.
  The signature covers the canonical checkpoint payload including the Merkle root.
  The private key is stored in an encrypted file (`signing_key.enc`, AES-256-GCM, scrypt KDF)
  and is never committed to Git. An attacker who cannot exfiltrate the decrypted private key
  cannot forge a valid signature for a rewritten chain.

- **Phase 3:** The Merkle root is anchored on an EVM chain. Even if the attacker forges a
  signature (by stealing the private key), the on-chain Merkle root (written before the attack)
  will not match the recomputed Merkle root over the modified data. On-chain data is immutable.

**Residual risk:**
If the attacker steals the signing key AND has write access to MongoDB AND the checkpoint was
not yet anchored on-chain, a full consistent rewrite with a valid signature is theoretically
possible. Key storage hardening (HSM, remote signing service) is out of scope for the hackathon.

---

## Threat 6: Key Compromise (Phase 2+ Threat)

**Description:**
An attacker obtains the Ed25519 private key (e.g., by reading `signing_key.enc` and the
`LOGN_KEY_PASSPHRASE` environment variable, or via a process memory dump).

**What the system detects (Phase 2):**
Nothing — a compromised key allows the attacker to sign forged checkpoints with a valid
signature that passes `crypto.verify`.

**Mitigation (design, not yet implemented):**
- `signing_key.enc` is AES-256-GCM encrypted with a scrypt-derived key from `LOGN_KEY_PASSPHRASE`
- The passphrase is injected via environment variable — never stored in source-controlled files
- File permissions: `signing_key.enc` → mode `0600` (owner read/write only)
- Key rotation: generate a new key pair, publish the new `signing_key.pub` and `key_id.txt`,
  keep old public key in `SecurityConfig` collection for historical checkpoint verification
- For the hackathon: document passphrase in a team password manager (e.g. shared `.env.local`)

**What cannot be guaranteed:**
If the host OS is fully compromised (root access), no software-only key protection is sufficient.
HSM-backed key storage is out of scope.

---

## Threat 7: Blockchain Transaction Manipulation (Phase 3+ Threat)

**Description:**
An attacker attempts to modify, replace, or suppress the on-chain checkpoint commitment —
for example, by front-running the transaction, exploiting the smart contract, or using a
compromised RPC endpoint.

**What the system provides (Phase 3 design):**
- `SecureLogAnchor` contract rejects duplicate `checkpointId` submissions (revert on duplicate)
- Only the designated `ANCHOR_ROLE` address can anchor checkpoints (access control)
- `BlockchainService` waits for transaction confirmation before recording `blockNumber`
- For the hackathon: local EVM chain (Hardhat/Ganache) — no real economic incentive for miners

**Limitation:**
On a local development chain, the "immutability" guarantee is as strong as the chain configuration.
On a public testnet (Phase 3+), Ethereum's immutability guarantees apply after sufficient
block confirmations (typically 12 for finality on PoS Ethereum).

**What cannot be guaranteed (hackathon scope):**
Chain reorganization attacks, 51% attacks, and RPC endpoint compromise are out of scope for the
local EVM development environment.

---

## Threat 8: Cross-Module Hash Formula Divergence

**Description:**
The backend (Node.js), storage (Python), and security modules each independently compute
log hashes. If they use different field sets, sorting rules, or encoding settings, the same
logical event will produce different hashes in different modules, breaking cross-module
verification.

**What the contract defines:**
LOGN-HASH-v1 (§1.3 of the integration contract) specifies an exact field set, sort order,
serialization rules, and encoding. It includes a worked test vector (§1.3.5) with an exact
canonical string that all implementations must reproduce identically.

**What the system detects:**
If implementations diverge, `verifyHashChain` will consistently report hash mismatches for
all events — a distinctive pattern that immediately indicates a serialization mismatch rather
than data tampering.

**Limitation:**
Divergence is only discovered at integration time. The integration contract (§1.3.5) requires
all teams to run the exact test vector through their implementations during integration testing
and confirm identical output. This has not yet been executed across all three modules.

**Integration requirement (marked as pending):**
Teams must run the §1.3.5 test vector in both Node.js (this module) and Python (storage module)
and confirm bit-identical SHA-256 output before treating LOGN-HASH-v1 as ratified.
Until this cross-module test passes, LOGN-HASH-v1 is **PROPOSED**, not confirmed.

---

## Summary Matrix

| Threat | Phase 1 | Phase 2 | Phase 3 | Phase 4 |
|--------|---------|---------|---------|---------|
| Field modification | ✅ Detected | ✅ | ✅ | ✅ |
| Event deletion (mid-chain) | ✅ Detected | ✅ | ✅ | ✅ |
| Event deletion (tail) | ⚠️ Partial | ✅ | ✅ | ✅ |
| Event insertion | ✅ Detected | ✅ | ✅ | ✅ |
| Event reordering | ✅ Detected | ✅ | ✅ | ✅ |
| Consistent chain rebuild | ❌ Undetected | ✅ Signatures | ✅ On-chain | ✅ |
| Key compromise | N/A | ⚠️ KDF mitigated | ⚠️ | ✅ HSM (future) |
| Smart contract exploit | N/A | N/A | ⚠️ Access ctrl | ✅ Audit |
| Hash formula divergence | ⚠️ Needs integration test | ⚠️ | ⚠️ | ✅ E2E test |

**Legend:** ✅ Addressed · ⚠️ Partially mitigated / requires action · ❌ Not addressed · N/A Not applicable
