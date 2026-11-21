# Adaptive Forward-Secure Logging Technical Specification

## 1. Problem Statement & Threat Model

In traditional log signing systems, an adversary who compromises the system's private signing key gains the ability to:
1. Forge past audit logs to conceal initial access or privilege escalation.
2. Re-sign modified checkpoints to forge a counterfeit history.
3. Retroactively alter security telemetry without detection.

### The Forward-Secure Guarantee

**A compromise of the currently active signing state must not enable an attacker to forge signatures for previously completed and retired epochs.**

```
Epoch 0 (Retired) ───▶ Epoch 1 (Retired) ───▶ Epoch 2 (ACTIVE) ───▶ Epoch 3 (Future)
  [Keys Destroyed]       [Keys Destroyed]       [Compromised!]         [Attacker Can Sign]
  [Cannot Forge!]        [Cannot Forge!]        
```

---

## 2. Malkin-Katz-Salil (MKT-FSS) Tree Construction

HHH implements a tree-based forward-secure signature scheme based on Malkin, Katz, and Salil (2002):

1. **Master Public Key (MPK):** The root of a binary Merkle tree of depth $D = \log_2(T)$, where $T$ is the maximum number of epochs (default 1024).
2. **Epoch Keys:** Each epoch $t \in [0, T-1]$ has a dedicated keypair $(esk_t, epk_t)$.
3. **Key Derivation:** Epoch secret keys are derived through forward-ratcheting pseudo-random functions (HKDF-SHA256).
4. **Authentication Path:** Each signature in epoch $t$ includes the Merkle authentication path proving that $epk_t$ is the $t$-th leaf of the tree rooted at MPK.
5. **Secure State Evolution:** When moving from epoch $t$ to $t+1$, the secret key material for epoch $t$ is cryptographically wiped using zero-fill buffer overwrites (`buffer.fill(0)`).

---

## 3. Schema & Canonical Signing Input

### Forward-Secure Checkpoint Schema (`logn-checkpoint-fss-v1`)

```json
{
  "schema_version": "logn-checkpoint-fss-v1",
  "checkpoint_id": "chk-1732176000-01",
  "source_id": "workstation-dc-alpha",
  "start_sequence": 1,
  "end_sequence": 50,
  "event_count": 50,
  "chain_head_hash": "6e7b1fc824ee557d9d5f19ef4269cfebec855b8e53fe08ed3ec168a73d61e97e",
  "merkle_root": "8a3d5b2c7e1f4092b6a7c8e9f0123456789abcdef0123456789abcdef0123456",
  "merkle_leaf_hashes": [ "..." ],
  "merkle_tree_algorithm": "HHH-CONTRACT-DUP-v1",
  "fss_epoch": 2,
  "mpk": "d4e5f6...",
  "epoch_public_key": "a1b2c3...",
  "fss_auth_path": [ "..." ],
  "fss_signature": "...",
  "timestamp": "2026-11-20T10:15:00Z",
  "signature_algorithm": "Ed25519-MKT-FSS",
  "signature_input": "...",
  "signature": "..."
}
```

---

## 4. Emergency Revocation Protocol

When a compromise is suspected or detected:
1. An administrator issues an emergency revocation notice:
   ```json
   {
     "schema_version": "logn-fss-revocation-v1",
     "compromiseEpoch": 2,
     "mpk": "d4e5f6...",
     "declared_at": "2026-11-20T10:20:00Z",
     "reason": "Host memory dump indicates active key material extracted."
   }
   ```
2. The verification engine enforces a strict revocation boundary:
   - All checkpoints signed in epochs $t < 2$ remain **mathematically VALID**.
   - All checkpoints signed in epochs $t \ge 2$ are flagged as **REVOKED**.
3. Zero key regeneration occurs: the platform preserves honest history and refuses to overwrite historical states.
