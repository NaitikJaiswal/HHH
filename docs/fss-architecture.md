# Forward-Secure Signature (FSS) Architecture Specification
## Adaptive Epoch Signing, Key Evolution, and Adversarial Defense Model

**Document ID:** HHH-SPEC-FSS-v1  
**Status:** Authoritative Architectural Specification  
**Phase:** Phase 3 (Cryptographic Foundation)  
**Security Level:** High / Defense-in-Depth  

---

## 1. Scheme Identification & Academic Citations

The forward-secure signature architecture in HHH is specified as **Merkle Key Tree Forward-Secure Signatures (MKT-FSS)** with **HMAC-SHA256 Evolution over Ed25519 (RFC 8032)**.

### Academic and Standard Foundations
1. **Bellare & Miner (1999):** *"A Forward-Secure Digital Signature Scheme"*, Advances in Cryptology — CRYPTO '99, LNCS 1666, pp. 271–289. Established the formal security definition of forward security for digital signatures ($\text{FS-EUF-CMA}$) and the finite-epoch tree reduction.
2. **Malkin, Micciancio, & Miner (2002):** *"Efficient Generic Forward-Secure Signatures with an Unbounded Number of Time Periods"*, Advances in Cryptology — EUROCRYPT 2002, LNCS 2332, pp. 400–417. Defined tree-based multi-period forward-secure constructions (MMM scheme) and optimal secret-state amortizations.
3. **Merkle (1989):** *"A Certified Digital Signature"*, Advances in Cryptology — CRYPTO '89, LNCS 435. Formalized authenticated binary hash trees for authenticating arbitrary sets of public keys under a single compact root.
4. **RFC 8032:** *"Edwards-Curve Digital Signature Algorithm (Ed25519)"*, IETF, 2017. Provides deterministic, high-performance, non-malleable signatures resistant to side-channel timing attacks.
5. **RFC 6962:** *"Certificate Transparency"*, IETF, 2013. Defines domain-separated binary Merkle trees (`0x00` leaf prefix, `0x01` interior node prefix) preventing second-preimage length-extension vulnerabilities.
6. **RFC 2104 / FIPS 198-1:** *"Keyed-Hash Message Authentication Code (HMAC-SHA256)"*, ensuring pseudorandom function (PRF) forward irreversibility.

---

## 2. Key Generation & Master Public Key (MPK)

### Parameters
- **Maximum Lifetime Epochs:** $T = 2^D$ (e.g., $D=10, T=1024$ or configurable system deployment parameter $T \in [2, 65536]$).
- **Cryptographic Primitives:**
  - Seed length: $\lambda = 256$ bits (32 bytes).
  - Tree Hash: SHA-256 with RFC 6962 domain prefixes.
  - Signature Algorithm: Pure Ed25519 (Edwards curve 25519, Curve25519).

### Master Generation Algorithm (`MKT-FSS-KeyGen(T)`)
1. Sample root master seed cryptographically:
   $$K_0 \stackrel{\$}{\leftarrow} \{0, 1\}^{256}$$
2. For each epoch index $j \in \{0, 1, \dots, T-1\}$:
   - Derive the epoch private signing key seed:
     $$sk_j = \text{HMAC-SHA256}(K_j, \text{"HHH-FSS-SIGNING-KEY"})$$
   - Derive the Ed25519 public key corresponding to $sk_j$:
     $$pk_j = \text{Ed25519-ExtractPublic}(sk_j) \in \{0, 1\}^{256}$$
   - Compute the domain-separated Merkle leaf hash:
     $$\text{Leaf}_j = \text{SHA256}\left( 0x00 \parallel \text{uint32BE}(j) \parallel pk_j \right)$$
   - Evolve the state seed for the subsequent epoch:
     $$K_{j+1} = \text{HMAC-SHA256}(K_j, \text{"HHH-FSS-EVOLVE-EPOCH"})$$
3. Compute the binary Merkle root $MPK$ over the ordered array $[\text{Leaf}_0, \text{Leaf}_1, \dots, \text{Leaf}_{T-1}]$ using RFC 6962 interior hashing:
   $$\text{Node}(A, B) = \text{SHA256}\left( 0x01 \parallel A \parallel B \right)$$
4. The **Master Public Key ($MPK$)** is defined as the 32-byte Merkle root:
   $$MPK = \text{MerkleRoot}\left( \text{Leaf}_0, \dots, \text{Leaf}_{T-1} \right)$$
5. The public commitment tuple is published to immutable storage:
   $$\mathcal{P}_{\text{public}} = \left( \text{version: "HHH-MKT-FSS-v1"}, MPK, T, \text{createdAt} \right)$$
6. Initial secret state for Epoch 0:
   $$SK_0 = \left( t=0, K_0, \text{AuthPath}_0 \right)$$
   where $\text{AuthPath}_0$ is the sibling audit path from $\text{Leaf}_0$ to $MPK$. All derived future keys $K_{j>0}$ and $sk_{j}$ are discarded immediately during initialization or derived sequentially at runtime, retaining strictly $SK_0$.

---

## 3. Key Evolution ($SK_t \to SK_{t+1}$)

Key evolution is an irreversible one-way state transition performed at the end of epoch $t$.

### Evolution Procedure (`MKT-FSS-Evolve`)
Given active state $SK_t = (t, K_t, \text{AuthPath}_t)$:
1. Verify $t + 1 < T$. (If $t + 1 \ge T$, the system has reached terminal lifetime and must transition to sealed retirement).
2. Calculate the next epoch seed using the PRF one-way ratchet:
   $$K_{t+1} = \text{HMAC-SHA256}(K_t, \text{"HHH-FSS-EVOLVE-EPOCH"})$$
3. Compute the next authentication path $\text{AuthPath}_{t+1}$.
4. Construct the new secret state:
   $$SK_{t+1} = \left( t + 1, K_{t+1}, \text{AuthPath}_{t+1} \right)$$
5. **Atomic State Swap:**
   - Write $SK_{t+1}$ to a temporary file `fss_state.tmp.<uuid>` with POSIX `0o600` permissions.
   - Force file synchronization (`fsync`).
   - Atomically replace active file `fss_state.json` via POSIX `rename()`.
6. **Active Erasure:**
   - Overwrite $K_t$ buffer in memory with zero bytes (`Buffer.fill(0)`).
   - Overwrite ephemeral $sk_t$ buffer with zero bytes.
   - Trigger garbage collection hinting where supported.

### Mathematical One-Way Guarantee
Let $\mathcal{H}_K(m) = \text{HMAC-SHA256}(K, m)$.
Reversing an evolved state $K_{t+1}$ to obtain $K_t$ requires finding a key $K$ such that $\mathcal{H}_K(\text{"HHH-FSS-EVOLVE-EPOCH"}) = K_{t+1}$.
Under the assumption that HMAC-SHA256 is a secure Pseudorandom Function (PRF) and preimage-resistant hash function family:
$$\mathbf{Adv}_{\text{HMAC-SHA256}}^{\text{preimage}}(2^{256}) \le \frac{q}{2^{256}} \approx 0$$
Hence, discovery of $K_t$ given $K_{t+1}$ is computationally intractable. Knowledge of $SK_{t+1}$ provides zero cryptographic advantage in recovering $sk_0, sk_1, \dots, sk_t$.

---

## 4. Epoch Signing Algorithm

For an event, batch, or checkpoint payload $M$ generated during epoch $t$:

1. Ensure the current operational state is $t$ and status is not revoked or frozen.
2. Derive the active epoch signing key:
   $$sk_t = \text{HMAC-SHA256}(K_t, \text{"HHH-FSS-SIGNING-KEY"})$$
3. Derive public key $pk_t = \text{Ed25519-ExtractPublic}(sk_t)$.
4. Construct the canonical signing envelope:
   $$E_t = \text{SHA256}\left( \text{"HHH-FSS-EPOCH-SIG"} \parallel \text{uint32BE}(t) \parallel pk_t \parallel \text{Canonical}(M) \right)$$
5. Sign $E_t$ using the derived private key $sk_t$:
   $$\sigma_{\text{raw}} = \text{Ed25519-Sign}(sk_t, E_t)$$
6. Zeroize $sk_t$ in working memory immediately after signing:
   $$\text{Buffer.fill}(sk_t, 0)$$
7. Assemble the complete Forward-Secure Signature object $\Sigma_t$:
   $$\Sigma_t = \begin{cases}
     \text{version}: & \text{"HHH-MKT-FSS-v1"} \\
     \text{epoch}: & t \\
     \text{public\_key}: & \text{hex}(pk_t) \\
     \text{raw\_signature}: & \text{hex}(\sigma_{\text{raw}}) \\
     \text{auth\_path}: & [\text{hex}(h_1), \dots, \text{hex}(h_D)] \\
     \text{mpk}: & \text{hex}(MPK)
   \end{cases}$$

---

## 5. Public Verification Algorithm

The verifier requires **only** the root $MPK$ and the public signature object $\Sigma_t$. No private keys, secrets, or server interactions are required.

### Verification Steps (`MKT-FSS-Verify(MPK, M, \Sigma_t)`)
1. **Range Validation:**
   Verify that $0 \le \Sigma_t.\text{epoch} < T$. If false $\to$ `FAIL(INVALID_EPOCH_RANGE)`.
2. **Payload Envelope Reconstruction:**
   Let $t = \Sigma_t.\text{epoch}$, $pk_t = \text{parseHex}(\Sigma_t.\text{public\_key})$.
   Recompute $E_t = \text{SHA256}\left( \text{"HHH-FSS-EPOCH-SIG"} \parallel \text{uint32BE}(t) \parallel pk_t \parallel \text{Canonical}(M) \right)$.
3. **Signature Cryptographic Verification:**
   Verify $\sigma_{\text{raw}}$ on $E_t$ using public key $pk_t$ via Ed25519:
   $$\text{Valid} = \text{Ed25519-Verify}(pk_t, E_t, \sigma_{\text{raw}})$$
   If $\text{Valid} = \text{false} \to$ `FAIL(INVALID_SIGNATURE)`.
4. **Leaf Computation:**
   Compute the Merkle leaf hash for epoch $t$:
   $$\text{Leaf}_t = \text{SHA256}\left( 0x00 \parallel \text{uint32BE}(t) \parallel pk_t \right)$$
5. **Merkle Path Evaluation:**
   Compute the candidate root $R$ starting from $\text{Leaf}_t$, hashing upward with sibling hashes in $\Sigma_t.\text{auth\_path}$ using RFC 6962 interior node rules:
   $$\text{Parent} = \text{SHA256}\left( 0x01 \parallel \text{Left} \parallel \text{Right} \right)$$
6. **Root Authentication:**
   Verify that $R == MPK$:
   If $R \ne MPK \to$ `FAIL(MERKLE_PATH_MISMATCH)`.
7. Return `PASS`.

---

## 6. Security Proof Sketch / Reduction

### Formal Security Model: $\text{FS-EUF-CMA}$
We model forward security via the standard game between Challenger $\mathcal{C}$ and Adversary $\mathcal{A}$:
1. **Setup:** $\mathcal{C}$ executes $\text{KeyGen}(T)$, delivers $MPK$ to $\mathcal{A}$, and initializes $t \leftarrow 0$.
2. **Queries:**
   - $\mathcal{A}$ may adaptively query signatures $\text{Sign}(M)$ on chosen messages for epoch $t$.
   - $\mathcal{A}$ may trigger epoch evolution $\text{Evolve}()$ advancing $t \leftarrow t + 1$.
3. **Break-In Query:** At an epoch $t^* \in [0, T-1]$ chosen by $\mathcal{A}$, $\mathcal{A}$ calls $\text{BreakIn}(t^*)$.
   $\mathcal{C}$ discloses the current active secret state $SK_{t^*}$.
4. **Forgery Phase:** $\mathcal{A}$ wins if it outputs a valid forgery $(t_{\text{forge}}, M^*, \Sigma^*)$ such that:
   - $t_{\text{forge}} < t^*$ (retroactive forgery).
   - $M^*$ was never submitted to $\text{Sign}$ during epoch $t_{\text{forge}}$.
   - $\text{Verify}(MPK, M^*, \Sigma^*) == \text{PASS}$.

### Reduction to Standard Cryptographic Assumptions
Suppose $\mathcal{A}$ breaks $\text{FS-EUF-CMA}$ with non-negligible probability $\epsilon$.
$\Sigma^*$ contains $(t_{\text{forge}}, pk^*, \sigma^*, \text{AuthPath}^*)$.
We distinguish two exhaustive cases:

- **Case 1: $pk^* \ne pk_{t_{\text{forge}}}$**  
  Because $\text{Verify}(MPK, \dots) == \text{PASS}$, the leaf $\text{SHA256}(0x00 \parallel t_{\text{forge}} \parallel pk^*)$ along with $\text{AuthPath}^*$ evaluates to $MPK$.
  However, the tree committed during $\text{KeyGen}$ already contains leaf $\text{SHA256}(0x00 \parallel t_{\text{forge}} \parallel pk_{t_{\text{forge}}})$ at index $t_{\text{forge}}$.
  Since $pk^* \ne pk_{t_{\text{forge}}}$, these leaves are distinct. A matching root $MPK$ implies finding a collision or second preimage in SHA-256.
  $$\Pr[\text{Case 1}] \le \mathbf{Adv}_{\text{SHA256}}^{\text{CR}}$$

- **Case 2: $pk^* == pk_{t_{\text{forge}}}$**  
  Here $\mathcal{A}$ has produced a valid Ed25519 signature $\sigma^*$ under public key $pk_{t_{\text{forge}}}$ for message $M^*$.
  $\mathcal{A}$ was given $SK_{t^*} = (t^*, K_{t^*}, \text{AuthPath}_{t^*})$ where $t^* > t_{\text{forge}}$.
  To forge under $pk_{t_{\text{forge}}}$, $\mathcal{A}$ must either:
  1. Forge an Ed25519 signature without knowing $sk_{t_{\text{forge}}}$ (breaking EUF-CMA of Ed25519), or
  2. Compute $sk_{t_{\text{forge}}}$ or $K_{t_{\text{forge}}}$ given $K_{t^*}$.
  Because each epoch seed is evolved via $K_{j+1} = \text{HMAC-SHA256}(K_j, \text{"HHH-FSS-EVOLVE-EPOCH"})$, inverting this chain back $t^* - t_{\text{forge}}$ steps requires computing the preimage of the HMAC-SHA256 PRF.
  $$\Pr[\text{Case 2}] \le \mathbf{Adv}_{\text{Ed25519}}^{\text{EUF-CMA}} + \mathbf{Adv}_{\text{HMAC-SHA256}}^{\text{PRF}}$$

Combining cases:
$$\mathbf{Adv}_{\text{HHH-MKT-FSS}}^{\text{FS-EUF-CMA}} \le \mathbf{Adv}_{\text{SHA256}}^{\text{CR}} + \mathbf{Adv}_{\text{Ed25519}}^{\text{EUF-CMA}} + \mathbf{Adv}_{\text{HMAC-SHA256}}^{\text{PRF}} \le \text{negl}(\lambda)$$

Past completed epochs $0 \le t < t^*$ are provably protected against retroactive forgery.

---

## 7. Threat Model & Boundaries

To provide rigorous security guarantees, the protective boundaries are explicitly defined:

### What IS Protected
1. **Past Epoch Immutability ($0 \le t < t^*$):**
   Even under full host compromise at epoch $t^*$ where the attacker gains root shell, kernel privileges, and dumps disk/RAM, the attacker cannot forge valid signatures, alter log entries, or tamper with checkpoints in epochs $0 \le t < t^*$ without failing $MPK$ cryptographic verification.
2. **Epoch Isolation:**
   Compromising key state $K_{t^*}$ does not compromise cryptographic secrets from earlier epochs.
3. **Tail Truncation Detection:**
   Any attempt to truncate the tail of the log is detected once a signed checkpoint for epoch $t$ has been observed by a verifier or anchored to the blockchain.

### What is NOT Protected (Explicit Cryptographic Limits)
1. **Active and Future Epochs ($t \ge t^*$):**
   Once the attacker compromises the host at epoch $t^*$, they possess $SK_{t^*}$. They can sign fraudulent logs during epoch $t^*$ and evolve forward to $t^*+1, \dots, T-1$.
2. **Pre-Ingestion Log Dropping:**
   An attacker who controls the host can intercept or drop logs in memory before they are appended to the hash chain or signed by the FSS module.
3. **Denial of Service (DoS):**
   An attacker with root access can delete the log files, erase the key state, or corrupt the disk. Forward security guarantees *detectability of tampering*, not high availability against root destruction.
4. **Hardware/Cold-Boot Attacks on Active Key:**
   While epoch $t$ is active, $K_t$ resides in volatile memory. Physical RAM extraction during epoch $t$ reveals $SK_t$.
5. **Runtime Memory Limitations (V8/Node.js):**
   In garbage-collected environments (Node.js/V8), strings and objects may be duplicated during memory compaction. While raw cryptographic buffers are overwritten with `0x00`, residual memory copies in V8 heap cannot be guaranteed fully wiped without operating-system-level page locking (`mlock`).

---

## 8. Adaptive Epoch Policy & State Transitions

The system implements an **Adaptive Risk Policy Controller** regulating epoch lifespan based on real-time operational risk signals.

```
       [ Normal Operations ]
           (Epoch: 8 hours)
                 │
                 │ Anomaly Detected
                 │ (Auth burst, sequence gap, SOC alert)
                 ▼
      [ Elevated-Risk Mode ]
           (Epoch: 5 minutes)
          * Eager Evolution *
                 │
       ┌─────────┴─────────┐
       │                   │
  Cooldown Cleared    Confirmed Intrusion
  (30m no anomalies)       │
       │                   ▼
       ▼          [ Suspected Compromise /
  [ Normal Mode ]        Emergency ]
                  * Freeze & Revoke *
```

### Policy Modes
| Mode | Configured Epoch Lifespan | Trigger Condition | Evolution Behavior |
| :--- | :--- | :--- | :--- |
| **NORMAL** | **8 hours** (28,800 s) | Default baseline operating state | Scheduled timer expiration |
| **ELEVATED** | **5 minutes** (300 s) | Anomaly burst, sequence error, high entropy | **Immediate eager evolution** upon entry, then 5m intervals |
| **EMERGENCY** | **0 (Halted)** | Verified root intrusion or manual revocation | **Immediate key zeroization**, signing halted |

### Anomaly Triggers
1. **Authentication Burst:** $\ge 5$ authentication failures within a 60-second sliding window.
2. **Hash-Chain Anomaly:** Any detected gap, duplicate sequence number, or invalid hash link.
3. **SOC / Admin Signal:** Explicit operator escalation via authenticated API.
4. **Log Flow Anomaly:** Sudden drop or surge exceeding $5\times$ rolling standard deviation.

### Eager Evolution Principle
When transitioning from `NORMAL` to `ELEVATED`, the system **does not merely shorten the subsequent timer**. It immediately forces an **eager evolution** ($SK_t \to SK_{t+1}$). This ensures that any suspicious activity observed during the elevated window is cryptographically isolated in a separate, narrow epoch key.

### Anti-Oscillation (Hysteresis)
To prevent thrashing between modes under noisy conditions:
- Transition from `NORMAL` $\to$ `ELEVATED` occurs immediately upon trigger.
- Transition from `ELEVATED` $\to$ `NORMAL` requires an unbroken **Cooldown Period of 30 minutes** with zero anomalies.
- Epoch index $t$ is strictly monotonic and never decrements.

---

## 9. State Lifecycle, Storage & Rollback Protection

### Key State File Architecture
The private state is stored in `keys/fss_state.json`:
```json
{
  "version": "HHH-MKT-FSS-STATE-v1",
  "epoch": 42,
  "seed_hex": "4a7f...",
  "auth_path": ["..."],
  "mpk": "9b12...",
  "max_epochs": 1024,
  "last_evolved_at": "2026-11-21T04:00:00Z",
  "state_checksum": "a82c..."
}
```

### Protection Mechanisms
1. **POSIX File Permissions:** Key state directory enforced at `0o700`; state file enforced at `0o600`.
2. **Atomic Writes:** Written via temporary file nonces (`fss_state.tmp.<uuid>`), synced to physical storage via `fsync()`, and renamed via atomic `rename()`.
3. **Rollback Attack Defense:**
   - **Monotonic Sequence Enforcement:** The system maintains an in-memory high-water mark $t_{\text{max}}$. Any loaded state file where $t_{\text{file}} < t_{\text{max}}$ is immediately rejected as a rollback attempt (`STATE_ROLLBACK_DETECTED`).
   - **External Checkpoint Witnessing:** Every published checkpoint contains epoch $t$. External verifiers and blockchain anchors reject any signature bearing an epoch $t \le t_{\text{witnessed\_final}}$.
4. **Volatile Scrubbing:** Ephemeral seed buffers are scrubbed immediately after deriving keys using `secretScrubber` utilities.

---

## 10. Suspected Compromise & Revocation Architecture

If a compromise is detected or suspected at epoch $t^*$:

### Emergency Response Workflow
1. **Immediate Execution Freeze:** The policy controller transitions state to `EMERGENCY`. All active signing routines reject further jobs.
2. **Local Key Annihilation:**
   - Active secret file `fss_state.json` is overwritten with random entropy, then zero bytes, then unlinked (`rm`).
   - In-memory key handles are overwritten with `Buffer.fill(0)`.
3. **Revocation Object Construction:**
   A cryptographically authenticated revocation record is broadcast:
   ```json
   {
     "type": "HHH-REVOCATION-NOTICE",
     "version": "v1",
     "mpk": "<MasterPublicKey>",
     "compromise_epoch": 45,
     "revocation_timestamp": "2026-11-21T04:45:00Z",
     "reason": "Host integrity violation detected by policy controller",
     "evidence_checkpoint_hash": "<LastValidCheckpointHash>"
   }
   ```
4. **Verification Impact:**
   - **Epochs $0 \le t < t^*$:** Fully trusted. All historical checkpoints remain cryptographically valid and unalterable.
   - **Epochs $t \ge t^*$:** Formally rejected by all verifiers and audit tools.
5. **Trusted Recovery:**
   - Re-keying **must never take place on the compromised host**.
   - A new clean server is provisioned out-of-band.
   - A fresh key pair $(MPK_{\text{new}}, SK_0)$ is initialized.
   - The genesis event of the recovered chain links the final valid checkpoint hash from $t^*-1$, creating an unbroken forensic provenance.
