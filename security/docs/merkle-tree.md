# Merkle Tree Specification & Engine

> **HHH SecureLog — Security Module (Phase 2)**  
> Reference: `docs/technical-integration-contract.md` §6

---

## 1. Overview & Purpose

A **Merkle tree** is a cryptographic data structure that summarizes an ordered list of transactions or events into a single 32-byte hash commitment: the **Merkle root**.

In HHH SecureLog, log events are ingested and linked into a per-source hash chain using the `LOGN-HASH-v1` formula. However, storing or verifying thousands of individual event hashes on an immutable blockchain or in external audit packages is prohibitively expensive and inefficient.

The Merkle tree solves this by:
1. **Compressing** a sequence window of $N$ authoritative log hashes (`Log.currentHash`) into a single 32-byte Merkle root (`merkle_root`).
2. **Enabling efficient verification**: Any single log event can be independently verified as part of the committed window using an **inclusion proof** of size $O(\log_2 N)$ hashes, without downloading or checking the other $N-1$ events.

---

## 2. Cryptographic Construction & Rules (§6)

The engine in `security/src/merkle/merkleTree.js` strictly adheres to the contract specification.

### 2.1 Domain Separation (§6.2)

To prevent **second-preimage attacks**—where an attacker could present an internal node hash as if it were a leaf node—all hashing uses strict single-byte domain prefixes:

- **Leaf Hash**:
  $$\text{Leaf}(h) = \text{SHA-256}(0\text{x}00 \mathbin{\Vert} \text{hex\_to\_bytes}(h))$$
  - Prefix byte: `0x00`
  - Input: 32 raw bytes of `Log.currentHash` (from the 64-character hex string)

- **Internal Node Hash**:
  $$\text{Node}(L, R) = \text{SHA-256}(0\text{x}01 \mathbin{\Vert} \text{hex\_to\_bytes}(L) \mathbin{\Vert} \text{hex\_to\_bytes}(R))$$
  - Prefix byte: `0x01`
  - Input: 32 raw bytes of left child followed by 32 raw bytes of right child

All resulting hashes are encoded as lowercase 64-character hexadecimal strings.

### 2.2 Odd-Node Handling (§6.4)

When any layer in the tree contains an odd number of nodes:
- The final unpaired node is **duplicated** and hashed with itself:
  $$\text{Parent} = \text{Node}(\text{Node}_{k}, \text{Node}_{k})$$
- This follows standard cryptographic conventions (e.g. Bitcoin) and produces a deterministic, reproducible root across implementations.

### 2.3 Empty Tree Behavior (§6.5)

If a tree is constructed from an empty array of hashes (e.g., zero logs in window):
$$\text{EMPTY\_TREE\_ROOT} = \text{SHA-256}(0\text{x}00) = \texttt{6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d}$$
This sentinel value is explicitly recognized by the verifier and guarded against submission to smart contracts.

### 2.4 Strict Input Ordering

The input array of `Log.currentHash` values must be ordered strictly ascending by `sequence_number`.
The Merkle engine **does not sort** incoming hashes. Reordering logs alters the tree geometry and produces a completely different Merkle root, preserving sequence integrity.

---

## 3. Inclusion Proofs (§6.6)

An inclusion proof demonstrates that a specific leaf exists in the tree committed by `merkle_root`.

### Proof Structure

```json
{
  "leaf_index": 2,
  "leaf_hash": "a1b2...",
  "proof": [
    { "sibling_hash": "c3d4...", "position": "right" },
    { "sibling_hash": "e5f6...", "position": "left" }
  ],
  "root": "9f8e..."
}
```

### Verification Algorithm

Given `currentHash`, `proof`, and `expectedRoot`:
1. Initialize $\text{current} = \text{Leaf}(currentHash)$.
2. For each step in `proof`:
   - If `position == "left"`: $\text{current} = \text{Node}(\text{sibling\_hash}, \text{current})$
   - If `position == "right"`: $\text{current} = \text{Node}(\text{current}, \text{sibling\_hash})$
3. Return `current == expectedRoot`.

---

## 4. API Reference

```javascript
import {
  buildMerkleTree,
  getMerkleRoot,
  generateMerkleProof,
  verifyMerkleProof,
  EMPTY_TREE_ROOT
} from './src/merkle/merkleTree.js';

// 1. Build tree
const hashes = ['e3b0c44298fc...', '2cf24dba5fb0...'];
const tree = buildMerkleTree(hashes);
const root = getMerkleRoot(tree);

// 2. Generate inclusion proof for leaf at index 1
const proof = generateMerkleProof(tree, 1);

// 3. Verify proof independently
const isValid = verifyMerkleProof(hashes[1], proof.proof, root);
// => true
```
