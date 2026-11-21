/**
 * @module merkleTree
 * @description Merkle tree construction and proof generation/verification.
 *
 * Implements the exact algorithm specified in:
 *   docs/technical-integration-contract.md §6
 *
 * Key design decisions (per contract):
 *   - Input: ordered array of Log.currentHash hex-64 strings (authoritative chain hashes)
 *   - Leaf encoding:     SHA-256(0x00 || hexToBytes(currentHash))   — domain tag 0x00
 *   - Internal nodes:   SHA-256(0x01 || hexToBytes(left) || hexToBytes(right)) — domain tag 0x01
 *   - Odd-node rule:    last node in a layer is duplicated (paired with itself)
 *   - Empty tree root:  SHA-256(0x00) = "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
 *   - All results are lowercase hex-64 strings
 *
 * Domain separation between leaf and internal nodes prevents second-preimage
 * attacks where an internal node could be mistaken for a leaf hash.
 */

import { createHash } from 'node:crypto';

// ── Constants ─────────────────────────────────────────────────────────────────

/**
 * Domain tag for leaf nodes (single byte 0x00).
 * @type {Buffer}
 */
const LEAF_TAG = Buffer.from([0x00]);

/**
 * Domain tag for internal nodes (single byte 0x01).
 * @type {Buffer}
 */
const NODE_TAG = Buffer.from([0x01]);

/**
 * Standard Merkle tree schema version.
 * @type {string}
 */
export const MERKLE_SCHEMA_VERSION = 'logn-merkle-v1';

/**
 * Cryptographic hash algorithm used for Merkle tree construction.
 * @type {string}
 */
export const MERKLE_HASH_ALGORITHM = 'SHA-256';

/**
 * The Merkle root for an empty set of leaves.
 * Per §6.5: SHA-256(0x00) = "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
 *
 * @type {string}
 */
export const EMPTY_TREE_ROOT = computeSha256hex(LEAF_TAG);

// ── Low-level helpers ─────────────────────────────────────────────────────────

/**
 * Compute SHA-256 of a Buffer and return lowercase hex-64.
 *
 * @param {Buffer} buf
 * @returns {string}
 */
function computeSha256hex(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

/**
 * Convert a 64-character lowercase hex string to a 32-byte Buffer.
 *
 * @param {string} hex - 64-char hex string.
 * @returns {Buffer} 32-byte Buffer.
 * @throws {TypeError} If hex is not a valid 64-char hex string.
 */
function hexToBytes(hex) {
  if (typeof hex !== 'string' || !/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new TypeError(
      `hexToBytes: expected a 64-character hex string, got: "${hex?.slice?.(0, 20)}..."`
    );
  }
  return Buffer.from(hex, 'hex');
}

/**
 * Compute a Merkle leaf hash.
 * Per §6.2: SHA-256(0x00 || hexToBytes(currentHash))
 *
 * @param {string} currentHash - 64-char hex string (Log.currentHash).
 * @returns {string} Leaf hash as lowercase hex-64.
 */
export function leafHash(currentHash) {
  const bytes = hexToBytes(currentHash);
  return computeSha256hex(Buffer.concat([LEAF_TAG, bytes]));
}

/**
 * Compute a Merkle internal node hash.
 * Per §6.2: SHA-256(0x01 || hexToBytes(left) || hexToBytes(right))
 *
 * @param {string} left - 64-char hex string (left child hash).
 * @param {string} right - 64-char hex string (right child hash).
 * @returns {string} Internal node hash as lowercase hex-64.
 */
export function internalHash(left, right) {
  const leftBytes  = hexToBytes(left);
  const rightBytes = hexToBytes(right);
  return computeSha256hex(Buffer.concat([NODE_TAG, leftBytes, rightBytes]));
}

// ── Tree construction ─────────────────────────────────────────────────────────

/**
 * @typedef {object} MerkleTree
 * @property {string}     root   - Merkle root (lowercase hex-64), or EMPTY_TREE_ROOT for empty input.
 * @property {string[][]} layers - Array of tree layers from bottom (leaves) to top (root).
 *                                 layers[0] is the leaf layer; layers[last] is [root].
 *                                 Empty if input is empty.
 */

/**
 * Build a Merkle tree from an ordered array of authoritative log hashes.
 *
 * The input hashes are Log.currentHash values ordered by ascending sequence_number.
 * They are NOT re-sorted here — the caller is responsible for providing them
 * in the correct order. Silently sorting would break the proof of sequence integrity.
 *
 * Algorithm (§6.3):
 *   1. Compute leaf hash for each input hash.
 *   2. Repeatedly pair and hash adjacent nodes to build each layer.
 *   3. If a layer has an odd number of nodes, duplicate the last node (§6.4).
 *   4. Continue until one node remains (the root).
 *
 * @param {string[]} currentHashes - Ordered array of hex-64 Log.currentHash values.
 * @returns {MerkleTree} The built Merkle tree with root and all layers.
 * @throws {TypeError} If any element is not a valid 64-char hex string.
 */
export function buildMerkleTree(currentHashes) {
  if (!Array.isArray(currentHashes)) {
    throw new TypeError('buildMerkleTree: input must be an array');
  }

  // Empty tree — per §6.5
  if (currentHashes.length === 0) {
    return { root: EMPTY_TREE_ROOT, layers: [], eventHashes: [], tree_size: 0 };
  }

  // Validate all inputs before computing anything
  for (let i = 0; i < currentHashes.length; i++) {
    if (typeof currentHashes[i] !== 'string' || !/^[0-9a-fA-F]{64}$/.test(currentHashes[i])) {
      throw new TypeError(
        `buildMerkleTree: element at index ${i} is not a valid 64-char hex string`
      );
    }
  }

  // Step 1: Compute leaf layer
  const leaves = currentHashes.map((h) => leafHash(h));
  const layers = [leaves];
  let currentLayer = leaves;

  // Step 2–4: Build tree upward
  while (currentLayer.length > 1) {
    const nextLayer = [];
    for (let i = 0; i < currentLayer.length; i += 2) {
      const left  = currentLayer[i];
      // Odd-node rule (§6.4): duplicate last node if no right sibling
      const right = (i + 1 < currentLayer.length) ? currentLayer[i + 1] : currentLayer[i];
      nextLayer.push(internalHash(left, right));
    }
    layers.push(nextLayer);
    currentLayer = nextLayer;
  }

  return {
    root: currentLayer[0],
    layers,
    eventHashes: currentHashes.slice(),
    tree_size: currentHashes.length,
  };
}

/**
 * Extract the Merkle root from a built MerkleTree.
 *
 * @param {MerkleTree} tree - A tree returned by buildMerkleTree().
 * @returns {string} The Merkle root (lowercase hex-64).
 */
export function getMerkleRoot(tree) {
  return tree.root;
}

// ── Inclusion proofs ──────────────────────────────────────────────────────────

/**
 * @typedef {object} ProofStep
 * @property {string} sibling_hash - The sibling's hash (lowercase hex-64).
 * @property {"left"|"right"} position - "left" if sibling is to the LEFT of current node;
 *   "right" if sibling is to the RIGHT.
 */

/**
 * @typedef {object} MerkleProof
 * @property {number}      leaf_index  - Zero-based index of the leaf in the original array.
 * @property {string}      leaf_hash   - The computed leaf hash (SHA-256(0x00 || currentHash bytes)).
 * @property {ProofStep[]} proof       - Ordered array of proof steps from leaf to root.
 * @property {string}      root        - The Merkle root this proof is relative to.
 */

/**
 * Generate a Merkle inclusion proof for the leaf at the given index.
 *
 * The proof allows any verifier to independently recompute the Merkle root
 * starting from just the leaf's currentHash, without needing the full tree.
 *
 * Proof format (§6.6):
 *   Each step: { sibling_hash, position }
 *   - position "right": sibling is to the right → current = internalHash(current, sibling)
 *   - position "left":  sibling is to the left  → current = internalHash(sibling, current)
 *
 * @param {MerkleTree} tree - A tree returned by buildMerkleTree().
 * @param {number} leafIndex - Zero-based index of the target leaf.
 * @returns {MerkleProof} The inclusion proof.
 * @throws {RangeError} If leafIndex is out of bounds.
 * @throws {Error} If the tree is empty (no layers).
 */
export function generateMerkleProof(tree, leafIndex) {
  if (!tree || tree.layers.length === 0) {
    throw new Error('generateMerkleProof: cannot generate proof for empty tree');
  }

  const leafLayer = tree.layers[0];
  if (!Number.isInteger(leafIndex) || leafIndex < 0 || leafIndex >= leafLayer.length) {
    throw new RangeError(
      `generateMerkleProof: leafIndex ${leafIndex} is out of bounds (tree has ${leafLayer.length} leaves)`
    );
  }

  const proof = [];
  let currentIndex = leafIndex;

  for (let layerIdx = 0; layerIdx < tree.layers.length - 1; layerIdx++) {
    const layer = tree.layers[layerIdx];
    const isRightChild = (currentIndex % 2 === 1);

    if (isRightChild) {
      // Current is on the right; sibling is on the left
      const siblingIndex = currentIndex - 1;
      proof.push({
        sibling_hash: layer[siblingIndex],
        position: 'left',
      });
    } else {
      // Current is on the left; sibling is on the right (or duplicated self for odd)
      const siblingIndex = currentIndex + 1;
      const sibling = (siblingIndex < layer.length) ? layer[siblingIndex] : layer[currentIndex];
      proof.push({
        sibling_hash: sibling,
        position: 'right',
      });
    }

    // Move up to parent index
    currentIndex = Math.floor(currentIndex / 2);
  }

  const eventHash = (tree.eventHashes && tree.eventHashes[leafIndex])
    ? tree.eventHashes[leafIndex]
    : null;
  const treeSize = tree.tree_size ?? leafLayer.length;

  return {
    version: MERKLE_SCHEMA_VERSION,
    tree_schema_version: MERKLE_SCHEMA_VERSION,
    hash_algorithm: MERKLE_HASH_ALGORITHM,
    tree_size: treeSize,
    leaf_index: leafIndex,
    event_hash: eventHash,
    leaf_hash:  leafLayer[leafIndex],
    proof,
    root: tree.root,
  };
}

/**
 * Verify a self-contained Merkle inclusion proof bundle.
 *
 * Verifies that the proof bundle correctly authenticates the event hash
 * against the tree root, checking schema version, hash algorithm,
 * leaf index bounds, and proof steps.
 *
 * @param {object} proofBundle - Proof object returned by generateMerkleProof().
 * @param {string} [expectedRoot] - Optional expected Merkle root to match against.
 * @returns {{ valid: boolean, root?: string, leaf_index?: number, error?: string, reason?: string }}
 */
export function verifyInclusionProofBundle(proofBundle, expectedRoot = null) {
  if (!proofBundle || typeof proofBundle !== 'object') {
    return { valid: false, error: 'INVALID_PROOF_BUNDLE', reason: 'Proof bundle must be an object' };
  }
  if (proofBundle.tree_schema_version && proofBundle.tree_schema_version !== MERKLE_SCHEMA_VERSION) {
    return { valid: false, error: 'UNSUPPORTED_SCHEMA_VERSION', reason: `Expected ${MERKLE_SCHEMA_VERSION}` };
  }
  if (proofBundle.hash_algorithm && proofBundle.hash_algorithm !== MERKLE_HASH_ALGORITHM) {
    return { valid: false, error: 'UNSUPPORTED_HASH_ALGORITHM', reason: `Expected ${MERKLE_HASH_ALGORITHM}` };
  }
  if (!Number.isInteger(proofBundle.leaf_index) || proofBundle.leaf_index < 0) {
    return { valid: false, error: 'INVALID_LEAF_INDEX', reason: 'leaf_index must be a non-negative integer' };
  }
  if (Number.isInteger(proofBundle.tree_size) && proofBundle.leaf_index >= proofBundle.tree_size) {
    return { valid: false, error: 'INDEX_OUT_OF_BOUNDS', reason: `leaf_index ${proofBundle.leaf_index} >= tree_size ${proofBundle.tree_size}` };
  }
  if (!Array.isArray(proofBundle.proof)) {
    return { valid: false, error: 'MALFORMED_PROOF', reason: 'proof must be an array' };
  }

  const currentHash = proofBundle.event_hash;
  if (!currentHash || typeof currentHash !== 'string' || !/^[0-9a-fA-F]{64}$/.test(currentHash)) {
    return { valid: false, error: 'INVALID_EVENT_HASH', reason: 'event_hash must be a 64-char hex string' };
  }

  const targetRoot = expectedRoot || proofBundle.root;
  if (!targetRoot || typeof targetRoot !== 'string' || !/^[0-9a-fA-F]{64}$/.test(targetRoot)) {
    return { valid: false, error: 'INVALID_ROOT', reason: 'Root must be a 64-char hex string' };
  }

  try {
    const isValid = verifyMerkleProof(currentHash, proofBundle.proof, targetRoot);
    if (!isValid) {
      return { valid: false, error: 'PROOF_VERIFICATION_FAILED', reason: 'Proof does not evaluate to expected root' };
    }
    if (proofBundle.root && targetRoot.toLowerCase() !== proofBundle.root.toLowerCase()) {
      return { valid: false, error: 'ROOT_MISMATCH', reason: 'Expected root does not match bundle root' };
    }
    return {
      valid: true,
      root: targetRoot,
      leaf_index: proofBundle.leaf_index,
      tree_size: proofBundle.tree_size,
    };
  } catch (err) {
    return { valid: false, error: 'VERIFICATION_ERROR', reason: err.message };
  }
}

/**
 * Verify a Merkle inclusion proof.
 *
 * Given the original Log.currentHash of a leaf and a proof, recomputes the
 * Merkle root and compares it to the expected root. Does NOT touch the original
 * tree object — it is completely independent.
 *
 * Verification algorithm (§6.6 pseudocode):
 *   current = leafHash(leaf_currentHash)
 *   for step in proof:
 *     if step.position == "left":
 *       current = internalHash(step.sibling_hash, current)
 *     else:  // "right"
 *       current = internalHash(current, step.sibling_hash)
 *   return current == expected_root
 *
 * @param {string}      currentHash   - The original Log.currentHash hex-64 for the leaf.
 * @param {ProofStep[]} proof         - The proof steps from generateMerkleProof().
 * @param {string}      expectedRoot  - The Merkle root to verify against (hex-64).
 * @returns {boolean} true if the proof is valid, false otherwise.
 * @throws {TypeError} If inputs are malformed.
 */
export function verifyMerkleProof(currentHash, proof, expectedRoot) {
  if (typeof currentHash !== 'string' || !/^[0-9a-fA-F]{64}$/.test(currentHash)) {
    throw new TypeError('verifyMerkleProof: currentHash must be a 64-char hex string');
  }
  if (!Array.isArray(proof)) {
    throw new TypeError('verifyMerkleProof: proof must be an array');
  }
  if (typeof expectedRoot !== 'string' || !/^[0-9a-fA-F]{64}$/.test(expectedRoot)) {
    throw new TypeError('verifyMerkleProof: expectedRoot must be a 64-char hex string');
  }

  // Validate each proof step
  for (let i = 0; i < proof.length; i++) {
    const step = proof[i];
    if (!step || typeof step !== 'object') {
      throw new TypeError(`verifyMerkleProof: proof step at index ${i} is not an object`);
    }
    if (typeof step.sibling_hash !== 'string' || !/^[0-9a-fA-F]{64}$/.test(step.sibling_hash)) {
      throw new TypeError(`verifyMerkleProof: proof step ${i} sibling_hash is not a 64-char hex string`);
    }
    if (step.position !== 'left' && step.position !== 'right') {
      throw new TypeError(`verifyMerkleProof: proof step ${i} position must be "left" or "right"`);
    }
  }

  // Recompute the root following the proof path
  let current = leafHash(currentHash);

  for (const step of proof) {
    if (step.position === 'left') {
      current = internalHash(step.sibling_hash, current);
    } else {
      current = internalHash(current, step.sibling_hash);
    }
  }

  return current === expectedRoot;
}

export default {
  EMPTY_TREE_ROOT,
  MERKLE_SCHEMA_VERSION,
  MERKLE_HASH_ALGORITHM,
  leafHash,
  internalHash,
  buildMerkleTree,
  getMerkleRoot,
  generateMerkleProof,
  verifyMerkleProof,
  verifyInclusionProofBundle,
};
