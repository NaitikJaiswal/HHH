/**
 * @module merkleTree
 * @description Merkle tree construction and proof generation/verification.
 *
 * Supports two distinct Merkle tree algorithms with explicit schema versioning:
 *
 * 1. "HHH-CONTRACT-DUP-v1" (Schema: 'logn-merkle-v1' or 'logn-merkle-dup-v1') [DEFAULT]:
 *    - Implements docs/technical-integration-contract.md §6
 *    - Layer reduction tree with odd-node duplication (Bitcoin-style)
 *    - Leaf encoding:     SHA-256(0x00 || hexToBytes(currentHash))   — domain tag 0x00
 *    - Internal nodes:    SHA-256(0x01 || hexToBytes(left) || hexToBytes(right)) — domain tag 0x01
 *    - Odd-node rule:     last node in an odd layer is duplicated (paired with itself)
 *    - Empty tree root:   SHA-256(0x00) = "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
 *    - Preserves 100% backward compatibility with existing HHH checkpoints, contracts, and tests.
 *
 * 2. "RFC-6962" (Schema: 'logn-merkle-rfc6962-v1'):
 *    - Implements authentic RFC 6962 Certificate Transparency §2.1 & §2.1.1
 *    - Splits at largest power of 2 less than n: k = 2^(floor(log2(n-1)))
 *    - Never duplicates nodes for non-power-of-2 tree sizes
 *    - Leaf encoding:     SHA-256(0x00 || hexToBytes(currentHash))
 *    - Internal nodes:    SHA-256(0x01 || hexToBytes(left) || hexToBytes(right))
 *    - Empty tree root:   SHA-256("") = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
 *
 * Note on convergence: For n = 1 and n = 2 (and all powers of 2 with balanced splits),
 * both algorithms evaluate to the exact same root and proof paths. They diverge on
 * n = 0 (empty tree) and non-power-of-two sizes (e.g. n = 3, 5, 6, 7).
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
 * Standard Merkle tree schema version for contract duplicated-node trees.
 * @type {string}
 */
export const MERKLE_SCHEMA_VERSION = 'logn-merkle-v1';
export const MERKLE_SCHEMA_VERSION_CONTRACT = 'logn-merkle-v1';

/**
 * Schema version for authentic RFC 6962 Merkle trees.
 * @type {string}
 */
export const MERKLE_SCHEMA_VERSION_RFC6962 = 'logn-merkle-rfc6962-v1';

/**
 * Algorithm identifiers.
 * @type {string}
 */
export const MERKLE_ALGORITHM_CONTRACT = 'HHH-CONTRACT-DUP-v1';
export const MERKLE_ALGORITHM_RFC6962 = 'RFC-6962';

/**
 * Cryptographic hash algorithm used for Merkle tree construction.
 * @type {string}
 */
export const MERKLE_HASH_ALGORITHM = 'SHA-256';

/**
 * The Merkle root for an empty set of leaves per contract §6.5:
 * SHA-256(0x00) = "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
 * @type {string}
 */
export const CONTRACT_EMPTY_TREE_ROOT = '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d';

/**
 * The Merkle root for an empty set of leaves per RFC 6962 §2.1:
 * SHA-256("") = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
 * @type {string}
 */
export const RFC6962_EMPTY_TREE_ROOT = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

/**
 * Default empty tree root (defaults to CONTRACT_EMPTY_TREE_ROOT for backward compatibility).
 * @type {string}
 */
export const EMPTY_TREE_ROOT = CONTRACT_EMPTY_TREE_ROOT;

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
 * Per §6.2 and RFC 6962: SHA-256(0x00 || hexToBytes(currentHash))
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
 * Per §6.2 and RFC 6962: SHA-256(0x01 || hexToBytes(left) || hexToBytes(right))
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

/**
 * Find the largest power of 2 strictly less than n (for n > 1).
 * Per RFC 6962 §2.1: k < n <= 2k.
 *
 * @param {number} n - Number of leaves (must be > 1).
 * @returns {number}
 */
export function largestPowerOf2LessThan(n) {
  if (n <= 1) return 0;
  let k = 1;
  while (k * 2 < n) {
    k *= 2;
  }
  return k;
}

/**
 * Compute the authentic RFC 6962 Merkle Tree Hash (MTH) for an array of leaf hashes.
 *
 * @param {string[]} leafHashes - Array of leaf hashes (computed via leafHash).
 * @returns {string} Merkle Tree Hash as lowercase hex-64.
 */
export function computeRfc6962Mth(leafHashes) {
  if (!Array.isArray(leafHashes) || leafHashes.length === 0) {
    return RFC6962_EMPTY_TREE_ROOT;
  }
  if (leafHashes.length === 1) {
    return leafHashes[0];
  }
  const k = largestPowerOf2LessThan(leafHashes.length);
  const leftMth = computeRfc6962Mth(leafHashes.slice(0, k));
  const rightMth = computeRfc6962Mth(leafHashes.slice(k));
  return internalHash(leftMth, rightMth);
}

/**
 * Generate authentic RFC 6962 audit path steps for leaf m in leafHashes of size n.
 *
 * @param {string[]} leafHashes - Array of leaf hashes.
 * @param {number} m - Target leaf index (0 <= m < n).
 * @returns {Array<{ sibling_hash: string, position: 'left' | 'right' }>} Ordered steps from leaf to root.
 */
export function generateRfc6962ProofSteps(leafHashes, m) {
  const n = leafHashes.length;
  if (n <= 1) {
    return [];
  }
  const k = largestPowerOf2LessThan(n);
  if (m < k) {
    const subPath = generateRfc6962ProofSteps(leafHashes.slice(0, k), m);
    const rightSibling = computeRfc6962Mth(leafHashes.slice(k));
    return [...subPath, { sibling_hash: rightSibling, position: 'right' }];
  } else {
    const subPath = generateRfc6962ProofSteps(leafHashes.slice(k), m - k);
    const leftSibling = computeRfc6962Mth(leafHashes.slice(0, k));
    return [...subPath, { sibling_hash: leftSibling, position: 'left' }];
  }
}

// ── Tree construction ─────────────────────────────────────────────────────────

/**
 * @typedef {object} MerkleTree
 * @property {string}     algorithm   - Algorithm identifier (MERKLE_ALGORITHM_CONTRACT or MERKLE_ALGORITHM_RFC6962).
 * @property {string}     version     - Schema version string.
 * @property {string}     root        - Merkle root (lowercase hex-64).
 * @property {string[][]} layers      - Array of tree layers from bottom to top.
 * @property {string[]}   [leaves]    - Array of leaf hashes (present for RFC-6962).
 * @property {string[]}   eventHashes - Ordered array of original event hashes.
 * @property {number}     tree_size   - Number of leaves in tree.
 */

/**
 * Build a Merkle tree from an ordered array of authoritative log hashes.
 *
 * Supports two algorithms via options.algorithm:
 *   - MERKLE_ALGORITHM_CONTRACT ('HHH-CONTRACT-DUP-v1') [Default]:
 *       Standard layer reduction tree with odd-node duplication per contract §6.
 *   - MERKLE_ALGORITHM_RFC6962 ('RFC-6962'):
 *       Authentic RFC 6962 Certificate Transparency tree with split at 2^(floor(log2(n-1))).
 *
 * @param {string[]} currentHashes - Ordered array of hex-64 Log.currentHash values.
 * @param {object} [options={}] - Optional configuration.
 * @param {string} [options.algorithm=MERKLE_ALGORITHM_CONTRACT] - Algorithm identifier.
 * @returns {MerkleTree} The built Merkle tree with root and metadata.
 * @throws {TypeError} If any element is not a valid 64-char hex string or algorithm is invalid.
 */
export function buildMerkleTree(currentHashes, options = {}) {
  if (!Array.isArray(currentHashes)) {
    throw new TypeError('buildMerkleTree: input must be an array');
  }

  const algorithm = (options && options.algorithm)
    ? options.algorithm
    : MERKLE_ALGORITHM_CONTRACT;

  if (algorithm !== MERKLE_ALGORITHM_CONTRACT && algorithm !== MERKLE_ALGORITHM_RFC6962) {
    throw new TypeError(`buildMerkleTree: unknown algorithm "${algorithm}"`);
  }

  // Validate all inputs before computing anything
  for (let i = 0; i < currentHashes.length; i++) {
    if (typeof currentHashes[i] !== 'string' || !/^[0-9a-fA-F]{64}$/.test(currentHashes[i])) {
      throw new TypeError(
        `buildMerkleTree: element at index ${i} is not a valid 64-char hex string`
      );
    }
  }

  // Empty tree handling
  if (currentHashes.length === 0) {
    const root = (algorithm === MERKLE_ALGORITHM_RFC6962)
      ? RFC6962_EMPTY_TREE_ROOT
      : CONTRACT_EMPTY_TREE_ROOT;
    const version = (algorithm === MERKLE_ALGORITHM_RFC6962)
      ? MERKLE_SCHEMA_VERSION_RFC6962
      : MERKLE_SCHEMA_VERSION_CONTRACT;

    return {
      algorithm,
      version,
      root,
      layers: [],
      leaves: [],
      eventHashes: [],
      tree_size: 0,
    };
  }

  // Step 1: Compute leaf hashes
  const leaves = currentHashes.map((h) => leafHash(h));

  // Branch for authentic RFC 6962
  if (algorithm === MERKLE_ALGORITHM_RFC6962) {
    const root = computeRfc6962Mth(leaves);
    return {
      algorithm: MERKLE_ALGORITHM_RFC6962,
      version: MERKLE_SCHEMA_VERSION_RFC6962,
      root,
      leaves,
      layers: [[...leaves], [root]],
      eventHashes: currentHashes.slice(),
      tree_size: currentHashes.length,
    };
  }

  // Branch for HHH-CONTRACT-DUP-v1 (default contract specification)
  const layers = [leaves];
  let currentLayer = leaves;

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
    algorithm: MERKLE_ALGORITHM_CONTRACT,
    version: MERKLE_SCHEMA_VERSION_CONTRACT,
    root: currentLayer[0],
    layers,
    leaves,
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
 * @property {string}      version             - Schema version string.
 * @property {string}      tree_schema_version - Standardized tree schema version.
 * @property {string}      algorithm           - Algorithm used to construct the tree.
 * @property {string}      hash_algorithm      - Cryptographic hash algorithm ('SHA-256').
 * @property {number}      tree_size           - Total number of leaves in tree.
 * @property {number}      leaf_index          - Zero-based index of the leaf in original order.
 * @property {string}      event_hash          - Original Log.currentHash for this leaf.
 * @property {string}      leaf_hash           - The computed leaf hash (SHA-256(0x00 || currentHash)).
 * @property {ProofStep[]} proof               - Ordered array of proof steps from leaf to root.
 * @property {string}      root                - The Merkle root this proof authenticates against.
 */

/**
 * Generate a Merkle inclusion proof for the leaf at the given index.
 *
 * Supports both HHH-CONTRACT-DUP-v1 and RFC-6962 trees.
 *
 * @param {MerkleTree} tree - A tree returned by buildMerkleTree().
 * @param {number} leafIndex - Zero-based index of the target leaf.
 * @returns {MerkleProof} The inclusion proof bundle.
 * @throws {RangeError} If leafIndex is out of bounds.
 * @throws {Error} If the tree is empty.
 */
export function generateMerkleProof(tree, leafIndex) {
  if (!tree || tree.tree_size === 0 || (!tree.layers?.length && !tree.leaves?.length)) {
    throw new Error('generateMerkleProof: cannot generate proof for empty tree');
  }

  const leafCount = tree.tree_size ?? (tree.layers ? tree.layers[0].length : tree.leaves.length);
  if (!Number.isInteger(leafIndex) || leafIndex < 0 || leafIndex >= leafCount) {
    throw new RangeError(
      `generateMerkleProof: leafIndex ${leafIndex} is out of bounds (tree has ${leafCount} leaves)`
    );
  }

  const eventHash = (tree.eventHashes && tree.eventHashes[leafIndex])
    ? tree.eventHashes[leafIndex]
    : null;
  const treeSize = leafCount;

  // RFC-6962 proof generation
  if (tree.algorithm === MERKLE_ALGORITHM_RFC6962) {
    const leaves = tree.leaves || (tree.layers && tree.layers[0]);
    const proofSteps = generateRfc6962ProofSteps(leaves, leafIndex);
    return {
      version: MERKLE_SCHEMA_VERSION_RFC6962,
      tree_schema_version: MERKLE_SCHEMA_VERSION_RFC6962,
      algorithm: MERKLE_ALGORITHM_RFC6962,
      hash_algorithm: MERKLE_HASH_ALGORITHM,
      tree_size: treeSize,
      leaf_index: leafIndex,
      event_hash: eventHash,
      leaf_hash: leaves[leafIndex],
      proof: proofSteps,
      root: tree.root,
    };
  }

  // Contract duplicated-node proof generation
  const leafLayer = tree.layers[0];
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

    currentIndex = Math.floor(currentIndex / 2);
  }

  return {
    version: MERKLE_SCHEMA_VERSION_CONTRACT,
    tree_schema_version: MERKLE_SCHEMA_VERSION_CONTRACT,
    algorithm: MERKLE_ALGORITHM_CONTRACT,
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
 * leaf index bounds, and proof steps. Supports both HHH-CONTRACT-DUP-v1
 * and RFC-6962 schemas.
 *
 * @param {object} proofBundle - Proof object returned by generateMerkleProof().
 * @param {string} [expectedRoot] - Optional expected Merkle root to match against.
 * @returns {{ valid: boolean, root?: string, leaf_index?: number, tree_size?: number, algorithm?: string, error?: string, reason?: string }}
 */
export function verifyInclusionProofBundle(proofBundle, expectedRoot = null) {
  if (!proofBundle || typeof proofBundle !== 'object') {
    return { valid: false, error: 'INVALID_PROOF_BUNDLE', reason: 'Proof bundle must be an object' };
  }

  const validSchemas = [
    MERKLE_SCHEMA_VERSION_CONTRACT,
    'logn-merkle-dup-v1',
    MERKLE_SCHEMA_VERSION_RFC6962,
  ];
  if (proofBundle.tree_schema_version && !validSchemas.includes(proofBundle.tree_schema_version)) {
    return {
      valid: false,
      error: 'UNSUPPORTED_SCHEMA_VERSION',
      reason: `Schema "${proofBundle.tree_schema_version}" not supported (expected one of: ${validSchemas.join(', ')})`,
    };
  }

  if (proofBundle.algorithm &&
      proofBundle.algorithm !== MERKLE_ALGORITHM_CONTRACT &&
      proofBundle.algorithm !== MERKLE_ALGORITHM_RFC6962) {
    return {
      valid: false,
      error: 'UNSUPPORTED_ALGORITHM',
      reason: `Algorithm "${proofBundle.algorithm}" not supported`,
    };
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
      algorithm: proofBundle.algorithm || MERKLE_ALGORITHM_CONTRACT,
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
 * Verification algorithm:
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
  CONTRACT_EMPTY_TREE_ROOT,
  RFC6962_EMPTY_TREE_ROOT,
  MERKLE_SCHEMA_VERSION,
  MERKLE_SCHEMA_VERSION_CONTRACT,
  MERKLE_SCHEMA_VERSION_RFC6962,
  MERKLE_ALGORITHM_CONTRACT,
  MERKLE_ALGORITHM_RFC6962,
  MERKLE_HASH_ALGORITHM,
  largestPowerOf2LessThan,
  computeRfc6962Mth,
  generateRfc6962ProofSteps,
  leafHash,
  internalHash,
  buildMerkleTree,
  getMerkleRoot,
  generateMerkleProof,
  verifyMerkleProof,
  verifyInclusionProofBundle,
};
