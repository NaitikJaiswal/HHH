/**
 * Tests for merkleTree.js — Merkle tree construction and proof generation/verification.
 * Uses Node.js built-in node:test and node:assert/strict.
 *
 * Verifies both:
 *   1. "HHH-CONTRACT-DUP-v1" (logn-merkle-v1) - odd-node duplicated tree per contract §6
 *   2. "RFC-6962" (logn-merkle-rfc6962-v1) - authentic Certificate Transparency tree
 *
 * Test coverage:
 *   1.  Empty tree -> returns CONTRACT_EMPTY_TREE_ROOT and RFC6962_EMPTY_TREE_ROOT
 *   2.  Single leaf -> deterministic root and empty proof verification (both algorithms identical)
 *   3.  Two leaves -> root matches contract §6.7 specification (both algorithms identical)
 *   4.  Odd number of leaves (3 leaves) -> duplicates last node per contract §6.4
 *   5.  Even number of leaves (4 leaves) -> balanced tree construction
 *   6.  Deterministic root -> identical input produces identical root
 *   7.  Valid inclusion proof -> generates and verifies proof for all leaves
 *   8.  Invalid inclusion proof -> altered proof steps fail verification
 *   9.  Modified leaf -> altered leaf fails proof verification against original root
 *  10.  Reordered leaves -> altered input order produces a completely different root
 *  11.  Malformed input -> non-hex or invalid length strings rejected
 *  12.  Contract Section 6.7 authoritative two-leaf test vector matches
 *  13.  Metadata-bound inclusion proof bundle contains all required fields and verifies independently
 *  14.  Large tree (128 leaves) builds and verifies inclusion proofs for all leaves
 *  15.  Duplicate event hashes in same tree produce valid distinct proofs for each position
 *  16.  Rejects malformed or tampered proof bundles
 *  17.  RFC 6962 tree construction & proof verification for n = 1, 2, 3, 5, 6, 7, 8
 *  18.  RFC 6962 vs Contract algorithm convergence on powers of 2 (n=1, 2, 4, 8) and divergence on non-powers of 2 (n=3, 5, 6, 7)
 *  19.  RFC 6962 largestPowerOf2LessThan mathematical properties
 *  20.  Multi-algorithm proof bundle verification and rejection of unsupported schemas/algorithms
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildMerkleTree,
  getMerkleRoot,
  generateMerkleProof,
  verifyMerkleProof,
  verifyInclusionProofBundle,
  MERKLE_SCHEMA_VERSION,
  MERKLE_SCHEMA_VERSION_CONTRACT,
  MERKLE_SCHEMA_VERSION_RFC6962,
  MERKLE_ALGORITHM_CONTRACT,
  MERKLE_ALGORITHM_RFC6962,
  MERKLE_HASH_ALGORITHM,
  CONTRACT_EMPTY_TREE_ROOT,
  RFC6962_EMPTY_TREE_ROOT,
  EMPTY_TREE_ROOT,
  leafHash,
  internalHash,
  largestPowerOf2LessThan,
  computeRfc6962Mth,
} from '../src/merkle/merkleTree.js';
import { sha256hex } from '../src/crypto/hashing.js';

// ── Test helpers ─────────────────────────────────────────────────────────────

function makeHexHash(val) {
  return sha256hex(String(val));
}

// ── Tests ────────────────────────────────────────────────────────────────────

test('1. Empty tree returns EMPTY_TREE_ROOT (contract §6.5) and RFC6962_EMPTY_TREE_ROOT', () => {
  // Default contract algorithm
  const contractTree = buildMerkleTree([]);
  assert.equal(contractTree.root, EMPTY_TREE_ROOT, 'Default empty tree root must match EMPTY_TREE_ROOT');
  assert.equal(getMerkleRoot(contractTree), CONTRACT_EMPTY_TREE_ROOT);
  assert.deepEqual(contractTree.layers, []);
  assert.equal(
    contractTree.root,
    '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d',
    'Root must match SHA256(0x00) per §6.5'
  );

  // RFC 6962 algorithm
  const rfcTree = buildMerkleTree([], { algorithm: MERKLE_ALGORITHM_RFC6962 });
  assert.equal(rfcTree.root, RFC6962_EMPTY_TREE_ROOT);
  assert.equal(
    rfcTree.root,
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'RFC 6962 empty tree root must match SHA256("") per RFC 6962 §2.1'
  );
});

test('2. Single leaf tree produces deterministic root and verifies (both algorithms identical)', () => {
  const h0 = makeHexHash('event-1');
  const expectedRoot = leafHash(h0);

  // Contract algorithm
  const treeContract = buildMerkleTree([h0]);
  assert.equal(treeContract.root, expectedRoot);
  assert.equal(treeContract.layers.length, 1);
  const proofContract = generateMerkleProof(treeContract, 0);
  assert.equal(proofContract.leaf_index, 0);
  assert.equal(proofContract.proof.length, 0);
  assert.equal(verifyMerkleProof(h0, proofContract.proof, treeContract.root), true);

  // RFC 6962 algorithm
  const treeRfc = buildMerkleTree([h0], { algorithm: MERKLE_ALGORITHM_RFC6962 });
  assert.equal(treeRfc.root, expectedRoot, 'Single leaf root is identical for both algorithms');
  const proofRfc = generateMerkleProof(treeRfc, 0);
  assert.equal(proofRfc.proof.length, 0);
  assert.equal(verifyMerkleProof(h0, proofRfc.proof, treeRfc.root), true);

  // Tampered leaf should fail
  const tamperedH0 = makeHexHash('event-tampered');
  assert.equal(verifyMerkleProof(tamperedH0, proofContract.proof, treeContract.root), false);
  assert.equal(verifyMerkleProof(tamperedH0, proofRfc.proof, treeRfc.root), false);
});

test('3. Two leaves tree matches contract §6.7 specification (both algorithms identical)', () => {
  const h0 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  const h1 = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';

  const L0 = leafHash(h0);
  const L1 = leafHash(h1);
  const expectedRoot = internalHash(L0, L1);

  const treeContract = buildMerkleTree([h0, h1]);
  const treeRfc = buildMerkleTree([h0, h1], { algorithm: MERKLE_ALGORITHM_RFC6962 });

  assert.equal(treeContract.root, expectedRoot);
  assert.equal(treeRfc.root, expectedRoot, 'Two-leaf root is identical in both algorithms');
  assert.equal(treeContract.root, '22e7f12936a0a01d0922a443fa639c60ad12a99d5ec7454ea38bc80e354ee58e');

  // Proofs for leaf 0
  const p0Contract = generateMerkleProof(treeContract, 0);
  const p0Rfc = generateMerkleProof(treeRfc, 0);
  assert.equal(p0Contract.proof[0].sibling_hash, L1);
  assert.equal(p0Rfc.proof[0].sibling_hash, L1);
  assert.equal(verifyMerkleProof(h0, p0Contract.proof, treeContract.root), true);
  assert.equal(verifyMerkleProof(h0, p0Rfc.proof, treeRfc.root), true);

  // Proofs for leaf 1
  const p1Contract = generateMerkleProof(treeContract, 1);
  const p1Rfc = generateMerkleProof(treeRfc, 1);
  assert.equal(p1Contract.proof[0].sibling_hash, L0);
  assert.equal(p1Rfc.proof[0].sibling_hash, L0);
  assert.equal(verifyMerkleProof(h1, p1Contract.proof, treeContract.root), true);
  assert.equal(verifyMerkleProof(h1, p1Rfc.proof, treeRfc.root), true);
});

test('4. Odd number of leaves (3 leaves) applies odd-node duplication rule in contract algorithm', () => {
  const h0 = makeHexHash('0');
  const h1 = makeHexHash('1');
  const h2 = makeHexHash('2');

  const L0 = leafHash(h0);
  const L1 = leafHash(h1);
  const L2 = leafHash(h2);

  // Level 1: internalHash(L0, L1) and internalHash(L2, L2)
  const P0 = internalHash(L0, L1);
  const P1 = internalHash(L2, L2); // odd node duplicated
  const expectedContractRoot = internalHash(P0, P1);

  const tree = buildMerkleTree([h0, h1, h2]);
  assert.equal(tree.root, expectedContractRoot, '3-leaf tree must duplicate last node per §6.4');

  for (let i = 0; i < 3; i++) {
    const proof = generateMerkleProof(tree, i);
    const hashes = [h0, h1, h2];
    assert.equal(verifyMerkleProof(hashes[i], proof.proof, tree.root), true);
  }
});

test('5. Even number of leaves (4 leaves) builds balanced tree', () => {
  const hashes = [0, 1, 2, 3].map(makeHexHash);
  const tree = buildMerkleTree(hashes);

  assert.equal(tree.layers.length, 3, '4 leaves should have 3 layers (leaves, level 1, root)');
  assert.equal(tree.layers[0].length, 4);
  assert.equal(tree.layers[1].length, 2);
  assert.equal(tree.layers[2].length, 1);

  for (let i = 0; i < 4; i++) {
    const proof = generateMerkleProof(tree, i);
    assert.equal(proof.proof.length, 2, 'Proof path length should be 2 for 4 leaves');
    assert.equal(verifyMerkleProof(hashes[i], proof.proof, tree.root), true);
  }
});

test('6. Deterministic root — same inputs always produce identical root', () => {
  const hashes = [1, 2, 3, 4, 5].map(makeHexHash);
  const tree1 = buildMerkleTree(hashes);
  const tree2 = buildMerkleTree(hashes);

  assert.equal(tree1.root, tree2.root, 'Merkle root must be strictly deterministic');
  assert.deepEqual(tree1.layers, tree2.layers);
});

test('7. Valid inclusion proofs for multi-leaf tree (7 leaves)', () => {
  const hashes = [0, 1, 2, 3, 4, 5, 6].map(makeHexHash);
  const tree = buildMerkleTree(hashes);

  for (let i = 0; i < hashes.length; i++) {
    const proof = generateMerkleProof(tree, i);
    assert.equal(
      verifyMerkleProof(hashes[i], proof.proof, tree.root),
      true,
      `Leaf ${i} proof verification must succeed`
    );
  }
});

test('8. Invalid inclusion proof fails verification', () => {
  const hashes = [0, 1, 2, 3].map(makeHexHash);
  const tree = buildMerkleTree(hashes);
  const proof = generateMerkleProof(tree, 0);

  // Alter sibling hash
  const tamperedProof = [
    { sibling_hash: makeHexHash('corrupted'), position: proof.proof[0].position },
    ...proof.proof.slice(1),
  ];
  assert.equal(verifyMerkleProof(hashes[0], tamperedProof, tree.root), false);

  // Alter position
  const invertedPositionProof = [
    { sibling_hash: proof.proof[0].sibling_hash, position: 'left' },
    ...proof.proof.slice(1),
  ];
  assert.equal(verifyMerkleProof(hashes[0], invertedPositionProof, tree.root), false);
});

test('9. Modified leaf fails proof verification against original root', () => {
  const hashes = [0, 1, 2, 3].map(makeHexHash);
  const tree = buildMerkleTree(hashes);
  const proof = generateMerkleProof(tree, 1);

  const fakeHash = makeHexHash('fake-event');
  const valid = verifyMerkleProof(fakeHash, proof.proof, tree.root);
  assert.equal(valid, false, 'Proof for original leaf must not verify for modified leaf');
});

test('10. Reordered leaves produce completely different root and fail proofs', () => {
  const hashes1 = [1, 2, 3, 4].map(makeHexHash);
  const hashes2 = [2, 1, 3, 4].map(makeHexHash);

  const tree1 = buildMerkleTree(hashes1);
  const tree2 = buildMerkleTree(hashes2);

  assert.notEqual(tree1.root, tree2.root, 'Reordering leaves must alter the Merkle root');

  const proof = generateMerkleProof(tree1, 0);
  assert.equal(
    verifyMerkleProof(hashes1[0], proof.proof, tree2.root),
    false,
    'Proof from tree1 must not verify against tree2 root'
  );
});

test('11. Input validation rejects malformed hashes and out-of-bounds indices', () => {
  assert.throws(() => buildMerkleTree(['1234']), TypeError);
  assert.throws(() => buildMerkleTree(['z'.repeat(64)]), TypeError);
  assert.throws(() => buildMerkleTree([makeHexHash(1)], { algorithm: 'UNKNOWN_ALGO' }), TypeError);

  const tree = buildMerkleTree([makeHexHash(1), makeHexHash(2)]);
  assert.throws(() => generateMerkleProof(tree, -1), RangeError);
  assert.throws(() => generateMerkleProof(tree, 2), RangeError);

  assert.throws(
    () => verifyMerkleProof(makeHexHash(1), [{ sibling_hash: 'short', position: 'left' }], tree.root),
    TypeError
  );
  assert.throws(
    () => verifyMerkleProof(makeHexHash(1), [{ sibling_hash: makeHexHash('ok'), position: 'top' }], tree.root),
    TypeError
  );
});

test('12. Contract Section 6.7 authoritative two-leaf test vector matches', () => {
  const h0 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  const h1 = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';
  const tree = buildMerkleTree([h0, h1]);

  assert.equal(tree.root, '22e7f12936a0a01d0922a443fa639c60ad12a99d5ec7454ea38bc80e354ee58e');
  const proof0 = generateMerkleProof(tree, 0);
  assert.equal(verifyMerkleProof(h0, proof0.proof, tree.root), true);
  const proof1 = generateMerkleProof(tree, 1);
  assert.equal(verifyMerkleProof(h1, proof1.proof, tree.root), true);
});

test('13. Metadata-bound inclusion proof bundle contains all required fields and verifies independently', () => {
  const hashes = [makeHexHash('a'), makeHexHash('b'), makeHexHash('c')];
  const tree = buildMerkleTree(hashes);

  const bundle = generateMerkleProof(tree, 1);
  assert.equal(bundle.version, MERKLE_SCHEMA_VERSION);
  assert.equal(bundle.tree_schema_version, MERKLE_SCHEMA_VERSION);
  assert.equal(bundle.algorithm, MERKLE_ALGORITHM_CONTRACT);
  assert.equal(bundle.hash_algorithm, MERKLE_HASH_ALGORITHM);
  assert.equal(bundle.tree_size, 3);
  assert.equal(bundle.leaf_index, 1);
  assert.equal(bundle.event_hash, hashes[1]);
  assert.equal(bundle.root, tree.root);

  const result = verifyInclusionProofBundle(bundle);
  assert.equal(result.valid, true);
  assert.equal(result.root, tree.root);
  assert.equal(result.leaf_index, 1);
});

test('14. Large tree (128 leaves) builds and verifies inclusion proofs for all sampled leaves', () => {
  const hashes = Array.from({ length: 128 }, (_, i) => makeHexHash(`event-batch-${i}`));
  const tree = buildMerkleTree(hashes);

  assert.equal(tree.layers.length, 8);
  assert.equal(tree.tree_size, 128);

  for (let i = 0; i < 128; i += 16) {
    const bundle = generateMerkleProof(tree, i);
    const ver = verifyInclusionProofBundle(bundle);
    assert.equal(ver.valid, true);
  }
});

test('15. Duplicate event hashes in same tree produce valid distinct proofs for each position', () => {
  const dupHash = makeHexHash('identical-event');
  const tree = buildMerkleTree([dupHash, dupHash]);

  const p0 = generateMerkleProof(tree, 0);
  const p1 = generateMerkleProof(tree, 1);

  assert.equal(p0.leaf_index, 0);
  assert.equal(p1.leaf_index, 1);
  assert.equal(p0.proof[0].position, 'right');
  assert.equal(p1.proof[0].position, 'left');

  assert.equal(verifyInclusionProofBundle(p0).valid, true);
  assert.equal(verifyInclusionProofBundle(p1).valid, true);
});

test('16. Rejects malformed or tampered proof bundles', () => {
  const hashes = [makeHexHash('1'), makeHexHash('2')];
  const tree = buildMerkleTree(hashes);
  const validBundle = generateMerkleProof(tree, 0);

  // 1. Wrong algorithm
  const badAlgo = { ...validBundle, hash_algorithm: 'MD5' };
  assert.equal(verifyInclusionProofBundle(badAlgo).valid, false);

  // 2. Index out of bounds
  const badIndex = { ...validBundle, leaf_index: 99 };
  assert.equal(verifyInclusionProofBundle(badIndex).valid, false);

  // 3. Altered event hash
  const badEventHash = { ...validBundle, event_hash: makeHexHash('tampered') };
  assert.equal(verifyInclusionProofBundle(badEventHash).valid, false);

  // 4. Altered root
  const badRoot = { ...validBundle, root: makeHexHash('fake-root') };
  assert.equal(verifyInclusionProofBundle(badRoot).valid, false);
});

test('17. RFC 6962 tree construction & proof verification for n = 1, 2, 3, 5, 6, 7, 8', () => {
  for (const n of [1, 2, 3, 5, 6, 7, 8]) {
    const hashes = Array.from({ length: n }, (_, i) => makeHexHash(`rfc6962-event-${n}-${i}`));
    const tree = buildMerkleTree(hashes, { algorithm: MERKLE_ALGORITHM_RFC6962 });

    assert.equal(tree.algorithm, MERKLE_ALGORITHM_RFC6962);
    assert.equal(tree.version, MERKLE_SCHEMA_VERSION_RFC6962);
    assert.equal(tree.tree_size, n);

    // Verify all leaf proofs
    for (let i = 0; i < n; i++) {
      const proofBundle = generateMerkleProof(tree, i);
      assert.equal(proofBundle.leaf_index, i);
      assert.equal(proofBundle.event_hash, hashes[i]);
      assert.equal(proofBundle.algorithm, MERKLE_ALGORITHM_RFC6962);
      assert.equal(proofBundle.tree_schema_version, MERKLE_SCHEMA_VERSION_RFC6962);

      // Verify with standard verifyMerkleProof
      const rawValid = verifyMerkleProof(hashes[i], proofBundle.proof, tree.root);
      assert.equal(rawValid, true, `RFC 6962 proof for n=${n}, leaf=${i} must verify`);

      // Verify with verifyInclusionProofBundle
      const bundleVer = verifyInclusionProofBundle(proofBundle);
      assert.equal(bundleVer.valid, true, `RFC 6962 bundle for n=${n}, leaf=${i} must verify`);
    }
  }
});

test('18. RFC 6962 vs Contract convergence on powers of 2 and divergence on non-powers of 2', () => {
  // Powers of 2: roots must match identically
  for (const n of [1, 2, 4, 8]) {
    const hashes = Array.from({ length: n }, (_, i) => makeHexHash(`power2-leaf-${i}`));
    const treeContract = buildMerkleTree(hashes, { algorithm: MERKLE_ALGORITHM_CONTRACT });
    const treeRfc = buildMerkleTree(hashes, { algorithm: MERKLE_ALGORITHM_RFC6962 });

    assert.equal(
      treeContract.root,
      treeRfc.root,
      `For power-of-2 size n=${n}, Contract and RFC 6962 roots must be identical`
    );
  }

  // Non-powers of 2: roots MUST diverge because Contract duplicates odd nodes whereas RFC 6962 splits at 2^k
  for (const n of [3, 5, 6, 7]) {
    const hashes = Array.from({ length: n }, (_, i) => makeHexHash(`non-power2-leaf-${i}`));
    const treeContract = buildMerkleTree(hashes, { algorithm: MERKLE_ALGORITHM_CONTRACT });
    const treeRfc = buildMerkleTree(hashes, { algorithm: MERKLE_ALGORITHM_RFC6962 });

    assert.notEqual(
      treeContract.root,
      treeRfc.root,
      `For non-power-of-2 size n=${n}, Contract duplicated-node root and RFC 6962 root must diverge`
    );
  }
});

test('19. largestPowerOf2LessThan adheres to RFC 6962 §2.1 bounds k < n <= 2k', () => {
  assert.equal(largestPowerOf2LessThan(0), 0);
  assert.equal(largestPowerOf2LessThan(1), 0);
  assert.equal(largestPowerOf2LessThan(2), 1);
  assert.equal(largestPowerOf2LessThan(3), 2);
  assert.equal(largestPowerOf2LessThan(4), 2);
  assert.equal(largestPowerOf2LessThan(5), 4);
  assert.equal(largestPowerOf2LessThan(6), 4);
  assert.equal(largestPowerOf2LessThan(7), 4);
  assert.equal(largestPowerOf2LessThan(8), 4);
  assert.equal(largestPowerOf2LessThan(9), 8);
  assert.equal(largestPowerOf2LessThan(16), 8);
  assert.equal(largestPowerOf2LessThan(17), 16);

  // Check inequality k < n <= 2k for all n from 2 to 100
  for (let n = 2; n <= 100; n++) {
    const k = largestPowerOf2LessThan(n);
    assert.ok(k < n, `k (${k}) must be strictly less than n (${n})`);
    assert.ok(n <= 2 * k, `n (${n}) must be <= 2*k (${2 * k})`);
    assert.equal((k & (k - 1)), 0, `k (${k}) must be a power of 2`);
  }
});

test('20. Multi-algorithm proof bundle verification and rejection of unsupported schemas/algorithms', () => {
  const hashes = [makeHexHash('a'), makeHexHash('b'), makeHexHash('c')];

  // Contract bundle verification
  const contractTree = buildMerkleTree(hashes, { algorithm: MERKLE_ALGORITHM_CONTRACT });
  const contractBundle = generateMerkleProof(contractTree, 2);
  assert.equal(verifyInclusionProofBundle(contractBundle).valid, true);

  // RFC bundle verification
  const rfcTree = buildMerkleTree(hashes, { algorithm: MERKLE_ALGORITHM_RFC6962 });
  const rfcBundle = generateMerkleProof(rfcTree, 2);
  assert.equal(verifyInclusionProofBundle(rfcBundle).valid, true);

  // Cross-verification fails (RFC proof bundle against contract root)
  assert.equal(
    verifyInclusionProofBundle(rfcBundle, contractTree.root).valid,
    false,
    'RFC proof bundle must not verify against Contract tree root'
  );

  // Unsupported schema rejection
  const badSchemaBundle = { ...contractBundle, tree_schema_version: 'logn-merkle-unsupported-v99' };
  const resBadSchema = verifyInclusionProofBundle(badSchemaBundle);
  assert.equal(resBadSchema.valid, false);
  assert.equal(resBadSchema.error, 'UNSUPPORTED_SCHEMA_VERSION');

  // Unsupported algorithm rejection
  const badAlgoBundle = { ...contractBundle, algorithm: 'NON_EXISTENT_MERKLE_ALGO' };
  const resBadAlgo = verifyInclusionProofBundle(badAlgoBundle);
  assert.equal(resBadAlgo.valid, false);
  assert.equal(resBadAlgo.error, 'UNSUPPORTED_ALGORITHM');
});
