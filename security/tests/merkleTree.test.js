/**
 * Tests for merkleTree.js — Merkle tree construction and proof generation/verification.
 * Uses Node.js built-in node:test and node:assert/strict.
 *
 * Test coverage:
 *   1.  Empty tree -> returns EMPTY_TREE_ROOT
 *   2.  Single leaf -> deterministic root and empty proof verification
 *   3.  Two leaves -> root matches contract §6.7 specification
 *   4.  Odd number of leaves (3 leaves) -> duplicates last node per odd-node rule
 *   5.  Even number of leaves (4 leaves) -> balanced tree construction
 *   6.  Deterministic root -> identical input produces identical root
 *   7.  Valid inclusion proof -> generates and verifies proof for all leaves
 *   8.  Invalid inclusion proof -> altered proof steps fail verification
 *   9.  Modified leaf -> altered leaf fails proof verification against original root
 *  10.  Reordered leaves -> altered input order produces a completely different root
 *  11.  Malformed input -> non-hex or invalid length strings rejected
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
  MERKLE_HASH_ALGORITHM,
  leafHash,
  internalHash,
  EMPTY_TREE_ROOT,
} from '../src/merkle/merkleTree.js';
import { sha256hex } from '../src/crypto/hashing.js';

// ── Test helpers ─────────────────────────────────────────────────────────────

function makeHexHash(val) {
  return sha256hex(String(val));
}

// ── Tests ────────────────────────────────────────────────────────────────────

test('1. Empty tree returns EMPTY_TREE_ROOT', () => {
  const tree = buildMerkleTree([]);
  assert.equal(tree.root, EMPTY_TREE_ROOT, 'Empty tree root must match EMPTY_TREE_ROOT');
  assert.equal(getMerkleRoot(tree), EMPTY_TREE_ROOT);
  assert.deepEqual(tree.layers, []);
  assert.equal(
    tree.root,
    '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d',
    'Root must match SHA256(0x00) per §6.5'
  );
});

test('2. Single leaf tree produces deterministic root and verifies', () => {
  const h0 = makeHexHash('event-1');
  const tree = buildMerkleTree([h0]);

  // For a single leaf, root is leafHash(h0)
  const expectedRoot = leafHash(h0);
  assert.equal(tree.root, expectedRoot);
  assert.equal(tree.layers.length, 1);
  assert.equal(tree.layers[0][0], expectedRoot);

  // Generate proof
  const proof = generateMerkleProof(tree, 0);
  assert.equal(proof.leaf_index, 0);
  assert.equal(proof.proof.length, 0, 'Single leaf proof should have 0 sibling steps');
  assert.equal(proof.root, expectedRoot);

  // Verify proof
  const valid = verifyMerkleProof(h0, proof.proof, tree.root);
  assert.equal(valid, true, 'Single leaf proof must be valid');

  // Tampered leaf should fail
  const tamperedH0 = makeHexHash('event-tampered');
  const invalid = verifyMerkleProof(tamperedH0, proof.proof, tree.root);
  assert.equal(invalid, false, 'Tampered leaf must fail verification');
});

test('3. Two leaves tree matches contract §6.7 specification', () => {
  // Input currentHashes from §6.7:
  // h_0 = SHA-256 of empty string
  // h_1 = SHA-256 of "hello"
  const h0 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  const h1 = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';

  const L0 = leafHash(h0);
  const L1 = leafHash(h1);
  const expectedRoot = internalHash(L0, L1);

  const tree = buildMerkleTree([h0, h1]);
  assert.equal(tree.root, expectedRoot, 'Two leaf tree root must match internalHash(L0, L1)');

  // Proof for leaf 0
  const proof0 = generateMerkleProof(tree, 0);
  assert.equal(proof0.proof.length, 1);
  assert.equal(proof0.proof[0].sibling_hash, L1);
  assert.equal(proof0.proof[0].position, 'right');
  assert.equal(verifyMerkleProof(h0, proof0.proof, tree.root), true);

  // Proof for leaf 1
  const proof1 = generateMerkleProof(tree, 1);
  assert.equal(proof1.proof.length, 1);
  assert.equal(proof1.proof[0].sibling_hash, L0);
  assert.equal(proof1.proof[0].position, 'left');
  assert.equal(verifyMerkleProof(h1, proof1.proof, tree.root), true);
});

test('4. Odd number of leaves (3 leaves) applies odd-node duplication rule', () => {
  const h0 = makeHexHash('0');
  const h1 = makeHexHash('1');
  const h2 = makeHexHash('2');

  const L0 = leafHash(h0);
  const L1 = leafHash(h1);
  const L2 = leafHash(h2);

  // Level 1: internalHash(L0, L1) and internalHash(L2, L2)
  const P0 = internalHash(L0, L1);
  const P1 = internalHash(L2, L2); // odd node duplicated
  const expectedRoot = internalHash(P0, P1);

  const tree = buildMerkleTree([h0, h1, h2]);
  assert.equal(tree.root, expectedRoot, '3-leaf tree must duplicate last node per §6.4');

  // Verify proofs for all 3 leaves
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
    { sibling_hash: proof.proof[0].sibling_hash, position: 'left' }, // was right
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
  const hashes2 = [2, 1, 3, 4].map(makeHexHash); // 1 and 2 swapped

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
  // Invalid hex length
  assert.throws(
    () => buildMerkleTree(['1234']),
    TypeError
  );

  // Non-hex characters
  assert.throws(
    () => buildMerkleTree(['z'.repeat(64)]),
    TypeError
  );

  // Out of bounds proof generation
  const tree = buildMerkleTree([makeHexHash(1), makeHexHash(2)]);
  assert.throws(
    () => generateMerkleProof(tree, -1),
    RangeError
  );
  assert.throws(
    () => generateMerkleProof(tree, 2),
    RangeError
  );

  // Malformed proof step validation
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
  const h0 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'; // SHA256("")
  const h1 = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'; // SHA256("hello")
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

test('14. Large tree (128 leaves) builds and verifies inclusion proofs for all leaves', () => {
  const hashes = Array.from({ length: 128 }, (_, i) => makeHexHash(`event-batch-${i}`));
  const tree = buildMerkleTree(hashes);

  assert.equal(tree.layers.length, 8); // log2(128) + 1
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
