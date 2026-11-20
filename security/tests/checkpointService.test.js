/**
 * Tests for checkpointService.js — Signed checkpoint creation and verification.
 * Uses Node.js built-in node:test and node:assert/strict.
 *
 * Test coverage:
 *   1. Generate a valid signed checkpoint
 *   2. Verify a valid checkpoint
 *   3. Reject modified Merkle roots (MERKLE_MISMATCH)
 *   4. Reject modified sequence ranges (INVALID_CHECKPOINT)
 *   5. Reject invalid / forged signatures (INVALID_SIGNATURE)
 *   6. Reject malformed checkpoints (INVALID_CHECKPOINT)
 *   7. Verify historical checkpoints after key rotation
 *   8. Merkle inclusion proof verification against checkpoint
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  createCheckpoint,
  verifyCheckpoint,
  verifyCheckpointProof,
  VerificationStatus,
  CHECKPOINT_SCHEMA_VERSION,
} from '../src/checkpoints/checkpointService.js';
import { KeyManager } from '../src/keys/keyManager.js';
import { generateMerkleProof, buildMerkleTree } from '../src/merkle/merkleTree.js';
import { sha256hex } from '../src/crypto/hashing.js';

function createTempKeysDir() {
  return mkdtempSync(join(tmpdir(), 'securelog-checkpoint-test-'));
}

function makeLeafHashes(n) {
  return Array.from({ length: n }, (_, i) => sha256hex(`event-hash-${i + 1}`));
}

test('1 & 2. Generate and verify a valid signed checkpoint', async () => {
  const dir = createTempKeysDir();
  try {
    const km = new KeyManager(dir);
    await km.loadOrGenerate('checkpoint-passphrase');

    const leafHashes = makeLeafHashes(5);
    const checkpoint = createCheckpoint(
      {
        source_id: 'server-alpha',
        start_sequence: 1,
        end_sequence: 5,
        leaf_hashes: leafHashes,
      },
      km
    );

    // Assert schema structure
    assert.equal(checkpoint.schema_version, CHECKPOINT_SCHEMA_VERSION);
    assert.equal(checkpoint.source_id, 'server-alpha');
    assert.equal(checkpoint.start_sequence, 1);
    assert.equal(checkpoint.end_sequence, 5);
    assert.equal(checkpoint.event_count, 5);
    assert.match(checkpoint.merkle_root, /^[0-9a-f]{64}$/i);
    assert.match(checkpoint.signature, /^[0-9a-f]{128}$/i);
    assert.equal(checkpoint.signing_key_id, km.keyId);
    assert.equal(checkpoint.signer_public_key, km.publicKeyHex);
    assert.equal(checkpoint.blockchain, null);

    // Verify checkpoint
    const res = verifyCheckpoint(checkpoint, km);
    assert.equal(res.status, VerificationStatus.VERIFIED);
    assert.equal(res.valid, true);
    assert.equal(res.failures.length, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('3. Reject modified Merkle root with MERKLE_MISMATCH', async () => {
  const dir = createTempKeysDir();
  try {
    const km = new KeyManager(dir);
    await km.loadOrGenerate('checkpoint-passphrase');

    const leafHashes = makeLeafHashes(3);
    const checkpoint = createCheckpoint(
      {
        source_id: 'source-1',
        start_sequence: 1,
        end_sequence: 3,
        leaf_hashes: leafHashes,
      },
      km
    );

    // Tamper with merkle_root
    checkpoint.merkle_root = sha256hex('tampered-root');

    const res = verifyCheckpoint(checkpoint, km);
    assert.equal(res.status, VerificationStatus.MERKLE_MISMATCH);
    assert.equal(res.valid, false);
    assert.ok(res.failures.some((f) => f.includes('Merkle root mismatch')));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('4. Reject modified sequence ranges or mismatched event_count with INVALID_CHECKPOINT', async () => {
  const dir = createTempKeysDir();
  try {
    const km = new KeyManager(dir);
    await km.loadOrGenerate('checkpoint-passphrase');

    const leafHashes = makeLeafHashes(4);
    const checkpoint = createCheckpoint(
      {
        source_id: 'source-1',
        start_sequence: 10,
        end_sequence: 13,
        leaf_hashes: leafHashes,
      },
      km
    );

    // Modify start_sequence without updating event_count
    checkpoint.start_sequence = 11;

    const res = verifyCheckpoint(checkpoint, km);
    assert.equal(res.status, VerificationStatus.INVALID_CHECKPOINT);
    assert.equal(res.valid, false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('5. Reject invalid or forged signatures with INVALID_SIGNATURE', async () => {
  const dir = createTempKeysDir();
  try {
    const km = new KeyManager(dir);
    await km.loadOrGenerate('checkpoint-passphrase');

    const leafHashes = makeLeafHashes(2);
    const checkpoint = createCheckpoint(
      {
        source_id: 'source-1',
        start_sequence: 1,
        end_sequence: 2,
        leaf_hashes: leafHashes,
      },
      km
    );

    // Corrupt signature
    checkpoint.signature = (checkpoint.signature[0] === 'f' ? 'e' : 'f') + checkpoint.signature.slice(1);

    const res = verifyCheckpoint(checkpoint, km);
    assert.equal(res.status, VerificationStatus.INVALID_SIGNATURE);
    assert.equal(res.valid, false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('6. Reject malformed checkpoints with missing fields', async () => {
  const dir = createTempKeysDir();
  try {
    const km = new KeyManager(dir);
    await km.loadOrGenerate('checkpoint-passphrase');

    const leafHashes = makeLeafHashes(2);
    const checkpoint = createCheckpoint(
      {
        source_id: 'source-1',
        start_sequence: 1,
        end_sequence: 2,
        leaf_hashes: leafHashes,
      },
      km
    );

    // Delete required field
    delete checkpoint.signing_key_id;

    const res = verifyCheckpoint(checkpoint, km);
    assert.equal(res.status, VerificationStatus.INVALID_CHECKPOINT);
    assert.equal(res.valid, false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('7. Verify historical checkpoints after key rotation', async () => {
  const dir = createTempKeysDir();
  try {
    const km = new KeyManager(dir);
    await km.loadOrGenerate('initial-key-passphrase');

    const leafHashes = makeLeafHashes(3);
    const historicalCheckpoint = createCheckpoint(
      {
        source_id: 'source-historical',
        start_sequence: 1,
        end_sequence: 3,
        leaf_hashes: leafHashes,
      },
      km
    );

    const oldKeyId = historicalCheckpoint.signing_key_id;

    // Rotate key
    await km.rotateKey('rotated-passphrase');
    assert.notEqual(km.keyId, oldKeyId, 'KeyManager active key must be updated');

    // The historical checkpoint must STILL verify successfully using the historical registry
    const res = verifyCheckpoint(historicalCheckpoint, km);
    assert.equal(res.status, VerificationStatus.VERIFIED);
    assert.equal(res.valid, true);

    // Standalone checkpoint with forged unknown signing_key_id must fail
    historicalCheckpoint.signing_key_id = '00000000-0000-4000-8000-000000000000';
    const resUnknown = verifyCheckpoint(historicalCheckpoint, km);
    assert.equal(resUnknown.status, VerificationStatus.UNKNOWN_SIGNING_KEY);
    assert.equal(resUnknown.valid, false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('8. Merkle inclusion proof verification against checkpoint', async () => {
  const dir = createTempKeysDir();
  try {
    const km = new KeyManager(dir);
    await km.loadOrGenerate('passphrase');

    const leafHashes = makeLeafHashes(4);
    const checkpoint = createCheckpoint(
      {
        source_id: 'source-proof',
        start_sequence: 1,
        end_sequence: 4,
        leaf_hashes: leafHashes,
      },
      km
    );

    // Generate proof for leaf index 2
    const tree = buildMerkleTree(leafHashes);
    const proof = generateMerkleProof(tree, 2);

    // Verify proof against checkpoint
    const res = verifyCheckpointProof(checkpoint, leafHashes[2], proof.proof);
    assert.equal(res.status, VerificationStatus.VERIFIED);
    assert.equal(res.valid, true);

    // Verify proof for wrong leaf fails
    const resWrong = verifyCheckpointProof(checkpoint, sha256hex('wrong-leaf'), proof.proof);
    assert.equal(resWrong.status, VerificationStatus.INVALID_PROOF);
    assert.equal(resWrong.valid, false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
