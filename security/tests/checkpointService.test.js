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
  createFssCheckpoint,
  verifyCheckpoint,
  verifyCheckpointProof,
  VerificationStatus,
  CHECKPOINT_SCHEMA_VERSION,
  CHECKPOINT_FSS_SCHEMA_VERSION,
  SIGNATURE_ALGORITHM_FSS,
} from '../src/checkpoints/checkpointService.js';
import { KeyManager } from '../src/keys/keyManager.js';
import { FssStateManager } from '../src/keys/fssStateManager.js';
import { generateFssMasterState } from '../src/crypto/fssSigner.js';
import { generateMerkleProof, buildMerkleTree } from '../src/merkle/merkleTree.js';
import { sha256hex } from '../src/crypto/hashing.js';

function createTempKeysDir() {
  return mkdtempSync(join(tmpdir(), 'securelog-checkpoint-test-'));
}

function createTestFssSetup(dir, maxEpochs = 8) {
  const { state, publicTree } = generateFssMasterState({ maxEpochs });
  const statePath = join(dir, 'fss_state.json');
  const fss = new FssStateManager({ statePath });
  fss.initState(state, true);
  return { fss, publicTree };
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

test('9. Generate and verify a valid FSS-signed checkpoint', async () => {
  const dir = createTempKeysDir();
  try {
    const { fss } = createTestFssSetup(dir, 8);
    const leafHashes = makeLeafHashes(5);

    // Test both createFssCheckpoint and createCheckpoint auto-delegation
    const checkpoint = createFssCheckpoint(
      {
        source_id: 'server-fss',
        start_sequence: 1,
        end_sequence: 5,
        leaf_hashes: leafHashes,
      },
      fss
    );

    assert.equal(checkpoint.schema_version, CHECKPOINT_FSS_SCHEMA_VERSION);
    assert.equal(checkpoint.signature_algorithm, SIGNATURE_ALGORITHM_FSS);
    assert.equal(checkpoint.source_id, 'server-fss');
    assert.equal(checkpoint.start_sequence, 1);
    assert.equal(checkpoint.end_sequence, 5);
    assert.equal(checkpoint.event_count, 5);
    assert.equal(checkpoint.fss_epoch, 0);
    assert.equal(checkpoint.mpk, fss.mpk);
    assert.match(checkpoint.epoch_public_key, /^[0-9a-f]{64}$/i);
    assert.match(checkpoint.signature, /^[0-9a-f]{128}$/i);
    assert.ok(Array.isArray(checkpoint.fss_auth_path));

    // Verify using FssStateManager
    const resMgr = verifyCheckpoint(checkpoint, fss);
    assert.equal(resMgr.valid, true);
    assert.equal(resMgr.status, VerificationStatus.VERIFIED);
    assert.equal(resMgr.checks.fss_auth_path, true);

    // Verify using raw MPK string
    const resMpk = verifyCheckpoint(checkpoint, fss.mpk);
    assert.equal(resMpk.valid, true);
    assert.equal(resMpk.status, VerificationStatus.VERIFIED);

    // Also test createCheckpoint with FssStateManager
    const checkpointAuto = createCheckpoint(
      {
        source_id: 'server-fss',
        start_sequence: 6,
        end_sequence: 10,
        leaf_hashes: leafHashes,
      },
      fss
    );
    assert.equal(checkpointAuto.schema_version, CHECKPOINT_FSS_SCHEMA_VERSION);
    assert.equal(verifyCheckpoint(checkpointAuto, fss).valid, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('10. Reject FSS checkpoint with modified Merkle root or sequence bounds', async () => {
  const dir = createTempKeysDir();
  try {
    const { fss } = createTestFssSetup(dir, 8);
    const leafHashes = makeLeafHashes(3);

    const checkpoint = createFssCheckpoint(
      {
        source_id: 'server-fss',
        start_sequence: 1,
        end_sequence: 3,
        leaf_hashes: leafHashes,
      },
      fss
    );

    // Tamper with Merkle root
    const tamperedRoot = { ...checkpoint, merkle_root: sha256hex('tampered-fss-root') };
    const resRoot = verifyCheckpoint(tamperedRoot, fss.mpk);
    assert.equal(resRoot.valid, false);
    assert.equal(resRoot.status, VerificationStatus.MERKLE_MISMATCH);

    // Tamper with start_sequence
    const tamperedSeq = { ...checkpoint, start_sequence: 2 };
    const resSeq = verifyCheckpoint(tamperedSeq, fss.mpk);
    assert.equal(resSeq.valid, false);
    assert.equal(resSeq.status, VerificationStatus.INVALID_CHECKPOINT);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('11. Reject FSS checkpoint with forged signature or tampered auth path', async () => {
  const dir = createTempKeysDir();
  try {
    const { fss } = createTestFssSetup(dir, 8);
    const leafHashes = makeLeafHashes(2);

    const checkpoint = createFssCheckpoint(
      {
        source_id: 'server-fss',
        start_sequence: 1,
        end_sequence: 2,
        leaf_hashes: leafHashes,
      },
      fss
    );

    // Corrupt signature
    const badSig = {
      ...checkpoint,
      signature: (checkpoint.signature[0] === '0' ? '1' : '0') + checkpoint.signature.slice(1),
      fss_signature: (checkpoint.signature[0] === '0' ? '1' : '0') + checkpoint.signature.slice(1),
    };
    const resSig = verifyCheckpoint(badSig, fss.mpk);
    assert.equal(resSig.valid, false);
    assert.equal(resSig.status, VerificationStatus.INVALID_SIGNATURE);

    // Corrupt auth path
    const badAuth = {
      ...checkpoint,
      fss_auth_path: checkpoint.fss_auth_path.map((node) => ({
        ...node,
        sibling_hash: sha256hex('corrupt-auth-hash'),
      })),
    };
    const resAuth = verifyCheckpoint(badAuth, fss.mpk);
    assert.equal(resAuth.valid, false);
    assert.equal(resAuth.status, VerificationStatus.MERKLE_MISMATCH);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('12. Reject FSS checkpoint when epoch is revoked via revocation notice', async () => {
  const dir = createTempKeysDir();
  try {
    const { fss, publicTree } = createTestFssSetup(dir, 8);
    const leafHashes = makeLeafHashes(3);

    const checkpointEpoch0 = createFssCheckpoint(
      {
        source_id: 'server-fss',
        start_sequence: 1,
        end_sequence: 3,
        leaf_hashes: leafHashes,
      },
      fss
    );

    // Advance to epoch 1
    fss.evolve(publicTree.authPaths[1]);
    assert.equal(fss.epoch, 1);

    const checkpointEpoch1 = createFssCheckpoint(
      {
        source_id: 'server-fss',
        start_sequence: 4,
        end_sequence: 6,
        leaf_hashes: leafHashes,
      },
      fss
    );

    // Revoke at epoch 1
    const revocationNotice = fss.revokeEmergency({ reason: 'Emergency security breach during epoch 1' });
    assert.equal(revocationNotice.compromiseEpoch, 1);

    // Epoch 0 was created BEFORE revocation -> must still verify!
    const resEpoch0 = verifyCheckpoint(checkpointEpoch0, fss.mpk, { revocationNotice });
    assert.equal(resEpoch0.valid, true);
    assert.equal(resEpoch0.status, VerificationStatus.VERIFIED);

    // Epoch 1 is revoked -> verification MUST fail with KEY_REVOKED
    const resEpoch1 = verifyCheckpoint(checkpointEpoch1, fss.mpk, { revocationNotice });
    assert.equal(resEpoch1.valid, false);
    assert.equal(resEpoch1.status, VerificationStatus.KEY_REVOKED);
    assert.ok(resEpoch1.failures.some((f) => f.includes('revoked')));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('13. Verify historical FSS checkpoint across multiple epoch evolutions', async () => {
  const dir = createTempKeysDir();
  try {
    const { fss, publicTree } = createTestFssSetup(dir, 8);
    const leafHashes = makeLeafHashes(2);

    const historicalCp = createFssCheckpoint(
      {
        source_id: 'server-fss',
        start_sequence: 1,
        end_sequence: 2,
        leaf_hashes: leafHashes,
      },
      fss
    );
    assert.equal(historicalCp.fss_epoch, 0);

    // Advance epoch 3 times
    fss.evolve(publicTree.authPaths[1]);
    fss.evolve(publicTree.authPaths[2]);
    fss.evolve(publicTree.authPaths[3]);
    assert.equal(fss.epoch, 3);

    // Historical checkpoint from epoch 0 must STILL verify successfully with MPK
    const resHistorical = verifyCheckpoint(historicalCp, fss.mpk);
    assert.equal(resHistorical.valid, true);
    assert.equal(resHistorical.status, VerificationStatus.VERIFIED);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
