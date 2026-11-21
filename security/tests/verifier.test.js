/**
 * Tests for verifier.js — Comprehensive verification engine.
 * Uses Node.js built-in node:test and node:assert/strict.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  verifySignedCheckpoint,
  verifyInclusionProof,
  verifyEventsAgainstCheckpoint,
  VerificationStatus,
} from '../src/verification/verifier.js';
import { KeyManager } from '../src/keys/keyManager.js';
import { FssStateManager } from '../src/keys/fssStateManager.js';
import { generateFssMasterState } from '../src/crypto/fssSigner.js';
import { createCheckpoint, createFssCheckpoint } from '../src/checkpoints/checkpointService.js';
import { buildChain } from '../src/crypto/hashChain.js';
import { buildMerkleTree, generateMerkleProof } from '../src/merkle/merkleTree.js';

function createTempKeysDir() {
  return mkdtempSync(join(tmpdir(), 'securelog-verifier-test-'));
}

function createTestFssSetup(dir, maxEpochs = 8) {
  const { state, publicTree } = generateFssMasterState({ maxEpochs });
  const statePath = join(dir, 'fss_state.json');
  const fss = new FssStateManager({ statePath });
  fss.initState(state, true);
  return { fss, publicTree };
}

function makeEvents(n, startSeq = 1) {
  const rawEvents = Array.from({ length: n }, (_, i) => ({
    event_id: `event-uuid-${startSeq + i}`,
    event_time: '2026-11-20T12:00:00Z',
    event_type: 'SYSTEM',
    message: `Event message ${startSeq + i}`,
    metadata: { seq: startSeq + i },
    sequence_number: startSeq + i,
    severity: 'INFO',
    source_id: 'server-1',
  }));
  return buildChain(rawEvents);
}

test('1. verifyEventsAgainstCheckpoint verifies valid sequence', async () => {
  const dir = createTempKeysDir();
  try {
    const km = new KeyManager(dir);
    await km.loadOrGenerate('verifier-passphrase');

    const events = makeEvents(5, 1);
    const leafHashes = events.map((e) => e.current_hash);

    const checkpoint = createCheckpoint(
      {
        source_id: 'server-1',
        start_sequence: 1,
        end_sequence: 5,
        leaf_hashes: leafHashes,
      },
      km
    );

    const result = verifyEventsAgainstCheckpoint(checkpoint, events, km);
    assert.equal(result.valid, true);
    assert.equal(result.status, VerificationStatus.VERIFIED);
    assert.equal(result.failures.length, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('2. verifyEventsAgainstCheckpoint detects tampered event message', async () => {
  const dir = createTempKeysDir();
  try {
    const km = new KeyManager(dir);
    await km.loadOrGenerate('verifier-passphrase');

    const events = makeEvents(3, 1);
    const leafHashes = events.map((e) => e.current_hash);

    const checkpoint = createCheckpoint(
      {
        source_id: 'server-1',
        start_sequence: 1,
        end_sequence: 3,
        leaf_hashes: leafHashes,
      },
      km
    );

    // Tamper with event 1
    events[1].message = 'HACKED EVENT MESSAGE';

    const result = verifyEventsAgainstCheckpoint(checkpoint, events, km);
    assert.equal(result.valid, false);
    assert.equal(result.status, VerificationStatus.MERKLE_MISMATCH);
    assert.ok(result.failures.some((f) => f.includes('hash mismatch')));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('3. verifyInclusionProof verifies inclusion correctly', async () => {
  const dir = createTempKeysDir();
  try {
    const km = new KeyManager(dir);
    await km.loadOrGenerate('verifier-passphrase');

    const events = makeEvents(4, 1);
    const leafHashes = events.map((e) => e.current_hash);

    const checkpoint = createCheckpoint(
      {
        source_id: 'server-1',
        start_sequence: 1,
        end_sequence: 4,
        leaf_hashes: leafHashes,
      },
      km
    );

    const tree = buildMerkleTree(leafHashes);
    const proof = generateMerkleProof(tree, 1);

    const result = verifyInclusionProof(checkpoint, leafHashes[1], proof.proof);
    assert.equal(result.valid, true);
    assert.equal(result.status, VerificationStatus.VERIFIED);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('4. verifyEventsAgainstCheckpoint verifies valid sequence with FSS checkpoint', async () => {
  const dir = createTempKeysDir();
  try {
    const { fss } = createTestFssSetup(dir, 8);
    const events = makeEvents(4, 1);
    const leafHashes = events.map((e) => e.current_hash);

    const checkpoint = createFssCheckpoint(
      {
        source_id: 'server-1',
        start_sequence: 1,
        end_sequence: 4,
        leaf_hashes: leafHashes,
      },
      fss
    );

    const result = verifyEventsAgainstCheckpoint(checkpoint, events, fss.mpk);
    assert.equal(result.valid, true);
    assert.equal(result.status, VerificationStatus.VERIFIED);
    assert.equal(result.failures.length, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('5. verifyEventsAgainstCheckpoint detects tampered event message with FSS checkpoint', async () => {
  const dir = createTempKeysDir();
  try {
    const { fss } = createTestFssSetup(dir, 8);
    const events = makeEvents(3, 1);
    const leafHashes = events.map((e) => e.current_hash);

    const checkpoint = createFssCheckpoint(
      {
        source_id: 'server-1',
        start_sequence: 1,
        end_sequence: 3,
        leaf_hashes: leafHashes,
      },
      fss
    );

    // Tamper with event 2
    events[2].message = 'TAMPERED IN FSS TEST';

    const result = verifyEventsAgainstCheckpoint(checkpoint, events, fss.mpk);
    assert.equal(result.valid, false);
    assert.equal(result.status, VerificationStatus.MERKLE_MISMATCH);
    assert.ok(result.failures.some((f) => f.includes('hash mismatch')));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
