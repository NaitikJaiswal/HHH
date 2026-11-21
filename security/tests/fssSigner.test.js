/**
 * @file fssSigner.test.js
 * @description Unit tests for Merkle Key Tree Forward-Secure Signatures (MKT-FSS).
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { unlinkSync, existsSync } from 'node:fs';

import {
  generateFssMasterState,
  signFssEpoch,
  verifyFssSignature,
  evolveFssState,
  saveFssState,
  loadFssState,
  computeLeafHash,
  computeInternalNodeHash,
  buildKeyTree,
  generateAuthPath,
  FSS_VERSION,
} from '../src/crypto/fssSigner.js';

describe('Forward-Secure Signatures (MKT-FSS)', () => {
  it('1. Generates master state with valid MPK and epoch 0 active state', () => {
    const { state, publicTree, mpk } = generateFssMasterState({ maxEpochs: 8 });

    assert.equal(typeof mpk, 'string');
    assert.equal(mpk.length, 64);
    assert.equal(state.epoch, 0);
    assert.equal(state.maxEpochs, 8);
    assert.equal(state.mpk, mpk);
    assert.equal(publicTree.mpk, mpk);
    assert.equal(publicTree.publicKeys.length, 8);
    assert.equal(publicTree.authPaths.length, 8);
  });

  it('2. Signs payload in epoch 0 and verifies against MPK', () => {
    const { state, mpk } = generateFssMasterState({ maxEpochs: 8 });
    const payload = {
      event_id: 'evt-001',
      sequence_number: 1,
      message: 'Initial checkpoint creation',
    };

    const sigBundle = signFssEpoch(state, payload);

    assert.equal(sigBundle.version, FSS_VERSION);
    assert.equal(sigBundle.epoch, 0);
    assert.equal(typeof sigBundle.signature, 'string');
    assert.equal(sigBundle.signature.length, 128);

    const result = verifyFssSignature(mpk, payload, sigBundle);
    assert.equal(result.valid, true);
    assert.equal(result.epoch, 0);
    assert.equal(result.mpk, mpk);
  });

  it('3. Successfully evolves through multiple epochs (0 -> 1 -> 2) verifying under the SAME fixed MPK', () => {
    const { state: state0, publicTree, mpk } = generateFssMasterState({ maxEpochs: 4 });

    // Epoch 0
    const payload0 = { sequence_number: 100, msg: 'Epoch 0 log' };
    const sig0 = signFssEpoch(state0, payload0);
    const ver0 = verifyFssSignature(mpk, payload0, sig0);
    assert.equal(ver0.valid, true);

    // Evolve 0 -> 1
    const state1 = evolveFssState(state0, publicTree.authPaths[1]);
    assert.equal(state1.epoch, 1);
    assert.equal(state0.seedHex, '0000000000000000000000000000000000000000000000000000000000000000'); // old seed wiped

    const payload1 = { sequence_number: 101, msg: 'Epoch 1 log' };
    const sig1 = signFssEpoch(state1, payload1);
    const ver1 = verifyFssSignature(mpk, payload1, sig1);
    assert.equal(ver1.valid, true);

    // Evolve 1 -> 2
    const state2 = evolveFssState(state1, publicTree.authPaths[2]);
    assert.equal(state2.epoch, 2);

    const payload2 = { sequence_number: 102, msg: 'Epoch 2 log' };
    const sig2 = signFssEpoch(state2, payload2);
    const ver2 = verifyFssSignature(mpk, payload2, sig2);
    assert.equal(ver2.valid, true);

    // Historical signature from epoch 0 still verifies perfectly against MPK
    const ver0Again = verifyFssSignature(mpk, payload0, sig0);
    assert.equal(ver0Again.valid, true);
  });

  it('4. Rejects tampered payload with INVALID_SIGNATURE', () => {
    const { state, mpk } = generateFssMasterState({ maxEpochs: 4 });
    const originalPayload = { message: 'Original authentic log', seq: 1 };
    const sigBundle = signFssEpoch(state, originalPayload);

    const tamperedPayload = { message: 'Attacker altered text', seq: 1 };
    const result = verifyFssSignature(mpk, tamperedPayload, sigBundle);

    assert.equal(result.valid, false);
    assert.equal(result.error, 'INVALID_SIGNATURE');
  });

  it('5. Rejects corrupted signature bytes with INVALID_SIGNATURE', () => {
    const { state, mpk } = generateFssMasterState({ maxEpochs: 4 });
    const payload = { seq: 42, event: 'AUTH_SUCCESS' };
    const sigBundle = signFssEpoch(state, payload);

    // Flip last byte
    const flippedChar = sigBundle.signature.endsWith('a') ? 'b' : 'a';
    const badSigBundle = {
      ...sigBundle,
      signature: sigBundle.signature.slice(0, -1) + flippedChar,
    };

    const result = verifyFssSignature(mpk, payload, badSigBundle);
    assert.equal(result.valid, false);
    assert.equal(result.error, 'INVALID_SIGNATURE');
  });

  it('6. Rejects mismatched epoch in signature bundle', () => {
    const { state, publicTree, mpk } = generateFssMasterState({ maxEpochs: 4 });
    const payload = { test: true };
    const sigBundle = signFssEpoch(state, payload);

    // Attacker claims epoch 1 instead of 0
    const spoofedBundle = {
      ...sigBundle,
      epoch: 1,
      authPath: publicTree.authPaths[1],
    };

    const result = verifyFssSignature(mpk, payload, spoofedBundle);
    assert.equal(result.valid, false);
  });

  it('7. Rejects corrupted Merkle auth path with MERKLE_PATH_MISMATCH', () => {
    const { state, mpk } = generateFssMasterState({ maxEpochs: 4 });
    const payload = { test: 'path_tampering' };
    const sigBundle = signFssEpoch(state, payload);

    // Alter sibling hash in auth path
    const corruptedPath = JSON.parse(JSON.stringify(sigBundle.authPath));
    corruptedPath[0].sibling_hash = '0000000000000000000000000000000000000000000000000000000000000000';

    const corruptedBundle = {
      ...sigBundle,
      authPath: corruptedPath,
    };

    const result = verifyFssSignature(mpk, payload, corruptedBundle);
    assert.equal(result.valid, false);
    assert.equal(result.error, 'MERKLE_PATH_MISMATCH');
  });

  it('8. Rejects verification against wrong MPK', () => {
    const { state } = generateFssMasterState({ maxEpochs: 4 });
    const payload = { test: 'wrong_mpk' };
    const sigBundle = signFssEpoch(state, payload);

    const wrongMpk = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
    const result = verifyFssSignature(wrongMpk, payload, sigBundle);

    assert.equal(result.valid, false);
    assert.ok(result.error === 'MPK_MISMATCH' || result.error === 'MERKLE_PATH_MISMATCH');
  });

  it('9. Persists active state to disk and reloads for valid signing', () => {
    const tempStateFile = join(tmpdir(), `test_fss_state_${Date.now()}.json`);
    try {
      const { state, mpk } = generateFssMasterState({ maxEpochs: 4 });
      saveFssState(state, tempStateFile);

      const reloadedState = loadFssState(tempStateFile);
      assert.equal(reloadedState.epoch, 0);
      assert.equal(reloadedState.mpk, mpk);

      const payload = { log: 'post-reload signing' };
      const sigBundle = signFssEpoch(reloadedState, payload);
      const verifyResult = verifyFssSignature(mpk, payload, sigBundle);
      assert.equal(verifyResult.valid, true);
    } finally {
      if (existsSync(tempStateFile)) {
        unlinkSync(tempStateFile);
      }
    }
  });

  it('10. Enforces maximum lifetime boundary (cannot evolve beyond maxEpochs)', () => {
    const { state, publicTree } = generateFssMasterState({ maxEpochs: 2 });
    assert.equal(state.epoch, 0);

    const state1 = evolveFssState(state, publicTree.authPaths[1]);
    assert.equal(state1.epoch, 1);

    assert.throws(
      () => evolveFssState(state1, null),
      /cannot evolve beyond maximum epochs/
    );
  });
});
