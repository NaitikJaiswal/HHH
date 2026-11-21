/**
 * @file fssStateManager.test.js
 * @description Unit tests for FssStateManager (rollback defense, key erasure, revocation).
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { writeFileSync, existsSync, unlinkSync } from 'node:fs';

import { FssStateManager, REVOCATION_VERSION } from '../src/keys/fssStateManager.js';
import { generateFssMasterState, signFssEpoch, evolveSeed } from '../src/crypto/fssSigner.js';

describe('FSS State Manager & Rollback Protection', () => {
  it('1. Initializes and persists state to disk with atomic write', () => {
    const tempDir = tmpdir();
    const statePath = join(tempDir, `fss_state_${Date.now()}_1.json`);
    const { state } = generateFssMasterState({ maxEpochs: 8 });

    try {
      const manager = new FssStateManager({ statePath });
      manager.initState(state, true);

      assert.equal(existsSync(statePath), true);
      assert.equal(manager.activeState.epoch, 0);

      // Reloading from disk succeeds
      const manager2 = new FssStateManager({ statePath });
      const loaded = manager2.loadStateFromDisk();
      assert.equal(loaded.epoch, 0);
      assert.equal(loaded.mpk, state.mpk);
    } finally {
      if (existsSync(statePath)) unlinkSync(statePath);
    }
  });

  it('2. Evolving updates state atomically and advances high-water mark', () => {
    const tempDir = tmpdir();
    const statePath = join(tempDir, `fss_state_${Date.now()}_2.json`);
    const { state, publicTree } = generateFssMasterState({ maxEpochs: 8 });

    try {
      const manager = new FssStateManager({ statePath });
      manager.initState(state, true);

      const evolved = manager.evolve(publicTree.authPaths[1]);
      assert.equal(evolved.epoch, 1);
      assert.equal(manager.highWaterMarkEpoch, 1);

      // Verify reloaded state matches epoch 1
      const managerReload = new FssStateManager({ statePath });
      managerReload.loadStateFromDisk();
      assert.equal(managerReload.activeState.epoch, 1);
    } finally {
      if (existsSync(statePath)) unlinkSync(statePath);
    }
  });

  it('3. Detects and blocks rollback attack when older state backup is restored', () => {
    const tempDir = tmpdir();
    const statePath = join(tempDir, `fss_state_${Date.now()}_3.json`);
    const { state, publicTree } = generateFssMasterState({ maxEpochs: 8 });

    try {
      const manager = new FssStateManager({ statePath });
      manager.initState(state, true);

      // Backup state at epoch 0
      const backupState0 = JSON.parse(JSON.stringify(manager.activeState));

      // Evolve to epoch 1, then epoch 2
      manager.evolve(publicTree.authPaths[1]);
      manager.evolve(publicTree.authPaths[2]);
      assert.equal(manager.activeState.epoch, 2);

      // Attacker attempts to restore old backup (epoch 0) into active manager
      assert.throws(
        () => manager.initState(backupState0),
        /STATE_ROLLBACK_DETECTED.*epoch 0 is lower than high-water mark 2/
      );

      // Attacker overwrites file on disk with epoch 0 backup and restarts manager
      writeFileSync(statePath, JSON.stringify(backupState0, null, 2));

      // New manager instance aware of high-water mark (e.g. from witness log or database)
      const managerWithWitness = new FssStateManager({
        statePath,
        highestWitnessedEpoch: 2,
      });

      assert.throws(
        () => managerWithWitness.loadStateFromDisk(),
        /STATE_ROLLBACK_DETECTED.*loaded state epoch 0 is below high-water mark 2/
      );
    } finally {
      if (existsSync(statePath)) unlinkSync(statePath);
    }
  });

  it('4. Rejects active state if behind external witness checkpoint', () => {
    const tempDir = tmpdir();
    const statePath = join(tempDir, `fss_state_${Date.now()}_4.json`);
    const { state } = generateFssMasterState({ maxEpochs: 8 });

    try {
      const manager = new FssStateManager({ statePath });
      manager.initState(state, true);
      assert.equal(manager.activeState.epoch, 0);

      // Verifier/witness observes that external ledger already anchored epoch 3
      assert.throws(
        () => manager.recordWitnessedEpoch(3),
        /STATE_ROLLBACK_DETECTED.*active state epoch 0 is behind external witness 3/
      );
    } finally {
      if (existsSync(statePath)) unlinkSync(statePath);
    }
  });

  it('5. Shreds key file on emergency revocation and halts further signing', () => {
    const tempDir = tmpdir();
    const statePath = join(tempDir, `fss_state_${Date.now()}_5.json`);
    const revocationPath = join(tempDir, `fss_revocation_${Date.now()}_5.json`);
    const { state, publicTree } = generateFssMasterState({ maxEpochs: 8 });

    try {
      const manager = new FssStateManager({ statePath, revocationPath });
      manager.initState(state, true);
      manager.evolve(publicTree.authPaths[1]); // epoch 1

      // Sign before compromise
      const sigBefore = manager.sign({ seq: 10, msg: 'Pre-compromise log' });
      assert.equal(sigBefore.epoch, 1);

      // Trigger emergency revocation at epoch 1
      const notice = manager.revokeEmergency({
        reason: 'Host kernel compromise detected',
        lastValidCheckpointHash: '1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff',
      });

      assert.equal(notice.version, REVOCATION_VERSION);
      assert.equal(notice.compromiseEpoch, 1);

      // Active state file must be wiped from disk
      assert.equal(existsSync(statePath), false);
      assert.equal(manager.activeState, null);

      // Further signing is disallowed
      assert.throws(
        () => manager.sign({ seq: 11, msg: 'Post-compromise attempt' }),
        /FSS_REVOKED/
      );
    } finally {
      if (existsSync(statePath)) unlinkSync(statePath);
      if (existsSync(revocationPath)) unlinkSync(revocationPath);
    }
  });

  it('6. Enforces revocation verification boundary (epochs < t* valid, epochs >= t* rejected)', () => {
    const { state: state0, publicTree, mpk } = generateFssMasterState({ maxEpochs: 8 });

    // Epoch 0 signature
    const payload0 = { seq: 1, text: 'Clean log before incident' };
    const sig0 = signFssEpoch(state0, payload0);

    // Evolve 0 -> 1
    const state1 = JSON.parse(JSON.stringify(state0));
    state1.epoch = 1;
    // Derive real epoch 1 key from K_0 evolution
    const state1Real = {
      ...state0,
      epoch: 1,
      seedHex: evolveSeed(Buffer.from(state0.seedHex, 'hex')).toString('hex'),
      authPath: publicTree.authPaths[1],
    };
    const payload1 = { seq: 2, text: 'Log during compromised epoch' };
    const sig1 = signFssEpoch(state1Real, payload1);

    // Revocation notice declaring compromise at epoch 1
    const revocationNotice = {
      version: REVOCATION_VERSION,
      mpk,
      compromiseEpoch: 1,
      reason: 'Root privilege escalation',
    };

    // Epoch 0: BEFORE compromise -> VALID and TRUSTED
    const ver0 = FssStateManager.verifyWithRevocation(mpk, payload0, sig0, revocationNotice);
    assert.equal(ver0.valid, true);
    assert.equal(ver0.epoch, 0);

    // Epoch 1: AT/AFTER compromise -> REJECTED with EPOCH_REVOKED
    const ver1 = FssStateManager.verifyWithRevocation(mpk, payload1, sig1, revocationNotice);
    assert.equal(ver1.valid, false);
    assert.equal(ver1.error, 'EPOCH_REVOKED');
  });
});
