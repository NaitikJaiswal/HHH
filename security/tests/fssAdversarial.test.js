/**
 * @file fssAdversarial.test.js
 * @description Comprehensive Adversarial Simulations for Forward-Secure Signatures (Stage 3.5).
 *
 * Implements the full adversarial test suite (Tests A through J):
 *   Test A: Retroactive forgery attempt with stolen active key SK_{t*} fails
 *   Test B: Historical verification of previous epochs remains valid after evolution
 *   Test C: Future signing boundaries (demonstrates what is and is not protected)
 *   Test D: Rollback attack simulation and high-water mark defense
 *   Test E: Epoch reuse and parameter permutation rejection
 *   Test F: Rogue leaf substitution attack rejection
 *   Test G: Merkle authentication path truncation/manipulation rejection
 *   Test H: Adaptive risk escalation and eager evolution under attack burst
 *   Test I: Emergency revocation boundary enforcement (t < t* vs t >= t*)
 *   Test J: Process crash/restart and state recovery
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { existsSync, writeFileSync, unlinkSync, readFileSync } from 'node:fs';
import { randomBytes, generateKeyPairSync, sign as cryptoSign } from 'node:crypto';

import {
  generateFssMasterState,
  signFssEpoch,
  verifyFssSignature,
  evolveFssState,
  evolveSeed,
  deriveEpochSigningSeed,
  privateKeyFromSeed,
  deriveRawPublicKey,
  saveFssState,
  loadFssState,
  FSS_VERSION,
} from '../src/crypto/fssSigner.js';

import {
  AdaptivePolicyController,
  POLICY_MODES,
  ANOMALY_TYPES,
} from '../src/policy/adaptivePolicyController.js';

import {
  FssStateManager,
  REVOCATION_VERSION,
} from '../src/keys/fssStateManager.js';

describe('Stage 3.5: Forward-Secure Adversarial Cryptographic Suite', () => {

  it('Test A: Retroactive forgery attempt with stolen active key SK_{t*} fails against MPK', () => {
    const { state: state0, publicTree, mpk } = generateFssMasterState({ maxEpochs: 16 });

    // Legitimate system signs log in epoch 0, 1, 2
    const msg0 = { seq: 10, text: 'Authentic genesis checkpoint' };
    const sig0 = signFssEpoch(state0, msg0);

    let currentState = state0;
    for (let e = 1; e <= 5; e++) {
      currentState = evolveFssState(currentState, publicTree.authPaths[e]);
    }
    assert.equal(currentState.epoch, 5);

    // ADVERSARIAL ACTION: Host compromise at epoch 5 (t* = 5)
    // Attacker exfiltrates active secret state SK_5
    const stolenSK5 = JSON.parse(JSON.stringify(currentState));

    // Attacker attempts retroactive forgery: forge a signature for past epoch 2
    // Strategy 1: Attacker uses stolen K_5 seed with epoch 2 parameter
    const forgedPayload = { seq: 10, text: 'FORGED RETROACTIVE LOG: attacker deleted evidence' };
    const forgedSigBundle = signFssEpoch(
      {
        ...stolenSK5,
        epoch: 2,
        authPath: publicTree.authPaths[2],
      },
      forgedPayload
    );

    // The forged signature must fail verification against MPK
    const verifyResult = verifyFssSignature(mpk, forgedPayload, forgedSigBundle);
    assert.equal(verifyResult.valid, false);
    assert.equal(verifyResult.error, 'MERKLE_PATH_MISMATCH');

    // Strategy 2: Attacker uses epoch 2's authentic public key from history but signs with sk_5
    const K_5_bytes = Buffer.from(stolenSK5.seedHex, 'hex');
    const sk_5 = deriveEpochSigningSeed(K_5_bytes);
    const priv5 = privateKeyFromSeed(sk_5);

    const envelope2 = Buffer.concat([
      Buffer.from('HHH-FSS-EPOCH-SIG', 'utf8'),
      Buffer.from([0, 0, 0, 2]),
      Buffer.from(publicTree.publicKeys[2], 'hex'),
      Buffer.from(JSON.stringify(forgedPayload), 'utf8'),
    ]);
    const sigWithWrongKey = cryptoSign(null, envelope2, priv5);

    const hybridBundle = {
      version: FSS_VERSION,
      epoch: 2,
      publicKey: publicTree.publicKeys[2],
      signature: sigWithWrongKey.toString('hex'),
      authPath: publicTree.authPaths[2],
      mpk,
    };

    const hybridResult = verifyFssSignature(mpk, forgedPayload, hybridBundle);
    assert.equal(hybridResult.valid, false);
    assert.equal(hybridResult.error, 'INVALID_SIGNATURE');
  });

  it('Test B: Historical signature verification after multiple evolutions remains valid', () => {
    const { state: state0, publicTree, mpk } = generateFssMasterState({ maxEpochs: 8 });

    // Sign payloads across epochs 0, 1, 2, 3
    const historicalRecords = [];
    let state = state0;

    for (let e = 0; e < 4; e++) {
      const payload = { epoch: e, data: `Log message for epoch ${e}` };
      const sig = signFssEpoch(state, payload);
      historicalRecords.push({ payload, sig });

      if (e < 3) {
        state = evolveFssState(state, publicTree.authPaths[e + 1]);
      }
    }
    assert.equal(state.epoch, 3);

    // Verifier checks all historical signatures against the single fixed MPK
    for (const record of historicalRecords) {
      const res = verifyFssSignature(mpk, record.payload, record.sig);
      assert.equal(res.valid, true);
      assert.equal(res.mpk, mpk);
    }
  });

  it('Test C: Future signing boundaries (demonstrates what is and is not protected)', () => {
    const { state: state0, publicTree, mpk } = generateFssMasterState({ maxEpochs: 8 });

    // Advance to epoch 2
    const state1 = evolveFssState(state0, publicTree.authPaths[1]);
    const state2 = evolveFssState(state1, publicTree.authPaths[2]);

    // Attacker steals SK_2
    const stolenSK2 = JSON.parse(JSON.stringify(state2));

    // DEMONSTRATION OF LIMIT: Attacker CAN evolve forward from t* = 2 to t = 3
    const K_2 = Buffer.from(stolenSK2.seedHex, 'hex');
    const K_3 = evolveSeed(K_2);
    const attackerState3 = {
      ...stolenSK2,
      epoch: 3,
      seedHex: K_3.toString('hex'),
      authPath: publicTree.authPaths[3],
    };

    const futurePayload = { text: 'Attacker signed future log at epoch 3' };
    const attackerSig3 = signFssEpoch(attackerState3, futurePayload);
    const futureVer = verifyFssSignature(mpk, futurePayload, attackerSig3);

    // Future signature verifies! This proves our security model correctly documents that
    // forward security protects epochs < t*, NOT epochs >= t*.
    assert.equal(futureVer.valid, true);
  });

  it('Test D: Rollback attack simulation and high-water mark defense', () => {
    const tempDir = tmpdir();
    const statePath = join(tempDir, `fss_rollback_${Date.now()}.json`);
    const { state: state0, publicTree } = generateFssMasterState({ maxEpochs: 8 });

    try {
      const manager = new FssStateManager({ statePath });
      manager.initState(state0, true);

      // Snapshot epoch 0
      const snapshotEpoch0 = readFileSync(statePath, 'utf8');

      // Legitimately evolve to epoch 1, then epoch 2
      manager.evolve(publicTree.authPaths[1]);
      manager.evolve(publicTree.authPaths[2]);
      assert.equal(manager.activeState.epoch, 2);

      // Attacker overwrites state file on disk with epoch 0 snapshot
      writeFileSync(statePath, snapshotEpoch0);

      // Manager detects rollback against internal high-water mark
      assert.throws(
        () => manager.loadStateFromDisk(),
        /STATE_ROLLBACK_DETECTED/
      );

      // Even on fresh boot, if an external witness recorded epoch 2:
      const rebootManager = new FssStateManager({
        statePath,
        highestWitnessedEpoch: 2,
      });

      assert.throws(
        () => rebootManager.loadStateFromDisk(),
        /STATE_ROLLBACK_DETECTED.*below high-water mark 2/
      );
    } finally {
      if (existsSync(statePath)) unlinkSync(statePath);
    }
  });

  it('Test E: Epoch reuse and parameter permutation rejection', () => {
    const { state: state0, publicTree, mpk } = generateFssMasterState({ maxEpochs: 4 });
    const payload = { seq: 50, msg: 'Epoch mix attack' };
    const sig0 = signFssEpoch(state0, payload);

    // Tamper 1: Bundle claims epoch 1, but carries signature made by key 0
    const tamperedBundle1 = {
      ...sig0,
      epoch: 1,
    };
    const res1 = verifyFssSignature(mpk, payload, tamperedBundle1);
    assert.equal(res1.valid, false);

    // Tamper 2: Bundle has epoch 0, but uses authPath of epoch 1
    const tamperedBundle2 = {
      ...sig0,
      authPath: publicTree.authPaths[1],
    };
    const res2 = verifyFssSignature(mpk, payload, tamperedBundle2);
    assert.equal(res2.valid, false);
    assert.equal(res2.error, 'MERKLE_PATH_MISMATCH');
  });

  it('Test F: Rogue leaf substitution attack rejection', () => {
    const { state: state0, publicTree, mpk } = generateFssMasterState({ maxEpochs: 4 });

    // Attacker generates their own rogue Ed25519 key
    const rogueKeys = generateKeyPairSync('ed25519');
    const roguePubRaw = rogueKeys.publicKey.export({ type: 'spki', format: 'der' }).slice(-32);

    const payload = { message: 'Rogue key payload' };
    const envelope = Buffer.concat([
      Buffer.from('HHH-FSS-EPOCH-SIG', 'utf8'),
      Buffer.from([0, 0, 0, 0]),
      roguePubRaw,
      Buffer.from(JSON.stringify(payload), 'utf8'),
    ]);
    const rogueSig = cryptoSign(null, envelope, rogueKeys.privateKey);

    // Attacker constructs bundle using rogue key pair + legitimate epoch 0 authPath
    const rogueBundle = {
      version: FSS_VERSION,
      epoch: 0,
      publicKey: roguePubRaw.toString('hex'),
      signature: rogueSig.toString('hex'),
      authPath: publicTree.authPaths[0],
      mpk,
    };

    const result = verifyFssSignature(mpk, payload, rogueBundle);
    assert.equal(result.valid, false);
    assert.equal(result.error, 'MERKLE_PATH_MISMATCH');
  });

  it('Test G: Merkle authentication path truncation/manipulation rejection', () => {
    const { state: state0, mpk } = generateFssMasterState({ maxEpochs: 8 });
    const payload = { event: 'PATH_TAMPER_TEST' };
    const sigBundle = signFssEpoch(state0, payload);

    // 1. Truncated path (remove last step)
    const truncatedBundle = {
      ...sigBundle,
      authPath: sigBundle.authPath.slice(0, -1),
    };
    const resTruncated = verifyFssSignature(mpk, payload, truncatedBundle);
    assert.equal(resTruncated.valid, false);
    assert.equal(resTruncated.error, 'MERKLE_PATH_MISMATCH');

    // 2. Flipped sibling position ('left' -> 'right')
    const flippedPath = JSON.parse(JSON.stringify(sigBundle.authPath));
    flippedPath[0].position = flippedPath[0].position === 'left' ? 'right' : 'left';
    const flippedBundle = {
      ...sigBundle,
      authPath: flippedPath,
    };
    const resFlipped = verifyFssSignature(mpk, payload, flippedBundle);
    assert.equal(resFlipped.valid, false);
    assert.equal(resFlipped.error, 'MERKLE_PATH_MISMATCH');
  });

  it('Test H: Adaptive risk escalation and eager evolution under attack burst', () => {
    let evolutionEvents = [];
    const policy = new AdaptivePolicyController({
      normalEpochMs: 8 * 60 * 60 * 1000,
      elevatedEpochMs: 5 * 60 * 1000,
      authFailureThreshold: 5,
      slidingWindowMs: 60000,
      onEagerEvolutionTrigger: (evt) => {
        evolutionEvents.push(evt);
      },
    });

    const { state: state0, publicTree } = generateFssMasterState({ maxEpochs: 16 });
    let activeState = state0;

    // Normal operation
    assert.equal(policy.getMode(), POLICY_MODES.NORMAL);
    assert.equal(activeState.epoch, 0);

    // Simulate attacker launching brute-force attack (5 auth failures in 20 seconds)
    const attackStart = Date.now();
    for (let i = 0; i < 5; i++) {
      policy.recordAuthFailure(attackStart + i * 4000);
    }

    // Policy escalates to ELEVATED and triggers eager evolution
    assert.equal(policy.getMode(), POLICY_MODES.ELEVATED);
    assert.equal(evolutionEvents.length, 1);
    assert.equal(policy.getCurrentEpochDurationMs(), 5 * 60 * 1000);

    // Execute eager evolution triggered by policy
    const shouldEvolve = policy.shouldEvolve(attackStart + 20000);
    assert.equal(shouldEvolve.shouldEvolve, true);
    assert.equal(shouldEvolve.eager, true);

    activeState = evolveFssState(activeState, publicTree.authPaths[1]);
    policy.onEvolutionComplete(activeState.epoch, attackStart + 20050);

    assert.equal(activeState.epoch, 1);

    // Next scheduled evolution is now 5 minutes, NOT 8 hours
    const checkSoon = policy.shouldEvolve(attackStart + 20050 + 60000); // 1 min later
    assert.equal(checkSoon.shouldEvolve, false);

    const check5Min = policy.shouldEvolve(attackStart + 20050 + 300005); // 5 min later
    assert.equal(check5Min.shouldEvolve, true);
    assert.equal(check5Min.reason, 'SCHEDULED_EPOCH_EXPIRATION');
  });

  it('Test I: Emergency revocation boundary enforcement (epochs < t* vs epochs >= t*)', () => {
    const tempDir = tmpdir();
    const statePath = join(tempDir, `fss_state_rev_${Date.now()}.json`);
    const revocationPath = join(tempDir, `fss_revocation_rev_${Date.now()}.json`);
    const { state: state0, publicTree, mpk } = generateFssMasterState({ maxEpochs: 8 });

    try {
      const manager = new FssStateManager({ statePath, revocationPath });
      manager.initState(state0, true);

      // Epoch 0 log
      const p0 = { seq: 1, data: 'Pre-intrusion log 1' };
      const sig0 = manager.sign(p0);

      // Evolve to Epoch 1
      manager.evolve(publicTree.authPaths[1]);
      const p1 = { seq: 2, data: 'Pre-intrusion log 2' };
      const sig1 = manager.sign(p1);

      // Evolve to Epoch 2 (Compromise epoch)
      manager.evolve(publicTree.authPaths[2]);
      const p2 = { seq: 3, data: 'Log during compromised epoch' };
      const sig2 = manager.sign(p2);

      // Emergency triggered at epoch 2
      const notice = manager.revokeEmergency({
        reason: 'Host kernel integrity violation',
      });
      assert.equal(notice.compromiseEpoch, 2);

      // State file is wiped
      assert.equal(existsSync(statePath), false);

      // Verification Boundary Test:
      // Epoch 0 (< 2): VALID and TRUSTED
      const ver0 = FssStateManager.verifyWithRevocation(mpk, p0, sig0, notice);
      assert.equal(ver0.valid, true);

      // Epoch 1 (< 2): VALID and TRUSTED
      const ver1 = FssStateManager.verifyWithRevocation(mpk, p1, sig1, notice);
      assert.equal(ver1.valid, true);

      // Epoch 2 (>= 2): DISTRUSTED / REJECTED
      const ver2 = FssStateManager.verifyWithRevocation(mpk, p2, sig2, notice);
      assert.equal(ver2.valid, false);
      assert.equal(ver2.error, 'EPOCH_REVOKED');
    } finally {
      if (existsSync(statePath)) unlinkSync(statePath);
      if (existsSync(revocationPath)) unlinkSync(revocationPath);
    }
  });

  it('Test J: Process crash/restart and state recovery without gap or rollback', () => {
    const tempDir = tmpdir();
    const statePath = join(tempDir, `fss_crash_${Date.now()}.json`);
    const { state: state0, publicTree, mpk } = generateFssMasterState({ maxEpochs: 8 });

    try {
      // Instance 1: boots, advances to epoch 2, signs
      const instance1 = new FssStateManager({ statePath });
      instance1.initState(state0, true);
      instance1.evolve(publicTree.authPaths[1]);
      instance1.evolve(publicTree.authPaths[2]);

      const logBeforeCrash = { seq: 200, data: 'Signed before simulated crash' };
      const sigBeforeCrash = instance1.sign(logBeforeCrash);
      assert.equal(sigBeforeCrash.epoch, 2);

      // SIMULATE CRASH: instance1 is destroyed, memory wiped
      const instance1Ref = null;

      // Instance 2: restarts from disk
      const instance2 = new FssStateManager({ statePath, highestWitnessedEpoch: 2 });
      instance2.loadStateFromDisk();
      assert.equal(instance2.activeState.epoch, 2);

      // Continues signing validly in epoch 2
      const logAfterRecovery = { seq: 201, data: 'Signed immediately after reboot' };
      const sigAfterRecovery = instance2.sign(logAfterRecovery);
      assert.equal(sigAfterRecovery.epoch, 2);

      const verAfter = verifyFssSignature(mpk, logAfterRecovery, sigAfterRecovery);
      assert.equal(verAfter.valid, true);

      // Evolve to epoch 3 on restarted node
      instance2.evolve(publicTree.authPaths[3]);
      assert.equal(instance2.activeState.epoch, 3);
      const logEpoch3 = { seq: 202, data: 'Signed in epoch 3 post-recovery' };
      const sigEpoch3 = instance2.sign(logEpoch3);
      const verEpoch3 = verifyFssSignature(mpk, logEpoch3, sigEpoch3);
      assert.equal(verEpoch3.valid, true);
    } finally {
      if (existsSync(statePath)) unlinkSync(statePath);
    }
  });

});
