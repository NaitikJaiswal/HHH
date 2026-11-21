/**
 * @module fssStateManager
 * @description Forward-Secure State Lifecycle, Anti-Rollback Verification,
 * and Revocation Management.
 *
 * Implements:
 *   - Monotonic high-water mark state tracking to prevent rollback attacks
 *   - Atomic state file rotation with POSIX 0o600 permissions
 *   - Memory zeroization of prior seeds
 *   - Emergency revocation notice generation and active key shredding
 *   - Revocation-aware signature verification enforcing historical boundaries
 */

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  zeroizeBuffer,
  atomicWriteSecretFile,
  secureEraseFile,
} from '../crypto/secretScrubber.js';
import {
  verifyFssSignature,
  evolveFssState,
  signFssEpoch,
  FSS_STATE_VERSION,
} from '../crypto/fssSigner.js';

export const REVOCATION_VERSION = 'HHH-REVOCATION-NOTICE-v1';

export class FssStateManager {
  /**
   * @param {object} options
   * @param {string} options.statePath - Path to fss_state.json.
   * @param {string} [options.revocationPath] - Path to fss_revocation.json.
   * @param {number} [options.highestWitnessedEpoch=0] - Initial high-water mark.
   */
  constructor(options) {
    if (!options || typeof options.statePath !== 'string') {
      throw new TypeError('FssStateManager: statePath must be provided');
    }
    this.statePath = options.statePath;
    this.revocationPath = options.revocationPath || join(this.statePath, '..', 'fss_revocation.json');
    this.highWaterMarkEpoch = options.highestWitnessedEpoch ?? 0;
    this.activeState = null;
    this.revocationNotice = null;

    if (existsSync(this.revocationPath)) {
      try {
        this.revocationNotice = JSON.parse(readFileSync(this.revocationPath, 'utf8'));
      } catch {
        // Suppress parsing error
      }
    }
  }

  get mpk() {
    return this.activeState?.mpk || this.revocationNotice?.mpk || null;
  }

  get epoch() {
    return this.activeState?.epoch ?? null;
  }

  /**
   * Initialize or set active in-memory state, verifying rollback protection.
   *
   * @param {object} state - FSS state object.
   * @param {boolean} [persist=false] - Whether to write to disk.
   */
  initState(state, persist = false) {
    if (!state || typeof state !== 'object') {
      throw new TypeError('initState: state must be an object');
    }
    if (state.epoch < this.highWaterMarkEpoch) {
      throw new Error(
        `STATE_ROLLBACK_DETECTED: provided epoch ${state.epoch} is lower than high-water mark ${this.highWaterMarkEpoch}`
      );
    }

    this.activeState = state;
    this.highWaterMarkEpoch = Math.max(this.highWaterMarkEpoch, state.epoch);

    if (persist) {
      this._saveActiveState();
    }
  }

  /**
   * Load active state from disk with rollback protection check.
   *
   * @returns {object} Loaded state.
   */
  loadStateFromDisk() {
    if (!existsSync(this.statePath)) {
      throw new Error(`FssStateManager: state file not found at ${this.statePath}`);
    }

    const raw = readFileSync(this.statePath, 'utf8');
    const parsed = JSON.parse(raw);

    if (parsed.version !== FSS_STATE_VERSION) {
      throw new Error(`FssStateManager: invalid state version "${parsed.version}"`);
    }

    // Rollback protection check
    if (parsed.epoch < this.highWaterMarkEpoch) {
      throw new Error(
        `STATE_ROLLBACK_DETECTED: loaded state epoch ${parsed.epoch} is below high-water mark ${this.highWaterMarkEpoch}`
      );
    }

    this.activeState = parsed;
    this.highWaterMarkEpoch = Math.max(this.highWaterMarkEpoch, parsed.epoch);
    return this.activeState;
  }

  /**
   * Update high-water mark from an external witness (e.g. verified checkpoint).
   *
   * @param {number} witnessedEpoch
   */
  recordWitnessedEpoch(witnessedEpoch) {
    if (Number.isInteger(witnessedEpoch) && witnessedEpoch > this.highWaterMarkEpoch) {
      this.highWaterMarkEpoch = witnessedEpoch;

      // If active state is below external witness, active state is invalid
      if (this.activeState && this.activeState.epoch < this.highWaterMarkEpoch) {
        throw new Error(
          `STATE_ROLLBACK_DETECTED: active state epoch ${this.activeState.epoch} is behind external witness ${this.highWaterMarkEpoch}`
        );
      }
    }
  }

  /**
   * Sign payload using the active state.
   * Rejects if revoked or active state is missing.
   *
   * @param {unknown} payload
   * @returns {object} Signature bundle.
   */
  sign(payload) {
    if (this.revocationNotice) {
      throw new Error(
        `FSS_REVOKED: signing disallowed after compromise at epoch ${this.revocationNotice.compromiseEpoch}`
      );
    }
    if (!this.activeState) {
      throw new Error('FssStateManager: no active state loaded');
    }

    return signFssEpoch(this.activeState, payload);
  }

  /**
   * Evolve the state to the next epoch (t -> t + 1):
   * 1. Derives next seed K_{t+1}.
   * 2. Overwrites old seed K_t.
   * 3. Updates high-water mark.
   * 4. Atomically saves new state file with 0o600 permissions.
   *
   * @param {Array} [nextAuthPath=null]
   * @returns {object} New evolved state.
   */
  evolve(nextAuthPath = null) {
    if (this.revocationNotice) {
      throw new Error('FSS_REVOKED: cannot evolve revoked key');
    }
    if (!this.activeState) {
      throw new Error('FssStateManager: no active state to evolve');
    }

    const newState = evolveFssState(this.activeState, nextAuthPath);
    this.activeState = newState;
    this.highWaterMarkEpoch = newState.epoch;
    this._saveActiveState();
    return this.activeState;
  }

  /**
   * Execute emergency revocation protocol:
   * 1. Constructs revocation notice.
   * 2. Shreds active key file on disk via secureEraseFile.
   * 3. Zeroizes in-memory active state seed.
   * 4. Persists revocation notice.
   *
   * @param {object} options
   * @param {string} options.reason - Reason for emergency revocation.
   * @param {string} [options.lastValidCheckpointHash] - Hash of final known valid checkpoint.
   * @returns {object} Revocation notice.
   */
  revokeEmergency(options = {}) {
    const compromiseEpoch = this.activeState ? this.activeState.epoch : this.highWaterMarkEpoch;
    const mpk = this.activeState ? this.activeState.mpk : 'UNKNOWN';

    const notice = {
      version: REVOCATION_VERSION,
      mpk,
      compromiseEpoch,
      revokedAt: new Date().toISOString(),
      reason: options.reason || 'Manual emergency revocation triggered',
      lastValidCheckpointHash: options.lastValidCheckpointHash || null,
    };

    this.revocationNotice = notice;

    // Shred active state file
    secureEraseFile(this.statePath);

    // Zeroize in-memory seed
    if (this.activeState && this.activeState.seedHex) {
      const buf = Buffer.from(this.activeState.seedHex, 'hex');
      zeroizeBuffer(buf);
      this.activeState.seedHex = '0000000000000000000000000000000000000000000000000000000000000000';
    }
    this.activeState = null;

    // Persist revocation notice
    atomicWriteSecretFile(this.revocationPath, JSON.stringify(notice, null, 2), 0o644);
    return notice;
  }

  /**
   * Internal helper to persist active state atomically.
   * @private
   */
  _saveActiveState() {
    if (!this.activeState) return;
    const content = JSON.stringify(this.activeState, null, 2);
    atomicWriteSecretFile(this.statePath, content, 0o600);
  }

  /**
   * Static verifier that takes revocation notices into account.
   *
   * Historical invariant:
   *   - Epochs t < compromiseEpoch remain cryptographically valid and trusted.
   *   - Epochs t >= compromiseEpoch are distrusted and rejected.
   *
   * @param {string} mpk - Master Public Key.
   * @param {unknown} payload - Payload to verify.
   * @param {object} signatureBundle - FSS signature bundle.
   * @param {object} [revocationNotice=null] - Optional revocation notice.
   * @returns {{ valid: boolean, error?: string, reason?: string, epoch?: number }}
   */
  static verifyWithRevocation(mpk, payload, signatureBundle, revocationNotice = null) {
    if (revocationNotice) {
      if (signatureBundle && Number.isInteger(signatureBundle.epoch)) {
        if (signatureBundle.epoch >= revocationNotice.compromiseEpoch) {
          return {
            valid: false,
            error: 'EPOCH_REVOKED',
            reason: `Signature epoch ${signatureBundle.epoch} >= compromise epoch ${revocationNotice.compromiseEpoch}`,
            revocationNotice,
          };
        }
      }
    }

    return verifyFssSignature(mpk, payload, signatureBundle);
  }
}

export default {
  FssStateManager,
  REVOCATION_VERSION,
};
