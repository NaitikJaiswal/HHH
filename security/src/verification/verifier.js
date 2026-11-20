/**
 * @module verifier
 * @description Comprehensive verification engine for HHH SecureLog.
 *
 * Provides a unified entry point to independently verify:
 *   - Checkpoint schema structure and versioning
 *   - Merkle root correctness
 *   - Merkle leaf inclusion proofs
 *   - Ed25519 digital signatures
 *   - Signing key ID validity and historical provenance
 *   - End-to-end alignment between raw log events, hash chains, and checkpoints
 *
 * Status codes returned:
 *   VERIFIED
 *   INVALID_SIGNATURE
 *   MERKLE_MISMATCH
 *   INVALID_PROOF
 *   UNKNOWN_SIGNING_KEY
 *   INVALID_CHECKPOINT
 *   VERIFICATION_ERROR
 */

import { verifyCheckpoint, verifyCheckpointProof, VerificationStatus } from '../checkpoints/checkpointService.js';
import { verifyMerkleProof, buildMerkleTree, getMerkleRoot } from '../merkle/merkleTree.js';
import { verifyHashChain } from '../crypto/hashChain.js';
import { hashLogEvent } from '../crypto/hashing.js';

export { VerificationStatus };

/**
 * @typedef {object} ComprehensiveVerificationResult
 * @property {string}   status   - VerificationStatus enum value.
 * @property {boolean}  valid    - true iff all checks succeeded.
 * @property {string[]} failures - Detailed failure messages.
 * @property {object}   details  - Sub-verification results.
 */

/**
 * Verify a checkpoint independently against a key manager.
 *
 * @param {object} checkpoint
 * @param {import('../keys/keyManager.js').KeyManager} [keyManager]
 * @returns {import('../checkpoints/checkpointService.js').VerificationResult}
 */
export function verifySignedCheckpoint(checkpoint, keyManager) {
  return verifyCheckpoint(checkpoint, keyManager);
}

/**
 * Verify a Merkle inclusion proof against a checkpoint's root.
 *
 * @param {object} checkpoint
 * @param {string} currentHash
 * @param {object[]} proof
 * @returns {import('../checkpoints/checkpointService.js').VerificationResult}
 */
export function verifyInclusionProof(checkpoint, currentHash, proof) {
  return verifyCheckpointProof(checkpoint, currentHash, proof);
}

/**
 * Perform a full end-to-end verification of an array of log events against a checkpoint.
 *
 * Verifies:
 *   1. Event hash chain integrity (verifyHashChain)
 *   2. Sequence range consistency with checkpoint (start_sequence, end_sequence, count)
 *   3. Event current_hash matches checkpoint.merkle_leaf_hashes
 *   4. Checkpoint integrity and digital signature (verifyCheckpoint)
 *
 * @param {object} checkpoint - Signed checkpoint document.
 * @param {object[]} events - Array of log events matching the checkpoint sequence window.
 * @param {import('../keys/keyManager.js').KeyManager} [keyManager] - Key manager for signature verification.
 * @returns {ComprehensiveVerificationResult}
 */
export function verifyEventsAgainstCheckpoint(checkpoint, events, keyManager) {
  const failures = [];
  const details = {
    chain: null,
    checkpoint: null,
    alignment: false,
  };

  // 1. Verify checkpoint structure and signature first
  const cpResult = verifyCheckpoint(checkpoint, keyManager);
  details.checkpoint = cpResult;
  if (!cpResult.valid) {
    failures.push(...cpResult.failures);
    return {
      status: cpResult.status,
      valid: false,
      failures,
      details,
    };
  }

  // 2. Verify events array
  if (!Array.isArray(events) || events.length === 0) {
    failures.push('Events must be a non-empty array');
    return {
      status: VerificationStatus.INVALID_CHECKPOINT,
      valid: false,
      failures,
      details,
    };
  }

  if (events.length !== checkpoint.event_count) {
    failures.push(
      `Events length (${events.length}) does not match checkpoint event_count (${checkpoint.event_count})`
    );
    return {
      status: VerificationStatus.INVALID_CHECKPOINT,
      valid: false,
      failures,
      details,
    };
  }

  // 3. Verify event sequence matches checkpoint bounds
  const firstSeq = events[0].sequence_number;
  const lastSeq = events[events.length - 1].sequence_number;
  if (firstSeq !== checkpoint.start_sequence || lastSeq !== checkpoint.end_sequence) {
    failures.push(
      `Event sequence bounds [${firstSeq}, ${lastSeq}] do not match checkpoint range [${checkpoint.start_sequence}, ${checkpoint.end_sequence}]`
    );
    return {
      status: VerificationStatus.INVALID_CHECKPOINT,
      valid: false,
      failures,
      details,
    };
  }

  // 4. Verify hash chain of events
  // Note: if events start at sequence > 1, first event's previous_hash won't be GENESIS_HASH,
  // so verify links and hashes directly
  let chainValid = true;
  for (let i = 0; i < events.length; i++) {
    const ev = events[i];
    try {
      const computedHash = hashLogEvent(ev);
      if (computedHash !== ev.current_hash) {
        failures.push(`Event at index ${i} hash mismatch: computed ${computedHash} ≠ stored ${ev.current_hash}`);
        chainValid = false;
        break;
      }
    } catch (err) {
      failures.push(`Event at index ${i} failed hashLogEvent: ${err.message}`);
      chainValid = false;
      break;
    }

    if (i > 0) {
      if (ev.previous_hash !== events[i - 1].current_hash) {
        failures.push(`Event at index ${i} broken previous_hash link`);
        chainValid = false;
        break;
      }
      if (ev.sequence_number !== events[i - 1].sequence_number + 1) {
        failures.push(`Event at index ${i} sequence gap: ${ev.sequence_number}`);
        chainValid = false;
        break;
      }
    }

    // Check alignment with checkpoint leaf hashes
    if (ev.current_hash !== checkpoint.merkle_leaf_hashes[i]) {
      failures.push(
        `Event ${i} current_hash does not match checkpoint merkle_leaf_hashes[${i}]`
      );
      chainValid = false;
      break;
    }
  }

  details.chain = { valid: chainValid };
  details.alignment = chainValid;

  if (!chainValid) {
    return {
      status: VerificationStatus.MERKLE_MISMATCH,
      valid: false,
      failures,
      details,
    };
  }

  return {
    status: VerificationStatus.VERIFIED,
    valid: true,
    failures: [],
    details,
  };
}

export default {
  VerificationStatus,
  verifySignedCheckpoint,
  verifyInclusionProof,
  verifyEventsAgainstCheckpoint,
};
