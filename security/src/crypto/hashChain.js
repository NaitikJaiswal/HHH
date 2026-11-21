/**
 * @module hashChain
 * @description Hash chain construction and verification for LOGN-HASH-v1 event sequences.
 *
 * A hash chain links log events such that each event's hash commits to:
 *   - All fields of the event itself (via LOGN-HASH-v1)
 *   - The hash of the previous event (via the previous_hash field)
 *
 * This means any modification, deletion, insertion, or reordering of events
 * is detectable by replaying the chain. What this module does NOT prove:
 *   - Authenticity (use Ed25519 signatures in Phase 2 for that)
 *   - On-chain anchoring (use blockchain module in Phase 2+)
 *   - That a re-built chain is the original chain (an attacker with database
 *     write access can rebuild a consistent chain — signatures and anchoring
 *     close this gap; see docs/threat-model.md)
 *
 * References: docs/technical-integration-contract.md §2 (Authoritative Integrity Chain)
 */

import { hashLogEvent, GENESIS_HASH } from './hashing.js';

export { GENESIS_HASH };

/**
 * Represents a single verification error at a specific position in the chain.
 *
 * @typedef {object} ChainError
 * @property {number} index - Zero-based index of the event in the array.
 * @property {number|undefined} sequenceNumber - sequence_number of the offending event (if available).
 * @property {string} reason - Human-readable description of the failure.
 */

/**
 * Result returned by verifyHashChain().
 *
 * @typedef {object} ChainVerificationResult
 * @property {boolean} valid - true iff the chain is internally consistent with no errors.
 * @property {ChainError[]} errors - Array of all detected errors (empty when valid === true).
 * @property {number|null} firstFailedIndex - Zero-based index of the first failed event, or null if valid.
 */

/**
 * Verify the integrity of an ordered array of log events.
 *
 * Each event must include:
 *   - All 9 LOGN-HASH-v1 fields (see hashing.js)
 *   - `current_hash` {string} — the stored hash value to validate against
 *   - `previous_hash` {string} — the hash of the preceding event
 *   - `sequence_number` {number} — monotonically increasing integer
 *
 * Checks performed (in order):
 *   1. Empty array → valid (no events, no violations).
 *   2. First event's previous_hash must equal GENESIS_HASH.
 *   3. Each event's recomputed hash (via hashLogEvent) must equal event.current_hash.
 *   4. Each event's previous_hash must equal the preceding event's current_hash.
 *   5. Sequence numbers must be strictly consecutive with no gaps.
 *
 * NOTE: An attacker with database write access can rebuild a fully consistent
 * chain (all checks pass) but with different content. Only Ed25519 signatures
 * on signed checkpoints and on-chain anchoring close this attack vector.
 * Do not interpret a passing chain as proof of authenticity — only as proof
 * of internal consistency given the stored hash values.
 *
 * @param {object[]} events - Ordered array of log event objects (ascending sequence_number).
 * @param {object} [options] - Verification configuration options.
 * @param {string} [options.expectedGenesisHash] - Expected hash before first event (defaults to GENESIS_HASH).
 * @param {number} [options.expectedStartSequence] - Expected sequence number of first event (optional).
 * @returns {ChainVerificationResult} Verification result.
 */
export function verifyHashChain(events, options = {}) {
  const errors = [];
  const expectedGenesis = options.expectedGenesisHash ?? GENESIS_HASH;

  // Empty chain is trivially valid
  if (!Array.isArray(events) || events.length === 0) {
    return { valid: true, errors: [], firstFailedIndex: null, firstFailedSequenceNumber: null };
  }

  // Check 2: First event must reference expectedGenesis (defaults to GENESIS_HASH)
  const firstEvent = events[0];
  if (firstEvent.previous_hash !== expectedGenesis) {
    errors.push({
      index: 0,
      sequenceNumber: firstEvent.sequence_number,
      sequence: firstEvent.sequence_number,
      type: 'GENESIS_MISMATCH',
      reason: `First event previous_hash is "${firstEvent.previous_hash}" but expected GENESIS_HASH (64 zeros)`,
    });
  }

  if (options.expectedStartSequence !== undefined && Number(firstEvent.sequence_number) !== Number(options.expectedStartSequence)) {
    errors.push({
      index: 0,
      sequenceNumber: firstEvent.sequence_number,
      sequence: firstEvent.sequence_number,
      type: 'START_SEQUENCE_MISMATCH',
      reason: `First event sequence_number is ${firstEvent.sequence_number} but expected ${options.expectedStartSequence}`,
    });
  }

  for (let i = 0; i < events.length; i++) {
    const event = events[i];
    const seqNum = event.sequence_number;

    // Check 3: Recomputed hash must equal stored current_hash
    let recomputedHash;
    try {
      recomputedHash = hashLogEvent(event);
    } catch (err) {
      errors.push({
        index: i,
        sequenceNumber: seqNum,
        sequence: seqNum,
        type: 'HASH_ERROR',
        reason: `hashLogEvent threw for event at index ${i}: ${err.message}`,
      });
      // Cannot proceed with link check for this event
      continue;
    }

    if (recomputedHash !== event.current_hash) {
      errors.push({
        index: i,
        sequenceNumber: seqNum,
        sequence: seqNum,
        type: 'HASH_MISMATCH',
        reason: `Hash mismatch at index ${i}: recomputed "${recomputedHash}" ≠ stored "${event.current_hash}"`,
      });
    }

    // Check 4: previous_hash link to preceding event
    if (i > 0) {
      const prevEvent = events[i - 1];
      if (event.previous_hash !== prevEvent.current_hash) {
        errors.push({
          index: i,
          sequenceNumber: seqNum,
          sequence: seqNum,
          type: 'LINK_MISMATCH',
          reason: `Broken chain link at index ${i}: previous_hash "${event.previous_hash}" ≠ preceding event current_hash "${prevEvent.current_hash}"`,
        });
      }
    }

    // Check 5: Sequence monotonicity, duplicate sequence, and gap detection
    if (i > 0) {
      const prevSeq = Number(events[i - 1].sequence_number);
      const curSeq = Number(seqNum);
      const expectedSeq = prevSeq + 1;

      if (curSeq === prevSeq) {
        errors.push({
          index: i,
          sequenceNumber: seqNum,
          sequence: seqNum,
          type: 'DUPLICATE_SEQUENCE',
          reason: `Duplicate sequence number ${curSeq} at index ${i}`,
        });
      } else if (curSeq < prevSeq) {
        errors.push({
          index: i,
          sequenceNumber: seqNum,
          sequence: seqNum,
          type: 'OUT_OF_ORDER_SEQUENCE',
          reason: `Out-of-order sequence at index ${i}: preceding was ${prevSeq}, got ${curSeq}`,
        });
      } else if (curSeq > expectedSeq) {
        errors.push({
          index: i,
          sequenceNumber: seqNum,
          sequence: seqNum,
          type: 'SEQUENCE_GAP',
          reason: `Sequence number gap at index ${i}: expected ${expectedSeq}, got ${curSeq}`,
        });
      }
    }
  }

  const firstFailedIndex = errors.length > 0 ? errors[0].index : null;
  const firstFailedSequenceNumber = errors.length > 0 ? errors[0].sequenceNumber : null;
  return {
    valid: errors.length === 0,
    errors,
    firstFailedIndex,
    firstFailedSequenceNumber,
  };
}

/**
 * Verify a local hash chain against an independently stored, trusted checkpoint.
 *
 * A local hash chain alone cannot reliably detect deletion of its entire latest
 * suffix without an independent trusted reference (e.g. from an Ed25519 checkpoint
 * or blockchain commitment). This function verifies internal consistency AND detects
 * tail truncations against the trusted checkpoint boundaries.
 *
 * @param {object[]} events - Local log events array.
 * @param {object} checkpoint - Trusted checkpoint document.
 * @returns {ChainVerificationResult} Verification result.
 */
export function verifyHashChainWithCheckpoint(events, checkpoint) {
  // First run local internal consistency checks
  const localResult = verifyHashChain(events);
  const errors = [...localResult.errors];

  if (!checkpoint || typeof checkpoint !== 'object') {
    errors.push({
      index: -1,
      sequenceNumber: undefined,
      sequence: undefined,
      type: 'INVALID_CHECKPOINT',
      reason: 'Missing or malformed checkpoint document for boundary verification',
    });
    return {
      valid: false,
      errors,
      firstFailedIndex: errors[0]?.index ?? null,
      firstFailedSequenceNumber: errors[0]?.sequenceNumber ?? null,
    };
  }

  const expectedStart = checkpoint.start_sequence ?? checkpoint.firstSequenceNumber ?? checkpoint.startSequence;
  const expectedEnd = checkpoint.end_sequence ?? checkpoint.lastSequenceNumber ?? checkpoint.endSequence;
  const expectedCount = checkpoint.event_count ?? checkpoint.totalEvents ?? checkpoint.eventCount;
  const expectedHead = checkpoint.chain_head_hash ?? checkpoint.chainHeadHash ?? checkpoint.headHash;

  if (events.length === 0) {
    if (expectedCount > 0) {
      errors.push({
        index: 0,
        sequenceNumber: expectedStart,
        sequence: expectedStart,
        type: 'COMPLETE_TRUNCATION',
        reason: `Local chain is empty, but checkpoint expects ${expectedCount} events from seq ${expectedStart} to ${expectedEnd}`,
      });
    }
    return {
      valid: errors.length === 0,
      errors,
      firstFailedIndex: errors.length > 0 ? 0 : null,
      firstFailedSequenceNumber: errors.length > 0 ? expectedStart : null,
    };
  }

  // Check event count
  if (expectedCount !== undefined && events.length !== Number(expectedCount)) {
    errors.push({
      index: events.length - 1,
      sequenceNumber: events[events.length - 1].sequence_number,
      sequence: events[events.length - 1].sequence_number,
      type: 'TAIL_TRUNCATION',
      reason: `Event count mismatch: local events (${events.length}) ≠ checkpoint expected (${expectedCount})`,
    });
  }

  // Check ending sequence number
  const lastEvent = events[events.length - 1];
  if (expectedEnd !== undefined && Number(lastEvent.sequence_number) !== Number(expectedEnd)) {
    errors.push({
      index: events.length - 1,
      sequenceNumber: lastEvent.sequence_number,
      sequence: lastEvent.sequence_number,
      type: 'TAIL_TRUNCATION',
      reason: `Tail truncation detected: last local sequence (${lastEvent.sequence_number}) < checkpoint end_sequence (${expectedEnd})`,
    });
  }

  // Check chain head hash
  if (expectedHead !== undefined && lastEvent.current_hash !== expectedHead) {
    errors.push({
      index: events.length - 1,
      sequenceNumber: lastEvent.sequence_number,
      sequence: lastEvent.sequence_number,
      type: 'CHAIN_HEAD_MISMATCH',
      reason: `Chain head mismatch: local tip "${lastEvent.current_hash}" ≠ checkpoint chain_head_hash "${expectedHead}"`,
    });
  }

  const firstFailedIndex = errors.length > 0 ? (errors[0].index >= 0 ? errors[0].index : 0) : null;
  const firstFailedSequenceNumber = errors.length > 0 ? errors[0].sequenceNumber : null;

  return {
    valid: errors.length === 0,
    errors,
    firstFailedIndex,
    firstFailedSequenceNumber,
  };
}

/**
 * Attach previous_hash and current_hash fields to an ordered array of events,
 * building a LOGN-HASH-v1 hash chain starting from GENESIS_HASH.
 *
 * The input events must already contain all 9 LOGN-HASH-v1 fields EXCEPT
 * previous_hash (which this function sets). Each event is mutated in place
 * and also returned in the output array.
 *
 * IMPORTANT SECURITY NOTE:
 * This function builds a chain that is INTERNALLY CONSISTENT but does NOT
 * authenticate the chain or prove it represents the original log sequence.
 * Any caller with the event data can rebuild an equally consistent chain.
 * Authenticity requires:
 *   1. Ed25519 signatures on checkpoint Merkle roots (Phase 2)
 *   2. On-chain anchoring of checkpoint commitments (Phase 2+)
 *
 * @param {object[]} events - Ordered array of event objects (mutable).
 *   Each event must contain: event_id, event_time, event_type, message,
 *   metadata, sequence_number, severity, source_id.
 *   The previous_hash field on each event will be overwritten.
 * @returns {object[]} The same array with previous_hash and current_hash set on each event.
 * @throws {TypeError} If hashLogEvent fails for any event.
 */
export function buildChain(events) {
  if (!Array.isArray(events)) {
    throw new TypeError('buildChain: events must be an array');
  }

  let previousHash = GENESIS_HASH;

  for (const event of events) {
    // Set the previous_hash on the event before hashing (previous_hash is part of the payload)
    event.previous_hash = previousHash;

    // Compute LOGN-HASH-v1 hash
    const currentHash = hashLogEvent(event);
    event.current_hash = currentHash;

    // Advance the chain tip
    previousHash = currentHash;
  }

  return events;
}

export default { verifyHashChain, buildChain, GENESIS_HASH };
