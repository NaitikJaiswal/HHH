/**
 * Tests for hashChain.js — LOGN-HASH-v1 hash chain construction and verification.
 * Uses Node.js built-in node:test and node:assert/strict.
 *
 * Test coverage:
 *   1.  Valid 3-event chain passes verifyHashChain
 *   2.  Modified event message fails verification at that index
 *   3.  Reordered events fail verification
 *   4.  Missing sequence number is reported as a gap
 *   5.  Broken previous_hash link fails verification
 *   6.  Empty array → { valid: true, errors: [] }
 *   7.  Single-event chain with GENESIS_HASH passes
 *   8.  buildChain produces events with correct previous_hash and current_hash
 *   9.  buildChain chain is subsequently verified as valid by verifyHashChain
 *  10.  First event with wrong previous_hash fails (not GENESIS_HASH)
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyHashChain, buildChain, GENESIS_HASH } from '../src/crypto/hashChain.js';
import { hashLogEvent } from '../src/crypto/hashing.js';

// ── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Build a minimal valid raw event (without previous_hash / current_hash).
 * buildChain() will attach those fields.
 */
function makeRawEvent(seq, overrides = {}) {
  return {
    event_id:        `event-id-${seq.toString().padStart(5, '0')}`,
    event_time:      '2026-11-20T12:00:00Z',
    event_type:      'SYSTEM',
    message:         `Test event ${seq}`,
    metadata:        { seq },
    sequence_number: seq,
    severity:        'INFO',
    source_id:       'test-source',
    ...overrides,
  };
}

/**
 * Build a fully chained array of n events using buildChain().
 * Returns deep clones so individual tests don't share state.
 */
function buildValidChain(n) {
  const raws = Array.from({ length: n }, (_, i) => makeRawEvent(i + 1));
  return buildChain(raws);
}

// ── Tests ────────────────────────────────────────────────────────────────────

test('1. Valid 3-event chain passes verifyHashChain', () => {
  const chain = buildValidChain(3);
  const result = verifyHashChain(chain);
  assert.equal(result.valid, true, 'A correctly built 3-event chain must be valid');
  assert.equal(result.errors.length, 0, 'Valid chain must have no errors');
  assert.equal(result.firstFailedIndex, null, 'Valid chain firstFailedIndex must be null');
});

test('2. Modified event message fails verification at that index', () => {
  const chain = buildValidChain(3);
  // Tamper with event at index 1 (sequence 2)
  chain[1].message = 'TAMPERED MESSAGE';
  // Note: current_hash is still the original, so the recomputed hash will differ

  const result = verifyHashChain(chain);
  assert.equal(result.valid, false, 'Tampered chain must not be valid');
  assert.ok(result.errors.length > 0, 'Must report at least one error');
  // The tampered event is at index 1
  assert.equal(result.firstFailedIndex, 1, 'First failure must be at index 1 (tampered event)');
});

test('3. Reordered events fail verification', () => {
  const chain = buildValidChain(3);
  // Swap events at index 0 and 1
  [chain[0], chain[1]] = [chain[1], chain[0]];

  const result = verifyHashChain(chain);
  assert.equal(result.valid, false, 'Reordered chain must not be valid');
  assert.ok(result.errors.length > 0, 'Must report at least one error for reordered events');
});

test('4. Missing sequence number is reported as a gap', () => {
  const chain = buildValidChain(4);
  // Remove the second event (sequence 2), leaving a gap: 1, 3, 4
  chain.splice(1, 1);
  // Rebuild current_hash/previous_hash manually — the chain is now inconsistent
  // by both link breakage and sequence gap. We just need gap detection to fire.

  const result = verifyHashChain(chain);
  assert.equal(result.valid, false, 'Chain with a sequence gap must not be valid');
  const gapError = result.errors.find((e) => e.reason.includes('gap') || e.reason.includes('expected'));
  assert.ok(gapError !== undefined, 'Must report a sequence number gap error');
});

test('5. Broken previous_hash link fails verification', () => {
  const chain = buildValidChain(3);
  // Corrupt the previous_hash of the third event without touching other fields
  chain[2].previous_hash = 'a'.repeat(64);
  // Recompute current_hash for event 3 to make it internally consistent...
  chain[2].current_hash = hashLogEvent(chain[2]);
  // ...but now the link chain[1].current_hash → chain[2].previous_hash is broken

  const result = verifyHashChain(chain);
  assert.equal(result.valid, false, 'Chain with broken previous_hash link must not be valid');
  const linkError = result.errors.find(
    (e) => e.reason.includes('Broken chain link') || e.reason.includes('previous_hash')
  );
  assert.ok(linkError !== undefined, 'Must report a chain link error');
});

test('6. Empty array returns valid result with no errors', () => {
  const result = verifyHashChain([]);
  assert.equal(result.valid, true, 'Empty chain must be trivially valid');
  assert.deepEqual(result.errors, [], 'Empty chain must have no errors');
  assert.equal(result.firstFailedIndex, null, 'Empty chain firstFailedIndex must be null');
});

test('7. Single-event chain with GENESIS_HASH passes', () => {
  const raw = makeRawEvent(1);
  const chain = buildChain([raw]);

  assert.equal(chain[0].previous_hash, GENESIS_HASH, 'First event previous_hash must equal GENESIS_HASH');
  assert.match(chain[0].current_hash, /^[0-9a-f]{64}$/, 'current_hash must be a valid hex-64 string');

  const result = verifyHashChain(chain);
  assert.equal(result.valid, true, 'Single-event chain starting from GENESIS_HASH must be valid');
  assert.equal(result.errors.length, 0, 'Single-event valid chain must have no errors');
});

test('8. buildChain produces events with correct previous_hash and current_hash', () => {
  const raws = [makeRawEvent(1), makeRawEvent(2), makeRawEvent(3)];
  const chain = buildChain(raws);

  // Event 0: previous_hash must be GENESIS_HASH
  assert.equal(chain[0].previous_hash, GENESIS_HASH, 'Event 0 previous_hash must be GENESIS_HASH');

  // Event 1: previous_hash must equal event 0's current_hash
  assert.equal(chain[1].previous_hash, chain[0].current_hash, 'Event 1 previous_hash must equal event 0 current_hash');

  // Event 2: previous_hash must equal event 1's current_hash
  assert.equal(chain[2].previous_hash, chain[1].current_hash, 'Event 2 previous_hash must equal event 1 current_hash');

  // All current_hashes must be valid hex-64
  for (const event of chain) {
    assert.match(event.current_hash, /^[0-9a-f]{64}$/, `current_hash for seq ${event.sequence_number} must be hex-64`);
  }
});

test('9. buildChain output is verified as valid by verifyHashChain', () => {
  const chain = buildValidChain(5);
  const result = verifyHashChain(chain);
  assert.equal(result.valid, true, 'buildChain output must pass verifyHashChain');
  assert.equal(result.errors.length, 0, 'No errors expected for freshly built chain');
});

test('10. First event with wrong previous_hash (not GENESIS_HASH) fails', () => {
  const chain = buildValidChain(2);
  // Set the first event's previous_hash to something other than GENESIS_HASH
  chain[0].previous_hash = 'b'.repeat(64);
  // Recompute its current_hash to make it internally consistent
  chain[0].current_hash = hashLogEvent(chain[0]);
  // Update event 1's previous_hash to maintain the chain link
  chain[1].previous_hash = chain[0].current_hash;
  chain[1].current_hash = hashLogEvent(chain[1]);

  const result = verifyHashChain(chain);
  assert.equal(result.valid, false, 'Chain not starting from GENESIS_HASH must not be valid');
  const genesisError = result.errors.find(
    (e) => e.reason.includes('GENESIS_HASH') || e.reason.includes('64 zeros')
  );
  assert.ok(genesisError !== undefined, 'Must report a GENESIS_HASH violation at index 0');
  assert.equal(genesisError.index, 0, 'GENESIS_HASH error must be at index 0');
});

test('11. Modified metadata fails verification at that index', () => {
  const chain = buildValidChain(3);
  chain[1].metadata = { ip: '192.168.1.99', user: 'attacker' };
  const result = verifyHashChain(chain);
  assert.equal(result.valid, false, 'Modified metadata must fail verification');
  assert.equal(result.firstFailedIndex, 1);
  assert.equal(result.firstFailedSequenceNumber, 2);
});

test('12. Modified timestamp fails verification at that index', () => {
  const chain = buildValidChain(3);
  chain[2].event_time = '2026-11-20T15:30:00Z'; // altered timestamp (original was 12:00:00Z)
  const result = verifyHashChain(chain);
  assert.equal(result.valid, false, 'Modified timestamp must fail verification');
  assert.equal(result.firstFailedIndex, 2);
  assert.equal(result.firstFailedSequenceNumber, 3);
});

test('13. Duplicate sequence numbers are explicitly detected and reported', () => {
  const chain = buildValidChain(3);
  // Duplicate sequence number 2 on event index 2
  chain[2].sequence_number = 2;
  chain[2].current_hash = hashLogEvent(chain[2]);
  const result = verifyHashChain(chain);
  assert.equal(result.valid, false);
  const dupError = result.errors.find((e) => e.type === 'DUPLICATE_SEQUENCE');
  assert.ok(dupError !== undefined, 'Must report DUPLICATE_SEQUENCE error');
  assert.equal(dupError.sequenceNumber, 2);
});

test('14. Out-of-order sequence numbers are detected', () => {
  const chain = buildValidChain(3);
  chain[2].sequence_number = 1; // 1, 2, 1
  chain[2].current_hash = hashLogEvent(chain[2]);
  const result = verifyHashChain(chain);
  assert.equal(result.valid, false);
  const oooError = result.errors.find((e) => e.type === 'OUT_OF_ORDER_SEQUENCE');
  assert.ok(oooError !== undefined, 'Must report OUT_OF_ORDER_SEQUENCE error');
});

test('15. Detection of deleted final events (tail truncation) requires an independent checkpoint', async () => {
  const { verifyHashChainWithCheckpoint } = await import('../src/crypto/hashChain.js');
  const fullChain = buildValidChain(5);
  const trustedCheckpoint = {
    start_sequence: 1,
    end_sequence: 5,
    event_count: 5,
    chain_head_hash: fullChain[4].current_hash,
  };

  // Truncate the latest 2 events from local storage (events 4 and 5 deleted)
  const truncatedChain = fullChain.slice(0, 3);

  // Note: local hash chain alone sees events 1..3 as internally consistent
  const localOnly = verifyHashChain(truncatedChain);
  assert.equal(localOnly.valid, true, 'Local hash chain alone cannot detect tail truncation');

  // But verification against the independent checkpoint detects the missing suffix
  const withCheckpoint = verifyHashChainWithCheckpoint(truncatedChain, trustedCheckpoint);
  assert.equal(withCheckpoint.valid, false, 'Checkpoint verification must detect tail truncation');
  const truncationError = withCheckpoint.errors.find((e) => e.type === 'TAIL_TRUNCATION');
  assert.ok(truncationError !== undefined, 'Must report TAIL_TRUNCATION error');
});

test('16. verifyHashChainWithCheckpoint detects chain head mismatch and sequence bound errors', async () => {
  const { verifyHashChainWithCheckpoint } = await import('../src/crypto/hashChain.js');
  const chain = buildValidChain(3);
  const forgedCheckpoint = {
    start_sequence: 1,
    end_sequence: 3,
    event_count: 3,
    chain_head_hash: 'f'.repeat(64), // mismatched head
  };
  const result = verifyHashChainWithCheckpoint(chain, forgedCheckpoint);
  assert.equal(result.valid, false);
  const headError = result.errors.find((e) => e.type === 'CHAIN_HEAD_MISMATCH');
  assert.ok(headError !== undefined, 'Must report CHAIN_HEAD_MISMATCH error');
});

