/**
 * Tests for hashing.js — SHA-256 and LOGN-HASH-v1 hashLogEvent.
 * Uses Node.js built-in node:test and node:assert/strict.
 *
 * Test coverage:
 *   1.  SHA-256 of empty string — known test vector
 *   2.  SHA-256 of "hello" — known test vector
 *   3.  hashLogEvent with §1.3.5 example event → consistent hex-64 (idempotent)
 *   4.  Changing message field changes the hash
 *   5.  Changing source_id changes the hash
 *   6.  Missing required field throws TypeError
 *   7.  metadata: null treated as {} (doesn't throw, deterministic hash)
 *   8.  sequence_number passed as string "1" is coerced to integer 1
 *   9.  event_time with milliseconds is normalized (hash matches stripped version)
 *  10.  GENESIS_HASH is exactly 64 zero characters
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sha256hex, hashLogEvent, GENESIS_HASH, LOGN_HASH_V1_FIELDS } from '../src/crypto/hashing.js';

// ── §1.3.5 worked example ────────────────────────────────────────────────────
const BASE_EVENT = {
  event_id:        'a1b2c3d4-0000-0000-0000-000000000001',
  event_time:      '2026-11-20T11:00:00Z',
  event_type:      'AUTHENTICATION',
  message:         'User login successful',
  metadata:        { ip: '10.0.0.1', user: 'alice' },
  previous_hash:   '0000000000000000000000000000000000000000000000000000000000000000',
  sequence_number: 1,
  severity:        'INFO',
  source_id:       'server-alpha',
};

// Helper: shallow clone with field overrides
function withFields(overrides) {
  return { ...BASE_EVENT, ...overrides };
}

// Helper: shallow clone with a field deleted
function withoutField(field) {
  const clone = { ...BASE_EVENT };
  delete clone[field];
  return clone;
}

// ── SHA-256 known test vectors ───────────────────────────────────────────────

test('1. SHA-256 of empty string — known test vector', () => {
  const expected = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  assert.equal(sha256hex(''), expected, 'SHA-256("") must equal the NIST test vector');
});

test('2. SHA-256 of "hello" — known test vector', () => {
  const expected = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';
  assert.equal(sha256hex('hello'), expected, 'SHA-256("hello") must equal the NIST test vector');
});

// ── hashLogEvent idempotency ──────────────────────────────────────────────────

test('3. hashLogEvent with §1.3.5 example event produces consistent hex-64 output', () => {
  const hash1 = hashLogEvent(BASE_EVENT);
  const hash2 = hashLogEvent(BASE_EVENT);

  // Must be a 64-character lowercase hex string
  assert.match(hash1, /^[0-9a-f]{64}$/, 'Hash must be a 64-character lowercase hex string');
  // Must be idempotent
  assert.equal(hash1, hash2, 'Two calls with identical input must produce identical hash');
});

// ── Field sensitivity tests ──────────────────────────────────────────────────

test('4. Changing message field changes the hash', () => {
  const originalHash = hashLogEvent(BASE_EVENT);
  const modifiedHash = hashLogEvent(withFields({ message: 'User login FAILED' }));
  assert.notEqual(
    originalHash,
    modifiedHash,
    'Hash must change when message is different'
  );
});

test('5. Changing source_id changes the hash', () => {
  const originalHash = hashLogEvent(BASE_EVENT);
  const modifiedHash = hashLogEvent(withFields({ source_id: 'server-beta' }));
  assert.notEqual(
    originalHash,
    modifiedHash,
    'Hash must change when source_id is different'
  );
});

// ── Missing field validation ─────────────────────────────────────────────────

test('6a. Missing event_id throws TypeError', () => {
  assert.throws(
    () => hashLogEvent(withoutField('event_id')),
    TypeError,
    'Missing event_id must throw TypeError'
  );
});

test('6b. Missing severity throws TypeError', () => {
  assert.throws(
    () => hashLogEvent(withoutField('severity')),
    TypeError,
    'Missing severity must throw TypeError'
  );
});

test('6c. Missing previous_hash throws TypeError', () => {
  assert.throws(
    () => hashLogEvent(withoutField('previous_hash')),
    TypeError,
    'Missing previous_hash must throw TypeError'
  );
});

// ── Metadata null handling ───────────────────────────────────────────────────

test('7. metadata: null is treated as {} — does not throw, produces deterministic hash', () => {
  const withNullMeta  = hashLogEvent(withFields({ metadata: null }));
  const withEmptyMeta = hashLogEvent(withFields({ metadata: {} }));

  // Must not throw — just verified by reaching this line
  assert.match(withNullMeta, /^[0-9a-f]{64}$/, 'Hash with null metadata must be valid hex-64');
  // Both null and {} must produce the same hash (per §1.3.4: "If metadata is null or absent: serialize as {}")
  assert.equal(
    withNullMeta,
    withEmptyMeta,
    'null metadata and {} metadata must produce the same hash (§1.3.4)'
  );
});

// ── sequence_number coercion ─────────────────────────────────────────────────

test('8. sequence_number passed as string "1" produces the same hash as integer 1', () => {
  const hashWithInt    = hashLogEvent(BASE_EVENT); // sequence_number: 1 (integer)
  const hashWithString = hashLogEvent(withFields({ sequence_number: '1' })); // coerced to 1
  assert.equal(
    hashWithInt,
    hashWithString,
    'String "1" must be coerced to integer 1 and produce the same hash'
  );
});

// ── event_time normalization ─────────────────────────────────────────────────

test('9. event_time with milliseconds is normalized — same hash as without milliseconds', () => {
  const hashNoMs   = hashLogEvent(BASE_EVENT);                                       // "2026-11-20T11:00:00Z"
  const hashWithMs = hashLogEvent(withFields({ event_time: '2026-11-20T11:00:00.123Z' })); // ms stripped
  assert.equal(
    hashNoMs,
    hashWithMs,
    'Milliseconds in event_time must be stripped; both timestamps must hash identically'
  );
});

// ── GENESIS_HASH sanity ──────────────────────────────────────────────────────

test('10. GENESIS_HASH is exactly 64 zero characters', () => {
  assert.equal(GENESIS_HASH.length, 64, 'GENESIS_HASH must be 64 characters long');
  assert.match(GENESIS_HASH, /^0{64}$/, 'GENESIS_HASH must consist only of "0" characters');
});

// ── LOGN_HASH_V1_FIELDS completeness ────────────────────────────────────────

test('11. LOGN_HASH_V1_FIELDS contains exactly the 9 specified fields', () => {
  const expected = new Set([
    'event_id', 'event_time', 'event_type', 'message', 'metadata',
    'previous_hash', 'sequence_number', 'severity', 'source_id',
  ]);
  assert.equal(LOGN_HASH_V1_FIELDS.length, 9, 'Must have exactly 9 fields');
  for (const field of LOGN_HASH_V1_FIELDS) {
    assert.ok(expected.has(field), `Unexpected field in LOGN_HASH_V1_FIELDS: "${field}"`);
  }
  for (const field of expected) {
    assert.ok(LOGN_HASH_V1_FIELDS.includes(field), `Missing field from LOGN_HASH_V1_FIELDS: "${field}"`);
  }
});
