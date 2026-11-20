/**
 * Tests for canonicalJson.js — LOGN-HASH-v1 deterministic serialization.
 * Uses Node.js built-in node:test and node:assert/strict.
 *
 * Test coverage:
 *   1.  Same event produces same canonical JSON (idempotency)
 *   2.  Different key insertion orders produce identical output
 *   3.  Unicode characters preserved as literal UTF-8 (not \uXXXX escaped)
 *   4.  undefined values in objects are omitted
 *   5.  Non-finite numbers (Infinity, NaN, -Infinity) are rejected
 *   6.  Nested objects have keys sorted recursively
 *   7.  Arrays: element order preserved
 *   8.  Null at top level serializes as "null"
 *   9.  Circular reference → throws TypeError
 *  10.  Exact §1.3.5 canonical string reproduced for the worked example event
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { canonicalJson, sortKeysDeep } from '../src/crypto/canonicalJson.js';

// ── §1.3.5 worked example ────────────────────────────────────────────────────
// Source: docs/technical-integration-contract.md §1.3.5
const CONTRACT_EXAMPLE_EVENT = {
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

// The exact canonical string defined in §1.3.5 of the integration contract.
// This string was produced by sorting keys by Unicode code point ascending:
//   event_id < event_time < event_type < message < metadata < previous_hash < sequence_number < severity < source_id
// and by sorting metadata keys ("ip" < "user").
const CONTRACT_CANONICAL_STRING =
  '{"event_id":"a1b2c3d4-0000-0000-0000-000000000001",' +
  '"event_time":"2026-11-20T11:00:00Z",' +
  '"event_type":"AUTHENTICATION",' +
  '"message":"User login successful",' +
  '"metadata":{"ip":"10.0.0.1","user":"alice"},' +
  '"previous_hash":"0000000000000000000000000000000000000000000000000000000000000000",' +
  '"sequence_number":1,' +
  '"severity":"INFO",' +
  '"source_id":"server-alpha"}';

// ── Tests ────────────────────────────────────────────────────────────────────

test('1. Same event produces same canonical JSON (idempotency)', () => {
  const event = {
    event_id: 'abc-123',
    event_type: 'SYSTEM',
    message: 'test',
    severity: 'INFO',
    source_id: 'node-1',
    sequence_number: 5,
  };
  const result1 = canonicalJson(event);
  const result2 = canonicalJson(event);
  assert.equal(result1, result2, 'Two calls with identical input must produce identical output');
});

test('2. Different key insertion orders produce identical output', () => {
  // Insert keys in different orders — output must be identical
  const eventA = {
    source_id: 's1',
    event_id:  'e1',
    message:   'hello',
    severity:  'DEBUG',
  };
  const eventB = {
    message:   'hello',
    severity:  'DEBUG',
    event_id:  'e1',
    source_id: 's1',
  };
  assert.equal(
    canonicalJson(eventA),
    canonicalJson(eventB),
    'Key insertion order must not affect canonical output'
  );
});

test('3. Unicode characters preserved as literal UTF-8 (not \\uXXXX escaped)', () => {
  const obj = { greeting: 'héllo wörld', emoji: '🔐', cjk: '日本語' };
  const result = canonicalJson(obj);
  // The characters must appear literally, not escaped
  assert.ok(
    result.includes('héllo wörld'),
    'Latin extended characters must not be \\u-escaped'
  );
  assert.ok(result.includes('🔐'), 'Emoji must not be \\u-escaped');
  assert.ok(result.includes('日本語'), 'CJK characters must not be \\u-escaped');
  // Must NOT contain \\u escape for non-ASCII (the é is U+00E9; check it literally)
  assert.ok(
    !result.includes('\\u00e9') && !result.includes('\\u00E9'),
    '\\u-escaping of non-ASCII characters is forbidden by LOGN-HASH-v1'
  );
});

test('4. undefined values in objects are omitted', () => {
  const obj = { a: 'keep', b: undefined, c: 'keep-too' };
  const result = canonicalJson(obj);
  assert.ok(!result.includes('"b"'), 'undefined values must be omitted from output');
  assert.ok(result.includes('"a"'), 'defined keys must appear');
  assert.ok(result.includes('"c"'), 'defined keys must appear');
});

test('5a. Infinity is rejected with RangeError', () => {
  assert.throws(
    () => canonicalJson({ value: Infinity }),
    RangeError,
    'Infinity must throw RangeError'
  );
});

test('5b. NaN is rejected with RangeError', () => {
  assert.throws(
    () => canonicalJson({ value: NaN }),
    RangeError,
    'NaN must throw RangeError'
  );
});

test('5c. -Infinity is rejected with RangeError', () => {
  assert.throws(
    () => canonicalJson({ value: -Infinity }),
    RangeError,
    '-Infinity must throw RangeError'
  );
});

test('6. Nested objects have keys sorted recursively', () => {
  const obj = {
    z_outer: { z_inner: 'last', a_inner: 'first' },
    a_outer: { m_inner: 'mid', a_inner: 'first' },
  };
  const result = canonicalJson(obj);
  // a_outer < z_outer; within each: a_inner < m_inner/z_inner
  const parsed = JSON.parse(result);
  assert.deepEqual(Object.keys(parsed), ['a_outer', 'z_outer'], 'Top-level keys must be sorted');
  assert.deepEqual(Object.keys(parsed.a_outer), ['a_inner', 'm_inner'], 'Nested keys must be sorted');
  assert.deepEqual(Object.keys(parsed.z_outer), ['a_inner', 'z_inner'], 'Nested keys must be sorted');
});

test('7. Arrays: element order preserved', () => {
  const obj = { items: [3, 1, 2, 'z', 'a'] };
  const result = canonicalJson(obj);
  const parsed = JSON.parse(result);
  assert.deepEqual(parsed.items, [3, 1, 2, 'z', 'a'], 'Array element order must not be changed');
});

test('8. Null at top level serializes as "null"', () => {
  const result = canonicalJson(null);
  assert.equal(result, 'null', 'null must serialize to the string "null"');
});

test('8b. Null metadata value serializes as null (not {})', () => {
  // canonicalJson itself serializes null as "null"; the metadata→{} normalization
  // is the caller's responsibility (hashLogEvent). Here we confirm raw null behaviour.
  const obj = { metadata: null };
  const result = canonicalJson(obj);
  assert.ok(result.includes('"metadata":null'), 'null object value serializes as JSON null');
});

test('9. Circular reference throws TypeError', () => {
  const obj = { a: 1 };
  obj.self = obj; // create cycle
  assert.throws(
    () => canonicalJson(obj),
    TypeError,
    'Circular reference must throw TypeError'
  );
});

test('10. §1.3.5 exact canonical string is reproduced', () => {
  // Build the payload exactly as hashLogEvent does, then serialize with canonicalJson.
  // The canonical string must match the exact string from the integration contract §1.3.5.
  const payload = {
    event_id:        CONTRACT_EXAMPLE_EVENT.event_id,
    event_time:      CONTRACT_EXAMPLE_EVENT.event_time,
    event_type:      CONTRACT_EXAMPLE_EVENT.event_type,
    message:         CONTRACT_EXAMPLE_EVENT.message,
    metadata:        CONTRACT_EXAMPLE_EVENT.metadata,
    previous_hash:   CONTRACT_EXAMPLE_EVENT.previous_hash,
    sequence_number: CONTRACT_EXAMPLE_EVENT.sequence_number,
    severity:        CONTRACT_EXAMPLE_EVENT.severity,
    source_id:       CONTRACT_EXAMPLE_EVENT.source_id,
  };

  const result = canonicalJson(payload);
  assert.equal(
    result,
    CONTRACT_CANONICAL_STRING,
    'Canonical string must match the exact string defined in §1.3.5 of the integration contract'
  );
});
