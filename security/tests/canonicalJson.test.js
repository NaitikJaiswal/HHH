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

test('11. RFC 8785 §3.2.2.2 standard escape sequences (\\b, \\t, \\n, \\f, \\r, \\", \\\\)', () => {
  const obj = {
    control: 'bell:\b tab:\t newline:\n formfeed:\f return:\r quote:\" backslash:\\ null:\u0000',
  };
  const result = canonicalJson(obj);
  assert.equal(
    result,
    '{"control":"bell:\\b tab:\\t newline:\\n formfeed:\\f return:\\r quote:\\\" backslash:\\\\ null:\\u0000"}',
    'Standard control characters must use short 2-character escapes per RFC 8785'
  );
});

test('12. RFC 8785 §3.2.2.3 negative zero (-0) serializes as 0', () => {
  const result = canonicalJson({ zero: -0, positiveZero: +0 });
  assert.equal(
    result,
    '{"positiveZero":0,"zero":0}',
    '-0 must be serialized as 0 per RFC 8785 §3.2.2.3'
  );
});

test('13. Numeric boundaries and precision', () => {
  const obj = {
    maxSafe: Number.MAX_SAFE_INTEGER,
    minSafe: Number.MIN_SAFE_INTEGER,
    float: 3.14159,
    smallFloat: 0.000001,
  };
  const result = canonicalJson(obj);
  const parsed = JSON.parse(result);
  assert.equal(parsed.maxSafe, 9007199254740991);
  assert.equal(parsed.minSafe, -9007199254740991);
  assert.equal(parsed.float, 3.14159);
});

test('14. Supplementary plane Unicode (non-BMP: U+10000 to U+10FFFF) preserved as literal UTF-8', () => {
  // 𠮷 is U+20BB7, 𝄞 is U+1D11E, 🔐 is U+1F510
  const obj = { kanji: '𠮷野家', clef: '𝄞', lock: '🔐' };
  const result = canonicalJson(obj);
  assert.equal(
    result,
    '{"clef":"𝄞","kanji":"𠮷野家","lock":"🔐"}',
    'Non-BMP supplementary characters must remain literal UTF-8'
  );
});

test('15. Unpaired surrogates are rejected with TypeError', () => {
  assert.throws(
    () => canonicalJson({ bad: '\uD800' }), // lone high surrogate
    TypeError,
    'Unpaired high surrogate must throw TypeError'
  );
  assert.throws(
    () => canonicalJson({ bad: '\uDC00' }), // lone low surrogate
    TypeError,
    'Unpaired low surrogate must throw TypeError'
  );
});

test('16. Excessive recursion depth (> 10 levels) capped with sentinel', () => {
  let deep = { val: 'leaf' };
  for (let i = 0; i < 12; i++) {
    deep = { next: deep };
  }
  const sorted = sortKeysDeep(deep);
  const result = canonicalJson(sorted);
  assert.ok(
    result.includes('[DEEP_OBJECT]'),
    'Nesting beyond MAX_DEPTH (10) must be replaced with [DEEP_OBJECT]'
  );
});

test('17. Deterministic output across 100 repeated permutations', () => {
  const values = {
    alpha: 1,
    bravo: 2,
    charlie: 3,
    delta: 4,
    echo: 5,
    foxtrot: 6,
  };
  const keys = Object.keys(values);
  const baseline = canonicalJson(values);

  for (let iter = 0; iter < 100; iter++) {
    // Shuffle keys
    const shuffled = [...keys].sort(() => Math.random() - 0.5);
    const obj = {};
    for (const k of shuffled) {
      obj[k] = values[k];
    }
    assert.equal(
      canonicalJson(obj),
      baseline,
      `Iteration ${iter} must produce identical canonical output regardless of insertion order`
    );
  }
});

