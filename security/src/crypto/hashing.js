/**
 * @module hashing
 * @description SHA-256 hashing and LOGN-HASH-v1 log event hashing.
 *
 * Implements the canonical log hash formula defined in:
 *   docs/technical-integration-contract.md §1.3
 *
 * LOGN-HASH-v1 field set (9 fields, snake_case):
 *   event_id, event_time, event_type, message, metadata,
 *   previous_hash, sequence_number, severity, source_id
 *
 * Key-sort order (Unicode code point ascending):
 *   event_id < event_time < event_type < message < metadata <
 *   previous_hash < sequence_number < severity < source_id
 *
 * Serialization: canonicalJson() from canonicalJson.js
 * Hash algorithm: SHA-256 via Node.js built-in node:crypto
 * Output: lowercase hex string, exactly 64 characters
 */

import { createHash } from 'node:crypto';
import { canonicalJson, sortKeysDeep } from './canonicalJson.js';

/**
 * The genesis previous_hash for the first event in any source.
 * Per §1.3.3: 64 zero characters.
 *
 * @type {string}
 */
export const GENESIS_HASH = '0'.repeat(64);

/**
 * The exact 9 field names included in the LOGN-HASH-v1 hash payload.
 * Order here is for reference; the canonicalJson serializer sorts keys
 * independently by Unicode code point.
 *
 * @type {readonly string[]}
 */
export const LOGN_HASH_V1_FIELDS = Object.freeze([
  'event_id',
  'event_time',
  'event_type',
  'message',
  'metadata',
  'previous_hash',
  'sequence_number',
  'severity',
  'source_id',
]);

/**
 * Compute the SHA-256 digest of a string or Buffer.
 *
 * @param {string | Buffer} data - Input to hash. If a string, it is
 *   encoded as UTF-8 before hashing (matching the LOGN-HASH-v1 requirement
 *   to encode the canonical JSON string as UTF-8 before hashing).
 * @returns {string} Lowercase hexadecimal SHA-256 digest (64 characters).
 */
export function sha256hex(data) {
  const hash = createHash('sha256');
  if (typeof data === 'string') {
    hash.update(data, 'utf8');
  } else {
    hash.update(data);
  }
  return hash.digest('hex');
}

/**
 * Normalize an ISO-8601 timestamp to the LOGN-HASH-v1 required format:
 *   "YYYY-MM-DDTHH:MM:SSZ"
 *   - No milliseconds
 *   - Always ends with Z (UTC)
 *
 * Accepts: ISO-8601 strings with or without milliseconds, with Z or +00:00 suffix.
 *
 * @param {string} timestamp - ISO-8601 timestamp string.
 * @returns {string} Normalized timestamp string.
 * @throws {TypeError} If the timestamp cannot be parsed as a valid date.
 */
function normalizeTimestamp(timestamp) {
  // Parse the timestamp to validate it
  const date = new Date(timestamp);
  if (isNaN(date.getTime())) {
    throw new TypeError(
      `hashLogEvent: invalid event_time value: "${timestamp}"`
    );
  }
  // Build YYYY-MM-DDTHH:MM:SSZ manually to avoid any locale/engine differences
  const year  = date.getUTCFullYear();
  const month = String(date.getUTCMonth() + 1).padStart(2, '0');
  const day   = String(date.getUTCDate()).padStart(2, '0');
  const hour  = String(date.getUTCHours()).padStart(2, '0');
  const min   = String(date.getUTCMinutes()).padStart(2, '0');
  const sec   = String(date.getUTCSeconds()).padStart(2, '0');
  return `${year}-${month}-${day}T${hour}:${min}:${sec}Z`;
}

/**
 * Compute the LOGN-HASH-v1 hash for a single log event.
 *
 * Steps (per §1.3.6 pseudocode):
 *   1. Validate all 9 required fields are present (throws if any are missing).
 *   2. Normalize event_time to "YYYY-MM-DDTHH:MM:SSZ" (strip milliseconds, force UTC Z).
 *   3. Build the 9-field LOGN-HASH-v1 payload with correct types:
 *        - sequence_number coerced to integer via Math.trunc(Number(...))
 *        - metadata null/absent → {}
 *        - metadata keys sorted recursively by sortKeysDeep
 *        - all other fields converted to string via String(...)
 *   4. Serialize with canonicalJson() — sorted keys, no whitespace, UTF-8 preserved.
 *   5. Compute SHA-256 of the UTF-8 encoding of the canonical JSON string.
 *   6. Return lowercase hex string (64 characters).
 *
 * This function never logs event contents.
 *
 * @param {object} event - The log event object. Must contain all 9 LOGN-HASH-v1 fields.
 * @param {string} event.event_id - UUID v4 string.
 * @param {string} event.event_time - ISO-8601 UTC timestamp.
 * @param {string} event.event_type - Event type (e.g. AUTHENTICATION, SYSTEM).
 * @param {string} event.message - Human-readable event message.
 * @param {object|null} [event.metadata] - Arbitrary key-value metadata. null/absent → {}.
 * @param {string} event.previous_hash - Previous event's hash, or GENESIS_HASH for first event.
 * @param {number|string} event.sequence_number - Monotonically increasing integer (coerced).
 * @param {string} event.severity - Severity level (DEBUG|INFO|WARNING|ERROR|CRITICAL).
 * @param {string} event.source_id - Identifier of the event source.
 * @returns {string} Lowercase SHA-256 hex digest of the canonical JSON payload (64 chars).
 * @throws {TypeError} If any required field is missing or event_time is invalid.
 * @throws {RangeError} If sequence_number cannot be converted to a finite integer.
 */
export function hashLogEvent(event) {
  // ── Step 1: Validate required fields ────────────────────────────────────────
  const missing = LOGN_HASH_V1_FIELDS.filter(
    (field) => event[field] === undefined && field !== 'metadata'
  );
  // metadata is allowed to be null or absent; all others must be present
  const strictMissing = LOGN_HASH_V1_FIELDS.filter((field) => {
    if (field === 'metadata') return false; // metadata: null/absent is allowed
    return event[field] === undefined || event[field] === null;
  });

  if (strictMissing.length > 0) {
    throw new TypeError(
      `hashLogEvent: missing required LOGN-HASH-v1 fields: ${strictMissing.join(', ')}`
    );
  }

  // ── Step 2: Normalize event_time ────────────────────────────────────────────
  const normalizedTime = normalizeTimestamp(String(event.event_time));

  // ── Step 3: Normalize sequence_number to integer ────────────────────────────
  const rawSeq = Number(event.sequence_number);
  if (!Number.isFinite(rawSeq)) {
    throw new RangeError(
      `hashLogEvent: sequence_number cannot be converted to a finite number`
    );
  }
  const seqInt = Math.trunc(rawSeq);

  // ── Step 4: Normalize metadata (null/absent → {}) ───────────────────────────
  const rawMetadata = event.metadata ?? {};
  const normalizedMetadata =
    rawMetadata === null
      ? {}
      : sortKeysDeep(typeof rawMetadata === 'object' ? rawMetadata : {});

  // ── Step 5: Build the LOGN-HASH-v1 payload ──────────────────────────────────
  // Field order here does NOT matter — canonicalJson() sorts keys independently.
  const payload = {
    event_id:        String(event.event_id),
    event_time:      normalizedTime,
    event_type:      String(event.event_type),
    message:         String(event.message),
    metadata:        normalizedMetadata,
    previous_hash:   String(event.previous_hash),
    sequence_number: seqInt,
    severity:        String(event.severity),
    source_id:       String(event.source_id),
  };

  // ── Step 6: Canonical JSON → SHA-256 ────────────────────────────────────────
  const canonicalString = canonicalJson(payload);
  return sha256hex(canonicalString);
}

export default { GENESIS_HASH, LOGN_HASH_V1_FIELDS, sha256hex, hashLogEvent };
