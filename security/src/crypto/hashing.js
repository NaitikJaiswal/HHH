/**
 * @module hashing
 * @description SHA-256 hashing and versioned LOGN-HASH-v1 log event hashing.
 *
 * Implements the authoritative canonical log hash specification defined in:
 *   docs/technical-integration-contract.md §1.3
 *
 * LOGN-HASH-v1 Specification:
 * ─────────────────────────────────────────────────────────────────────────────
 * Schema Version: LOGN-HASH-v1
 * Field set: Exactly 9 canonical fields (snake_case):
 *   1. event_id        (string, UUID v4 or alphanumeric string, required)
 *   2. event_time      (string, ISO-8601 UTC normalized: YYYY-MM-DDTHH:MM:SSZ, required)
 *   3. event_type      (string, e.g. AUTHENTICATION, SYSTEM, required)
 *   4. message         (string, human-readable message, required)
 *   5. metadata        (object, key-value map, optional: defaults to {})
 *   6. previous_hash   (string, 64-character lowercase hex SHA-256, required)
 *   7. sequence_number (integer, non-negative monotonic sequence index, required)
 *   8. severity        (string, e.g. DEBUG, INFO, WARNING, ERROR, CRITICAL, required)
 *   9. source_id       (string, system or component identifier, required)
 *
 * Key-sort order (UTF-16 code units / Unicode code point ascending):
 *   event_id < event_time < event_type < message < metadata <
 *   previous_hash < sequence_number < severity < source_id
 *
 * Serialization: canonicalJson() (RFC 8785 compliant)
 * Hash algorithm: SHA-256 (FIPS 180-4) via Node.js native crypto
 * Output: lowercase hex string, exactly 64 characters
 * Genesis hash: 64 zero characters ('0' repeated 64 times)
 *
 * Backward Compatibility:
 *   Accepts both canonical snake_case events and legacy camelCase records
 *   (eventId, sourceId, sequenceNumber, timestamp/eventTime, eventType, previousHash)
 *   and normalizes them into the authoritative LOGN-HASH-v1 canonical representation.
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
 * The schema version identifier.
 *
 * @type {string}
 */
export const HASH_SCHEMA_VERSION = 'LOGN-HASH-v1';

/**
 * The exact 9 field names included in the LOGN-HASH-v1 hash payload.
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
 * @param {string | Buffer} data - Input to hash. If a string, encoded as UTF-8.
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
 *   - Strips millisecond precision deterministically per §1.3.1
 *   - Converted to UTC and always terminated with 'Z'
 *
 * Accepts: ISO-8601 strings, Date objects, epoch timestamps.
 *
 * @param {string | Date | number} timestamp - Timestamp to normalize.
 * @returns {string} Normalized UTC timestamp string.
 * @throws {TypeError} If the timestamp cannot be parsed as a valid date.
 */
export function normalizeTimestamp(timestamp) {
  const date = timestamp instanceof Date ? timestamp : new Date(timestamp);
  if (isNaN(date.getTime())) {
    throw new TypeError(
      `hashLogEvent: invalid event_time value: "${timestamp}"`
    );
  }
  const year  = date.getUTCFullYear();
  const month = String(date.getUTCMonth() + 1).padStart(2, '0');
  const day   = String(date.getUTCDate()).padStart(2, '0');
  const hour  = String(date.getUTCHours()).padStart(2, '0');
  const min   = String(date.getUTCMinutes()).padStart(2, '0');
  const sec   = String(date.getUTCSeconds()).padStart(2, '0');
  return `${year}-${month}-${day}T${hour}:${min}:${sec}Z`;
}

/**
 * Normalize an arbitrary event representation (snake_case or legacy camelCase)
 * into a validated LOGN-HASH-v1 canonical event payload.
 *
 * @param {object} event - Raw or normalized event object.
 * @returns {object} Canonical LOGN-HASH-v1 payload object.
 * @throws {TypeError} If any required field is missing or invalid.
 * @throws {RangeError} If sequence_number is negative or non-finite.
 */
export function normalizeEventPayload(event) {
  if (!event || typeof event !== 'object') {
    throw new TypeError('hashLogEvent: event must be a non-null object');
  }

  // Extract fields supporting both canonical snake_case and legacy camelCase
  const eventId = event.event_id ?? event.eventId;
  const eventTime = event.event_time ?? event.eventTime ?? event.timestamp;
  const eventType = event.event_type ?? event.eventType;
  const message = event.message;
  const metadata = event.metadata;
  const previousHash = event.previous_hash ?? event.previousHash;
  const sequenceNumber = event.sequence_number ?? event.sequenceNumber;
  const severity = event.severity;
  const sourceId = event.source_id ?? event.sourceId;

  // Validation
  const missing = [];
  if (eventId === undefined || eventId === null) missing.push('event_id');
  if (eventTime === undefined || eventTime === null) missing.push('event_time');
  if (eventType === undefined || eventType === null) missing.push('event_type');
  if (message === undefined || message === null) missing.push('message');
  if (previousHash === undefined || previousHash === null) missing.push('previous_hash');
  if (sequenceNumber === undefined || sequenceNumber === null) missing.push('sequence_number');
  if (severity === undefined || severity === null) missing.push('severity');
  if (sourceId === undefined || sourceId === null) missing.push('source_id');

  if (missing.length > 0) {
    throw new TypeError(
      `hashLogEvent: missing required LOGN-HASH-v1 field(s): ${missing.join(', ')}`
    );
  }

  // Sequence number normalization
  const rawSeq = Number(sequenceNumber);
  if (!Number.isFinite(rawSeq)) {
    throw new RangeError(
      `hashLogEvent: sequence_number cannot be converted to a finite number`
    );
  }
  const seqInt = Math.trunc(rawSeq);
  if (seqInt < 0) {
    throw new RangeError(
      `hashLogEvent: sequence_number must be a non-negative integer: ${seqInt}`
    );
  }

  // Previous hash normalization & validation (must be 64 hex characters)
  const prevHashStr = String(previousHash).trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(prevHashStr)) {
    throw new TypeError(
      `hashLogEvent: previous_hash must be a 64-character lowercase hexadecimal string, got "${previousHash}"`
    );
  }

  // Metadata normalization (null/absent/non-object → {})
  const rawMetadata = metadata ?? {};
  const normalizedMetadata =
    rawMetadata === null || typeof rawMetadata !== 'object' || Array.isArray(rawMetadata)
      ? {}
      : sortKeysDeep(rawMetadata);

  return {
    event_id:        String(eventId),
    event_time:      normalizeTimestamp(eventTime),
    event_type:      String(eventType),
    message:         String(message),
    metadata:        normalizedMetadata,
    previous_hash:   prevHashStr,
    sequence_number: seqInt,
    severity:        String(severity),
    source_id:       String(sourceId),
  };
}

/**
 * Compute the canonical LOGN-HASH-v1 hash for a single log event.
 *
 * @param {object} event - The log event object (snake_case or legacy camelCase).
 * @returns {string} Lowercase SHA-256 hex digest of the canonical JSON payload (64 chars).
 */
export function hashLogEvent(event) {
  const payload = normalizeEventPayload(event);
  const canonicalString = canonicalJson(payload);
  return sha256hex(canonicalString);
}

/**
 * Explicitly versioned alias for LOGN-HASH-v1 event hashing.
 */
export const hashLogEventV1 = hashLogEvent;

export default {
  GENESIS_HASH,
  HASH_SCHEMA_VERSION,
  LOGN_HASH_V1_FIELDS,
  sha256hex,
  normalizeTimestamp,
  normalizeEventPayload,
  hashLogEvent,
  hashLogEventV1,
};
