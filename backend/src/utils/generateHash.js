import crypto from 'crypto';
import { canonicalize } from './canonicalize.js';
import {
  hashLogEvent,
  sha256hex,
  normalizeTimestamp,
  HASH_SCHEMA_VERSION,
  GENESIS_HASH,
} from '../../../security/src/crypto/hashing.js';

export { HASH_SCHEMA_VERSION, GENESIS_HASH, normalizeTimestamp };

/**
 * Computes a standard SHA-256 hex hash from any string or buffer
 */
export const sha256 = (data) => {
  return sha256hex(data);
};

/**
 * Legacy 7-field camelCase log hash generator for backward compatibility.
 */
export const generateLegacyLogHash = ({
  eventId,
  sourceId,
  sequenceNumber,
  timestamp,
  message,
  metadata = {},
  previousHash,
}) => {
  const normalizedTimestamp =
    timestamp instanceof Date ? timestamp.toISOString() : new Date(timestamp).toISOString();

  const hashPayload = {
    eventId: String(eventId),
    sourceId: String(sourceId),
    sequenceNumber: Number(sequenceNumber),
    timestamp: normalizedTimestamp,
    message: String(message),
    metadata: metadata || {},
    previousHash: String(previousHash),
  };

  const canonicalString = canonicalize(hashPayload);
  return crypto.createHash('sha256').update(canonicalString, 'utf8').digest('hex');
};

/**
 * Authoritative LOGN-HASH-v1 canonical event hash generator.
 * Uses security/src/crypto/hashing.js as single source of truth.
 */
export const hashCanonicalEvent = (event) => {
  return hashLogEvent({
    event_id: event.event_id ?? event.eventId,
    event_time: event.event_time ?? event.eventTime ?? event.timestamp,
    event_type: event.event_type ?? event.eventType ?? 'SYSTEM_EVENT',
    message: event.message ?? '',
    metadata: event.metadata ?? {},
    previous_hash: event.previous_hash ?? event.previousHash,
    sequence_number: event.sequence_number ?? event.sequenceNumber,
    severity: event.severity ?? 'INFO',
    source_id: event.source_id ?? event.sourceId,
  });
};

/**
 * Deterministic log hash calculation with dual-schema compatibility:
 * - If event.hashSchemaVersion === 'LOGN-HASH-v1' or event contains canonical snake_case fields: computes LOGN-HASH-v1.
 * - Otherwise (legacy events or legacy test cases without hashSchemaVersion): computes legacy 7-field hash.
 */
export const generateLogHash = (event) => {
  if (!event || typeof event !== 'object') {
    throw new TypeError('generateLogHash: event must be an object');
  }

  const isV1 =
    event.hashSchemaVersion === HASH_SCHEMA_VERSION ||
    event.schemaVersion === HASH_SCHEMA_VERSION ||
    (event.event_id !== undefined && event.event_time !== undefined);

  if (isV1) {
    return hashCanonicalEvent(event);
  }

  // Fallback to legacy hash for backward compatibility
  return generateLegacyLogHash(event);
};

export default {
  sha256,
  generateLogHash,
  generateLegacyLogHash,
  hashCanonicalEvent,
  HASH_SCHEMA_VERSION,
  GENESIS_HASH,
  normalizeTimestamp,
};
