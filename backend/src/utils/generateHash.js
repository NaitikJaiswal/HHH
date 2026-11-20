import crypto from 'crypto';
import { canonicalize } from './canonicalize.js';

/**
 * Computes a standard SHA-256 hex hash from any string or buffer
 */
export const sha256 = (data) => {
  return crypto.createHash('sha256').update(data).digest('hex');
};

/**
 * Computes a deterministic SHA-256 hash for a log entry.
 * Cryptographically binds:
 *  - eventId
 *  - sourceId
 *  - sequenceNumber
 *  - timestamp (ISO formatted)
 *  - message
 *  - metadata (canonicalized)
 *  - previousHash
 */
export const generateLogHash = ({
  eventId,
  sourceId,
  sequenceNumber,
  timestamp,
  message,
  metadata = {},
  previousHash,
}) => {
  // Ensure timestamp is normalized to ISO string
  const normalizedTimestamp = timestamp instanceof Date ? timestamp.toISOString() : new Date(timestamp).toISOString();

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

export default {
  sha256,
  generateLogHash,
};
