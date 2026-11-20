import Log from '../models/Log.js';
import Source from '../models/Source.js';
import { generateLogHash } from '../utils/generateHash.js';

const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

/**
 * Verify cryptographic hash chain integrity for a specific log source.
 * Detects:
 *  - Modified event contents or metadata
 *  - Deleted records (sequence number gaps)
 *  - Out-of-order / reordered records
 *  - Broken hash chains (previousHash mismatch)
 */
export const verifySourceHashChain = async (sourceId) => {
  const logs = await Log.find({ sourceId }).sort({ sequenceNumber: 1 }).lean();

  const report = {
    sourceId,
    totalLogs: logs.length,
    isValid: true,
    firstSequence: logs.length > 0 ? logs[0].sequenceNumber : 0,
    lastSequence: logs.length > 0 ? logs[logs.length - 1].sequenceNumber : 0,
    chainHeadHash: logs.length > 0 ? logs[logs.length - 1].currentHash : GENESIS_HASH,
    tamperedCount: 0,
    anomalies: [],
    verifiedAt: new Date().toISOString(),
  };

  if (logs.length === 0) {
    return report;
  }

  let expectedPreviousHash = GENESIS_HASH;
  let expectedSequence = 1;

  for (let i = 0; i < logs.length; i++) {
    const current = logs[i];
    let recordValid = true;

    // 1. Detect missing sequence numbers or deletions
    if (current.sequenceNumber !== expectedSequence) {
      report.isValid = false;
      report.anomalies.push({
        type: 'MISSING_SEQUENCE',
        severity: 'high',
        sequenceNumber: current.sequenceNumber,
        expectedSequence,
        eventId: current.eventId,
        message: `Sequence gap detected: expected ${expectedSequence}, but found ${current.sequenceNumber}. Possible record deletion.`,
      });
      // Resynchronize expected sequence to current to continue inspecting remaining chain
      expectedSequence = current.sequenceNumber;
    }

    // 2. Detect broken hash chains (previousHash pointer corruption)
    if (current.previousHash !== expectedPreviousHash) {
      recordValid = false;
      report.isValid = false;
      report.anomalies.push({
        type: 'BROKEN_CHAIN',
        severity: 'critical',
        sequenceNumber: current.sequenceNumber,
        eventId: current.eventId,
        expectedPreviousHash,
        actualPreviousHash: current.previousHash,
        message: `Broken hash chain at sequence ${current.sequenceNumber}: previousHash does not match preceding record's currentHash.`,
      });
    }

    // 3. Recalculate deterministic SHA-256 hash to detect content or timestamp tampering
    const recalculatedHash = generateLogHash({
      eventId: current.eventId,
      sourceId: current.sourceId,
      sequenceNumber: current.sequenceNumber,
      timestamp: current.timestamp,
      message: current.message,
      metadata: current.metadata,
      previousHash: current.previousHash,
    });

    if (recalculatedHash !== current.currentHash) {
      recordValid = false;
      report.isValid = false;
      report.anomalies.push({
        type: 'MODIFIED_RECORD',
        severity: 'critical',
        sequenceNumber: current.sequenceNumber,
        eventId: current.eventId,
        storedHash: current.currentHash,
        recalculatedHash,
        message: `Cryptographic tampering detected on event ${current.eventId}: stored hash does not match canonical payload.`,
      });
    }

    // 4. Detect sequence or timestamp order inversion (reordering)
    if (i > 0) {
      const prev = logs[i - 1];
      if (current.sequenceNumber <= prev.sequenceNumber) {
        recordValid = false;
        report.isValid = false;
        report.anomalies.push({
          type: 'REORDERED_RECORD',
          severity: 'high',
          sequenceNumber: current.sequenceNumber,
          eventId: current.eventId,
          message: `Reordered log detected: sequence ${current.sequenceNumber} appears after ${prev.sequenceNumber}.`,
        });
      }
    }

    if (!recordValid) {
      report.tamperedCount++;
    }

    // Update expected pointer for next iteration
    expectedPreviousHash = current.currentHash;
    expectedSequence = current.sequenceNumber + 1;
  }

  return report;
};

/**
 * Verify integrity across all registered log sources
 */
export const verifyAllSources = async () => {
  const sources = await Source.find({}).lean();
  const results = [];

  for (const src of sources) {
    const report = await verifySourceHashChain(src.sourceId);
    results.push(report);
  }

  const hasAnyTampering = results.some((r) => !r.isValid);

  return {
    overallIntegrity: !hasAnyTampering,
    totalSourcesChecked: sources.length,
    sourcesWithAnomalies: results.filter((r) => !r.isValid).length,
    reports: results,
    checkedAt: new Date().toISOString(),
  };
};

export default {
  verifySourceHashChain,
  verifyAllSources,
};
