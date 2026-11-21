import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  generateLogHash,
  generateLegacyLogHash,
  hashCanonicalEvent,
  sha256,
  HASH_SCHEMA_VERSION,
  GENESIS_HASH,
  normalizeTimestamp,
} from '../utils/generateHash.js';
import { hashLogEvent } from '../../../security/src/crypto/hashing.js';
import { ingestSingleLog } from '../services/logService.js';
import { verifySourceHashChain } from '../services/integrityService.js';
import Log from '../models/Log.js';
import Source from '../models/Source.js';
import Checkpoint from '../models/Checkpoint.js';
import Incident from '../models/Incident.js';

describe('Phase 5.1 Cryptographic Core Integration - LOGN-HASH-v1 Hashing', () => {
  const sampleCanonicalEvent = {
    event_id: 'evt-canon-100',
    event_time: '2026-11-20T10:00:00Z',
    event_type: 'AUTHENTICATION',
    message: 'User authentication successful',
    metadata: { ip: '192.168.1.50', role: 'admin' },
    previous_hash: '0000000000000000000000000000000000000000000000000000000000000000',
    sequence_number: 1,
    severity: 'INFO',
    source_id: 'auth-service',
  };

  it('1. Authoritative hash matches security/src/crypto/hashing.js exact digest', () => {
    const directSecurityHash = hashLogEvent(sampleCanonicalEvent);
    const backendCanonicalHash = hashCanonicalEvent(sampleCanonicalEvent);
    const backendDispatchedHash = generateLogHash({
      ...sampleCanonicalEvent,
      hashSchemaVersion: HASH_SCHEMA_VERSION,
    });

    expect(backendCanonicalHash).toBe(directSecurityHash);
    expect(backendDispatchedHash).toBe(directSecurityHash);
    expect(backendCanonicalHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('2. Normalizes camelCase attributes into canonical LOGN-HASH-v1 payload', () => {
    const camelCaseEvent = {
      eventId: 'evt-canon-100',
      timestamp: '2026-11-20T10:00:00.123Z', // Milliseconds must be stripped deterministically
      eventType: 'AUTHENTICATION',
      message: 'User authentication successful',
      metadata: { role: 'admin', ip: '192.168.1.50' }, // Key ordering must be normalized
      previousHash: '0000000000000000000000000000000000000000000000000000000000000000',
      sequenceNumber: 1,
      severity: 'INFO',
      sourceId: 'auth-service',
      hashSchemaVersion: HASH_SCHEMA_VERSION,
    };

    const hash = generateLogHash(camelCaseEvent);
    const expectedDirect = hashLogEvent(sampleCanonicalEvent);
    expect(hash).toBe(expectedDirect);
  });

  it('3. Preserves backward compatibility: calculates legacy 7-field hash when hashSchemaVersion is absent', () => {
    const legacyEvent = {
      eventId: 'legacy-evt-1',
      sourceId: 'legacy-srv',
      sequenceNumber: 1,
      timestamp: '2026-11-20T10:00:00.000Z',
      message: 'Legacy event message',
      metadata: { legacyKey: 'legacyVal' },
      previousHash: GENESIS_HASH,
    };

    const legacyHash = generateLegacyLogHash(legacyEvent);
    const dispatchedHash = generateLogHash(legacyEvent);

    expect(dispatchedHash).toBe(legacyHash);
    expect(dispatchedHash).toMatch(/^[0-9a-f]{64}$/);

    // Ensure it differs from a LOGN-HASH-v1 hash of the same content due to schema versioning
    const v1Hash = hashCanonicalEvent({
      ...legacyEvent,
      severity: 'INFO',
      eventType: 'SYSTEM_EVENT',
    });
    expect(dispatchedHash).not.toBe(v1Hash);
  });

  it('4. Detects tampering across all 9 canonical fields', () => {
    const baseHash = hashCanonicalEvent(sampleCanonicalEvent);

    const testModifications = [
      { field: 'event_id', val: 'evt-tampered-999' },
      { field: 'event_time', val: '2026-11-20T10:00:01Z' },
      { field: 'event_type', val: 'AUTHORIZATION' },
      { field: 'message', val: 'User authentication failed' },
      { field: 'metadata', val: { ip: '192.168.1.99', role: 'admin' } },
      { field: 'previous_hash', val: '1111111111111111111111111111111111111111111111111111111111111111' },
      { field: 'sequence_number', val: 2 },
      { field: 'severity', val: 'WARNING' },
      { field: 'source_id', val: 'auth-service-secondary' },
    ];

    for (const mod of testModifications) {
      const altered = { ...sampleCanonicalEvent, [mod.field]: mod.val };
      const alteredHash = hashCanonicalEvent(altered);
      expect(alteredHash).not.toBe(baseHash);
    }
  });

  describe('Integrity Service with LOGN-HASH-v1 Chain', () => {
    let mockDbLogs = [];

    beforeEach(() => {
      vi.restoreAllMocks();
      mockDbLogs = [];

      let prev = GENESIS_HASH;
      for (let seq = 1; seq <= 3; seq++) {
        const doc = {
          eventId: `canon-evt-${seq}`,
          sourceId: 'server-v1',
          sequenceNumber: seq,
          timestamp: new Date(`2026-11-20T10:0${seq}:00Z`),
          eventType: 'SECURITY_EVENT',
          severity: 'INFO',
          hashSchemaVersion: 'LOGN-HASH-v1',
          message: `Canon event ${seq}`,
          metadata: { seqIndex: seq },
          previousHash: prev,
        };

        doc.currentHash = generateLogHash(doc);
        mockDbLogs.push(doc);
        prev = doc.currentHash;
      }

      vi.spyOn(Log, 'find').mockImplementation(() => ({
        sort: vi.fn().mockReturnValue({
          lean: vi.fn().mockResolvedValue(JSON.parse(JSON.stringify(mockDbLogs))),
        }),
      }));

      vi.spyOn(Checkpoint, 'find').mockImplementation(() => ({
        sort: vi.fn().mockReturnValue({
          lean: vi.fn().mockResolvedValue([]),
        }),
      }));

      vi.spyOn(Incident, 'create').mockResolvedValue({ incidentId: 'inc-v1' });
    });

    it('5. Successfully verifies pure LOGN-HASH-v1 chain', async () => {
      const report = await verifySourceHashChain('server-v1');
      expect(report.isValid).toBe(true);
      expect(report.totalLogs).toBe(3);
      expect(report.anomalies).toHaveLength(0);
      expect(report.chainHeadHash).toBe(mockDbLogs[2].currentHash);
    });

    it('6. Detects field tampering on LOGN-HASH-v1 record (MODIFIED_RECORD)', async () => {
      // Attacker maliciously alters the message of record 2
      mockDbLogs[1].message = 'MALICIOUS_ALTERATION_ATTACK';

      const report = await verifySourceHashChain('server-v1');
      expect(report.isValid).toBe(false);
      const modAnomaly = report.anomalies.find((a) => a.type === 'MODIFIED_RECORD');
      expect(modAnomaly).toBeDefined();
      expect(modAnomaly.sequenceNumber).toBe(2);
      expect(modAnomaly.eventId).toBe('canon-evt-2');
    });

    it('7. Ingests single log with LOGN-HASH-v1 schema and verifies chain addition', async () => {
      const mockSources = new Map();
      const mockSavedLogs = new Map();

      vi.spyOn(Log, 'findOne').mockImplementation(({ eventId }) => {
        return Promise.resolve(mockSavedLogs.get(eventId) || null);
      });

      vi.spyOn(Log, 'create').mockImplementation((data) => {
        mockSavedLogs.set(data.eventId, data);
        return Promise.resolve(data);
      });

      vi.spyOn(Source, 'findOne').mockImplementation(({ sourceId }) => {
        const s = mockSources.get(sourceId);
        if (!s) return Promise.resolve(null);
        return Promise.resolve({
          ...s,
          save: vi.fn().mockImplementation(function () {
            mockSources.set(sourceId, this);
            return Promise.resolve(this);
          }),
        });
      });

      vi.spyOn(Source, 'create').mockImplementation((data) => {
        mockSources.set(data.sourceId, {
          ...data,
          save: vi.fn().mockImplementation(function () {
            mockSources.set(data.sourceId, this);
            return Promise.resolve(this);
          }),
        });
        return Promise.resolve(mockSources.get(data.sourceId));
      });

      const outcome = await ingestSingleLog({
        event_id: 'ingest-v1-001',
        source_id: 'ingest-source',
        event_time: '2026-11-20T12:00:00Z',
        event_type: 'SYSTEM',
        severity: 'WARNING',
        message: 'High CPU utilization detected',
        metadata: { cpu: 94.2 },
      });

      expect(outcome.isDuplicate).toBe(false);
      expect(outcome.log.hashSchemaVersion).toBe('LOGN-HASH-v1');
      expect(outcome.log.severity).toBe('WARNING');
      expect(outcome.log.sequenceNumber).toBe(1);
      expect(outcome.log.previousHash).toBe(GENESIS_HASH);

      const expectedHash = hashCanonicalEvent({
        event_id: 'ingest-v1-001',
        source_id: 'ingest-source',
        event_time: '2026-11-20T12:00:00Z',
        event_type: 'SYSTEM',
        severity: 'WARNING',
        message: 'High CPU utilization detected',
        metadata: { cpu: 94.2 },
        previous_hash: GENESIS_HASH,
        sequence_number: 1,
      });

      expect(outcome.log.currentHash).toBe(expectedHash);
    });
  });
});
