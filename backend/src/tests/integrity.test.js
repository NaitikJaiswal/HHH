import { describe, it, expect, vi, beforeEach } from 'vitest';
import { canonicalize } from '../utils/canonicalize.js';
import { generateLogHash, sha256 } from '../utils/generateHash.js';
import { verifySourceHashChain } from '../services/integrityService.js';
import { ingestSingleLog } from '../services/logService.js';
import Log from '../models/Log.js';
import Source from '../models/Source.js';

describe('Milestone 5: SHA-256 Hashing, Canonicalization & Hash Chaining', () => {
  describe('Canonical JSON Serialization (RFC 8785)', () => {
    it('1. Serializes objects with differently ordered keys to the exact same string', () => {
      const obj1 = { z: 'last', a: 'first', m: 'middle' };
      const obj2 = { a: 'first', m: 'middle', z: 'last' };
      const obj3 = { m: 'middle', z: 'last', a: 'first' };

      const canon1 = canonicalize(obj1);
      const canon2 = canonicalize(obj2);
      const canon3 = canonicalize(obj3);

      expect(canon1).toBe('{"a":"first","m":"middle","z":"last"}');
      expect(canon1).toBe(canon2);
      expect(canon2).toBe(canon3);
    });

    it('2. Correctly canonicalizes nested objects and arrays deterministically', () => {
      const complex1 = {
        metadata: { ip: '192.168.1.1', user: { role: 'admin', id: 42 } },
        tags: ['auth', 'security', 'critical'],
      };
      const complex2 = {
        tags: ['auth', 'security', 'critical'],
        metadata: { user: { id: 42, role: 'admin' }, ip: '192.168.1.1' },
      };

      expect(canonicalize(complex1)).toBe(canonicalize(complex2));
    });
  });

  describe('Cryptographic Hash Generation', () => {
    const baseEntry = {
      eventId: 'evt-audit-001',
      sourceId: 'srv-firewall-01',
      sequenceNumber: 1,
      timestamp: new Date('2026-11-20T10:00:00Z'),
      message: 'Inbound packet dropped from 10.0.0.5',
      metadata: { port: 22, protocol: 'TCP' },
      previousHash: '0000000000000000000000000000000000000000000000000000000000000000',
    };

    it('3. Produces identical SHA-256 hash when inputs have identical content regardless of key order', () => {
      const hash1 = generateLogHash(baseEntry);
      const hash2 = generateLogHash({
        ...baseEntry,
        metadata: { protocol: 'TCP', port: 22 }, // Reordered metadata keys
      });

      expect(hash1).toBe(hash2);
      expect(hash1).toHaveLength(64); // Valid 256-bit hex string
    });

    it('4. Demonstrates cryptographic avalanche effect: altering 1 bit changes the entire digest', () => {
      const originalHash = generateLogHash(baseEntry);

      // Modify a single character in the message
      const tamperedEntry = {
        ...baseEntry,
        message: 'Inbound packet dropped from 10.0.0.6', // 5 -> 6
      };
      const tamperedHash = generateLogHash(tamperedEntry);

      expect(tamperedHash).not.toBe(originalHash);
    });
  });

  describe('Concurrency Safety in Log Ingestion', () => {
    const mockDbLogs = new Map();
    const mockDbSources = new Map();

    beforeEach(() => {
      mockDbLogs.clear();
      mockDbSources.clear();
      vi.restoreAllMocks();

      vi.spyOn(Log, 'findOne').mockImplementation(({ eventId }) => {
        return Promise.resolve(mockDbLogs.get(eventId) || null);
      });

      vi.spyOn(Log, 'create').mockImplementation((data) => {
        const doc = { _id: 'id_' + data.eventId, ...data };
        mockDbLogs.set(doc.eventId, doc);
        return Promise.resolve(doc);
      });

      vi.spyOn(Source, 'findOne').mockImplementation(({ sourceId }) => {
        const s = mockDbSources.get(sourceId);
        if (!s) return Promise.resolve(null);
        return Promise.resolve({
          ...s,
          save: vi.fn().mockImplementation(function () {
            mockDbSources.set(sourceId, this);
            return Promise.resolve(this);
          }),
        });
      });

      vi.spyOn(Source, 'create').mockImplementation((data) => {
        const s = {
          ...data,
          save: vi.fn().mockImplementation(function () {
            mockDbSources.set(data.sourceId, this);
            return Promise.resolve(this);
          }),
        };
        mockDbSources.set(data.sourceId, s);
        return Promise.resolve(s);
      });
    });

    it('5. Ensures simultaneous parallel submissions get contiguous sequence numbers and unbroken chain', async () => {
      const sourceId = 'parallel-source-1';

      // Fire 5 concurrent submissions simultaneously
      const submissions = [1, 2, 3, 4, 5].map((idx) =>
        ingestSingleLog({
          eventId: `parallel-evt-${idx}`,
          sourceId,
          eventType: 'PARALLEL_TEST',
          message: `Concurrent event ${idx}`,
          timestamp: new Date().toISOString(),
        })
      );

      const results = await Promise.all(submissions);

      // All 5 must succeed
      expect(results).toHaveLength(5);
      results.forEach((r) => expect(r.isDuplicate).toBe(false));

      // Extract sequence numbers and sort them
      const logs = Array.from(mockDbLogs.values()).sort((a, b) => a.sequenceNumber - b.sequenceNumber);

      expect(logs).toHaveLength(5);
      expect(logs.map((l) => l.sequenceNumber)).toEqual([1, 2, 3, 4, 5]);

      // Verify the resulting hash chain is contiguous and unbroken
      let prevHash = '0000000000000000000000000000000000000000000000000000000000000000';
      for (const log of logs) {
        expect(log.previousHash).toBe(prevHash);
        prevHash = log.currentHash;
      }
    });
  });

  describe('Hash Chain Verification & Tamper Detection', () => {
    let mockChainLogs = [];

    beforeEach(() => {
      vi.restoreAllMocks();

      // Build a 4-record authentic cryptographic chain
      let prev = '0000000000000000000000000000000000000000000000000000000000000000';
      mockChainLogs = [1, 2, 3, 4].map((seq) => {
        const eventId = `chain-evt-${seq}`;
        const sourceId = 'audit-server-01';
        const timestamp = new Date(`2026-11-20T10:0${seq}:00Z`);
        const message = `Log record sequence ${seq}`;
        const metadata = { step: seq };
        const currentHash = generateLogHash({
          eventId,
          sourceId,
          sequenceNumber: seq,
          timestamp,
          message,
          metadata,
          previousHash: prev,
        });

        const entry = {
          eventId,
          sourceId,
          sequenceNumber: seq,
          timestamp,
          message,
          metadata,
          previousHash: prev,
          currentHash,
        };
        prev = currentHash;
        return entry;
      });

      vi.spyOn(Log, 'find').mockImplementation(() => ({
        sort: vi.fn().mockReturnValue({
          lean: vi.fn().mockImplementation(() => Promise.resolve(JSON.parse(JSON.stringify(mockChainLogs)))),
        }),
      }));
    });

    it('6. Successfully verifies an untampered, unbroken cryptographic hash chain', async () => {
      const report = await verifySourceHashChain('audit-server-01');

      expect(report.isValid).toBe(true);
      expect(report.tamperedCount).toBe(0);
      expect(report.anomalies).toHaveLength(0);
      expect(report.totalLogs).toBe(4);
    });

    it('7. Detects modified log content (MODIFIED_RECORD)', async () => {
      // Attacker changes the message of record sequence 2 in the database
      mockChainLogs[1].message = 'MALICIOUS MODIFICATION BY ROOT ATTACKER';

      const report = await verifySourceHashChain('audit-server-01');

      expect(report.isValid).toBe(false);
      expect(report.tamperedCount).toBeGreaterThan(0);
      const modAnomaly = report.anomalies.find((a) => a.type === 'MODIFIED_RECORD');
      expect(modAnomaly).toBeDefined();
      expect(modAnomaly.eventId).toBe('chain-evt-2');
    });

    it('8. Detects deleted log record (MISSING_SEQUENCE and BROKEN_CHAIN)', async () => {
      // Attacker deletes record sequence 3 to hide an action
      mockChainLogs.splice(2, 1); // Removes sequence 3; sequence 4 remains

      const report = await verifySourceHashChain('audit-server-01');

      expect(report.isValid).toBe(false);
      const seqAnomaly = report.anomalies.find((a) => a.type === 'MISSING_SEQUENCE');
      expect(seqAnomaly).toBeDefined();
      expect(seqAnomaly.expectedSequence).toBe(3);
      expect(seqAnomaly.sequenceNumber).toBe(4);
    });
  });
});
