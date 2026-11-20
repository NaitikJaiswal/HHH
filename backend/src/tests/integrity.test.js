import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import app from '../app.js';
import { canonicalize } from '../utils/canonicalize.js';
import { generateLogHash } from '../utils/generateHash.js';
import { signData, verifySignature, getKeyPair } from '../utils/generateSignature.js';
import { verifySourceHashChain } from '../services/integrityService.js';
import { createCheckpoint, verifyCheckpointSignature } from '../services/checkpointService.js';
import { ingestSingleLog } from '../services/logService.js';
import { generateToken } from '../services/authService.js';
import Log from '../models/Log.js';
import Source from '../models/Source.js';
import Checkpoint from '../models/Checkpoint.js';

describe('Milestone 6: Ed25519 Signatures, Signed Checkpoints & Integrity Auditing', () => {
  const testAuthToken = generateToken({
    id: 'user_auditor_99',
    email: 'auditor@securelog.io',
    role: 'auditor',
  });

  describe('Ed25519 Digital Signatures', () => {
    it('1. Generates and verifies valid Ed25519 digital signature', () => {
      const payload = {
        checkpointId: 'chk-test-01',
        sourceId: 'server-alpha',
        lastSequenceNumber: 10,
        chainHeadHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        timestamp: '2026-11-20T10:00:00.000Z',
      };

      const signature = signData(payload);
      expect(signature).toBeDefined();
      expect(typeof signature).toBe('string');

      const isValid = verifySignature(payload, signature);
      expect(isValid).toBe(true);
    });

    it('2. Detects tampering: signature verification fails if payload was altered', () => {
      const originalPayload = {
        checkpointId: 'chk-test-02',
        sourceId: 'server-alpha',
        lastSequenceNumber: 5,
        chainHeadHash: 'aaaa1111222233334444555566667777888899990000aaaabbbbccccddddeeee',
        timestamp: '2026-11-20T10:00:00.000Z',
      };

      const signature = signData(originalPayload);

      // Malicious alteration: attacker tries to change the head hash to a forged one
      const tamperedPayload = {
        ...originalPayload,
        chainHeadHash: 'ffff00000000000000000000000000000000000000000000000000000000ffff',
      };

      const isValid = verifySignature(tamperedPayload, signature);
      expect(isValid).toBe(false);
    });
  });

  describe('Signed Checkpoint Generation and Cross-Verification', () => {
    let mockLogs = [];
    let mockCheckpoints = [];

    beforeEach(() => {
      vi.restoreAllMocks();
      mockLogs = [];
      mockCheckpoints = [];

      // Build a 3-record chain
      let prev = '0000000000000000000000000000000000000000000000000000000000000000';
      for (let seq = 1; seq <= 3; seq++) {
        const eventId = `evt-${seq}`;
        const sourceId = 'server-prod';
        const timestamp = new Date(`2026-11-20T10:0${seq}:00Z`);
        const message = `Authentic event ${seq}`;
        const currentHash = generateLogHash({
          eventId,
          sourceId,
          sequenceNumber: seq,
          timestamp,
          message,
          metadata: {},
          previousHash: prev,
        });

        mockLogs.push({
          eventId,
          sourceId,
          sequenceNumber: seq,
          timestamp,
          message,
          metadata: {},
          previousHash: prev,
          currentHash,
        });
        prev = currentHash;
      }

      // Checkpoint at sequence 3
      const keyPair = getKeyPair();
      const chkPayload = {
        checkpointId: 'chk-prod-3',
        sourceId: 'server-prod',
        lastSequenceNumber: 3,
        chainHeadHash: mockLogs[2].currentHash,
        timestamp: '2026-11-20T10:03:00.000Z',
      };
      const sig = signData(chkPayload);

      mockCheckpoints.push({
        ...chkPayload,
        signature: sig,
        publicKey: keyPair.publicKeyDer,
      });

      vi.spyOn(Log, 'find').mockImplementation(() => ({
        sort: vi.fn().mockReturnValue({
          lean: vi.fn().mockResolvedValue(JSON.parse(JSON.stringify(mockLogs))),
        }),
      }));

      vi.spyOn(Checkpoint, 'find').mockImplementation(() => ({
        sort: vi.fn().mockReturnValue({
          lean: vi.fn().mockResolvedValue(JSON.parse(JSON.stringify(mockCheckpoints))),
        }),
      }));
    });

    it('3. Successfully verifies valid log chain and corresponding signed checkpoint', async () => {
      const report = await verifySourceHashChain('server-prod');

      expect(report.isValid).toBe(true);
      expect(report.totalLogs).toBe(3);
      expect(report.totalCheckpoints).toBe(1);
      expect(report.anomalies).toHaveLength(0);
    });

    it('4. Detects forged or corrupted checkpoint signature (INVALID_CHECKPOINT_SIGNATURE)', async () => {
      // Corrupt the checkpoint signature
      mockCheckpoints[0].signature = 'bad' + mockCheckpoints[0].signature.slice(3);

      const report = await verifySourceHashChain('server-prod');

      expect(report.isValid).toBe(false);
      const sigAnomaly = report.anomalies.find((a) => a.type === 'INVALID_CHECKPOINT_SIGNATURE');
      expect(sigAnomaly).toBeDefined();
      expect(sigAnomaly.severity).toBe('critical');
    });

    it('5. Detects root compromise chain rewrite attack (CHECKPOINT_CHAIN_MISMATCH)', async () => {
      // Scenario: Attacker gains root on MongoDB server, rewrites history, and recalculates a valid hash chain
      // But the attacker CANNOT forge the previously signed checkpoint stored off-server!
      mockLogs[0].message = 'ROOT ATTACKER REWROTE EVENT 1';

      // Recalculate hash chain from seq 1 to 3 to make the chain internally mathematically consistent
      let prev = '0000000000000000000000000000000000000000000000000000000000000000';
      for (let i = 0; i < mockLogs.length; i++) {
        mockLogs[i].previousHash = prev;
        mockLogs[i].currentHash = generateLogHash(mockLogs[i]);
        prev = mockLogs[i].currentHash;
      }

      // Chain by itself would now look recalculated, BUT checkpoint cross-check catches it!
      const report = await verifySourceHashChain('server-prod');

      expect(report.isValid).toBe(false);
      const mismatchAnomaly = report.anomalies.find((a) => a.type === 'CHECKPOINT_CHAIN_MISMATCH');
      expect(mismatchAnomaly).toBeDefined();
      expect(mismatchAnomaly.message).toContain('Hash chain may have been rewritten by an attacker with root access');
    });
  });

  describe('Integrity REST APIs', () => {
    it('6. POST /api/integrity/verify triggers an audit and returns report', async () => {
      const res = await request(app)
        .post('/api/integrity/verify')
        .set('Authorization', `Bearer ${testAuthToken}`)
        .send({ sourceId: 'server-prod' });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty('isValid');
      expect(res.body.data).toHaveProperty('anomalies');
    });

    it('7. GET /api/integrity/status returns system-wide audit summary', async () => {
      vi.spyOn(Source, 'find').mockReturnValue({
        lean: vi.fn().mockResolvedValue([{ sourceId: 'src-1' }]),
      });

      const res = await request(app)
        .get('/api/integrity/status')
        .set('Authorization', `Bearer ${testAuthToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty('overallIntegrity');
    });
  });
});
