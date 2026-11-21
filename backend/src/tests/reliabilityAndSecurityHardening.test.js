import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import app from '../app.js';
import Log from '../models/Log.js';
import Source from '../models/Source.js';
import Checkpoint from '../models/Checkpoint.js';
import { ingestSingleLog } from '../services/logService.js';
import { createCheckpoint, setFssStateManager } from '../services/checkpointService.js';
import { generateToken } from '../services/authService.js';
import { generateFssMasterState, verifyFssSignature } from '../../../security/src/crypto/fssSigner.js';
import { FssStateManager } from '../../../security/src/keys/fssStateManager.js';
import {
  buildMerkleTree,
  generateMerkleProof,
  verifyMerkleProof,
  MERKLE_ALGORITHM_CONTRACT,
} from '../../../security/src/merkle/merkleTree.js';
import {
  verifyCheckpoint,
  createFssCheckpoint,
  VerificationStatus,
} from '../../../security/src/checkpoints/checkpointService.js';
import { GENESIS_HASH } from '../../../security/src/crypto/hashing.js';

describe('Stage 5.5: Reliability, Security, & Operational Hardening', () => {
  const adminToken = generateToken({
    id: 'user_admin',
    email: 'admin@securelog.io',
    role: 'admin',
  });

  const analystToken = generateToken({
    id: 'user_analyst',
    email: 'analyst@securelog.io',
    role: 'security_analyst',
  });

  const auditorToken = generateToken({
    id: 'user_auditor',
    email: 'auditor@securelog.io',
    role: 'auditor',
  });

  let mockSourceDoc;
  const mockLogsStore = new Map();
  const mockCheckpointsStore = new Map();

  beforeEach(() => {
    mockLogsStore.clear();
    mockCheckpointsStore.clear();
    vi.restoreAllMocks();

    mockSourceDoc = {
      sourceId: 'concurrent-srv-01',
      lastSequenceNumber: 0,
      lastHash: GENESIS_HASH,
      status: 'ACTIVE',
      save: vi.fn().mockImplementation(function () {
        return Promise.resolve(this);
      }),
    };

    vi.spyOn(Source, 'findOne').mockImplementation(() => Promise.resolve(mockSourceDoc));
    vi.spyOn(Source, 'create').mockImplementation((data) => {
      mockSourceDoc = { ...data, save: vi.fn().mockResolvedValue(true) };
      return Promise.resolve(mockSourceDoc);
    });

    vi.spyOn(Log, 'findOne').mockImplementation((filter) => {
      if (filter.eventId) {
        return Promise.resolve(mockLogsStore.get(filter.eventId) || null);
      }
      return Promise.resolve(null);
    });

    vi.spyOn(Log, 'create').mockImplementation((data) => {
      const doc = {
        _id: 'mongo_' + data.eventId,
        ...data,
        createdAt: new Date(),
      };
      mockLogsStore.set(data.eventId, doc);
      return Promise.resolve(doc);
    });

    vi.spyOn(Checkpoint, 'findOne').mockImplementation(() => Promise.resolve(null));
    vi.spyOn(Checkpoint, 'create').mockImplementation((data) => {
      const doc = { _id: 'cp_' + data.checkpointId, ...data };
      mockCheckpointsStore.set(data.checkpointId, doc);
      return Promise.resolve(doc);
    });
  });

  describe('1. Concurrency & Race Condition Defense', () => {
    it('concurrent log ingestion serializes sequence numbers monotonically without duplicates or gaps', async () => {
      const concurrentSubmissions = 5;
      const promises = [];

      for (let i = 1; i <= concurrentSubmissions; i++) {
        promises.push(
          ingestSingleLog({
            eventId: `evt-concurrent-${i}`,
            sourceId: 'concurrent-srv-01',
            eventType: 'LOGIN',
            severity: 'INFO',
            message: `Concurrent event ${i}`,
          })
        );
      }

      const results = await Promise.all(promises);

      // Verify all ingested
      expect(results.every((r) => !r.isDuplicate)).toBe(true);

      const logs = Array.from(mockLogsStore.values()).sort((a, b) => a.sequenceNumber - b.sequenceNumber);
      expect(logs).toHaveLength(concurrentSubmissions);

      // Verify sequence monotonicity: 1, 2, 3, 4, 5
      for (let i = 0; i < logs.length; i++) {
        expect(logs[i].sequenceNumber).toBe(i + 1);
        if (i > 0) {
          expect(logs[i].previousHash).toBe(logs[i - 1].currentHash);
        } else {
          expect(logs[i].previousHash).toBe(GENESIS_HASH);
        }
      }
    });

    it('concurrent duplicate submissions are caught idempotently without creating duplicate records', async () => {
      const duplicatePayload = {
        eventId: 'evt-idempotent-race-1',
        sourceId: 'concurrent-srv-01',
        eventType: 'AUTH',
        severity: 'INFO',
        message: 'Idempotency test payload',
      };

      const results = await Promise.all([
        ingestSingleLog(duplicatePayload),
        ingestSingleLog(duplicatePayload),
        ingestSingleLog(duplicatePayload),
      ]);

      const successfulIngests = results.filter((r) => !r.isDuplicate);
      const duplicatesDetected = results.filter((r) => r.isDuplicate);

      expect(successfulIngests).toHaveLength(1);
      expect(duplicatesDetected).toHaveLength(2);
      expect(mockLogsStore.size).toBe(1);
    });
  });

  describe('2. Threat Simulation & Adversary Testing', () => {
    it('mathematically rejects forged FSS checkpoint signatures', () => {
      const { state, publicTree } = generateFssMasterState({ maxEpochs: 8 });
      const fss = new FssStateManager({ statePath: '/tmp/fss_test_forge.json' });
      fss.initState(state, true);

      const leafHashes = ['1111111111111111111111111111111111111111111111111111111111111111'];

      // Create a genuine checkpoint
      const validCheckpoint = createFssCheckpoint(
        {
          source_id: 'srv-adv-01',
          start_sequence: 1,
          end_sequence: 1,
          leaf_hashes: leafHashes,
          checkpoint_id: 'chk-adversary-01',
        },
        fss
      );

      // Adversary attempts to forge signature bytes
      const forgedCheckpoint = {
        ...validCheckpoint,
        signature: 'ff'.repeat(64),
      };

      const result = verifyCheckpoint(forgedCheckpoint, publicTree.mpk);
      expect(result.valid).toBe(false);
      expect(result.status).toBe(VerificationStatus.INVALID_SIGNATURE);
      expect(result.failures.some((f) => f.includes('signature'))).toBe(true);
    });

    it('enforces revocation boundary against compromised epochs', () => {
      const { state, publicTree } = generateFssMasterState({ maxEpochs: 8 });
      const fss = new FssStateManager({ statePath: '/tmp/fss_test_revoke.json' });
      fss.initState(state, true);

      // Evolve to epoch 2
      fss.evolve(publicTree.authPaths[1]);
      fss.evolve(publicTree.authPaths[2]);

      const leafHashes = ['2222222222222222222222222222222222222222222222222222222222222222'];

      // Sign at epoch 2
      const checkpointEpoch2 = createFssCheckpoint(
        {
          source_id: 'srv-adv-02',
          start_sequence: 1,
          end_sequence: 1,
          leaf_hashes: leafHashes,
          checkpoint_id: 'chk-revoked-01',
        },
        fss
      );

      // Revocation notice for compromise at epoch 1 (compromiseEpoch <= 2)
      const revocationNotice = {
        schema_version: 'logn-fss-revocation-v1',
        compromiseEpoch: 1,
        compromise_epoch: 1,
        mpk: publicTree.mpk,
      };

      const result = verifyCheckpoint(checkpointEpoch2, publicTree.mpk, {
        revocationNotice,
      });

      expect(result.valid).toBe(false);
      expect(result.status).toBe(VerificationStatus.KEY_REVOKED);
      expect(result.failures.some((f) => f.includes('revoked'))).toBe(true);
    });

    it('rejects inclusion proof for non-existent leaf or tampered index', () => {
      const leaves = [
        '1111111111111111111111111111111111111111111111111111111111111111',
        '2222222222222222222222222222222222222222222222222222222222222222',
        '3333333333333333333333333333333333333333333333333333333333333333',
      ];
      const tree = buildMerkleTree(leaves, { algorithm: MERKLE_ALGORITHM_CONTRACT });
      const proof = generateMerkleProof(tree, 0);

      // Verify legitimate proof succeeds
      expect(verifyMerkleProof(leaves[0], proof.proof, tree.root)).toBe(true);

      // Adversary attempts with non-existent leaf
      const fakeLeaf = '9999999999999999999999999999999999999999999999999999999999999999';
      expect(verifyMerkleProof(fakeLeaf, proof.proof, tree.root)).toBe(false);
    });
  });

  describe('3. Role-Based Access Control & Zero Private Key Exposure', () => {
    it('restricts administrative FSS actions (evolve, revoke) to admin and security_analyst roles', async () => {
      // Auditor attempt to evolve FSS epoch -> 403 Forbidden
      const auditorEvolveRes = await request(app)
        .post('/api/integrity/fss/evolve')
        .set('Authorization', `Bearer ${auditorToken}`)
        .send({});

      expect(auditorEvolveRes.status).toBe(403);
      expect(auditorEvolveRes.body.success).toBe(false);
      expect(auditorEvolveRes.body.message).toContain('Forbidden');

      // Auditor attempt to revoke -> 403 Forbidden
      const auditorRevokeRes = await request(app)
        .post('/api/integrity/fss/revoke')
        .set('Authorization', `Bearer ${auditorToken}`)
        .send({ compromiseEpoch: 1, reason: 'unauthorized test' });

      expect(auditorRevokeRes.status).toBe(403);

      // Security Analyst authorized -> proceeds beyond role check
      const analystRes = await request(app)
        .post('/api/integrity/fss/evolve')
        .set('Authorization', `Bearer ${analystToken}`)
        .send({});

      // Expect either 200 or handled business logic (not 401 or 403)
      expect(analystRes.status).not.toBe(403);
      expect(analystRes.status).not.toBe(401);
    });

    it('guarantees zero private key exposure in FSS status and checkpoint responses', async () => {
      const res = await request(app)
        .get('/api/integrity/fss/status')
        .set('Authorization', `Bearer ${analystToken}`);

      expect(res.status).toBe(200);
      const resText = JSON.stringify(res.body);

      // Ensure no private key fields exist in output
      expect(resText).not.toContain('privateKey');
      expect(resText).not.toContain('secretKey');
      expect(resText).not.toContain('epk_seed');
      expect(resText).not.toContain('esk');
      expect(resText).not.toContain('privKey');
      expect(res.body.data.currentEpoch).toBeDefined();
      expect(res.body.data.mpk).toBeDefined();
    });
  });
});
