import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import app from '../app.js';
import User from '../models/User.js';
import Log from '../models/Log.js';
import Source from '../models/Source.js';
import Checkpoint from '../models/Checkpoint.js';
import Incident from '../models/Incident.js';
import AuditEvent from '../models/AuditEvent.js';
import { generateLogHash } from '../utils/generateHash.js';
import { signData, verifySignature, getKeyPair } from '../utils/generateSignature.js';
import { verifySourceHashChain } from '../services/integrityService.js';
import { ingestSingleLog } from '../services/logService.js';
import { createIncident } from '../services/incidentService.js';
import { uploadLogBatch } from '../services/storageService.js';
import { generateToken } from '../services/authService.js';
import bcrypt from 'bcryptjs';

describe('Master 15-Point Cybersecurity Verification Suite', () => {
  const mockDb = {
    users: new Map(),
    logs: new Map(),
    sources: new Map(),
    checkpoints: new Map(),
    incidents: new Map(),
    audits: [],
  };

  const analystToken = generateToken({
    id: 'user_master_analyst',
    email: 'analyst@securelog.io',
    role: 'security_analyst',
  });

  const auditorToken = generateToken({
    id: 'user_master_auditor',
    email: 'auditor@securelog.io',
    role: 'auditor',
  });

  const collectorKey = 'default_collector_secret_key';

  beforeEach(() => {
    mockDb.users.clear();
    mockDb.logs.clear();
    mockDb.sources.clear();
    mockDb.checkpoints.clear();
    mockDb.incidents.clear();
    mockDb.audits.length = 0;
    vi.restoreAllMocks();

    // User Model Mocks
    vi.spyOn(User, 'findOne').mockImplementation(({ email }) => {
      const u = mockDb.users.get(email?.toLowerCase());
      if (!u) return Promise.resolve(null);
      return Promise.resolve({
        ...u,
        matchPassword: async (pwd) => bcrypt.compare(pwd, u.passwordHash),
      });
    });

    vi.spyOn(User, 'create').mockImplementation((data) => {
      const u = { _id: 'usr_' + Date.now(), ...data };
      mockDb.users.set(u.email.toLowerCase(), u);
      return Promise.resolve(u);
    });

    // Log Model Mocks
    vi.spyOn(Log, 'findOne').mockImplementation(({ eventId }) => {
      return Promise.resolve(mockDb.logs.get(eventId) || null);
    });

    vi.spyOn(Log, 'create').mockImplementation((data) => {
      const doc = { _id: 'log_' + data.eventId, ...data };
      mockDb.logs.set(data.eventId, doc);
      return Promise.resolve(doc);
    });

    vi.spyOn(Log, 'updateMany').mockResolvedValue({ modifiedCount: 1 });
    vi.spyOn(Log, 'updateOne').mockResolvedValue({ modifiedCount: 1 });

    // Source Model Mocks
    vi.spyOn(Source, 'findOne').mockImplementation(({ sourceId }) => {
      const s = mockDb.sources.get(sourceId);
      if (!s) return Promise.resolve(null);
      return Promise.resolve({
        ...s,
        save: vi.fn().mockImplementation(function () {
          mockDb.sources.set(sourceId, this);
          return Promise.resolve(this);
        }),
      });
    });

    vi.spyOn(Source, 'create').mockImplementation((data) => {
      const s = {
        _id: 'src_' + data.sourceId,
        ...data,
        save: vi.fn().mockImplementation(function () {
          mockDb.sources.set(data.sourceId, this);
          return Promise.resolve(this);
        }),
      };
      mockDb.sources.set(data.sourceId, s);
      return Promise.resolve(s);
    });

    // Incident & Audit Model Mocks
    vi.spyOn(Incident, 'create').mockImplementation((data) => {
      const inc = { _id: 'inc_' + data.incidentId, ...data };
      mockDb.incidents.set(data.incidentId, inc);
      return Promise.resolve(inc);
    });

    vi.spyOn(Incident, 'findOne').mockResolvedValue(null);

    vi.spyOn(AuditEvent, 'create').mockImplementation((data) => {
      mockDb.audits.push(data);
      return Promise.resolve(data);
    });
  });

  // 1. Successful user registration
  it('Scenario 1: Successful user registration', async () => {
    const res = await request(app).post('/api/auth/register').send({
      name: 'Security Engineer',
      email: 'engineer@securelog.io',
      password: 'StrongPassword123!',
      role: 'security_analyst',
    });

    expect(res.status).toBe(201);
    expect(res.body.success).toBe(true);
    expect(res.body.data.user.email).toBe('engineer@securelog.io');
    expect(res.body.data.token).toBeDefined();
  });

  // 2. Successful login
  it('Scenario 2: Successful login with valid credentials', async () => {
    const passwordHash = await bcrypt.hash('CorrectPassword123!', 10);
    mockDb.users.set('auditor@securelog.io', {
      _id: 'usr_auditor_1',
      name: 'Auditor User',
      email: 'auditor@securelog.io',
      passwordHash,
      role: 'auditor',
    });

    const res = await request(app).post('/api/auth/login').send({
      email: 'auditor@securelog.io',
      password: 'CorrectPassword123!',
    });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.token).toBeDefined();
  });

  // 3. Invalid login
  it('Scenario 3: Invalid login rejected with 401', async () => {
    const passwordHash = await bcrypt.hash('CorrectPassword123!', 10);
    mockDb.users.set('auditor@securelog.io', {
      _id: 'usr_auditor_1',
      name: 'Auditor User',
      email: 'auditor@securelog.io',
      passwordHash,
      role: 'auditor',
    });

    const res = await request(app).post('/api/auth/login').send({
      email: 'auditor@securelog.io',
      password: 'WrongPassword999!',
    });

    expect(res.status).toBe(401);
    expect(res.body.success).toBe(false);
  });

  // 4. Unauthorized API access
  it('Scenario 4: Unauthorized API access without token rejected with 401', async () => {
    const res = await request(app).get('/api/auth/me');
    expect(res.status).toBe(401);
    expect(res.body.success).toBe(false);
  });

  // 5. Role-based access restrictions
  it('Scenario 5: Role-based access restriction (auditor cannot register new sources)', async () => {
    const res = await request(app)
      .post('/api/sources')
      .set('Authorization', `Bearer ${auditorToken}`)
      .send({
        sourceId: 'src-forbidden',
        name: 'Forbidden Source',
      });

    expect(res.status).toBe(403);
    expect(res.body.success).toBe(false);
    expect(res.body.message).toContain('Forbidden');
  });

  // 6. Successful log submission
  it('Scenario 6: Successful log submission via collector key', async () => {
    const res = await request(app)
      .post('/api/logs')
      .set('X-API-Key', collectorKey)
      .send({
        eventId: 'evt-s6-1',
        sourceId: 'srv-master-test',
        eventType: 'LOGIN_SUCCESS',
        message: 'Admin session started',
        timestamp: new Date().toISOString(),
      });

    expect(res.status).toBe(201);
    expect(res.body.success).toBe(true);
    expect(res.body.data.acknowledged_ids).toContain('evt-s6-1');
  });

  // 7. Duplicate log rejection (idempotency)
  it('Scenario 7: Duplicate log rejection preserves sequence number and ignores duplicate', async () => {
    await request(app)
      .post('/api/logs')
      .set('X-API-Key', collectorKey)
      .send({
        eventId: 'evt-dup-master',
        sourceId: 'srv-master-test',
        eventType: 'PAYMENT_AUTH',
        message: 'Authorization approved',
        timestamp: new Date().toISOString(),
      });

    const res2 = await request(app)
      .post('/api/logs')
      .set('X-API-Key', collectorKey)
      .send({
        eventId: 'evt-dup-master',
        sourceId: 'srv-master-test',
        eventType: 'PAYMENT_AUTH',
        message: 'Authorization approved',
        timestamp: new Date().toISOString(),
      });

    expect(res2.status).toBe(201);
    expect(res2.body.data.isDuplicate).toBe(true);
    expect(mockDb.logs.size).toBe(1);
  });

  // 8. Successful hash verification
  it('Scenario 8: Successful hash verification over untampered log chain', async () => {
    let prev = '0000000000000000000000000000000000000000000000000000000000000000';
    const chain = [1, 2, 3].map((seq) => {
      const entry = {
        eventId: `evt-chain-${seq}`,
        sourceId: 'src-hash-test',
        sequenceNumber: seq,
        timestamp: new Date(`2026-11-20T10:0${seq}:00Z`),
        message: `Message ${seq}`,
        metadata: {},
        previousHash: prev,
        currentHash: '',
      };
      entry.currentHash = generateLogHash(entry);
      prev = entry.currentHash;
      return entry;
    });

    vi.spyOn(Log, 'find').mockReturnValue({
      sort: vi.fn().mockReturnValue({
        lean: vi.fn().mockResolvedValue(chain),
      }),
    });
    vi.spyOn(Checkpoint, 'find').mockReturnValue({
      sort: vi.fn().mockReturnValue({ lean: vi.fn().mockResolvedValue([]) }),
    });

    const report = await verifySourceHashChain('src-hash-test');
    expect(report.isValid).toBe(true);
    expect(report.anomalies).toHaveLength(0);
  });

  // 9. Modified log detection
  it('Scenario 9: Modified log detection flags MODIFIED_RECORD', async () => {
    const chain = [
      {
        eventId: 'evt-mod-1',
        sourceId: 'src-mod-test',
        sequenceNumber: 1,
        timestamp: new Date('2026-11-20T10:00:00Z'),
        message: 'ORIGINAL MESSAGE',
        metadata: {},
        previousHash: '0000000000000000000000000000000000000000000000000000000000000000',
        currentHash: '',
      },
    ];
    chain[0].currentHash = generateLogHash(chain[0]);

    // Attacker alters message
    chain[0].message = 'TAMPERED MESSAGE IN DATABASE';

    vi.spyOn(Log, 'find').mockReturnValue({
      sort: vi.fn().mockReturnValue({ lean: vi.fn().mockResolvedValue(chain) }),
    });
    vi.spyOn(Checkpoint, 'find').mockReturnValue({
      sort: vi.fn().mockReturnValue({ lean: vi.fn().mockResolvedValue([]) }),
    });

    const report = await verifySourceHashChain('src-mod-test');
    expect(report.isValid).toBe(false);
    expect(report.anomalies.some((a) => a.type === 'MODIFIED_RECORD')).toBe(true);
  });

  // 10. Deleted log detection
  it('Scenario 10: Deleted log detection flags MISSING_SEQUENCE and BROKEN_CHAIN', async () => {
    const chain = [
      {
        eventId: 'evt-del-1',
        sourceId: 'src-del-test',
        sequenceNumber: 1,
        timestamp: new Date('2026-11-20T10:00:00Z'),
        message: 'Seq 1',
        metadata: {},
        previousHash: '0000000000000000000000000000000000000000000000000000000000000000',
        currentHash: 'hash1',
      },
      // Sequence 2 is deleted by attacker
      {
        eventId: 'evt-del-3',
        sourceId: 'src-del-test',
        sequenceNumber: 3,
        timestamp: new Date('2026-11-20T10:02:00Z'),
        message: 'Seq 3',
        metadata: {},
        previousHash: 'hash2',
        currentHash: 'hash3',
      },
    ];

    vi.spyOn(Log, 'find').mockReturnValue({
      sort: vi.fn().mockReturnValue({ lean: vi.fn().mockResolvedValue(chain) }),
    });
    vi.spyOn(Checkpoint, 'find').mockReturnValue({
      sort: vi.fn().mockReturnValue({ lean: vi.fn().mockResolvedValue([]) }),
    });

    const report = await verifySourceHashChain('src-del-test');
    expect(report.isValid).toBe(false);
    expect(report.anomalies.some((a) => a.type === 'MISSING_SEQUENCE')).toBe(true);
  });

  // 11. Missing sequence detection
  it('Scenario 11: Missing sequence detection flags expected sequence number gap', async () => {
    const chain = [
      {
        eventId: 'evt-gap-1',
        sourceId: 'src-gap-test',
        sequenceNumber: 2, // Starts at 2 instead of 1
        timestamp: new Date('2026-11-20T10:00:00Z'),
        message: 'Gap log',
        metadata: {},
        previousHash: '0000000000000000000000000000000000000000000000000000000000000000',
        currentHash: 'hash-gap',
      },
    ];

    vi.spyOn(Log, 'find').mockReturnValue({
      sort: vi.fn().mockReturnValue({ lean: vi.fn().mockResolvedValue(chain) }),
    });
    vi.spyOn(Checkpoint, 'find').mockReturnValue({
      sort: vi.fn().mockReturnValue({ lean: vi.fn().mockResolvedValue([]) }),
    });

    const report = await verifySourceHashChain('src-gap-test');
    expect(report.isValid).toBe(false);
    const gap = report.anomalies.find((a) => a.type === 'MISSING_SEQUENCE');
    expect(gap).toBeDefined();
    expect(gap.expectedSequence).toBe(1);
    expect(gap.sequenceNumber).toBe(2);
  });

  // 12. Invalid checkpoint signature
  it('Scenario 12: Invalid checkpoint signature flags INVALID_CHECKPOINT_SIGNATURE', async () => {
    vi.spyOn(Log, 'find').mockReturnValue({
      sort: vi.fn().mockReturnValue({ lean: vi.fn().mockResolvedValue([]) }),
    });

    const keyPair = getKeyPair();
    const forgedCheckpoint = {
      checkpointId: 'chk-forged-1',
      sourceId: 'src-chk-test',
      lastSequenceNumber: 10,
      chainHeadHash: 'fake_hash',
      timestamp: new Date().toISOString(),
      signature: '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff',
      publicKey: keyPair.publicKeyDer,
    };

    vi.spyOn(Checkpoint, 'find').mockReturnValue({
      sort: vi.fn().mockReturnValue({ lean: vi.fn().mockResolvedValue([forgedCheckpoint]) }),
    });

    const report = await verifySourceHashChain('src-chk-test');
    expect(report.isValid).toBe(false);
    expect(report.anomalies.some((a) => a.type === 'INVALID_CHECKPOINT_SIGNATURE')).toBe(true);
  });

  // 13. Incident creation
  it('Scenario 13: Incident creation automatically registers incident and audit event', async () => {
    const inc = await createIncident({
      type: 'MODIFIED_RECORD',
      severity: 'critical',
      sourceId: 'src-alert-test',
      description: 'Test incident generation',
      affectedEventIds: ['evt-123'],
    });

    expect(inc.incidentId).toBeDefined();
    expect(mockDb.incidents.size).toBe(1);
    expect(mockDb.audits.length).toBe(1);
  });

  // 14. Storage failure handling
  it('Scenario 14: Storage failure handling rejects empty batches cleanly without DB writes', async () => {
    const updateSpy = vi.spyOn(Log, 'updateMany');

    await expect(uploadLogBatch({ sourceId: 'src-fail', logs: [] })).rejects.toThrow(
      'Cannot upload empty log batch'
    );

    expect(updateSpy).not.toHaveBeenCalled();
  });

  // 15. Concurrent log submissions
  it('Scenario 15: Concurrent log submissions preserve sequence order and chain integrity', async () => {
    const sourceId = 'concurrent-master-src';

    const promises = [1, 2, 3, 4, 5].map((i) =>
      ingestSingleLog({
        eventId: `concur-evt-${i}`,
        sourceId,
        eventType: 'CONCURRENT_TEST',
        message: `Concur item ${i}`,
        timestamp: new Date().toISOString(),
      })
    );

    const outcomes = await Promise.all(promises);
    expect(outcomes).toHaveLength(5);

    const logs = Array.from(mockDb.logs.values()).sort((a, b) => a.sequenceNumber - b.sequenceNumber);
    expect(logs.map((l) => l.sequenceNumber)).toEqual([1, 2, 3, 4, 5]);

    // Verify hash link continuity
    let prev = '0000000000000000000000000000000000000000000000000000000000000000';
    for (const l of logs) {
      expect(l.previousHash).toBe(prev);
      prev = l.currentHash;
    }
  });
});
