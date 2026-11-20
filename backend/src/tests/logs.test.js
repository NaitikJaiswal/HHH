import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import app from '../app.js';
import Log from '../models/Log.js';
import Source from '../models/Source.js';
import { generateToken } from '../services/authService.js';

describe('Milestone 4: Log Management & Ingestion APIs', () => {
  const mockLogs = new Map();
  const mockSources = new Map();

  const testAuthToken = generateToken({
    id: 'user_analyst_1',
    email: 'analyst@securelog.io',
    role: 'security_analyst',
  });

  const collectorApiKey = 'default_collector_secret_key';

  beforeEach(() => {
    mockLogs.clear();
    mockSources.clear();
    vi.restoreAllMocks();

    // Mock Log.findOne
    vi.spyOn(Log, 'findOne').mockImplementation((filter) => {
      if (filter.eventId) {
        return Promise.resolve(mockLogs.get(filter.eventId) || null);
      }
      return Promise.resolve(null);
    });

    // Mock Log.create
    vi.spyOn(Log, 'create').mockImplementation((data) => {
      const doc = {
        _id: 'mongo_' + Math.random().toString(36).substring(2, 9),
        ...data,
        createdAt: new Date().toISOString(),
      };
      mockLogs.set(doc.eventId, doc);
      return Promise.resolve(doc);
    });

    // Mock Log.find
    vi.spyOn(Log, 'find').mockImplementation((filter) => {
      let results = Array.from(mockLogs.values());
      if (filter.sourceId) {
        results = results.filter((l) => l.sourceId === filter.sourceId);
      }
      if (filter.eventType) {
        results = results.filter((l) => l.eventType === filter.eventType);
      }
      return {
        sort: vi.fn().mockReturnThis(),
        skip: vi.fn().mockReturnThis(),
        limit: vi.fn().mockReturnThis(),
        lean: vi.fn().mockResolvedValue(results),
      };
    });

    // Mock Log.countDocuments
    vi.spyOn(Log, 'countDocuments').mockImplementation((filter = {}) => {
      let count = mockLogs.size;
      if (filter.sourceId) {
        count = Array.from(mockLogs.values()).filter((l) => l.sourceId === filter.sourceId).length;
      }
      return Promise.resolve(count);
    });

    // Mock Log.aggregate
    vi.spyOn(Log, 'aggregate').mockResolvedValue([
      { _id: 'AUTH_SUCCESS', count: 5 },
      { _id: 'AUTH_FAILURE', count: 2 },
    ]);

    // Mock Source.findOne
    vi.spyOn(Source, 'findOne').mockImplementation((filter) => {
      if (filter.sourceId) {
        const src = mockSources.get(filter.sourceId);
        if (!src) return Promise.resolve(null);
        return Promise.resolve({
          ...src,
          save: vi.fn().mockResolvedValue(src),
        });
      }
      return Promise.resolve(null);
    });

    // Mock Source.create
    vi.spyOn(Source, 'create').mockImplementation((data) => {
      const src = {
        _id: 'src_' + Math.random().toString(36).substring(2, 9),
        ...data,
        save: vi.fn().mockResolvedValue(data),
      };
      mockSources.set(src.sourceId, src);
      return Promise.resolve(src);
    });
  });

  describe('Collector Ingestion Authentication', () => {
    it('1. Rejects log submission without API key or JWT (401)', async () => {
      const res = await request(app)
        .post('/api/logs')
        .send({
          eventId: 'evt-101',
          sourceId: 'srv-web-01',
          eventType: 'AUTH_FAILURE',
          message: 'Failed login attempt for root',
        });

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toContain('Collector authentication failed');
    });

    it('2. Accepts log submission with valid X-API-Key header', async () => {
      const res = await request(app)
        .post('/api/logs')
        .set('X-API-Key', collectorApiKey)
        .send({
          eventId: 'evt-102',
          sourceId: 'srv-web-01',
          eventType: 'AUTH_SUCCESS',
          message: 'User admin logged in from 192.168.1.10',
          timestamp: new Date().toISOString(),
        });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.acknowledged_ids).toContain('evt-102');
    });
  });

  describe('Log Ingestion & Idempotency', () => {
    it('3. Successfully ingests single log and maintains sequential numbering', async () => {
      const res1 = await request(app)
        .post('/api/logs')
        .set('X-API-Key', collectorApiKey)
        .send({
          eventId: 'evt-seq-1',
          sourceId: 'srv-db-01',
          eventType: 'SERVICE_START',
          message: 'PostgreSQL daemon started',
          timestamp: new Date().toISOString(),
        });

      expect(res1.status).toBe(201);
      expect(res1.body.data.log.sequenceNumber).toBe(1);
      expect(res1.body.data.log.previousHash).toBeDefined();

      const res2 = await request(app)
        .post('/api/logs')
        .set('X-API-Key', collectorApiKey)
        .send({
          eventId: 'evt-seq-2',
          sourceId: 'srv-db-01',
          eventType: 'SERVICE_READY',
          message: 'Database accepts connections on port 5432',
          timestamp: new Date().toISOString(),
        });

      expect(res2.status).toBe(201);
      expect(res2.body.data.log.sequenceNumber).toBe(2);
      expect(res2.body.data.log.previousHash).toBe(res1.body.data.log.currentHash);
    });

    it('4. Rejects duplicate event submissions idempotently without creating duplicate records', async () => {
      // First submission
      await request(app)
        .post('/api/logs')
        .set('X-API-Key', collectorApiKey)
        .send({
          eventId: 'evt-dup-check',
          sourceId: 'srv-app-01',
          eventType: 'PAYMENT_PROCESSED',
          message: 'Order #4092 completed',
          timestamp: new Date().toISOString(),
        });

      // Second identical submission
      const res = await request(app)
        .post('/api/logs')
        .set('X-API-Key', collectorApiKey)
        .send({
          eventId: 'evt-dup-check',
          sourceId: 'srv-app-01',
          eventType: 'PAYMENT_PROCESSED',
          message: 'Order #4092 completed',
          timestamp: new Date().toISOString(),
        });

      expect(res.status).toBe(201);
      expect(res.body.data.isDuplicate).toBe(true);
      expect(res.body.data.acknowledged_ids).toContain('evt-dup-check');
      // Verify store has only 1 record
      expect(mockLogs.size).toBe(1);
    });

    it('5. Successfully ingests Python collector batch format', async () => {
      const res = await request(app)
        .post('/api/logs')
        .set('Authorization', `Bearer ${collectorApiKey}`)
        .send({
          collector_id: 'logn-agent-linux-01',
          batch_size: 2,
          events: [
            {
              event_id: 'py-evt-1',
              source_id: 'linux-node-1',
              event_type: 'CRON_EXEC',
              message: 'Cron job run-parts finished',
              timestamp: new Date().toISOString(),
            },
            {
              event_id: 'py-evt-2',
              source_id: 'linux-node-1',
              event_type: 'SSHD_DISCONNECT',
              message: 'Session closed for user root',
              timestamp: new Date().toISOString(),
            },
          ],
        });

      expect(res.status).toBe(201);
      expect(res.body.data.acknowledged_ids).toEqual(['py-evt-1', 'py-evt-2']);
      expect(res.body.data.ingestedCount).toBe(2);
      expect(mockLogs.size).toBe(2);
    });
  });

  describe('Log Retrieval & Filtering', () => {
    beforeEach(async () => {
      // Seed two test logs
      mockLogs.set('evt-search-1', {
        eventId: 'evt-search-1',
        sourceId: 'srv-firewall',
        eventType: 'PORT_SCAN',
        message: 'TCP SYN flood detected',
        serverTimestamp: new Date(),
        sequenceNumber: 1,
      });
      mockLogs.set('evt-search-2', {
        eventId: 'evt-search-2',
        sourceId: 'srv-web',
        eventType: 'HTTP_404',
        message: 'Resource not found /admin.php',
        serverTimestamp: new Date(),
        sequenceNumber: 1,
      });
    });

    it('6. Query logs requires authentication (401 without JWT)', async () => {
      const res = await request(app).get('/api/logs');
      expect(res.status).toBe(401);
    });

    it('7. Query logs with filters returns paginated results', async () => {
      const res = await request(app)
        .get('/api/logs?sourceId=srv-firewall')
        .set('Authorization', `Bearer ${testAuthToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty('logs');
      expect(res.body.data).toHaveProperty('pagination');
      expect(res.body.data.logs.length).toBe(1);
      expect(res.body.data.logs[0].sourceId).toBe('srv-firewall');
    });

    it('8. Retrieve single log by eventId succeeds', async () => {
      const res = await request(app)
        .get('/api/logs/evt-search-1')
        .set('Authorization', `Bearer ${testAuthToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.eventId).toBe('evt-search-1');
      expect(res.body.data.eventType).toBe('PORT_SCAN');
    });

    it('9. Retrieve log statistics aggregation', async () => {
      const res = await request(app)
        .get('/api/logs/stats')
        .set('Authorization', `Bearer ${testAuthToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty('totalLogs');
      expect(res.body.data).toHaveProperty('byEventType');
    });
  });
});
