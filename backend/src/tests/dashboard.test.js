import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import app from '../app.js';
import Log from '../models/Log.js';
import Source from '../models/Source.js';
import Incident from '../models/Incident.js';
import Checkpoint from '../models/Checkpoint.js';
import { generateToken } from '../services/authService.js';

describe('Milestone 9: Dashboard APIs, Activity Feeds & Source Registry', () => {
  const mockSources = new Map();

  const analystToken = generateToken({
    id: 'user_analyst_dash',
    email: 'analyst@securelog.io',
    role: 'security_analyst',
  });

  const collectorKey = 'default_collector_secret_key';

  beforeEach(() => {
    mockSources.clear();
    vi.restoreAllMocks();

    // Mock Log queries
    vi.spyOn(Log, 'countDocuments').mockResolvedValue(128);
    vi.spyOn(Log, 'aggregate').mockResolvedValue([
      { _id: 'AUTH_SUCCESS', count: 90 },
      { _id: 'AUTH_FAILURE', count: 38 },
    ]);
    vi.spyOn(Log, 'find').mockReturnValue({
      sort: vi.fn().mockReturnThis(),
      limit: vi.fn().mockReturnThis(),
      select: vi.fn().mockReturnThis(),
      lean: vi.fn().mockResolvedValue([
        {
          eventId: 'evt-dash-1',
          sourceId: 'src-1',
          eventType: 'AUTH_SUCCESS',
          message: 'User login from 10.0.0.1',
          serverTimestamp: new Date().toISOString(),
          verificationStatus: 'VERIFIED',
        },
      ]),
    });

    // Mock Incident queries
    vi.spyOn(Incident, 'countDocuments').mockImplementation((filter) => {
      if (filter?.severity === 'critical') return Promise.resolve(0);
      return Promise.resolve(2);
    });
    vi.spyOn(Incident, 'aggregate').mockResolvedValue([
      { _id: 'medium', count: 2 },
    ]);
    vi.spyOn(Incident, 'find').mockReturnValue({
      sort: vi.fn().mockReturnThis(),
      limit: vi.fn().mockReturnThis(),
      select: vi.fn().mockReturnThis(),
      lean: vi.fn().mockResolvedValue([
        {
          incidentId: 'inc-dash-1',
          type: 'COLLECTOR_DISCONNECTED',
          severity: 'medium',
          sourceId: 'src-stalled',
          description: 'Collector stalled',
          detectedAt: new Date().toISOString(),
          status: 'OPEN',
        },
      ]),
    });

    // Mock Checkpoint queries
    vi.spyOn(Checkpoint, 'countDocuments').mockResolvedValue(15);
    vi.spyOn(Checkpoint, 'find').mockReturnValue({
      sort: vi.fn().mockReturnThis(),
      limit: vi.fn().mockReturnThis(),
      select: vi.fn().mockReturnThis(),
      lean: vi.fn().mockResolvedValue([
        {
          checkpointId: 'chk-dash-1',
          sourceId: 'src-1',
          lastSequenceNumber: 50,
          createdAt: new Date().toISOString(),
          status: 'VALID',
        },
      ]),
    });

    // Mock Source queries
    vi.spyOn(Source, 'countDocuments').mockImplementation((filter) => {
      return Promise.resolve(filter?.status === 'ACTIVE' ? 3 : 4);
    });

    vi.spyOn(Source, 'findOne').mockImplementation((filter) => {
      const src = mockSources.get(filter.sourceId);
      if (!src) return Promise.resolve(null);
      return Promise.resolve({
        ...src,
        save: vi.fn().mockImplementation(function () {
          mockSources.set(src.sourceId, this);
          return Promise.resolve(this);
        }),
      });
    });

    vi.spyOn(Source, 'create').mockImplementation((data) => {
      const doc = {
        _id: 'src_doc_' + data.sourceId,
        ...data,
        save: vi.fn().mockResolvedValue(data),
      };
      mockSources.set(data.sourceId, doc);
      return Promise.resolve(doc);
    });

    vi.spyOn(Source, 'find').mockReturnValue({
      select: vi.fn().mockReturnThis(),
      sort: vi.fn().mockReturnThis(),
      lean: vi.fn().mockImplementation(() => Promise.resolve(Array.from(mockSources.values()))),
    });
  });

  describe('Dashboard Analytics (GET /api/dashboard/stats & /activity)', () => {
    it('1. Rejects unauthenticated request to /api/dashboard/stats (401)', async () => {
      const res = await request(app).get('/api/dashboard/stats');
      expect(res.status).toBe(401);
    });

    it('2. Returns aggregated real MongoDB-backed stats to authenticated frontend', async () => {
      const res = await request(app)
        .get('/api/dashboard/stats')
        .set('Authorization', `Bearer ${analystToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.totalLogs).toBe(128);
      expect(res.body.data.totalSources).toBe(4);
      expect(res.body.data.activeSources).toBe(3);
      expect(res.body.data.openIncidents).toBe(2);
      expect(res.body.data.totalCheckpoints).toBe(15);
      expect(res.body.data).toHaveProperty('storageMode');
      expect(res.body.data).toHaveProperty('systemStatus');
      expect(res.body.data.byEventType).toHaveLength(2);
    });

    it('3. Returns combined recent activity timeline feed', async () => {
      const res = await request(app)
        .get('/api/dashboard/activity?limit=10')
        .set('Authorization', `Bearer ${analystToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty('activities');
      expect(res.body.data.activities.length).toBeGreaterThan(0);

      // Check structure of activity items
      const item = res.body.data.activities[0];
      expect(item).toHaveProperty('id');
      expect(item).toHaveProperty('category');
      expect(item).toHaveProperty('timestamp');
    });
  });

  describe('Source Registry & Telemetry (POST & GET /api/sources)', () => {
    it('4. Successfully registers new log source and generates an API key', async () => {
      const res = await request(app)
        .post('/api/sources')
        .set('Authorization', `Bearer ${analystToken}`)
        .send({
          sourceId: 'k8s-ingress-controller',
          name: 'Kubernetes Ingress Controller',
          sourceType: 'cloud',
        });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.sourceId).toBe('k8s-ingress-controller');
      expect(res.body.data.apiKey).toBeDefined();
      expect(res.body.data.apiKey).toMatch(/^sec_/);
    });

    it('5. Lists registered sources for management dashboard', async () => {
      mockSources.set('src-101', {
        sourceId: 'src-101',
        name: 'Database Node Alpha',
        sourceType: 'application',
        status: 'ACTIVE',
      });

      const res = await request(app)
        .get('/api/sources')
        .set('Authorization', `Bearer ${analystToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.sources.length).toBe(1);
      expect(res.body.data.sources[0].sourceId).toBe('src-101');
    });

    it('6. Collector emits heartbeat telemetry and receives 200 acknowledgment', async () => {
      mockSources.set('srv-node-1', {
        sourceId: 'srv-node-1',
        name: 'Node 1',
        status: 'ACTIVE',
        lastSequenceNumber: 10,
      });

      const res = await request(app)
        .post('/api/sources/srv-node-1/heartbeat')
        .set('X-API-Key', collectorKey)
        .send({
          status: 'HEALTHY',
          last_delivered_sequence: 15,
          pending_events_count: 0,
          uptime_seconds: 4500,
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.sourceId).toBe('srv-node-1');
      expect(res.body.data.status).toBe('ACTIVE');
    });
  });
});
