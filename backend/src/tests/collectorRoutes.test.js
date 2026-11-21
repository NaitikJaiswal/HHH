import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import app from '../app.js';
import Log from '../models/Log.js';
import Source from '../models/Source.js';

describe('Phase 5.1 Route Compatibility - Collector & v1 API Aliases', () => {
  const collectorKey = 'default_collector_secret_key';

  beforeEach(() => {
    vi.restoreAllMocks();

    vi.spyOn(Log, 'findOne').mockResolvedValue(null);
    vi.spyOn(Log, 'create').mockImplementation((data) =>
      Promise.resolve({ ...data, _id: 'log_' + data.eventId, createdAt: new Date() })
    );

    vi.spyOn(Source, 'findOne').mockResolvedValue({
      sourceId: 'test-src-route',
      lastSequenceNumber: 0,
      lastHash: '0000000000000000000000000000000000000000000000000000000000000000',
      save: vi.fn().mockResolvedValue(true),
    });

    vi.spyOn(Source, 'create').mockImplementation((data) =>
      Promise.resolve({ ...data, _id: 'src_route', save: vi.fn().mockResolvedValue(true) })
    );
  });

  describe('Log Ingestion Route Compatibility', () => {
    it('1. Successfully ingests log batch via /api/v1/logs/ingest', async () => {
      const payload = {
        collector_id: 'collector-agent-01',
        batch_size: 2,
        events: [
          {
            event_id: 'evt-alias-1',
            event_time: '2026-11-20T10:00:00Z',
            event_type: 'AUTH',
            severity: 'INFO',
            message: 'Alias event 1',
            source_id: 'test-src-route',
          },
          {
            event_id: 'evt-alias-2',
            event_time: '2026-11-20T10:00:01Z',
            event_type: 'AUTH',
            severity: 'INFO',
            message: 'Alias event 2',
            source_id: 'test-src-route',
          },
        ],
      };

      const res = await request(app)
        .post('/api/v1/logs/ingest')
        .set('X-Collector-Key', collectorKey)
        .send(payload);

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.acknowledged_ids).toEqual(['evt-alias-1', 'evt-alias-2']);
      expect(res.body.data.acknowledged_ids).toEqual(['evt-alias-1', 'evt-alias-2']);
    });

    it('2. Successfully ingests single log via /api/logs/ingest and /api/logs', async () => {
      const payload = {
        event_id: 'evt-single-alias-1',
        event_time: '2026-11-20T10:05:00Z',
        event_type: 'SYSTEM',
        severity: 'INFO',
        message: 'Single log alias test',
        source_id: 'test-src-route',
      };

      const res1 = await request(app)
        .post('/api/logs/ingest')
        .set('X-Collector-Key', collectorKey)
        .send(payload);

      expect(res1.status).toBe(201);
      expect(res1.body.success).toBe(true);
      expect(res1.body.acknowledged_ids).toEqual(['evt-single-alias-1']);

      const res2 = await request(app)
        .post('/api/logs')
        .set('X-Collector-Key', collectorKey)
        .send({ ...payload, event_id: 'evt-single-alias-2' });

      expect(res2.status).toBe(201);
      expect(res2.body.acknowledged_ids).toEqual(['evt-single-alias-2']);
    });
  });

  describe('Collector Heartbeat Route Compatibility', () => {
    it('3. Successfully receives heartbeat via /api/v1/collectors/heartbeat', async () => {
      const heartbeatPayload = {
        collector_id: 'test-collector-hb',
        host_id: 'host-agent-alpha',
        status: 'ACTIVE',
        last_delivered_sequence: 120,
      };

      const res = await request(app)
        .post('/api/v1/collectors/heartbeat')
        .set('X-Collector-Key', collectorKey)
        .send(heartbeatPayload);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.message).toBe('Heartbeat acknowledged');
      expect(res.body.data.status).toBe('ACTIVE');
    });

    it('4. Successfully receives heartbeat via /api/sources/heartbeat', async () => {
      const heartbeatPayload = {
        collector_id: 'test-collector-legacy',
        status: 'ACTIVE',
        last_delivered_sequence: 250,
      };

      const res = await request(app)
        .post('/api/sources/heartbeat')
        .set('X-Collector-Key', collectorKey)
        .send(heartbeatPayload);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.message).toBe('Heartbeat acknowledged');
    });

    it('5. Rejects unauthorized collector access with 401', async () => {
      const res = await request(app)
        .post('/api/v1/collectors/heartbeat')
        .send({ collector_id: 'unauthorized-collector' });

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });
  });
});
