import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import app from '../app.js';
import Incident from '../models/Incident.js';
import AuditEvent from '../models/AuditEvent.js';
import Source from '../models/Source.js';
import { createIncident, checkCollectorHeartbeats } from '../services/incidentService.js';
import { generateToken } from '../services/authService.js';

describe('Milestone 8: Tamper Detection, Incidents & Heartbeat Monitoring', () => {
  const mockIncidents = new Map();
  const mockAuditEvents = [];
  const mockSources = new Map();

  const analystToken = generateToken({
    id: 'user_analyst_2',
    email: 'analyst@securelog.io',
    role: 'security_analyst',
  });

  beforeEach(() => {
    mockIncidents.clear();
    mockAuditEvents.length = 0;
    mockSources.clear();
    vi.restoreAllMocks();

    vi.spyOn(Incident, 'findOne').mockImplementation((filter) => {
      for (const inc of mockIncidents.values()) {
        if (filter.incidentId && inc.incidentId === filter.incidentId) {
          return Promise.resolve({
            ...inc,
            save: vi.fn().mockImplementation(function () {
              mockIncidents.set(inc.incidentId, this);
              return Promise.resolve(this);
            }),
          });
        }
        if (filter.sourceId && inc.sourceId === filter.sourceId && filter.type && inc.type === filter.type) {
          return Promise.resolve({
            ...inc,
            save: vi.fn().mockImplementation(function () {
              mockIncidents.set(inc.incidentId, this);
              return Promise.resolve(this);
            }),
          });
        }
      }
      return Promise.resolve(null);
    });

    vi.spyOn(Incident, 'create').mockImplementation((data) => {
      const doc = {
        _id: 'mongo_' + data.incidentId,
        ...data,
        save: vi.fn().mockImplementation(function () {
          mockIncidents.set(data.incidentId, this);
          return Promise.resolve(this);
        }),
      };
      mockIncidents.set(data.incidentId, doc);
      return Promise.resolve(doc);
    });

    vi.spyOn(Incident, 'find').mockReturnValue({
      sort: vi.fn().mockReturnThis(),
      skip: vi.fn().mockReturnThis(),
      limit: vi.fn().mockReturnThis(),
      lean: vi.fn().mockImplementation(() => Promise.resolve(Array.from(mockIncidents.values()))),
    });

    vi.spyOn(Incident, 'countDocuments').mockImplementation(() => Promise.resolve(mockIncidents.size));

    vi.spyOn(AuditEvent, 'create').mockImplementation((data) => {
      mockAuditEvents.push(data);
      return Promise.resolve(data);
    });

    vi.spyOn(Source, 'find').mockReturnValue({
      lean: vi.fn().mockImplementation(() => Promise.resolve(Array.from(mockSources.values()))),
    });

    vi.spyOn(Source, 'updateOne').mockResolvedValue({ modifiedCount: 1 });
  });

  describe('Automated Incident Creation & Audit Trail', () => {
    it('1. Creates security incident with assigned severity and logs AuditEvent', async () => {
      const incident = await createIncident({
        type: 'MODIFIED_RECORD',
        severity: 'critical',
        sourceId: 'srv-finance-01',
        description: 'SHA-256 mismatch detected on financial ledger event',
        affectedEventIds: ['evt-fin-99'],
      });

      expect(incident.incidentId).toBeDefined();
      expect(incident.severity).toBe('critical');
      expect(incident.type).toBe('MODIFIED_RECORD');
      expect(incident.status).toBe('OPEN');

      // Verify AuditEvent was logged
      expect(mockAuditEvents).toHaveLength(1);
      expect(mockAuditEvents[0].action).toBe('INCIDENT_CREATED');
      expect(mockAuditEvents[0].resource).toContain(incident.incidentId);
    });

    it('2. De-duplicates repeated open incidents for same source and type', async () => {
      const inc1 = await createIncident({
        type: 'BROKEN_CHAIN',
        severity: 'critical',
        sourceId: 'srv-db-01',
        description: 'First detection of broken chain',
        affectedEventIds: ['evt-1'],
      });

      const inc2 = await createIncident({
        type: 'BROKEN_CHAIN',
        severity: 'critical',
        sourceId: 'srv-db-01',
        description: 'Second detection of broken chain',
        affectedEventIds: ['evt-2'],
      });

      // Should update the existing incident rather than creating two separate records
      expect(inc1.incidentId).toBe(inc2.incidentId);
      expect(inc2.affectedEventIds).toContain('evt-1');
      expect(inc2.affectedEventIds).toContain('evt-2');
    });
  });

  describe('Collector Heartbeat Monitoring', () => {
    it('3. Detects dead/interrupted collector and triggers high-severity COLLECTOR_DISCONNECTED incident', async () => {
      // Seed an inactive source with heartbeat older than 5 minutes
      mockSources.set('srv-stalled-node', {
        _id: 'src_stalled',
        sourceId: 'srv-stalled-node',
        name: 'Stalled Production Node',
        lastHeartbeat: new Date(Date.now() - 10 * 60 * 1000), // 10 minutes ago
        status: 'ACTIVE',
      });

      const result = await checkCollectorHeartbeats(2); // 2 minute threshold

      expect(result.disconnectedCount).toBe(1);
      expect(result.disconnectedSources).toContain('srv-stalled-node');

      // Verify incident was created
      const incidents = Array.from(mockIncidents.values());
      const disconnectedIncident = incidents.find((i) => i.type === 'COLLECTOR_DISCONNECTED');
      expect(disconnectedIncident).toBeDefined();
      expect(disconnectedIncident.severity).toBe('high');
      expect(disconnectedIncident.description).toContain('interrupted');
    });
  });

  describe('Incident Management REST APIs', () => {
    beforeEach(async () => {
      await createIncident({
        type: 'INVALID_CHECKPOINT_SIGNATURE',
        severity: 'critical',
        sourceId: 'srv-vault-01',
        description: 'Digital signature mismatch on checkpoint #12',
      });
    });

    it('4. GET /api/incidents returns paginated incident list', async () => {
      const res = await request(app)
        .get('/api/incidents')
        .set('Authorization', `Bearer ${analystToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty('incidents');
      expect(res.body.data.incidents.length).toBeGreaterThan(0);
    });

    it('5. PATCH /api/incidents/:id/status updates incident status and records resolver', async () => {
      const currentInc = Array.from(mockIncidents.values())[0];

      const res = await request(app)
        .patch(`/api/incidents/${currentInc.incidentId}/status`)
        .set('Authorization', `Bearer ${analystToken}`)
        .send({
          status: 'RESOLVED',
          resolutionNotes: 'Key rotation resolved signature discrepancy. Validated authentic.',
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.status).toBe('RESOLVED');
      expect(res.body.data.resolutionNotes).toContain('Key rotation');
      expect(res.body.data.resolvedBy).toBe('analyst@securelog.io');
      expect(res.body.data.resolvedAt).toBeDefined();
    });
  });
});
