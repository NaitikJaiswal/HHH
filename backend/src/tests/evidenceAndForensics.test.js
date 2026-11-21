import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import app from '../app.js';
import Log from '../models/Log.js';
import Checkpoint from '../models/Checkpoint.js';
import Incident from '../models/Incident.js';
import evidenceService from '../services/evidenceService.js';
import forensicService from '../services/forensicService.js';
import integrityService from '../services/integrityService.js';
import { generateToken } from '../services/authService.js';
import { hashLogEvent, GENESIS_HASH } from '../../../security/src/crypto/hashing.js';

describe('Stage 5.4: Evidence Engine & Forensic Investigation Workflow', () => {
  const testToken = generateToken({
    id: 'user_analyst_54',
    email: 'forensic.lead@securelog.io',
    role: 'security_analyst',
  });

  const mockLogs = [];
  const mockCheckpoints = [];
  const mockIncidents = [];

  beforeEach(() => {
    mockLogs.length = 0;
    mockCheckpoints.length = 0;
    mockIncidents.length = 0;
    vi.restoreAllMocks();

    // Populate mock sequential logs
    let prevHash = GENESIS_HASH;
    for (let seq = 1; seq <= 5; seq++) {
      const event = {
        event_id: `ev-${seq}`,
        event_time: `2026-11-20T10:0${seq}:00.000Z`,
        event_type: seq === 1 ? 'AUTH_FAILURE' : 'SYSTEM_TELEMETRY',
        message: seq === 1 ? 'Failed SSH login attempt' : `System telemetry check #${seq}`,
        metadata: { client_ip: '192.168.1.100' },
        previous_hash: prevHash,
        sequence_number: seq,
        severity: seq === 1 ? 'HIGH' : 'INFO',
        source_id: 'host-srv-01',
      };
      const curHash = hashLogEvent(event);
      mockLogs.push({
        _id: `id_log_${seq}`,
        eventId: event.event_id,
        eventTime: event.event_time,
        serverTimestamp: event.event_time,
        eventType: event.event_type,
        message: event.message,
        metadata: event.metadata,
        previousHash: event.previous_hash,
        sequenceNumber: event.sequence_number,
        severity: event.severity,
        sourceId: event.source_id,
        currentHash: curHash,
      });
      prevHash = curHash;
    }

    // Mock Log.find
    vi.spyOn(Log, 'find').mockReturnValue({
      sort: vi.fn().mockReturnThis(),
      limit: vi.fn().mockReturnValue({
        lean: vi.fn().mockResolvedValue(mockLogs),
      }),
    });

    // Populate mock checkpoint
    mockCheckpoints.push({
      _id: 'cp_1',
      checkpointId: 'CP-1001',
      schema_version: 'logn-checkpoint-fss-v1',
      sourceId: 'host-srv-01',
      start_sequence: 1,
      end_sequence: 5,
      lastSequenceNumber: 5,
      event_count: 5,
      chainHeadHash: prevHash,
      merkle_root: '9999999999999999999999999999999999999999999999999999999999999999',
      merkle_leaf_hashes: mockLogs.map((l) => l.currentHash),
      merkle_tree_algorithm: 'HHH-CONTRACT-DUP-v1',
      signature: 'aabbccddeeff',
      signature_algorithm: 'Ed25519-MKT-FSS',
      fss_epoch: 0,
      createdAt: new Date().toISOString(),
    });

    vi.spyOn(Checkpoint, 'find').mockReturnValue({
      sort: vi.fn().mockReturnThis(),
      limit: vi.fn().mockReturnValue({
        lean: vi.fn().mockResolvedValue(mockCheckpoints),
      }),
    });

    // Mock Incident
    vi.spyOn(Incident, 'find').mockReturnValue({
      sort: vi.fn().mockReturnThis(),
      limit: vi.fn().mockReturnValue({
        lean: vi.fn().mockResolvedValue(mockIncidents),
      }),
    });

    vi.spyOn(Incident, 'create').mockImplementation((data) => {
      const doc = { ...data, _id: 'inc_' + Math.random().toString(36).substring(7) };
      mockIncidents.push(doc);
      return Promise.resolve(doc);
    });

    vi.spyOn(integrityService, 'verifySourceHashChain').mockResolvedValue({
      sourceId: 'host-srv-01',
      isValid: true,
      totalLogs: 5,
      totalCheckpoints: 1,
      anomalies: [],
    });

    vi.spyOn(integrityService, 'verifyAllSources').mockResolvedValue({
      overallIntegrity: true,
      totalSourcesChecked: 1,
      sourcesWithAnomalies: 0,
      reports: [],
    });
  });

  describe('1. Evidence Packaging Service', () => {
    it('packages logs, checkpoints, and inclusion proofs into a sealed evidence bundle', async () => {
      const result = await evidenceService.packageEvidence({
        sourceId: 'host-srv-01',
        limit: 10,
        investigator: 'Analyst Jane Doe',
      });

      expect(result).toHaveProperty('bundle');
      expect(result).toHaveProperty('files');

      const { bundle, files } = result;

      // Manifest checks
      expect(bundle.manifest).toBeDefined();
      expect(bundle.manifest.source_id).toBe('host-srv-01');
      expect(bundle.manifest.event_count).toBe(5);
      expect(bundle.manifest.manifest_hash).toBeDefined();

      // Events checks
      expect(bundle.events).toHaveLength(5);
      expect(bundle.events[0].sequence_number).toBe(1);
      expect(bundle.events[4].sequence_number).toBe(5);

      // Checkpoints & Proofs checks
      expect(bundle.checkpoints).toHaveLength(1);
      expect(bundle.merkle_proofs.length).toBeGreaterThan(0);

      // Chain of Custody & Readme
      expect(bundle.chain_of_custody).toHaveLength(1);
      expect(bundle.chain_of_custody[0].actor).toBe('Analyst Jane Doe');
      expect(bundle.readme).toContain('HHH FORENSIC EVIDENCE BUNDLE');

      // Structured files output
      expect(files['manifest.json']).toBeDefined();
      expect(files['events.jsonl']).toContain('ev-1');
      expect(files['checkpoints.json']).toBeDefined();
      expect(files['chain_of_custody.json']).toBeDefined();
      expect(files['README.txt']).toBeDefined();
    });

    it('verifies generated evidence bundle and detects tampering', async () => {
      const { bundle } = await evidenceService.packageEvidence({
        sourceId: 'host-srv-01',
        limit: 10,
      });

      // Tampered event test
      const tamperedBundle = JSON.parse(JSON.stringify(bundle));
      tamperedBundle.events[2].message = 'MALICIOUS_ALTERATION_ATTEMPT';

      const verifyTampered = evidenceService.verifyEvidence(tamperedBundle);
      expect(verifyTampered.status).toBe('INVALID');
      expect(verifyTampered.exitCode).toBe(1);
      expect(verifyTampered.errors.length).toBeGreaterThan(0);
    });
  });

  describe('2. Forensic Timeline & Investigation Management', () => {
    it('creates and lists forensic investigation dossiers', async () => {
      const newCase = await forensicService.createInvestigation({
        title: 'Unauthorized LSASS Memory Access Investigation',
        severity: 'CRITICAL',
        sourceId: 'host-srv-01',
        description: 'Suspicious process injected memory space into LSASS.',
        analyst: 'Analyst Vance',
        startSequence: 1,
        endSequence: 5,
      });

      expect(newCase.caseId).toContain('CASE-INC-');
      expect(newCase.severity).toBe('CRITICAL');
      expect(newCase.status).toBe('INVESTIGATING');

      const cases = await forensicService.listInvestigations();
      expect(cases.length).toBeGreaterThanOrEqual(1);
      expect(cases[0].title).toContain('LSASS');
    });

    it('reconstructs chronologically ordered attack timeline and detects sequence continuity', async () => {
      const timeline = await forensicService.getInvestigationTimeline({
        sourceId: 'host-srv-01',
        limit: 10,
      });

      expect(timeline.summary.total).toBe(5);
      expect(timeline.summary.anomalies).toBe(0);
      expect(timeline.events).toHaveLength(5);
      expect(timeline.events[0].phase).toBe('CREDENTIAL_ACCESS');
      expect(timeline.events[0].integrityStatus).toBe('VERIFIED');
    });

    it('generates authoritative forensic report with Quai Network blockchain anchoring in JSON and Markdown', async () => {
      const result = await forensicService.generateForensicReport({
        title: 'Forensic Audit of host-srv-01',
        sourceId: 'host-srv-01',
        investigator: 'Lead Investigator Smith',
        format: 'json',
      });

      expect(result.report).toBeDefined();
      expect(result.markdown).toBeDefined();

      const rep = result.report;
      expect(rep.title).toContain('Forensic Audit');
      expect(rep.summary.total_events_collected).toBe(5);
      expect(rep.blockchain_anchoring.network).toContain('Quai Network');
      expect(rep.blockchain_anchoring.chain_id).toBe(15000);
      expect(rep.blockchain_anchoring.contract).toBe('SecureLogAnchor');
      expect(rep.recommended_investigation_steps.length).toBeGreaterThan(0);

      // Markdown inspection
      expect(result.markdown).toContain('# FORENSIC INCIDENT DOSSIER');
      expect(result.markdown).toContain('Quai Network Orchard Cyprus-1');
      expect(result.markdown).toContain('Reconstructed Attack Timeline');
    });
  });

  describe('3. REST API Integration', () => {
    it('GET /api/evidence returns list of verifiable evidence packages', async () => {
      const res = await request(app)
        .get('/api/evidence')
        .set('Authorization', `Bearer ${testToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toBeInstanceOf(Array);
      expect(res.body.data[0].evidenceId).toContain('EVD-');
    });

    it('POST /api/evidence/package creates sealed bundle', async () => {
      const res = await request(app)
        .post('/api/evidence/package')
        .set('Authorization', `Bearer ${testToken}`)
        .send({ sourceId: 'host-srv-01', limit: 5 });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.bundle_id).toBeDefined();
      expect(res.body.files['README.txt']).toBeDefined();
    });

    it('POST /api/evidence/verify returns verification verdict', async () => {
      const { bundle } = await evidenceService.packageEvidence({
        sourceId: 'host-srv-01',
        limit: 5,
      });

      const res = await request(app)
        .post('/api/evidence/verify')
        .set('Authorization', `Bearer ${testToken}`)
        .send(bundle);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.eventsChecked).toBe(5);
    });

    it('GET /api/forensics/investigations lists active cases', async () => {
      const res = await request(app)
        .get('/api/forensics/investigations')
        .set('Authorization', `Bearer ${testToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toBeInstanceOf(Array);
    });

    it('POST /api/forensics/report generates report and supports format=markdown', async () => {
      const resJson = await request(app)
        .post('/api/forensics/report')
        .set('Authorization', `Bearer ${testToken}`)
        .send({ sourceId: 'host-srv-01', format: 'json' });

      expect(resJson.status).toBe(201);
      expect(resJson.body.data.report_id).toBeDefined();

      const resMd = await request(app)
        .post('/api/forensics/report')
        .set('Authorization', `Bearer ${testToken}`)
        .send({ sourceId: 'host-srv-01', format: 'markdown' });

      expect(resMd.status).toBe(201);
      expect(resMd.text).toContain('# FORENSIC INCIDENT DOSSIER');
    });
  });
});
