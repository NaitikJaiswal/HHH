import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import Checkpoint from '../models/Checkpoint.js';
import Log from '../models/Log.js';
import Source from '../models/Source.js';
import Incident from '../models/Incident.js';
import {
  createCheckpoint,
  verifyCheckpointSignature,
  evolveEpoch,
  revokeKeyEmergency,
  getFssStatus,
  setFssStateManager,
  resetFssStateManager,
  CHECKPOINT_FSS_SCHEMA_VERSION,
} from '../services/checkpointService.js';
import { verifySourceHashChain } from '../services/integrityService.js';
import { generateLogHash } from '../utils/generateHash.js';
import { generateFssMasterState } from '../../../security/src/crypto/fssSigner.js';
import { FssStateManager } from '../../../security/src/keys/fssStateManager.js';
import { sha256hex } from '../../../security/src/crypto/hashing.js';
import { signData, getKeyPair } from '../utils/generateSignature.js';

describe('Phase 5.1 Cryptographic Core Integration - Forward-Secure Checkpoint Signing', () => {
  let tempDir;
  let fssManager;

  beforeEach(() => {
    vi.restoreAllMocks();
    tempDir = mkdtempSync(join(tmpdir(), 'fss-chk-backend-test-'));
    const statePath = join(tempDir, 'fss_state.json');
    const revocationPath = join(tempDir, 'fss_revocation.json');
    const publicTreePath = join(tempDir, 'fss_public_tree.json');

    const { state, publicTree } = generateFssMasterState({ maxEpochs: 16 });
    writeFileSync(publicTreePath, JSON.stringify(publicTree, null, 2));
    process.env.FSS_PUBLIC_TREE_PATH = publicTreePath;
    process.env.FSS_STATE_DIR = tempDir;

    fssManager = new FssStateManager({ statePath, revocationPath });
    fssManager.initState(state, true);
    setFssStateManager(fssManager);

    // Default safe model mocks
    vi.spyOn(Checkpoint, 'findOne').mockImplementation(() => ({
      sort: vi.fn().mockResolvedValue(null),
    }));
    vi.spyOn(Checkpoint, 'create').mockImplementation((data) => Promise.resolve({ ...data, _id: 'chk_mock' }));
    vi.spyOn(Log, 'find').mockImplementation(() => ({
      sort: vi.fn().mockResolvedValue([]),
    }));
  });

  afterEach(() => {
    resetFssStateManager();
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup error
    }
  });

  it('1. Generates and stores forward-secure checkpoint with full cryptographic metadata', async () => {
    const sourceId = 'fss-srv-alpha';
    const mockLogs = [
      { sequenceNumber: 1, currentHash: sha256hex('log-1') },
      { sequenceNumber: 2, currentHash: sha256hex('log-2') },
      { sequenceNumber: 3, currentHash: sha256hex('log-3') },
    ];

    vi.spyOn(Log, 'find').mockImplementation(() => ({
      sort: vi.fn().mockResolvedValue(mockLogs),
    }));

    let savedDoc = null;
    vi.spyOn(Checkpoint, 'create').mockImplementation((data) => {
      savedDoc = { _id: 'chk_mongo_1', ...data };
      return Promise.resolve(savedDoc);
    });

    const chk = await createCheckpoint(sourceId);

    expect(chk).toBeDefined();
    expect(chk.schema_version).toBe(CHECKPOINT_FSS_SCHEMA_VERSION);
    expect(chk.sourceId).toBe(sourceId);
    expect(chk.start_sequence).toBe(1);
    expect(chk.end_sequence).toBe(3);
    expect(chk.event_count).toBe(3);
    expect(chk.merkle_leaf_hashes).toHaveLength(3);
    expect(chk.merkle_root).toMatch(/^[0-9a-f]{64}$/);
    expect(chk.fss_epoch).toBe(0);
    expect(chk.mpk).toBe(fssManager.mpk);
    expect(chk.epoch_public_key).toMatch(/^[0-9a-f]{64}$/);
    expect(chk.signature).toMatch(/^[0-9a-f]{128}$/);
    expect(chk.fss_auth_path).toBeDefined();
    expect(chk.fss_auth_path.length).toBeGreaterThan(0);

    // Verify cryptographic signature
    const verification = verifyCheckpointSignature(chk);
    expect(verification.isValid).toBe(true);
    expect(verification.error).toBeNull();
  });

  it('2. Detects Merkle root tampering in forward-secure checkpoint', async () => {
    const sourceId = 'fss-srv-beta';
    const leafHashes = [sha256hex('alpha'), sha256hex('beta')];

    vi.spyOn(Log, 'find').mockImplementation(() => ({
      sort: vi.fn().mockResolvedValue([
        { sequenceNumber: 1, currentHash: leafHashes[0] },
        { sequenceNumber: 2, currentHash: leafHashes[1] },
      ]),
    }));

    const chk = await createCheckpoint(sourceId);

    // Malicious attacker alters Merkle root
    const tampered = {
      ...chk,
      merkle_root: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    };

    const verification = verifyCheckpointSignature(tampered);
    expect(verification.isValid).toBe(false);
    expect(verification.status).toBe('MERKLE_MISMATCH');
  });

  it('3. Detects forged signature in forward-secure checkpoint', async () => {
    const sourceId = 'fss-srv-gamma';
    const leafHashes = [sha256hex('event-gamma-1')];

    vi.spyOn(Log, 'find').mockImplementation(() => ({
      sort: vi.fn().mockResolvedValue([{ sequenceNumber: 1, currentHash: leafHashes[0] }]),
    }));

    const chk = await createCheckpoint(sourceId);

    // Corrupt signature bytes
    const tampered = {
      ...chk,
      signature: 'bad0' + chk.signature.slice(4),
      fss_signature: 'bad0' + chk.signature.slice(4),
    };

    const verification = verifyCheckpointSignature(tampered);
    expect(verification.isValid).toBe(false);
    expect(verification.status).toBe('INVALID_SIGNATURE');
  });

  it('4. Preserves backward compatibility: verifies legacy Ed25519 checkpoints', () => {
    const keyPair = getKeyPair();
    const legacyPayload = {
      checkpointId: 'chk-legacy-001',
      sourceId: 'legacy-srv',
      lastSequenceNumber: 15,
      chainHeadHash: sha256hex('legacy-head'),
      timestamp: '2026-11-20T10:00:00.000Z',
    };

    const signature = signData(legacyPayload);

    const legacyCheckpoint = {
      ...legacyPayload,
      signature,
      publicKey: keyPair.publicKeyDer,
      status: 'VALID',
    };

    const res = verifyCheckpointSignature(legacyCheckpoint);
    expect(res.isValid).toBe(true);
    expect(res.error).toBeNull();

    // Verify tampering detection on legacy checkpoint
    const tamperedLegacy = {
      ...legacyCheckpoint,
      chainHeadHash: sha256hex('forged-head'),
    };
    const tamperedRes = verifyCheckpointSignature(tamperedLegacy);
    expect(tamperedRes.isValid).toBe(false);
  });

  it('5. Verifies forward security across epoch evolution (ratchet)', async () => {
    const leafHashesEpoch0 = [sha256hex('log-e0-1')];
    const leafHashesEpoch1 = [sha256hex('log-e1-2')];

    // Epoch 0 Checkpoint
    vi.spyOn(Log, 'find').mockImplementation(() => ({
      sort: vi.fn().mockResolvedValue([{ sequenceNumber: 1, currentHash: leafHashesEpoch0[0] }]),
    }));
    const chkEpoch0 = await createCheckpoint('srv-ratchet');
    expect(chkEpoch0.fss_epoch).toBe(0);

    // Verify valid at epoch 0
    expect(verifyCheckpointSignature(chkEpoch0).isValid).toBe(true);

    // Evolve key to Epoch 1 (ratchet one-way advancement)
    const { epoch } = await evolveEpoch();
    expect(epoch).toBe(1);

    // Epoch 1 Checkpoint
    vi.spyOn(Log, 'find').mockImplementation(() => ({
      sort: vi.fn().mockResolvedValue([{ sequenceNumber: 2, currentHash: leafHashesEpoch1[0] }]),
    }));
    const chkEpoch1 = await createCheckpoint('srv-ratchet');
    expect(chkEpoch1.fss_epoch).toBe(1);

    // Core Forward-Security Invariant: Historical epoch 0 checkpoint MUST remain valid
    const histVerify = verifyCheckpointSignature(chkEpoch0);
    expect(histVerify.isValid).toBe(true);

    // New epoch 1 checkpoint is also valid
    const currVerify = verifyCheckpointSignature(chkEpoch1);
    expect(currVerify.isValid).toBe(true);

    // Key status reflects current epoch
    const status = getFssStatus();
    expect(status.epoch).toBe(1);
    expect(status.isRevoked).toBe(false);
  });

  it('6. Emergency revocation shreds active key and forbids subsequent signing', async () => {
    const statusBefore = getFssStatus();
    expect(statusBefore.isRevoked).toBe(false);

    // Trigger emergency revocation
    const notice = await revokeKeyEmergency({
      reason: 'Server compromise detected in DMZ',
      lastValidCheckpointHash: sha256hex('final-valid-head'),
    });

    expect(notice).toBeDefined();
    expect(notice.reason).toBe('Server compromise detected in DMZ');

    const statusAfter = getFssStatus();
    expect(statusAfter.isRevoked).toBe(true);

    // Subsequent checkpoint creation attempts MUST fail safely
    vi.spyOn(Log, 'find').mockImplementation(() => ({
      sort: vi.fn().mockResolvedValue([{ sequenceNumber: 1, currentHash: sha256hex('post-rev') }]),
    }));

    await expect(createCheckpoint('srv-revoked')).rejects.toThrow(/FSS_REVOKED/);
  });

  it('7. Integrates FSS checkpoint verification into verifySourceHashChain', async () => {
    const sourceId = 'fss-integrated-src';

    const logs = [];
    let prev = '0000000000000000000000000000000000000000000000000000000000000000';
    for (let seq = 1; seq <= 2; seq++) {
      const doc = {
        eventId: `int-evt-${seq}`,
        sourceId,
        sequenceNumber: seq,
        timestamp: new Date(`2026-11-20T10:0${seq}:00Z`),
        eventType: 'SECURITY',
        severity: 'INFO',
        hashSchemaVersion: 'LOGN-HASH-v1',
        message: `Integrated log ${seq}`,
        metadata: {},
        previousHash: prev,
      };
      doc.currentHash = generateLogHash(doc);
      logs.push(doc);
      prev = doc.currentHash;
    }

    const leafHashes = logs.map((l) => l.currentHash);

    vi.spyOn(Log, 'find').mockImplementation(() => ({
      sort: vi.fn().mockReturnValue({
        lean: vi.fn().mockResolvedValue(logs),
      }),
    }));

    // Create authentic FSS Checkpoint covering sequence 1 to 2
    let fssChkDoc = null;
    vi.spyOn(Checkpoint, 'create').mockImplementation((doc) => {
      fssChkDoc = doc;
      return Promise.resolve(doc);
    });

    await createCheckpoint(sourceId, {
      start_sequence: 1,
      end_sequence: 2,
      leaf_hashes: leafHashes,
    });

    vi.spyOn(Checkpoint, 'find').mockImplementation(() => ({
      sort: vi.fn().mockReturnValue({
        lean: vi.fn().mockResolvedValue([fssChkDoc]),
      }),
    }));

    vi.spyOn(Incident, 'create').mockResolvedValue({ incidentId: 'inc-int' });

    const report = await verifySourceHashChain(sourceId);
    expect(report.isValid).toBe(true);
    expect(report.totalCheckpoints).toBe(1);
    expect(report.anomalies).toHaveLength(0);
  });
});
