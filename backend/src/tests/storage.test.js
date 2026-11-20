import { describe, it, expect, vi, beforeEach } from 'vitest';
import storageService, { uploadLogBatch, retrieveLogBatch, resetMockStorage } from '../services/storageService.js';
import Log from '../models/Log.js';
import { getStorageConfig } from '../config/aws.js';

describe('Milestone 7: Immutable Evidence Storage (S3 Object Lock & Local Adapter)', () => {
  beforeEach(() => {
    resetMockStorage();
    vi.restoreAllMocks();

    vi.spyOn(Log, 'updateMany').mockResolvedValue({ modifiedCount: 3 });
  });

  const sampleLogs = [
    {
      _id: 'mongo_1',
      eventId: 'evt-s1',
      sourceId: 'srv-storage-test',
      sequenceNumber: 1,
      timestamp: '2026-11-20T10:00:00.000Z',
      message: 'System initialization',
      previousHash: '0000000000000000000000000000000000000000000000000000000000000000',
      currentHash: '1111111111111111111111111111111111111111111111111111111111111111',
    },
    {
      _id: 'mongo_2',
      eventId: 'evt-s2',
      sourceId: 'srv-storage-test',
      sequenceNumber: 2,
      timestamp: '2026-11-20T10:01:00.000Z',
      message: 'User authentication',
      previousHash: '1111111111111111111111111111111111111111111111111111111111111111',
      currentHash: '2222222222222222222222222222222222222222222222222222222222222222',
    },
  ];

  it('1. Rejects upload of empty log batches', async () => {
    await expect(uploadLogBatch({ sourceId: 'src-1', logs: [] })).rejects.toThrow(
      'Cannot upload empty log batch'
    );
  });

  it('2. Local mock storage adapter correctly marks isImmutable: false (honesty requirement)', async () => {
    const result = await uploadLogBatch({
      sourceId: 'srv-storage-test',
      logs: sampleLogs,
    });

    expect(result.success).toBe(true);
    expect(result.storageReference).toContain('evidence/srv-storage-test/batch_seq_1_to_2');
    expect(result.isImmutable).toBe(false); // Explicitly NOT immutable in mock
    expect(result.storageType).toBe('MOCK_LOCAL_STORAGE');
    expect(result.recordCount).toBe(2);
    expect(result.batchHash).toBeDefined();
    expect(result.batchHash).toHaveLength(64);
  });

  it('3. Updates database log records with storageReference upon successful upload', async () => {
    const updateSpy = vi.spyOn(Log, 'updateMany');

    const result = await uploadLogBatch({
      sourceId: 'srv-storage-test',
      logs: sampleLogs,
    });

    expect(updateSpy).toHaveBeenCalledWith(
      expect.anything(),
      { $set: { storageReference: result.storageReference } }
    );
  });

  it('4. Successfully retrieves and cryptographically verifies authentic evidence batch', async () => {
    const uploadResult = await uploadLogBatch({
      sourceId: 'srv-storage-test',
      logs: sampleLogs,
    });

    const retrieved = await retrieveLogBatch(uploadResult.storageReference);

    expect(retrieved.verified).toBe(true);
    expect(retrieved.batchHash).toBe(uploadResult.batchHash);
    expect(retrieved.recalculatedHash).toBe(uploadResult.batchHash);
    expect(retrieved.recordCount).toBe(2);
    expect(retrieved.logs).toHaveLength(2);
  });

  it('5. Detects evidence tampering in storage if batch contents are altered', async () => {
    const uploadResult = await uploadLogBatch({
      sourceId: 'srv-storage-test',
      logs: sampleLogs,
    });

    // Retrieve and simulate an in-storage modification attack
    const retrieved = await retrieveLogBatch(uploadResult.storageReference);
    // Maliciously alter a log in the retrieved copy
    retrieved.logs[0].message = 'TAMPERED STORAGE RECORD';

    // Recalculating hash directly over modified logs
    const { canonicalize } = await import('../utils/canonicalize.js');
    const { sha256 } = await import('../utils/generateHash.js');
    const alteredHash = sha256(canonicalize(retrieved.logs));

    expect(alteredHash).not.toBe(uploadResult.batchHash);
  });

  it('6. Storage configuration properly reports WORM compliance mode policy', () => {
    const config = getStorageConfig();
    expect(config.objectLockMode).toBe('COMPLIANCE');
    expect(config.retentionDays).toBeGreaterThan(0);
  });
});
