import { PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';
import { getS3Client, getStorageConfig, isS3Configured } from '../config/aws.js';
import { canonicalize } from '../utils/canonicalize.js';
import { sha256 } from '../utils/generateHash.js';
import Log from '../models/Log.js';

// In-memory storage mock for development and testing
// NOTE: Mock storage is NOT immutable and must never be represented as such.
const mockStorageStore = new Map();

/**
 * Resets local mock storage (for testing)
 */
export const resetMockStorage = () => {
  mockStorageStore.clear();
};

/**
 * Uploads a batch of log records to immutable storage (AWS S3 Object Lock or Local Mock)
 */
export const uploadLogBatch = async ({ sourceId, logs }) => {
  if (!logs || !Array.isArray(logs) || logs.length === 0) {
    throw new Error('Cannot upload empty log batch to storage.');
  }

  // Sort logs by sequence number to ensure deterministic ordering
  const sortedLogs = [...logs].sort((a, b) => a.sequenceNumber - b.sequenceNumber);
  const firstSeq = sortedLogs[0].sequenceNumber;
  const lastSeq = sortedLogs[sortedLogs.length - 1].sequenceNumber;

  // Compute canonical SHA-256 batch hash
  const canonicalBatchData = canonicalize(sortedLogs);
  const batchHash = sha256(canonicalBatchData);

  const timestamp = Date.now();
  const objectKey = `evidence/${sourceId}/batch_seq_${firstSeq}_to_${lastSeq}_${timestamp}.json`;

  const config = getStorageConfig();
  const retainUntilDate = new Date(Date.now() + config.retentionDays * 24 * 60 * 60 * 1000);

  const batchPayload = {
    sourceId,
    batchHash,
    firstSequenceNumber: firstSeq,
    lastSequenceNumber: lastSeq,
    recordCount: sortedLogs.length,
    uploadedAt: new Date().toISOString(),
    retainUntilDate: retainUntilDate.toISOString(),
    storageMode: config.isS3Active ? 'AWS_S3_OBJECT_LOCK' : 'MOCK_LOCAL_STORAGE',
    isImmutable: config.isS3Active,
    logs: sortedLogs,
  };

  let uploadSucceeded = false;

  if (config.isS3Active) {
    const s3 = getS3Client();
    try {
      const command = new PutObjectCommand({
        Bucket: config.bucketName,
        Key: objectKey,
        Body: JSON.stringify(batchPayload, null, 2),
        ContentType: 'application/json',
        ObjectLockMode: 'COMPLIANCE',
        ObjectLockRetainUntilDate: retainUntilDate,
        Metadata: {
          'batch-hash': batchHash,
          'source-id': sourceId,
          'first-sequence': String(firstSeq),
          'last-sequence': String(lastSeq),
          'record-count': String(sortedLogs.length),
        },
      });

      await s3.send(command);
      uploadSucceeded = true;
    } catch (awsError) {
      console.error('[Storage Error] AWS S3 upload failed:', awsError.message);
      const safeError = new Error(`Immutable storage upload failed: ${awsError.message}`);
      safeError.statusCode = 502;
      throw safeError;
    }
  } else {
    // Development / Local Mock Storage Adapter
    mockStorageStore.set(objectKey, {
      payload: JSON.parse(JSON.stringify(batchPayload)),
      uploadedAt: new Date(),
    });
    uploadSucceeded = true;
  }

  // CRITICAL SECURITY RULE: Only update database storage reference AFTER upload has actually succeeded
  if (uploadSucceeded) {
    const logIds = sortedLogs.map((l) => l._id || l.eventId);
    await Log.updateMany(
      { $or: [{ _id: { $in: logIds } }, { eventId: { $in: logIds } }] },
      { $set: { storageReference: objectKey } }
    );
  }

  return {
    success: true,
    storageReference: objectKey,
    batchHash,
    firstSequenceNumber: firstSeq,
    lastSequenceNumber: lastSeq,
    recordCount: sortedLogs.length,
    retainUntilDate: retainUntilDate.toISOString(),
    storageType: config.isS3Active ? 'AWS_S3_OBJECT_LOCK_COMPLIANCE' : 'MOCK_LOCAL_STORAGE',
    isImmutable: config.isS3Active, // Explicitly false for mock
  };
};

/**
 * Retrieves and cryptographically verifies an evidence batch from storage
 */
export const retrieveLogBatch = async (storageReference) => {
  const config = getStorageConfig();
  let batchPayload = null;

  if (config.isS3Active) {
    const s3 = getS3Client();
    try {
      const command = new GetObjectCommand({
        Bucket: config.bucketName,
        Key: storageReference,
      });

      const response = await s3.send(command);
      const bodyString = await response.Body.transformToString('utf-8');
      batchPayload = JSON.parse(bodyString);
    } catch (awsError) {
      console.error(`[Storage Error] Could not retrieve evidence ${storageReference}:`, awsError.message);
      const safeError = new Error(`Failed to retrieve storage object: ${awsError.message}`);
      safeError.statusCode = 404;
      throw safeError;
    }
  } else {
    // Mock retrieval
    const record = mockStorageStore.get(storageReference);
    if (!record) {
      const error = new Error(`Evidence batch not found in storage: ${storageReference}`);
      error.statusCode = 404;
      throw error;
    }
    batchPayload = record.payload;
  }

  // Cryptographic Verification: Recalculate batch SHA-256 and compare with stored batchHash
  const canonicalLogs = canonicalize(batchPayload.logs);
  const recalculatedHash = sha256(canonicalLogs);
  const isVerified = recalculatedHash === batchPayload.batchHash;

  return {
    verified: isVerified,
    storageReference,
    batchHash: batchPayload.batchHash,
    recalculatedHash,
    recordCount: batchPayload.recordCount,
    sourceId: batchPayload.sourceId,
    firstSequenceNumber: batchPayload.firstSequenceNumber,
    lastSequenceNumber: batchPayload.lastSequenceNumber,
    isImmutable: batchPayload.isImmutable,
    storageMode: batchPayload.storageMode,
    logs: batchPayload.logs,
  };
};

export default {
  uploadLogBatch,
  retrieveLogBatch,
  resetMockStorage,
};
