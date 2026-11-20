import Checkpoint from '../models/Checkpoint.js';
import Source from '../models/Source.js';
import Log from '../models/Log.js';
import { signData, verifySignature, getKeyPair } from '../utils/generateSignature.js';

/**
 * Creates and digitally signs a new checkpoint for a given log source.
 */
export const createCheckpoint = async (sourceId) => {
  // Find source or query highest sequence log
  const source = await Source.findOne({ sourceId });
  const latestLog = await Log.findOne({ sourceId }).sort({ sequenceNumber: -1 });

  const lastSequenceNumber = latestLog ? latestLog.sequenceNumber : (source?.lastSequenceNumber || 0);
  const chainHeadHash = latestLog
    ? latestLog.currentHash
    : (source?.lastHash || '0000000000000000000000000000000000000000000000000000000000000000');

  const checkpointId = `chk-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;
  const timestamp = new Date();

  const checkpointPayload = {
    checkpointId,
    sourceId,
    lastSequenceNumber,
    chainHeadHash,
    timestamp: timestamp.toISOString(),
  };

  const keyPair = getKeyPair();
  const signature = signData(checkpointPayload);

  const checkpointDoc = await Checkpoint.create({
    checkpointId,
    sourceId,
    lastSequenceNumber,
    chainHeadHash,
    timestamp,
    signature,
    publicKey: keyPair.publicKeyDer,
    status: 'VALID',
  });

  return checkpointDoc;
};

/**
 * Verifies an Ed25519 digital signature of a checkpoint
 */
export const verifyCheckpointSignature = (checkpoint) => {
  const timestampIso = checkpoint.timestamp instanceof Date
    ? checkpoint.timestamp.toISOString()
    : new Date(checkpoint.timestamp).toISOString();

  const payload = {
    checkpointId: checkpoint.checkpointId,
    sourceId: checkpoint.sourceId,
    lastSequenceNumber: Number(checkpoint.lastSequenceNumber),
    chainHeadHash: checkpoint.chainHeadHash,
    timestamp: timestampIso,
  };

  const isValid = verifySignature(payload, checkpoint.signature, checkpoint.publicKey);

  return {
    isValid,
    error: isValid ? null : 'Ed25519 signature verification failed. Checkpoint payload was altered or forged.',
  };
};

/**
 * Retrieve checkpoints with pagination
 */
export const getCheckpoints = async (query = {}) => {
  const page = Math.max(1, parseInt(query.page, 10) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(query.limit, 10) || 20));
  const skip = (page - 1) * limit;

  const filter = {};
  if (query.sourceId) {
    filter.sourceId = query.sourceId;
  }

  const [checkpoints, total] = await Promise.all([
    Checkpoint.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
    Checkpoint.countDocuments(filter),
  ]);

  return {
    checkpoints,
    pagination: {
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit) || 1,
    },
  };
};

/**
 * Retrieve latest checkpoint for a source
 */
export const getLatestCheckpoint = async (sourceId) => {
  return Checkpoint.findOne({ sourceId }).sort({ lastSequenceNumber: -1, createdAt: -1 });
};

export default {
  createCheckpoint,
  verifyCheckpointSignature,
  getCheckpoints,
  getLatestCheckpoint,
};
