import fs from 'node:fs';
import { join } from 'node:path';
import Checkpoint from '../models/Checkpoint.js';
import Source from '../models/Source.js';
import Log from '../models/Log.js';
import { signData, verifySignature, getKeyPair } from '../utils/generateSignature.js';
import {
  createFssCheckpoint,
  verifyCheckpoint,
  CHECKPOINT_FSS_SCHEMA_VERSION,
  CHECKPOINT_SCHEMA_VERSION,
  VerificationStatus,
} from '../../../security/src/checkpoints/checkpointService.js';
import { FssStateManager } from '../../../security/src/keys/fssStateManager.js';
import { generateFssMasterState } from '../../../security/src/crypto/fssSigner.js';

let activeFssManager = null;

// Concurrency lock to prevent race conditions during concurrent checkpoint generation per source
const checkpointLocks = new Map();

const acquireCheckpointLock = async (sourceId) => {
  while (checkpointLocks.get(sourceId)) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  checkpointLocks.set(sourceId, true);
};

const releaseCheckpointLock = (sourceId) => {
  checkpointLocks.delete(sourceId);
};

/**
 * Returns the singleton FssStateManager instance for forward-secure checkpoint signing.
 * Fails safely if state is corrupted, rolled back, or revoked without silently regenerating keys.
 */
export const getFssStateManager = () => {
  if (activeFssManager) {
    return activeFssManager;
  }

  const stateDir = process.env.FSS_STATE_DIR || join(process.cwd(), 'vault');
  const statePath = process.env.FSS_STATE_PATH || join(stateDir, 'fss_state.json');
  const revocationPath = process.env.FSS_REVOCATION_PATH || join(stateDir, 'fss_revocation.json');

  if (fs.existsSync(statePath)) {
    const manager = new FssStateManager({ statePath, revocationPath });
    manager.loadStateFromDisk();
    activeFssManager = manager;
    return activeFssManager;
  }

  // If state file does not exist, initialize new forward-secure master state
  if (!fs.existsSync(stateDir)) {
    fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  }

  const { state, publicTree } = generateFssMasterState({ maxEpochs: 1024 });
  const manager = new FssStateManager({ statePath, revocationPath });
  manager.initState(state, true);

  const publicTreePath = join(stateDir, 'fss_public_tree.json');
  fs.writeFileSync(publicTreePath, JSON.stringify(publicTree, null, 2), { mode: 0o644 });

  activeFssManager = manager;
  return activeFssManager;
};

/**
 * Injects a custom or mock FssStateManager (primarily for testing).
 */
export const setFssStateManager = (customManager) => {
  activeFssManager = customManager;
};

/**
 * Resets the active FssStateManager instance.
 */
export const resetFssStateManager = () => {
  activeFssManager = null;
};

/**
 * Creates and digitally signs a new forward-secure checkpoint for a given log source.
 */
export const createCheckpoint = async (sourceId, options = {}) => {
  if (!sourceId || typeof sourceId !== 'string') {
    throw new TypeError('createCheckpoint: sourceId must be a non-empty string');
  }

  await acquireCheckpointLock(sourceId);
  try {

  // 1. Resolve log window and leaf hashes
  let startSequence = options.start_sequence || options.startSequence;
  let endSequence = options.end_sequence || options.endSequence;
  let leafHashes = options.leaf_hashes || options.leafHashes;

  if (!leafHashes || leafHashes.length === 0) {
    if (!startSequence) {
      const query = Checkpoint.findOne({ sourceId });
      const prevCheckpoint = query && typeof query.sort === 'function'
        ? await query.sort({ end_sequence: -1, lastSequenceNumber: -1 })
        : await query;
      startSequence = prevCheckpoint ? ((prevCheckpoint.end_sequence || prevCheckpoint.lastSequenceNumber || 0) + 1) : 1;
    }

    const logQuery = Log.find({ sourceId, sequenceNumber: { $gte: startSequence } });
    if (endSequence && logQuery && typeof logQuery.where === 'function') {
      logQuery.where('sequenceNumber').lte(endSequence);
    }

    let logs = logQuery && typeof logQuery.sort === 'function'
      ? await logQuery.sort({ sequenceNumber: 1 })
      : await logQuery;

    // If no new un-checkpointed logs, check if any logs exist for this source
    if (!logs || logs.length === 0) {
      const allQuery = Log.find({ sourceId });
      const allLogs = allQuery && typeof allQuery.sort === 'function'
        ? await allQuery.sort({ sequenceNumber: 1 })
        : await allQuery;
      if (allLogs && allLogs.length > 0) {
        logs = allLogs;
        startSequence = logs[0].sequenceNumber;
      }
    }

    if (logs.length === 0) {
      throw new Error(`Cannot create checkpoint for source "${sourceId}": no log events found`);
    }

    startSequence = logs[0].sequenceNumber;
    endSequence = logs[logs.length - 1].sequenceNumber;
    leafHashes = logs.map((l) => l.currentHash);
  } else {
    startSequence = startSequence || 1;
    endSequence = endSequence || (startSequence + leafHashes.length - 1);
  }

  const chainHeadHash = leafHashes[leafHashes.length - 1];
  const checkpointId =
    options.checkpoint_id ||
    options.checkpointId ||
    `chk-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;

  // 2. Obtain forward-secure signer
  const fssManager = getFssStateManager();

  // 3. Create FSS Checkpoint using security engine
  const fssCheckpoint = createFssCheckpoint(
    {
      source_id: sourceId,
      start_sequence: startSequence,
      end_sequence: endSequence,
      leaf_hashes: leafHashes,
      checkpoint_id: checkpointId,
    },
    fssManager
  );

  // 4. Persist to MongoDB with full forward-secure metadata
  const checkpointDoc = await Checkpoint.create({
    checkpointId: fssCheckpoint.checkpoint_id,
    schema_version: fssCheckpoint.schema_version,
    sourceId: fssCheckpoint.source_id,
    start_sequence: fssCheckpoint.start_sequence,
    end_sequence: fssCheckpoint.end_sequence,
    lastSequenceNumber: fssCheckpoint.end_sequence,
    event_count: fssCheckpoint.event_count,
    chainHeadHash,
    merkle_root: fssCheckpoint.merkle_root,
    merkle_leaf_hashes: fssCheckpoint.merkle_leaf_hashes,
    merkle_tree_algorithm: 'HHH-CONTRACT-DUP-v1',
    fss_epoch: fssCheckpoint.fss_epoch,
    mpk: fssCheckpoint.mpk,
    epoch_public_key: fssCheckpoint.epoch_public_key,
    fss_auth_path: fssCheckpoint.fss_auth_path,
    fss_signature: fssCheckpoint.fss_signature,
    fss_bundle: fssCheckpoint.fss_bundle,
    timestamp: new Date(fssCheckpoint.timestamp),
    signature: fssCheckpoint.signature,
    publicKey: fssCheckpoint.epoch_public_key,
    signature_algorithm: fssCheckpoint.signature_algorithm,
    signature_input: fssCheckpoint.signature_input,
    blockchain: null,
    status: 'VALID',
  });

    return checkpointDoc;
  } finally {
    releaseCheckpointLock(sourceId);
  }
};

/**
 * Verifies the digital signature of a checkpoint (FSS or legacy).
 */
export const verifyCheckpointSignature = (checkpoint) => {
  if (!checkpoint || typeof checkpoint !== 'object') {
    return {
      isValid: false,
      error: 'Checkpoint must be an object',
    };
  }

  // Detect whether this is a forward-secure checkpoint (logn-checkpoint-fss-v1) or legacy checkpoint
  const isFss =
    checkpoint.schema_version === CHECKPOINT_FSS_SCHEMA_VERSION ||
    Boolean(checkpoint.mpk) ||
    Boolean(checkpoint.fss_signature);

  if (isFss) {
    const rawTimestamp =
      checkpoint.timestamp instanceof Date
        ? checkpoint.timestamp.toISOString().replace(/\.\d+Z$/, 'Z')
        : String(checkpoint.timestamp || new Date().toISOString().replace(/\.\d+Z$/, 'Z'));

    const normalizedFssCheckpoint = {
      schema_version: checkpoint.schema_version || CHECKPOINT_FSS_SCHEMA_VERSION,
      checkpoint_id: checkpoint.checkpoint_id || checkpoint.checkpointId,
      source_id: checkpoint.source_id || checkpoint.sourceId,
      start_sequence: checkpoint.start_sequence ?? 1,
      end_sequence: checkpoint.end_sequence ?? checkpoint.lastSequenceNumber,
      event_count: checkpoint.event_count ?? (checkpoint.merkle_leaf_hashes?.length || 1),
      merkle_root: checkpoint.merkle_root,
      merkle_leaf_hashes: checkpoint.merkle_leaf_hashes || [],
      timestamp: rawTimestamp,
      fss_epoch: checkpoint.fss_epoch ?? 0,
      epoch_public_key: checkpoint.epoch_public_key || checkpoint.publicKey,
      mpk: checkpoint.mpk,
      signature: checkpoint.signature || checkpoint.fss_signature,
      signature_algorithm: checkpoint.signature_algorithm || 'Ed25519-MKT-FSS',
      signature_input: checkpoint.signature_input || CHECKPOINT_FSS_SCHEMA_VERSION,
      fss_auth_path: checkpoint.fss_auth_path,
      fss_bundle: checkpoint.fss_bundle,
    };

    let trustedMpk = checkpoint.mpk;
    if (!trustedMpk) {
      try {
        trustedMpk = getFssStateManager().mpk;
      } catch {
        // Suppress if state not initialized
      }
    }

    const result = verifyCheckpoint(normalizedFssCheckpoint, trustedMpk);
    return {
      isValid: result.valid,
      status: result.status,
      failures: result.failures,
      checks: result.checks,
      error: result.valid ? null : result.failures.join('; '),
    };
  }

  // Legacy Checkpoint verification
  const timestampIso =
    checkpoint.timestamp instanceof Date
      ? checkpoint.timestamp.toISOString()
      : new Date(checkpoint.timestamp).toISOString();

  const payload = {
    checkpointId: checkpoint.checkpointId || checkpoint.checkpoint_id,
    sourceId: checkpoint.sourceId || checkpoint.source_id,
    lastSequenceNumber: Number(checkpoint.lastSequenceNumber ?? checkpoint.end_sequence),
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
 * Evolves the forward-secure signing state to the next epoch (t -> t + 1).
 */
export const evolveEpoch = async (authPathOverride = null) => {
  const manager = getFssStateManager();
  const nextEpoch = (manager.epoch ?? 0) + 1;
  let nextAuthPath = authPathOverride;

  if (!nextAuthPath) {
    const stateDir = process.env.FSS_STATE_DIR || join(process.cwd(), 'vault');
    const publicTreePath = process.env.FSS_PUBLIC_TREE_PATH || join(stateDir, 'fss_public_tree.json');
    if (fs.existsSync(publicTreePath)) {
      try {
        const tree = JSON.parse(fs.readFileSync(publicTreePath, 'utf8'));
        if (Array.isArray(tree.authPaths) && tree.authPaths[nextEpoch]) {
          nextAuthPath = tree.authPaths[nextEpoch];
        }
      } catch {
        // Suppress parsing error
      }
    }
  }

  const newState = manager.evolve(nextAuthPath);
  return {
    epoch: newState.epoch,
    mpk: manager.mpk,
  };
};

/**
 * Triggers emergency revocation: shreds active epoch key and records revocation notice.
 */
export const revokeKeyEmergency = async (options = {}) => {
  const manager = getFssStateManager();
  const notice = manager.revokeEmergency(options);
  return notice;
};

/**
 * Returns active forward-secure key status.
 */
export const getFssStatus = () => {
  const manager = getFssStateManager();
  return {
    mpk: manager.mpk,
    epoch: manager.epoch,
    currentEpoch: manager.epoch,
    maxEpochs: manager.maxEpochs,
    isRevoked: Boolean(manager.revocationNotice),
    revocationNotice: manager.revocationNotice,
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
  const query = Checkpoint.findOne({ sourceId });
  return query && typeof query.sort === 'function'
    ? query.sort({ end_sequence: -1, lastSequenceNumber: -1, createdAt: -1 })
    : query;
};

export {
  CHECKPOINT_FSS_SCHEMA_VERSION,
  CHECKPOINT_SCHEMA_VERSION,
  VerificationStatus,
};

export default {
  createCheckpoint,
  verifyCheckpointSignature,
  evolveEpoch,
  revokeKeyEmergency,
  getFssStatus,
  getFssStateManager,
  setFssStateManager,
  resetFssStateManager,
  getCheckpoints,
  getLatestCheckpoint,
  CHECKPOINT_FSS_SCHEMA_VERSION,
  CHECKPOINT_SCHEMA_VERSION,
  VerificationStatus,
};
