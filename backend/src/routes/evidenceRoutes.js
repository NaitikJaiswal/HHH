import express from 'express';
import { protect } from '../middleware/authMiddleware.js';
import Log from '../models/Log.js';
import Checkpoint from '../models/Checkpoint.js';
import { verifyEvidence } from '../../../cli/hhh.js';
import { GENESIS_HASH } from '../../../security/src/crypto/hashing.js';

const router = express.Router();

router.use(protect);

/**
 * GET /api/evidence
 * List available evidence bundles and packages
 */
router.get('/', async (req, res, next) => {
  try {
    const checkpoints = await Checkpoint.find()
      .sort({ createdAt: -1 })
      .limit(50)
      .lean();

    const evidenceList = checkpoints.map((cp, idx) => ({
      evidenceId: `EVD-${cp.checkpointId || cp._id}`,
      name: `Signed Checkpoint Docket (${cp.sourceId})`,
      category: 'EVIDENCE',
      sourceId: cp.sourceId,
      startSequence: cp.start_sequence || cp.lastSequenceNumber - (cp.event_count || 1) + 1,
      endSequence: cp.end_sequence || cp.lastSequenceNumber,
      eventCount: cp.event_count || 1,
      merkleRoot: cp.merkle_root || cp.chainHeadHash,
      signatureAlgorithm: cp.signature_algorithm || 'Ed25519-MKT-FSS',
      fssEpoch: cp.fss_epoch ?? 0,
      createdAt: cp.createdAt || cp.timestamp,
      status: cp.status || 'VERIFIED',
      isImmutable: true,
    }));

    res.status(200).json({
      success: true,
      message: 'Evidence packages retrieved successfully',
      data: evidenceList,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/evidence/package
 * Package sequences of logs and signed checkpoints into a sealed evidence bundle
 */
router.post('/package', async (req, res, next) => {
  try {
    const { sourceId, limit = 50 } = req.body || {};
    const filter = {};
    if (sourceId) filter.sourceId = sourceId;

    const [logs, checkpoints] = await Promise.all([
      Log.find(filter).sort({ sequenceNumber: 1 }).limit(Number(limit)).lean(),
      Checkpoint.find(filter).sort({ createdAt: 1 }).limit(10).lean(),
    ]);

    const bundleId = `BND-${Date.now()}-${Math.random().toString(36).substring(7)}`;
    const bundle = {
      schema_version: '1.0',
      bundle_id: bundleId,
      created_at: new Date().toISOString(),
      manifest: {
        bundle_id: bundleId,
        source_id: sourceId || 'all_sources',
        event_count: logs.length,
        checkpoint_count: checkpoints.length,
        first_sequence: logs[0]?.sequenceNumber ?? 0,
        last_sequence: logs[logs.length - 1]?.sequenceNumber ?? 0,
        genesis_hash: logs[0]?.previousHash || GENESIS_HASH,
        final_root_hash: logs[logs.length - 1]?.currentHash || GENESIS_HASH,
      },
      events: logs.map((l) => ({
        event_id: l.eventId || String(l._id),
        event_time: l.eventTime || l.serverTimestamp || l.timestamp,
        event_type: l.eventType,
        message: l.message,
        metadata: l.metadata || {},
        previous_hash: l.previousHash,
        sequence_number: l.sequenceNumber,
        severity: l.severity || l.level || 'INFO',
        source_id: l.sourceId,
        current_hash: l.currentHash,
      })),
      checkpoints: checkpoints.map((cp) => ({
        schema_version: cp.schema_version || 'logn-checkpoint-fss-v1',
        checkpoint_id: cp.checkpointId,
        source_id: cp.sourceId,
        start_sequence: cp.start_sequence || 1,
        end_sequence: cp.end_sequence || cp.lastSequenceNumber,
        event_count: cp.event_count || (cp.end_sequence - cp.start_sequence + 1),
        merkle_root: cp.merkle_root || cp.chainHeadHash,
        merkle_leaf_hashes: cp.merkle_leaf_hashes || [],
        signature: cp.signature,
        signature_algorithm: cp.signature_algorithm || 'Ed25519-MKT-FSS',
        fss_epoch: cp.fss_epoch ?? 0,
        mpk: cp.mpk,
        epoch_public_key: cp.epoch_public_key || cp.publicKey,
        fss_auth_path: cp.fss_auth_path || [],
        timestamp: cp.timestamp || cp.createdAt,
      })),
    };

    res.status(201).json({
      success: true,
      message: 'Evidence bundle packaged successfully',
      data: bundle,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/evidence/verify
 * Cryptographically verify an evidence bundle
 */
router.post('/verify', async (req, res, next) => {
  try {
    const bundle = req.body;
    if (!bundle || typeof bundle !== 'object') {
      return res.status(400).json({
        success: false,
        message: 'Evidence bundle is required',
      });
    }

    const verificationResult = verifyEvidence(bundle);

    res.status(200).json({
      success: true,
      message: 'Evidence bundle verification completed',
      data: verificationResult,
    });
  } catch (error) {
    next(error);
  }
});

export default router;
