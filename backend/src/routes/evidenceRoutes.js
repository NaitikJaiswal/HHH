/**
 * @file evidenceRoutes.js
 * @description REST API endpoints for evidence packaging, verification, and retrieval.
 */

import express from 'express';
import { protect } from '../middleware/authMiddleware.js';
import evidenceService from '../services/evidenceService.js';
import Checkpoint from '../models/Checkpoint.js';

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

    const evidenceList = checkpoints.map((cp) => ({
      evidenceId: `EVD-${cp.checkpointId || cp._id}`,
      checkpointId: cp.checkpointId,
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
      custody: [
        'Operator Ingest (Web Crypto Hash Sealed)',
        'Evidence Enclave Vault (FSS Epoch Bound)',
        'Quai Blockchain Anchor (Cyprus-1 Testnet)',
      ],
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
    const { sourceId, startSequence, endSequence, limit, notes } = req.body || {};
    const investigator = req.user?.username || req.user?.email || 'HHH Forensic Lead';

    const result = await evidenceService.packageEvidence({
      sourceId,
      startSequence,
      endSequence,
      limit,
      investigator,
      notes,
    });

    res.status(201).json({
      success: true,
      message: 'Evidence bundle packaged and sealed successfully',
      data: result.bundle,
      files: result.files,
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

    const verificationResult = evidenceService.verifyEvidence(bundle);

    res.status(200).json({
      success: true,
      message: 'Evidence bundle verification completed',
      data: verificationResult,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/evidence/:id/download
 * Download packaged evidence archive / bundle JSON
 */
router.get('/:id/download', async (req, res, next) => {
  try {
    const { id } = req.params;
    const investigator = req.user?.username || 'HHH Auditor';

    const result = await evidenceService.packageEvidence({
      sourceId: id.startsWith('EVD-') ? undefined : id,
      limit: 100,
      investigator,
    });

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${id}_evidence.json"`);
    res.status(200).send(JSON.stringify(result.bundle, null, 2));
  } catch (error) {
    next(error);
  }
});

export default router;
