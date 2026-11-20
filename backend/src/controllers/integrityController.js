import integrityService from '../services/integrityService.js';
import checkpointService from '../services/checkpointService.js';

/**
 * Trigger an on-demand cryptographic verification audit
 * POST /api/integrity/verify
 */
export const verifyIntegrity = async (req, res, next) => {
  try {
    const { sourceId } = req.body || {};
    const report = sourceId
      ? await integrityService.verifySourceHashChain(sourceId)
      : await integrityService.verifyAllSources();

    res.status(200).json({
      success: true,
      message: 'Cryptographic integrity audit completed',
      data: report,
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Retrieve high-level integrity status
 * GET /api/integrity/status
 */
export const getStatus = async (req, res, next) => {
  try {
    const status = await integrityService.verifyAllSources();
    res.status(200).json({
      success: true,
      message: 'System integrity status retrieved',
      data: status,
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Retrieve list of signed checkpoints
 * GET /api/integrity/checkpoints
 */
export const getCheckpointsList = async (req, res, next) => {
  try {
    const result = await checkpointService.getCheckpoints(req.query);
    res.status(200).json({
      success: true,
      message: 'Signed checkpoints retrieved successfully',
      data: result,
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Manually generate a signed checkpoint for a source
 * POST /api/integrity/checkpoints
 */
export const createSourceCheckpoint = async (req, res, next) => {
  try {
    const { sourceId } = req.body || {};
    if (!sourceId) {
      return res.status(400).json({
        success: false,
        message: 'sourceId is required to generate a signed checkpoint',
      });
    }

    const checkpoint = await checkpointService.createCheckpoint(sourceId);
    res.status(201).json({
      success: true,
      message: 'Signed Ed25519 checkpoint created successfully',
      data: checkpoint,
    });
  } catch (error) {
    next(error);
  }
};

export default {
  verifyIntegrity,
  getStatus,
  getCheckpointsList,
  createSourceCheckpoint,
};
