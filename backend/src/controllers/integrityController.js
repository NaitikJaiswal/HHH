import integrityService from '../services/integrityService.js';
import checkpointService from '../services/checkpointService.js';
import incidentService from '../services/incidentService.js';

/**
 * Retrieve active security alerts
 * GET /api/integrity/alerts
 */
export const getAlerts = async (req, res, next) => {
  try {
    const activeAlerts = await incidentService.getIncidents({ status: 'OPEN', limit: 50 });
    res.status(200).json({
      success: true,
      message: 'Active security alerts retrieved',
      data: activeAlerts,
    });
  } catch (error) {
    next(error);
  }
};

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

/**
 * Get active forward-secure signing key status
 * GET /api/integrity/fss/status
 */
export const getFssState = async (req, res, next) => {
  try {
    const status = checkpointService.getFssStatus();
    res.status(200).json({
      success: true,
      message: 'FSS key status retrieved',
      data: {
        ...status,
        version: 'HHH-MKT-FSS-v1',
        algorithm: 'Ed25519-MKT-FSS',
      },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Evolve FSS signing state to next epoch
 * POST /api/integrity/fss/evolve
 */
export const evolveFssEpoch = async (req, res, next) => {
  try {
    const result = await checkpointService.evolveEpoch();
    res.status(200).json({
      success: true,
      message: 'FSS epoch evolved successfully',
      data: result,
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Emergency key revocation
 * POST /api/integrity/fss/revoke
 */
export const revokeFssEmergency = async (req, res, next) => {
  try {
    const notice = await checkpointService.revokeKeyEmergency(req.body);
    res.status(200).json({
      success: true,
      message: 'Emergency revocation executed',
      data: notice,
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get Quai blockchain anchoring status and network info
 * GET /api/integrity/blockchain/status
 */
export const getBlockchainStatus = async (req, res, next) => {
  try {
    const status = {
      network: 'Quai Orchard Testnet',
      zone: 'cyprus1',
      chainId: 15000,
      rpcUrl: process.env.QUAI_RPC_URL || 'https://orchard.rpc.quai.network/cyprus1',
      contractAddress: process.env.QUAI_CONTRACT_ADDRESS || '0x0000000000000000000000000000000000000000',
      isLiveConfigured: Boolean(process.env.QUAI_RPC_URL),
      status: process.env.QUAI_RPC_URL ? 'ONLINE' : 'PREFLIGHT_STANDBY',
      explorerBaseUrl: 'https://quaiscan.io',
      lastAnchoredEpoch: checkpointService.getFssStatus()?.epoch ?? 0,
    };

    res.status(200).json({
      success: true,
      message: 'Quai anchoring status retrieved',
      data: status,
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
  getAlerts,
  getFssState,
  evolveFssEpoch,
  revokeFssEmergency,
  getBlockchainStatus,
};
