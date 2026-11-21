import express from 'express';
import {
  verifyIntegrity,
  getStatus,
  getCheckpointsList,
  createSourceCheckpoint,
  getAlerts,
  getFssState,
  evolveFssEpoch,
  revokeFssEmergency,
  getBlockchainStatus,
} from '../controllers/integrityController.js';
import { protect } from '../middleware/authMiddleware.js';

const router = express.Router();

// All integrity endpoints require authenticated access
router.use(protect);

router.post('/verify', verifyIntegrity);
router.get('/status', getStatus);
router.get('/checkpoints', getCheckpointsList);
router.post('/checkpoints', createSourceCheckpoint);
router.get('/alerts', getAlerts);

// FSS and Blockchain endpoints
router.get('/fss/status', getFssState);
router.post('/fss/evolve', evolveFssEpoch);
router.post('/fss/revoke', revokeFssEmergency);
router.get('/blockchain/status', getBlockchainStatus);

export default router;
