import express from 'express';
import {
  verifyIntegrity,
  getStatus,
  getCheckpointsList,
  createSourceCheckpoint,
} from '../controllers/integrityController.js';
import { protect } from '../middleware/authMiddleware.js';

const router = express.Router();

// All integrity endpoints require authenticated access
router.use(protect);

router.post('/verify', verifyIntegrity);
router.get('/status', getStatus);
router.get('/checkpoints', getCheckpointsList);
router.post('/checkpoints', createSourceCheckpoint);

export default router;
