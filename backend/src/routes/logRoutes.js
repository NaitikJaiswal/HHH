import express from 'express';
import { ingestLogs, getLogs, getLogDetails, getStats } from '../controllers/logController.js';
import { protect } from '../middleware/authMiddleware.js';
import { authenticateCollector } from '../middleware/collectorAuthMiddleware.js';
import { validate } from '../middleware/validateMiddleware.js';
import { validateLogPayload } from '../validators/logValidator.js';

const router = express.Router();

// Ingest logs: Accepts API key or authenticated user token
router.post('/', authenticateCollector, validate(validateLogPayload), ingestLogs);
router.post('/ingest', authenticateCollector, validate(validateLogPayload), ingestLogs);

// Query stats: Protected for authenticated users (analysts, auditors, admins)
router.get('/stats', protect, getStats);

// Search & list logs: Protected
router.get('/', protect, getLogs);

// Get single log: Protected
router.get('/:id', protect, getLogDetails);

export default router;
