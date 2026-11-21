import express from 'express';
import { createSource, getSources, recordHeartbeat } from '../controllers/sourceController.js';
import { protect } from '../middleware/authMiddleware.js';
import { authorizeRoles } from '../middleware/roleMiddleware.js';
import { authenticateCollector } from '../middleware/collectorAuthMiddleware.js';

const router = express.Router();

// Heartbeat endpoints (Collector authenticated via X-API-Key or Bearer token)
router.post('/heartbeat', authenticateCollector, recordHeartbeat);
router.post('/:id/heartbeat', authenticateCollector, recordHeartbeat);

// Source registry management (JWT protected for security analysts & admins)
router.post('/', protect, authorizeRoles('admin', 'security_analyst'), createSource);
router.get('/', protect, getSources);

export default router;
