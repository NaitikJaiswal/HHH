import express from 'express';
import { getIncidentsList, getIncident, updateStatus } from '../controllers/incidentController.js';
import { protect } from '../middleware/authMiddleware.js';
import { authorizeRoles } from '../middleware/roleMiddleware.js';

const router = express.Router();

router.use(protect);

router.get('/', getIncidentsList);
router.get('/:id', getIncident);
router.patch('/:id/status', authorizeRoles('admin', 'security_analyst'), updateStatus);

export default router;
