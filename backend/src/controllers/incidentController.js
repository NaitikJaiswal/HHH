import incidentService from '../services/incidentService.js';

/**
 * Query security incidents with pagination and filters
 * GET /api/incidents
 */
export const getIncidentsList = async (req, res, next) => {
  try {
    const result = await incidentService.getIncidents(req.query);
    res.status(200).json({
      success: true,
      message: 'Incidents retrieved successfully',
      data: result,
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Retrieve individual incident details
 * GET /api/incidents/:id
 */
export const getIncident = async (req, res, next) => {
  try {
    const incident = await incidentService.getIncidentById(req.params.id);
    res.status(200).json({
      success: true,
      message: 'Incident details retrieved successfully',
      data: incident,
    });
  } catch (error) {
    res.status(error.statusCode || 500);
    next(error);
  }
};

/**
 * Update incident status (e.g. from OPEN to INVESTIGATING or RESOLVED)
 * PATCH /api/incidents/:id/status
 */
export const updateStatus = async (req, res, next) => {
  try {
    const { status, resolutionNotes } = req.body || {};
    if (!status) {
      return res.status(400).json({
        success: false,
        message: 'status field is required in request body',
      });
    }

    const updated = await incidentService.updateIncidentStatus(req.params.id, {
      status,
      resolutionNotes,
      user: req.user,
    });

    res.status(200).json({
      success: true,
      message: `Incident status updated to '${status}'`,
      data: updated,
    });
  } catch (error) {
    res.status(error.statusCode || 500);
    next(error);
  }
};

export default {
  getIncidentsList,
  getIncident,
  updateStatus,
};
