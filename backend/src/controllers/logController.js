import logService from '../services/logService.js';

/**
 * Handle log ingestion (from Python collector or authorized apps)
 * POST /api/logs
 */
export const ingestLogs = async (req, res, next) => {
  try {
    const isBatch = Array.isArray(req.body.events);
    const result = isBatch
      ? await logService.ingestLogBatch(req.body)
      : await logService.ingestSingleLog(req.body, req.collector?.id);

    const acknowledged_ids = isBatch ? result.acknowledged_ids : [result.acknowledgedId];

    res.status(201).json({
      success: true,
      status: 'success',
      message: 'Log record(s) processed and chained successfully',
      acknowledged_ids,
      data: {
        acknowledged_ids,
        ...(isBatch ? result : { log: result.log, isDuplicate: result.isDuplicate }),
      },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Query logs with pagination and search filters
 * GET /api/logs
 */
export const getLogs = async (req, res, next) => {
  try {
    const result = await logService.getLogs(req.query);
    res.status(200).json({
      success: true,
      message: 'Logs retrieved successfully',
      data: result,
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Retrieve individual log details by ID or eventId
 * GET /api/logs/:id
 */
export const getLogDetails = async (req, res, next) => {
  try {
    const log = await logService.getLogById(req.params.id);
    res.status(200).json({
      success: true,
      message: 'Log details retrieved successfully',
      data: log,
    });
  } catch (error) {
    res.status(error.statusCode || 500);
    next(error);
  }
};

/**
 * Retrieve log statistics and telemetry
 * GET /api/logs/stats
 */
export const getStats = async (req, res, next) => {
  try {
    const stats = await logService.getLogStats();
    res.status(200).json({
      success: true,
      message: 'Log statistics retrieved successfully',
      data: stats,
    });
  } catch (error) {
    next(error);
  }
};

export default {
  ingestLogs,
  getLogs,
  getLogDetails,
  getStats,
};
