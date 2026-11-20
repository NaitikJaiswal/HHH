import crypto from 'crypto';
import Source from '../models/Source.js';

/**
 * Register a new log source
 * POST /api/sources
 */
export const createSource = async (req, res, next) => {
  try {
    const { sourceId, name, sourceType = 'application', metadata = {} } = req.body || {};

    if (!sourceId || !name) {
      return res.status(400).json({
        success: false,
        message: 'Both sourceId and name are required.',
      });
    }

    const existing = await Source.findOne({ sourceId });
    if (existing) {
      return res.status(400).json({
        success: false,
        message: `Source with sourceId '${sourceId}' already exists.`,
      });
    }

    // Generate dedicated collector API key for this source
    const apiKey = `sec_${crypto.randomBytes(24).toString('hex')}`;

    const source = await Source.create({
      sourceId: sourceId.trim(),
      name: name.trim(),
      sourceType,
      apiKey,
      status: 'ACTIVE',
      lastSequenceNumber: 0,
      lastHash: '0000000000000000000000000000000000000000000000000000000000000000',
      lastHeartbeat: new Date(),
      metadata,
    });

    res.status(201).json({
      success: true,
      message: 'Log source registered successfully',
      data: {
        sourceId: source.sourceId,
        name: source.name,
        sourceType: source.sourceType,
        apiKey, // Exposed once at creation for collector configuration
        status: source.status,
        createdAt: source.createdAt,
      },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * List all registered sources
 * GET /api/sources
 */
export const getSources = async (req, res, next) => {
  try {
    const sources = await Source.find()
      .select('sourceId name sourceType status lastSequenceNumber lastHash lastHeartbeat createdAt updatedAt')
      .sort({ createdAt: -1 })
      .lean();

    res.status(200).json({
      success: true,
      message: 'Log sources retrieved successfully',
      data: {
        sources,
        total: sources.length,
      },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Process collector heartbeat telemetry
 * POST /api/sources/:id/heartbeat or POST /api/sources/heartbeat
 */
export const recordHeartbeat = async (req, res, next) => {
  try {
    const targetSourceId = req.params.id || req.body.host_id || req.body.collector_id || req.collector?.id;

    if (!targetSourceId) {
      return res.status(400).json({
        success: false,
        message: 'Unable to determine source identifier for heartbeat telemetry.',
      });
    }

    let source = await Source.findOne({ sourceId: targetSourceId });

    if (!source) {
      // Auto-provision source on first heartbeat if collector credentials are valid
      source = await Source.create({
        sourceId: targetSourceId,
        name: req.body.host_id ? `Host ${req.body.host_id}` : `Collector ${targetSourceId}`,
        sourceType: 'application',
        status: req.body.status === 'DEGRADED' ? 'DEGRADED' : 'ACTIVE',
        lastHeartbeat: new Date(),
      });
    } else {
      source.lastHeartbeat = new Date();
      source.status = req.body.status === 'DEGRADED' ? 'DEGRADED' : 'ACTIVE';
      if (req.body.last_delivered_sequence && req.body.last_delivered_sequence > (source.lastSequenceNumber || 0)) {
        source.lastSequenceNumber = req.body.last_delivered_sequence;
      }
      await source.save();
    }

    res.status(200).json({
      success: true,
      message: 'Heartbeat acknowledged',
      data: {
        sourceId: source.sourceId,
        status: source.status,
        lastHeartbeat: source.lastHeartbeat,
      },
    });
  } catch (error) {
    next(error);
  }
};

export default {
  createSource,
  getSources,
  recordHeartbeat,
};
