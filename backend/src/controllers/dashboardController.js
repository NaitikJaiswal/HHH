import Log from '../models/Log.js';
import Source from '../models/Source.js';
import Incident from '../models/Incident.js';
import Checkpoint from '../models/Checkpoint.js';
import AuditEvent from '../models/AuditEvent.js';
import { getStorageConfig } from '../config/aws.js';

/**
 * Get aggregated dashboard statistics
 * GET /api/dashboard/stats
 */
export const getDashboardStats = async (req, res, next) => {
  try {
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);

    const [
      totalLogs,
      logs24h,
      totalSources,
      activeSources,
      openIncidents,
      criticalIncidents,
      totalCheckpoints,
      logsByEventType,
      incidentsBySeverity,
    ] = await Promise.all([
      Log.countDocuments(),
      Log.countDocuments({ serverTimestamp: { $gte: oneDayAgo } }),
      Source.countDocuments(),
      Source.countDocuments({ status: 'ACTIVE' }),
      Incident.countDocuments({ status: { $in: ['OPEN', 'INVESTIGATING'] } }),
      Incident.countDocuments({ status: { $in: ['OPEN', 'INVESTIGATING'] }, severity: 'critical' }),
      Checkpoint.countDocuments(),
      Log.aggregate([
        { $group: { _id: '$eventType', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 10 },
      ]),
      Incident.aggregate([
        { $match: { status: { $in: ['OPEN', 'INVESTIGATING'] } } },
        { $group: { _id: '$severity', count: { $sum: 1 } } },
      ]),
    ]);

    const storageConfig = getStorageConfig();

    let systemStatus = 'SECURE';
    if (criticalIncidents > 0) {
      systemStatus = 'COMPROMISED';
    } else if (openIncidents > 0) {
      systemStatus = 'WARNING';
    }

    res.status(200).json({
      success: true,
      message: 'Dashboard statistics retrieved successfully',
      data: {
        systemStatus,
        totalLogs,
        logs24h,
        totalSources,
        activeSources,
        openIncidents,
        criticalIncidents,
        totalCheckpoints,
        storageMode: storageConfig.isS3Active ? 'AWS_S3_OBJECT_LOCK' : 'MOCK_LOCAL_STORAGE',
        isStorageImmutable: storageConfig.isS3Active,
        byEventType: logsByEventType.map((item) => ({ eventType: item._id, count: item.count })),
        bySeverity: incidentsBySeverity.map((item) => ({ severity: item._id, count: item.count })),
        generatedAt: new Date().toISOString(),
      },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get recent activity feed (combining recent logs, incidents, checkpoints, and audits)
 * GET /api/dashboard/activity
 */
export const getDashboardActivity = async (req, res, next) => {
  try {
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit, 10) || 15));

    const [recentLogs, recentIncidents, recentCheckpoints] = await Promise.all([
      Log.find()
        .sort({ serverTimestamp: -1 })
        .limit(limit)
        .select('eventId sourceId eventType message serverTimestamp verificationStatus')
        .lean(),
      Incident.find()
        .sort({ detectedAt: -1 })
        .limit(limit)
        .select('incidentId type severity sourceId description detectedAt status')
        .lean(),
      Checkpoint.find()
        .sort({ createdAt: -1 })
        .limit(limit)
        .select('checkpointId sourceId lastSequenceNumber createdAt status')
        .lean(),
    ]);

    // Format into unified timeline feed
    const activities = [
      ...recentLogs.map((l) => ({
        id: l.eventId,
        category: 'LOG_INGESTED',
        sourceId: l.sourceId,
        title: `Log: ${l.eventType}`,
        description: l.message,
        timestamp: l.serverTimestamp,
        badge: l.verificationStatus,
      })),
      ...recentIncidents.map((i) => ({
        id: i.incidentId,
        category: 'SECURITY_INCIDENT',
        sourceId: i.sourceId,
        title: `Incident: ${i.type}`,
        description: i.description,
        timestamp: i.detectedAt,
        badge: i.severity.toUpperCase(),
      })),
      ...recentCheckpoints.map((c) => ({
        id: c.checkpointId,
        category: 'SIGNED_CHECKPOINT',
        sourceId: c.sourceId,
        title: `Checkpoint #${c.lastSequenceNumber}`,
        description: `Signed Ed25519 checkpoint for ${c.sourceId}`,
        timestamp: c.createdAt,
        badge: c.status,
      })),
    ];

    // Sort combined feed descending by timestamp
    activities.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    res.status(200).json({
      success: true,
      message: 'Dashboard activity timeline retrieved successfully',
      data: {
        activities: activities.slice(0, limit),
        totalActivities: activities.length,
      },
    });
  } catch (error) {
    next(error);
  }
};

export default {
  getDashboardStats,
  getDashboardActivity,
};
