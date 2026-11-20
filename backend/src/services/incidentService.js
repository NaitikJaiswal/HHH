import Incident from '../models/Incident.js';
import AuditEvent from '../models/AuditEvent.js';
import Source from '../models/Source.js';
import { isDBConnected } from '../config/db.js';

/**
 * Creates a security incident and logs an audit trail event.
 * De-duplicates open incidents to avoid flood storms.
 */
export const createIncident = async ({
  type,
  severity = 'medium',
  sourceId,
  description,
  affectedEventIds = [],
  evidenceReference = null,
}) => {
  // Check for an existing open incident with identical type and source
  const existingOpen = await Incident.findOne({
    sourceId,
    type,
    status: { $in: ['OPEN', 'INVESTIGATING'] },
  });

  if (existingOpen) {
    // Merge affected events and return existing incident
    const combinedIds = Array.from(new Set([...existingOpen.affectedEventIds, ...affectedEventIds]));
    existingOpen.affectedEventIds = combinedIds;
    existingOpen.description = `${existingOpen.description} | Update: ${description}`;
    await existingOpen.save();
    return existingOpen;
  }

  const incidentId = `inc-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;

  const incident = await Incident.create({
    incidentId,
    type,
    severity,
    sourceId,
    description,
    affectedEventIds,
    evidenceReference,
    detectedAt: new Date(),
    status: 'OPEN',
  });

  // Record audit trail entry if connected or mocked
  if (isDBConnected() || AuditEvent.create?.mock) {
    await AuditEvent.create({
      actorId: 'system_integrity_engine',
      action: 'INCIDENT_CREATED',
      resource: `incident/${incidentId}`,
      result: 'SUCCESS',
      details: {
        type,
        severity,
        sourceId,
        incidentId,
      },
    });
  }

  return incident;
};

/**
 * Retrieve incidents with search filters and pagination
 */
export const getIncidents = async (query = {}) => {
  const page = Math.max(1, parseInt(query.page, 10) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(query.limit, 10) || 20));
  const skip = (page - 1) * limit;

  const filter = {};

  if (query.status) {
    filter.status = query.status;
  }
  if (query.severity) {
    filter.severity = query.severity;
  }
  if (query.sourceId) {
    filter.sourceId = query.sourceId;
  }
  if (query.type) {
    filter.type = query.type;
  }

  const [incidents, total] = await Promise.all([
    Incident.find(filter).sort({ detectedAt: -1 }).skip(skip).limit(limit).lean(),
    Incident.countDocuments(filter),
  ]);

  return {
    incidents,
    pagination: {
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit) || 1,
    },
  };
};

/**
 * Retrieve incident details by incidentId or _id
 */
export const getIncidentById = async (id) => {
  let incident = await Incident.findOne({ incidentId: id });
  if (!incident && id.match(/^[0-9a-fA-F]{24}$/)) {
    incident = await Incident.findById(id);
  }

  if (!incident) {
    const error = new Error(`Incident not found for ID: ${id}`);
    error.statusCode = 404;
    throw error;
  }

  return incident;
};

/**
 * Update incident status (e.g. from OPEN to INVESTIGATING or RESOLVED)
 */
export const updateIncidentStatus = async (id, { status, resolutionNotes = '', user = null }) => {
  const incident = await getIncidentById(id);

  if (!['OPEN', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'].includes(status)) {
    const error = new Error(`Invalid status: ${status}. Permitted: OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE`);
    error.statusCode = 400;
    throw error;
  }

  incident.status = status;
  if (resolutionNotes) {
    incident.resolutionNotes = resolutionNotes;
  }

  if (['RESOLVED', 'FALSE_POSITIVE'].includes(status)) {
    incident.resolvedBy = user?.email || user?.id || 'system';
    incident.resolvedAt = new Date();
  }

  await incident.save();

  // Audit trail
  await AuditEvent.create({
    actorId: user?.email || user?.id || 'system',
    action: 'INCIDENT_STATUS_UPDATED',
    resource: `incident/${incident.incidentId}`,
    result: 'SUCCESS',
    details: {
      newStatus: status,
      resolutionNotes,
    },
  });

  return incident;
};

/**
 * Evaluates collector heartbeats across all registered sources.
 * Triggers COLLECTOR_DISCONNECTED incidents for missing heartbeats.
 */
export const checkCollectorHeartbeats = async (thresholdMinutes = 2) => {
  const sources = await Source.find({}).lean();
  const disconnectedSources = [];
  const cutoffTime = new Date(Date.now() - thresholdMinutes * 60 * 1000);

  for (const src of sources) {
    const hasHeartbeat = src.lastHeartbeat && new Date(src.lastHeartbeat) >= cutoffTime;

    if (!hasHeartbeat) {
      disconnectedSources.push(src);

      // Mark source status as DISCONNECTED
      await Source.updateOne({ _id: src._id }, { $set: { status: 'DISCONNECTED' } });

      // Automatically generate a high-severity alert incident
      await createIncident({
        type: 'COLLECTOR_DISCONNECTED',
        severity: 'high',
        sourceId: src.sourceId,
        description: `Heartbeat telemetry interrupted for source '${src.name || src.sourceId}'. No heartbeat received since ${src.lastHeartbeat ? new Date(src.lastHeartbeat).toISOString() : 'initialization'}.`,
        affectedEventIds: [],
      });
    }
  }

  return {
    checkedSources: sources.length,
    disconnectedCount: disconnectedSources.length,
    disconnectedSources: disconnectedSources.map((s) => s.sourceId),
  };
};

export default {
  createIncident,
  getIncidents,
  getIncidentById,
  updateIncidentStatus,
  checkCollectorHeartbeats,
};
