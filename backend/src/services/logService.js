import Log from '../models/Log.js';
import Source from '../models/Source.js';
import { generateLogHash } from '../utils/generateHash.js';
import { normalizeEvent } from '../validators/logValidator.js';

const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

// In-process lock map to prevent race conditions during concurrent log submissions per source
const sourceLocks = new Map();

const acquireLock = async (sourceId) => {
  while (sourceLocks.get(sourceId)) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  sourceLocks.set(sourceId, true);
};

const releaseLock = (sourceId) => {
  sourceLocks.delete(sourceId);
};

/**
 * Ingest a single log event with cryptographic hash chaining and idempotency protection
 */
export const ingestSingleLog = async (rawEvent, collectorId = null) => {
  const normalized = normalizeEvent(rawEvent, collectorId);
  const { eventId, sourceId, eventType, message, metadata, timestamp } = normalized;

  // 1. Idempotency Check: Prevent duplicate event ingestion
  const existingLog = await Log.findOne({ eventId });
  if (existingLog) {
    return {
      isDuplicate: true,
      log: existingLog,
      acknowledgedId: eventId,
    };
  }

  // 2. Concurrency Safety: Acquire source lock to guarantee atomic sequence numbers & hash chain
  await acquireLock(sourceId);

  try {
    // Re-check idempotency inside lock to prevent concurrent duplicates
    const lockedDuplicateCheck = await Log.findOne({ eventId });
    if (lockedDuplicateCheck) {
      return {
        isDuplicate: true,
        log: lockedDuplicateCheck,
        acknowledgedId: eventId,
      };
    }

    // 3. Find or initialize the source tracking record
    let source = await Source.findOne({ sourceId });
    if (!source) {
      source = await Source.create({
        sourceId,
        name: `Source ${sourceId}`,
        sourceType: 'application',
        status: 'ACTIVE',
        lastSequenceNumber: 0,
        lastHash: GENESIS_HASH,
        lastHeartbeat: new Date(),
      });
    }

    const nextSequence = (source.lastSequenceNumber || 0) + 1;
    const previousHash = source.lastHash || GENESIS_HASH;

    // 4. Compute deterministic SHA-256 hash
    const currentHash = generateLogHash({
      eventId,
      sourceId,
      sequenceNumber: nextSequence,
      timestamp,
      message,
      metadata,
      previousHash,
    });

    // 5. Persist Log record with server timestamp
    const logDoc = await Log.create({
      eventId,
      sourceId,
      eventType,
      message,
      metadata,
      timestamp,
      serverTimestamp: new Date(),
      sequenceNumber: nextSequence,
      previousHash,
      currentHash,
      verificationStatus: 'PENDING',
    });

    // 6. Update source head state atomically
    source.lastSequenceNumber = nextSequence;
    source.lastHash = currentHash;
    source.lastHeartbeat = new Date();
    await source.save();

    return {
      isDuplicate: false,
      log: logDoc,
      acknowledgedId: eventId,
    };
  } finally {
    releaseLock(sourceId);
  }
};

/**
 * Ingest a batch of log events (e.g. from Python collector)
 */
export const ingestLogBatch = async (batchPayload) => {
  const events = Array.isArray(batchPayload.events) ? batchPayload.events : [batchPayload];
  const collectorId = batchPayload.collector_id || batchPayload.collectorId || 'default_collector';

  const acknowledgedIds = [];
  const ingestedLogs = [];
  let duplicatesCount = 0;

  for (const ev of events) {
    const result = await ingestSingleLog(ev, collectorId);
    acknowledgedIds.push(result.acknowledgedId);

    if (result.isDuplicate) {
      duplicatesCount++;
    } else {
      ingestedLogs.push(result.log);
    }
  }

  return {
    acknowledged_ids: acknowledgedIds,
    ingestedCount: ingestedLogs.length,
    duplicatesCount,
    totalReceived: events.length,
  };
};

/**
 * Query and filter logs with pagination
 */
export const getLogs = async (query = {}) => {
  const page = Math.max(1, parseInt(query.page, 10) || 1);
  const limit = Math.min(200, Math.max(1, parseInt(query.limit, 10) || 20));
  const skip = (page - 1) * limit;

  const filter = {};

  if (query.sourceId) {
    filter.sourceId = query.sourceId;
  }

  if (query.eventType) {
    filter.eventType = query.eventType;
  }

  if (query.verificationStatus) {
    filter.verificationStatus = query.verificationStatus;
  }

  if (query.startDate || query.endDate) {
    filter.timestamp = {};
    if (query.startDate) filter.timestamp.$gte = new Date(query.startDate);
    if (query.endDate) filter.timestamp.$lte = new Date(query.endDate);
  }

  if (query.search) {
    filter.message = { $regex: query.search, $options: 'i' };
  }

  const [logs, total] = await Promise.all([
    Log.find(filter)
      .sort({ serverTimestamp: -1, sequenceNumber: -1 })
      .skip(skip)
      .limit(limit)
      .lean(),
    Log.countDocuments(filter),
  ]);

  return {
    logs,
    pagination: {
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit) || 1,
    },
  };
};

/**
 * Retrieve a single log by eventId or internal database _id
 */
export const getLogById = async (id) => {
  let log = await Log.findOne({ eventId: id });
  if (!log && id.match(/^[0-9a-fA-F]{24}$/)) {
    log = await Log.findById(id);
  }

  if (!log) {
    const error = new Error(`Log entry not found for identifier: ${id}`);
    error.statusCode = 404;
    throw error;
  }

  return log;
};

/**
 * Aggregate summary statistics for dashboard and telemetry
 */
export const getLogStats = async () => {
  const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);

  const [totalLogs, last24hLogs, byEventType, bySource, byStatus] = await Promise.all([
    Log.countDocuments(),
    Log.countDocuments({ serverTimestamp: { $gte: oneDayAgo } }),
    Log.aggregate([
      { $group: { _id: '$eventType', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
    ]),
    Log.aggregate([
      { $group: { _id: '$sourceId', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
    ]),
    Log.aggregate([
      { $group: { _id: '$verificationStatus', count: { $sum: 1 } } },
    ]),
  ]);

  return {
    totalLogs,
    last24hLogs,
    byEventType: byEventType.map((item) => ({ eventType: item._id, count: item.count })),
    bySource: bySource.map((item) => ({ sourceId: item._id, count: item.count })),
    byStatus: byStatus.map((item) => ({ status: item._id, count: item.count })),
  };
};

export default {
  ingestSingleLog,
  ingestLogBatch,
  getLogs,
  getLogById,
  getLogStats,
};
