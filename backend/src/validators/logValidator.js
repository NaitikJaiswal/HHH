/**
 * Normalizes an event item to ensure field consistency
 * Maps both snake_case and camelCase attributes into canonical backend format
 */
export const normalizeEvent = (rawEvent, fallbackSourceId = 'default_source') => {
  const eventTimeRaw = rawEvent.event_time || rawEvent.eventTime || rawEvent.timestamp;
  const parsedDate = eventTimeRaw ? new Date(eventTimeRaw) : new Date();
  const safeDate = isNaN(parsedDate.getTime()) ? new Date() : parsedDate;

  // Normalize severity to standard 5-level enum (DEBUG, INFO, WARNING, ERROR, CRITICAL)
  const rawSev = String(rawEvent.severity || rawEvent.level || 'INFO').trim().toUpperCase();
  const validSeverities = new Set(['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']);
  const severity = validSeverities.has(rawSev) ? rawSev : (rawSev === 'WARN' ? 'WARNING' : 'INFO');

  return {
    eventId: String(rawEvent.eventId || rawEvent.event_id || rawEvent.id || '').trim(),
    sourceId: String(rawEvent.sourceId || rawEvent.source_id || rawEvent.host_id || fallbackSourceId).trim(),
    eventType: String(rawEvent.eventType || rawEvent.event_type || 'SYSTEM_EVENT').trim().toUpperCase(),
    severity,
    message: String(rawEvent.message || rawEvent.msg || (typeof rawEvent === 'string' ? rawEvent : '')),
    metadata: (rawEvent.metadata && typeof rawEvent.metadata === 'object' && !Array.isArray(rawEvent.metadata))
      ? rawEvent.metadata
      : (rawEvent.details && typeof rawEvent.details === 'object' && !Array.isArray(rawEvent.details))
        ? rawEvent.details
        : {},
    timestamp: safeDate,
  };
};

/**
 * Validates incoming log ingestion payload (single event or batch)
 */
export const validateLogPayload = (payload) => {
  const errors = [];

  if (!payload || typeof payload !== 'object') {
    return { isValid: false, errors: ['Request body must be a valid JSON object.'] };
  }

  // Batch format: { collector_id, batch_size, events: [...] }
  if (Array.isArray(payload.events)) {
    if (payload.events.length === 0) {
      errors.push('The "events" batch array must contain at least one log event.');
    } else {
      payload.events.forEach((ev, idx) => {
        const norm = normalizeEvent(ev, payload.collector_id);
        if (!norm.eventId) {
          errors.push(`Event at index ${idx} is missing an "eventId" or "event_id".`);
        }
        if (!norm.message) {
          errors.push(`Event at index ${idx} is missing a "message".`);
        }
      });
    }
  } else {
    // Single event format
    const norm = normalizeEvent(payload);
    if (!norm.eventId) {
      errors.push('The log event must include an "eventId" or "event_id".');
    }
    if (!norm.message) {
      errors.push('The log event must include a "message".');
    }
    if (!norm.sourceId) {
      errors.push('The log event must include a "sourceId" or "source_id".');
    }
  }

  return {
    isValid: errors.length === 0,
    errors,
  };
};

export default {
  normalizeEvent,
  validateLogPayload,
};
