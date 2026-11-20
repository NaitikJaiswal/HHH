/**
 * Normalizes an event item to ensure camelCase field consistency
 */
export const normalizeEvent = (rawEvent, fallbackSourceId = 'default_source') => {
  return {
    eventId: rawEvent.eventId || rawEvent.event_id || rawEvent.id,
    sourceId: rawEvent.sourceId || rawEvent.source_id || rawEvent.host_id || fallbackSourceId,
    eventType: rawEvent.eventType || rawEvent.event_type || 'SYSTEM_EVENT',
    message: rawEvent.message || rawEvent.msg || (typeof rawEvent === 'string' ? rawEvent : ''),
    metadata: rawEvent.metadata || rawEvent.details || {},
    timestamp: rawEvent.timestamp ? new Date(rawEvent.timestamp) : new Date(),
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
