/**
 * LOGN Evidence Retrieval Service
 *
 * Provides query capabilities across stored evidence bundles with
 * multi-criteria filtering (time range, source, event type, severity, keywords)
 * and automatic SHA-256 integrity verification.
 */

const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const StorageService = require('./storageService');

class LogRetriever {
  /**
   * @param {StorageService|string} storageOrDir - StorageService instance or vault root path.
   */
  constructor(storageOrDir) {
    if (typeof storageOrDir === 'string') {
      this.storage = new StorageService(storageOrDir);
    } else {
      this.storage = storageOrDir || new StorageService();
    }
  }

  /**
   * Search stored events matching specified query criteria.
   * @param {Object} query
   * @param {string} [query.sourceId] - Filter by source machine/host ID.
   * @param {string} [query.eventType] - Filter by event category (e.g. AUTHENTICATION).
   * @param {string} [query.severity] - Filter by severity level (e.g. WARNING, ERROR).
   * @param {string} [query.startTime] - ISO 8601 UTC start time.
   * @param {string} [query.endTime] - ISO 8601 UTC end time.
   * @param {string} [query.keyword] - Substring search in message or metadata.
   * @param {number} [query.limit=100] - Max events to return.
   * @param {number} [query.offset=0] - Offset for pagination.
   * @returns {Promise<Object>} Search results with matched events and metadata.
   */
  async queryLogs(query = {}) {
    const {
      sourceId,
      eventType,
      severity,
      startTime,
      endTime,
      keyword,
      limit = 100,
      offset = 0,
    } = query;

    const startMs = startTime ? new Date(startTime).getTime() : null;
    const endMs = endTime ? new Date(endTime).getTime() : null;
    const keywordLower = keyword ? String(keyword).toLowerCase() : null;

    const files = await this.storage.listAllBundleFiles();
    const matchedEvents = [];
    const corruptedFiles = [];

    for (const filePath of files) {
      let bundle;
      try {
        bundle = await this.storage.retrieveEvidenceByPath(filePath);
      } catch (err) {
        corruptedFiles.push({ path: filePath, error: err.message });
        continue;
      }

      if (!bundle || !Array.isArray(bundle.events)) continue;

      for (const ev of bundle.events) {
        // Source ID filter
        if (sourceId && ev.source_id !== sourceId) continue;

        // Event type filter
        if (eventType && ev.event_type !== eventType) continue;

        // Severity filter
        if (severity && ev.severity !== severity) continue;

        // Time range filter
        if (startMs !== null || endMs !== null) {
          const evTimeMs = ev.event_time ? new Date(ev.event_time).getTime() : null;
          if (evTimeMs !== null) {
            if (startMs !== null && evTimeMs < startMs) continue;
            if (endMs !== null && evTimeMs > endMs) continue;
          }
        }

        // Keyword filter in message or metadata
        if (keywordLower) {
          const msgMatch = ev.message && ev.message.toLowerCase().includes(keywordLower);
          const metaMatch = ev.metadata && JSON.stringify(ev.metadata).toLowerCase().includes(keywordLower);
          if (!msgMatch && !metaMatch) continue;
        }

        matchedEvents.push(ev);
      }
    }

    // Sort chronologically by sequence_number or event_time
    matchedEvents.sort((a, b) => {
      const tA = new Date(a.event_time || 0).getTime();
      const tB = new Date(b.event_time || 0).getTime();
      if (tA !== tB) return tA - tB;
      return (a.sequence_number || 0) - (b.sequence_number || 0);
    });

    const totalMatched = matchedEvents.length;
    const paginated = matchedEvents.slice(offset, offset + limit);

    return {
      total: totalMatched,
      count: paginated.length,
      offset,
      limit,
      events: paginated,
      corrupted_files: corruptedFiles,
    };
  }

  /**
   * Retrieve a specific bundle by its ID.
   * @param {string} bundleId
   * @returns {Promise<Object|null>}
   */
  async getBundle(bundleId) {
    return this.storage.findBundleById(bundleId);
  }
}

module.exports = LogRetriever;
