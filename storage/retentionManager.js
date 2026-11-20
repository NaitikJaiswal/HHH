/**
 * LOGN Retention Policy Manager
 *
 * Enforces automated evidence and backup lifecycle policies while
 * protecting evidence under legal hold or active forensic investigation.
 */

const fs = require('fs');
const fsp = fs.promises;
const path = require('path');

class RetentionManager {
  /**
   * @param {Object} options
   * @param {number} options.defaultRetentionDays - Default retention duration (default 90).
   * @param {string} options.holdsFile - Path to persistent legal holds record.
   */
  constructor(options = {}) {
    this.defaultRetentionDays = options.defaultRetentionDays || 90;
    this.holds = new Map(); // bundleId -> { reason, added_at }
  }

  /**
   * Place an evidence bundle under legal hold, preventing purge regardless of age.
   * @param {string} bundleId
   * @param {string} reason
   */
  addLegalHold(bundleId, reason = 'Active Forensic Investigation') {
    this.holds.set(bundleId, {
      reason,
      added_at: new Date().toISOString(),
    });
  }

  /**
   * Remove a legal hold.
   * @param {string} bundleId
   */
  removeLegalHold(bundleId) {
    this.holds.delete(bundleId);
  }

  /**
   * Check if a bundle is currently under legal hold.
   * @param {string} bundleId
   * @returns {boolean}
   */
  isUnderLegalHold(bundleId) {
    return this.holds.has(bundleId);
  }

  /**
   * Apply retention policy across all files in a StorageService vault.
   * @param {Object} storageService
   * @param {Object} options
   * @returns {Promise<Object>} Execution report.
   */
  async applyRetention(storageService, options = {}) {
    const retentionDays = options.retentionDays || this.defaultRetentionDays;
    const now = options.referenceDate ? new Date(options.referenceDate) : new Date();
    const cutoffTime = now.getTime() - retentionDays * 24 * 60 * 60 * 1000;

    const files = await storageService.listAllBundleFiles();
    const results = {
      scanned_count: files.length,
      purged_count: 0,
      preserved_under_hold: 0,
      active_count: 0,
      purged_files: [],
    };

    for (const filePath of files) {
      const filename = path.basename(filePath);
      const bundleId = filename.replace(/\.json$/, '');

      // 1. Check legal hold
      if (this.isUnderLegalHold(bundleId)) {
        results.preserved_under_hold += 1;
        continue;
      }

      // 2. Check file modification / creation time
      const stats = await fsp.stat(filePath);
      if (stats.mtimeMs < cutoffTime) {
        // Expired and not under legal hold: purge safely
        await fsp.unlink(filePath);
        const checksumPath = `${filePath}.sha256`;
        if (fs.existsSync(checksumPath)) {
          await fsp.unlink(checksumPath);
        }
        results.purged_count += 1;
        results.purged_files.push(filename);
      } else {
        results.active_count += 1;
      }
    }

    return results;
  }
}

module.exports = RetentionManager;
