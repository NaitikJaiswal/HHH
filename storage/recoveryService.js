/**
 * LOGN Evidence Recovery Service
 *
 * Implements safe, integrity-verified evidence recovery from backups:
 * - Verifies backup checksums and decompression before restoring.
 * - Prevents overwriting existing evidence without explicit confirmation.
 * - Reports missing or corrupted records.
 * - Generates persistent, immutable recovery audit logs.
 */

const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');
const { promisify } = require('util');

const gunzip = promisify(zlib.gunzip);

class RecoveryService {
  /**
   * @param {Object} backupService - BackupService instance.
   * @param {Object} storageService - StorageService instance.
   * @param {string} auditDir - Directory to store recovery audit records.
   */
  constructor(backupService, storageService, auditDir = path.join(process.cwd(), 'vault', 'recovery_audit')) {
    this.backupService = backupService;
    this.storageService = storageService;
    this.auditDir = path.resolve(auditDir);
  }

  async init() {
    await fsp.mkdir(this.auditDir, { recursive: true });
    if (this.storageService) {
      await this.storageService.init();
    }
  }

  /**
   * List all available backups with status.
   * @returns {Promise<Object[]>}
   */
  async listAvailableBackups() {
    return this.backupService.listBackups();
  }

  /**
   * Restore evidence files from a backup archive.
   * @param {string} backupId - ID of backup to restore.
   * @param {Object} options
   * @param {boolean} [options.overwrite=false] - Explicit permission to overwrite existing files.
   * @param {string} [options.targetDir] - Custom directory (defaults to storageService.baseDir).
   * @param {string} [options.operator='analyst'] - Identity of the investigator performing recovery.
   * @returns {Promise<Object>} Recovery operation report.
   */
  async restoreFromBackup(backupId, options = {}) {
    await this.init();

    const overwrite = Boolean(options.overwrite);
    const operator = String(options.operator || 'forensic_analyst');
    const targetDir = options.targetDir
      ? path.resolve(options.targetDir)
      : this.storageService.baseDir;

    await fsp.mkdir(targetDir, { recursive: true });

    // 1. Verify backup integrity before restoration
    const verification = await this.backupService.verifyBackup(backupId);
    if (!verification.valid) {
      throw new Error(`Cannot restore from backup '${backupId}': integrity check failed (${verification.error})`);
    }

    // 2. Read and decompress archive
    const manifestPath = path.join(this.backupService.backupDir, `${backupId}.manifest.json`);
    const archivePath = path.join(this.backupService.backupDir, `${backupId}.archive.gz`);

    const archiveBuffer = await fsp.readFile(archivePath);
    const decompressed = await gunzip(archiveBuffer);
    const archiveData = JSON.parse(decompressed.toString('utf-8'));

    const entries = archiveData.entries || [];
    const restoredFiles = [];
    const skippedFiles = [];
    const corruptedRecords = [];

    for (const entry of entries) {
      const destPath = path.join(targetDir, entry.filename);

      // Verify content integrity
      const computedHash = crypto.createHash('sha256').update(entry.content).digest('hex');
      if (computedHash !== entry.sha256) {
        corruptedRecords.push({
          filename: entry.filename,
          expected_sha256: entry.sha256,
          computed_sha256: computedHash,
        });
        continue;
      }

      // Check overwrite protection
      if (fs.existsSync(destPath) && !overwrite) {
        skippedFiles.push({
          filename: entry.filename,
          path: destPath,
          reason: 'File exists. Overwrite not confirmed.',
        });
        continue;
      }

      // Write restored bundle
      await fsp.writeFile(destPath, entry.content, 'utf-8');

      // Write sidecar checksum file
      const checksumPath = `${destPath}.sha256`;
      await fsp.writeFile(checksumPath, `${computedHash}  ${entry.filename}\n`, 'utf-8');

      restoredFiles.push({
        filename: entry.filename,
        path: destPath,
        sha256: computedHash,
        bytes: Buffer.byteLength(entry.content, 'utf-8'),
      });
    }

    // 3. Record recovery audit log
    const recoveryId = `rec_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    const auditRecord = {
      recovery_id: recoveryId,
      backup_id: backupId,
      restored_at: new Date().toISOString(),
      operator,
      target_dir: targetDir,
      overwrite_allowed: overwrite,
      total_in_backup: entries.length,
      restored_count: restoredFiles.length,
      skipped_count: skippedFiles.length,
      corrupted_count: corruptedRecords.length,
      restored_files: restoredFiles,
      skipped_files: skippedFiles,
      corrupted_records: corruptedRecords,
      status: corruptedRecords.length === 0 ? 'SUCCESS' : 'PARTIAL_SUCCESS_WITH_CORRUPTION',
    };

    const auditPath = path.join(this.auditDir, `${recoveryId}.audit.json`);
    await fsp.writeFile(auditPath, JSON.stringify(auditRecord, null, 2), 'utf-8');

    return {
      recovery_id: recoveryId,
      status: auditRecord.status,
      restored_count: restoredFiles.length,
      skipped_count: skippedFiles.length,
      corrupted_count: corruptedRecords.length,
      audit_file: auditPath,
      audit: auditRecord,
    };
  }

  /**
   * List all historical recovery audit records.
   * @returns {Promise<Object[]>}
   */
  async listRecoveryAuditLogs() {
    await this.init();
    const files = await fsp.readdir(this.auditDir);
    const logs = [];

    for (const f of files) {
      if (f.endsWith('.audit.json')) {
        try {
          const content = await fsp.readFile(path.join(this.auditDir, f), 'utf-8');
          logs.push(JSON.parse(content));
        } catch {
          // ignore unreadable
        }
      }
    }

    return logs.sort((a, b) => new Date(b.restored_at) - new Date(a.restored_at));
  }
}

module.exports = RecoveryService;
