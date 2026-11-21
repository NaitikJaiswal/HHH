/**
 * LOGN Secure Backup Service
 *
 * Creates compressed, tamper-evident backups of stored evidence bundles with
 * cryptographic verification and structured metadata manifests.
 */

const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');
const { promisify } = require('util');

const gzip = promisify(zlib.gzip);
const gunzip = promisify(zlib.gunzip);

class BackupService {
  /**
   * @param {string} backupDir - Directory for storing backup archives and manifests.
   */
  constructor(backupDir = path.join(process.cwd(), 'vault', 'backups')) {
    this.backupDir = path.resolve(backupDir);
  }

  /**
   * Initialize backup directory.
   */
  async init() {
    await fsp.mkdir(this.backupDir, { recursive: true });
  }

  /**
   * Calculate SHA-256 digest of a buffer.
   * @param {Buffer} buffer
   * @returns {string} Hex digest.
   */
  calculateChecksum(buffer) {
    return crypto.createHash('sha256').update(buffer).digest('hex');
  }

  /**
   * Create a compressed backup of a list of evidence bundle files.
   * @param {string[]} filePaths - Array of absolute file paths to evidence bundles.
   * @param {Object} options - Optional parameters (e.g. retention_days, tag).
   * @returns {Promise<Object>} Backup metadata manifest.
   */
  async createBackup(filePaths = [], options = {}) {
    await this.init();

    if (!Array.isArray(filePaths) || filePaths.length === 0) {
      throw new Error('No files provided for backup creation');
    }

    const backupId = options.backup_id || `backup_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    const archiveEntries = [];
    let totalUncompressedBytes = 0;

    for (const filePath of filePaths) {
      if (!fs.existsSync(filePath)) continue;
      const rawContent = await fsp.readFile(filePath, 'utf-8');
      const filename = path.basename(filePath);
      const size = Buffer.byteLength(rawContent, 'utf-8');
      totalUncompressedBytes += size;

      archiveEntries.push({
        filename,
        original_path: filePath,
        content: rawContent,
        sha256: crypto.createHash('sha256').update(rawContent).digest('hex'),
      });
    }

    if (archiveEntries.length === 0) {
      throw new Error('All specified backup source files were missing or unreadable');
    }

    const uncompressedData = JSON.stringify({
      backup_id: backupId,
      created_at: new Date().toISOString(),
      entries: archiveEntries,
    });

    const compressedBuffer = await gzip(Buffer.from(uncompressedData, 'utf-8'));
    const archiveChecksum = this.calculateChecksum(compressedBuffer);

    const archivePath = path.join(this.backupDir, `${backupId}.archive.gz`);
    const manifestPath = path.join(this.backupDir, `${backupId}.manifest.json`);

    await fsp.writeFile(archivePath, compressedBuffer);

    const manifest = {
      backup_id: backupId,
      created_at: new Date().toISOString(),
      file_count: archiveEntries.length,
      uncompressed_bytes: totalUncompressedBytes,
      compressed_bytes: compressedBuffer.length,
      archive_path: archivePath,
      sha256_checksum: archiveChecksum,
      retention_days: options.retention_days || 90,
      tag: options.tag || 'routine_backup',
      files: archiveEntries.map(e => ({ filename: e.filename, sha256: e.sha256 })),
    };

    await fsp.writeFile(manifestPath, JSON.stringify(manifest, null, 2), 'utf-8');
    return manifest;
  }

  /**
   * Verify the cryptographic and structural integrity of an existing backup archive.
   * @param {string} backupId
   * @returns {Promise<Object>} Verification report.
   */
  async verifyBackup(backupId) {
    const manifestPath = path.join(this.backupDir, `${backupId}.manifest.json`);
    const archivePath = path.join(this.backupDir, `${backupId}.archive.gz`);

    if (!fs.existsSync(manifestPath)) {
      return { valid: false, error: `Manifest not found for backup '${backupId}'` };
    }
    if (!fs.existsSync(archivePath)) {
      return { valid: false, error: `Archive file not found for backup '${backupId}'` };
    }

    const manifest = JSON.parse(await fsp.readFile(manifestPath, 'utf-8'));
    const archiveBuffer = await fsp.readFile(archivePath);

    // 1. Verify archive SHA-256 checksum
    const computedChecksum = this.calculateChecksum(archiveBuffer);
    if (computedChecksum !== manifest.sha256_checksum) {
      return {
        valid: false,
        error: `Archive checksum mismatch. Expected ${manifest.sha256_checksum}, computed ${computedChecksum}`,
      };
    }

    // 2. Verify decompression and inner file checksums
    try {
      const decompressed = await gunzip(archiveBuffer);
      const parsed = JSON.parse(decompressed.toString('utf-8'));

      if (!parsed.entries || parsed.entries.length !== manifest.file_count) {
        return {
          valid: false,
          error: `Entry count mismatch. Manifest: ${manifest.file_count}, Archive: ${parsed.entries ? parsed.entries.length : 0}`,
        };
      }

      for (const entry of parsed.entries) {
        const entryChecksum = crypto.createHash('sha256').update(entry.content).digest('hex');
        if (entryChecksum !== entry.sha256) {
          return {
            valid: false,
            error: `Corrupt entry in backup: ${entry.filename} checksum mismatch`,
          };
        }
      }

      return {
        valid: true,
        backup_id: backupId,
        verified_at: new Date().toISOString(),
        file_count: manifest.file_count,
        checksum: computedChecksum,
      };
    } catch (err) {
      return { valid: false, error: `Decompression or JSON parse failure: ${err.message}` };
    }
  }

  /**
   * List all available backup manifests.
   * @returns {Promise<Object[]>}
   */
  async listBackups() {
    await this.init();
    const files = await fsp.readdir(this.backupDir);
    const manifests = [];

    for (const f of files) {
      if (f.endsWith('.manifest.json')) {
        try {
          const content = await fsp.readFile(path.join(this.backupDir, f), 'utf-8');
          manifests.push(JSON.parse(content));
        } catch {
          // ignore corrupted manifest reads
        }
      }
    }

    return manifests.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  }
}

module.exports = BackupService;
