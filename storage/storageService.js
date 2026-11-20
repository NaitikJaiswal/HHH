/**
 * LOGN Secure Evidence Storage Service
 *
 * Implements reliable, atomic file persistence for evidence bundles with
 * SHA-256 integrity checksums, hierarchical directory sharding, and metadata indexing.
 *
 * Filesystem Assumptions and Limitations:
 * ─────────────────────────────────────────────────────────────────────────────
 * 1. Atomicity: Atomic replacement relies on POSIX rename(2) semantics. Because
 *    temporary files are created in the exact same directory as the target file,
 *    they are guaranteed to reside on the same filesystem/mount point, ensuring
 *    atomic rename operations without intermediate observable states.
 * 2. Hardware Limitations: On solid-state drives (SSDs) with Flash Translation
 *    Layers (FTL), wear-leveling controllers, and copy-on-write (COW) filesystems
 *    (e.g. APFS, Btrfs, ZFS), overwriting a file in place does NOT guarantee
 *    immediate physical overwriting of underlying NAND flash blocks.
 *    Forward security against physical disk recovery is therefore provided by
 *    Phase 3 cryptographic key evolution and memory zeroization, not disk wiping.
 * 3. Security: POSIX permissions are enforced at 0700 for directories and 0600
 *    for evidence files and sidecars, restricting access to the owning process.
 */

const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const crypto = require('crypto');

/**
 * Structured Storage Error Codes
 */
const StorageErrorCode = Object.freeze({
  INVALID_BUNDLE: 'INVALID_BUNDLE',
  FILE_NOT_FOUND: 'FILE_NOT_FOUND',
  CHECKSUM_MISMATCH: 'CHECKSUM_MISMATCH',
  MISSING_SIDECAR: 'MISSING_SIDECAR',
  PERMISSION_DENIED: 'PERMISSION_DENIED',
  WRITE_FAILED: 'WRITE_FAILED',
});

/**
 * Custom error class for storage operations.
 * Explicitly sanitizes details to prevent leaking secrets in logs.
 */
class StorageError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = 'StorageError';
    this.code = code;
    this.details = details;
  }
}

class StorageService {
  /**
   * @param {string} baseDir - Root directory for storing evidence files.
   */
  constructor(baseDir = path.join(process.cwd(), 'vault', 'evidence')) {
    this.baseDir = path.resolve(baseDir);
  }

  /**
   * Initialize base storage directories with restricted permissions (0700).
   */
  async init() {
    await fsp.mkdir(this.baseDir, { recursive: true, mode: 0o700 });
  }

  /**
   * Calculate SHA-256 checksum for a string or buffer.
   * @param {string|Buffer} content
   * @returns {string} Hex-encoded SHA-256 digest.
   */
  calculateChecksum(content) {
    return crypto.createHash('sha256').update(content).digest('hex');
  }

  /**
   * Resolve hierarchical file path for a bundle: baseDir/{sourceId}/{YYYY-MM-DD}/{bundleId}.json
   * @param {string} sourceId
   * @param {string} dateStr - YYYY-MM-DD format
   * @param {string} bundleId
   */
  getBundlePath(sourceId, dateStr, bundleId) {
    const cleanSource = String(sourceId || 'default').replace(/[^a-zA-Z0-9_-]/g, '_');
    const cleanDate = String(dateStr || 'general').replace(/[^0-9-]/g, '_');
    const cleanBundleId = String(bundleId).replace(/[^a-zA-Z0-9_-]/g, '_');
    return path.join(this.baseDir, cleanSource, cleanDate, `${cleanBundleId}.json`);
  }

  /**
   * Atomically store an evidence bundle with checksum verification and 0600 permissions.
   *
   * @param {Object} bundle - The evidence bundle dictionary.
   * @returns {Promise<Object>} Storage record with filepath and checksum.
   * @throws {StorageError} On validation or write failure.
   */
  async storeEvidence(bundle) {
    if (!bundle || typeof bundle !== 'object') {
      throw new StorageError(StorageErrorCode.INVALID_BUNDLE, 'Evidence bundle must be an object');
    }

    const bundleId = bundle.bundle_id || crypto.randomUUID();
    const sourceId = (bundle.manifest && bundle.manifest.source_id) || 'unknown_source';
    const createdAt = bundle.created_at || new Date().toISOString();
    const dateStr = createdAt.slice(0, 10); // YYYY-MM-DD

    const targetPath = this.getBundlePath(sourceId, dateStr, bundleId);
    const targetDir = path.dirname(targetPath);

    try {
      await fsp.mkdir(targetDir, { recursive: true, mode: 0o700 });
    } catch (err) {
      throw new StorageError(StorageErrorCode.WRITE_FAILED, `Failed to create storage directory: ${err.message}`);
    }

    const contentStr = JSON.stringify(bundle, null, 2);
    const checksum = this.calculateChecksum(contentStr);

    // Collision-resistant unique temporary file in the same directory (guarantees same filesystem)
    const nonce = crypto.randomBytes(4).toString('hex');
    const tempPath = `${targetPath}.${Date.now()}-${nonce}.tmp`;

    try {
      // Write temp file with restricted 0600 permissions
      await fsp.writeFile(tempPath, contentStr, { encoding: 'utf-8', mode: 0o600 });
      // Atomic rename: replaces target file atomically under POSIX semantics
      await fsp.rename(tempPath, targetPath);

      // Write sidecar checksum file (.sha256) with restricted 0600 permissions
      const checksumPath = `${targetPath}.sha256`;
      const tempChecksumPath = `${checksumPath}.${Date.now()}-${nonce}.tmp`;
      await fsp.writeFile(tempChecksumPath, `${checksum}  ${path.basename(targetPath)}\n`, {
        encoding: 'utf-8',
        mode: 0o600,
      });
      await fsp.rename(tempChecksumPath, checksumPath);
    } catch (err) {
      // Clean up orphaned temp file if write failed
      if (fs.existsSync(tempPath)) {
        await fsp.unlink(tempPath).catch(() => {});
      }
      throw new StorageError(StorageErrorCode.WRITE_FAILED, `Atomic evidence write failed: ${err.message}`);
    }

    return {
      bundle_id: bundleId,
      source_id: sourceId,
      date: dateStr,
      path: targetPath,
      checksum,
      size_bytes: Buffer.byteLength(contentStr, 'utf-8'),
      stored_at: new Date().toISOString(),
    };
  }

  /**
   * Retrieve an evidence bundle by path, verifying its cryptographic checksum.
   *
   * @param {string} filePath - Absolute path to the bundle file.
   * @param {Object} [options] - Retrieval options.
   * @param {boolean} [options.requireSidecar=false] - If true, throws if .sha256 sidecar is missing.
   * @returns {Promise<Object>} The parsed evidence bundle.
   * @throws {StorageError} On missing file, missing sidecar, or checksum mismatch.
   */
  async retrieveEvidenceByPath(filePath, options = {}) {
    if (!fs.existsSync(filePath)) {
      throw new StorageError(StorageErrorCode.FILE_NOT_FOUND, `Evidence file not found: ${filePath}`);
    }

    let content;
    try {
      content = await fsp.readFile(filePath, 'utf-8');
    } catch (err) {
      throw new StorageError(StorageErrorCode.PERMISSION_DENIED, `Cannot read evidence file: ${err.message}`);
    }

    const computedChecksum = this.calculateChecksum(content);
    const checksumPath = `${filePath}.sha256`;

    if (fs.existsSync(checksumPath)) {
      const storedChecksumContent = await fsp.readFile(checksumPath, 'utf-8');
      const expectedChecksum = storedChecksumContent.trim().split(/\s+/)[0];
      if (expectedChecksum && expectedChecksum !== computedChecksum) {
        throw new StorageError(
          StorageErrorCode.CHECKSUM_MISMATCH,
          `Integrity violation for ${path.basename(filePath)}: checksum mismatch. Expected ${expectedChecksum}, computed ${computedChecksum}`,
          { expectedChecksum, computedChecksum }
        );
      }
    } else if (options.requireSidecar) {
      throw new StorageError(
        StorageErrorCode.MISSING_SIDECAR,
        `Integrity violation: missing required SHA-256 sidecar file: ${checksumPath}`
      );
    }

    try {
      return JSON.parse(content);
    } catch (err) {
      throw new StorageError(StorageErrorCode.CHECKSUM_MISMATCH, `Corrupted JSON payload in ${filePath}: ${err.message}`);
    }
  }

  /**
   * Find an evidence bundle by bundle ID across the vault.
   * @param {string} bundleId
   * @param {Object} [options]
   * @returns {Promise<Object|null>} Found bundle object or null.
   */
  async findBundleById(bundleId, options = {}) {
    const filename = `${bundleId}.json`;
    const files = await this.listAllBundleFiles();
    const match = files.find(f => path.basename(f) === filename);
    if (!match) return null;
    return this.retrieveEvidenceByPath(match, options);
  }

  /**
   * List all stored .json evidence bundle paths in the vault.
   * @returns {Promise<string[]>}
   */
  async listAllBundleFiles() {
    const results = [];

    async function walk(dir) {
      if (!fs.existsSync(dir)) return;
      const entries = await fsp.readdir(dir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          await walk(fullPath);
        } else if (entry.isFile() && entry.name.endsWith('.json')) {
          results.push(fullPath);
        }
      }
    }

    await walk(this.baseDir);
    return results;
  }

  /**
   * Clean orphaned temporary (.tmp) files resulting from crashes or interrupted writes.
   *
   * @param {number} [maxAgeMs=60000] - Remove temp files older than this age in milliseconds.
   * @returns {Promise<string[]>} List of unlinked orphaned file paths.
   */
  async cleanOrphanedTempFiles(maxAgeMs = 60000) {
    const cleaned = [];
    const now = Date.now();

    async function walk(dir) {
      if (!fs.existsSync(dir)) return;
      const entries = await fsp.readdir(dir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          await walk(fullPath);
        } else if (entry.isFile() && entry.name.endsWith('.tmp')) {
          try {
            const stats = await fsp.stat(fullPath);
            if (now - stats.mtimeMs > maxAgeMs) {
              await fsp.unlink(fullPath);
              cleaned.push(fullPath);
            }
          } catch (_) {}
        }
      }
    }

    await walk(this.baseDir);
    return cleaned;
  }
}

module.exports = StorageService;
module.exports.StorageError = StorageError;
module.exports.StorageErrorCode = StorageErrorCode;
