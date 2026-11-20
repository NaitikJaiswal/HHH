/**
 * LOGN Secure Evidence Storage Service
 *
 * Implements reliable, atomic file persistence for evidence bundles with
 * SHA-256 integrity checksums, hierarchical directory sharding, and metadata indexing.
 */

const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const crypto = require('crypto');

class StorageService {
  /**
   * @param {string} baseDir - Root directory for storing evidence files.
   */
  constructor(baseDir = path.join(process.cwd(), 'vault', 'evidence')) {
    this.baseDir = path.resolve(baseDir);
  }

  /**
   * Initialize base storage directories.
   */
  async init() {
    await fsp.mkdir(this.baseDir, { recursive: true });
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
   * Atomically store an evidence bundle with checksum verification.
   * @param {Object} bundle - The evidence bundle dictionary.
   * @returns {Promise<Object>} Storage record with filepath and checksum.
   */
  async storeEvidence(bundle) {
    if (!bundle || typeof bundle !== 'object') {
      throw new Error('Evidence bundle must be an object');
    }

    const bundleId = bundle.bundle_id || crypto.randomUUID();
    const sourceId = (bundle.manifest && bundle.manifest.source_id) || 'unknown_source';
    const createdAt = bundle.created_at || new Date().toISOString();
    const dateStr = createdAt.slice(0, 10); // YYYY-MM-DD

    const targetPath = this.getBundlePath(sourceId, dateStr, bundleId);
    const targetDir = path.dirname(targetPath);
    await fsp.mkdir(targetDir, { recursive: true });

    const contentStr = JSON.stringify(bundle, null, 2);
    const checksum = this.calculateChecksum(contentStr);

    // Atomic write: write to .tmp file then rename
    const tempPath = `${targetPath}.${Date.now()}.tmp`;
    await fsp.writeFile(tempPath, contentStr, 'utf-8');
    await fsp.rename(tempPath, targetPath);

    // Write sidecar checksum file (.sha256)
    const checksumPath = `${targetPath}.sha256`;
    await fsp.writeFile(checksumPath, `${checksum}  ${path.basename(targetPath)}\n`, 'utf-8');

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
   * @param {string} filePath - Absolute path to the bundle file.
   * @returns {Promise<Object>} The parsed evidence bundle.
   */
  async retrieveEvidenceByPath(filePath) {
    if (!fs.existsSync(filePath)) {
      throw new Error(`Evidence file not found: ${filePath}`);
    }

    const content = await fsp.readFile(filePath, 'utf-8');
    const computedChecksum = this.calculateChecksum(content);

    const checksumPath = `${filePath}.sha256`;
    if (fs.existsSync(checksumPath)) {
      const storedChecksumContent = await fsp.readFile(checksumPath, 'utf-8');
      const expectedChecksum = storedChecksumContent.trim().split(/\s+/)[0];
      if (expectedChecksum && expectedChecksum !== computedChecksum) {
        throw new Error(
          `Integrity violation for ${filePath}: checksum mismatch. Expected ${expectedChecksum}, computed ${computedChecksum}`
        );
      }
    }

    return JSON.parse(content);
  }

  /**
   * Find an evidence bundle by bundle ID across the vault.
   * @param {string} bundleId
   * @returns {Promise<Object|null>} Found bundle object or null.
   */
  async findBundleById(bundleId) {
    const filename = `${bundleId}.json`;
    const files = await this.listAllBundleFiles();
    const match = files.find(f => path.basename(f) === filename);
    if (!match) return null;
    return this.retrieveEvidenceByPath(match);
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
}

module.exports = StorageService;
