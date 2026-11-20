/**
 * LOGN Multi-Vault Redundancy Storage Adapter
 *
 * Implements high-availability multi-vault storage:
 * - Writes synchronously to primary vault and replicates to secondary vault.
 * - Automatic failover to secondary replica if primary evidence is missing or corrupted.
 * - Reconciles and detects discrepancies across storage tiers.
 */

const StorageService = require('./storageService');

class MultiVaultStorage {
  /**
   * @param {string} primaryDir
   * @param {string} secondaryDir
   */
  constructor(primaryDir, secondaryDir) {
    this.primary = new StorageService(primaryDir);
    this.secondary = new StorageService(secondaryDir);
  }

  async init() {
    await this.primary.init();
    await this.secondary.init();
  }

  /**
   * Store bundle into primary vault and replicate to secondary vault.
   * @param {Object} bundle
   * @returns {Promise<Object>}
   */
  async storeEvidence(bundle) {
    const primaryRecord = await this.primary.storeEvidence(bundle);

    let secondaryRecord = null;
    let replicationError = null;

    try {
      secondaryRecord = await this.secondary.storeEvidence(bundle);
    } catch (err) {
      replicationError = err.message;
    }

    return {
      bundle_id: primaryRecord.bundle_id,
      primary: primaryRecord,
      secondary: secondaryRecord,
      replicated: secondaryRecord !== null,
      replication_error: replicationError,
    };
  }

  /**
   * Retrieve bundle with automatic failover to secondary vault if primary fails.
   * @param {string} bundleId
   * @returns {Promise<Object>}
   */
  async retrieveEvidence(bundleId) {
    let bundle = null;
    let sourceTier = 'primary';

    try {
      bundle = await this.primary.findBundleById(bundleId);
    } catch (primaryErr) {
      // Primary vault corrupted or failed
      bundle = null;
    }

    if (!bundle) {
      // Failover to secondary replica
      sourceTier = 'secondary';
      bundle = await this.secondary.findBundleById(bundleId);
    }

    if (!bundle) {
      throw new Error(`Evidence bundle '${bundleId}' not found in any vault tier`);
    }

    return {
      bundle,
      source_tier: sourceTier,
    };
  }

  /**
   * Check synchronization status across primary and secondary vaults.
   * @returns {Promise<Object>}
   */
  async reconcile() {
    const primaryFiles = await this.primary.listAllBundleFiles();
    const secondaryFiles = await this.secondary.listAllBundleFiles();

    const getFilename = p => require('path').basename(p);
    const primaryNames = new Set(primaryFiles.map(getFilename));
    const secondaryNames = new Set(secondaryFiles.map(getFilename));

    const missingInSecondary = [...primaryNames].filter(x => !secondaryNames.has(x));
    const missingInPrimary = [...secondaryNames].filter(x => !primaryNames.has(x));

    return {
      in_sync: missingInSecondary.length === 0 && missingInPrimary.length === 0,
      primary_count: primaryNames.size,
      secondary_count: secondaryNames.size,
      missing_in_secondary: missingInSecondary,
      missing_in_primary: missingInPrimary,
    };
  }
}

module.exports = MultiVaultStorage;
