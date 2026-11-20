/**
 * Unit tests for LOGN Storage, Backup, Multi-Vault, and Retention
 * Executed via Node.js native test runner: node --test tests/test_storage.js
 */

const { test, describe, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const os = require('os');

const StorageService = require('../storage/storageService');
const BackupService = require('../storage/backupService');
const MultiVaultStorage = require('../storage/multiVault');
const RetentionManager = require('../storage/retentionManager');

describe('LOGN Storage & Backup Services', () => {
  let tempBaseDir;

  beforeEach(async () => {
    tempBaseDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'logn-storage-test-'));
  });

  afterEach(async () => {
    if (fs.existsSync(tempBaseDir)) {
      await fsp.rm(tempBaseDir, { recursive: true, force: true });
    }
  });

  test('StorageService: stores evidence atomically with SHA-256 sidecar checksum', async () => {
    const storage = new StorageService(path.join(tempBaseDir, 'vault'));
    await storage.init();

    const sampleBundle = {
      bundle_id: 'test-bundle-001',
      created_at: '2026-11-20T10:00:00Z',
      manifest: { source_id: 'srv-omega' },
      events: [{ event_id: 'ev-1', message: 'Auth success' }],
    };

    const record = await storage.storeEvidence(sampleBundle);

    assert.equal(record.bundle_id, 'test-bundle-001');
    assert.equal(record.source_id, 'srv-omega');
    assert.ok(fs.existsSync(record.path));
    assert.ok(fs.existsSync(`${record.path}.sha256`));

    // Verify retrieval
    const retrieved = await storage.retrieveEvidenceByPath(record.path);
    assert.equal(retrieved.bundle_id, 'test-bundle-001');
    assert.equal(retrieved.events.length, 1);
  });

  test('StorageService: detects checksum tampering on retrieval', async () => {
    const storage = new StorageService(path.join(tempBaseDir, 'vault'));
    const record = await storage.storeEvidence({
      bundle_id: 'tamper-bundle',
      created_at: '2026-11-20T10:00:00Z',
      manifest: { source_id: 'srv-omega' },
      events: [{ event_id: 'ev-1' }],
    });

    // Tamper with the stored file content directly
    await fsp.writeFile(record.path, '{"bundle_id":"tamper-bundle","tampered":true}', 'utf-8');

    await assert.rejects(
      async () => {
        await storage.retrieveEvidenceByPath(record.path);
      },
      /Integrity violation/
    );
  });

  test('BackupService: creates and cryptographically verifies Gzip backup archives', async () => {
    const storage = new StorageService(path.join(tempBaseDir, 'vault'));
    const backupService = new BackupService(path.join(tempBaseDir, 'backups'));

    const r1 = await storage.storeEvidence({
      bundle_id: 'b-1',
      manifest: { source_id: 'host-a' },
      events: [{ seq: 1 }],
    });
    const r2 = await storage.storeEvidence({
      bundle_id: 'b-2',
      manifest: { source_id: 'host-b' },
      events: [{ seq: 2 }],
    });

    const backupManifest = await backupService.createBackup([r1.path, r2.path], {
      tag: 'test_backup',
      retention_days: 60,
    });

    assert.equal(backupManifest.file_count, 2);
    assert.ok(backupManifest.sha256_checksum);
    assert.ok(fs.existsSync(backupManifest.archive_path));

    // Verify valid backup
    const verifyResult = await backupService.verifyBackup(backupManifest.backup_id);
    assert.equal(verifyResult.valid, true);
    assert.equal(verifyResult.file_count, 2);

    // Corrupt archive file
    await fsp.appendFile(backupManifest.archive_path, Buffer.from([0x00, 0x01]));
    const corruptResult = await backupService.verifyBackup(backupManifest.backup_id);
    assert.equal(corruptResult.valid, false);
    assert.match(corruptResult.error, /checksum mismatch/i);
  });

  test('MultiVaultStorage: replicates across tiers and performs automatic failover', async () => {
    const multiVault = new MultiVaultStorage(
      path.join(tempBaseDir, 'primary_vault'),
      path.join(tempBaseDir, 'secondary_vault')
    );
    await multiVault.init();

    const sample = {
      bundle_id: 'replicated-bundle-99',
      manifest: { source_id: 'host-multi' },
      events: [{ message: 'critical action' }],
    };

    const storeResult = await multiVault.storeEvidence(sample);
    assert.equal(storeResult.replicated, true);

    // Initial retrieval from primary
    const resPrimary = await multiVault.retrieveEvidence('replicated-bundle-99');
    assert.equal(resPrimary.source_tier, 'primary');
    assert.equal(resPrimary.bundle.bundle_id, 'replicated-bundle-99');

    // Simulate primary failure by corrupting the primary copy
    const primaryPath = storeResult.primary.path;
    await fsp.writeFile(primaryPath, 'CORRUPTED_FILE_DATA', 'utf-8');

    // Failover to secondary
    const resFailover = await multiVault.retrieveEvidence('replicated-bundle-99');
    assert.equal(resFailover.source_tier, 'secondary');
    assert.equal(resFailover.bundle.bundle_id, 'replicated-bundle-99');
  });

  test('RetentionManager: purges expired evidence while strictly protecting legal holds', async () => {
    const storage = new StorageService(path.join(tempBaseDir, 'vault'));
    const retention = new RetentionManager({ defaultRetentionDays: 30 });

    // Store regular bundle
    const rNormal = await storage.storeEvidence({
      bundle_id: 'bundle-expired',
      manifest: { source_id: 'host-x' },
    });

    // Store bundle under legal hold
    const rProtected = await storage.storeEvidence({
      bundle_id: 'bundle-held',
      manifest: { source_id: 'host-x' },
    });
    retention.addLegalHold('bundle-held', 'Case #4092 - Active Investigation');

    // Backdate the modification time of both files to 60 days ago (> 30 days)
    const sixtyDaysAgo = new Date(Date.now() - 60 * 24 * 60 * 60 * 1000);
    await fsp.utimes(rNormal.path, sixtyDaysAgo, sixtyDaysAgo);
    await fsp.utimes(rProtected.path, sixtyDaysAgo, sixtyDaysAgo);

    const report = await retention.applyRetention(storage, { retentionDays: 30 });

    assert.equal(report.scanned_count, 2);
    assert.equal(report.purged_count, 1);
    assert.equal(report.preserved_under_hold, 1);

    // Expired normal bundle deleted
    assert.equal(fs.existsSync(rNormal.path), false);
    // Protected bundle intact
    assert.equal(fs.existsSync(rProtected.path), true);
  });
});
