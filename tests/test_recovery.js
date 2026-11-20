/**
 * Unit tests for LOGN Evidence Retrieval and Recovery Services
 * Executed via Node.js native test runner: node --test tests/test_recovery.js
 */

const { test, describe, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const os = require('os');

const StorageService = require('../storage/storageService');
const BackupService = require('../storage/backupService');
const LogRetriever = require('../storage/retrieveLogs');
const RecoveryService = require('../storage/recoveryService');

describe('LOGN Evidence Retrieval & Recovery Services', () => {
  let tempBaseDir;
  let storage;
  let backupService;
  let retriever;
  let recoveryService;

  beforeEach(async () => {
    tempBaseDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'logn-recovery-test-'));
    const vaultDir = path.join(tempBaseDir, 'vault');
    const backupDir = path.join(tempBaseDir, 'backups');
    const auditDir = path.join(tempBaseDir, 'audit');

    storage = new StorageService(vaultDir);
    backupService = new BackupService(backupDir);
    retriever = new LogRetriever(storage);
    recoveryService = new RecoveryService(backupService, storage, auditDir);

    await storage.init();
    await backupService.init();
    await recoveryService.init();
  });

  afterEach(async () => {
    if (fs.existsSync(tempBaseDir)) {
      await fsp.rm(tempBaseDir, { recursive: true, force: true });
    }
  });

  test('LogRetriever: queries logs by source, event_type, severity, and time range', async () => {
    // Populate storage with diverse events
    await storage.storeEvidence({
      bundle_id: 'bundle-auth-01',
      manifest: { source_id: 'srv-01' },
      events: [
        {
          source_id: 'srv-01',
          sequence_number: 10,
          event_type: 'AUTHENTICATION',
          severity: 'WARNING',
          event_time: '2026-11-20T10:00:00Z',
          message: 'Failed root login',
          metadata: { user: 'root', ip: '192.168.1.1' },
        },
        {
          source_id: 'srv-01',
          sequence_number: 11,
          event_type: 'AUTHENTICATION',
          severity: 'INFO',
          event_time: '2026-11-20T10:05:00Z',
          message: 'User alice logged in',
          metadata: { user: 'alice' },
        },
      ],
    });

    await storage.storeEvidence({
      bundle_id: 'bundle-sys-02',
      manifest: { source_id: 'srv-02' },
      events: [
        {
          source_id: 'srv-02',
          sequence_number: 1,
          event_type: 'SYSTEM',
          severity: 'ERROR',
          event_time: '2026-11-20T10:15:00Z',
          message: 'Kernel panic detected',
          metadata: {},
        },
      ],
    });

    // 1. Query by event_type and severity
    const q1 = await retriever.queryLogs({ eventType: 'AUTHENTICATION', severity: 'WARNING' });
    assert.equal(q1.total, 1);
    assert.equal(q1.events[0].message, 'Failed root login');

    // 2. Query by keyword
    const q2 = await retriever.queryLogs({ keyword: 'alice' });
    assert.equal(q2.total, 1);
    assert.equal(q2.events[0].metadata.user, 'alice');

    // 3. Query by time range
    const q3 = await retriever.queryLogs({
      startTime: '2026-11-20T10:02:00Z',
      endTime: '2026-11-20T10:20:00Z',
    });
    assert.equal(q3.total, 2); // alice login (10:05) and kernel panic (10:15)
  });

  test('RecoveryService: restores files with overwrite protection and creates audit record', async () => {
    // 1. Create source evidence
    const r1 = await storage.storeEvidence({
      bundle_id: 'bundle-restore-1',
      manifest: { source_id: 'srv-backup' },
      events: [{ seq: 1, msg: 'Initial record' }],
    });

    // 2. Create backup
    const backupManifest = await backupService.createBackup([r1.path], { tag: 'restore_test' });
    assert.ok(backupManifest.backup_id);

    // 3. Test destination directory
    const restoreDir = path.join(tempBaseDir, 'restored_vault');
    await fsp.mkdir(restoreDir, { recursive: true });

    // Pre-create existing file in restoreDir to test overwrite protection
    const preExistingFile = path.join(restoreDir, path.basename(r1.path));
    await fsp.writeFile(preExistingFile, 'ORIGINAL_UNTOUCHED_CONTENT', 'utf-8');

    // 4. Restore with overwrite = false (default)
    const report1 = await recoveryService.restoreFromBackup(backupManifest.backup_id, {
      targetDir: restoreDir,
      overwrite: false,
      operator: 'sec_investigator_4',
    });

    assert.equal(report1.skipped_count, 1);
    assert.equal(report1.restored_count, 0);
    // Content should NOT be modified
    assert.equal(await fsp.readFile(preExistingFile, 'utf-8'), 'ORIGINAL_UNTOUCHED_CONTENT');

    // 5. Restore with overwrite = true (explicit confirmation)
    const report2 = await recoveryService.restoreFromBackup(backupManifest.backup_id, {
      targetDir: restoreDir,
      overwrite: true,
      operator: 'sec_investigator_4',
    });

    assert.equal(report2.restored_count, 1);
    assert.equal(report2.skipped_count, 0);
    const restoredContent = await fsp.readFile(preExistingFile, 'utf-8');
    assert.match(restoredContent, /bundle-restore-1/);

    // 6. Verify audit logs
    const auditLogs = await recoveryService.listRecoveryAuditLogs();
    assert.equal(auditLogs.length, 2);
    assert.equal(auditLogs[0].operator, 'sec_investigator_4');
    assert.equal(auditLogs[0].backup_id, backupManifest.backup_id);
  });

  test('RecoveryService: refuses restoration from a corrupted backup', async () => {
    const r1 = await storage.storeEvidence({
      bundle_id: 'b-corrupt-test',
      events: [{ test: true }],
    });
    const backupManifest = await backupService.createBackup([r1.path]);

    // Corrupt archive
    await fsp.appendFile(backupManifest.archive_path, 'CORRUPTION_BYTES');

    await assert.rejects(
      async () => {
        await recoveryService.restoreFromBackup(backupManifest.backup_id);
      },
      /integrity check failed/i
    );
  });
});
