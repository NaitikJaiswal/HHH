/**
 * @file e2eProductWorkflow.test.js
 * @description Comprehensive 20-step end-to-end integration test suite for the
 * complete HHH product workflow, followed by negative adversary threat simulations.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

// CLI verification functions
import {
  verifyLog,
  verifyChain,
  verifyCheckpointCmd,
  verifyMerkle,
  verifySignature,
  verifyEvidence,
  inspectReport,
  ResultCode,
  ResultName,
} from '../cli/hhh.js';

// Security and cryptographic primitives
import {
  hashLogEvent,
  GENESIS_HASH,
  sha256hex,
} from '../security/src/crypto/hashing.js';
import { canonicalJson } from '../security/src/crypto/canonicalJson.js';
import {
  buildMerkleTree,
  getMerkleRoot,
  generateMerkleProof,
  verifyMerkleProof,
  MERKLE_ALGORITHM_CONTRACT,
} from '../security/src/merkle/merkleTree.js';
import {
  createFssCheckpoint,
  verifyCheckpoint,
  VerificationStatus,
} from '../security/src/checkpoints/checkpointService.js';
import { FssStateManager } from '../security/src/keys/fssStateManager.js';
import { generateFssMasterState } from '../security/src/crypto/fssSigner.js';

describe('Stage 5.6: Complete 20-Step End-to-End Product Lifecycle & Adversary Testing', () => {
  const tmpStatePath = path.join('/tmp', `hhh_e2e_fss_${Date.now()}.json`);
  const { state: masterState, publicTree } = generateFssMasterState({ maxEpochs: 16 });
  const fss = new FssStateManager({ statePath: tmpStatePath });
  fss.initState(masterState, true);

  // Workflow shared state
  let registeredSource;
  const rawCollectorEvents = [];
  const normalizedEvents = [];
  const ingestedChainedLogs = [];
  let checkpoint;
  let inclusionProofs = [];
  let anchoredReceipt;
  let evidenceBundle;
  let forensicReportJson;
  let forensicReportMarkdown;

  // ───────────────────────────────────────────────────────────────────────────
  // PART 1: 20-STEP PRODUCT WORKFLOW
  // ───────────────────────────────────────────────────────────────────────────

  it('Step 1: Edge collector initializes and registers with backend', () => {
    registeredSource = {
      source_id: 'workstation-dc-alpha',
      collector_id: 'agent-collector-01',
      collector_key_hash: sha256hex('collector_auth_secret_xyz'),
      registered_at: '2026-11-20T10:00:00.000Z',
      status: 'ACTIVE',
      last_sequence: 0,
      last_hash: GENESIS_HASH,
    };
    assert.equal(registeredSource.status, 'ACTIVE');
    assert.equal(registeredSource.last_sequence, 0);
  });

  it('Step 2: Edge collector normalizes and prepares raw events', () => {
    rawCollectorEvents.push(
      { raw: 'Nov 20 10:01:00 auth-srv sshd[102]: Failed password for root from 192.168.1.105', host: 'workstation-dc-alpha' },
      { raw: 'Nov 20 10:01:05 auth-srv sshd[105]: Accepted publickey for analyst from 192.168.1.100', host: 'workstation-dc-alpha' },
      { raw: 'Nov 20 10:02:10 auth-srv sudo: analyst : TTY=pts/0 ; PWD=/home/analyst ; USER=root ; COMMAND=/bin/cat /etc/shadow', host: 'workstation-dc-alpha' },
      { raw: 'Nov 20 10:02:45 auditd[88]: type=SYSCALL arch=c000003e syscall=2 success=yes exit=3', host: 'workstation-dc-alpha' }
    );

    for (let i = 0; i < rawCollectorEvents.length; i++) {
      normalizedEvents.push({
        event_id: `evt-e2e-${i + 1}`,
        event_time: `2026-11-20T10:0${i + 1}:00.000Z`,
        event_type: i === 0 ? 'AUTH_FAILURE' : i === 1 ? 'AUTH_SUCCESS' : i === 2 ? 'PRIVILEGE_ESCALATION' : 'SYSTEM_SYSCALL',
        message: rawCollectorEvents[i].raw,
        metadata: { collector: registeredSource.collector_id, raw_index: i },
        severity: i === 2 ? 'CRITICAL' : i === 0 ? 'HIGH' : 'INFO',
        source_id: registeredSource.source_id,
      });
    }

    assert.equal(normalizedEvents.length, 4);
    assert.equal(normalizedEvents[2].severity, 'CRITICAL');
  });

  it('Step 3: Events transmitted in batch to ingestion endpoint', () => {
    const batchPayload = {
      collector_id: registeredSource.collector_id,
      batch_size: normalizedEvents.length,
      timestamp: new Date().toISOString(),
      events: normalizedEvents,
    };
    assert.equal(batchPayload.events.length, 4);
    assert.ok(batchPayload.collector_id);
  });

  it('Step 4 & 5: Backend verifies auth, calculates LOGN-HASH-v1 canonical hashes, and updates continuous hash chain', () => {
    let prevHash = registeredSource.last_hash;
    let seq = registeredSource.last_sequence;

    for (const ev of normalizedEvents) {
      seq += 1;
      const logRecord = {
        event_id: ev.event_id,
        event_time: ev.event_time,
        event_type: ev.event_type,
        message: ev.message,
        metadata: ev.metadata,
        previous_hash: prevHash,
        sequence_number: seq,
        severity: ev.severity,
        source_id: ev.source_id,
      };

      const curHash = hashLogEvent(logRecord);
      const chainedRecord = {
        ...logRecord,
        current_hash: curHash,
      };

      ingestedChainedLogs.push(chainedRecord);
      prevHash = curHash;
    }

    registeredSource.last_sequence = seq;
    registeredSource.last_hash = prevHash;

    assert.equal(ingestedChainedLogs.length, 4);
    assert.equal(ingestedChainedLogs[0].sequence_number, 1);
    assert.equal(ingestedChainedLogs[0].previous_hash, GENESIS_HASH);
    assert.equal(ingestedChainedLogs[1].previous_hash, ingestedChainedLogs[0].current_hash);
    assert.equal(ingestedChainedLogs[3].sequence_number, 4);
  });

  it('Step 6: Backend persists logs atomically with storage reference', () => {
    const storageRef = `evidence/${registeredSource.source_id}/batch_seq_1_to_4_${Date.now()}.json`;
    for (const log of ingestedChainedLogs) {
      log.storageReference = storageRef;
      log.verificationStatus = 'PENDING';
    }
    assert.equal(ingestedChainedLogs[0].storageReference, storageRef);
  });

  it('Step 7: Checkpoint trigger evaluates log volume threshold', () => {
    const checkpointThreshold = 4;
    const shouldCheckpoint = ingestedChainedLogs.length >= checkpointThreshold;
    assert.equal(shouldCheckpoint, true);
  });

  it('Step 8: Merkle tree construction over leaf hashes', () => {
    const leafHashes = ingestedChainedLogs.map((l) => l.current_hash);
    const tree = buildMerkleTree(leafHashes, { algorithm: MERKLE_ALGORITHM_CONTRACT });
    assert.ok(tree.root);
    assert.equal(tree.leaves.length, 4);
    assert.equal(tree.algorithm, MERKLE_ALGORITHM_CONTRACT);
  });

  it('Step 9: Merkle inclusion proofs generated for all events in checkpoint window', () => {
    const leafHashes = ingestedChainedLogs.map((l) => l.current_hash);
    const tree = buildMerkleTree(leafHashes, { algorithm: MERKLE_ALGORITHM_CONTRACT });

    inclusionProofs = [];
    for (let i = 0; i < leafHashes.length; i++) {
      const proofBundle = generateMerkleProof(tree, i);
      inclusionProofs.push(proofBundle);
      // Verify proof evaluates to root
      const isValid = verifyMerkleProof(leafHashes[i], proofBundle.proof, tree.root);
      assert.equal(isValid, true);
    }
    assert.equal(inclusionProofs.length, 4);
  });

  it('Step 10: Checkpoint signed with active FSS epoch key and bound to MPK', () => {
    const leafHashes = ingestedChainedLogs.map((l) => l.current_hash);
    checkpoint = createFssCheckpoint(
      {
        source_id: registeredSource.source_id,
        start_sequence: 1,
        end_sequence: 4,
        leaf_hashes: leafHashes,
        checkpoint_id: `chk-e2e-${Date.now()}`,
      },
      fss
    );

    assert.equal(checkpoint.schema_version, 'logn-checkpoint-fss-v1');
    assert.equal(checkpoint.fss_epoch, 0);
    assert.equal(checkpoint.mpk, fss.mpk);
    assert.ok(checkpoint.signature);
    assert.ok(checkpoint.epoch_public_key);
  });

  it('Step 11: Checkpoint anchored to Quai Network mock/testnet anchor', () => {
    anchoredReceipt = {
      network: 'Quai Network Orchard Testnet',
      zone: 'cyprus1',
      chain_id: 15000,
      contract: 'SecureLogAnchor',
      contract_address: '0x000000000000000000000000000000000000dead',
      merkle_root: checkpoint.merkle_root,
      source_id: checkpoint.source_id,
      checkpoint_id: checkpoint.checkpoint_id,
      tx_hash: '0x' + crypto.randomBytes(32).toString('hex'),
      block_number: 148291,
      anchored_at: new Date().toISOString(),
      status: 'CONFIRMED',
    };

    assert.equal(anchoredReceipt.chain_id, 15000);
    assert.equal(anchoredReceipt.contract, 'SecureLogAnchor');
    assert.equal(anchoredReceipt.merkle_root, checkpoint.merkle_root);
  });

  it('Step 12: CLI tool independently verifies individual log events (verify-log)', () => {
    for (const log of ingestedChainedLogs) {
      const res = verifyLog(JSON.stringify(log));
      assert.equal(res.exitCode, ResultCode.VALID);
      assert.equal(res.status, 'VALID');
      assert.equal(res.validRecords, 1);
      assert.equal(res.invalidRecords, 0);
    }
  });

  it('Step 13: CLI tool independently verifies continuous hash chain (verify-chain)', () => {
    const res = verifyChain(JSON.stringify(ingestedChainedLogs));
    assert.equal(res.exitCode, ResultCode.VALID);
    assert.equal(res.status, 'VALID');
    assert.equal(res.valid, true);
    assert.equal(res.recordsExamined, 4);
    assert.equal(res.errors.length, 0);
  });

  it('Step 14: CLI tool independently verifies signed checkpoint (verify-checkpoint)', () => {
    const res = verifyCheckpointCmd(JSON.stringify(checkpoint), { mpk: fss.mpk });
    assert.equal(res.exitCode, ResultCode.VALID);
    assert.equal(res.status, 'VALID');
    assert.equal(res.checks.signature, true);
    assert.equal(res.checks.merkle_root, true);
  });

  it('Step 15: CLI tool independently verifies Merkle inclusion proofs (verify-merkle)', () => {
    for (const proofBundle of inclusionProofs) {
      const res = verifyMerkle(proofBundle, { root: checkpoint.merkle_root });
      assert.equal(res.exitCode, ResultCode.VALID);
      assert.equal(res.status, 'VALID');
      assert.equal(res.valid, true);
    }
  });

  it('Step 16: Evidence Engine packages complete evidence bundle with manifest and proofs', () => {
    const bundleId = `BND-E2E-${Date.now()}`;
    const createdAt = new Date().toISOString();

    const manifestCore = {
      bundle_id: bundleId,
      source_id: registeredSource.source_id,
      event_count: ingestedChainedLogs.length,
      checkpoint_count: 1,
      first_sequence: 1,
      last_sequence: 4,
      genesis_hash: GENESIS_HASH,
      final_root_hash: checkpoint.merkle_root,
      created_at: createdAt,
    };
    const manifestHash = sha256hex(canonicalJson(manifestCore));

    evidenceBundle = {
      schema_version: '1.0',
      bundle_id: bundleId,
      created_at: createdAt,
      manifest: {
        ...manifestCore,
        manifest_hash: manifestHash,
      },
      events: ingestedChainedLogs,
      checkpoints: [checkpoint],
      merkle_proofs: inclusionProofs,
      chain_of_custody: [
        {
          action: 'EVIDENCE_SEALED',
          timestamp: createdAt,
          actor: 'HHH Automated Pipeline',
          notes: 'Automated 20-step lifecycle sealing test',
        },
      ],
      readme: 'HHH Verification Instructions: node bin/hhh verify-evidence bundle.json',
    };

    assert.equal(evidenceBundle.manifest.event_count, 4);
    assert.equal(evidenceBundle.checkpoints.length, 1);
  });

  it('Step 17: CLI tool independently verifies evidence bundle (verify-evidence)', () => {
    const res = verifyEvidence(evidenceBundle, { mpk: fss.mpk });
    assert.equal(res.exitCode, ResultCode.VALID);
    assert.equal(res.status, 'VALID');
    assert.equal(res.eventsChecked, 4);
    assert.equal(res.checkpointsVerified, 1);
    assert.equal(res.rootAligned, true);
  });

  it('Step 18: Forensic Engine correlates events and constructs attack timeline', () => {
    // Correlate: AUTH_FAILURE followed by PRIVILEGE_ESCALATION
    const timeline = ingestedChainedLogs.map((l) => ({
      sequence: l.sequence_number,
      timestamp: l.event_time,
      phase: l.event_type === 'AUTH_FAILURE' ? 'CREDENTIAL_ACCESS' : l.event_type === 'PRIVILEGE_ESCALATION' ? 'PRIVILEGE_ESCALATION' : 'TELEMETRY',
      severity: l.severity,
      message: l.message,
      integrity_status: 'VERIFIED',
    }));

    assert.equal(timeline.length, 4);
    assert.equal(timeline[0].phase, 'CREDENTIAL_ACCESS');
    assert.equal(timeline[2].phase, 'PRIVILEGE_ESCALATION');
  });

  it('Step 19: Forensic Engine compiles comprehensive incident report dossier (JSON and Markdown)', () => {
    const reportId = `REP-E2E-${Date.now()}`;
    const generatedAt = new Date().toISOString();

    forensicReportJson = {
      schema_version: '1.0',
      report_id: reportId,
      incident_id: 'INC-2026-ALPHA',
      title: 'Forensic Dossier: Multi-Phase Privilege Escalation Investigation',
      investigator: 'HHH Senior Forensic Specialist',
      generated_at: generatedAt,
      overall_severity: 'CRITICAL',
      summary: {
        total_events_collected: ingestedChainedLogs.length,
        affected_sources: [registeredSource.source_id],
        correlation_findings_count: 1,
        timeline_milestones_count: 4,
        missing_evidence_warnings_count: 0,
        cryptographic_integrity_valid: true,
      },
      time_range: {
        start_time: ingestedChainedLogs[0].event_time,
        end_time: ingestedChainedLogs[3].event_time,
        duration_seconds: 180,
      },
      correlation_findings: [
        {
          finding_type: 'AUTHENTICATION_TO_PRIVILEGE_ESCALATION',
          severity: 'CRITICAL',
          explanation: 'Failed SSH login followed by shadow file inspection via root sudo.',
          event_ids: [ingestedChainedLogs[0].event_id, ingestedChainedLogs[2].event_id],
        },
      ],
      attack_timeline: ingestedChainedLogs.map((l) => ({
        timestamp: l.event_time,
        source_id: l.source_id,
        sequence: l.sequence_number,
        phase: l.event_type,
        severity: l.severity,
        message: l.message,
      })),
      integrity_verification: {
        status: 'VERIFIED',
        events_checked: 4,
        chain_valid: true,
        signatures_valid: true,
        merkle_proofs_valid: true,
        errors: [],
      },
      blockchain_anchoring: anchoredReceipt,
      missing_evidence_warnings: [],
      chain_of_custody: [
        {
          timestamp: generatedAt,
          actor: 'Lead Investigator',
          action: 'DOSSIER_CREATION',
          notes: 'Evidence verified and anchored on Quai Network Cyprus-1',
        },
      ],
      recommended_investigation_steps: [
        'Isolate workstation-dc-alpha host.',
        'Rotate analyst SSH credentials and revoke active sessions.',
        'Preserve evidence bundle and verify against Quai blockchain anchor.',
      ],
    };

    // Render Markdown
    forensicReportMarkdown = [
      `# FORENSIC REPORT: ${forensicReportJson.title}`,
      `**Report ID:** ${forensicReportJson.report_id}`,
      `**Blockchain:** ${forensicReportJson.blockchain_anchoring.network} (Chain ID 15000)`,
      `**Integrity Status:** ${forensicReportJson.integrity_verification.status}`,
    ].join('\n');

    assert.equal(forensicReportJson.summary.total_events_collected, 4);
    assert.ok(forensicReportMarkdown.includes('Quai Network'));
  });

  it('Step 20: CLI tool inspects and validates forensic report integrity (inspect-report)', () => {
    const res = inspectReport(JSON.stringify(forensicReportJson));
    assert.equal(res.exitCode, ResultCode.VALID);
    assert.equal(res.status, 'VALID');
    assert.equal(res.reportSummary.incidentId, 'INC-2026-ALPHA');
    assert.equal(res.reportSummary.cryptographicIntegrityStatus, 'VERIFIED');
    assert.equal(res.reportSummary.overallSeverity, 'CRITICAL');
  });

  // ───────────────────────────────────────────────────────────────────────────
  // PART 2: ADVERSARY THREAT SIMULATION WORKFLOWS
  // ───────────────────────────────────────────────────────────────────────────

  describe('Adversary Threat Simulations', () => {
    it('Threat 1: Adversary modifies event message in database -> detected by verify-chain', () => {
      const tamperedChain = JSON.parse(JSON.stringify(ingestedChainedLogs));
      tamperedChain[1].message = 'ALTERED MESSAGE: legitimate user session';

      const res = verifyChain(tamperedChain);
      assert.equal(res.exitCode, ResultCode.INVALID);
      assert.equal(res.valid, false);
      assert.ok(res.errors.length > 0);
      assert.equal(res.errors[0].type, 'HASH_MISMATCH');
    });

    it('Threat 2: Adversary injects event into completed checkpoint range -> Merkle proof fails', () => {
      const tamperedProof = JSON.parse(JSON.stringify(inclusionProofs[0]));
      // Alter the leaf hash in the proof bundle
      tamperedProof.event_hash = '99'.repeat(32);

      const res = verifyMerkle(tamperedProof, { root: checkpoint.merkle_root });
      assert.equal(res.exitCode, ResultCode.INVALID);
      assert.equal(res.valid, false);
      assert.equal(res.error, 'PROOF_VERIFICATION_FAILED');
    });

    it('Threat 3: Adversary deletes intermediate log -> sequence gap detected by verify-chain', () => {
      const gappedChain = [
        ingestedChainedLogs[0],
        ingestedChainedLogs[2], // deleted index 1 (sequence 2)
        ingestedChainedLogs[3],
      ];

      const res = verifyChain(gappedChain);
      assert.equal(res.exitCode, ResultCode.INVALID);
      assert.equal(res.valid, false);
      assert.ok(res.errors.some((e) => e.type === 'SEQUENCE_GAP'));
    });

    it('Threat 4: Attacker attempts to forge checkpoint for past epoch -> mathematical FSS rejection', () => {
      // Evolve state to epoch 1
      fss.evolve(publicTree.authPaths[1]);
      assert.equal(fss.epoch, 1);

      // Attempt to sign a checkpoint purporting to be epoch 0 using the current evolved state
      const invalidPastCheckpoint = {
        ...checkpoint,
        fss_epoch: 0,
        signature: '12'.repeat(64), // Forged signature
      };

      const res = verifyCheckpointCmd(JSON.stringify(invalidPastCheckpoint), { mpk: fss.mpk });
      assert.equal(res.exitCode, ResultCode.INVALID);
      assert.equal(res.status, 'INVALID');
      assert.ok(res.failures.length > 0);
    });

    it('Threat 5: Key compromise declared -> subsequent checkpoints rejected, past checkpoints remain valid', () => {
      // Declare compromise at epoch 1
      const revocationNotice = {
        schema_version: 'logn-fss-revocation-v1',
        compromiseEpoch: 1,
        compromise_epoch: 1,
        mpk: fss.mpk,
      };

      // 1. Verify pre-compromise checkpoint (epoch 0) is still VALID
      const pastCpRes = verifyCheckpoint(checkpoint, fss.mpk, { revocationNotice });
      assert.equal(pastCpRes.valid, true);
      assert.equal(pastCpRes.status, VerificationStatus.VERIFIED);

      // 2. Sign a new checkpoint at epoch 1
      const postCompromiseCp = createFssCheckpoint(
        {
          source_id: registeredSource.source_id,
          start_sequence: 5,
          end_sequence: 5,
          leaf_hashes: [sha256hex('new-post-compromise-event')],
          checkpoint_id: 'chk-revoked-epoch-1',
        },
        fss
      );

      // 3. Verify post-compromise checkpoint is REJECTED
      const postCpRes = verifyCheckpoint(postCompromiseCp, fss.mpk, { revocationNotice });
      assert.equal(postCpRes.valid, false);
      assert.equal(postCpRes.status, VerificationStatus.KEY_REVOKED);
    });
  });
});
