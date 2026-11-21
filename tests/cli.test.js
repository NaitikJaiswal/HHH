/**
 * @file cli.test.js
 * @description Comprehensive test suite for HHH Verification CLI (Stage 5.2).
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

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

import {
  hashLogEvent,
  GENESIS_HASH,
} from '../security/src/crypto/hashing.js';
import { generateLegacyLogHash } from '../backend/src/utils/generateHash.js';
import {
  buildMerkleTree,
  getMerkleRoot,
  generateMerkleProof,
  MERKLE_ALGORITHM_CONTRACT,
  MERKLE_ALGORITHM_RFC6962,
} from '../security/src/merkle/merkleTree.js';
import {
  createCheckpoint,
  createFssCheckpoint,
  buildSigningPayload,
} from '../security/src/checkpoints/checkpointService.js';
import { KeyManager } from '../security/src/keys/keyManager.js';
import { FssStateManager } from '../security/src/keys/fssStateManager.js';
import { generateFssMasterState } from '../security/src/crypto/fssSigner.js';

function createTestFssSetup(statePath, maxEpochs = 8) {
  const { state, publicTree } = generateFssMasterState({ maxEpochs });
  const fss = new FssStateManager({ statePath });
  fss.initState(state, true);
  return { fss, state, publicTree, mpk: state.mpk };
}

describe('Stage 5.2: Verification CLI & Independent Forensic Tooling', () => {
  // ── 1. verify-log ───────────────────────────────────────────────────────────
  describe('verify-log', () => {
    it('verifies a valid LOGN-HASH-v1 event', () => {
      const event = {
        event_id: 'evt-001',
        event_time: '2026-11-21T07:00:00Z',
        event_type: 'AUTH_SUCCESS',
        message: 'User login authorized',
        metadata: { ip: '192.168.1.100' },
        previous_hash: GENESIS_HASH,
        sequence_number: 0,
        severity: 'INFO',
        source_id: 'srv-auth-1',
      };
      event.current_hash = hashLogEvent(event);

      const res = verifyLog(JSON.stringify(event));
      assert.equal(res.exitCode, ResultCode.VALID);
      assert.equal(res.status, 'VALID');
      assert.equal(res.validRecords, 1);
      assert.equal(res.invalidRecords, 0);
    });

    it('rejects a tampered LOGN-HASH-v1 event', () => {
      const event = {
        event_id: 'evt-002',
        event_time: '2026-11-21T07:00:00Z',
        event_type: 'AUTH_SUCCESS',
        message: 'User login authorized',
        metadata: {},
        previous_hash: GENESIS_HASH,
        sequence_number: 1,
        severity: 'INFO',
        source_id: 'srv-auth-1',
      };
      event.current_hash = hashLogEvent(event);
      // Tamper message
      event.message = 'Tampered text by attacker';

      const res = verifyLog(JSON.stringify(event));
      assert.equal(res.exitCode, ResultCode.INVALID);
      assert.equal(res.status, 'INVALID');
      assert.equal(res.invalidRecords, 1);
      assert.ok(res.firstFailure);
      assert.equal(res.firstFailure.error, 'Hash mismatch');
    });

    it('verifies legacy 7-field camelCase log event', () => {
      const legacyEvent = {
        eventId: 'leg-001',
        sourceId: 'src-legacy',
        sequenceNumber: 0,
        timestamp: '2026-11-21T07:00:00Z',
        message: 'Legacy event message',
        metadata: { legacy: true },
        previousHash: GENESIS_HASH,
      };
      legacyEvent.current_hash = generateLegacyLogHash(legacyEvent);

      const res = verifyLog(JSON.stringify(legacyEvent), { legacy: true });
      assert.equal(res.exitCode, ResultCode.VALID);
      assert.equal(res.schemaVersion, 'legacy-7field');
    });

    it('returns INSUFFICIENT_DATA on malformed or empty input', () => {
      const res = verifyLog('');
      assert.equal(res.exitCode, ResultCode.INSUFFICIENT_DATA);
    });
  });

  // ── 2. verify-chain ─────────────────────────────────────────────────────────
  describe('verify-chain', () => {
    function generateValidChain(count = 5) {
      const chain = [];
      let prevHash = GENESIS_HASH;
      for (let i = 0; i < count; i++) {
        const ev = {
          event_id: `chain-evt-${i}`,
          event_time: new Date(Date.now() + i * 1000).toISOString(),
          event_type: 'SYSTEM',
          message: `Event message ${i}`,
          metadata: { seq: i },
          previous_hash: prevHash,
          sequence_number: i,
          severity: 'INFO',
          source_id: 'srv-chain-1',
        };
        ev.current_hash = hashLogEvent(ev);
        prevHash = ev.current_hash;
        chain.push(ev);
      }
      return chain;
    }

    it('verifies a valid hash chain', () => {
      const chain = generateValidChain(5);
      const res = verifyChain(JSON.stringify(chain));
      assert.equal(res.exitCode, ResultCode.VALID);
      assert.equal(res.valid, true);
      assert.equal(res.recordsExamined, 5);
      assert.equal(res.errors.length, 0);
    });

    it('detects broken hash link between events', () => {
      const chain = generateValidChain(5);
      // Corrupt event 2 link
      chain[2].previous_hash = 'f'.repeat(64);
      const res = verifyChain(JSON.stringify(chain));
      assert.equal(res.exitCode, ResultCode.INVALID);
      assert.equal(res.valid, false);
      assert.ok(res.errors.length > 0);
    });

    it('detects reordered events', () => {
      const chain = generateValidChain(5);
      // Swap event 1 and event 2
      const tmp = chain[1];
      chain[1] = chain[2];
      chain[2] = tmp;

      const res = verifyChain(JSON.stringify(chain));
      assert.equal(res.exitCode, ResultCode.INVALID);
      assert.equal(res.valid, false);
    });

    it('detects missing sequence gap', () => {
      const chain = generateValidChain(5);
      // Remove event 2
      chain.splice(2, 1);

      const res = verifyChain(JSON.stringify(chain));
      assert.equal(res.exitCode, ResultCode.INVALID);
      assert.equal(res.valid, false);
    });

    it('detects duplicate sequence numbers', () => {
      const chain = generateValidChain(5);
      chain[2].sequence_number = chain[1].sequence_number;

      const res = verifyChain(JSON.stringify(chain));
      assert.equal(res.exitCode, ResultCode.INVALID);
      assert.equal(res.valid, false);
    });

    it('detects timestamp regression', () => {
      const chain = generateValidChain(3);
      // Set timestamp of event 2 earlier than event 1
      chain[2].event_time = '2020-01-01T00:00:00Z';
      chain[2].current_hash = hashLogEvent(chain[2]);

      const res = verifyChain(JSON.stringify(chain));
      assert.equal(res.exitCode, ResultCode.INVALID);
      assert.equal(res.valid, false);
    });
  });

  // ── 3. verify-checkpoint ───────────────────────────────────────────────────
  describe('verify-checkpoint', () => {
    it('verifies a valid FSS checkpoint with MPK', () => {
      const statePath = path.join('/tmp', `fss_${Date.now()}_1.json`);
      const { fss, mpk } = createTestFssSetup(statePath, 4);

      const leaves = ['a'.repeat(64), 'b'.repeat(64)];
      const cp = createFssCheckpoint(
        {
          source_id: 'src-fss-cli',
          start_sequence: 1,
          end_sequence: 2,
          event_count: 2,
          leaf_hashes: leaves,
        },
        fss
      );

      const res = verifyCheckpointCmd(JSON.stringify(cp), { mpk });
      assert.equal(res.exitCode, ResultCode.VALID);
      assert.equal(res.status, 'VALID');
      assert.equal(res.checks.merkle_root, true);
      assert.equal(res.checks.signature, true);
      if (fs.existsSync(statePath)) fs.unlinkSync(statePath);
    });

    it('rejects checkpoint with altered Merkle root', () => {
      const statePath = path.join('/tmp', `fss_${Date.now()}_2.json`);
      const { fss, mpk } = createTestFssSetup(statePath, 4);

      const leaves = ['a'.repeat(64), 'b'.repeat(64)];
      const cp = createFssCheckpoint(
        {
          source_id: 'src-fss-cli',
          start_sequence: 1,
          end_sequence: 2,
          event_count: 2,
          leaf_hashes: leaves,
        },
        fss
      );

      cp.merkle_root = '0'.repeat(64);
      const res = verifyCheckpointCmd(JSON.stringify(cp), { mpk });
      assert.equal(res.exitCode, ResultCode.INVALID);
      assert.equal(res.status, 'INVALID');
      if (fs.existsSync(statePath)) fs.unlinkSync(statePath);
    });

    it('enforces revocation notice on revoked epoch', () => {
      const statePath = path.join('/tmp', `fss_${Date.now()}_3.json`);
      const { fss, mpk, publicTree } = createTestFssSetup(statePath, 8);

      // Checkpoint created at epoch 0
      const cp0 = createFssCheckpoint(
        {
          source_id: 'src-fss-rev',
          start_sequence: 1,
          end_sequence: 2,
          event_count: 2,
          leaf_hashes: ['1'.repeat(64), '2'.repeat(64)],
        },
        fss
      );

      // Evolve to epoch 1
      fss.evolve(publicTree.authPaths[1]);
      const cp1 = createFssCheckpoint(
        {
          source_id: 'src-fss-rev',
          start_sequence: 3,
          end_sequence: 4,
          event_count: 2,
          leaf_hashes: ['3'.repeat(64), '4'.repeat(64)],
        },
        fss
      );

      // Revocation notice declaring compromise at epoch 1
      const revNotice = {
        revocationId: 'rev-001',
        compromiseEpoch: 1,
        reason: 'Key compromised in epoch 1',
      };
      const tmpRevPath = path.join('/tmp', `rev_${Date.now()}.json`);
      fs.writeFileSync(tmpRevPath, JSON.stringify(revNotice));

      // Checkpoint 0 (epoch 0 < 1) remains VALID!
      const res0 = verifyCheckpointCmd(JSON.stringify(cp0), { mpk, revocation: tmpRevPath });
      assert.equal(res0.exitCode, ResultCode.VALID);

      // Checkpoint 1 (epoch 1 >= 1) is REVOKED!
      const res1 = verifyCheckpointCmd(JSON.stringify(cp1), { mpk, revocation: tmpRevPath });
      assert.equal(res1.exitCode, ResultCode.REVOKED);
      assert.equal(res1.status, 'REVOKED');

      fs.unlinkSync(tmpRevPath);
      if (fs.existsSync(statePath)) fs.unlinkSync(statePath);
    });
  });

  // ── 4. verify-merkle ───────────────────────────────────────────────────────
  describe('verify-merkle', () => {
    it('verifies proof bundle for HHH-CONTRACT-DUP-v1', () => {
      const leaves = ['11'.repeat(32), '22'.repeat(32), '33'.repeat(32)];
      const tree = buildMerkleTree(leaves, { algorithm: MERKLE_ALGORITHM_CONTRACT });
      const root = getMerkleRoot(tree);
      const bundle = generateMerkleProof(tree, 1);

      const res = verifyMerkle(JSON.stringify(bundle), { root });
      assert.equal(res.exitCode, ResultCode.VALID);
      assert.equal(res.valid, true);
      assert.equal(res.algorithm, MERKLE_ALGORITHM_CONTRACT);
    });

    it('verifies proof bundle for RFC-6962', () => {
      const leaves = ['aa'.repeat(32), 'bb'.repeat(32), 'cc'.repeat(32)];
      const tree = buildMerkleTree(leaves, { algorithm: MERKLE_ALGORITHM_RFC6962 });
      const root = getMerkleRoot(tree);
      const bundle = generateMerkleProof(tree, 2);

      const res = verifyMerkle(JSON.stringify(bundle), { root });
      assert.equal(res.exitCode, ResultCode.VALID);
      assert.equal(res.valid, true);
      assert.equal(res.algorithm, MERKLE_ALGORITHM_RFC6962);
    });

    it('rejects tampered leaf in proof verification', () => {
      const leaves = ['11'.repeat(32), '22'.repeat(32)];
      const tree = buildMerkleTree(leaves);
      const root = getMerkleRoot(tree);
      const bundle = generateMerkleProof(tree, 0);
      bundle.event_hash = 'ff'.repeat(32); // tampered leaf

      const res = verifyMerkle(JSON.stringify(bundle), { root });
      assert.equal(res.exitCode, ResultCode.INVALID);
      assert.equal(res.valid, false);
    });
  });

  // ── 5. verify-signature ────────────────────────────────────────────────────
  describe('verify-signature', () => {
    it('verifies valid Ed25519 signature', () => {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
      const payload = 'CRITICAL FORENSIC REPORT DATA';
      const sig = crypto.sign(null, Buffer.from(payload, 'utf8'), privateKey).toString('hex');
      const pubkeyHex = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('hex');

      const res = verifySignature(payload, { pubkey: pubkeyHex, sig });
      assert.equal(res.exitCode, ResultCode.VALID);
      assert.equal(res.valid, true);
    });

    it('rejects forged signature on modified payload', () => {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
      const payload = 'ORIGINAL DATA';
      const sig = crypto.sign(null, Buffer.from(payload, 'utf8'), privateKey).toString('hex');
      const pubkeyHex = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('hex');

      const res = verifySignature('TAMPERED DATA', { pubkey: pubkeyHex, sig });
      assert.equal(res.exitCode, ResultCode.INVALID);
      assert.equal(res.valid, false);
    });
  });

  // ── 6. verify-evidence ─────────────────────────────────────────────────────
  describe('verify-evidence', () => {
    it('verifies a complete evidence bundle', () => {
      const statePath = path.join('/tmp', `fss_${Date.now()}_4.json`);
      const { fss, mpk } = createTestFssSetup(statePath, 4);

      const ev0 = {
        event_id: 'ev-0',
        event_time: '2026-11-21T07:00:00Z',
        event_type: 'AUTH',
        message: 'login',
        metadata: {},
        previous_hash: GENESIS_HASH,
        sequence_number: 1,
        severity: 'INFO',
        source_id: 'src-evid',
      };
      ev0.current_hash = hashLogEvent(ev0);

      const cp = createFssCheckpoint(
        {
          source_id: 'src-evid',
          start_sequence: 1,
          end_sequence: 1,
          event_count: 1,
          leaf_hashes: [ev0.current_hash],
        },
        fss
      );

      const bundle = {
        schema_version: '1.0',
        bundle_id: 'bundle-001',
        manifest: {
          bundle_id: 'bundle-001',
          source_id: 'src-evid',
          event_count: 1,
          checkpoint_count: 1,
        },
        events: [ev0],
        checkpoints: [cp],
      };

      const res = verifyEvidence(JSON.stringify(bundle), { mpk });
      assert.equal(res.exitCode, ResultCode.VALID);
      assert.equal(res.status, 'VALID');
      assert.equal(res.chainValid, true);
      assert.equal(res.checkpointsVerified, 1);
      if (fs.existsSync(statePath)) fs.unlinkSync(statePath);
    });
  });

  // ── 7. inspect-report ──────────────────────────────────────────────────────
  describe('inspect-report', () => {
    it('inspects a valid forensic report', () => {
      const report = {
        schema_version: '1.0',
        incident_id: 'INC-20261121-AB12CD',
        title: 'Unauthorized Lateral Movement Investigation',
        overall_severity: 'HIGH',
        investigator: 'Lead Forensics Analyst',
        generated_at: '2026-11-21T07:15:00Z',
        summary: {
          total_events_collected: 42,
          affected_sources: ['srv-auth', 'srv-db'],
          correlation_findings_count: 3,
          timeline_milestones_count: 5,
          missing_evidence_warnings_count: 0,
          cryptographic_integrity_valid: true,
        },
        integrity_verification: {
          status: 'VERIFIED',
          events_checked: 42,
          chain_valid: true,
          signatures_valid: true,
          errors: [],
        },
        attack_timeline: [{ milestone: 'Brute force detected' }],
        correlation_findings: [{ rule: 'Privilege escalation' }],
      };

      const res = inspectReport(JSON.stringify(report));
      assert.equal(res.exitCode, ResultCode.VALID);
      assert.equal(res.status, 'VALID');
      assert.equal(res.reportSummary.incidentId, 'INC-20261121-AB12CD');
      assert.equal(res.reportSummary.cryptographicIntegrityStatus, 'VERIFIED');
    });

    it('detects compromised integrity in forensic report', () => {
      const report = {
        schema_version: '1.0',
        incident_id: 'INC-COMPROMISED',
        title: 'Tampering Investigation',
        summary: {},
        integrity_verification: {
          status: 'INTEGRITY_COMPROMISED',
          chain_valid: false,
          signatures_valid: false,
          errors: ['Hash chain broken at event 14'],
        },
      };

      const res = inspectReport(JSON.stringify(report));
      assert.equal(res.exitCode, ResultCode.INVALID);
      assert.equal(res.status, 'INVALID');
    });
  });
});
