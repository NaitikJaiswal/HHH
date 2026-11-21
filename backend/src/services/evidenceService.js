/**
 * @file evidenceService.js
 * @description Evidence packaging, verification, and chain-of-custody tracking.
 */

import crypto from 'node:crypto';
import Log from '../models/Log.js';
import Checkpoint from '../models/Checkpoint.js';
import { verifyEvidence } from '../../../cli/hhh.js';
import { GENESIS_HASH, sha256hex } from '../../../security/src/crypto/hashing.js';
import { canonicalJson } from '../../../security/src/crypto/canonicalJson.js';
import {
  buildMerkleTree,
  generateMerkleProof,
  MERKLE_ALGORITHM_CONTRACT,
} from '../../../security/src/merkle/merkleTree.js';

class EvidenceService {
  /**
   * Package sequences of logs and signed checkpoints into a sealed evidence bundle.
   */
  async packageEvidence({
    sourceId,
    startSequence,
    endSequence,
    limit = 100,
    investigator = 'HHH Forensic Enclave',
    notes = 'Official cryptographic evidence sealing',
  } = {}) {
    const filter = {};
    if (sourceId) filter.sourceId = sourceId;

    if (startSequence !== undefined || endSequence !== undefined) {
      filter.sequenceNumber = {};
      if (startSequence !== undefined) filter.sequenceNumber.$gte = Number(startSequence);
      if (endSequence !== undefined) filter.sequenceNumber.$lte = Number(endSequence);
    }

    const [logs, checkpoints] = await Promise.all([
      Log.find(filter)
        .sort({ sequenceNumber: 1 })
        .limit(Number(limit))
        .lean(),
      Checkpoint.find(sourceId ? { sourceId } : {})
        .sort({ createdAt: 1 })
        .limit(20)
        .lean(),
    ]);

    const bundleId = `BND-${Date.now()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    const createdAt = new Date().toISOString();

    const formattedEvents = logs.map((l) => ({
      event_id: l.eventId || String(l._id),
      event_time: l.eventTime || l.serverTimestamp || l.timestamp,
      event_type: l.eventType,
      message: l.message,
      metadata: l.metadata || {},
      previous_hash: l.previousHash,
      sequence_number: l.sequenceNumber,
      severity: l.severity || l.level || 'INFO',
      source_id: l.sourceId,
      current_hash: l.currentHash,
    }));

    // Filter checkpoints that overlap with our log sequence range
    const minSeq = formattedEvents[0]?.sequence_number ?? 1;
    const maxSeq = formattedEvents[formattedEvents.length - 1]?.sequence_number ?? 1;

    const relevantCheckpoints = checkpoints.filter((cp) => {
      const cpStart = cp.start_sequence || 1;
      const cpEnd = cp.end_sequence || cp.lastSequenceNumber || 1;
      return cpEnd >= minSeq && cpStart <= maxSeq;
    });

    // If no relevant checkpoint found, use latest or build representation
    const activeCheckpoints = relevantCheckpoints.length > 0 ? relevantCheckpoints : checkpoints.slice(-1);

    const formattedCheckpoints = activeCheckpoints.map((cp) => ({
      schema_version: cp.schema_version || 'logn-checkpoint-fss-v1',
      checkpoint_id: cp.checkpointId,
      source_id: cp.sourceId,
      start_sequence: cp.start_sequence || 1,
      end_sequence: cp.end_sequence || cp.lastSequenceNumber,
      event_count: cp.event_count || (cp.end_sequence - cp.start_sequence + 1),
      merkle_root: cp.merkle_root || cp.chainHeadHash,
      merkle_leaf_hashes: cp.merkle_leaf_hashes || formattedEvents.map((e) => e.current_hash),
      merkle_tree_algorithm: cp.merkle_tree_algorithm || MERKLE_ALGORITHM_CONTRACT,
      signature: cp.signature,
      signature_algorithm: cp.signature_algorithm || 'Ed25519-MKT-FSS',
      fss_epoch: cp.fss_epoch ?? 0,
      mpk: cp.mpk,
      epoch_public_key: cp.epoch_public_key || cp.publicKey,
      fss_auth_path: cp.fss_auth_path || [],
      timestamp: cp.timestamp || cp.createdAt,
    }));

    // Generate Merkle inclusion proofs for events covered by checkpoints
    const merkleProofs = [];
    for (const cp of formattedCheckpoints) {
      if (cp.merkle_leaf_hashes && cp.merkle_leaf_hashes.length > 0) {
        try {
          const tree = buildMerkleTree(cp.merkle_leaf_hashes, { algorithm: MERKLE_ALGORITHM_CONTRACT });
          for (let leafIdx = 0; leafIdx < cp.merkle_leaf_hashes.length; leafIdx++) {
            const proof = generateMerkleProof(tree, leafIdx);
            merkleProofs.push({
              checkpoint_id: cp.checkpoint_id,
              leaf_index: leafIdx,
              leaf_hash: cp.merkle_leaf_hashes[leafIdx],
              proof: proof.proof || proof.path || [],
              root: tree.root,
              algorithm: MERKLE_ALGORITHM_CONTRACT,
            });
          }
        } catch {
          // If tree generation fails, continue gracefully
        }
      }
    }

    // Events JSONL representation
    const eventsJsonl = formattedEvents.map((e) => canonicalJson(e)).join('\n');
    const eventsExportHash = sha256hex(eventsJsonl || 'EMPTY_EVENTS');

    // Build Manifest
    const manifestCore = {
      bundle_id: bundleId,
      source_id: sourceId || (logs[0] ? logs[0].sourceId : 'all_sources'),
      event_count: formattedEvents.length,
      checkpoint_count: formattedCheckpoints.length,
      first_sequence: logs[0]?.sequenceNumber ?? 0,
      last_sequence: logs[logs.length - 1]?.sequenceNumber ?? 0,
      genesis_hash: logs[0]?.previousHash || GENESIS_HASH,
      final_root_hash: logs[logs.length - 1]?.currentHash || GENESIS_HASH,
      created_at: createdAt,
      generator: investigator,
    };
    const manifestHash = sha256hex(canonicalJson(manifestCore));

    const manifest = {
      ...manifestCore,
      manifest_hash: manifestHash,
    };

    // Chain of Custody
    const chainOfCustody = [
      {
        action: 'EVIDENCE_INGESTION_AND_SEALING',
        timestamp: createdAt,
        actor: investigator,
        export_hash: eventsExportHash,
        manifest_hash: manifestHash,
        notes: notes || 'Cryptographic seal established with forward-secure signatures and Merkle inclusion roots.',
      },
    ];

    // Readme instructions for independent CLI verification
    const readme = [
      '========================================================================',
      'HHH FORENSIC EVIDENCE BUNDLE VERIFICATION INSTRUCTIONS',
      '========================================================================',
      `Bundle ID:     ${bundleId}`,
      `Created At:    ${createdAt}`,
      `Events Count:  ${formattedEvents.length}`,
      `Checkpoints:   ${formattedCheckpoints.length}`,
      `Source ID:     ${manifest.source_id}`,
      `Events SHA256: ${eventsExportHash}`,
      '------------------------------------------------------------------------',
      'This bundle is cryptographically sealed and independently verifiable.',
      '',
      'INDEPENDENT VERIFICATION WITH HHH CLI:',
      '1. Verify the entire evidence package:',
      '   node bin/hhh verify-evidence bundle.json',
      '',
      '2. Verify individual components:',
      '   - Event hash-chain continuity: node bin/hhh verify-chain events.jsonl',
      '   - Signed FSS checkpoints:      node bin/hhh verify-checkpoint checkpoints.json',
      '   - Merkle inclusion proof:      node bin/hhh verify-merkle proof.json',
      '========================================================================',
    ].join('\n');

    // Build unified bundle object
    const bundle = {
      schema_version: '1.0',
      bundle_id: bundleId,
      created_at: createdAt,
      manifest,
      events: formattedEvents,
      checkpoints: formattedCheckpoints,
      merkle_proofs: merkleProofs,
      chain_of_custody: chainOfCustody,
      readme,
    };

    // Pre-compute verification report
    const verificationReport = verifyEvidence(bundle);
    bundle.verification_report = verificationReport;

    // Structured files collection
    const files = {
      'manifest.json': JSON.stringify(manifest, null, 2),
      'events.jsonl': eventsJsonl,
      'checkpoints.json': JSON.stringify(formattedCheckpoints, null, 2),
      'merkle_proofs.json': JSON.stringify(merkleProofs, null, 2),
      'chain_of_custody.json': JSON.stringify(chainOfCustody, null, 2),
      'verification_report.json': JSON.stringify(verificationReport, null, 2),
      'README.txt': readme,
      'bundle.json': JSON.stringify(bundle, null, 2),
    };

    return {
      bundle,
      files,
    };
  }

  /**
   * Verify an evidence bundle using independent cryptographic rules.
   */
  verifyEvidence(bundle) {
    return verifyEvidence(bundle);
  }
}

export default new EvidenceService();
