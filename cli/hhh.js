#!/usr/bin/env node

/**
 * @file hhh.js
 * @description HHH Verification CLI & Independent Forensic Tooling.
 *
 * Provides independent off-chain and offline cryptographic verification for:
 *   - Individual log events (LOGN-HASH-v1 and legacy 7-field formats)
 *   - Continuous hash chains (sequence, monotonicity, tamper detection)
 *   - Signed checkpoints (FSS Ed25519-MKT-FSS and legacy Ed25519)
 *   - Merkle inclusion proofs (HHH-CONTRACT-DUP-v1 and RFC-6962)
 *   - Cryptographic signatures (Ed25519 and FSS)
 *   - Sealed forensic evidence packages
 *   - Incident investigation reports
 *
 * Exit Codes:
 *   0: VALID
 *   1: INVALID
 *   2: PARTIALLY VERIFIED
 *   3: UNVERIFIABLE
 *   4: REVOKED
 *   5: INSUFFICIENT DATA
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

// Security module imports
import {
  hashLogEvent,
  sha256hex,
  GENESIS_HASH,
  LOGN_HASH_V1_FIELDS,
  normalizeTimestamp,
} from '../security/src/crypto/hashing.js';
import { verifyHashChain } from '../security/src/crypto/hashChain.js';
import { canonicalJson } from '../security/src/crypto/canonicalJson.js';
import {
  buildMerkleTree,
  getMerkleRoot,
  verifyMerkleProof,
  verifyInclusionProofBundle,
  MERKLE_ALGORITHM_CONTRACT,
  MERKLE_ALGORITHM_RFC6962,
} from '../security/src/merkle/merkleTree.js';
import {
  verifyCheckpoint,
  buildSigningPayload,
  VerificationStatus,
  CHECKPOINT_FSS_SCHEMA_VERSION,
  CHECKPOINT_SCHEMA_VERSION,
} from '../security/src/checkpoints/checkpointService.js';
import { verifyFssSignature } from '../security/src/crypto/fssSigner.js';
import { publicKeyFromHex } from '../security/src/keys/keyManager.js';
import { generateLegacyLogHash } from '../backend/src/utils/generateHash.js';

// Standard Result States & Exit Codes
export const ResultCode = Object.freeze({
  VALID: 0,
  INVALID: 1,
  PARTIALLY_VERIFIED: 2,
  UNVERIFIABLE: 3,
  REVOKED: 4,
  INSUFFICIENT_DATA: 5,
});

export const ResultName = Object.freeze({
  [ResultCode.VALID]: 'VALID',
  [ResultCode.INVALID]: 'INVALID',
  [ResultCode.PARTIALLY_VERIFIED]: 'PARTIALLY VERIFIED',
  [ResultCode.UNVERIFIABLE]: 'UNVERIFIABLE',
  [ResultCode.REVOKED]: 'REVOKED',
  [ResultCode.INSUFFICIENT_DATA]: 'INSUFFICIENT DATA',
});

// Helper: Parse CLI Arguments
function parseArgs(args) {
  const parsed = {
    command: args[0] || null,
    target: null,
    options: {},
  };

  for (let i = 1; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      if (i + 1 < args.length && !args[i + 1].startsWith('--')) {
        parsed.options[key] = args[i + 1];
        i++;
      } else {
        parsed.options[key] = true;
      }
    } else if (!parsed.target) {
      parsed.target = arg;
    }
  }

  return parsed;
}

// Helper: Read and parse input (JSON, JSONL, or raw string)
function loadInput(target) {
  if (!target) {
    throw new Error('No input target provided');
  }

  // Already parsed object or array
  if (typeof target === 'object' && target !== null) {
    return {
      data: target,
      format: Array.isArray(target) ? 'json-array' : 'json-object',
      raw: JSON.stringify(target),
      isFilePath: false,
    };
  }

  let raw = String(target);
  let isFilePath = false;

  if (typeof target === 'string' && fs.existsSync(target)) {
    isFilePath = true;
    raw = fs.readFileSync(target, 'utf8').trim();
  }

  // Handle JSONL
  if (raw.includes('\n')) {
    const lines = raw.split('\n').map((l) => l.trim()).filter(Boolean);
    try {
      const parsedLines = lines.map((l) => JSON.parse(l));
      return { data: parsedLines, format: 'jsonl', raw, isFilePath };
    } catch {
      // If not JSONL, fall through to single JSON attempt
    }
  }

  try {
    const data = JSON.parse(raw);
    return { data, format: Array.isArray(data) ? 'json-array' : 'json-object', raw, isFilePath };
  } catch (err) {
    return { data: raw, format: 'raw-string', raw, isFilePath, parseError: err.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Command: verify-log
// ─────────────────────────────────────────────────────────────────────────────
export function verifyLog(target, options = {}) {
  let input;
  try {
    input = loadInput(target);
  } catch (err) {
    return {
      status: ResultName[ResultCode.INSUFFICIENT_DATA],
      exitCode: ResultCode.INSUFFICIENT_DATA,
      message: `Failed to load log input: ${err.message}`,
      recordsExamined: 0,
      validRecords: 0,
      invalidRecords: 0,
    };
  }

  const items = Array.isArray(input.data) ? input.data : [input.data];
  if (items.length === 0 || typeof items[0] !== 'object' || items[0] === null) {
    return {
      status: ResultName[ResultCode.INSUFFICIENT_DATA],
      exitCode: ResultCode.INSUFFICIENT_DATA,
      message: 'Log input must be a valid JSON object or an array of log objects',
      recordsExamined: 0,
      validRecords: 0,
      invalidRecords: 0,
    };
  }

  let validCount = 0;
  let invalidCount = 0;
  const failures = [];
  const examined = [];

  for (let i = 0; i < items.length; i++) {
    const event = items[i];
    const storedHash =
      event.current_hash ||
      event.event_hash ||
      event.hash ||
      (event.integrity && event.integrity.event_hash);

    let computedHash = null;
    let schemaUsed = 'LOGN-HASH-v1';
    let error = null;

    if (options.legacy) {
      schemaUsed = 'legacy-7field';
      try {
        computedHash = generateLegacyLogHash(event);
      } catch (e) {
        error = e.message;
      }
    } else {
      try {
        computedHash = hashLogEvent(event);
      } catch (v1Err) {
        // Try fallback to legacy if event has legacy camelCase fields
        try {
          computedHash = generateLegacyLogHash(event);
          schemaUsed = 'legacy-7field';
        } catch {
          error = v1Err.message;
        }
      }
    }

    const isValid = !error && storedHash && computedHash && storedHash.toLowerCase() === computedHash.toLowerCase();

    if (isValid) {
      validCount++;
    } else {
      invalidCount++;
      failures.push({
        index: i,
        eventId: event.event_id || event.eventId || `index-${i}`,
        sequenceNumber: event.sequence_number ?? event.sequenceNumber,
        storedHash: storedHash || null,
        computedHash: computedHash || null,
        schemaUsed,
        error: error || (storedHash ? 'Hash mismatch' : 'Missing stored hash for comparison'),
      });
    }

    examined.push({
      index: i,
      valid: Boolean(isValid),
      schemaUsed,
      storedHash,
      computedHash,
    });
  }

  const allValid = invalidCount === 0 && validCount > 0;
  const exitCode = allValid ? ResultCode.VALID : ResultCode.INVALID;

  return {
    status: ResultName[exitCode],
    exitCode,
    schemaVersion: examined[0]?.schemaUsed || 'LOGN-HASH-v1',
    recordsExamined: items.length,
    validRecords: validCount,
    invalidRecords: invalidCount,
    firstFailure: failures[0] || null,
    failures,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Command: verify-chain
// ─────────────────────────────────────────────────────────────────────────────
export function verifyChain(target, options = {}) {
  let input;
  try {
    input = loadInput(target);
  } catch (err) {
    return {
      status: ResultName[ResultCode.INSUFFICIENT_DATA],
      exitCode: ResultCode.INSUFFICIENT_DATA,
      message: `Failed to load chain input: ${err.message}`,
      recordsExamined: 0,
      valid: false,
    };
  }

  const rawEvents = Array.isArray(input.data)
    ? input.data
    : input.data?.events || [input.data];

  if (!Array.isArray(rawEvents) || rawEvents.length === 0) {
    return {
      status: ResultName[ResultCode.INSUFFICIENT_DATA],
      exitCode: ResultCode.INSUFFICIENT_DATA,
      message: 'Chain input must contain a non-empty array of events',
      recordsExamined: 0,
      valid: false,
    };
  }

  // Normalize events to standard fields (supporting evidence-engine integrity envelope if present)
  const events = rawEvents.map((ev) => {
    if (ev.integrity && typeof ev.integrity === 'object') {
      return {
        ...ev,
        current_hash: ev.integrity.event_hash || ev.current_hash,
        previous_hash: ev.integrity.previous_hash || ev.previous_hash,
        sequence_number: ev.sequence_number ?? ev.integrity.sequence_number,
      };
    }
    return {
      ...ev,
      current_hash: ev.current_hash || ev.event_hash || ev.hash,
      previous_hash: ev.previous_hash || ev.prev_hash || ev.previousHash,
      sequence_number: ev.sequence_number ?? ev.sequenceNumber,
    };
  });

  const chainOpts = {
    expectedGenesisHash: options['expected-genesis'] || options.expectedGenesis || GENESIS_HASH,
  };
  if (options['expected-start-seq'] !== undefined || options.expectedStartSequence !== undefined) {
    chainOpts.expectedStartSequence = Number(options['expected-start-seq'] ?? options.expectedStartSequence);
  }

  const result = verifyHashChain(events, chainOpts);

  // Additional check: timestamp monotonicity
  const timestampErrors = [];
  let prevTime = null;
  for (let i = 0; i < events.length; i++) {
    const rawTime = events[i].event_time || events[i].timestamp;
    if (rawTime) {
      const currTime = new Date(rawTime).getTime();
      if (prevTime !== null && currTime < prevTime) {
        timestampErrors.push({
          index: i,
          sequenceNumber: events[i].sequence_number,
          type: 'TIMESTAMP_REGRESSION',
          reason: `Timestamp regression at index ${i}: current time (${rawTime}) is before previous time`,
        });
      }
      prevTime = currTime;
    }
  }

  const allErrors = [...result.errors, ...timestampErrors];
  const isValid = result.valid && timestampErrors.length === 0;
  const exitCode = isValid ? ResultCode.VALID : ResultCode.INVALID;

  const validRecords = isValid ? events.length : Math.max(0, (result.firstFailedIndex ?? events.length) - timestampErrors.length);

  return {
    status: ResultName[exitCode],
    exitCode,
    recordsExamined: events.length,
    validRecords,
    invalidRecords: events.length - validRecords,
    valid: isValid,
    firstFailure: allErrors[0] || null,
    errors: allErrors,
    details: {
      genesisHashUsed: chainOpts.expectedGenesisHash,
      startSequence: events[0]?.sequence_number,
      endSequence: events[events.length - 1]?.sequence_number,
    },
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Command: verify-checkpoint
// ─────────────────────────────────────────────────────────────────────────────
export function verifyCheckpointCmd(target, options = {}) {
  let input;
  try {
    input = loadInput(target);
  } catch (err) {
    return {
      status: ResultName[ResultCode.INSUFFICIENT_DATA],
      exitCode: ResultCode.INSUFFICIENT_DATA,
      message: `Failed to load checkpoint file: ${err.message}`,
    };
  }

  const checkpoint = input.data;
  if (!checkpoint || typeof checkpoint !== 'object') {
    return {
      status: ResultName[ResultCode.INSUFFICIENT_DATA],
      exitCode: ResultCode.INSUFFICIENT_DATA,
      message: 'Checkpoint must be a JSON object',
    };
  }

  // Check revocation notice option if provided
  let revocationNotice = null;
  if (options.revocation) {
    try {
      const revInput = loadInput(options.revocation);
      revocationNotice = revInput.data;
    } catch (e) {
      return {
        status: ResultName[ResultCode.INSUFFICIENT_DATA],
        exitCode: ResultCode.INSUFFICIENT_DATA,
        message: `Failed to load revocation file: ${e.message}`,
      };
    }
  }

  const keyOrMpk = options.mpk || options.key || checkpoint.mpk || checkpoint.public_key || null;

  const verifyOpts = {
    revocationNotice,
  };

  const res = verifyCheckpoint(checkpoint, keyOrMpk, verifyOpts);

  let exitCode = ResultCode.INVALID;
  if (res.valid) {
    exitCode = ResultCode.VALID;
  } else if (res.status === VerificationStatus.KEY_REVOKED) {
    exitCode = ResultCode.REVOKED;
  } else if (res.status === VerificationStatus.UNKNOWN_SIGNING_KEY) {
    exitCode = ResultCode.UNVERIFIABLE;
  } else if (res.status === VerificationStatus.INVALID_CHECKPOINT) {
    exitCode = ResultCode.INSUFFICIENT_DATA;
  }

  return {
    status: ResultName[exitCode],
    exitCode,
    schemaVersion: checkpoint.schema_version,
    checkpointId: checkpoint.checkpoint_id,
    sourceId: checkpoint.source_id,
    sequenceRange: {
      start: checkpoint.start_sequence,
      end: checkpoint.end_sequence,
      eventCount: checkpoint.event_count,
    },
    merkleRoot: checkpoint.merkle_root,
    merkleAlgorithm: checkpoint.merkle_algorithm || MERKLE_ALGORITHM_CONTRACT,
    fssEpoch: checkpoint.fss_epoch ?? null,
    mpk: checkpoint.mpk || null,
    checks: res.checks,
    failures: res.failures,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Command: verify-merkle
// ─────────────────────────────────────────────────────────────────────────────
export function verifyMerkle(target, options = {}) {
  let input;
  try {
    input = loadInput(target);
  } catch (err) {
    return {
      status: ResultName[ResultCode.INSUFFICIENT_DATA],
      exitCode: ResultCode.INSUFFICIENT_DATA,
      message: `Failed to load Merkle proof: ${err.message}`,
    };
  }

  const proofData = input.data;

  // Bundle format: { event_hash, leaf_index, proof, root, algorithm, ... }
  if (proofData && typeof proofData === 'object' && Array.isArray(proofData.proof)) {
    const expectedRoot = options.root || proofData.root;
    if (!expectedRoot) {
      return {
        status: ResultName[ResultCode.INSUFFICIENT_DATA],
        exitCode: ResultCode.INSUFFICIENT_DATA,
        message: 'No Merkle root specified in proof bundle or via --root',
      };
    }

    const bundleResult = verifyInclusionProofBundle(proofData, expectedRoot);
    const exitCode = bundleResult.valid ? ResultCode.VALID : ResultCode.INVALID;

    return {
      status: ResultName[exitCode],
      exitCode,
      algorithm: bundleResult.algorithm || proofData.algorithm || MERKLE_ALGORITHM_CONTRACT,
      leafIndex: bundleResult.leaf_index ?? proofData.leaf_index,
      targetLeaf: proofData.event_hash,
      root: expectedRoot,
      valid: bundleResult.valid,
      error: bundleResult.error || null,
      reason: bundleResult.reason || null,
    };
  }

  // Raw array proof with options --leaf and --root
  if (Array.isArray(proofData)) {
    const leaf = options.leaf;
    const root = options.root;
    if (!leaf || !root) {
      return {
        status: ResultName[ResultCode.INSUFFICIENT_DATA],
        exitCode: ResultCode.INSUFFICIENT_DATA,
        message: 'Raw proof array requires both --leaf <hex> and --root <hex>',
      };
    }

    const algo = options.algo || MERKLE_ALGORITHM_CONTRACT;
    const isValid = verifyMerkleProof(leaf, proofData, root, { algorithm: algo });
    const exitCode = isValid ? ResultCode.VALID : ResultCode.INVALID;

    return {
      status: ResultName[exitCode],
      exitCode,
      algorithm: algo,
      targetLeaf: leaf,
      root,
      valid: isValid,
    };
  }

  return {
    status: ResultName[ResultCode.INSUFFICIENT_DATA],
    exitCode: ResultCode.INSUFFICIENT_DATA,
    message: 'Invalid Merkle proof input format',
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Command: verify-signature
// ─────────────────────────────────────────────────────────────────────────────
export function verifySignature(target, options = {}) {
  let payloadStr;
  try {
    if (fs.existsSync(target)) {
      payloadStr = fs.readFileSync(target, 'utf8');
    } else {
      payloadStr = target;
    }
  } catch (err) {
    return {
      status: ResultName[ResultCode.INSUFFICIENT_DATA],
      exitCode: ResultCode.INSUFFICIENT_DATA,
      message: `Failed to read payload file: ${err.message}`,
    };
  }

  const sig = options.sig || options.signature;
  const pubkey = options.pubkey || options['public-key'];
  const mpk = options.mpk;
  const isFss = Boolean(options.fss || mpk);

  if (!sig) {
    return {
      status: ResultName[ResultCode.INSUFFICIENT_DATA],
      exitCode: ResultCode.INSUFFICIENT_DATA,
      message: 'Missing required signature (--sig <hex>)',
    };
  }

  if (isFss) {
    const targetMpk = mpk || pubkey;
    if (!targetMpk) {
      return {
        status: ResultName[ResultCode.INSUFFICIENT_DATA],
        exitCode: ResultCode.INSUFFICIENT_DATA,
        message: 'FSS signature verification requires --mpk <hex>',
      };
    }

    let authPath = [];
    if (options['auth-path']) {
      try {
        const apInput = loadInput(options['auth-path']);
        authPath = Array.isArray(apInput.data) ? apInput.data : apInput.data?.authPath || [];
      } catch {
        // authPath remains empty
      }
    }

    const bundle = {
      version: 'HHH-MKT-FSS-v1',
      epoch: Number(options.epoch || 0),
      publicKey: pubkey,
      signature: sig,
      authPath,
      mpk: targetMpk,
    };

    const fssResult = verifyFssSignature(targetMpk, payloadStr, bundle);
    const exitCode = fssResult.valid ? ResultCode.VALID : ResultCode.INVALID;

    return {
      status: ResultName[exitCode],
      exitCode,
      algorithm: 'Ed25519-MKT-FSS',
      epoch: bundle.epoch,
      mpk: targetMpk,
      valid: fssResult.valid,
      error: fssResult.error || null,
      reason: fssResult.reason || null,
    };
  }

  // Standard Ed25519 signature
  if (!pubkey) {
    return {
      status: ResultName[ResultCode.INSUFFICIENT_DATA],
      exitCode: ResultCode.INSUFFICIENT_DATA,
      message: 'Signature verification requires --pubkey <hex>',
    };
  }

  try {
    const keyObject = publicKeyFromHex(pubkey);
    const sigBytes = Buffer.from(sig, 'hex');
    const isValid = crypto.verify(null, Buffer.from(payloadStr, 'utf8'), keyObject, sigBytes);
    const exitCode = isValid ? ResultCode.VALID : ResultCode.INVALID;

    return {
      status: ResultName[exitCode],
      exitCode,
      algorithm: 'Ed25519',
      publicKey: pubkey,
      valid: isValid,
    };
  } catch (err) {
    return {
      status: ResultName[ResultCode.INVALID],
      exitCode: ResultCode.INVALID,
      algorithm: 'Ed25519',
      valid: false,
      error: err.message,
    };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Command: verify-evidence
// ─────────────────────────────────────────────────────────────────────────────
export function verifyEvidence(target, options = {}) {
  let input;
  try {
    input = loadInput(target);
  } catch (err) {
    return {
      status: ResultName[ResultCode.INSUFFICIENT_DATA],
      exitCode: ResultCode.INSUFFICIENT_DATA,
      message: `Failed to load evidence bundle: ${err.message}`,
    };
  }

  const bundle = input.data;
  if (!bundle || typeof bundle !== 'object') {
    return {
      status: ResultName[ResultCode.INSUFFICIENT_DATA],
      exitCode: ResultCode.INSUFFICIENT_DATA,
      message: 'Evidence bundle must be a JSON object',
    };
  }

  const manifest = bundle.manifest || {};
  const events = bundle.events || [];
  const checkpoints = bundle.checkpoints || [];

  if (events.length === 0 && checkpoints.length === 0) {
    return {
      status: ResultName[ResultCode.INSUFFICIENT_DATA],
      exitCode: ResultCode.INSUFFICIENT_DATA,
      message: 'Evidence bundle contains no events or checkpoints',
    };
  }

  const errors = [];
  let chainValid = true;

  // 1. Verify Event Chain
  if (events.length > 0) {
    const chainRes = verifyChain(events, options);
    if (!chainRes.valid) {
      chainValid = false;
      errors.push(...chainRes.errors.map((e) => `Event chain error: ${e.reason || e.type}`));
    }
  }

  // 2. Verify Checkpoints
  let checkpointsVerified = 0;
  let checkpointsInvalid = 0;
  let checkpointsUnverifiable = 0;

  for (let i = 0; i < checkpoints.length; i++) {
    const cp = checkpoints[i];
    const cpRes = verifyCheckpointCmd(cp, options);
    if (cpRes.exitCode === ResultCode.VALID) {
      checkpointsVerified++;
    } else if (cpRes.exitCode === ResultCode.UNVERIFIABLE) {
      checkpointsUnverifiable++;
      errors.push(`Checkpoint [${i}] (${cp.checkpoint_id}): Unverifiable (missing key)`);
    } else {
      checkpointsInvalid++;
      errors.push(`Checkpoint [${i}] (${cp.checkpoint_id}): Invalid (${cpRes.failures?.join(', ') || 'failed'})`);
    }
  }

  // 3. Align event chain tip with latest checkpoint
  let rootAligned = true;
  if (events.length > 0 && checkpoints.length > 0) {
    const lastEvent = events[events.length - 1];
    const lastEventHash =
      lastEvent.current_hash ||
      lastEvent.event_hash ||
      (lastEvent.integrity && lastEvent.integrity.event_hash);
    const lastCp = checkpoints[checkpoints.length - 1];
    const lastCpRoot = lastCp.merkle_root || lastCp.root_hash;

    if (lastCp.merkle_leaf_hashes && Array.isArray(lastCp.merkle_leaf_hashes)) {
      if (!lastCp.merkle_leaf_hashes.includes(lastEventHash)) {
        rootAligned = false;
        errors.push(`Latest event hash "${lastEventHash}" not found in latest checkpoint leaf hashes`);
      }
    } else if (lastCpRoot && lastEventHash && lastCpRoot !== lastEventHash && checkpoints.length === 1 && events.length === 1) {
      rootAligned = false;
      errors.push(`Event hash "${lastEventHash}" does not match checkpoint root "${lastCpRoot}"`);
    }
  }

  let exitCode = ResultCode.VALID;
  if (!chainValid || checkpointsInvalid > 0 || !rootAligned) {
    exitCode = ResultCode.INVALID;
  } else if (checkpointsUnverifiable > 0 && checkpointsVerified > 0) {
    exitCode = ResultCode.PARTIALLY_VERIFIED;
  } else if (checkpointsUnverifiable > 0 && checkpointsVerified === 0) {
    exitCode = ResultCode.UNVERIFIABLE;
  }

  return {
    status: ResultName[exitCode],
    exitCode,
    bundleId: bundle.bundle_id || manifest.bundle_id || null,
    sourceId: manifest.source_id || null,
    eventsChecked: events.length,
    checkpointsChecked: checkpoints.length,
    checkpointsVerified,
    checkpointsInvalid,
    checkpointsUnverifiable,
    chainValid,
    rootAligned,
    errors,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Command: inspect-report
// ─────────────────────────────────────────────────────────────────────────────
export function inspectReport(target, options = {}) {
  let input;
  try {
    input = loadInput(target);
  } catch (err) {
    return {
      status: ResultName[ResultCode.INSUFFICIENT_DATA],
      exitCode: ResultCode.INSUFFICIENT_DATA,
      message: `Failed to load forensic report: ${err.message}`,
    };
  }

  const report = input.data;
  if (!report || typeof report !== 'object') {
    return {
      status: ResultName[ResultCode.INSUFFICIENT_DATA],
      exitCode: ResultCode.INSUFFICIENT_DATA,
      message: 'Forensic report must be a JSON object',
    };
  }

  const requiredFields = ['schema_version', 'incident_id', 'title', 'summary', 'integrity_verification'];
  const missing = requiredFields.filter((f) => report[f] === undefined);
  if (missing.length > 0) {
    return {
      status: ResultName[ResultCode.INSUFFICIENT_DATA],
      exitCode: ResultCode.INSUFFICIENT_DATA,
      message: `Forensic report is missing required fields: ${missing.join(', ')}`,
    };
  }

  const integrity = report.integrity_verification || {};
  const isIntegrityValid =
    integrity.status === 'VERIFIED' ||
    integrity.status === 'VALID' ||
    (integrity.chain_valid === true && integrity.signatures_valid === true && (!integrity.errors || integrity.errors.length === 0));

  const exitCode = isIntegrityValid ? ResultCode.VALID : ResultCode.INVALID;

  return {
    status: ResultName[exitCode],
    exitCode,
    reportSummary: {
      incidentId: report.incident_id,
      title: report.title,
      overallSeverity: report.overall_severity || 'UNKNOWN',
      investigator: report.investigator || 'UNKNOWN',
      generatedAt: report.generated_at,
      totalEventsCollected: report.summary?.total_events_collected ?? 0,
      affectedSources: report.summary?.affected_sources ?? [],
      correlationFindingsCount: report.summary?.correlation_findings_count ?? report.correlation_findings?.length ?? 0,
      timelineMilestonesCount: report.summary?.timeline_milestones_count ?? report.attack_timeline?.length ?? 0,
      missingEvidenceWarningsCount: report.summary?.missing_evidence_warnings_count ?? report.missing_evidence_warnings?.length ?? 0,
      cryptographicIntegrityStatus: integrity.status || (isIntegrityValid ? 'VERIFIED' : 'INTEGRITY_COMPROMISED'),
      chainValid: integrity.chain_valid ?? isIntegrityValid,
      signaturesValid: integrity.signatures_valid ?? isIntegrityValid,
      integrityErrors: integrity.errors || [],
    },
    recommendationsCount: report.recommended_investigation_steps?.length ?? 0,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI Main Entry Point
// ─────────────────────────────────────────────────────────────────────────────
export function main(args = process.argv.slice(2)) {
  const { command, target, options } = parseArgs(args);

  if (!command || command === '--help' || command === '-h' || command === 'help') {
    printHelp();
    process.exit(0);
  }

  let result;
  switch (command) {
    case 'verify-log':
      result = verifyLog(target, options);
      break;
    case 'verify-chain':
      result = verifyChain(target, options);
      break;
    case 'verify-checkpoint':
      result = verifyCheckpointCmd(target, options);
      break;
    case 'verify-merkle':
      result = verifyMerkle(target, options);
      break;
    case 'verify-signature':
      result = verifySignature(target, options);
      break;
    case 'verify-evidence':
      result = verifyEvidence(target, options);
      break;
    case 'inspect-report':
      result = inspectReport(target, options);
      break;
    default:
      console.error(`Unknown command: "${command}"\nRun "hhh --help" for available commands.`);
      process.exit(ResultCode.INSUFFICIENT_DATA);
  }

  if (options.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    printHumanOutput(command, result);
  }

  process.exit(result.exitCode);
}

function printHumanOutput(command, result) {
  const colorReset = '\x1b[0m';
  const colorGreen = '\x1b[32m';
  const colorRed = '\x1b[31m';
  const colorYellow = '\x1b[33m';
  const colorCyan = '\x1b[36m';
  const colorBold = '\x1b[1m';

  let statusColor = colorGreen;
  if (result.exitCode === ResultCode.INVALID || result.exitCode === ResultCode.REVOKED) {
    statusColor = colorRed;
  } else if (result.exitCode === ResultCode.PARTIALLY_VERIFIED || result.exitCode === ResultCode.UNVERIFIABLE) {
    statusColor = colorYellow;
  } else if (result.exitCode === ResultCode.INSUFFICIENT_DATA) {
    statusColor = colorYellow;
  }

  console.log(`\n${colorBold}HHH Security & Forensic Verification Tool${colorReset}`);
  console.log(`Command:  ${colorCyan}${command}${colorReset}`);
  console.log(`Status:   ${statusColor}${colorBold}${result.status}${colorReset} (Exit Code: ${result.exitCode})\n`);

  if (result.message) {
    console.log(`Message:  ${result.message}`);
  }

  if (result.recordsExamined !== undefined) {
    console.log(`Records Examined:  ${result.recordsExamined}`);
    console.log(`Valid Records:     ${result.validRecords}`);
    console.log(`Invalid Records:   ${result.invalidRecords}`);
  }

  if (result.schemaVersion) {
    console.log(`Schema Version:    ${result.schemaVersion}`);
  }

  if (result.checkpointId) {
    console.log(`Checkpoint ID:     ${result.checkpointId}`);
    console.log(`Sequence Range:    [${result.sequenceRange.start}..${result.sequenceRange.end}] (${result.sequenceRange.eventCount} events)`);
    console.log(`Merkle Root:       ${result.merkleRoot}`);
    console.log(`Merkle Algorithm:  ${result.merkleAlgorithm}`);
    if (result.fssEpoch !== null) console.log(`FSS Epoch:         ${result.fssEpoch}`);
    if (result.mpk) console.log(`Master PubKey:     ${result.mpk}`);
  }

  if (result.firstFailure) {
    console.log(`\n${colorRed}First Failure:${colorReset}`);
    console.log(`  Index:    ${result.firstFailure.index ?? result.firstFailure.sequenceNumber ?? 'N/A'}`);
    console.log(`  Reason:   ${result.firstFailure.reason ?? result.firstFailure.error ?? 'Unknown'}`);
    if (result.firstFailure.storedHash) console.log(`  Stored:   ${result.firstFailure.storedHash}`);
    if (result.firstFailure.computedHash) console.log(`  Computed: ${result.firstFailure.computedHash}`);
  }

  if (result.errors && result.errors.length > 0) {
    console.log(`\n${colorRed}Errors (${result.errors.length}):${colorReset}`);
    result.errors.slice(0, 10).forEach((err, idx) => {
      console.log(`  [${idx + 1}] ${typeof err === 'string' ? err : err.reason || JSON.stringify(err)}`);
    });
    if (result.errors.length > 10) {
      console.log(`  ... and ${result.errors.length - 10} more errors.`);
    }
  }

  if (result.reportSummary) {
    const s = result.reportSummary;
    console.log(`Incident ID:       ${s.incidentId}`);
    console.log(`Title:             ${s.title}`);
    console.log(`Severity:          ${s.overallSeverity}`);
    console.log(`Investigator:      ${s.investigator}`);
    console.log(`Generated At:      ${s.generatedAt}`);
    console.log(`Total Events:      ${s.totalEventsCollected}`);
    console.log(`Timeline Count:    ${s.timelineMilestonesCount}`);
    console.log(`Findings Count:    ${s.correlationFindingsCount}`);
    console.log(`Integrity Status:  ${s.cryptographicIntegrityStatus}`);
  }

  console.log('');
}

function printHelp() {
  console.log(`
HHH — Hash. Hunt. Harden.
Adaptive Forward-Secure Cryptography & Forensic Verification CLI

USAGE:
  hhh <command> [target] [options]

COMMANDS:
  verify-log <file|json>        Verify single canonical event hash (LOGN-HASH-v1 or legacy)
  verify-chain <file>           Verify sequential hash chain continuity and event integrity
  verify-checkpoint <file>      Verify signed checkpoint (FSS Ed25519-MKT-FSS or legacy Ed25519)
  verify-merkle <proof-file>    Verify Merkle inclusion proof (HHH-CONTRACT-DUP-v1 or RFC-6962)
  verify-signature <file>       Verify standalone cryptographic signature
  verify-evidence <bundle-file> Verify sealed forensic evidence package
  inspect-report <report-file>  Inspect and validate structured forensic investigation report

OPTIONS:
  --json                        Output structured JSON result
  --legacy                      Force legacy 7-field hash calculation (for verify-log)
  --mpk <hex>                   Master Public Key for FSS checkpoint / signature verification
  --key <hex>                   Public key for legacy checkpoint / signature verification
  --sig <hex>                   Signature bytes (for verify-signature)
  --pubkey <hex>                Public key (for verify-signature)
  --root <hex>                  Expected Merkle root
  --leaf <hex>                  Target leaf hash (for raw proof verification)
  --algo <name>                 Merkle algorithm: HHH-CONTRACT-DUP-v1 or RFC-6962
  --revocation <file>           Revocation notice JSON file to test against revoked epochs
  --help, -h                    Show this help screen

EXIT CODES:
  0: VALID              Verification succeeded completely
  1: INVALID            Cryptographic failure, tampering, or broken chain
  2: PARTIALLY VERIFIED Some artifacts verified, but verification incomplete
  3: UNVERIFIABLE       Required keys or proofs unavailable to verify
  4: REVOKED            Signer key or epoch has been revoked
  5: INSUFFICIENT DATA  Missing required parameters or malformed input
`);
}

// Auto-run if executed directly as a script
const isMainModule = process.argv[1] && (
  process.argv[1].endsWith('hhh.js') ||
  process.argv[1].endsWith('hhh') ||
  process.argv[1] === fileURLToPath(import.meta.url)
);

if (isMainModule) {
  main();
}
