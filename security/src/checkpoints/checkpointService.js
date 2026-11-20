/**
 * @module checkpointService
 * @description Signed checkpoint generation and verification.
 *
 * Implements the checkpoint schema and signing specification in:
 *   docs/technical-integration-contract.md §5
 *
 * A checkpoint commits to a sequence window of log events by:
 *   1. Accepting ordered Log.currentHash values for the window
 *   2. Building a Merkle tree over those hashes (§6)
 *   3. Constructing a canonical signing payload (§5.3)
 *   4. Signing the payload with Ed25519 (§4)
 *   5. Returning the complete signed checkpoint document
 *
 * IMPORTANT per §5.3:
 *   - The signature covers the payload WITHOUT the "signature" and "blockchain" fields
 *   - Canonical serialization is used for the signing payload (canonicalJson from Phase 1)
 *   - The signature encodes as lowercase hex-128 (64 raw Ed25519 bytes)
 *
 * WHAT CHECKPOINTS PROVE:
 *   A signed checkpoint with a valid signature proves that:
 *   - The Security service (the key holder) observed a specific set of log hashes
 *   - In a specific sequence range for a specific source
 *   - At a specific timestamp
 *   - Committed to a specific Merkle root
 *   It does NOT prove that the original log events were authentic or unaltered
 *   before the checkpoint was created. For that, on-chain anchoring (Phase 3) is needed.
 *
 * WHAT CHECKPOINTS DO NOT PROVE:
 *   - That a chain rewrite did not occur BEFORE the checkpoint was created
 *   - That the events in merkle_leaf_hashes accurately represent the original events
 *   - Authenticity of events themselves (use hash chain + signatures together)
 */

import { verify as cryptoVerify } from 'node:crypto';
import { buildMerkleTree, getMerkleRoot, generateMerkleProof, verifyMerkleProof } from '../merkle/merkleTree.js';
import { canonicalJson } from '../crypto/canonicalJson.js';
import { generateUuidV4, publicKeyFromHex } from '../keys/keyManager.js';
import { BlockchainError, BlockchainErrorCode } from '../blockchain/errors.js';

// ── Schema constants ──────────────────────────────────────────────────────────

/**
 * Schema version string — included in canonical signing payload.
 * Per §5.1: bumping this string invalidates all existing signatures.
 *
 * @type {string}
 */
export const CHECKPOINT_SCHEMA_VERSION = 'logn-checkpoint-v1';

/**
 * Signature algorithm identifier stored in checkpoint documents.
 * @type {string}
 */
export const SIGNATURE_ALGORITHM = 'Ed25519';

/**
 * Documents what was signed — always this exact string.
 * @type {string}
 */
export const SIGNATURE_INPUT_LABEL = 'logn-checkpoint-v1';

// ── Verification status codes ─────────────────────────────────────────────────

/**
 * Possible verification status codes returned by verifyCheckpoint().
 *
 * @enum {string}
 */
export const VerificationStatus = Object.freeze({
  VERIFIED:            'VERIFIED',
  INVALID_SIGNATURE:   'INVALID_SIGNATURE',
  MERKLE_MISMATCH:     'MERKLE_MISMATCH',
  INVALID_PROOF:       'INVALID_PROOF',
  UNKNOWN_SIGNING_KEY: 'UNKNOWN_SIGNING_KEY',
  INVALID_CHECKPOINT:  'INVALID_CHECKPOINT',
  VERIFICATION_ERROR:  'VERIFICATION_ERROR',
});

// ── Canonical signing payload ─────────────────────────────────────────────────

/**
 * Construct the canonical signing payload for a checkpoint.
 *
 * Per §5.3: exclude "signature" and "blockchain" fields; sort all keys
 * lexicographically by Unicode code point; no whitespace; UTF-8 preserved.
 *
 * @param {object} checkpoint - The checkpoint document (may include signature and blockchain).
 * @returns {string} Canonical JSON string of the signing payload.
 */
export function buildSigningPayload(checkpoint) {
  if (!checkpoint || typeof checkpoint !== 'object') {
    throw new TypeError('buildSigningPayload: checkpoint must be an object');
  }
  // Build a copy without "signature" and "blockchain"
  const payload = {};
  for (const [key, value] of Object.entries(checkpoint)) {
    if (key === 'signature' || key === 'blockchain') continue;
    payload[key] = value;
  }
  return canonicalJson(payload);
}

// ── Checkpoint generation ─────────────────────────────────────────────────────

/**
 * @typedef {object} CheckpointInput
 * @property {string}   source_id      - Log source identifier.
 * @property {number}   start_sequence - First sequence number in the window (inclusive).
 * @property {number}   end_sequence   - Last sequence number in the window (inclusive).
 * @property {string[]} leaf_hashes    - Ordered Log.currentHash hex-64 values (ascending seq).
 */

/**
 * @typedef {object} SignedCheckpoint
 * @property {string}   schema_version    - Always "logn-checkpoint-v1".
 * @property {string}   checkpoint_id     - UUID v4 unique identifier.
 * @property {string}   source_id         - Log source identifier.
 * @property {number}   start_sequence    - First sequence number (inclusive).
 * @property {number}   end_sequence      - Last sequence number (inclusive).
 * @property {number}   event_count       - end_sequence - start_sequence + 1.
 * @property {string}   merkle_root       - Hex-64 Merkle root over leaf hashes.
 * @property {string[]} merkle_leaf_hashes - Ordered array of hex-64 Log.currentHash values.
 * @property {string}   timestamp         - ISO-8601 UTC creation timestamp.
 * @property {string}   signing_key_id    - UUID v4 key identifier.
 * @property {string}   signer_public_key - Hex-64 Ed25519 public key.
 * @property {string}   signature         - Hex-128 Ed25519 signature of the signing payload.
 * @property {string}   signature_algorithm - Always "Ed25519".
 * @property {string}   signature_input   - Always "logn-checkpoint-v1".
 * @property {object|null} blockchain     - Null until Phase 3 on-chain anchoring.
 */

/**
 * Generate a signed checkpoint for a window of log events.
 *
 * Steps:
 *   1. Validate inputs (source_id, sequences, leaf_hashes count)
 *   2. Build Merkle tree over leaf_hashes
 *   3. Compute Merkle root
 *   4. Build the checkpoint document (sans signature)
 *   5. Serialise signing payload canonically
 *   6. Sign with Ed25519 private key
 *   7. Attach signature and return
 *
 * @param {CheckpointInput} input    - Window parameters and leaf hashes.
 * @param {import('../keys/keyManager.js').KeyManager} keyManager - Loaded KeyManager.
 * @returns {SignedCheckpoint} The complete signed checkpoint document.
 * @throws {TypeError} If inputs are invalid.
 * @throws {RangeError} If event_count does not match sequence range.
 */
export function createCheckpoint(input, keyManager) {
  // ── Input validation ────────────────────────────────────────────────────────
  if (!input || typeof input !== 'object') {
    throw new TypeError('createCheckpoint: input must be an object');
  }
  const { source_id, start_sequence, end_sequence, leaf_hashes } = input;

  if (!source_id || typeof source_id !== 'string') {
    throw new TypeError('createCheckpoint: source_id must be a non-empty string');
  }
  if (!Number.isInteger(start_sequence) || start_sequence < 1) {
    throw new TypeError('createCheckpoint: start_sequence must be a positive integer');
  }
  if (!Number.isInteger(end_sequence) || end_sequence < start_sequence) {
    throw new TypeError('createCheckpoint: end_sequence must be >= start_sequence');
  }
  if (!Array.isArray(leaf_hashes) || leaf_hashes.length === 0) {
    throw new TypeError('createCheckpoint: leaf_hashes must be a non-empty array');
  }

  const expectedCount = end_sequence - start_sequence + 1;
  if (leaf_hashes.length !== expectedCount) {
    throw new RangeError(
      `createCheckpoint: leaf_hashes has ${leaf_hashes.length} entries but sequence range [${start_sequence}, ${end_sequence}] requires ${expectedCount}`
    );
  }

  if (!keyManager || !keyManager.isLoaded) {
    throw new Error('createCheckpoint: keyManager must be loaded before creating checkpoints');
  }

  // ── Build Merkle tree ───────────────────────────────────────────────────────
  const tree       = buildMerkleTree(leaf_hashes);
  const merkleRoot = getMerkleRoot(tree);

  // ── Build timestamp ─────────────────────────────────────────────────────────
  const timestamp = new Date().toISOString().replace(/\.\d+Z$/, 'Z');

  // ── Assemble unsigned checkpoint ────────────────────────────────────────────
  const checkpoint = {
    schema_version:      CHECKPOINT_SCHEMA_VERSION,
    checkpoint_id:       input.checkpoint_id || generateUuidV4(),
    source_id,
    start_sequence,
    end_sequence,
    event_count:         expectedCount,
    merkle_root:         merkleRoot,
    merkle_leaf_hashes:  leaf_hashes.slice(), // defensive copy
    timestamp,
    signing_key_id:      keyManager.keyId,
    signer_public_key:   keyManager.publicKeyHex,
    signature_algorithm: SIGNATURE_ALGORITHM,
    signature_input:     SIGNATURE_INPUT_LABEL,
    // "signature" and "blockchain" excluded from signing payload per §5.3
  };

  // ── Sign the canonical payload ──────────────────────────────────────────────
  const payloadStr = buildSigningPayload(checkpoint);
  const signature  = keyManager.sign(payloadStr);

  // ── Return complete signed checkpoint ───────────────────────────────────────
  checkpoint.signature = signature;
  checkpoint.blockchain = null; // set in Phase 3 after on-chain anchoring

  return checkpoint;
}

// ── Checkpoint verification ───────────────────────────────────────────────────

/**
 * @typedef {object} VerificationResult
 * @property {string}   status   - One of VerificationStatus codes.
 * @property {boolean}  valid    - true iff status === "VERIFIED".
 * @property {string[]} failures - Array of human-readable failure descriptions.
 * @property {object}   checks   - Per-check boolean results.
 */

/**
 * Verify a signed checkpoint document.
 *
 * Checks performed (in order):
 *   1. Schema structure — required fields present, correct types
 *   2. Schema version — must be "logn-checkpoint-v1"
 *   3. event_count consistency — must equal end - start + 1
 *   4. leaf_hashes count — must equal event_count
 *   5. Merkle root correctness — rebuild tree from leaf_hashes, compare root
 *   6. Signing key ID lookup — key must be recognized in registry (or keyManager's current key)
 *   7. Signature verification — Ed25519 verify over canonical signing payload
 *
 * Returns a structured result with status, failures and per-check details.
 * Does NOT return VERIFIED unless ALL checks pass.
 *
 * @param {object} checkpoint - The checkpoint document to verify.
 * @param {import('../keys/keyManager.js').KeyManager} [keyManager] - For public key lookup.
 * @returns {VerificationResult}
 */
export function verifyCheckpoint(checkpoint, keyManager) {
  const failures = [];
  const checks   = {
    structure:      false,
    schema_version: false,
    event_count:    false,
    leaf_count:     false,
    merkle_root:    false,
    signing_key:    false,
    signature:      false,
  };

  if (!checkpoint || typeof checkpoint !== 'object') {
    failures.push('Checkpoint must be a non-null object');
    return _result(VerificationStatus.INVALID_CHECKPOINT, failures, checks);
  }

  // ── Check 1: Structure ──────────────────────────────────────────────────────
  const required = [
    'schema_version', 'checkpoint_id', 'source_id',
    'start_sequence', 'end_sequence',  'event_count',
    'merkle_root',    'merkle_leaf_hashes', 'timestamp',
    'signing_key_id', 'signer_public_key',  'signature',
    'signature_algorithm', 'signature_input',
  ];
  const missing = required.filter((f) => checkpoint[f] === undefined || checkpoint[f] === null);
  if (missing.length > 0) {
    failures.push(`Missing required fields: ${missing.join(', ')}`);
    return _result(VerificationStatus.INVALID_CHECKPOINT, failures, checks);
  }
  checks.structure = true;

  // ── Check 2: Schema version ─────────────────────────────────────────────────
  if (checkpoint.schema_version !== CHECKPOINT_SCHEMA_VERSION) {
    failures.push(
      `Unexpected schema_version "${checkpoint.schema_version}" (expected "${CHECKPOINT_SCHEMA_VERSION}")`
    );
    return _result(VerificationStatus.INVALID_CHECKPOINT, failures, checks);
  }
  checks.schema_version = true;

  // ── Check 3: event_count consistency ───────────────────────────────────────
  const expectedCount = checkpoint.end_sequence - checkpoint.start_sequence + 1;
  if (!Number.isInteger(checkpoint.start_sequence) ||
      !Number.isInteger(checkpoint.end_sequence) ||
      checkpoint.start_sequence < 1 ||
      checkpoint.end_sequence < checkpoint.start_sequence ||
      checkpoint.event_count !== expectedCount) {
    failures.push(
      `event_count ${checkpoint.event_count} inconsistent with sequence range [${checkpoint.start_sequence}, ${checkpoint.end_sequence}] (expected ${expectedCount})`
    );
    return _result(VerificationStatus.INVALID_CHECKPOINT, failures, checks);
  }
  checks.event_count = true;

  // ── Check 4: leaf_hashes count ─────────────────────────────────────────────
  if (!Array.isArray(checkpoint.merkle_leaf_hashes) ||
      checkpoint.merkle_leaf_hashes.length !== checkpoint.event_count) {
    failures.push(
      `merkle_leaf_hashes length ${checkpoint.merkle_leaf_hashes?.length} ≠ event_count ${checkpoint.event_count}`
    );
    return _result(VerificationStatus.INVALID_CHECKPOINT, failures, checks);
  }
  checks.leaf_count = true;

  // ── Check 5: Merkle root ────────────────────────────────────────────────────
  try {
    const rebuilt = buildMerkleTree(checkpoint.merkle_leaf_hashes);
    const computedRoot = getMerkleRoot(rebuilt);
    if (computedRoot !== checkpoint.merkle_root) {
      failures.push(
        `Merkle root mismatch: computed "${computedRoot}" ≠ stored "${checkpoint.merkle_root}"`
      );
      checks.merkle_root = false;
      return _result(VerificationStatus.MERKLE_MISMATCH, failures, checks);
    }
    checks.merkle_root = true;
  } catch (err) {
    failures.push(`Merkle root computation failed: ${err.message}`);
    checks.merkle_root = false;
    return _result(VerificationStatus.MERKLE_MISMATCH, failures, checks);
  }

  // ── Check 6: Signing key lookup ─────────────────────────────────────────────
  let resolvedPublicKey = null;
  if (keyManager) {
    // Try current key first
    if (keyManager.isLoaded && keyManager.keyId === checkpoint.signing_key_id) {
      resolvedPublicKey = keyManager.publicKeyHex;
    } else {
      // Try historical registry
      const entry = keyManager.getPublicKeyById(checkpoint.signing_key_id);
      if (entry) {
        resolvedPublicKey = entry.public_key_hex;
      }
    }

    if (!resolvedPublicKey) {
      failures.push(`signing_key_id "${checkpoint.signing_key_id}" not found in KeyManager active key or registry`);
      checks.signing_key = false;
      return _result(VerificationStatus.UNKNOWN_SIGNING_KEY, failures, checks);
    }

    // Verify key match against trusted registry
    if (resolvedPublicKey !== checkpoint.signer_public_key) {
      failures.push(
        `Registry public key for "${checkpoint.signing_key_id}" does not match embedded signer_public_key`
      );
      checks.signing_key = false;
      return _result(VerificationStatus.UNKNOWN_SIGNING_KEY, failures, checks);
    }
    checks.signing_key = true;
  } else {
    // Trusted provenance enforcement: Never trust an arbitrary public key supplied by an untrusted checkpoint
    failures.push('KeyManager is required to verify signing key provenance against the trusted key registry');
    checks.signing_key = false;
    return _result(VerificationStatus.UNKNOWN_SIGNING_KEY, failures, checks);
  }

  // ── Check 7: Signature verification ────────────────────────────────────────
  try {
    const payloadStr = buildSigningPayload(checkpoint);
    const sigValid = _verifySignatureRaw(payloadStr, checkpoint.signature, resolvedPublicKey);

    if (!sigValid) {
      failures.push('Ed25519 signature verification failed');
      checks.signature = false;
      return _result(VerificationStatus.INVALID_SIGNATURE, failures, checks);
    }
    checks.signature = true;
  } catch (err) {
    failures.push(`Signature check threw: ${err.message}`);
    return _result(VerificationStatus.VERIFICATION_ERROR, failures, checks);
  }

  return _result(VerificationStatus.VERIFIED, [], checks);
}

/**
 * Verify a Merkle inclusion proof for a specific leaf in a checkpoint.
 *
 * @param {SignedCheckpoint} checkpoint   - The checkpoint containing the proof root.
 * @param {string}           currentHash - The Log.currentHash to verify (hex-64).
 * @param {object[]}         proof       - The proof steps from generateMerkleProof().
 * @returns {VerificationResult}
 */
export function verifyCheckpointProof(checkpoint, currentHash, proof) {
  const failures = [];
  const checks   = { proof_valid: false };

  if (!checkpoint || typeof checkpoint !== 'object' || !checkpoint.merkle_root) {
    failures.push('Invalid checkpoint object');
    return _result(VerificationStatus.INVALID_CHECKPOINT, failures, checks);
  }

  try {
    const isValid = verifyMerkleProof(currentHash, proof, checkpoint.merkle_root);
    if (!isValid) {
      failures.push('Merkle inclusion proof verification failed');
      return _result(VerificationStatus.INVALID_PROOF, failures, checks);
    }
    checks.proof_valid = true;
    return _result(VerificationStatus.VERIFIED, [], checks);
  } catch (err) {
    failures.push(`Proof verification threw: ${err.message}`);
    return _result(VerificationStatus.VERIFICATION_ERROR, failures, checks);
  }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/**
 * Verify Ed25519 signature directly from raw strings.
 *
 * @param {string} payloadStr
 * @param {string} signatureHex
 * @param {string} publicKeyHex
 * @returns {boolean}
 */
function _verifySignatureRaw(payloadStr, signatureHex, publicKeyHex) {
  if (typeof signatureHex !== 'string' || !/^[0-9a-fA-F]{128}$/.test(signatureHex)) {
    return false;
  }
  if (typeof publicKeyHex !== 'string' || !/^[0-9a-fA-F]{64}$/.test(publicKeyHex)) {
    return false;
  }
  const buf    = Buffer.from(payloadStr, 'utf8');
  const sigBuf = Buffer.from(signatureHex, 'hex');
  const pubKey = publicKeyFromHex(publicKeyHex);
  try {
    return cryptoVerify(null, buf, pubKey, sigBuf);
  } catch {
    return false;
  }
}

/**
 * @param {string}   status
 * @param {string[]} failures
 * @param {object}   checks
 * @returns {VerificationResult}
 */
function _result(status, failures, checks) {
  return {
    status,
    valid:    status === VerificationStatus.VERIFIED,
    failures: [...failures],
    checks:   { ...checks },
  };
}

/**
 * Anchors a completed, signed checkpoint to the blockchain.
 *
 * Implements the Step 3 workflow:
 *  1. Receives completed signed checkpoint.
 *  2. Validates structure and verifies its Ed25519 signature.
 *  3. Extracts existing checkpoint ID and Merkle root.
 *  4. Extracts sequence range, event count, and timestamp.
 *  5. Submits commitment to SecureLogAnchor via blockchainService.
 *  6. Waits for transaction confirmation.
 *  7. Records transaction metadata into checkpoint.blockchain.
 *  8. Retrieves commitment from the contract.
 *  9. Compares retrieved root and metadata with the original checkpoint.
 *
 * @param {SignedCheckpoint} checkpoint - Valid signed checkpoint document.
 * @param {import('../blockchain/blockchainService.js').BlockchainService} blockchainService
 * @param {import('../keys/keyManager.js').KeyManager} [keyManager]
 * @returns {Promise<{ checkpoint: SignedCheckpoint, anchorResult: object, verified: boolean }>}
 */
export async function anchorSignedCheckpoint(checkpoint, blockchainService, keyManager) {
  if (!checkpoint || typeof checkpoint !== 'object') {
    throw new BlockchainError(
      BlockchainErrorCode.INVALID_CHECKPOINT,
      'checkpoint must be a non-null object'
    );
  }

  if (!blockchainService) {
    throw new TypeError('blockchainService is required');
  }

  // 1 & 2: Verify checkpoint structure and signature
  const verifyResult = verifyCheckpoint(checkpoint, keyManager);
  if (!verifyResult.valid) {
    const isSigError = verifyResult.status === VerificationStatus.INVALID_SIGNATURE;
    const isKeyError = verifyResult.status === VerificationStatus.UNKNOWN_SIGNING_KEY;
    const errCode = isSigError || isKeyError
      ? BlockchainErrorCode.INVALID_SIGNATURE
      : BlockchainErrorCode.INVALID_CHECKPOINT;

    throw new BlockchainError(
      errCode,
      `Cannot anchor invalid checkpoint: ${verifyResult.failures.join('; ')}`,
      { details: verifyResult }
    );
  }

  // 3, 4, 5 & 6: Extract parameters and submit commitment
  const anchorParams = {
    checkpointId: checkpoint.checkpoint_id,
    merkleRoot: checkpoint.merkle_root,
    startSequence: checkpoint.start_sequence,
    endSequence: checkpoint.end_sequence,
    eventCount: checkpoint.event_count,
    timestamp: checkpoint.timestamp,
  };

  const anchorResult = await blockchainService.anchorCheckpoint(anchorParams);

  // 7: Record transaction metadata
  checkpoint.blockchain = {
    contractAddress: anchorResult.contractAddress,
    txHash:          anchorResult.txHash,
    blockNumber:     anchorResult.blockNumber,
    chainId:         anchorResult.chainId,
    anchoredAt:      anchorResult.anchoredAt,
    gasUsed:         anchorResult.gasUsed,
  };

  // 8 & 9: Retrieve commitment and compare with original checkpoint
  const onChainCommitment = await blockchainService.getCommitment(checkpoint.checkpoint_id);

  // Compare Merkle root (normalize 0x prefix and lowercase)
  const storedRoot = checkpoint.merkle_root.toLowerCase().replace(/^0x/, '');
  const onChainRoot = onChainCommitment.merkleRoot.toLowerCase().replace(/^0x/, '');

  if (storedRoot !== onChainRoot) {
    throw new BlockchainError(
      BlockchainErrorCode.MERKLE_MISMATCH,
      `On-chain root "${onChainRoot}" does not match checkpoint root "${storedRoot}"`
    );
  }

  if (
    onChainCommitment.startSequence !== checkpoint.start_sequence ||
    onChainCommitment.endSequence !== checkpoint.end_sequence ||
    onChainCommitment.eventCount !== checkpoint.event_count
  ) {
    throw new BlockchainError(
      BlockchainErrorCode.INVALID_CHECKPOINT,
      `On-chain commitment sequence bounds [${onChainCommitment.startSequence}, ${onChainCommitment.endSequence}] or count (${onChainCommitment.eventCount}) do not match checkpoint [${checkpoint.start_sequence}, ${checkpoint.end_sequence}] count (${checkpoint.event_count})`
    );
  }

  return {
    checkpoint,
    anchorResult,
    verified: true,
  };
}

export default {
  CHECKPOINT_SCHEMA_VERSION,
  SIGNATURE_ALGORITHM,
  SIGNATURE_INPUT_LABEL,
  VerificationStatus,
  buildSigningPayload,
  createCheckpoint,
  verifyCheckpoint,
  verifyCheckpointProof,
  anchorSignedCheckpoint,
};
