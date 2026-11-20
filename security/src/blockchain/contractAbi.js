/**
 * @module contractAbi
 * @description ABI definition and parameter formatters for SecureLogAnchor.
 */

import { ethers } from 'ethers';

/**
 * Standard ABI for the SecureLogAnchor contract (ISecureLogAnchor).
 */
export const SECURE_LOG_ANCHOR_ABI = [
  // Write functions
  'function anchorCheckpoint(bytes32 checkpointId, bytes32 merkleRoot, uint64 startSequence, uint64 endSequence, uint32 eventCount, uint64 timestamp) external',
  'function setSubmitter(address submitter, bool authorized) external',

  // Read functions
  'function getCommitment(bytes32 checkpointId) external view returns (tuple(bytes32 merkleRoot, uint64 startSequence, uint64 endSequence, uint32 eventCount, uint64 timestamp, address submitter, uint256 blockNumber, bool exists))',
  'function commitmentExists(bytes32 checkpointId) external view returns (bool)',
  'function verifyCommitment(bytes32 checkpointId, bytes32 expectedMerkleRoot) external view returns (bool isMatch)',
  'function getTotalCheckpoints() external view returns (uint256)',
  'function getCheckpointIds(uint256 offset, uint256 limit) external view returns (bytes32[])',
  'function owner() external view returns (address)',
  'function authorizedSubmitters(address submitter) external view returns (bool)',

  // Events
  'event CheckpointAnchored(bytes32 indexed checkpointId, bytes32 indexed merkleRoot, uint64 startSequence, uint64 endSequence, uint32 eventCount, address indexed submitter, uint256 blockNumber, uint64 timestamp)',
  'event SubmitterUpdated(address indexed submitter, bool authorized)',
];

/**
 * Formats a checkpoint ID into a 32-byte hex string (bytes32).
 * Per docs/technical-integration-contract.md §7.6:
 * If the input is a UUID string, compute ethers.keccak256(ethers.toUtf8Bytes(id)).
 * If already a 0x-prefixed 64-character hex string, returns it directly.
 *
 * @param {string} id - UUID string or bytes32 hex string.
 * @returns {string} 0x-prefixed 64-character hex string (32 bytes).
 * @throws {TypeError} If id is invalid.
 */
export function formatCheckpointId(id) {
  if (typeof id !== 'string' || id.trim() === '') {
    throw new TypeError('checkpointId must be a non-empty string');
  }
  const trimmed = id.trim();
  if (/^0x[0-9a-fA-F]{64}$/.test(trimmed)) {
    return trimmed.toLowerCase();
  }
  return ethers.keccak256(ethers.toUtf8Bytes(trimmed));
}

/**
 * Formats a Merkle root into a 0x-prefixed 32-byte hex string.
 *
 * @param {string} root - 64-char hex string (with or without 0x prefix).
 * @returns {string} 0x-prefixed 64-character hex string.
 * @throws {TypeError} If root is invalid.
 */
export function formatMerkleRoot(root) {
  if (typeof root !== 'string' || root.trim() === '') {
    throw new TypeError('merkleRoot must be a non-empty string');
  }
  const clean = root.trim().replace(/^0x/i, '');
  if (!/^[0-9a-fA-F]{64}$/.test(clean)) {
    throw new TypeError(`merkleRoot must be a 64-character hex string, got: "${root}"`);
  }
  return '0x' + clean.toLowerCase();
}

/**
 * Formats a timestamp into Unix epoch seconds as a BigInt.
 * Supports ISO-8601 strings, millisecond numbers, second numbers, or BigInts.
 *
 * @param {string|number|bigint} ts - Timestamp representation.
 * @returns {bigint} Unix epoch seconds.
 * @throws {TypeError} If timestamp is invalid.
 */
export function formatTimestamp(ts) {
  if (typeof ts === 'bigint') {
    if (ts <= 0n) throw new TypeError('timestamp must be greater than zero');
    return ts;
  }
  if (typeof ts === 'number') {
    if (!Number.isFinite(ts) || ts <= 0) {
      throw new TypeError('timestamp must be a positive finite number');
    }
    // If > 1e11, treat as milliseconds
    const sec = ts > 1e11 ? Math.floor(ts / 1000) : Math.floor(ts);
    return BigInt(sec);
  }
  if (typeof ts === 'string') {
    const ms = Date.parse(ts);
    if (Number.isNaN(ms)) {
      throw new TypeError(`Invalid date string: "${ts}"`);
    }
    const sec = Math.floor(ms / 1000);
    if (sec <= 0) throw new TypeError('Parsed timestamp must be greater than zero');
    return BigInt(sec);
  }
  throw new TypeError(`Unsupported timestamp type: ${typeof ts}`);
}

/**
 * Formats and validates a sequence number.
 *
 * @param {number|bigint|string} seq - Sequence number.
 * @param {string} paramName - Parameter name for error message.
 * @returns {bigint}
 */
export function formatSequence(seq, paramName = 'sequence') {
  let val;
  if (typeof seq === 'bigint') {
    val = seq;
  } else if (typeof seq === 'number') {
    if (!Number.isInteger(seq)) {
      throw new TypeError(`${paramName} must be an integer`);
    }
    val = BigInt(seq);
  } else if (typeof seq === 'string') {
    if (!/^\d+$/.test(seq)) {
      throw new TypeError(`${paramName} must be a numeric integer string`);
    }
    val = BigInt(seq);
  } else {
    throw new TypeError(`${paramName} must be a number or BigInt`);
  }
  if (val <= 0n) {
    throw new RangeError(`${paramName} must be greater than zero`);
  }
  return val;
}
