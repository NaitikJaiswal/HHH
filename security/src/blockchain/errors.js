/**
 * @module errors
 * @description Structured blockchain error types and normalization utilities for HHH SecureLog.
 */

/**
 * Standardized blockchain error codes.
 * Conforms to docs/technical-integration-contract.md §8.4.
 *
 * @enum {string}
 */
export const BlockchainErrorCode = Object.freeze({
  NETWORK:             'NETWORK',             // RPC unreachable or JSON-RPC transport error
  CHAIN_ID:            'CHAIN_ID',            // Connected network does not match expected chain ID
  CONTRACT_NOT_FOUND:  'CONTRACT_NOT_FOUND',  // No contract bytecode found at the configured address
  INVALID_ADDRESS:     'INVALID_ADDRESS',     // Malformed contract or account address
  INSUFFICIENT_FUNDS:  'INSUFFICIENT_FUNDS',  // Signer account has insufficient ETH for gas
  INVALID_CHECKPOINT:  'INVALID_CHECKPOINT',  // Checkpoint document is malformed or invalid
  INVALID_SIGNATURE:   'INVALID_SIGNATURE',   // Checkpoint Ed25519 signature verification failed
  DUPLICATE:           'DUPLICATE',           // Checkpoint ID already anchored on-chain
  REVERT:              'REVERT',              // EVM transaction reverted by contract logic
  TIMEOUT:             'TIMEOUT',             // Transaction submitted to mempool but not mined within timeout window
  CONFIRMATION_FAILED: 'CONFIRMATION_FAILED', // Transaction receipt reported failure (status === 0)
  NOT_FOUND:           'NOT_FOUND',           // Commitment not found on-chain
  MERKLE_MISMATCH:     'MERKLE_MISMATCH',     // On-chain Merkle root does not match expected root
  UNAUTHORIZED:        'UNAUTHORIZED',        // Signer account is not an authorized submitter
});

/**
 * Custom error class for blockchain operations in HHH SecureLog.
 */
export class BlockchainError extends Error {
  /**
   * @param {string} code - Value from BlockchainErrorCode.
   * @param {string} message - Human-readable explanation.
   * @param {object} [options] - Additional error context.
   * @param {string} [options.txHash] - Transaction hash if transaction was broadcast.
   * @param {Error}  [options.cause]  - Underlying library error.
   * @param {any}    [options.details] - Extra debug metadata.
   */
  constructor(code, message, options = {}) {
    super(message);
    this.name = 'BlockchainError';
    this.code = code;
    this.txHash = options.txHash || null;
    this.cause = options.cause || null;
    this.details = options.details || null;
  }
}

/**
 * Normalizes lower-level ethers / JSON-RPC errors into structured BlockchainErrors.
 *
 * @param {any} err - Caught error.
 * @param {object} [context] - Context metadata such as txHash, checkpointId, etc.
 * @returns {BlockchainError}
 */
export function normalizeBlockchainError(err, context = {}) {
  if (err instanceof BlockchainError) {
    return err;
  }

  const msg = err?.message || String(err);
  const errCode = err?.code;

  // Duplicate checkpoint
  if (msg.includes('checkpoint already anchored') || msg.includes('DUPLICATE')) {
    return new BlockchainError(
      BlockchainErrorCode.DUPLICATE,
      'Checkpoint has already been anchored on-chain (immutability violated)',
      { cause: err, txHash: context.txHash }
    );
  }

  // Unauthorized submitter
  if (msg.includes('caller is not an authorized submitter') || msg.includes('caller is not the owner')) {
    return new BlockchainError(
      BlockchainErrorCode.UNAUTHORIZED,
      'Submitter wallet is not authorized to anchor checkpoints on this contract',
      { cause: err, txHash: context.txHash }
    );
  }

  // Revert conditions
  if (
    msg.includes('execution reverted') ||
    msg.includes('revert') ||
    errCode === 'CALL_EXCEPTION'
  ) {
    return new BlockchainError(
      BlockchainErrorCode.REVERT,
      `Transaction execution reverted on-chain: ${msg}`,
      { cause: err, txHash: context.txHash }
    );
  }

  // Insufficient funds
  if (
    msg.includes('insufficient funds') ||
    errCode === 'INSUFFICIENT_FUNDS'
  ) {
    return new BlockchainError(
      BlockchainErrorCode.INSUFFICIENT_FUNDS,
      'Signer wallet has insufficient funds to pay for transaction gas fees',
      { cause: err, txHash: context.txHash }
    );
  }

  // Network / RPC connection failures
  if (
    msg.includes('ECONNREFUSED') ||
    msg.includes('ETIMEDOUT') ||
    msg.includes('ENOTFOUND') ||
    msg.includes('network') ||
    errCode === 'NETWORK_ERROR' ||
    errCode === 'SERVER_ERROR'
  ) {
    return new BlockchainError(
      BlockchainErrorCode.NETWORK,
      `Blockchain RPC endpoint is unreachable or returned network error: ${msg}`,
      { cause: err, txHash: context.txHash }
    );
  }

  // Timeout
  if (msg.includes('timeout') || errCode === 'TIMEOUT') {
    return new BlockchainError(
      BlockchainErrorCode.TIMEOUT,
      `Transaction confirmation timed out: ${msg}`,
      { cause: err, txHash: context.txHash }
    );
  }

  // Generic fallback revert
  return new BlockchainError(
    BlockchainErrorCode.REVERT,
    `Blockchain operation failed: ${msg}`,
    { cause: err, txHash: context.txHash, details: context }
  );
}
