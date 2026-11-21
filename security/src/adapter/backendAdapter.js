/**
 * @module backendAdapter
 * @description Integration adapter for the Backend team to interact with the Security + Blockchain module.
 *
 * Exposes documented, high-level functions for:
 *   - Submitting signed checkpoints for on-chain anchoring
 *   - Querying checkpoint anchoring status
 *   - Fetching transaction metadata
 *   - Performing dual off-chain + on-chain verification
 *   - Safely retrying failed or timed-out anchoring operations without duplicate submissions
 *
 * Implements docs/technical-integration-contract.md §8, §9, §12.
 */

import { anchorSignedCheckpoint, verifyCheckpoint } from '../checkpoints/checkpointService.js';
import { verifyCheckpointWithBlockchain } from '../verification/verifier.js';
import { BlockchainError, BlockchainErrorCode, normalizeBlockchainError } from '../blockchain/errors.js';
import { formatCheckpointId } from '../blockchain/contractAbi.js';

/**
 * @typedef {object} BackendAnchorResult
 * @property {boolean} success          - True if anchored successfully.
 * @property {string}  checkpointId     - Original checkpoint UUID.
 * @property {string}  txHash           - EVM transaction hash.
 * @property {number}  blockNumber      - EVM block number.
 * @property {number}  chainId          - Network chain ID.
 * @property {string}  anchoredAt       - ISO-8601 UTC timestamp.
 * @property {string}  gasUsed          - Gas used units.
 * @property {object}  checkpoint       - Updated checkpoint document containing blockchain metadata.
 * @property {boolean} [alreadyAnchored] - True if resolved via idempotency check.
 */

export class BackendAdapter {
  /**
   * @param {object} options
   * @param {import('../blockchain/blockchainService.js').BlockchainService} options.blockchainService
   * @param {import('../keys/keyManager.js').KeyManager} [options.keyManager]
   */
  constructor({ blockchainService, keyManager = null }) {
    if (!blockchainService) {
      throw new TypeError('BackendAdapter requires a blockchainService instance');
    }
    this.blockchainService = blockchainService;
    this.keyManager = keyManager;
  }

  /**
   * Submit a signed checkpoint for on-chain anchoring.
   *
   * Validates checkpoint structure and signature, extracts on-chain commitment,
   * submits transaction, awaits confirmation, attaches blockchain metadata,
   * and verifies the anchored commitment against the input checkpoint.
   *
   * @param {object} checkpoint - Complete signed checkpoint document.
   * @param {object} [options]
   * @param {import('../keys/keyManager.js').KeyManager} [options.keyManager]
   * @returns {Promise<BackendAnchorResult>}
   * @throws {BlockchainError} Structured error on failure.
   */
  async anchorCheckpointForBackend(checkpoint, options = {}) {
    const km = options.keyManager || options.mpk || this.keyManager;

    try {
      const { checkpoint: updatedCheckpoint, anchorResult } =
        await anchorSignedCheckpoint(checkpoint, this.blockchainService, km, options);

      return {
        success: true,
        checkpointId: checkpoint.checkpoint_id,
        txHash: anchorResult.txHash,
        blockNumber: anchorResult.blockNumber,
        chainId: anchorResult.chainId,
        anchoredAt: anchorResult.anchoredAt,
        gasUsed: anchorResult.gasUsed,
        checkpoint: updatedCheckpoint,
      };
    } catch (err) {
      throw normalizeBlockchainError(err, { checkpointId: checkpoint?.checkpoint_id });
    }
  }

  /**
   * Retrieve the anchoring status of a checkpoint by ID.
   *
   * @param {string} checkpointId - UUID string or bytes32 hex ID.
   * @returns {Promise<object>} Status object { anchored, checkpointId, onChainRoot, blockNumber, submitter, timestamp }
   */
  async getAnchoringStatus(checkpointId) {
    try {
      const exists = await this.blockchainService.commitmentExists(checkpointId);
      if (!exists) {
        return {
          anchored: false,
          checkpointId,
          onChainRoot: null,
          blockNumber: null,
          submitter: null,
          timestamp: null,
        };
      }

      const commitment = await this.blockchainService.getCommitment(checkpointId);
      return {
        anchored: true,
        checkpointId,
        onChainRoot: commitment.merkleRoot,
        blockNumber: commitment.blockNumber,
        submitter: commitment.submitter,
        timestamp: commitment.timestamp,
        startSequence: commitment.startSequence,
        endSequence: commitment.endSequence,
        eventCount: commitment.eventCount,
      };
    } catch (err) {
      throw normalizeBlockchainError(err, { checkpointId });
    }
  }

  /**
   * Retrieve on-chain transaction and commitment metadata for a checkpoint.
   *
   * @param {string} checkpointId
   * @returns {Promise<object>}
   */
  async getTransactionMetadata(checkpointId) {
    try {
      const commitment = await this.blockchainService.getCommitment(checkpointId);
      return {
        checkpointId,
        contractAddress: this.blockchainService.contractAddress,
        chainId: this.blockchainService.expectedChainId,
        merkleRoot: commitment.merkleRoot,
        startSequence: commitment.startSequence,
        endSequence: commitment.endSequence,
        eventCount: commitment.eventCount,
        submitter: commitment.submitter,
        blockNumber: commitment.blockNumber,
        timestamp: commitment.timestamp,
      };
    } catch (err) {
      throw normalizeBlockchainError(err, { checkpointId });
    }
  }

  /**
   * Verify a checkpoint against both its off-chain cryptographic signature
   * and its on-chain smart contract commitment.
   *
   * @param {object} checkpoint - Checkpoint document.
   * @param {object} [options]
   * @returns {Promise<object>} Full verification report conforming to §9.5.
   */
  async verifyCheckpointOnChain(checkpoint, options = {}) {
    const km = options.keyManager || options.mpk || this.keyManager;
    return verifyCheckpointWithBlockchain(checkpoint, this.blockchainService, km, options);
  }

  /**
   * Safely retry an anchoring operation.
   *
   * Performs an idempotency check:
   * 1. If checkpoint is already anchored on-chain, retrieves existing commitment,
   *    populates `checkpoint.blockchain` metadata, and returns success without submitting a new transaction.
   * 2. If not yet anchored, proceeds with anchoring normally.
   *
   * @param {object} checkpoint - Complete signed checkpoint.
   * @param {object} [options]
   * @returns {Promise<BackendAnchorResult>}
   */
  async safeRetryAnchor(checkpoint, options = {}) {
    if (!checkpoint || typeof checkpoint !== 'object' || !checkpoint.checkpoint_id) {
      throw new BlockchainError(
        BlockchainErrorCode.INVALID_CHECKPOINT,
        'checkpoint must have a valid checkpoint_id'
      );
    }

    try {
      // Check if commitment already exists on-chain
      const exists = await this.blockchainService.commitmentExists(checkpoint.checkpoint_id);

      if (exists) {
        const commitment = await this.blockchainService.getCommitment(checkpoint.checkpoint_id);

        checkpoint.blockchain = {
          contractAddress: this.blockchainService.contractAddress,
          txHash: checkpoint.blockchain?.txHash || null,
          blockNumber: commitment.blockNumber,
          chainId: this.blockchainService.expectedChainId,
          anchoredAt: checkpoint.blockchain?.anchoredAt || new Date(commitment.timestamp * 1000).toISOString(),
          gasUsed: checkpoint.blockchain?.gasUsed || '0',
        };

        return {
          success: true,
          alreadyAnchored: true,
          checkpointId: checkpoint.checkpoint_id,
          txHash: checkpoint.blockchain.txHash,
          blockNumber: commitment.blockNumber,
          chainId: this.blockchainService.expectedChainId,
          anchoredAt: checkpoint.blockchain.anchoredAt,
          gasUsed: checkpoint.blockchain.gasUsed,
          checkpoint,
        };
      }

      // Not anchored yet: proceed with fresh anchor
      return await this.anchorCheckpointForBackend(checkpoint, options);
    } catch (err) {
      throw normalizeBlockchainError(err, { checkpointId: checkpoint.checkpoint_id });
    }
  }
}

/**
 * Factory to create and configure a BackendAdapter instance.
 *
 * @param {object} config
 * @param {import('../blockchain/blockchainService.js').BlockchainService} config.blockchainService
 * @param {import('../keys/keyManager.js').KeyManager} [config.keyManager]
 * @returns {BackendAdapter}
 */
export function createBackendAdapter(config) {
  return new BackendAdapter(config);
}

export default {
  BackendAdapter,
  createBackendAdapter,
};
