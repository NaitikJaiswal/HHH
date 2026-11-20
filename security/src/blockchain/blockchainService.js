/**
 * @module blockchainService
 * @description Encapsulates all EVM smart contract interactions using ethers.js v6.
 *
 * Implements the specification in docs/technical-integration-contract.md §8.
 */

import { ethers } from 'ethers';
import {
  SECURE_LOG_ANCHOR_ABI,
  formatCheckpointId,
  formatMerkleRoot,
  formatTimestamp,
  formatSequence,
} from './contractAbi.js';
import {
  BlockchainError,
  BlockchainErrorCode,
  normalizeBlockchainError,
} from './errors.js';

/**
 * @typedef {object} BlockchainConfig
 * @property {string}   [rpcUrl]          - JSON-RPC provider URL (e.g. http://127.0.0.1:8545).
 * @property {number}   [chainId]         - Expected EVM chain ID (e.g. 31337).
 * @property {string}   [contractAddress] - Address of deployed SecureLogAnchor contract.
 * @property {string}   [submitterKey]    - Hex private key for transaction signing.
 * @property {ethers.Provider} [provider] - Pre-instantiated ethers provider (for testing/DI).
 * @property {ethers.Signer}   [signer]   - Pre-instantiated ethers signer (for testing/DI).
 * @property {number}   [timeoutSeconds]  - Confirmation timeout in seconds (default 60).
 */

/**
 * @typedef {object} AnchorParams
 * @property {string} checkpointId  - UUID string or 32-byte hex ID.
 * @property {string} merkleRoot    - 64-char hex string (SHA-256 root).
 * @property {number|bigint|string} startSequence - First sequence in checkpoint window.
 * @property {number|bigint|string} endSequence   - Last sequence in checkpoint window.
 * @property {number|bigint|string} eventCount    - Number of events in window.
 * @property {string|number|bigint} timestamp     - Creation timestamp (ISO string or epoch sec).
 */

/**
 * @typedef {object} AnchorResult
 * @property {string} txHash          - 0x-prefixed transaction hash.
 * @property {number} blockNumber     - Block number where transaction was included.
 * @property {string} contractAddress - Deployed contract address (checksummed).
 * @property {number} chainId         - EVM chain ID.
 * @property {string} anchoredAt      - ISO-8601 UTC timestamp.
 * @property {string} gasUsed         - Total gas units consumed as string.
 */

/**
 * @typedef {object} CommitmentResult
 * @property {string}  merkleRoot    - Stored 32-byte Merkle root (hex).
 * @property {number}  startSequence - Initial sequence number.
 * @property {number}  endSequence   - Ending sequence number.
 * @property {number}  eventCount    - Number of log events.
 * @property {number}  timestamp     - Unix epoch seconds.
 * @property {string}  submitter     - Checksummed address of submitter.
 * @property {number}  blockNumber   - Block number when anchored.
 * @property {boolean} exists        - True if commitment exists.
 */

/**
 * @typedef {object} OnChainVerifyResult
 * @property {boolean} match        - True if on-chain commitment exists and matches expected root.
 * @property {string|null} onChainRoot - Root retrieved from contract (or null if not found).
 * @property {string|null} txHash   - Transaction hash if retrieved from event (optional).
 * @property {number|null} blockNumber - Block number of on-chain commitment.
 */

export class BlockchainService {
  /**
   * @param {BlockchainConfig} [config]
   */
  constructor(config = {}) {
    // 1. Resolve RPC URL
    this.rpcUrl =
      config.rpcUrl ||
      process.env.RPC_URL ||
      process.env.LOGN_RPC_URL ||
      'http://127.0.0.1:8545';

    // 2. Resolve Chain ID
    const rawChainId =
      config.chainId ??
      process.env.EXPECTED_CHAIN_ID ??
      process.env.LOGN_CHAIN_ID ??
      31337;
    this.expectedChainId = Number(rawChainId);

    // 3. Resolve Contract Address
    this.contractAddress =
      config.contractAddress ||
      process.env.CONTRACT_ADDRESS ||
      process.env.LOGN_CONTRACT_ADDRESS ||
      null;

    // 4. Resolve Submitter Private Key
    this.submitterKey =
      config.submitterKey ||
      process.env.BLOCKCHAIN_PRIVATE_KEY ||
      process.env.LOGN_SUBMITTER_PRIVATE_KEY ||
      null;

    // 5. Timeout
    this.timeoutSeconds =
      config.timeoutSeconds ??
      (process.env.LOGN_TX_TIMEOUT_SECONDS ? Number(process.env.LOGN_TX_TIMEOUT_SECONDS) : 60);

    // 6. Provider and Signer injection or creation
    if (config.provider) {
      this.provider = config.provider;
    } else {
      this.provider = new ethers.JsonRpcProvider(this.rpcUrl);
    }

    if (config.signer) {
      this.signer = config.signer;
    } else if (this.submitterKey) {
      this.signer = new ethers.Wallet(this.submitterKey, this.provider);
    } else {
      this.signer = null;
    }

    this.contract = null;
    this.isInitialized = false;
  }

  // ─── Lifecycle & Initialization ───────────────────────────────────────────

  /**
   * Initializes and validates blockchain connectivity, chain ID, and contract deployment.
   * Call once at startup before executing transactions.
   *
   * @returns {Promise<BlockchainService>}
   * @throws {BlockchainError}
   */
  async init() {
    try {
      // 1. Verify RPC connectivity & network chain ID
      const network = await this.provider.getNetwork();
      const actualChainId = Number(network.chainId);

      if (actualChainId !== this.expectedChainId) {
        throw new BlockchainError(
          BlockchainErrorCode.CHAIN_ID,
          `Connected chain ID (${actualChainId}) does not match expected chain ID (${this.expectedChainId})`
        );
      }

      // 2. Validate contract address format
      if (!this.contractAddress) {
        throw new BlockchainError(
          BlockchainErrorCode.INVALID_ADDRESS,
          'Contract address is not configured. Set CONTRACT_ADDRESS or pass contractAddress in config.'
        );
      }

      if (!ethers.isAddress(this.contractAddress)) {
        throw new BlockchainError(
          BlockchainErrorCode.INVALID_ADDRESS,
          `Invalid contract address format: "${this.contractAddress}"`
        );
      }

      // Checksum address
      this.contractAddress = ethers.getAddress(this.contractAddress);

      // 3. Verify that contract code exists at the given address
      const code = await this.provider.getCode(this.contractAddress);
      if (!code || code === '0x' || code === '0x0') {
        throw new BlockchainError(
          BlockchainErrorCode.CONTRACT_NOT_FOUND,
          `No smart contract bytecode deployed at address "${this.contractAddress}" on chain ${actualChainId}`
        );
      }

      // 4. Instantiate contract instance with signer (if available) or provider (read-only)
      const targetSignerOrProvider = this.signer || this.provider;
      this.contract = new ethers.Contract(
        this.contractAddress,
        SECURE_LOG_ANCHOR_ABI,
        targetSignerOrProvider
      );

      this.isInitialized = true;
      return this;
    } catch (err) {
      throw normalizeBlockchainError(err);
    }
  }

  /**
   * Check connection status and get wallet info.
   *
   * @returns {Promise<object>}
   */
  async checkConnectivity() {
    try {
      const blockNumber = await this.provider.getBlockNumber();
      const network = await this.provider.getNetwork();
      let address = null;
      let balance = null;

      if (this.signer) {
        address = await this.signer.getAddress();
        const bal = await this.provider.getBalance(address);
        balance = ethers.formatEther(bal);
      }

      return {
        connected: true,
        blockNumber,
        chainId: Number(network.chainId),
        address,
        balance,
      };
    } catch (err) {
      throw normalizeBlockchainError(err);
    }
  }

  // ─── Write Operations ─────────────────────────────────────────────────────

  /**
   * Estimate gas units required to anchor a checkpoint.
   *
   * @param {AnchorParams} params
   * @returns {Promise<string>} Gas estimate as string.
   */
  async estimateGas(params) {
    this._assertReady(true);
    const formatted = this._formatParams(params);

    try {
      const estimate = await this.contract.anchorCheckpoint.estimateGas(
        formatted.checkpointId,
        formatted.merkleRoot,
        formatted.startSequence,
        formatted.endSequence,
        formatted.eventCount,
        formatted.timestamp
      );
      return estimate.toString();
    } catch (err) {
      throw normalizeBlockchainError(err, { checkpointId: params.checkpointId });
    }
  }

  /**
   * Submits a checkpoint commitment to the SecureLogAnchor smart contract.
   *
   * Flow:
   *  1. Formats & validates parameters.
   *  2. Idempotency check: verifies checkpoint is not already anchored.
   *  3. Broadcasts transaction.
   *  4. Awaits 1 confirmation.
   *  5. Returns structured AnchorResult.
   *
   * @param {AnchorParams} params
   * @returns {Promise<AnchorResult>}
   * @throws {BlockchainError}
   */
  async anchorCheckpoint(params) {
    this._assertReady(true);
    const formatted = this._formatParams(params);

    // Idempotency: duplicate checkpoint check before broadcasting
    const exists = await this.commitmentExists(formatted.checkpointId);
    if (exists) {
      throw new BlockchainError(
        BlockchainErrorCode.DUPLICATE,
        `Checkpoint "${params.checkpointId}" is already anchored on-chain`
      );
    }

    let tx = null;
    try {
      // Broadcast transaction
      tx = await this.contract.anchorCheckpoint(
        formatted.checkpointId,
        formatted.merkleRoot,
        formatted.startSequence,
        formatted.endSequence,
        formatted.eventCount,
        formatted.timestamp
      );

      // Wait for confirmation with configured timeout
      const receipt = await tx.wait(1);

      if (!receipt || receipt.status === 0) {
        throw new BlockchainError(
          BlockchainErrorCode.CONFIRMATION_FAILED,
          `Transaction confirmed with reverted status (0)`,
          { txHash: tx.hash }
        );
      }

      return {
        txHash: receipt.hash,
        blockNumber: Number(receipt.blockNumber),
        contractAddress: this.contractAddress,
        chainId: this.expectedChainId,
        anchoredAt: new Date().toISOString(),
        gasUsed: receipt.gasUsed.toString(),
      };
    } catch (err) {
      throw normalizeBlockchainError(err, {
        txHash: tx?.hash,
        checkpointId: params.checkpointId,
      });
    }
  }

  // ─── Read Operations ──────────────────────────────────────────────────────

  /**
   * Retrieves a stored commitment from the smart contract.
   *
   * @param {string} checkpointId
   * @returns {Promise<CommitmentResult>}
   * @throws {BlockchainError} with NOT_FOUND if checkpoint does not exist.
   */
  async getCommitment(checkpointId) {
    this._assertReady(false);
    const idBytes32 = formatCheckpointId(checkpointId);

    try {
      const c = await this.contract.getCommitment(idBytes32);

      if (!c.exists) {
        throw new BlockchainError(
          BlockchainErrorCode.NOT_FOUND,
          `Commitment for checkpointId "${checkpointId}" was not found on-chain`
        );
      }

      return {
        merkleRoot: c.merkleRoot,
        startSequence: Number(c.startSequence),
        endSequence: Number(c.endSequence),
        eventCount: Number(c.eventCount),
        timestamp: Number(c.timestamp),
        submitter: ethers.getAddress(c.submitter),
        blockNumber: Number(c.blockNumber),
        exists: Boolean(c.exists),
      };
    } catch (err) {
      const norm = normalizeBlockchainError(err, { checkpointId });
      if (norm.message.includes('commitment does not exist')) {
        throw new BlockchainError(
          BlockchainErrorCode.NOT_FOUND,
          `Commitment for checkpointId "${checkpointId}" was not found on-chain`,
          { cause: err }
        );
      }
      throw norm;
    }
  }

  /**
   * Checks whether a checkpoint has been anchored on-chain without throwing.
   *
   * @param {string} checkpointId
   * @returns {Promise<boolean>}
   */
  async commitmentExists(checkpointId) {
    this._assertReady(false);
    const idBytes32 = formatCheckpointId(checkpointId);

    try {
      return await this.contract.commitmentExists(idBytes32);
    } catch (err) {
      throw normalizeBlockchainError(err, { checkpointId });
    }
  }

  /**
   * Verifies whether an expected Merkle root matches the on-chain stored commitment.
   * Does NOT throw on mismatch; returns match: false.
   *
   * @param {string} checkpointId
   * @param {string} expectedMerkleRoot
   * @returns {Promise<OnChainVerifyResult>}
   */
  async verifyOnChain(checkpointId, expectedMerkleRoot) {
    this._assertReady(false);
    const idBytes32 = formatCheckpointId(checkpointId);
    const rootBytes32 = formatMerkleRoot(expectedMerkleRoot);

    try {
      const isMatch = await this.contract.verifyCommitment(idBytes32, rootBytes32);

      let onChainRoot = null;
      let blockNumber = null;

      // If commitment exists, retrieve its recorded root and block
      if (await this.contract.commitmentExists(idBytes32)) {
        try {
          const c = await this.contract.getCommitment(idBytes32);
          onChainRoot = c.merkleRoot;
          blockNumber = Number(c.blockNumber);
        } catch {
          // Ignore if getCommitment fails
        }
      }

      return {
        match: Boolean(isMatch),
        onChainRoot,
        txHash: null,
        blockNumber,
      };
    } catch (err) {
      throw normalizeBlockchainError(err, { checkpointId });
    }
  }

  /**
   * Returns total count of checkpoints anchored on the contract.
   *
   * @returns {Promise<number>}
   */
  async getTotalCheckpoints() {
    this._assertReady(false);
    try {
      const count = await this.contract.getTotalCheckpoints();
      return Number(count);
    } catch (err) {
      throw normalizeBlockchainError(err);
    }
  }

  /**
   * Enumerate anchored checkpoint IDs with pagination.
   *
   * @param {number} [offset=0]
   * @param {number} [limit=50]
   * @returns {Promise<string[]>} Array of bytes32 strings.
   */
  async listCheckpointIds(offset = 0, limit = 50) {
    this._assertReady(false);
    try {
      const ids = await this.contract.getCheckpointIds(BigInt(offset), BigInt(limit));
      return Array.from(ids);
    } catch (err) {
      throw normalizeBlockchainError(err);
    }
  }

  // ─── Internal Helpers ─────────────────────────────────────────────────────

  /**
   * Ensures service has been initialized and contract is available.
   *
   * @param {boolean} requiresSigner - True if operation requires write permissions.
   * @private
   */
  _assertReady(requiresSigner = false) {
    if (!this.contract) {
      throw new BlockchainError(
        BlockchainErrorCode.CONTRACT_NOT_FOUND,
        'BlockchainService is not initialized. Call await blockchainService.init() first.'
      );
    }
    if (requiresSigner && !this.signer) {
      throw new BlockchainError(
        BlockchainErrorCode.UNAUTHORIZED,
        'BlockchainService has no configured signer wallet. Submitter private key is required for write operations.'
      );
    }
  }

  /**
   * Formats and validates input parameters for anchorCheckpoint.
   *
   * @param {AnchorParams} params
   * @returns {object} Formatted BigInt/bytes parameters.
   * @private
   */
  _formatParams(params) {
    if (!params || typeof params !== 'object') {
      throw new BlockchainError(
        BlockchainErrorCode.INVALID_CHECKPOINT,
        'anchorCheckpoint parameters must be an object'
      );
    }

    try {
      const checkpointId = formatCheckpointId(params.checkpointId);
      const merkleRoot = formatMerkleRoot(params.merkleRoot);
      const startSequence = formatSequence(params.startSequence, 'startSequence');
      const endSequence = formatSequence(params.endSequence, 'endSequence');

      if (endSequence < startSequence) {
        throw new BlockchainError(
          BlockchainErrorCode.INVALID_CHECKPOINT,
          `endSequence (${endSequence}) cannot be less than startSequence (${startSequence})`
        );
      }

      const expectedCount = endSequence - startSequence + 1n;
      const eventCountVal = formatSequence(params.eventCount, 'eventCount');

      if (eventCountVal !== expectedCount) {
        throw new BlockchainError(
          BlockchainErrorCode.INVALID_CHECKPOINT,
          `eventCount (${eventCountVal}) does not match sequence range count (${expectedCount})`
        );
      }

      const eventCount = Number(eventCountVal);
      const timestamp = formatTimestamp(params.timestamp);

      return {
        checkpointId,
        merkleRoot,
        startSequence,
        endSequence,
        eventCount,
        timestamp,
      };
    } catch (err) {
      if (err instanceof BlockchainError) throw err;
      throw new BlockchainError(
        BlockchainErrorCode.INVALID_CHECKPOINT,
        `Invalid checkpoint parameter: ${err.message}`,
        { cause: err }
      );
    }
  }
}

export default BlockchainService;
