/**
 * @module security
 * @description Main entry point for the HHH SecureLog Security + Blockchain module.
 */

// Phase 1: Canonical JSON, SHA-256 Hashing, and Hash Chain
export { canonicalJson, sortKeysDeep } from './crypto/canonicalJson.js';
export { hashLogEvent, sha256hex, GENESIS_HASH, LOGN_HASH_V1_FIELDS } from './crypto/hashing.js';
export { buildChain, verifyHashChain } from './crypto/hashChain.js';

// Phase 2: Merkle Tree and Proofs
export {
  buildMerkleTree,
  getMerkleRoot,
  generateMerkleProof,
  verifyMerkleProof,
  leafHash,
  internalHash,
  EMPTY_TREE_ROOT,
} from './merkle/merkleTree.js';

// Phase 2: Ed25519 Key Management
export {
  KeyManager,
  generateUuidV4,
  publicKeyFromHex,
  privateKeyFromBytes,
} from './keys/keyManager.js';

// Phase 2 & 3: Signed Checkpoints and Anchoring
export {
  createCheckpoint,
  verifyCheckpoint,
  verifyCheckpointProof,
  buildSigningPayload,
  anchorSignedCheckpoint,
  CHECKPOINT_SCHEMA_VERSION,
  SIGNATURE_ALGORITHM,
  SIGNATURE_INPUT_LABEL,
  VerificationStatus,
} from './checkpoints/checkpointService.js';

// Phase 2 & 3: Verification Engine
export {
  verifySignedCheckpoint,
  verifyInclusionProof,
  verifyEventsAgainstCheckpoint,
  verifyCheckpointWithBlockchain,
} from './verification/verifier.js';

// Phase 3B: Blockchain Service & Contract Integration
export { BlockchainService } from './blockchain/blockchainService.js';
export {
  BlockchainError,
  BlockchainErrorCode,
  normalizeBlockchainError,
} from './blockchain/errors.js';
export {
  SECURE_LOG_ANCHOR_ABI,
  formatCheckpointId,
  formatMerkleRoot,
  formatTimestamp,
  formatSequence,
} from './blockchain/contractAbi.js';

// Phase 4A: Backend Integration Adapter
export { BackendAdapter, createBackendAdapter } from './adapter/backendAdapter.js';
