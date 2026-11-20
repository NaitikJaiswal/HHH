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

// Phase 2: Signed Checkpoints
export {
  createCheckpoint,
  verifyCheckpoint,
  verifyCheckpointProof,
  buildSigningPayload,
  CHECKPOINT_SCHEMA_VERSION,
  SIGNATURE_ALGORITHM,
  SIGNATURE_INPUT_LABEL,
  VerificationStatus,
} from './checkpoints/checkpointService.js';

// Phase 2: Verification Engine
export {
  verifySignedCheckpoint,
  verifyInclusionProof,
  verifyEventsAgainstCheckpoint,
} from './verification/verifier.js';
