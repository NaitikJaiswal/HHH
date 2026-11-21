/**
 * @module fssSigner
 * @description Merkle Key Tree Forward-Secure Signatures (MKT-FSS)
 * with HMAC-SHA256 Evolution over Ed25519.
 *
 * Implements the authoritative forward-secure digital signature scheme defined in:
 *   docs/fss-architecture.md
 *
 * Key guarantees:
 *   - Master Public Key (MPK) is a compact 32-byte Merkle root committing to T epochs.
 *   - Signatures are self-contained: (epoch, publicKey, signature, authPath, mpk).
 *   - Verifiers need ONLY the fixed MPK and public signature; no secrets needed.
 *   - One-way evolution: SK_t -> SK_{t+1} via HMAC-SHA256 ratchet.
 *   - A compromise of SK_t at epoch t CANNOT forge signatures for epochs 0 ... t-1.
 */

import {
  createHmac,
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
  randomBytes,
} from 'node:crypto';

import { readFileSync, existsSync } from 'node:fs';
import { canonicalJson } from './canonicalJson.js';
import { zeroizeBuffer, atomicWriteSecretFile, secureEraseFile } from './secretScrubber.js';

// ── Domain Tags & Constants ──────────────────────────────────────────────────

export const FSS_VERSION = 'HHH-MKT-FSS-v1';
export const FSS_STATE_VERSION = 'HHH-MKT-FSS-STATE-v1';

const DOMAIN_LEAF = Buffer.from([0x00]);
const DOMAIN_NODE = Buffer.from([0x01]);
const DERIVATION_LABEL_SIGN = 'HHH-FSS-SIGNING-KEY';
const DERIVATION_LABEL_EVOLVE = 'HHH-FSS-EVOLVE-EPOCH';
const ENVELOPE_PREFIX = Buffer.from('HHH-FSS-EPOCH-SIG', 'utf8');

// Minimal RFC 8410 DER headers for Ed25519
const PKCS8_HEADER = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI_HEADER = Buffer.from('302a300506032b6570032100', 'hex');

// ── Low-Level Cryptographic Helpers ──────────────────────────────────────────

/**
 * Encode an unsigned 32-bit integer into a 4-byte big-endian Buffer.
 *
 * @param {number} num
 * @returns {Buffer}
 */
export function uint32BE(num) {
  const buf = Buffer.alloc(4);
  buf.writeUInt32BE(num >>> 0, 0);
  return buf;
}

/**
 * Reconstruct an Ed25519 private KeyObject from a raw 32-byte seed.
 *
 * @param {Buffer} seedBytes
 * @returns {import('node:crypto').KeyObject}
 */
export function privateKeyFromSeed(seedBytes) {
  if (!Buffer.isBuffer(seedBytes) || seedBytes.length !== 32) {
    throw new TypeError('privateKeyFromSeed: expected a 32-byte Buffer');
  }
  const pkcs8 = Buffer.concat([PKCS8_HEADER, seedBytes]);
  return createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
}

/**
 * Reconstruct an Ed25519 public KeyObject from raw 32 bytes or 64-char hex.
 *
 * @param {Buffer|string} publicKey
 * @returns {import('node:crypto').KeyObject}
 */
export function publicKeyFromBytes(publicKey) {
  const bytes = typeof publicKey === 'string'
    ? Buffer.from(publicKey, 'hex')
    : publicKey;

  if (!Buffer.isBuffer(bytes) || bytes.length !== 32) {
    throw new TypeError('publicKeyFromBytes: expected a 32-byte public key');
  }
  const spki = Buffer.concat([SPKI_HEADER, bytes]);
  return createPublicKey({ key: spki, format: 'der', type: 'spki' });
}

/**
 * Extract raw 32-byte public key from an Ed25519 KeyObject.
 *
 * @param {import('node:crypto').KeyObject} privKey
 * @returns {Buffer}
 */
export function deriveRawPublicKey(privKey) {
  const pub = createPublicKey(privKey);
  return pub.export({ type: 'spki', format: 'der' }).slice(-32);
}

/**
 * Derive epoch signing seed sk_t from epoch master seed K_t.
 *
 * @param {Buffer} K_t - 32-byte epoch seed.
 * @returns {Buffer} 32-byte private signing seed.
 */
export function deriveEpochSigningSeed(K_t) {
  return createHmac('sha256', K_t)
    .update(DERIVATION_LABEL_SIGN, 'utf8')
    .digest();
}

/**
 * Evolve epoch master seed K_t -> K_{t+1}.
 *
 * @param {Buffer} K_t - 32-byte current epoch seed.
 * @returns {Buffer} 32-byte next epoch seed.
 */
export function evolveSeed(K_t) {
  return createHmac('sha256', K_t)
    .update(DERIVATION_LABEL_EVOLVE, 'utf8')
    .digest();
}

/**
 * Compute the domain-separated Merkle leaf hash for epoch t:
 *   SHA-256( 0x00 || uint32BE(t) || rawPublicKey )
 *
 * @param {number} epoch - 0-based integer epoch.
 * @param {Buffer} rawPublicKey - 32-byte raw public key.
 * @returns {string} Lowercase hex-64 leaf hash.
 */
export function computeLeafHash(epoch, rawPublicKey) {
  return createHash('sha256')
    .update(DOMAIN_LEAF)
    .update(uint32BE(epoch))
    .update(rawPublicKey)
    .digest('hex');
}

/**
 * Compute the domain-separated Merkle internal node hash:
 *   SHA-256( 0x01 || leftBytes || rightBytes )
 *
 * @param {string} leftHex - 64-char hex left child.
 * @param {string} rightHex - 64-char hex right child.
 * @returns {string} Lowercase hex-64 node hash.
 */
export function computeInternalNodeHash(leftHex, rightHex) {
  return createHash('sha256')
    .update(DOMAIN_NODE)
    .update(Buffer.from(leftHex, 'hex'))
    .update(Buffer.from(rightHex, 'hex'))
    .digest('hex');
}

// ── Merkle Key Tree Construction ─────────────────────────────────────────────

/**
 * Build Merkle Key Tree layers from an array of leaf hashes.
 *
 * @param {string[]} leafHashes - Array of lowercase hex-64 leaf hashes.
 * @returns {{ root: string, layers: string[][] }}
 */
export function buildKeyTree(leafHashes) {
  if (!Array.isArray(leafHashes) || leafHashes.length === 0) {
    throw new TypeError('buildKeyTree: leaves must be a non-empty array');
  }

  const layers = [leafHashes.slice()];
  let currentLayer = layers[0];

  while (currentLayer.length > 1) {
    const nextLayer = [];
    for (let i = 0; i < currentLayer.length; i += 2) {
      const left = currentLayer[i];
      const right = (i + 1 < currentLayer.length) ? currentLayer[i + 1] : left;
      nextLayer.push(computeInternalNodeHash(left, right));
    }
    layers.push(nextLayer);
    currentLayer = nextLayer;
  }

  return { root: currentLayer[0], layers };
}

/**
 * Generate Merkle authentication path for the given epoch index.
 *
 * @param {string[][]} layers - Tree layers from buildKeyTree().
 * @param {number} epoch - Target epoch index.
 * @returns {Array<{ sibling_hash: string, position: 'left'|'right' }>}
 */
export function generateAuthPath(layers, epoch) {
  if (!layers || layers.length === 0) {
    throw new Error('generateAuthPath: invalid tree layers');
  }
  const leafCount = layers[0].length;
  if (!Number.isInteger(epoch) || epoch < 0 || epoch >= leafCount) {
    throw new RangeError(`generateAuthPath: epoch ${epoch} out of bounds (0..${leafCount - 1})`);
  }

  const path = [];
  let currentIndex = epoch;

  for (let l = 0; l < layers.length - 1; l++) {
    const layer = layers[l];
    const isRight = (currentIndex % 2 === 1);

    if (isRight) {
      path.push({
        sibling_hash: layer[currentIndex - 1],
        position: 'left',
      });
    } else {
      const siblingIndex = currentIndex + 1;
      const sibling = (siblingIndex < layer.length) ? layer[siblingIndex] : layer[currentIndex];
      path.push({
        sibling_hash: sibling,
        position: 'right',
      });
    }

    currentIndex = Math.floor(currentIndex / 2);
  }

  return path;
}

// ── Master Key Generation & Initialization ────────────────────────────────────

/**
 * Generate a complete Forward-Secure Master Key Tree and initial active state.
 *
 * @param {object} [options={}]
 * @param {number} [options.maxEpochs=1024] - Maximum lifetime epochs T (must be >= 2).
 * @param {Buffer} [options.initialSeed=null] - Optional 32-byte master seed K_0 (randomized if omitted).
 * @returns {{ state: object, publicTree: object, mpk: string }}
 */
export function generateFssMasterState(options = {}) {
  const maxEpochs = Number.isInteger(options.maxEpochs) && options.maxEpochs >= 2
    ? options.maxEpochs
    : 1024;

  const K_0 = (options.initialSeed && Buffer.isBuffer(options.initialSeed) && options.initialSeed.length === 32)
    ? Buffer.from(options.initialSeed)
    : randomBytes(32);

  const leaves = new Array(maxEpochs);
  const publicKeys = new Array(maxEpochs);

  let currentSeed = Buffer.from(K_0);

  for (let j = 0; j < maxEpochs; j++) {
    const sk_j = deriveEpochSigningSeed(currentSeed);
    let privKey = null;
    try {
      privKey = privateKeyFromSeed(sk_j);
      const pk_j = deriveRawPublicKey(privKey);
      publicKeys[j] = pk_j.toString('hex');
      leaves[j] = computeLeafHash(j, pk_j);
    } finally {
      zeroizeBuffer(sk_j);
    }

    const nextSeed = evolveSeed(currentSeed);
    if (j > 0) {
      zeroizeBuffer(currentSeed);
    }
    currentSeed = nextSeed;
  }
  // Zeroize terminal seed
  zeroizeBuffer(currentSeed);

  // Build Merkle Key Tree
  const tree = buildKeyTree(leaves);
  const mpk = tree.root;

  // Precompute auth paths for public tree structure
  const authPaths = new Array(maxEpochs);
  for (let j = 0; j < maxEpochs; j++) {
    authPaths[j] = generateAuthPath(tree.layers, j);
  }

  const publicTree = {
    version: FSS_VERSION,
    mpk,
    maxEpochs,
    publicKeys,
    authPaths,
  };

  const state = {
    version: FSS_STATE_VERSION,
    epoch: 0,
    seedHex: K_0.toString('hex'),
    authPath: authPaths[0],
    mpk,
    maxEpochs,
    createdAt: new Date().toISOString(),
  };

  return { state, publicTree, mpk };
}

// ── Signing ───────────────────────────────────────────────────────────────────

/**
 * Construct the canonical signing envelope buffer for epoch t.
 *
 * @param {number} epoch - Active epoch index.
 * @param {Buffer} rawPublicKey - 32-byte raw public key.
 * @param {unknown} payload - Payload object, string, or Buffer.
 * @returns {Buffer}
 */
export function buildSigningEnvelope(epoch, rawPublicKey, payload) {
  let payloadBytes;
  if (Buffer.isBuffer(payload)) {
    payloadBytes = payload;
  } else if (typeof payload === 'string') {
    payloadBytes = Buffer.from(payload, 'utf8');
  } else {
    payloadBytes = Buffer.from(canonicalJson(payload), 'utf8');
  }

  return Buffer.concat([
    ENVELOPE_PREFIX,
    uint32BE(epoch),
    rawPublicKey,
    payloadBytes,
  ]);
}

/**
 * Sign a payload using the active forward-secure state.
 *
 * @param {object} state - Active private state (from generateFssMasterState or evolveFssState).
 * @param {unknown} payload - Payload to sign (object, string, or Buffer).
 * @param {Array} [authPathOverride=null] - Optional override auth path.
 * @returns {object} Full forward-secure signature bundle.
 */
export function signFssEpoch(state, payload, authPathOverride = null) {
  if (!state || typeof state !== 'object') {
    throw new TypeError('signFssEpoch: state must be an object');
  }
  if (!Number.isInteger(state.epoch) || state.epoch < 0 || state.epoch >= state.maxEpochs) {
    throw new RangeError(`signFssEpoch: state epoch ${state.epoch} is out of bounds (max ${state.maxEpochs})`);
  }
  if (typeof state.seedHex !== 'string' || state.seedHex.length !== 64) {
    throw new Error('signFssEpoch: missing or invalid active seed in state');
  }

  const K_t = Buffer.from(state.seedHex, 'hex');
  const sk_t = deriveEpochSigningSeed(K_t);
  zeroizeBuffer(K_t);

  let privKey = null;
  let rawPub = null;
  let signature = null;

  try {
    privKey = privateKeyFromSeed(sk_t);
    rawPub = deriveRawPublicKey(privKey);

    const envelope = buildSigningEnvelope(state.epoch, rawPub, payload);
    signature = cryptoSign(null, envelope, privKey);
  } finally {
    zeroizeBuffer(sk_t);
  }

  const authPath = authPathOverride || state.authPath;
  if (!Array.isArray(authPath)) {
    throw new Error('signFssEpoch: missing Merkle authentication path in state');
  }

  return {
    version: FSS_VERSION,
    epoch: state.epoch,
    publicKey: rawPub.toString('hex'),
    signature: signature.toString('hex'),
    authPath,
    mpk: state.mpk,
    signedAt: new Date().toISOString(),
  };
}

// ── Verification ──────────────────────────────────────────────────────────────

/**
 * Verify a forward-secure signature bundle against the Master Public Key (MPK).
 *
 * Requires ONLY the MPK, the signed payload, and the signature bundle.
 *
 * @param {string} mpk - 64-char hex Master Public Key.
 * @param {unknown} payload - Original payload.
 * @param {object} signatureBundle - Signature bundle returned by signFssEpoch.
 * @returns {{ valid: boolean, epoch?: number, publicKey?: string, mpk?: string, error?: string, reason?: string }}
 */
export function verifyFssSignature(mpk, payload, signatureBundle) {
  if (typeof mpk !== 'string' || !/^[0-9a-fA-F]{64}$/.test(mpk)) {
    return { valid: false, error: 'INVALID_MPK', reason: 'MPK must be a 64-char hex string' };
  }
  if (!signatureBundle || typeof signatureBundle !== 'object') {
    return { valid: false, error: 'INVALID_BUNDLE', reason: 'Signature bundle must be an object' };
  }
  if (signatureBundle.version !== FSS_VERSION) {
    return { valid: false, error: 'UNSUPPORTED_VERSION', reason: `Expected version ${FSS_VERSION}` };
  }
  if (!Number.isInteger(signatureBundle.epoch) || signatureBundle.epoch < 0) {
    return { valid: false, error: 'INVALID_EPOCH', reason: 'Epoch must be a non-negative integer' };
  }
  if (typeof signatureBundle.publicKey !== 'string' || !/^[0-9a-fA-F]{64}$/.test(signatureBundle.publicKey)) {
    return { valid: false, error: 'INVALID_PUBLIC_KEY', reason: 'Public key must be a 64-char hex string' };
  }
  if (typeof signatureBundle.signature !== 'string' || !/^[0-9a-fA-F]{128}$/.test(signatureBundle.signature)) {
    return { valid: false, error: 'INVALID_SIGNATURE_FORMAT', reason: 'Signature must be a 128-char hex string' };
  }
  if (!Array.isArray(signatureBundle.authPath)) {
    return { valid: false, error: 'INVALID_AUTH_PATH', reason: 'Auth path must be an array' };
  }
  if (signatureBundle.mpk && signatureBundle.mpk.toLowerCase() !== mpk.toLowerCase()) {
    return { valid: false, error: 'MPK_MISMATCH', reason: 'Bundle MPK does not match expected MPK' };
  }

  const rawPub = Buffer.from(signatureBundle.publicKey, 'hex');
  const sigBytes = Buffer.from(signatureBundle.signature, 'hex');

  // 1. Verify Ed25519 signature on canonical envelope
  try {
    const pubKeyObj = publicKeyFromBytes(rawPub);
    const envelope = buildSigningEnvelope(signatureBundle.epoch, rawPub, payload);
    const sigValid = cryptoVerify(null, envelope, pubKeyObj, sigBytes);
    if (!sigValid) {
      return { valid: false, error: 'INVALID_SIGNATURE', reason: 'Ed25519 signature verification failed' };
    }
  } catch (err) {
    return { valid: false, error: 'SIGNATURE_VERIFICATION_ERROR', reason: err.message };
  }

  // 2. Compute leaf hash for this epoch
  const computedLeaf = computeLeafHash(signatureBundle.epoch, rawPub);

  // 3. Evaluate Merkle authentication path to reconstruct candidate root
  let currentHash = computedLeaf;
  for (let i = 0; i < signatureBundle.authPath.length; i++) {
    const step = signatureBundle.authPath[i];
    if (!step || typeof step !== 'object' || typeof step.sibling_hash !== 'string' || !/^[0-9a-fA-F]{64}$/.test(step.sibling_hash)) {
      return { valid: false, error: 'MALFORMED_AUTH_PATH_STEP', reason: `Invalid step at index ${i}` };
    }

    if (step.position === 'left') {
      currentHash = computeInternalNodeHash(step.sibling_hash, currentHash);
    } else if (step.position === 'right') {
      currentHash = computeInternalNodeHash(currentHash, step.sibling_hash);
    } else {
      return { valid: false, error: 'INVALID_AUTH_PATH_POSITION', reason: `Position must be left or right at step ${i}` };
    }
  }

  // 4. Verify candidate root matches expected MPK
  if (currentHash.toLowerCase() !== mpk.toLowerCase()) {
    return {
      valid: false,
      error: 'MERKLE_PATH_MISMATCH',
      reason: `Computed root ${currentHash} does not match expected MPK ${mpk}`,
    };
  }

  return {
    valid: true,
    epoch: signatureBundle.epoch,
    publicKey: signatureBundle.publicKey,
    mpk,
  };
}

// ── Key Evolution ─────────────────────────────────────────────────────────────

/**
 * Evolve the forward-secure secret state to the next epoch (t -> t + 1).
 *
 * Irreversibly overwrites the old seed K_t in memory.
 *
 * @param {object} state - Active private state.
 * @param {Array} [nextAuthPath=null] - Next epoch's Merkle authentication path (optional if publicTree is referenced).
 * @returns {object} New private state for epoch t + 1.
 */
export function evolveFssState(state, nextAuthPath = null) {
  if (!state || typeof state !== 'object') {
    throw new TypeError('evolveFssState: state must be an object');
  }
  const nextEpoch = state.epoch + 1;
  if (nextEpoch >= state.maxEpochs) {
    throw new Error(`evolveFssState: cannot evolve beyond maximum epochs (${state.maxEpochs})`);
  }

  const K_t = Buffer.from(state.seedHex, 'hex');
  const K_next = evolveSeed(K_t);

  // Irreversibly wipe old seed
  zeroizeBuffer(K_t);
  state.seedHex = '0000000000000000000000000000000000000000000000000000000000000000';

  const newState = {
    version: FSS_STATE_VERSION,
    epoch: nextEpoch,
    seedHex: K_next.toString('hex'),
    authPath: nextAuthPath || null,
    mpk: state.mpk,
    maxEpochs: state.maxEpochs,
    evolvedAt: new Date().toISOString(),
  };

  return newState;
}

// ── Persistence Helpers ───────────────────────────────────────────────────────

/**
 * Persist active FSS state to disk atomically with POSIX 0o600 permissions.
 *
 * @param {object} state - FSS state object.
 * @param {string} filePath - Path to save state.
 */
export function saveFssState(state, filePath) {
  const content = JSON.stringify(state, null, 2);
  atomicWriteSecretFile(filePath, content, 0o600);
}

/**
 * Load FSS state from disk.
 *
 * @param {string} filePath - Path to load state from.
 * @returns {object} Loaded state.
 */
export function loadFssState(filePath) {
  if (!existsSync(filePath)) {
    throw new Error(`loadFssState: file not found at ${filePath}`);
  }
  const raw = readFileSync(filePath, 'utf8');
  const parsed = JSON.parse(raw);
  if (parsed.version !== FSS_STATE_VERSION) {
    throw new Error(`loadFssState: invalid state version "${parsed.version}"`);
  }
  return parsed;
}

export default {
  FSS_VERSION,
  FSS_STATE_VERSION,
  uint32BE,
  privateKeyFromSeed,
  publicKeyFromBytes,
  deriveRawPublicKey,
  deriveEpochSigningSeed,
  evolveSeed,
  computeLeafHash,
  computeInternalNodeHash,
  buildKeyTree,
  generateAuthPath,
  generateFssMasterState,
  buildSigningEnvelope,
  signFssEpoch,
  verifyFssSignature,
  evolveFssState,
  saveFssState,
  loadFssState,
};
