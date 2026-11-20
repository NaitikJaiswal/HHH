import crypto from 'crypto';
import { canonicalize } from './canonicalize.js';

let activeKeyPair = null;

/**
 * Initializes or loads the Ed25519 key pair for digital checkpoint signing.
 * In production, private keys are loaded from secure KMS / secrets manager.
 */
export const getKeyPair = () => {
  if (activeKeyPair) {
    return activeKeyPair;
  }

  // Load from environment if configured
  if (process.env.ED25519_PRIVATE_KEY && process.env.ED25519_PUBLIC_KEY) {
    activeKeyPair = {
      privateKey: crypto.createPrivateKey({
        key: Buffer.from(process.env.ED25519_PRIVATE_KEY, 'base64'),
        format: 'der',
        type: 'pkcs8',
      }),
      publicKey: crypto.createPublicKey({
        key: Buffer.from(process.env.ED25519_PUBLIC_KEY, 'base64'),
        format: 'der',
        type: 'spki',
      }),
      publicKeyDer: process.env.ED25519_PUBLIC_KEY,
    };
    return activeKeyPair;
  }

  // Generate ephemeral in-memory Ed25519 key pair (retained outside version control)
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const publicKeyDer = publicKey.export({ format: 'der', type: 'spki' }).toString('base64');

  activeKeyPair = {
    privateKey,
    publicKey,
    publicKeyDer,
  };

  return activeKeyPair;
};

/**
 * Resets the active key pair (primarily used for test isolation)
 */
export const resetKeyPair = (customKeyPair = null) => {
  activeKeyPair = customKeyPair;
};

/**
 * Signs data using Ed25519 asymmetric cryptography.
 * Input can be string, object, or buffer. Objects are canonicalized deterministically.
 */
export const signData = (data, customPrivateKey = null) => {
  const privateKey = customPrivateKey || getKeyPair().privateKey;
  const contentToSign = typeof data === 'object' && !Buffer.isBuffer(data) ? canonicalize(data) : data;
  const buffer = Buffer.isBuffer(contentToSign) ? contentToSign : Buffer.from(String(contentToSign), 'utf8');

  // Sign using Ed25519 (null algorithm because Ed25519 pre-hashes natively)
  const signatureBuffer = crypto.sign(null, buffer, privateKey);
  return signatureBuffer.toString('hex');
};

/**
 * Verifies an Ed25519 digital signature.
 */
export const verifySignature = (data, signatureHex, customPublicKey = null) => {
  try {
    let publicKey = customPublicKey;

    if (!publicKey) {
      publicKey = getKeyPair().publicKey;
    } else if (typeof publicKey === 'string') {
      // Decode base64 DER public key
      publicKey = crypto.createPublicKey({
        key: Buffer.from(publicKey, 'base64'),
        format: 'der',
        type: 'spki',
      });
    }

    const contentToVerify = typeof data === 'object' && !Buffer.isBuffer(data) ? canonicalize(data) : data;
    const buffer = Buffer.isBuffer(contentToVerify) ? contentToVerify : Buffer.from(String(contentToVerify), 'utf8');
    const signatureBuffer = Buffer.from(signatureHex, 'hex');

    return crypto.verify(null, buffer, publicKey, signatureBuffer);
  } catch (err) {
    return false;
  }
};

export default {
  getKeyPair,
  resetKeyPair,
  signData,
  verifySignature,
};
