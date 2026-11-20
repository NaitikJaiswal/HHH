/**
 * @module keyManager
 * @description Ed25519 key pair generation, persistent encrypted storage, signing and verification.
 *
 * Implements the key management specification in:
 *   docs/technical-integration-contract.md §4
 *
 * Key design decisions (per contract §4):
 *   - Private key encrypted at rest using AES-256-GCM with scrypt KDF
 *   - Passphrase injected via LOGN_KEY_PASSPHRASE environment variable — NEVER hardcoded
 *   - Key stored in keys/ directory (signing_key.enc, signing_key.pub, key_id.txt)
 *   - Ed25519 signing uses Node.js built-in crypto.sign / crypto.verify
 *   - Signature: 64 raw bytes → 128 hex chars
 *   - Public key: 32 raw bytes → 64 hex chars
 *   - Key ID: UUID v4 (generated once at key creation, persisted in key_id.txt)
 *   - Historical public keys preserved in key_registry.json for checkpoint verification
 *   - Key rotation archives existing key material and preserves historical verification
 *
 * SECURITY WARNINGS:
 *   - Never print the passphrase or private key bytes in logs
 *   - signing_key.enc is listed in .gitignore — it must NEVER be committed
 *   - signing_key.pub IS committed (it is a public key)
 *   - key_id.txt IS committed (it is a non-secret identifier)
 */

import {
  createCipheriv,
  createDecipheriv,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
  randomBytes,
  createPublicKey,
  createPrivateKey,
  scrypt,
} from 'node:crypto';

import {
  readFileSync,
  writeFileSync,
  existsSync,
  mkdirSync,
  chmodSync,
} from 'node:fs';

import { join } from 'node:path';

// ── UUID v4 generator (no third-party deps) ───────────────────────────────────

/**
 * Generate a RFC 4122 UUID v4 string using Node.js built-in crypto.randomBytes.
 *
 * @returns {string} UUID v4 string, e.g. "f47ac10b-58cc-4372-a567-0e02b2c3d479"
 */
export function generateUuidV4() {
  const bytes = randomBytes(16);
  // Set version 4 bits and variant bits per RFC 4122
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const h = bytes.toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

// ── KDF + Encryption ──────────────────────────────────────────────────────────

/**
 * Derive a 32-byte AES key from a passphrase using scrypt.
 * Parameters follow the contract §4.3: N=32768, r=8, p=1.
 *
 * @param {string} passphrase - User-supplied passphrase (never logged).
 * @param {Buffer} salt - 32-byte random salt.
 * @returns {Promise<Buffer>} 32-byte derived key.
 */
function deriveKey(passphrase, salt) {
  return new Promise((resolve, reject) => {
    scrypt(passphrase, salt, 32, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }, (err, derivedKey) => {
      if (err) reject(err);
      else resolve(derivedKey);
    });
  });
}

/**
 * Encrypt 32-byte private key seed bytes with AES-256-GCM.
 * Returns a JSON-serialisable envelope per the contract §4.3 schema.
 *
 * @param {Buffer} seedBytes - 32-byte raw Ed25519 private key seed.
 * @param {string} passphrase - Passphrase (from env, never stored).
 * @returns {Promise<object>} Encrypted envelope object.
 */
async function encryptSeed(seedBytes, passphrase) {
  const salt = randomBytes(32);
  const iv = randomBytes(12);
  const aesKey = await deriveKey(passphrase, salt);

  const cipher = createCipheriv('aes-256-gcm', aesKey, iv);
  const ciphertext = Buffer.concat([cipher.update(seedBytes), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    schema: 'logn-key-v1',
    algorithm: 'Ed25519',
    kdf: 'scrypt',
    kdf_params: { N: 32768, r: 8, p: 1, salt_hex: salt.toString('hex') },
    encryption: 'AES-256-GCM',
    iv_hex: iv.toString('hex'),
    auth_tag_hex: authTag.toString('hex'),
    ciphertext_hex: ciphertext.toString('hex'),
  };
}

/**
 * Decrypt an encrypted key envelope.
 *
 * @param {object} envelope - Parsed JSON from signing_key.enc.
 * @param {string} passphrase - Decryption passphrase.
 * @returns {Promise<Buffer>} 32-byte raw private key seed.
 * @throws {Error} If decryption fails (wrong passphrase, bad auth tag, corrupted file).
 */
async function decryptEnvelope(envelope, passphrase) {
  if (!envelope || typeof envelope !== 'object') {
    throw new Error('KeyManager: invalid key envelope structure');
  }
  if (envelope.schema !== 'logn-key-v1') {
    throw new Error(`KeyManager: unsupported key schema: "${envelope.schema}"`);
  }
  if (envelope.encryption !== 'AES-256-GCM') {
    throw new Error(`KeyManager: unsupported encryption: "${envelope.encryption}"`);
  }

  const salt = Buffer.from(envelope.kdf_params.salt_hex, 'hex');
  const iv = Buffer.from(envelope.iv_hex, 'hex');
  const authTag = Buffer.from(envelope.auth_tag_hex, 'hex');
  const ciphertext = Buffer.from(envelope.ciphertext_hex, 'hex');
  const aesKey = await deriveKey(passphrase, salt);

  try {
    const decipher = createDecipheriv('aes-256-gcm', aesKey, iv);
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new Error(
      'KeyManager: decryption failed — wrong passphrase or corrupted key file'
    );
  }
}

// ── Ed25519 key serialisation helpers ─────────────────────────────────────────

/**
 * Extract the raw 32-byte public key from an Ed25519 KeyObject.
 * Node.js exports SPKI DER (44 bytes); the public key occupies the last 32 bytes.
 *
 * @param {import('node:crypto').KeyObject} pub
 * @returns {Buffer}
 */
function exportPublicKeyBytes(pub) {
  return pub.export({ type: 'spki', format: 'der' }).slice(-32);
}

/**
 * Extract the raw 32-byte private key seed from an Ed25519 KeyObject.
 * Node.js exports PKCS8 DER (48 bytes); the seed occupies the last 32 bytes.
 *
 * @param {import('node:crypto').KeyObject} priv
 * @returns {Buffer}
 */
function exportPrivateKeyBytes(priv) {
  return priv.export({ type: 'pkcs8', format: 'der' }).slice(-32);
}

/**
 * Reconstruct an Ed25519 private KeyObject from a raw 32-byte seed.
 *
 * The seed is wrapped in a minimal PKCS8 DER header (RFC 8410).
 * Header hex: 302e020100300506032b657004220420
 *
 * @param {Buffer} seedBytes - 32-byte raw Ed25519 private key seed.
 * @returns {import('node:crypto').KeyObject}
 */
export function privateKeyFromBytes(seedBytes) {
  if (!Buffer.isBuffer(seedBytes) || seedBytes.length !== 32) {
    throw new TypeError('privateKeyFromBytes: expected a 32-byte Buffer');
  }
  const header = Buffer.from('302e020100300506032b657004220420', 'hex');
  const pkcs8 = Buffer.concat([header, seedBytes]);
  return createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
}

/**
 * Reconstruct an Ed25519 public KeyObject from a raw 32-byte hex string.
 *
 * The bytes are wrapped in a minimal SPKI DER header (RFC 8410).
 * Header hex: 302a300506032b6570032100
 *
 * @param {string} publicKeyHex - 64-char hex public key.
 * @returns {import('node:crypto').KeyObject}
 */
export function publicKeyFromHex(publicKeyHex) {
  if (typeof publicKeyHex !== 'string' || !/^[0-9a-fA-F]{64}$/.test(publicKeyHex)) {
    throw new TypeError('publicKeyFromHex: expected a 64-char hex string');
  }
  const rawBytes = Buffer.from(publicKeyHex, 'hex');
  const header = Buffer.from('302a300506032b6570032100', 'hex');
  const spki = Buffer.concat([header, rawBytes]);
  return createPublicKey({ key: spki, format: 'der', type: 'spki' });
}

// ── KeyManager class ──────────────────────────────────────────────────────────

/**
 * @typedef {object} HistoricalKeyEntry
 * @property {string}  key_id         - UUID v4.
 * @property {string}  public_key_hex - Hex-64 public key.
 * @property {string}  created_at     - ISO-8601 UTC creation timestamp.
 * @property {boolean} is_active      - Whether this is the current active key.
 */

/**
 * KeyManager handles Ed25519 key lifecycle:
 *   - Load an existing encrypted key from disk, or generate one on first run
 *   - Sign arbitrary data with the private key
 *   - Verify signatures (using stored or historical public keys)
 *   - Maintain a JSON registry of historical public keys for checkpoint verification
 *   - Key rotation with archiving and preservation of old public keys
 *
 * @example
 *   const km = new KeyManager('/abs/path/to/security/keys');
 *   await km.loadOrGenerate(process.env.LOGN_KEY_PASSPHRASE);
 *   const sigHex = km.sign(Buffer.from('hello'));
 *   const ok     = km.verify(Buffer.from('hello'), sigHex, km.publicKeyHex);
 */
export class KeyManager {
  /**
   * @param {string} keysDir - Absolute path to the keys directory.
   */
  constructor(keysDir) {
    if (!keysDir || typeof keysDir !== 'string') {
      throw new TypeError('KeyManager: keysDir must be a non-empty string path');
    }
    this.keysDir = keysDir;
    this._loaded = false;
    this._keyId = null;
    this._pubHex = null;
    this._privKey = null; // KeyObject — private key seed never stored as plain field after load
    this._currentPassphrase = null; // Stored in-memory only during session for rotation if needed
  }

  // ── File paths ───────────────────────────────────────────────────────────────
  get _encPath() { return join(this.keysDir, 'signing_key.enc'); }
  get _pubPath() { return join(this.keysDir, 'signing_key.pub'); }
  get _idPath() { return join(this.keysDir, 'key_id.txt'); }
  get _registryPath() { return join(this.keysDir, 'key_registry.json'); }

  // ── Public accessors ─────────────────────────────────────────────────────────

  /** @returns {string} UUID v4 key identifier. */
  get keyId() { this._assertLoaded(); return this._keyId; }

  /** @returns {string} Hex-64 Ed25519 public key. */
  get publicKeyHex() { this._assertLoaded(); return this._pubHex; }

  /** @returns {boolean} Whether a key is loaded. */
  get isLoaded() { return this._loaded; }

  // ── Core lifecycle ───────────────────────────────────────────────────────────

  /**
   * Load an existing encrypted key from disk, or generate a new key pair on first run.
   *
   * Per §4.6 restart behaviour:
   *   - If signing_key.enc exists: decrypt using passphrase and load.
   *   - Otherwise: generate new Ed25519 pair, encrypt, persist all three files.
   *
   * @param {string} [passphrase] - Passphrase. Defaults to LOGN_KEY_PASSPHRASE env var.
   * @returns {Promise<void>}
   * @throws {Error} If passphrase is missing or key file is corrupted.
   */
  async loadOrGenerate(passphrase) {
    const pp = passphrase ?? process.env.LOGN_KEY_PASSPHRASE ?? '';
    if (!pp) {
      throw new Error(
        'KeyManager: passphrase required — provide it explicitly or set LOGN_KEY_PASSPHRASE'
      );
    }

    if (!existsSync(this.keysDir)) {
      mkdirSync(this.keysDir, { recursive: true });
    }

    if (existsSync(this._encPath)) {
      await this._loadExisting(pp);
    } else {
      await this._generateNew(pp);
    }
    this._currentPassphrase = pp;
    this._loaded = true;
  }

  /**
   * Rotate the active signing key:
   *   1. Back up existing signing_key.enc to signing_key.enc.<timestamp>.bak
   *   2. Back up existing signing_key.pub to signing_key_OLD_<oldKeyId>.pub
   *   3. Mark the current key in key_registry.json as is_active = false
   *   4. Generate a new Ed25519 key pair with newPassphrase (or current passphrase)
   *   5. Write new signing_key.enc, signing_key.pub, key_id.txt
   *   6. Add new key to key_registry.json as is_active = true
   *   7. Update internal active key state
   *   8. Return { oldKeyId, newKeyId, newPublicKeyHex }
   *
   * @param {string} [newPassphrase] - Optional new passphrase.
   * @returns {Promise<{ oldKeyId: string, newKeyId: string, newPublicKeyHex: string }>}
   */
  async rotateKey(newPassphrase) {
    this._assertLoaded();
    const pp = newPassphrase ?? this._currentPassphrase ?? process.env.LOGN_KEY_PASSPHRASE ?? '';
    if (!pp) {
      throw new Error('KeyManager.rotateKey: passphrase required');
    }

    const oldKeyId = this._keyId;
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

    // Archive current files per §4.7
    if (existsSync(this._encPath)) {
      writeFileSync(join(this.keysDir, `signing_key.enc.${timestamp}.bak`), readFileSync(this._encPath));
    }
    if (existsSync(this._pubPath)) {
      writeFileSync(join(this.keysDir, `signing_key_OLD_${oldKeyId}.pub`), readFileSync(this._pubPath));
    }

    // Generate and persist new key pair
    await this._generateNew(pp);
    this._currentPassphrase = pp;

    return {
      oldKeyId,
      newKeyId: this._keyId,
      newPublicKeyHex: this._pubHex,
    };
  }

  /**
   * Sign a data buffer with the loaded Ed25519 private key.
   *
   * @param {Buffer|string} data - Data to sign (string → UTF-8).
   * @returns {string} Ed25519 signature as lowercase hex-128 (64 bytes).
   */
  sign(data) {
    this._assertLoaded();
    const buf = typeof data === 'string' ? Buffer.from(data, 'utf8') : Buffer.from(data);
    // Ed25519: null algorithm is correct — the algorithm is implicit in the key type
    return cryptoSign(null, buf, this._privKey).toString('hex');
  }

  /**
   * Verify an Ed25519 signature against a public key.
   *
   * @param {Buffer|string} data        - The original signed data (string → UTF-8).
   * @param {string}        sigHex      - 128-char hex signature.
   * @param {string}        pubKeyHex   - 64-char hex public key.
   * @returns {boolean} true if valid, false otherwise (never throws for bad sigs).
   */
  verify(data, sigHex, pubKeyHex) {
    if (typeof sigHex !== 'string' || !/^[0-9a-fA-F]{128}$/.test(sigHex)) {
      throw new TypeError('KeyManager.verify: sigHex must be a 128-char hex string');
    }
    if (typeof pubKeyHex !== 'string' || !/^[0-9a-fA-F]{64}$/.test(pubKeyHex)) {
      throw new TypeError('KeyManager.verify: pubKeyHex must be a 64-char hex string');
    }
    const buf = typeof data === 'string' ? Buffer.from(data, 'utf8') : Buffer.from(data);
    const sigBuf = Buffer.from(sigHex, 'hex');
    try {
      return cryptoVerify(null, buf, publicKeyFromHex(pubKeyHex), sigBuf);
    } catch {
      return false;
    }
  }

  /**
   * Verify a signature against a specific key ID (either active or historical).
   *
   * @param {Buffer|string} data - Original data signed.
   * @param {string} sigHex - 128-char hex signature.
   * @param {string} keyId - UUID v4 key ID.
   * @returns {boolean} true if key is known and signature is valid; false if key is unknown or signature is invalid.
   */
  verifyWithKeyId(data, sigHex, keyId) {
    if (!keyId || typeof keyId !== 'string') {
      return false;
    }
    let pubHex = null;
    if (this._loaded && this._keyId === keyId) {
      pubHex = this._pubHex;
    } else {
      const entry = this.getPublicKeyById(keyId);
      if (entry) {
        pubHex = entry.public_key_hex;
      }
    }
    if (!pubHex) {
      return false; // Unknown key ID
    }
    return this.verify(data, sigHex, pubHex);
  }

  // ── Historical key registry ──────────────────────────────────────────────────

  /**
   * Retrieve a historical public key entry by key ID.
   * Returns null if the key ID is not in the registry.
   *
   * Essential for verifying checkpoints signed with an old key after rotation.
   *
   * @param {string} keyId - UUID v4 key identifier.
   * @returns {HistoricalKeyEntry|null}
   */
  getPublicKeyById(keyId) {
    return this._loadRegistry().find((e) => e.key_id === keyId) ?? null;
  }

  /**
   * Return the full historical key registry.
   *
   * @returns {HistoricalKeyEntry[]}
   */
  getKeyRegistry() {
    return this._loadRegistry();
  }

  // ── Private methods ──────────────────────────────────────────────────────────

  _assertLoaded() {
    if (!this._loaded) {
      throw new Error('KeyManager: no key loaded — call loadOrGenerate() first');
    }
  }

  async _loadExisting(passphrase) {
    let envelope;
    try {
      envelope = JSON.parse(readFileSync(this._encPath, 'utf8'));
    } catch (err) {
      throw new Error(`KeyManager: cannot read signing_key.enc — ${err.message}`);
    }

    const seedBytes = await decryptEnvelope(envelope, passphrase);

    if (!existsSync(this._idPath) || !existsSync(this._pubPath)) {
      throw new Error(
        'KeyManager: signing_key.enc found but key_id.txt or signing_key.pub is missing'
      );
    }

    const keyId = readFileSync(this._idPath, 'utf8').trim();
    const pubKeyHex = readFileSync(this._pubPath, 'utf8').trim();

    if (!/^[0-9a-fA-F]{64}$/.test(pubKeyHex)) {
      throw new Error('KeyManager: signing_key.pub contains invalid hex data');
    }

    this._keyId = keyId;
    this._pubHex = pubKeyHex;
    this._privKey = privateKeyFromBytes(seedBytes);
  }

  async _generateNew(passphrase) {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');

    const keyId = generateUuidV4();
    const pubBytes = exportPublicKeyBytes(publicKey);
    const seedBytes = exportPrivateKeyBytes(privateKey);
    const pubHex = pubBytes.toString('hex');
    const createdAt = new Date().toISOString().replace(/\.\d+Z$/, 'Z');

    // Encrypt and persist
    const envelope = await encryptSeed(seedBytes, passphrase);
    envelope.key_id = keyId;
    envelope.created_at = createdAt;

    writeFileSync(this._encPath, JSON.stringify(envelope, null, 2), 'utf8');
    writeFileSync(this._pubPath, pubHex, 'utf8');
    writeFileSync(this._idPath, keyId, 'utf8');

    // Set restrictive permissions (Unix/macOS; non-fatal on Windows)
    try {
      chmodSync(this._encPath, 0o600);
      chmodSync(this._pubPath, 0o644);
      chmodSync(this._idPath, 0o644);
    } catch { /* Windows — ignore */ }

    // Persist to historical registry
    this._upsertRegistry({
      key_id: keyId,
      public_key_hex: pubHex,
      created_at: createdAt,
      is_active: true,
    });

    this._keyId = keyId;
    this._pubHex = pubHex;
    this._privKey = privateKey; // Use KeyObject directly in memory
  }

  _loadRegistry() {
    if (!existsSync(this._registryPath)) return [];
    try {
      return JSON.parse(readFileSync(this._registryPath, 'utf8'));
    } catch {
      return [];
    }
  }

  _upsertRegistry(newEntry) {
    const registry = this._loadRegistry();
    // Mark all existing entries inactive when adding a new active one
    if (newEntry.is_active) {
      for (const e of registry) e.is_active = false;
    }
    const idx = registry.findIndex((e) => e.key_id === newEntry.key_id);
    if (idx >= 0) {
      registry[idx] = newEntry;
    } else {
      registry.push(newEntry);
    }
    writeFileSync(this._registryPath, JSON.stringify(registry, null, 2), 'utf8');
  }
}

export default KeyManager;
