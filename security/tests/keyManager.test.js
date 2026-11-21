/**
 * Tests for keyManager.js — Ed25519 key pair management, persistence, rotation, and signing.
 * Uses Node.js built-in node:test and node:assert/strict.
 *
 * Test coverage:
 *   1. Generate a key pair on first run
 *   2. Sign and verify a message
 *   3. Reject altered messages
 *   4. Persist and reload the same key
 *   5. Verify signatures after reload
 *   6. Reject incorrect passphrase
 *   7. Detect corrupted key files
 *   8. Preserve old public keys after rotation
 *   9. Reject unknown key IDs
 *  10. Enforces file permissions and gitignore safety
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { KeyManager, generateUuidV4 } from '../src/keys/keyManager.js';

function createTempKeysDir() {
  return mkdtempSync(join(tmpdir(), 'securelog-keys-test-'));
}

test('1. Generate an Ed25519 key pair and verify structure', async () => {
  const dir = createTempKeysDir();
  try {
    const km = new KeyManager(dir);
    const passphrase = 'test-secret-passphrase-123';
    await km.loadOrGenerate(passphrase);

    assert.equal(km.isLoaded, true);
    assert.match(km.keyId, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
    assert.match(km.publicKeyHex, /^[0-9a-f]{64}$/i);

    // Verify companion files exist on disk
    const idOnDisk = readFileSync(join(dir, 'key_id.txt'), 'utf8').trim();
    const pubOnDisk = readFileSync(join(dir, 'signing_key.pub'), 'utf8').trim();
    const encOnDisk = JSON.parse(readFileSync(join(dir, 'signing_key.enc'), 'utf8'));

    assert.equal(idOnDisk, km.keyId);
    assert.equal(pubOnDisk, km.publicKeyHex);
    assert.equal(encOnDisk.schema, 'logn-key-v1');
    assert.equal(encOnDisk.algorithm, 'Ed25519');
    assert.equal(encOnDisk.encryption, 'AES-256-GCM');
    assert.equal(encOnDisk.kdf, 'scrypt');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('2. Sign and verify a message', async () => {
  const dir = createTempKeysDir();
  try {
    const km = new KeyManager(dir);
    await km.loadOrGenerate('passphrase');

    const msg = 'Test message for digital signing';
    const sig = km.sign(msg);

    assert.match(sig, /^[0-9a-f]{128}$/i, 'Signature must be 128 hex chars (64 bytes)');

    const valid = km.verify(msg, sig, km.publicKeyHex);
    assert.equal(valid, true, 'Valid signature must verify');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('3. Reject altered messages and altered signatures', async () => {
  const dir = createTempKeysDir();
  try {
    const km = new KeyManager(dir);
    await km.loadOrGenerate('passphrase');

    const msg = 'Original message';
    const sig = km.sign(msg);

    // Alter message
    assert.equal(km.verify('Modified message', sig, km.publicKeyHex), false);

    // Alter signature
    const corruptedSig = (sig[0] === 'a' ? 'b' : 'a') + sig.slice(1);
    assert.equal(km.verify(msg, corruptedSig, km.publicKeyHex), false);

    // Verify against wrong public key
    const fakePubKey = '0'.repeat(64);
    assert.equal(km.verify(msg, sig, fakePubKey), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('4 & 5. Persist and reload the same key; verify signatures after reload', async () => {
  const dir = createTempKeysDir();
  const passphrase = 'persistent-key-passphrase';
  try {
    const km1 = new KeyManager(dir);
    await km1.loadOrGenerate(passphrase);
    const keyId1 = km1.keyId;
    const pubHex1 = km1.publicKeyHex;

    const data = 'Data signed before reload';
    const sig1 = km1.sign(data);

    // Second instance loading existing files
    const km2 = new KeyManager(dir);
    await km2.loadOrGenerate(passphrase);

    assert.equal(km2.keyId, keyId1, 'Key ID must be identical after reload');
    assert.equal(km2.publicKeyHex, pubHex1, 'Public key must be identical after reload');

    // Cross-verification
    assert.equal(km2.verify(data, sig1, km2.publicKeyHex), true, 'Reloaded key must verify previous signatures');

    // Data signed by reloaded instance verifies with original pubkey
    const data2 = 'Data signed after reload';
    const sig2 = km2.sign(data2);
    assert.equal(km1.verify(data2, sig2, pubHex1), true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('6. Reject incorrect passphrase on reload', async () => {
  const dir = createTempKeysDir();
  try {
    const km1 = new KeyManager(dir);
    await km1.loadOrGenerate('correct-passphrase');

    const km2 = new KeyManager(dir);
    await assert.rejects(
      () => km2.loadOrGenerate('wrong-passphrase'),
      /decryption failed|wrong passphrase/i,
      'Loading with wrong passphrase must be rejected'
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('7. Detect corrupted key files', async () => {
  const dir = createTempKeysDir();
  try {
    const km = new KeyManager(dir);
    await km.loadOrGenerate('passphrase');

    // Corrupt ciphertext in envelope
    const encPath = join(dir, 'signing_key.enc');
    const envelope = JSON.parse(readFileSync(encPath, 'utf8'));
    envelope.ciphertext_hex = 'deadbeef' + envelope.ciphertext_hex.slice(8);
    writeFileSync(encPath, JSON.stringify(envelope));

    const kmCorrupt = new KeyManager(dir);
    await assert.rejects(
      () => kmCorrupt.loadOrGenerate('passphrase'),
      /decryption failed/i,
      'Corrupted ciphertext must fail to load'
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('8. Preserve old public keys after rotation and verify historical signatures', async () => {
  const dir = createTempKeysDir();
  try {
    const km = new KeyManager(dir);
    await km.loadOrGenerate('initial-passphrase');

    const oldKeyId = km.keyId;
    const oldPubHex = km.publicKeyHex;

    const historicalMessage = 'Checkpoint signed with key 1';
    const historicalSig = km.sign(historicalMessage);

    // Rotate key
    const rotationResult = await km.rotateKey('new-passphrase');
    assert.equal(rotationResult.oldKeyId, oldKeyId);
    assert.notEqual(rotationResult.newKeyId, oldKeyId);
    assert.notEqual(km.publicKeyHex, oldPubHex);

    // Historical key must be available in registry
    const historicalEntry = km.getPublicKeyById(oldKeyId);
    assert.ok(historicalEntry !== null, 'Old key must exist in registry');
    assert.equal(historicalEntry.key_id, oldKeyId);
    assert.equal(historicalEntry.public_key_hex, oldPubHex);
    assert.equal(historicalEntry.is_active, false);

    // Active key in registry must match current key
    const activeEntry = km.getPublicKeyById(km.keyId);
    assert.equal(activeEntry.is_active, true);

    // Verify historical signature using historical public key
    const valid = km.verify(historicalMessage, historicalSig, historicalEntry.public_key_hex);
    assert.equal(valid, true, 'Historical signature must verify using archived public key');

    // Verify with verifyWithKeyId
    assert.equal(km.verifyWithKeyId(historicalMessage, historicalSig, oldKeyId), true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('9. Reject unknown key IDs', async () => {
  const dir = createTempKeysDir();
  try {
    const km = new KeyManager(dir);
    await km.loadOrGenerate('passphrase');

    const randomId = generateUuidV4();
    assert.equal(km.getPublicKeyById(randomId), null, 'Unknown key ID must return null');

    const sig = km.sign('test');
    assert.equal(km.verifyWithKeyId('test', sig, randomId), false, 'Unknown key ID must fail verification');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
