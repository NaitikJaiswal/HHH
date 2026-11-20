# Ed25519 Key Management Specification

> **HHH SecureLog — Security Module (Phase 2)**  
> Reference: `docs/technical-integration-contract.md` §4

---

## 1. Overview & Motivation

Digital signatures are the bridge between **internal consistency** (which hash chains prove) and **authenticity / non-repudiation** (which proves who committed to the data).

### Why Ed25519?
- **High Security**: 128-bit security level based on Curve25519.
- **Side-Channel Resistance**: Constant-time execution by design, eliminating timing attacks.
- **Fast Signing & Verification**: Orders of magnitude faster than RSA and faster than standard ECDSA.
- **Compact Keys and Signatures**:
  - Raw public key: 32 bytes (64 hex characters)
  - Raw private seed: 32 bytes
  - Raw signature: 64 bytes (128 hex characters)
- **Built-in Node.js Support**: Implemented via Node.js native `crypto.sign(null, ...)` and `crypto.verify(null, ...)`.

---

## 2. Key Storage & Encryption at Rest (§4.2, §4.3)

### File Layout

```
security/keys/
├── .gitignore             ← Must exclude: signing_key.enc, *.enc, *.key
├── signing_key.enc        ← AES-256-GCM encrypted private key seed (mode 0600)
├── signing_key.pub        ← Plaintext hex-64 Ed25519 public key (mode 0644)
├── key_id.txt             ← UUID v4 key identifier (mode 0644)
└── key_registry.json      ← Historical public key registry for audit
```

### Encryption Envelope Format (`signing_key.enc`)

The raw 32-byte Ed25519 private seed is encrypted using AES-256-GCM with a key derived via scrypt:

```json
{
  "schema": "logn-key-v1",
  "key_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "algorithm": "Ed25519",
  "created_at": "2026-11-20T11:00:00Z",
  "kdf": "scrypt",
  "kdf_params": {
    "N": 32768,
    "r": 8,
    "p": 1,
    "salt_hex": "<32-byte hex salt>"
  },
  "encryption": "AES-256-GCM",
  "iv_hex": "<12-byte hex IV>",
  "auth_tag_hex": "<16-byte hex GCM authentication tag>",
  "ciphertext_hex": "<encrypted 32-byte seed in hex>"
}
```

### Security Invariants
1. **Passphrase Isolation**: The encryption passphrase is never hardcoded. It is passed via parameter or read from `LOGN_KEY_PASSPHRASE`.
2. **File Permissions**: On Unix/macOS, `signing_key.enc` is created with mode `0600` (owner read/write only).
3. **Git Hygiene**: `signing_key.enc` and all `.enc` files are explicitly gitignored.

---

## 3. Key Lifecycle & Restart Behavior (§4.6)

```
loadOrGenerate(passphrase):
  if signing_key.enc exists:
    Read and parse envelope
    Derive AES key using scrypt(passphrase, salt, N=32768, r=8, p=1, maxmem=64MB)
    Decrypt ciphertext with AES-256-GCM using IV and auth tag
    Load key_id from key_id.txt and public key from signing_key.pub
    Reconstruct KeyObject in memory
  else:
    Generate new Ed25519 key pair
    Generate UUID v4 key_id
    Derive AES key and encrypt 32-byte private seed
    Write signing_key.enc (mode 0600), signing_key.pub (mode 0644), key_id.txt (mode 0644)
    Register new key in key_registry.json as is_active = true
```

---

## 4. Key Rotation Protocol (§4.7)

When an operator rotates keys:
1. `rotateKey(newPassphrase)` archives `signing_key.enc` and `signing_key.pub` with timestamp backups.
2. The old key in `key_registry.json` is updated with `is_active = false`.
3. A fresh Ed25519 key pair and UUID v4 key ID are generated and persisted.
4. The new key is set as active in `key_registry.json`.
5. **Historical Verification**: Historical checkpoints signed with the old key remain verifiable because `getPublicKeyById(oldKeyId)` retrieves the archived public key.

---

## 5. What Key Management Proves and Does Not Prove

### What It Proves
- **Authenticity of Checkpoints**: Confirms that the checkpoint was produced by the entity possessing the private key.
- **Integrity**: Any change to the signed canonical checkpoint payload invalidates the Ed25519 signature.
- **Traceability**: `key_id` maps directly to an audited key record in the registry.

### What It Does Not Prove
- It does **not** prove that the underlying server or log source was uncompromised before log generation.
- It does **not** prevent an attacker with root access and passphrase memory dumps from generating false signatures (hardware security modules / KMS are recommended for production environments).
