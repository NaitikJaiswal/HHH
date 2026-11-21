/**
 * @module secretScrubber
 * @description Secure memory erasure, atomic persistence, and disk scrubbing
 * for forward-secure cryptographic keys and private states.
 *
 * Implements best-effort memory zeroization and POSIX filesystem protection:
 *   - Overwrite memory buffers with zeros via Buffer.fill(0)
 *   - Overwrite and unlink sensitive key files
 *   - Atomic file creation with strict POSIX 0o600 permissions and fsync
 */

import { randomBytes } from 'node:crypto';
import {
  writeFileSync,
  readFileSync,
  unlinkSync,
  existsSync,
  openSync,
  fsyncSync,
  closeSync,
  renameSync,
  chmodSync,
  statSync,
} from 'node:fs';
import { dirname } from 'node:path';

/**
 * Irreversibly zeroize a memory buffer.
 * If the input is a Buffer, fills it with 0x00 bytes.
 *
 * @param {Buffer|null|undefined} buf - Buffer to zeroize.
 */
export function zeroizeBuffer(buf) {
  if (buf && Buffer.isBuffer(buf)) {
    buf.fill(0);
  }
}

/**
 * Securely erase a file on disk:
 * 1. Overwrites existing contents with random bytes.
 * 2. Overwrites with all zeros.
 * 3. Fsyncs to storage.
 * 4. Unlinks (removes) the file.
 *
 * Note on physical storage: On copy-on-write filesystems (APFS, ZFS) or wear-leveling
 * SSDs, physical flash cells may not be immediately overwritten. This provides best-effort
 * operating-system-level wiping.
 *
 * @param {string} filePath - Path to file to shred.
 */
export function secureEraseFile(filePath) {
  if (!existsSync(filePath)) {
    return;
  }

  try {
    const stats = statSync(filePath);
    const size = Math.max(stats.size, 64);

    // Pass 1: Random entropy overwrite
    const randomPass = randomBytes(size);
    writeFileSync(filePath, randomPass);

    // Pass 2: All zeros overwrite
    const zeroPass = Buffer.alloc(size, 0);
    writeFileSync(filePath, zeroPass);

    // Force fsync
    const fd = openSync(filePath, 'r+');
    try {
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }

    // Pass 3: Unlink
    unlinkSync(filePath);
  } catch (err) {
    // If overwrite fails, attempt direct unlink as fallback
    if (existsSync(filePath)) {
      try {
        unlinkSync(filePath);
      } catch {
        // Suppress secondary error
      }
    }
  }
}

/**
 * Atomically write sensitive state to disk with strict POSIX permissions (0o600).
 *
 * @param {string} targetPath - Final destination path.
 * @param {string|Buffer} content - Content to write.
 * @param {number} [mode=0o600] - File permissions.
 */
export function atomicWriteSecretFile(targetPath, content, mode = 0o600) {
  const nonce = randomBytes(8).toString('hex');
  const tempPath = `${targetPath}.tmp.${nonce}`;

  const fd = openSync(tempPath, 'w', mode);
  try {
    const buffer = Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf8');
    writeFileSync(fd, buffer);
    fsyncSync(fd);
    chmodSync(tempPath, mode);
  } finally {
    closeSync(fd);
  }

  renameSync(tempPath, targetPath);
}

export default {
  zeroizeBuffer,
  secureEraseFile,
  atomicWriteSecretFile,
};
