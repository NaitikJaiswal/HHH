/**
 * @file benchmark.js
 * @description Standalone performance benchmark for HHH SecureLog cryptographic primitives.
 *
 * Measures:
 *   - Canonical JSON serialization
 *   - SHA-256 event hashing (LOGN-HASH-v1)
 *   - Hash-chain construction & validation
 *   - Merkle tree generation & proof verification
 *   - Ed25519 signing & verification
 */

import { performance } from 'node:perf_hooks';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { canonicalJson } from '../src/crypto/canonicalJson.js';
import { hashLogEvent, sha256hex, GENESIS_HASH } from '../src/crypto/hashing.js';
import { buildChain, verifyHashChain } from '../src/crypto/hashChain.js';
import {
  buildMerkleTree,
  getMerkleRoot,
  generateMerkleProof,
  verifyMerkleProof,
} from '../src/merkle/merkleTree.js';
import { KeyManager } from '../src/keys/keyManager.js';
import { createCheckpoint, verifyCheckpoint } from '../src/checkpoints/checkpointService.js';

console.log('='.repeat(70));
console.log('  HHH SecureLog — Cryptographic Performance Benchmark');
console.log('='.repeat(70));
console.log(`Platform: Node.js ${process.version} on ${process.platform} (${process.arch})`);
console.log(`Timestamp: ${new Date().toISOString()}`);
console.log('-'.repeat(70));

const initialMemory = process.memoryUsage().heapUsed / 1024 / 1024;
console.log(`Initial Heap: ${initialMemory.toFixed(2)} MB\n`);

// 1. Canonical JSON Benchmark
const sampleEvent = {
  event_id: 'e-bench-001',
  event_time: '2026-11-20T12:00:00Z',
  event_type: 'SYSTEM',
  message: 'Security benchmark telemetry payload',
  metadata: { priority: 1, tags: ['bench', 'sec', 'audit'] },
  sequence_number: 1,
  severity: 'INFO',
  source_id: 'benchmark-source',
  previous_hash: GENESIS_HASH,
};

const cJsonIters = 10000;
const startCJson = performance.now();
for (let i = 0; i < cJsonIters; i++) {
  canonicalJson(sampleEvent);
}
const durCJson = performance.now() - startCJson;
console.log(`[1] Canonical JSON (canonicalJson):`);
console.log(`    Iterations: ${cJsonIters.toLocaleString()}`);
console.log(`    Total Time: ${durCJson.toFixed(2)} ms`);
console.log(`    Throughput: ${((cJsonIters / durCJson) * 1000).toFixed(0)} ops/sec\n`);

// 2. SHA-256 Hashing Benchmark
const hashIters = 10000;
const startHash = performance.now();
for (let i = 0; i < hashIters; i++) {
  hashLogEvent(sampleEvent);
}
const durHash = performance.now() - startHash;
console.log(`[2] SHA-256 Event Hashing (hashLogEvent):`);
console.log(`    Iterations: ${hashIters.toLocaleString()}`);
console.log(`    Total Time: ${durHash.toFixed(2)} ms`);
console.log(`    Throughput: ${((hashIters / durHash) * 1000).toFixed(0)} hashes/sec\n`);

// 3. Hash Chain Construction & Validation
const chainScales = [10, 100, 500, 1000];
console.log(`[3] Hash Chain Scaling (buildChain & verifyHashChain):`);
for (const count of chainScales) {
  const raw = Array.from({ length: count }, (_, i) => ({
    ...sampleEvent,
    event_id: `evt-${i + 1}`,
    sequence_number: i + 1,
  }));

  const t0 = performance.now();
  const chained = buildChain(raw, GENESIS_HASH);
  const tBuild = performance.now() - t0;

  const t1 = performance.now();
  const vRes = verifyHashChain(chained);
  const tVerify = performance.now() - t1;

  console.log(
    `    N = ${count.toString().padEnd(5)} | Build: ${tBuild.toFixed(2).padStart(6)} ms | Verify: ${tVerify.toFixed(2).padStart(6)} ms | Status: ${vRes.valid ? 'VALID' : 'INVALID'}`
  );
}
console.log('');

// 4. Merkle Tree Scaling
const merkleScales = [10, 100, 500, 1000];
console.log(`[4] Merkle Tree Construction & Proof Verification:`);
for (const count of merkleScales) {
  const leaves = Array.from({ length: count }, (_, i) => sha256hex(`leaf-${i}`));

  const t0 = performance.now();
  const tree = buildMerkleTree(leaves);
  const root = getMerkleRoot(tree);
  const tBuild = performance.now() - t0;

  const p = generateMerkleProof(tree, Math.floor(count / 2));
  const t1 = performance.now();
  const vProof = verifyMerkleProof(leaves[Math.floor(count / 2)], p.proof, root);
  const tVerify = performance.now() - t1;

  console.log(
    `    N = ${count.toString().padEnd(5)} | Build: ${tBuild.toFixed(2).padStart(6)} ms | Proof Depth: ${p.proof.length.toString().padStart(2)} | Proof Verify: ${tVerify.toFixed(3)} ms | Root: ${root.slice(0, 12)}...`
  );
}
console.log('');

// 5. Ed25519 Signing & Checkpoint Verification
const tempDir = mkdtempSync(join(tmpdir(), 'securelog-bench-keys-'));
try {
  const km = new KeyManager(tempDir);
  await km.loadOrGenerate('bench-passphrase');

  const leaves = Array.from({ length: 100 }, (_, i) => sha256hex(`evt-leaf-${i}`));

  const t0 = performance.now();
  const checkpoint = createCheckpoint(
    {
      source_id: 'bench-host',
      start_sequence: 1,
      end_sequence: 100,
      leaf_hashes: leaves,
    },
    km
  );
  const tCreate = performance.now() - t0;

  const t1 = performance.now();
  const vCheck = verifyCheckpoint(checkpoint, km);
  const tVerify = performance.now() - t1;

  console.log(`[5] Ed25519 Checkpoint (100 events):`);
  console.log(`    Create & Sign:  ${tCreate.toFixed(2)} ms`);
  console.log(`    Verify Signature & Merkle: ${tVerify.toFixed(2)} ms`);
  console.log(`    Verification:   ${vCheck.valid ? 'PASS (VERIFIED)' : 'FAIL'}\n`);
} finally {
  rmSync(tempDir, { recursive: true, force: true });
}

const finalMemory = process.memoryUsage().heapUsed / 1024 / 1024;
console.log('-'.repeat(70));
console.log(`Final Heap:   ${finalMemory.toFixed(2)} MB (Delta: +${(finalMemory - initialMemory).toFixed(2)} MB)`);
console.log('='.repeat(70));
console.log('Benchmark completed successfully.');
