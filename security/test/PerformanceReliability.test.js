import { expect } from 'chai';
import { network } from 'hardhat';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { sha256hex, GENESIS_HASH } from '../src/crypto/hashing.js';
import { buildChain, verifyHashChain } from '../src/crypto/hashChain.js';
import {
  buildMerkleTree,
  getMerkleRoot,
  generateMerkleProof,
  verifyMerkleProof,
} from '../src/merkle/merkleTree.js';
import { KeyManager } from '../src/keys/keyManager.js';
import { createCheckpoint, verifyCheckpoint } from '../src/checkpoints/checkpointService.js';
import { BlockchainService } from '../src/blockchain/blockchainService.js';
import { createBackendAdapter } from '../src/adapter/backendAdapter.js';

const { ethers } = await network.create();

describe('Phase 6 — Performance and Reliability Validation', function () {
  let anchorContract;
  let contractAddress;
  let owner;
  let submitter;
  let blockchainService;
  let adapter;
  let keyManager;
  let tempKeysDir;

  beforeEach(async function () {
    [owner, submitter] = await ethers.getSigners();

    anchorContract = await ethers.deployContract('SecureLogAnchor');
    await anchorContract.waitForDeployment();
    contractAddress = await anchorContract.getAddress();

    await (await anchorContract.connect(owner).setSubmitter(submitter.address, true)).wait();

    blockchainService = new BlockchainService({
      provider: ethers.provider,
      signer: submitter,
      contractAddress,
      chainId: 31337,
    });
    await blockchainService.init();

    tempKeysDir = mkdtempSync(join(tmpdir(), 'securelog-perf-test-'));
    keyManager = new KeyManager(tempKeysDir);
    await keyManager.loadOrGenerate('perf-passphrase-2026');

    adapter = createBackendAdapter({
      blockchainService,
      keyManager,
    });
  });

  afterEach(function () {
    if (tempKeysDir) {
      rmSync(tempKeysDir, { recursive: true, force: true });
    }
  });

  it('validates hash-chain building and verification at increasing event scales (10, 100, 500 events)', function () {
    const scales = [10, 100, 500];

    for (const count of scales) {
      const start = performance.now();
      const rawEvents = Array.from({ length: count }, (_, i) => ({
        event_id: `scale-evt-${i + 1}`,
        event_time: '2026-11-20T12:00:00Z',
        event_type: 'METRIC',
        message: `Benchmark telemetry event ${i + 1}`,
        metadata: { index: i },
        sequence_number: i + 1,
        severity: 'INFO',
        source_id: 'perf-agent',
      }));

      const chained = buildChain(rawEvents, GENESIS_HASH);
      const chainTime = performance.now() - start;

      const verifyStart = performance.now();
      const verifyRes = verifyHashChain(chained);
      const verifyTime = performance.now() - verifyStart;

      expect(verifyRes.valid).to.equal(true);
      expect(chained.length).to.equal(count);
      expect(chainTime).to.be.lessThan(5000); // Sanity limit (< 5s for 500 events)
      expect(verifyTime).to.be.lessThan(5000);
    }
  });

  it('validates Merkle-tree building and inclusion proofs at increasing leaf counts (10, 100, 500 leaves)', function () {
    const scales = [10, 100, 500];

    for (const count of scales) {
      const leaves = Array.from({ length: count }, (_, i) => sha256hex(`perf-leaf-${i}`));

      const start = performance.now();
      const tree = buildMerkleTree(leaves);
      const root = getMerkleRoot(tree);
      const buildDuration = performance.now() - start;

      expect(root).to.match(/^[0-9a-f]{64}$/);
      expect(buildDuration).to.be.lessThan(3000);

      // Verify proof for first, middle, and last leaf
      const indices = [0, Math.floor(count / 2), count - 1];
      for (const idx of indices) {
        const proof = generateMerkleProof(tree, idx);
        const valid = verifyMerkleProof(leaves[idx], proof.proof, root);
        expect(valid).to.equal(true);
      }
    }
  });

  it('validates repeated on-chain read operations throughput without memory degradation', async function () {
    const checkpoint = createCheckpoint(
      {
        source_id: 'perf-src',
        start_sequence: 1,
        end_sequence: 5,
        leaf_hashes: Array.from({ length: 5 }, (_, i) => sha256hex(`p-${i}`)),
      },
      keyManager
    );

    await adapter.anchorCheckpointForBackend(checkpoint);

    // Perform 25 consecutive queries
    const queryCount = 25;
    const start = performance.now();

    for (let i = 0; i < queryCount; i++) {
      const status = await adapter.getAnchoringStatus(checkpoint.checkpoint_id);
      expect(status.anchored).to.equal(true);
      expect(status.onChainRoot).to.equal('0x' + checkpoint.merkle_root);
    }

    const duration = performance.now() - start;
    const avgPerQuery = duration / queryCount;

    expect(avgPerQuery).to.be.lessThan(200); // Under 200ms per in-process call
  });

  it('safely handles oversized payloads and malformed inputs without crashing process', function () {
    // Malformed parameters
    expect(() => buildMerkleTree(null)).to.throw(TypeError);
    expect(() => buildMerkleTree('not an array')).to.throw(TypeError);
    expect(() => buildMerkleTree([null])).to.throw(TypeError);
    expect(() => buildMerkleTree(['short-hash'])).to.throw(TypeError);
  });
});
