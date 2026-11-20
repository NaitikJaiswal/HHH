import { expect } from 'chai';
import { network } from 'hardhat';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { BlockchainService } from '../src/blockchain/blockchainService.js';
import { BackendAdapter, createBackendAdapter } from '../src/adapter/backendAdapter.js';
import { BlockchainError, BlockchainErrorCode } from '../src/blockchain/errors.js';
import { KeyManager } from '../src/keys/keyManager.js';
import { createCheckpoint } from '../src/checkpoints/checkpointService.js';
import { sha256hex } from '../src/crypto/hashing.js';

const { ethers } = await network.create();

describe('BackendAdapter', function () {
  let anchorContract;
  let contractAddress;
  let owner;
  let submitter;
  let blockchainService;
  let adapter;
  let keyManager;
  let tempDir;

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

    tempDir = mkdtempSync(join(tmpdir(), 'securelog-adapter-test-'));
    keyManager = new KeyManager(tempDir);
    await keyManager.loadOrGenerate('test-adapter-passphrase');

    adapter = createBackendAdapter({
      blockchainService,
      keyManager,
    });
  });

  afterEach(function () {
    if (tempDir) {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  function makeSampleCheckpoint(start = 1, end = 3) {
    const leafHashes = [];
    for (let i = start; i <= end; i++) {
      leafHashes.push(sha256hex(`event-${i}`));
    }
    return createCheckpoint(
      {
        source_id: 'server-alpha',
        start_sequence: start,
        end_sequence: end,
        leaf_hashes: leafHashes,
      },
      keyManager
    );
  }

  describe('1. anchorCheckpointForBackend', function () {
    it('successfully anchors a signed checkpoint for backend and returns metadata', async function () {
      const checkpoint = makeSampleCheckpoint(1, 4);

      const res = await adapter.anchorCheckpointForBackend(checkpoint);

      expect(res.success).to.equal(true);
      expect(res.checkpointId).to.equal(checkpoint.checkpoint_id);
      expect(res.txHash).to.match(/^0x[0-9a-fA-F]{64}$/);
      expect(res.blockNumber).to.be.greaterThan(0);
      expect(res.chainId).to.equal(31337);
      expect(res.checkpoint.blockchain).to.not.equal(null);
      expect(res.checkpoint.blockchain.contractAddress).to.equal(ethers.getAddress(contractAddress));
    });

    it('rejects an invalid checkpoint with structured error', async function () {
      const checkpoint = makeSampleCheckpoint(1, 2);
      // Tamper signature
      checkpoint.signature = '0'.repeat(128);

      let err = null;
      try {
        await adapter.anchorCheckpointForBackend(checkpoint);
      } catch (e) {
        err = e;
      }

      expect(err).to.be.instanceOf(BlockchainError);
      expect(err.code).to.equal(BlockchainErrorCode.INVALID_SIGNATURE);
    });

    it('rejects anchoring when signing key is not in the trusted registry', async function () {
      // Create an untrusted key in a separate directory
      const untrustedDir = mkdtempSync(join(tmpdir(), 'securelog-untrusted-'));
      try {
        const untrustedKm = new KeyManager(untrustedDir);
        await untrustedKm.loadOrGenerate('untrusted-passphrase');

        const untrustedCheckpoint = createCheckpoint(
          {
            source_id: 'rogue-server',
            start_sequence: 1,
            end_sequence: 2,
            leaf_hashes: [sha256hex('e1'), sha256hex('e2')],
          },
          untrustedKm
        );

        let err = null;
        try {
          // Attempt to anchor via adapter with trusted keyManager
          await adapter.anchorCheckpointForBackend(untrustedCheckpoint);
        } catch (e) {
          err = e;
        }

        expect(err).to.be.instanceOf(BlockchainError);
        expect(err.code).to.equal(BlockchainErrorCode.INVALID_SIGNATURE);
        expect(err.message).to.include('KeyManager active key or registry');
      } finally {
        rmSync(untrustedDir, { recursive: true, force: true });
      }
    });

    it('rejects anchoring when no keyManager is provided to verify provenance', async function () {
      const checkpoint = makeSampleCheckpoint(1, 2);
      const noKmAdapter = createBackendAdapter({
        blockchainService,
        keyManager: null,
      });

      let err = null;
      try {
        await noKmAdapter.anchorCheckpointForBackend(checkpoint);
      } catch (e) {
        err = e;
      }

      expect(err).to.be.instanceOf(BlockchainError);
      expect(err.code).to.equal(BlockchainErrorCode.INVALID_SIGNATURE);
      expect(err.message).to.include('KeyManager is required to verify signing key provenance');
    });
  });

  describe('2. getAnchoringStatus and getTransactionMetadata', function () {
    it('returns unanchored status for fresh checkpoint', async function () {
      const status = await adapter.getAnchoringStatus('unanchored-test-uuid');
      expect(status.anchored).to.equal(false);
      expect(status.onChainRoot).to.equal(null);
    });

    it('returns anchored status and full metadata once anchored', async function () {
      const checkpoint = makeSampleCheckpoint(10, 12);
      await adapter.anchorCheckpointForBackend(checkpoint);

      const status = await adapter.getAnchoringStatus(checkpoint.checkpoint_id);
      expect(status.anchored).to.equal(true);
      expect(status.onChainRoot).to.equal('0x' + checkpoint.merkle_root);
      expect(status.startSequence).to.equal(10);
      expect(status.endSequence).to.equal(12);
      expect(status.eventCount).to.equal(3);

      const meta = await adapter.getTransactionMetadata(checkpoint.checkpoint_id);
      expect(meta.checkpointId).to.equal(checkpoint.checkpoint_id);
      expect(meta.contractAddress).to.equal(ethers.getAddress(contractAddress));
      expect(meta.merkleRoot).to.equal('0x' + checkpoint.merkle_root);
      expect(meta.submitter).to.equal(submitter.address);
    });
  });

  describe('3. verifyCheckpointOnChain (Dual Off-Chain + On-Chain Verification)', function () {
    it('returns overallValid: true for an authentic anchored checkpoint', async function () {
      const checkpoint = makeSampleCheckpoint(1, 5);
      await adapter.anchorCheckpointForBackend(checkpoint);

      const report = await adapter.verifyCheckpointOnChain(checkpoint);

      expect(report.overallValid).to.equal(true);
      expect(report.signatureValid).to.equal(true);
      expect(report.merkleRootMatch).to.equal(true);
      expect(report.onChainMatch).to.equal(true);
      expect(report.onChainStatus).to.equal('MATCH');
      expect(report.errors.length).to.equal(0);
    });

    it('detects unanchored checkpoint as onChainStatus NOT_ANCHORED', async function () {
      const checkpoint = makeSampleCheckpoint(1, 3); // created but not anchored

      const report = await adapter.verifyCheckpointOnChain(checkpoint);

      expect(report.overallValid).to.equal(false);
      expect(report.signatureValid).to.equal(true);
      expect(report.onChainMatch).to.equal(false);
      expect(report.onChainStatus).to.equal('NOT_ANCHORED');
      expect(report.errors.some((e) => e.includes('not found on blockchain'))).to.equal(true);
    });

    it('detects tampered leaf hashes in checkpoint with on-chain anchor', async function () {
      const checkpoint = makeSampleCheckpoint(1, 3);
      await adapter.anchorCheckpointForBackend(checkpoint);

      // Tamper leaf hashes after anchoring
      checkpoint.merkle_leaf_hashes[0] = sha256hex('tampered');

      const report = await adapter.verifyCheckpointOnChain(checkpoint);
      expect(report.overallValid).to.equal(false);
      expect(report.merkleRootMatch).to.equal(false);
    });

    it('does not falsely report success when blockchain provider or contract fails', async function () {
      const checkpoint = makeSampleCheckpoint(1, 3);
      await adapter.anchorCheckpointForBackend(checkpoint);

      // Create a faulty blockchain service that throws a NETWORK error
      const brokenService = {
        verifyOnChain: async () => {
          throw new BlockchainError(
            BlockchainErrorCode.NETWORK,
            'Simulated RPC network connection failure'
          );
        },
      };

      const brokenAdapter = createBackendAdapter({
        blockchainService: brokenService,
        keyManager,
      });

      const report = await brokenAdapter.verifyCheckpointOnChain(checkpoint);

      expect(report.overallValid).to.equal(false);
      expect(report.onChainMatch).to.equal(false);
      expect(report.onChainStatus).to.equal('ERROR');
      expect(report.errors.some((e) => e.includes('On-chain verification error'))).to.equal(true);
    });

    it('reports overallValid: false when signing key is not registered in registry', async function () {
      const untrustedDir = mkdtempSync(join(tmpdir(), 'securelog-untrusted-verify-'));
      try {
        const untrustedKm = new KeyManager(untrustedDir);
        await untrustedKm.loadOrGenerate('untrusted-passphrase');

        const untrustedCheckpoint = createCheckpoint(
          {
            source_id: 'rogue-server',
            start_sequence: 1,
            end_sequence: 2,
            leaf_hashes: [sha256hex('e1'), sha256hex('e2')],
          },
          untrustedKm
        );

        // Verify against trusted adapter
        const report = await adapter.verifyCheckpointOnChain(untrustedCheckpoint);

        expect(report.overallValid).to.equal(false);
        expect(report.keyRegistered).to.equal(false);
        expect(report.errors.some((e) => e.includes('KeyManager active key or registry'))).to.equal(true);
      } finally {
        rmSync(untrustedDir, { recursive: true, force: true });
      }
    });
  });

  describe('4. safeRetryAnchor (Idempotent Recovery)', function () {
    it('anchors cleanly on first attempt', async function () {
      const checkpoint = makeSampleCheckpoint(100, 102);

      const res = await adapter.safeRetryAnchor(checkpoint);
      expect(res.success).to.equal(true);
      expect(res.alreadyAnchored).to.equal(undefined);
      expect(res.blockNumber).to.be.greaterThan(0);
    });

    it('returns existing on-chain data without duplicate transaction on second attempt', async function () {
      const checkpoint = makeSampleCheckpoint(200, 202);

      // First submission
      const firstRes = await adapter.safeRetryAnchor(checkpoint);
      expect(firstRes.success).to.equal(true);
      const originalBlock = firstRes.blockNumber;

      // Second attempt (simulating retry after timeout/network hiccup)
      const secondRes = await adapter.safeRetryAnchor(checkpoint);
      expect(secondRes.success).to.equal(true);
      expect(secondRes.alreadyAnchored).to.equal(true);
      expect(secondRes.blockNumber).to.equal(originalBlock);
      expect(secondRes.checkpoint.blockchain.blockNumber).to.equal(originalBlock);
    });

    it('rejects checkpoint missing checkpoint_id', async function () {
      let err = null;
      try {
        await adapter.safeRetryAnchor({});
      } catch (e) {
        err = e;
      }
      expect(err).to.be.instanceOf(BlockchainError);
      expect(err.code).to.equal(BlockchainErrorCode.INVALID_CHECKPOINT);
    });
  });
});
