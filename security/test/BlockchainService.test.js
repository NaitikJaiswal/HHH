import { expect } from 'chai';
import { network } from 'hardhat';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { BlockchainService } from '../src/blockchain/blockchainService.js';
import { BlockchainError, BlockchainErrorCode } from '../src/blockchain/errors.js';
import { KeyManager } from '../src/keys/keyManager.js';
import { createCheckpoint, anchorSignedCheckpoint } from '../src/checkpoints/checkpointService.js';
import { sha256hex } from '../src/crypto/hashing.js';

const { ethers } = await network.create();

describe('BlockchainService', function () {
  let anchorContract;
  let contractAddress;
  let owner;
  let submitter;
  let unauthorized;
  let service;

  const validCheckpointId = '11111111-2222-3333-4444-555555555555';
  const validMerkleRoot = 'a'.repeat(64);
  const startSeq = 1;
  const endSeq = 5;
  const eventCount = 5;
  const timestamp = '2026-11-20T12:00:00Z';

  beforeEach(async function () {
    [owner, submitter, unauthorized] = await ethers.getSigners();
    anchorContract = await ethers.deployContract('SecureLogAnchor');
    await anchorContract.waitForDeployment();
    contractAddress = await anchorContract.getAddress();

    // Authorize submitter
    await (await anchorContract.connect(owner).setSubmitter(submitter.address, true)).wait();

    // Default service using submitter signer
    service = new BlockchainService({
      provider: ethers.provider,
      signer: submitter,
      contractAddress,
      chainId: 31337,
    });
    await service.init();
  });

  describe('1. Initialization & Network Validation', function () {
    it('initializes successfully with valid provider, signer, and contract', async function () {
      expect(service.isInitialized).to.equal(true);
      expect(service.contractAddress).to.equal(ethers.getAddress(contractAddress));

      const status = await service.checkConnectivity();
      expect(status.connected).to.equal(true);
      expect(status.chainId).to.equal(31337);
      expect(status.address).to.equal(submitter.address);
      expect(parseFloat(status.balance)).to.be.greaterThan(0);
    });

    it('throws CHAIN_ID error when connected chainId does not match expected', async function () {
      const badService = new BlockchainService({
        provider: ethers.provider,
        signer: submitter,
        contractAddress,
        chainId: 1, // Wrong chain (Ethereum mainnet)
      });

      let err = null;
      try {
        await badService.init();
      } catch (e) {
        err = e;
      }

      expect(err).to.be.instanceOf(BlockchainError);
      expect(err.code).to.equal(BlockchainErrorCode.CHAIN_ID);
    });

    it('throws INVALID_ADDRESS when contractAddress is missing or malformed', async function () {
      const noAddrService = new BlockchainService({
        provider: ethers.provider,
        signer: submitter,
        contractAddress: '',
      });

      let err1 = null;
      try {
        await noAddrService.init();
      } catch (e) {
        err1 = e;
      }
      expect(err1).to.be.instanceOf(BlockchainError);
      expect(err1.code).to.equal(BlockchainErrorCode.INVALID_ADDRESS);

      const badAddrService = new BlockchainService({
        provider: ethers.provider,
        signer: submitter,
        contractAddress: 'not-an-address',
      });

      let err2 = null;
      try {
        await badAddrService.init();
      } catch (e) {
        err2 = e;
      }
      expect(err2).to.be.instanceOf(BlockchainError);
      expect(err2.code).to.equal(BlockchainErrorCode.INVALID_ADDRESS);
    });

    it('throws CONTRACT_NOT_FOUND when address has no bytecode', async function () {
      // Use an unused EOA address with no bytecode deployed
      const emptyWallet = ethers.Wallet.createRandom();
      const emptyService = new BlockchainService({
        provider: ethers.provider,
        signer: submitter,
        contractAddress: emptyWallet.address,
        chainId: 31337,
      });

      let err = null;
      try {
        await emptyService.init();
      } catch (e) {
        err = e;
      }

      expect(err).to.be.instanceOf(BlockchainError);
      expect(err.code).to.equal(BlockchainErrorCode.CONTRACT_NOT_FOUND);
    });

    it('throws CONTRACT_NOT_FOUND if operations are invoked before init()', async function () {
      const uninitService = new BlockchainService({
        provider: ethers.provider,
        signer: submitter,
        contractAddress,
      });

      let err = null;
      try {
        await uninitService.getTotalCheckpoints();
      } catch (e) {
        err = e;
      }

      expect(err).to.be.instanceOf(BlockchainError);
      expect(err.code).to.equal(BlockchainErrorCode.CONTRACT_NOT_FOUND);
    });
  });

  describe('2. Gas Estimation and Checkpoint Anchoring', function () {
    it('estimates gas for valid checkpoint anchoring parameters', async function () {
      const gas = await service.estimateGas({
        checkpointId: validCheckpointId,
        merkleRoot: validMerkleRoot,
        startSequence: startSeq,
        endSequence: endSeq,
        eventCount,
        timestamp,
      });

      expect(typeof gas).to.equal('string');
      expect(BigInt(gas) > 0n).to.equal(true);
    });

    it('successfully anchors a checkpoint and returns AnchorResult', async function () {
      const result = await service.anchorCheckpoint({
        checkpointId: validCheckpointId,
        merkleRoot: validMerkleRoot,
        startSequence: startSeq,
        endSequence: endSeq,
        eventCount,
        timestamp,
      });

      expect(result.txHash).to.match(/^0x[0-9a-fA-F]{64}$/);
      expect(result.blockNumber).to.be.a('number');
      expect(result.blockNumber).to.be.greaterThan(0);
      expect(result.contractAddress).to.equal(ethers.getAddress(contractAddress));
      expect(result.chainId).to.equal(31337);
      expect(result.anchoredAt).to.be.a('string');
      expect(BigInt(result.gasUsed) > 0n).to.equal(true);

      // Verify on-chain state
      expect(await service.commitmentExists(validCheckpointId)).to.equal(true);
    });

    it('rejects duplicate checkpoint submissions with DUPLICATE error', async function () {
      await service.anchorCheckpoint({
        checkpointId: validCheckpointId,
        merkleRoot: validMerkleRoot,
        startSequence: startSeq,
        endSequence: endSeq,
        eventCount,
        timestamp,
      });

      let err = null;
      try {
        await service.anchorCheckpoint({
          checkpointId: validCheckpointId,
          merkleRoot: 'b'.repeat(64),
          startSequence: startSeq,
          endSequence: endSeq,
          eventCount,
          timestamp,
        });
      } catch (e) {
        err = e;
      }

      expect(err).to.be.instanceOf(BlockchainError);
      expect(err.code).to.equal(BlockchainErrorCode.DUPLICATE);
    });

    it('rejects anchoring without a signer with UNAUTHORIZED error', async function () {
      const readOnlyService = new BlockchainService({
        provider: ethers.provider,
        contractAddress,
        chainId: 31337,
      });
      await readOnlyService.init();

      let err = null;
      try {
        await readOnlyService.anchorCheckpoint({
          checkpointId: '22222222-2222-2222-2222-222222222222',
          merkleRoot: validMerkleRoot,
          startSequence: 1,
          endSequence: 1,
          eventCount: 1,
          timestamp,
        });
      } catch (e) {
        err = e;
      }

      expect(err).to.be.instanceOf(BlockchainError);
      expect(err.code).to.equal(BlockchainErrorCode.UNAUTHORIZED);
    });

    it('rejects anchoring by unauthorized account', async function () {
      const unauthService = new BlockchainService({
        provider: ethers.provider,
        signer: unauthorized,
        contractAddress,
        chainId: 31337,
      });
      await unauthService.init();

      let err = null;
      try {
        await unauthService.anchorCheckpoint({
          checkpointId: '33333333-3333-3333-3333-333333333333',
          merkleRoot: validMerkleRoot,
          startSequence: 1,
          endSequence: 1,
          eventCount: 1,
          timestamp,
        });
      } catch (e) {
        err = e;
      }

      expect(err).to.be.instanceOf(BlockchainError);
      expect([BlockchainErrorCode.UNAUTHORIZED, BlockchainErrorCode.REVERT]).to.include(err.code);
    });
  });

  describe('3. Retrieval & On-Chain Verification', function () {
    beforeEach(async function () {
      await service.anchorCheckpoint({
        checkpointId: validCheckpointId,
        merkleRoot: validMerkleRoot,
        startSequence: startSeq,
        endSequence: endSeq,
        eventCount,
        timestamp,
      });
    });

    it('retrieves an existing commitment with correct fields', async function () {
      const commitment = await service.getCommitment(validCheckpointId);

      expect(commitment.merkleRoot).to.equal('0x' + validMerkleRoot);
      expect(commitment.startSequence).to.equal(startSeq);
      expect(commitment.endSequence).to.equal(endSeq);
      expect(commitment.eventCount).to.equal(eventCount);
      expect(commitment.submitter).to.equal(submitter.address);
      expect(commitment.exists).to.equal(true);
      expect(commitment.blockNumber).to.be.greaterThan(0);
    });

    it('throws NOT_FOUND for non-existent checkpoint ID', async function () {
      let err = null;
      try {
        await service.getCommitment('non-existent-uuid');
      } catch (e) {
        err = e;
      }

      expect(err).to.be.instanceOf(BlockchainError);
      expect(err.code).to.equal(BlockchainErrorCode.NOT_FOUND);
    });

    it('verifyOnChain returns true for matching root, false for mismatched root', async function () {
      const matchRes = await service.verifyOnChain(validCheckpointId, validMerkleRoot);
      expect(matchRes.match).to.equal(true);
      expect(matchRes.onChainRoot).to.equal('0x' + validMerkleRoot);
      expect(matchRes.blockNumber).to.be.greaterThan(0);

      const wrongRoot = 'f'.repeat(64);
      const mismatchRes = await service.verifyOnChain(validCheckpointId, wrongRoot);
      expect(mismatchRes.match).to.equal(false);
      expect(mismatchRes.onChainRoot).to.equal('0x' + validMerkleRoot);

      const missingRes = await service.verifyOnChain('unanchored-id', validMerkleRoot);
      expect(missingRes.match).to.equal(false);
      expect(missingRes.onChainRoot).to.equal(null);
    });

    it('supports getTotalCheckpoints and listCheckpointIds pagination', async function () {
      const id2 = '22222222-3333-4444-5555-666666666666';
      await service.anchorCheckpoint({
        checkpointId: id2,
        merkleRoot: 'b'.repeat(64),
        startSequence: 6,
        endSequence: 10,
        eventCount: 5,
        timestamp,
      });

      const total = await service.getTotalCheckpoints();
      expect(total).to.equal(2);

      const ids = await service.listCheckpointIds(0, 10);
      expect(ids.length).to.equal(2);

      const page1 = await service.listCheckpointIds(0, 1);
      expect(page1.length).to.equal(1);
    });
  });

  describe('4. CheckpointService Integration (anchorSignedCheckpoint)', function () {
    let tempDir;
    let km;

    beforeEach(async function () {
      tempDir = mkdtempSync(join(tmpdir(), 'securelog-blockchain-test-'));
      km = new KeyManager(tempDir);
      await km.loadOrGenerate('test-blockchain-passphrase');
    });

    afterEach(function () {
      if (tempDir) {
        rmSync(tempDir, { recursive: true, force: true });
      }
    });

    it('anchors a valid signed checkpoint and records blockchain metadata', async function () {
      const leafHashes = [
        sha256hex('event-1'),
        sha256hex('event-2'),
        sha256hex('event-3'),
      ];

      const checkpoint = createCheckpoint(
        {
          source_id: 'test-server',
          start_sequence: 1,
          end_sequence: 3,
          leaf_hashes: leafHashes,
        },
        km
      );

      const res = await anchorSignedCheckpoint(checkpoint, service, km);

      expect(res.verified).to.equal(true);
      expect(res.checkpoint.blockchain).to.not.equal(null);
      expect(res.checkpoint.blockchain.txHash).to.match(/^0x[0-9a-fA-F]{64}$/);
      expect(res.checkpoint.blockchain.blockNumber).to.be.greaterThan(0);
      expect(res.checkpoint.blockchain.contractAddress).to.equal(ethers.getAddress(contractAddress));

      // Verify on-chain commitment exists
      const onChain = await service.getCommitment(checkpoint.checkpoint_id);
      expect(onChain.merkleRoot).to.equal('0x' + checkpoint.merkle_root);
    });

    it('rejects anchoring a checkpoint with invalid signature', async function () {
      const leafHashes = [sha256hex('ev1')];
      const checkpoint = createCheckpoint(
        {
          source_id: 'test-server',
          start_sequence: 1,
          end_sequence: 1,
          leaf_hashes: leafHashes,
        },
        km
      );

      // Tamper signature
      checkpoint.signature = '0'.repeat(128);

      let err = null;
      try {
        await anchorSignedCheckpoint(checkpoint, service, km);
      } catch (e) {
        err = e;
      }

      expect(err).to.be.instanceOf(BlockchainError);
      expect(err.code).to.equal(BlockchainErrorCode.INVALID_SIGNATURE);
    });
  });
});
