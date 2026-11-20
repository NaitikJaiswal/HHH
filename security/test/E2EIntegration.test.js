import { expect } from 'chai';
import { network } from 'hardhat';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

// Security Module Primitives
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
import {
  createCheckpoint,
  verifyCheckpoint,
  verifyCheckpointProof,
  VerificationStatus,
} from '../src/checkpoints/checkpointService.js';
import { BlockchainService } from '../src/blockchain/blockchainService.js';
import { BackendAdapter, createBackendAdapter } from '../src/adapter/backendAdapter.js';
import { formatCheckpointId, formatMerkleRoot } from '../src/blockchain/contractAbi.js';
import { BlockchainError, BlockchainErrorCode } from '../src/blockchain/errors.js';

const { ethers } = await network.create();

describe('Phase 4B — Final Integration Validation', function () {
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

    // Deploy contract
    anchorContract = await ethers.deployContract('SecureLogAnchor');
    await anchorContract.waitForDeployment();
    contractAddress = await anchorContract.getAddress();

    // Authorize submitter
    await (await anchorContract.connect(owner).setSubmitter(submitter.address, true)).wait();

    // Initialize BlockchainService
    blockchainService = new BlockchainService({
      provider: ethers.provider,
      signer: submitter,
      contractAddress,
      chainId: 31337,
    });
    await blockchainService.init();

    // Initialize KeyManager with persistent directory
    tempKeysDir = mkdtempSync(join(tmpdir(), 'securelog-e2e-test-'));
    keyManager = new KeyManager(tempKeysDir);
    await keyManager.loadOrGenerate('test-e2e-passphrase-2026');

    // Create BackendAdapter
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

  describe('A. Complete 14-Step Checkpoint Lifecycle', function () {
    it('executes all 14 steps from raw log events to on-chain verified report', async function () {
      // Step 1: Receive synthetic log events (5 sequential security events)
      const rawEvents = [
        {
          event_id: 'evt-sec-0001-uuid',
          event_time: '2026-11-20T10:00:00Z',
          event_type: 'AUTH_SUCCESS',
          message: 'User admin logged in from 192.168.1.100',
          metadata: { ip: '192.168.1.100', user: 'admin', auth_method: 'MFA' },
          sequence_number: 1,
          severity: 'INFO',
          source_id: 'auth-gateway-01',
        },
        {
          event_id: 'evt-sec-0002-uuid',
          event_time: '2026-11-20T10:00:05Z',
          event_type: 'POLICY_EVAL',
          message: 'Role RBAC_ADMIN granted for session',
          metadata: { role: 'RBAC_ADMIN', session_id: 'sess-9821' },
          sequence_number: 2,
          severity: 'INFO',
          source_id: 'auth-gateway-01',
        },
        {
          event_id: 'evt-sec-0003-uuid',
          event_time: '2026-11-20T10:00:15Z',
          event_type: 'CONFIG_ACCESS',
          message: 'Security policy updated: firewall rule #44',
          metadata: { rule_id: 44, action: 'ALLOW' },
          sequence_number: 3,
          severity: 'WARN',
          source_id: 'auth-gateway-01',
        },
        {
          event_id: 'evt-sec-0004-uuid',
          event_time: '2026-11-20T10:00:30Z',
          event_type: 'VAULT_ACCESS',
          message: 'Decryption key requested: vault/sec-token',
          metadata: { token: 'vault/sec-token', access_type: 'READ' },
          sequence_number: 4,
          severity: 'INFO',
          source_id: 'auth-gateway-01',
        },
        {
          event_id: 'evt-sec-0005-uuid',
          event_time: '2026-11-20T10:00:45Z',
          event_type: 'SESSION_TERMINATE',
          message: 'Admin session closed gracefully',
          metadata: { session_id: 'sess-9821', duration_sec: 45 },
          sequence_number: 5,
          severity: 'INFO',
          source_id: 'auth-gateway-01',
        },
      ];

      // Step 2 & 3: Canonicalize each event and generate SHA-256 hashes
      for (const raw of rawEvents) {
        const cJson = canonicalJson(raw);
        expect(typeof cJson).to.equal('string');
        expect(cJson).to.not.include('\n');
        expect(cJson).to.not.include('\r');
        expect(cJson).to.not.include('\t');
        expect(cJson.startsWith('{')).to.equal(true);
        expect(cJson.endsWith('}')).to.equal(true);
      }

      // Step 4: Build hash chain
      const chainedEvents = buildChain(rawEvents, GENESIS_HASH);
      expect(chainedEvents.length).to.equal(5);
      expect(chainedEvents[0].previous_hash).to.equal(GENESIS_HASH);
      expect(chainedEvents[1].previous_hash).to.equal(chainedEvents[0].current_hash);
      expect(chainedEvents[4].sequence_number).to.equal(5);

      // Step 5: Validate the hash chain
      const chainVerification = verifyHashChain(chainedEvents);
      expect(chainVerification.valid).to.equal(true);
      expect(chainVerification.errors.length).to.equal(0);
      expect(chainedEvents.length).to.equal(5);

      // Step 6: Generate Merkle tree from committed current_hash values
      const leafHashes = chainedEvents.map((e) => e.current_hash);
      const tree = buildMerkleTree(leafHashes);
      expect(tree.layers.length).to.be.greaterThan(1);

      // Step 7: Generate Merkle root
      const root = getMerkleRoot(tree);
      expect(root).to.match(/^[0-9a-f]{64}$/);

      // Step 8: Create signed checkpoint with Ed25519
      const checkpoint = createCheckpoint(
        {
          source_id: 'auth-gateway-01',
          start_sequence: 1,
          end_sequence: 5,
          leaf_hashes: leafHashes,
        },
        keyManager
      );
      expect(checkpoint.schema_version).to.equal('logn-checkpoint-v1');
      expect(checkpoint.merkle_root).to.equal(root);
      expect(checkpoint.signature).to.match(/^[0-9a-f]{128}$/);
      expect(checkpoint.signer_public_key).to.equal(keyManager.publicKeyHex);

      // Step 9: Verify checkpoint signature & structure
      const offChainCheck = verifyCheckpoint(checkpoint, keyManager);
      expect(offChainCheck.valid).to.equal(true);
      expect(offChainCheck.status).to.equal(VerificationStatus.VERIFIED);

      // Step 10: Generate and verify Merkle inclusion proof for leaf #2 (seq 3)
      const leafIndex = 2;
      const proof = generateMerkleProof(tree, leafIndex);
      expect(proof.leaf_index).to.equal(leafIndex);
      expect(proof.proof.length).to.be.greaterThan(0);

      const proofVerification = verifyMerkleProof(leafHashes[leafIndex], proof.proof, root);
      expect(proofVerification).to.equal(true);

      const checkpointProofResult = verifyCheckpointProof(
        checkpoint,
        leafHashes[leafIndex],
        proof.proof
      );
      expect(checkpointProofResult.valid).to.equal(true);

      // Step 11: Anchor checkpoint commitment to local Hardhat blockchain
      const anchorResult = await adapter.anchorCheckpointForBackend(checkpoint);
      expect(anchorResult.success).to.equal(true);
      expect(anchorResult.txHash).to.match(/^0x[0-9a-fA-F]{64}$/);
      expect(anchorResult.blockNumber).to.be.greaterThan(0);
      expect(anchorResult.chainId).to.equal(31337);

      // Verify checkpoint was enriched with blockchain metadata
      expect(checkpoint.blockchain).to.not.equal(null);
      expect(checkpoint.blockchain.txHash).to.equal(anchorResult.txHash);
      expect(checkpoint.blockchain.blockNumber).to.equal(anchorResult.blockNumber);

      // Step 12: Retrieve commitment from blockchain
      const status = await adapter.getAnchoringStatus(checkpoint.checkpoint_id);
      expect(status.anchored).to.equal(true);
      expect(status.onChainRoot).to.equal('0x' + root);
      expect(status.startSequence).to.equal(1);
      expect(status.endSequence).to.equal(5);
      expect(status.eventCount).to.equal(5);

      const metadata = await adapter.getTransactionMetadata(checkpoint.checkpoint_id);
      expect(metadata.checkpointId).to.equal(checkpoint.checkpoint_id);
      expect(metadata.merkleRoot).to.equal('0x' + root);
      expect(metadata.submitter).to.equal(submitter.address);

      // Step 13 & 14: Verify on-chain commitment and produce final verification report
      const report = await adapter.verifyCheckpointOnChain(checkpoint);
      expect(report.overallValid).to.equal(true);
      expect(report.checkpointId).to.equal(checkpoint.checkpoint_id);
      expect(report.sourceId).to.equal('auth-gateway-01');
      expect(report.signatureValid).to.equal(true);
      expect(report.merkleRootMatch).to.equal(true);
      expect(report.onChainMatch).to.equal(true);
      expect(report.onChainStatus).to.equal('MATCH');
      expect(report.keyRegistered).to.equal(true);
      expect(report.keyMismatch).to.equal(false);
      expect(report.errors.length).to.equal(0);
      expect(report.recomputedRoot).to.equal(root);
      expect(report.storedRoot).to.equal(root);
      expect(report.onChainRoot).to.equal('0x' + root);
      expect(report.onChainBlockNumber).to.equal(anchorResult.blockNumber);
    });
  });

  describe('B. Cross-Module Consistency Checks', function () {
    it('guarantees UUID-to-bytes32 conversion is deterministic and idempotent across all paths', async function () {
      const sampleUuid = 'a3f89012-4567-8901-2345-678901234567';
      const bytes32Id = formatCheckpointId(sampleUuid);

      // 1. Deterministic
      expect(formatCheckpointId(sampleUuid)).to.equal(bytes32Id);

      // 2. Idempotent (calling format on already formatted ID returns same value)
      expect(formatCheckpointId(bytes32Id)).to.equal(bytes32Id);

      // 3. Anchoring and querying with either format yields the exact same on-chain commitment
      const leafHashes = [sha256hex('x1'), sha256hex('x2')];
      const checkpoint = createCheckpoint(
        {
          checkpoint_id: sampleUuid,
          source_id: 'srv-1',
          start_sequence: 1,
          end_sequence: 2,
          leaf_hashes: leafHashes,
        },
        keyManager
      );

      await adapter.anchorCheckpointForBackend(checkpoint);

      // Query using UUID
      const resByUuid = await adapter.getAnchoringStatus(sampleUuid);
      expect(resByUuid.anchored).to.equal(true);

      // Query using bytes32 directly
      const resByBytes32 = await adapter.getAnchoringStatus(bytes32Id);
      expect(resByBytes32.anchored).to.equal(true);
      expect(resByBytes32.onChainRoot).to.equal(resByUuid.onChainRoot);
    });

    it('enforces that Merkle leaves strictly match committed Log.currentHash values', async function () {
      const rawEvents = [
        {
          event_id: 'e1',
          event_time: '2026-11-20T10:00:00Z',
          event_type: 'TYPE_A',
          message: 'Log 1',
          metadata: {},
          sequence_number: 1,
          severity: 'INFO',
          source_id: 'src-1',
        },
      ];
      const chained = buildChain(rawEvents);
      const computedHash = hashLogEvent(chained[0]);
      expect(chained[0].current_hash).to.equal(computedHash);

      const tree = buildMerkleTree([chained[0].current_hash]);
      const root = getMerkleRoot(tree);

      const checkpoint = createCheckpoint(
        {
          source_id: 'src-1',
          start_sequence: 1,
          end_sequence: 1,
          leaf_hashes: [chained[0].current_hash],
        },
        keyManager
      );

      expect(checkpoint.merkle_root).to.equal(root);
    });
  });

  describe('C. Backend Integration Boundary Validation', function () {
    it('rejects checkpoint missing required fields', async function () {
      const badCp = {
        checkpoint_id: 'uuid-1',
        source_id: 's1',
      };

      let err = null;
      try {
        await adapter.anchorCheckpointForBackend(badCp);
      } catch (e) {
        err = e;
      }

      expect(err).to.be.instanceOf(BlockchainError);
      expect(err.code).to.equal(BlockchainErrorCode.INVALID_CHECKPOINT);
    });

    it('rejects checkpoint with Merkle inconsistency', async function () {
      const leafHashes = [sha256hex('1'), sha256hex('2')];
      const checkpoint = createCheckpoint(
        {
          source_id: 's1',
          start_sequence: 1,
          end_sequence: 2,
          leaf_hashes: leafHashes,
        },
        keyManager
      );

      // Corrupt leaf hashes without recomputing root
      checkpoint.merkle_leaf_hashes[0] = sha256hex('tampered-leaf');

      let err = null;
      try {
        await adapter.anchorCheckpointForBackend(checkpoint);
      } catch (e) {
        err = e;
      }

      expect(err).to.be.instanceOf(BlockchainError);
      expect(err.code).to.equal(BlockchainErrorCode.INVALID_CHECKPOINT);
      expect(err.message).to.include('Merkle root mismatch');
    });

    it('rejects checkpoint with invalid Ed25519 signature', async function () {
      const checkpoint = createCheckpoint(
        {
          source_id: 's1',
          start_sequence: 1,
          end_sequence: 2,
          leaf_hashes: [sha256hex('1'), sha256hex('2')],
        },
        keyManager
      );

      // Invert last byte of signature
      const sigBuf = Buffer.from(checkpoint.signature, 'hex');
      sigBuf[sigBuf.length - 1] ^= 0xff;
      checkpoint.signature = sigBuf.toString('hex');

      let err = null;
      try {
        await adapter.anchorCheckpointForBackend(checkpoint);
      } catch (e) {
        err = e;
      }

      expect(err).to.be.instanceOf(BlockchainError);
      expect(err.code).to.equal(BlockchainErrorCode.INVALID_SIGNATURE);
    });

    it('handles idempotent retry after successful confirmation', async function () {
      const checkpoint = createCheckpoint(
        {
          source_id: 's1',
          start_sequence: 1,
          end_sequence: 3,
          leaf_hashes: [sha256hex('1'), sha256hex('2'), sha256hex('3')],
        },
        keyManager
      );

      // First anchor
      const first = await adapter.safeRetryAnchor(checkpoint);
      expect(first.success).to.equal(true);
      expect(first.alreadyAnchored).to.equal(undefined);

      // Second anchor call on same checkpoint (simulating retry)
      const second = await adapter.safeRetryAnchor(checkpoint);
      expect(second.success).to.equal(true);
      expect(second.alreadyAnchored).to.equal(true);
      expect(second.blockNumber).to.equal(first.blockNumber);
    });
  });
});
