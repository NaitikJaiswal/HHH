import { expect } from 'chai';
import { network } from 'hardhat';
import { mkdtempSync, rmSync, writeFileSync, statSync } from 'node:fs';
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
  EMPTY_TREE_ROOT,
} from '../src/merkle/merkleTree.js';
import { KeyManager } from '../src/keys/keyManager.js';
import {
  createCheckpoint,
  verifyCheckpoint,
  verifyCheckpointProof,
  VerificationStatus,
} from '../src/checkpoints/checkpointService.js';
import {
  verifyEventsAgainstCheckpoint,
  verifyCheckpointWithBlockchain,
} from '../src/verification/verifier.js';
import { BlockchainService } from '../src/blockchain/blockchainService.js';
import { BackendAdapter, createBackendAdapter } from '../src/adapter/backendAdapter.js';
import { BlockchainError, BlockchainErrorCode } from '../src/blockchain/errors.js';

const { ethers } = await network.create();

describe('Phase 5 — Adversarial Security Testing', function () {
  let anchorContract;
  let contractAddress;
  let owner;
  let submitter;
  let attacker;
  let blockchainService;
  let adapter;
  let keyManager;
  let tempKeysDir;

  beforeEach(async function () {
    [owner, submitter, attacker] = await ethers.getSigners();

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

    tempKeysDir = mkdtempSync(join(tmpdir(), 'securelog-adv-test-'));
    keyManager = new KeyManager(tempKeysDir);
    await keyManager.loadOrGenerate('adv-passphrase-2026');

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

  function makeChainedEvents(count = 5, startSeq = 1) {
    const rawEvents = Array.from({ length: count }, (_, i) => ({
      event_id: `evt-${startSeq + i}`,
      event_time: '2026-11-20T12:00:00Z',
      event_type: 'SECURITY_AUDIT',
      message: `Audit log record ${startSeq + i}`,
      metadata: { index: startSeq + i },
      sequence_number: startSeq + i,
      severity: 'INFO',
      source_id: 'host-gateway',
    }));
    return buildChain(rawEvents, startSeq === 1 ? GENESIS_HASH : undefined);
  }

  // ─── 4A: Log Tampering & Deletion Simulations ──────────────────────────────
  describe('A. Log Tampering and Deletion Simulations', function () {
    it('1. Unchanged valid log sequence passes verification cleanly', function () {
      const events = makeChainedEvents(5);
      const res = verifyHashChain(events);
      expect(res.valid).to.equal(true);
      expect(res.errors.length).to.equal(0);
    });

    it('2. Modification of an existing log event is detected immediately', function () {
      const events = makeChainedEvents(5);
      // Tamper message in event #2
      events[2].message = 'MALICIOUS MODIFICATION OF AUDIT LOG';

      const res = verifyHashChain(events);
      expect(res.valid).to.equal(false);
      expect(res.errors.some((e) => e.type === 'HASH_MISMATCH' && e.sequence === 3)).to.equal(true);
    });

    it('3. Deletion of a middle log entry is detected via sequence gap and broken link', function () {
      const events = makeChainedEvents(5);
      // Delete index 2 (seq 3)
      events.splice(2, 1);

      const res = verifyHashChain(events);
      expect(res.valid).to.equal(false);
      expect(res.errors.some((e) => e.type === 'SEQUENCE_GAP')).to.equal(true);
      expect(res.errors.some((e) => e.type === 'LINK_MISMATCH')).to.equal(true);
    });

    it('4. Deletion of the final log entry is detected by count & sequence bounds against checkpoint', function () {
      const events = makeChainedEvents(5);
      const checkpoint = createCheckpoint(
        {
          source_id: 'host-gateway',
          start_sequence: 1,
          end_sequence: 5,
          leaf_hashes: events.map((e) => e.current_hash),
        },
        keyManager
      );

      // Delete final event
      events.pop();

      const res = verifyEventsAgainstCheckpoint(checkpoint, events, keyManager);
      expect(res.valid).to.equal(false);
      expect(res.failures.some((f) => f.includes('does not match checkpoint event_count'))).to.equal(true);
    });

    it('5. Reordering of log entries fails both hash-chain linkage and Merkle alignment', function () {
      const events = makeChainedEvents(5);
      // Swap event 1 and event 2
      const tmp = events[1];
      events[1] = events[2];
      events[2] = tmp;

      const res = verifyHashChain(events);
      expect(res.valid).to.equal(false);
      expect(res.errors.length).to.be.greaterThan(0);
    });

    it('6. Modification of previous_hash breaks the cryptographic chain link', function () {
      const events = makeChainedEvents(4);
      events[2].previous_hash = 'f'.repeat(64);

      const res = verifyHashChain(events);
      expect(res.valid).to.equal(false);
      expect(res.errors.some((e) => e.type === 'LINK_MISMATCH')).to.equal(true);
    });

    it('7. Modification of stored current_hash fails SHA-256 integrity verification', function () {
      const events = makeChainedEvents(3);
      events[1].current_hash = '0'.repeat(64);

      const res = verifyHashChain(events);
      expect(res.valid).to.equal(false);
      expect(res.errors.some((e) => e.type === 'HASH_MISMATCH')).to.equal(true);
    });

    it('8. Insertion of unexpected log entry creates a broken link or sequence anomaly', function () {
      const events = makeChainedEvents(4);
      const injectedEvent = {
        event_id: 'injected-evt',
        event_time: '2026-11-20T12:00:00Z',
        event_type: 'INJECTION',
        message: 'Unauthorized injected log',
        metadata: {},
        sequence_number: 2, // Duplicate sequence number
        severity: 'CRITICAL',
        source_id: 'host-gateway',
        previous_hash: events[0].current_hash,
        current_hash: '1'.repeat(64),
      };
      // Insert after index 0
      events.splice(1, 0, injectedEvent);

      const res = verifyHashChain(events);
      expect(res.valid).to.equal(false);
    });

    it('9. Sequence-number gaps are accurately reported with specific sequence numbers', function () {
      const rawEvents = [
        { sequence_number: 1, message: 'm1', event_id: 'e1', event_time: '2026-11-20T12:00:00Z', event_type: 'T', metadata: {}, severity: 'I', source_id: 's' },
        { sequence_number: 2, message: 'm2', event_id: 'e2', event_time: '2026-11-20T12:00:00Z', event_type: 'T', metadata: {}, severity: 'I', source_id: 's' },
        { sequence_number: 4, message: 'm4', event_id: 'e4', event_time: '2026-11-20T12:00:00Z', event_type: 'T', metadata: {}, severity: 'I', source_id: 's' }, // Gap: 3 missing
      ];
      const chained = buildChain(rawEvents);
      const res = verifyHashChain(chained);
      expect(res.valid).to.equal(false);
      expect(res.errors.some((e) => e.type === 'SEQUENCE_GAP' && e.sequence === 4)).to.equal(true);
    });

    it('10. Log chain with invalid starting point (not GENESIS_HASH) is rejected', function () {
      const events = makeChainedEvents(3);
      events[0].previous_hash = '1'.repeat(64); // Not 64 zeros

      const res = verifyHashChain(events);
      expect(res.valid).to.equal(false);
      expect(res.errors.some((e) => e.type === 'GENESIS_MISMATCH')).to.equal(true);
    });
  });

  // ─── 4B: Merkle-Tree Attack Simulations ────────────────────────────────────
  describe('B. Merkle-Tree Attack Simulations', function () {
    let leaves;
    let tree;
    let root;

    beforeEach(function () {
      leaves = Array.from({ length: 7 }, (_, i) => sha256hex(`merkle-leaf-${i}`));
      tree = buildMerkleTree(leaves);
      root = getMerkleRoot(tree);
    });

    it('1. Modified leaf fails proof verification against original root', function () {
      const proof = generateMerkleProof(tree, 2);
      const tamperedLeaf = sha256hex('tampered-leaf-content');
      expect(verifyMerkleProof(tamperedLeaf, proof.proof, root)).to.equal(false);
    });

    it('2. Modified Merkle root fails proof verification', function () {
      const proof = generateMerkleProof(tree, 0);
      const tamperedRoot = sha256hex('fake-root');
      expect(verifyMerkleProof(leaves[0], proof.proof, tamperedRoot)).to.equal(false);
    });

    it('3. Invalid sibling hash in proof fails verification', function () {
      const proof = generateMerkleProof(tree, 3);
      proof.proof[0].sibling_hash = sha256hex('fake-sibling');
      expect(verifyMerkleProof(leaves[3], proof.proof, root)).to.equal(false);
    });

    it('4. Incorrect proof path / swapped position fails verification', function () {
      const proof = generateMerkleProof(tree, 1);
      // Invert position
      proof.proof[0].position = proof.proof[0].position === 'left' ? 'right' : 'left';
      expect(verifyMerkleProof(leaves[1], proof.proof, root)).to.equal(false);
    });

    it('5. Truncated or empty proof array fails verification', function () {
      expect(verifyMerkleProof(leaves[0], [], root)).to.equal(false);
    });

    it('6. Extra proof elements appended to proof fail verification', function () {
      const proof = generateMerkleProof(tree, 0);
      proof.proof.push({ sibling_hash: sha256hex('extra'), position: 'right' });
      expect(verifyMerkleProof(leaves[0], proof.proof, root)).to.equal(false);
    });

    it('7. Empty-tree evaluates to deterministic EMPTY_TREE_ROOT sentinel', function () {
      const emptyTree = buildMerkleTree([]);
      expect(getMerkleRoot(emptyTree)).to.equal(EMPTY_TREE_ROOT);
      expect(EMPTY_TREE_ROOT).to.equal(sha256hex('\0'));
    });

    it('8. Odd number of leaves applies Bitcoin node duplication rule consistently', function () {
      const threeLeaves = [sha256hex('a'), sha256hex('b'), sha256hex('c')];
      const tree3 = buildMerkleTree(threeLeaves);
      expect(tree3.layers[1].length).to.equal(2); // Pair(A,B) and Pair(C,C)
      expect(getMerkleRoot(tree3)).to.match(/^[0-9a-f]{64}$/);
    });

    it('9. Single-leaf tree constructs valid root and verifies inclusion', function () {
      const single = [sha256hex('single-entry')];
      const singleTree = buildMerkleTree(single);
      const singleRoot = getMerkleRoot(singleTree);
      const proof = generateMerkleProof(singleTree, 0);
      expect(verifyMerkleProof(single[0], proof.proof, singleRoot)).to.equal(true);
    });

    it('10. Large multi-level tree (100 leaves) verifies inclusion for all leaves', function () {
      const largeLeaves = Array.from({ length: 100 }, (_, i) => sha256hex(`bulk-event-${i}`));
      const largeTree = buildMerkleTree(largeLeaves);
      const largeRoot = getMerkleRoot(largeTree);

      for (let i = 0; i < 100; i += 10) {
        const p = generateMerkleProof(largeTree, i);
        expect(verifyMerkleProof(largeLeaves[i], p.proof, largeRoot)).to.equal(true);
      }
    });
  });

  // ─── 4C: Signature & Key-Management Attacks ────────────────────────────────
  describe('C. Signature and Key-Management Attacks', function () {
    let checkpoint;

    beforeEach(function () {
      const leafHashes = [sha256hex('k1'), sha256hex('k2'), sha256hex('k3')];
      checkpoint = createCheckpoint(
        {
          source_id: 'key-test-source',
          start_sequence: 1,
          end_sequence: 3,
          leaf_hashes: leafHashes,
        },
        keyManager
      );
    });

    it('1. Valid Ed25519 signature verifies successfully', function () {
      const res = verifyCheckpoint(checkpoint, keyManager);
      expect(res.valid).to.equal(true);
      expect(res.status).to.equal(VerificationStatus.VERIFIED);
    });

    it('2. Modifying any field after signing invalidates the digital signature', function () {
      checkpoint.message = 'Tampering with signed document';
      checkpoint.end_sequence = 4; // Altered sequence
      checkpoint.event_count = 4;

      const res = verifyCheckpoint(checkpoint, keyManager);
      expect(res.valid).to.equal(false);
    });

    it('3. Modified signature bytes fail verification with INVALID_SIGNATURE', function () {
      const sigBuf = Buffer.from(checkpoint.signature, 'hex');
      sigBuf[0] ^= 0x01; // Flip bit
      checkpoint.signature = sigBuf.toString('hex');

      const res = verifyCheckpoint(checkpoint, keyManager);
      expect(res.valid).to.equal(false);
      expect(res.status).to.equal(VerificationStatus.INVALID_SIGNATURE);
    });

    it('4. Untrusted public key supplied by untrusted checkpoint is rejected', function () {
      // Attacker replaces signing_key_id with unknown key ID
      checkpoint.signing_key_id = '00000000-0000-0000-0000-000000000000';

      const res = verifyCheckpoint(checkpoint, keyManager);
      expect(res.valid).to.equal(false);
      expect(res.status).to.equal(VerificationStatus.UNKNOWN_SIGNING_KEY);
      expect(res.failures.some((f) => f.includes('not found in KeyManager active key or registry'))).to.equal(true);
    });

    it('5. Missing signature field is rejected with INVALID_CHECKPOINT', function () {
      delete checkpoint.signature;

      const res = verifyCheckpoint(checkpoint, keyManager);
      expect(res.valid).to.equal(false);
      expect(res.status).to.equal(VerificationStatus.INVALID_CHECKPOINT);
    });

    it('6. Malformed signature string (invalid hex/length) is rejected', function () {
      checkpoint.signature = 'not-valid-hex-length';

      const res = verifyCheckpoint(checkpoint, keyManager);
      expect(res.valid).to.equal(false);
      expect(res.status).to.equal(VerificationStatus.INVALID_SIGNATURE);
    });

    it('7. Key rotation archives old public key and preserves historical verification', async function () {
      const oldKeyId = keyManager.keyId;
      const oldPubKey = keyManager.publicKeyHex;

      // Rotate key
      const rotationResult = await keyManager.rotateKey('new-passphrase-2026');
      expect(rotationResult.newKeyId).to.not.equal(oldKeyId);
      expect(keyManager.keyId).to.equal(rotationResult.newKeyId);

      // Verify that old checkpoint signed with old key remains verifiable via registry
      const historicalRes = verifyCheckpoint(checkpoint, keyManager);
      expect(historicalRes.valid).to.equal(true);
      expect(historicalRes.status).to.equal(VerificationStatus.VERIFIED);
    });

    it('8. Incorrect passphrase rejects loading encrypted private key', async function () {
      const separateDir = mkdtempSync(join(tmpdir(), 'securelog-pass-test-'));
      try {
        const km = new KeyManager(separateDir);
        await km.loadOrGenerate('correct-passphrase');

        const reloadKm = new KeyManager(separateDir);
        let err = null;
        try {
          await reloadKm.loadOrGenerate('wrong-passphrase');
        } catch (e) {
          err = e;
        }

        expect(err).to.not.equal(null);
        expect(err.message).to.include('decryption failed');
      } finally {
        rmSync(separateDir, { recursive: true, force: true });
      }
    });

    it('9. Corrupted key file is detected and rejected on reload', async function () {
      const separateDir = mkdtempSync(join(tmpdir(), 'securelog-corrupt-test-'));
      try {
        const km = new KeyManager(separateDir);
        await km.loadOrGenerate('passphrase');

        // Corrupt signing_key.enc
        const encPath = join(separateDir, 'signing_key.enc');
        writeFileSync(encPath, 'CORRUPTED NON JSON CONTENT');

        const reloadKm = new KeyManager(separateDir);
        let err = null;
        try {
          await reloadKm.loadOrGenerate('passphrase');
        } catch (e) {
          err = e;
        }

        expect(err).to.not.equal(null);
      } finally {
        rmSync(separateDir, { recursive: true, force: true });
      }
    });

    it('10. Encrypted key file permissions are restricted to owner-only mode 0600 on POSIX', function () {
      if (process.platform === 'win32') {
        this.skip();
      }
      const encPath = join(tempKeysDir, 'signing_key.enc');
      const stats = statSync(encPath);
      // 0600 octal = 384 decimal (or mode & 0777 == 0600)
      const mode = stats.mode & 0o777;
      expect(mode).to.equal(0o600);
    });
  });

  // ─── 4D: Blockchain Attack Simulations ─────────────────────────────────────
  describe('D. Blockchain Attack Simulations', function () {
    let checkpoint;

    beforeEach(function () {
      checkpoint = createCheckpoint(
        {
          source_id: 'bc-test',
          start_sequence: 1,
          end_sequence: 4,
          leaf_hashes: [sha256hex('1'), sha256hex('2'), sha256hex('3'), sha256hex('4')],
        },
        keyManager
      );
    });

    it('1. Successfully anchors a valid checkpoint commitment', async function () {
      const res = await adapter.anchorCheckpointForBackend(checkpoint);
      expect(res.success).to.equal(true);
      expect(res.blockNumber).to.be.greaterThan(0);
    });

    it('2. Duplicate checkpoint ID is strictly rejected with DUPLICATE error', async function () {
      await adapter.anchorCheckpointForBackend(checkpoint);

      let err = null;
      try {
        await adapter.anchorCheckpointForBackend(checkpoint);
      } catch (e) {
        err = e;
      }

      expect(err).to.be.instanceOf(BlockchainError);
      expect(err.code).to.equal(BlockchainErrorCode.DUPLICATE);
    });

    it('3. Zero checkpoint ID is rejected by contract validation', async function () {
      let err = null;
      try {
        await blockchainService.anchorCheckpoint({
          checkpointId: ethers.ZeroHash,
          merkleRoot: checkpoint.merkle_root,
          startSequence: 1,
          endSequence: 1,
          eventCount: 1,
          timestamp: 1700000000,
        });
      } catch (e) {
        err = e;
      }

      expect(err).to.be.instanceOf(BlockchainError);
      expect(err.code).to.equal(BlockchainErrorCode.REVERT);
    });

    it('4. Zero Merkle root is rejected by contract validation', async function () {
      let err = null;
      try {
        await blockchainService.anchorCheckpoint({
          checkpointId: checkpoint.checkpoint_id,
          merkleRoot: ethers.ZeroHash,
          startSequence: 1,
          endSequence: 1,
          eventCount: 1,
          timestamp: 1700000000,
        });
      } catch (e) {
        err = e;
      }

      expect(err).to.be.instanceOf(BlockchainError);
      expect(err.code).to.equal(BlockchainErrorCode.REVERT);
    });

    it('5. Invalid sequence range (startSequence = 0) is rejected', async function () {
      let err = null;
      try {
        await blockchainService.anchorCheckpoint({
          checkpointId: checkpoint.checkpoint_id,
          merkleRoot: checkpoint.merkle_root,
          startSequence: 0,
          endSequence: 5,
          eventCount: 6,
          timestamp: 1700000000,
        });
      } catch (e) {
        err = e;
      }

      expect(err).to.be.instanceOf(BlockchainError);
    });

    it('6. Invalid sequence range (endSequence < startSequence) is rejected', async function () {
      let err = null;
      try {
        await blockchainService.anchorCheckpoint({
          checkpointId: checkpoint.checkpoint_id,
          merkleRoot: checkpoint.merkle_root,
          startSequence: 10,
          endSequence: 5,
          eventCount: 1,
          timestamp: 1700000000,
        });
      } catch (e) {
        err = e;
      }

      expect(err).to.be.instanceOf(BlockchainError);
      expect(err.code).to.equal(BlockchainErrorCode.INVALID_CHECKPOINT);
    });

    it('7. Inconsistent event count is rejected', async function () {
      let err = null;
      try {
        await blockchainService.anchorCheckpoint({
          checkpointId: checkpoint.checkpoint_id,
          merkleRoot: checkpoint.merkle_root,
          startSequence: 1,
          endSequence: 10,
          eventCount: 5, // Requires 10
          timestamp: 1700000000,
        });
      } catch (e) {
        err = e;
      }

      expect(err).to.be.instanceOf(BlockchainError);
      expect(err.code).to.equal(BlockchainErrorCode.INVALID_CHECKPOINT);
    });

    it('8. Unauthorized submitter account is rejected with UNAUTHORIZED / REVERT', async function () {
      const attackerService = new BlockchainService({
        provider: ethers.provider,
        signer: attacker,
        contractAddress,
        chainId: 31337,
      });
      await attackerService.init();

      let err = null;
      try {
        await attackerService.anchorCheckpoint({
          checkpointId: checkpoint.checkpoint_id,
          merkleRoot: checkpoint.merkle_root,
          startSequence: 1,
          endSequence: 4,
          eventCount: 4,
          timestamp: 1700000000,
        });
      } catch (e) {
        err = e;
      }

      expect(err).to.be.instanceOf(BlockchainError);
      expect([BlockchainErrorCode.UNAUTHORIZED, BlockchainErrorCode.REVERT]).to.include(err.code);
    });

    it('9. Revoked submitter cannot continue anchoring', async function () {
      // Revoke submitter
      await (await anchorContract.connect(owner).setSubmitter(submitter.address, false)).wait();

      let err = null;
      try {
        await adapter.anchorCheckpointForBackend(checkpoint);
      } catch (e) {
        err = e;
      }

      expect(err).to.be.instanceOf(BlockchainError);
      expect([BlockchainErrorCode.UNAUTHORIZED, BlockchainErrorCode.REVERT]).to.include(err.code);
    });

    it('10. Altered Merkle root returns match: false on verification', async function () {
      await adapter.anchorCheckpointForBackend(checkpoint);

      // Verify against fake root
      const fakeRoot = sha256hex('fake-root');
      const verifyRes = await blockchainService.verifyOnChain(checkpoint.checkpoint_id, fakeRoot);
      expect(verifyRes.match).to.equal(false);
      expect(verifyRes.onChainRoot).to.equal('0x' + checkpoint.merkle_root);
    });

    it('11. Querying non-existent checkpoint ID throws NOT_FOUND', async function () {
      let err = null;
      try {
        await blockchainService.getCommitment('non-existent-uuid-999');
      } catch (e) {
        err = e;
      }

      expect(err).to.be.instanceOf(BlockchainError);
      expect(err.code).to.equal(BlockchainErrorCode.NOT_FOUND);
    });
  });

  // ─── 4E: Blockchain Failure & Recovery Simulations ─────────────────────────
  describe('E. Blockchain Failure and Recovery', function () {
    it('1. RPC endpoint failure maps to BlockchainErrorCode.NETWORK', async function () {
      const deadProvider = {
        getNetwork: async () => {
          throw new Error('connect ECONNREFUSED 127.0.0.1:9999');
        },
      };

      const badService = new BlockchainService({
        provider: deadProvider,
        contractAddress,
        chainId: 31337,
      });

      let err = null;
      try {
        await badService.init();
      } catch (e) {
        err = e;
      }

      expect(err).to.be.instanceOf(BlockchainError);
      expect(err.code).to.equal(BlockchainErrorCode.NETWORK);
    });

    it('2. Missing deployed bytecode maps to BlockchainErrorCode.CONTRACT_NOT_FOUND', async function () {
      const randomWallet = ethers.Wallet.createRandom();
      const emptyService = new BlockchainService({
        provider: ethers.provider,
        contractAddress: randomWallet.address,
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

    it('3. Idempotent safeRetryAnchor recovers confirmed commitment without sending new transaction', async function () {
      const checkpoint = createCheckpoint(
        {
          source_id: 'retry-test',
          start_sequence: 10,
          end_sequence: 12,
          leaf_hashes: [sha256hex('r1'), sha256hex('r2'), sha256hex('r3')],
        },
        keyManager
      );

      // Initial anchor succeeds
      const initial = await adapter.anchorCheckpointForBackend(checkpoint);
      expect(initial.success).to.equal(true);

      // Simulate network crash where backend retries
      const retryResult = await adapter.safeRetryAnchor(checkpoint);
      expect(retryResult.success).to.equal(true);
      expect(retryResult.alreadyAnchored).to.equal(true);
      expect(retryResult.blockNumber).to.equal(initial.blockNumber);
    });
  });
});
