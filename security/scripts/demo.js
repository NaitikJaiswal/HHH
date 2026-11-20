/**
 * @file demo.js
 * @description Standalone runnable end-to-end demonstration script for HHH SecureLog.
 *
 * Demonstrates:
 *   - Scenario 1: Valid evidence pipeline (logs -> hash chain -> Merkle tree -> signed checkpoint -> EVM anchor -> dual verification)
 *   - Scenario 2: Tampered evidence detection (forensic analysis of altered log event & broken commitment)
 *
 * Usage:
 *   npx hardhat run scripts/demo.js --config blockchain/hardhat.config.js
 *   or:
 *   npm run demo
 */

import { network } from 'hardhat';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

// Core Cryptographic & Security Modules
import { buildChain, verifyHashChain } from '../src/crypto/hashChain.js';
import {
  buildMerkleTree,
  getMerkleRoot,
  generateMerkleProof,
  verifyMerkleProof,
} from '../src/merkle/merkleTree.js';
import { KeyManager } from '../src/keys/keyManager.js';
import { createCheckpoint } from '../src/checkpoints/checkpointService.js';
import { BlockchainService } from '../src/blockchain/blockchainService.js';
import { createBackendAdapter } from '../src/adapter/backendAdapter.js';

const { ethers } = await network.create();

async function runDemo() {
  console.log('='.repeat(78));
  console.log('       HHH SecureLog — Tamper-Evident Security Logging Demonstration');
  console.log('='.repeat(78));
  console.log('Cryptographic Primitives: SHA-256 | LOGN-HASH-v1 | Ed25519 | EVM Smart Contract');
  console.log(`Execution Environment: Node.js ${process.version} | Local Hardhat EVM (31337)`);
  console.log('-'.repeat(78));

  // Setup local keys and deploy contract
  const tempDir = mkdtempSync(join(tmpdir(), 'securelog-demo-keys-'));
  try {
    const [deployer, submitter] = await ethers.getSigners();
    console.log(`\n[+] Deploying SecureLogAnchor to local EVM...`);
    const anchorContract = await ethers.deployContract('SecureLogAnchor');
    await anchorContract.waitForDeployment();
    const contractAddress = await anchorContract.getAddress();
    console.log(`    Contract Address: ${contractAddress}`);

    // Authorize submitter
    await (await anchorContract.connect(deployer).setSubmitter(submitter.address, true)).wait();
    console.log(`    Authorized Submitter: ${submitter.address}`);

    // Initialize services
    const km = new KeyManager(tempDir);
    await km.loadOrGenerate('demo-secure-passphrase-2026');
    console.log(`[+] Initialized Ed25519 KeyManager. Active Key ID: ${km.keyId}`);
    console.log(`    Signer Public Key: ${km.publicKeyHex.slice(0, 32)}...`);

    const blockchainService = new BlockchainService({
      provider: ethers.provider,
      signer: submitter,
      contractAddress,
      chainId: 31337,
    });
    await blockchainService.init();

    const adapter = createBackendAdapter({
      blockchainService,
      keyManager: km,
    });

    // ──────────────────────────────────────────────────────────────────────────
    // SCENARIO 1: Valid Evidence Pipeline
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n' + '='.repeat(78));
    console.log('  SCENARIO 1: Valid Evidence Ingestion, Anchoring & Dual Verification');
    console.log('='.repeat(78));

    // Step 1: Synthetic security logs
    const rawEvents = [
      {
        event_id: 'evt-001-uuid',
        event_time: '2026-11-20T10:00:00Z',
        event_type: 'AUTH_SUCCESS',
        message: 'Security analyst alice authenticated via WebAuthn MFA',
        metadata: { user: 'alice', ip: '10.0.4.15', role: 'FORENSIC_ANALYST' },
        sequence_number: 1,
        severity: 'INFO',
        source_id: 'sec-ops-node-01',
      },
      {
        event_id: 'evt-002-uuid',
        event_time: '2026-11-20T10:00:10Z',
        event_type: 'VAULT_ACCESS',
        message: 'Alice accessed evidence locker vault: case/2026-904',
        metadata: { case_id: '2026-904', action: 'READ' },
        sequence_number: 2,
        severity: 'INFO',
        source_id: 'sec-ops-node-01',
      },
      {
        event_id: 'evt-003-uuid',
        event_time: '2026-11-20T10:00:25Z',
        event_type: 'EXPORT_ARTIFACT',
        message: 'Forensic memory dump exported for analysis: dump-002.raw',
        metadata: { file: 'dump-002.raw', size_bytes: 4294967 },
        sequence_number: 3,
        severity: 'INFO',
        source_id: 'sec-ops-node-01',
      },
    ];

    console.log(`\n1. Ingesting ${rawEvents.length} sequential security events...`);
    const chained = buildChain(rawEvents);
    console.log(`   [✓] Built SHA-256 hash chain:`);
    chained.forEach((e) => {
      console.log(`       Seq #${e.sequence_number}: current_hash=${e.current_hash.slice(0, 16)}... prev=${e.previous_hash.slice(0, 16)}...`);
    });

    const chainValid = verifyHashChain(chained);
    console.log(`   [✓] Hash chain integrity check: ${chainValid.valid ? 'PASSED (Zero breaks)' : 'FAILED'}`);

    // Step 2: Build Merkle Tree & Sign Checkpoint
    console.log('\n2. Building domain-separated Merkle Tree & signing Checkpoint...');
    const leafHashes = chained.map((e) => e.current_hash);
    const tree = buildMerkleTree(leafHashes);
    const merkleRoot = getMerkleRoot(tree);
    console.log(`   [✓] Merkle Root computed: ${merkleRoot}`);

    const checkpoint = createCheckpoint(
      {
        source_id: 'sec-ops-node-01',
        start_sequence: 1,
        end_sequence: 3,
        leaf_hashes: leafHashes,
      },
      km
    );
    console.log(`   [✓] Checkpoint created: ID=${checkpoint.checkpoint_id}`);
    console.log(`   [✓] Ed25519 digital signature: ${checkpoint.signature.slice(0, 32)}...`);

    // Step 3: Merkle inclusion proof
    console.log('\n3. Generating Merkle Inclusion Proof for Event #2...');
    const proof = generateMerkleProof(tree, 1);
    const proofOk = verifyMerkleProof(leafHashes[1], proof.proof, merkleRoot);
    console.log(`   [✓] Merkle inclusion proof verification: ${proofOk ? 'VERIFIED' : 'FAILED'}`);
    console.log(`       Proof length: ${proof.proof.length} sibling nodes`);

    // Step 4: Blockchain Anchoring
    console.log('\n4. Anchoring Checkpoint Commitment to Smart Contract...');
    const anchorRes = await adapter.anchorCheckpointForBackend(checkpoint);
    console.log(`   [✓] Checkpoint Anchored on EVM!`);
    console.log(`       Transaction Hash: ${anchorRes.txHash}`);
    console.log(`       Block Number:     ${anchorRes.blockNumber}`);
    console.log(`       Gas Units Used:   ${anchorRes.gasUsed}`);

    // Step 5: Verification Report
    console.log('\n5. Performing Dual Verification (Off-Chain + On-Chain)...');
    const validReport = await adapter.verifyCheckpointOnChain(checkpoint);
    console.log(`\n${'─'.repeat(50)}`);
    console.log('       FORENSIC AUDIT REPORT (SCENARIO 1)');
    console.log(`${'─'.repeat(50)}`);
    console.log(`Checkpoint ID:         ${validReport.checkpointId}`);
    console.log(`Source Node:           ${validReport.sourceId}`);
    console.log(`Sequence Window:       [${validReport.sequenceRange.start} .. ${validReport.sequenceRange.end}]`);
    console.log(`Off-Chain Merkle Root: ${validReport.storedRoot}`);
    console.log(`On-Chain Merkle Root:  ${validReport.onChainRoot}`);
    console.log(`On-Chain Block Number: ${validReport.onChainBlockNumber}`);
    console.log(`Off-Chain Signature:   ${validReport.signatureValid ? 'VALID (Ed25519 Verified)' : 'INVALID'}`);
    console.log(`On-Chain Status:       ${validReport.onChainStatus}`);
    console.log(`Key Provenance:        ${validReport.keyRegistered ? 'REGISTERED & TRUSTED' : 'UNKNOWN'}`);
    console.log(`OVERALL VALIDITY:      ${validReport.overallValid ? '✅ VERIFIED (Tamper-evident record intact)' : '❌ TAMPERED'}`);
    console.log(`${'─'.repeat(50)}`);

    // ──────────────────────────────────────────────────────────────────────────
    // SCENARIO 2: Tampered Evidence Detection
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n' + '='.repeat(78));
    console.log('  SCENARIO 2: Adversarial Attack & Tamper Detection');
    console.log('='.repeat(78));
    console.log('Simulating a rogue insider with direct database write access:');
    console.log(' - Attack: Altering Event #2 message to conceal evidence export');
    console.log(' - Original: "Alice accessed evidence locker vault: case/2026-904"');
    console.log(' - Tampered: "Alice performed routine heartbeat ping"');

    // Clone checkpoint and tamper with one leaf hash
    const tamperedCheckpoint = JSON.parse(JSON.stringify(checkpoint));
    const tamperedEvents = JSON.parse(JSON.stringify(chained));

    tamperedEvents[1].message = 'Alice performed routine heartbeat ping';

    console.log('\n1. Forensic Analysis: Hash Chain Verification...');
    const tamperedChainRes = verifyHashChain(tamperedEvents);
    console.log(`   [!] Hash chain validation result: ${tamperedChainRes.valid ? 'VALID' : '❌ CORRUPT / TAMPERED'}`);
    tamperedChainRes.errors.forEach((err) => {
      console.log(`       Anomaly detected: Sequence #${err.sequenceNumber} (index ${err.index}): ${err.reason}`);
    });

    console.log('\n2. Forensic Analysis: Merkle Tree Re-derivation against On-Chain Anchor...');
    // Replace leaf hash in checkpoint to simulate database modification
    tamperedCheckpoint.merkle_leaf_hashes[1] = '0'.repeat(64);

    const tamperedReport = await adapter.verifyCheckpointOnChain(tamperedCheckpoint);
    console.log(`\n${'─'.repeat(50)}`);
    console.log('       FORENSIC AUDIT REPORT (SCENARIO 2)');
    console.log(`${'─'.repeat(50)}`);
    console.log(`Checkpoint ID:         ${tamperedReport.checkpointId}`);
    console.log(`Stored Merkle Root:    ${tamperedReport.storedRoot}`);
    console.log(`Recomputed Root:       ${tamperedReport.recomputedRoot}`);
    console.log(`On-Chain Root:         ${tamperedReport.onChainRoot}`);
    console.log(`Signature Valid:       ${tamperedReport.signatureValid ? 'VALID' : 'INVALID'}`);
    console.log(`Merkle Root Match:     ${tamperedReport.merkleRootMatch ? 'MATCH' : '❌ MISMATCH'}`);
    console.log(`OVERALL VALIDITY:      ${tamperedReport.overallValid ? 'VERIFIED' : '❌ TAMPERED / EVIDENCE REJECTED'}`);
    console.log(`Detected Anomalies:`);
    tamperedReport.errors.forEach((err) => {
      console.log(`  - 🚨 ${err}`);
    });
    console.log(`${'─'.repeat(50)}`);

    console.log('\n3. Core Forensics Principle Demonstrated:');
    console.log('   - The attacker successfully modified the MongoDB database log records.');
    console.log('   - HOWEVER, because the Merkle root was immutably committed on the blockchain');
    console.log('     and the checkpoint was signed with Ed25519, the retroactive modification');
    console.log('     was mathematically and cryptographically provable.');
    console.log('   - Zero raw logs or private data were ever exposed on-chain.\n');
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }

  console.log('='.repeat(78));
  console.log('  Demonstration Completed Successfully.');
  console.log('='.repeat(78));
}

runDemo()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error('Demo error:', err);
    process.exit(1);
  });
