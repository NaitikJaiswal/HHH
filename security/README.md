# HHH SecureLog — Security & Cryptography Module

> **Phase 1: Core Cryptographic Primitives — COMPLETE**  
> **Phase 2: Merkle Tree, Ed25519 Key Management & Signed Checkpoints — COMPLETE**  
> **Phase 3A: SecureLogAnchor Smart Contract Foundation — COMPLETE**  
> **Phase 3B: BlockchainService (ethers.js v6) — COMPLETE**  
> **Phase 4A: Backend Integration Adapter & Forensic Verification — COMPLETE**  

---

## 1. Purpose

This module owns the **Security + Blockchain** responsibilities for **HHH (Hash. Hunt. Harden.) / SecureLog**, a blockchain-powered tamper-evident digital forensics platform.

- **Phase 1** established the canonical hashing and per-event hash chain layer (`LOGN-HASH-v1`).
- **Phase 2** established the Merkle tree engine, persistent encrypted Ed25519 key management, signed checkpoint generation, and independent forensic verification.
- **Phase 3A** implemented the EVM smart contract `SecureLogAnchor.sol` and isolated Hardhat environment.
- **Phase 3B** implemented the `BlockchainService` client using ethers.js v6 to submit, retrieve, and verify on-chain commitments.
- **Phase 4A** implemented the `BackendAdapter` providing high-level anchoring, status inspection, dual verification, and idempotent retry recovery for the Backend module.

---

## 2. Module Status & Test Coverage

| Phase | Capability | Implementation File | Status |
|-------|-----------|---------------------|--------|
| **1** | Canonical JSON serialization (LOGN-HASH-v1) | `src/crypto/canonicalJson.js` | ✅ Complete |
| **1** | SHA-256 hashing (`sha256hex`, `hashLogEvent`) | `src/crypto/hashing.js` | ✅ Complete |
| **1** | Hash chain construction (`buildChain`) | `src/crypto/hashChain.js` | ✅ Complete |
| **1** | Hash chain verification (`verifyHashChain`) | `src/crypto/hashChain.js` | ✅ Complete |
| **2** | Merkle tree construction and inclusion proofs | `src/merkle/merkleTree.js` | ✅ Complete |
| **2** | Ed25519 key management & AES-256-GCM storage | `src/keys/keyManager.js` | ✅ Complete |
| **2** | Key rotation with historical public key registry | `src/keys/keyManager.js` | ✅ Complete |
| **2** | Signed checkpoint creation (`createCheckpoint`) | `src/checkpoints/checkpointService.js` | ✅ Complete |
| **2** | Forensic verification engine (`verifyCheckpoint`) | `src/verification/verifier.js` | ✅ Complete |
| **3A**| Solidity `SecureLogAnchor` smart contract | `contracts/SecureLogAnchor.sol` | ✅ Complete |
| **3B**| ethers.js v6 `BlockchainService` | `src/blockchain/blockchainService.js` | ✅ Complete |
| **3B**| Checkpoint blockchain connection (`anchorSignedCheckpoint`)| `src/checkpoints/checkpointService.js` | ✅ Complete |
| **4A**| Backend Integration Adapter (`BackendAdapter`) | `src/adapter/backendAdapter.js` | ✅ Complete |
| **4A**| Dual Off-Chain + On-Chain Verification | `src/verification/verifier.js` | ✅ Complete |

Current Test Baseline: **113 tests pass, 0 fail**.
- **65** Node.js unit tests (Phase 1 & 2)
- **48** Hardhat Mocha tests (Phase 3A, 3B, 4A)

---

## 3. Environment Setup & Configuration

Copy `.env.example` to `.env` in the `security/` directory:

```bash
cp .env.example .env
```

### Environment Variables

| Variable | Description | Default (Local Hardhat) |
|----------|-------------|-------------------------|
| `RPC_URL` / `LOGN_RPC_URL` | EVM JSON-RPC provider URL | `http://127.0.0.1:8545` |
| `EXPECTED_CHAIN_ID` / `LOGN_CHAIN_ID` | Expected EVM network chain ID | `31337` (Hardhat local) |
| `CONTRACT_ADDRESS` / `LOGN_CONTRACT_ADDRESS` | Deployed `SecureLogAnchor` address | `0x5FbDB2315678afecb367f032d93F642f64180aa3` |
| `BLOCKCHAIN_PRIVATE_KEY` / `LOGN_SUBMITTER_PRIVATE_KEY` | Hex private key of authorized submitter | Hardhat Account #0 key |
| `LOGN_TX_TIMEOUT_SECONDS` | Transaction confirmation timeout | `60` seconds |
| `LOGN_KEY_PASSPHRASE` | Passphrase for encrypted Ed25519 key | (Required for keyManager) |

> [!CAUTION]
> Never commit real private keys, secrets, or passphrase files to Git. All private keys and `.env` files are ignored via `.gitignore`.

---

## 4. Local Blockchain & Contract Deployment

### A. Start Local Hardhat Node (Daemon)
In a dedicated terminal:

```bash
cd security
npx hardhat node
```

This starts a persistent local EVM node at `http://127.0.0.1:8545` with chain ID `31337`.

### B. Compile Smart Contracts
```bash
npm run compile
```

### C. Deploy SecureLogAnchor Locally
```bash
npm run deploy:local
```

Default deployed contract address: `0x5FbDB2315678afecb367f032d93F642f64180aa3`.

---

## 5. Running Automated Tests

Run the complete test suite (Unit + Contracts + Blockchain Service + Adapter):

```bash
cd security
npm run test:all
```

Or run targeted test suites:

```bash
# Phase 1 & Phase 2 Node.js tests (65 tests)
npm test

# Phase 3 & Phase 4 Hardhat tests (48 tests)
npm run test:contracts
```

---

## 6. Architecture & Integration Workflows

### A. Checkpoint Anchoring Workflow
1. **Receive Checkpoint**: Backend receives or triggers a window of log events.
2. **Off-Chain Verification**: Checkpoint structure and Ed25519 signature are verified using `verifyCheckpoint`.
3. **Parameter Extraction**: `checkpoint_id`, `merkle_root`, sequence range `[start, end]`, `event_count`, and `timestamp` are parsed.
4. **On-Chain Commitment**: `BlockchainService.anchorCheckpoint` estimates gas and broadcasts `anchorCheckpoint` to `SecureLogAnchor`.
5. **Confirmation**: Awaits 1 confirmation and verifies `receipt.status === 1`.
6. **Metadata Attachment**: Checkpoint document is enriched with `checkpoint.blockchain` metadata (`txHash`, `blockNumber`, `contractAddress`, `chainId`, `anchoredAt`, `gasUsed`).
7. **Post-Anchor Sanity Check**: Directly queries `getCommitment` from the contract to verify that the recorded on-chain root matches the local checkpoint.

### B. Dual Verification Workflow
Forensic auditors verify tamper evidence through dual verification:
1. **Off-Chain Verification**:
   - Rebuilds Merkle tree from `checkpoint.merkle_leaf_hashes`.
   - Recomputes root and checks against `checkpoint.merkle_root`.
   - Canonicalizes signing payload and verifies Ed25519 digital signature.
2. **On-Chain Verification**:
   - Calls `SecureLogAnchor.verifyCommitment(checkpointId, expectedMerkleRoot)`.
   - Confirms that the cryptographic commitment on-chain matches the local root and was recorded at or before the claimed block.
3. **Structured Report**:
   - Returns a `VerificationReport` conforming to `docs/technical-integration-contract.md` §9.5.

---

## 7. Backend Integration Adapter Usage

The Backend team integrates with the Security module via `security/src/adapter/backendAdapter.js`:

```javascript
import { createBackendAdapter, BlockchainService } from '@hhh/security';

// 1. Initialize BlockchainService
const blockchainService = new BlockchainService({
  rpcUrl: process.env.RPC_URL,
  chainId: 31337,
  contractAddress: process.env.CONTRACT_ADDRESS,
  submitterKey: process.env.BLOCKCHAIN_PRIVATE_KEY,
});
await blockchainService.init();

// 2. Create Adapter instance
const adapter = createBackendAdapter({ blockchainService, keyManager });

// 3. Anchor a checkpoint
const result = await adapter.anchorCheckpointForBackend(checkpoint);
console.log(`Anchored tx: ${result.txHash} in block ${result.blockNumber}`);

// 4. Query anchoring status
const status = await adapter.getAnchoringStatus(checkpoint.checkpoint_id);
console.log(`Is anchored: ${status.anchored}, On-chain root: ${status.onChainRoot}`);

// 5. Dual verification
const report = await adapter.verifyCheckpointOnChain(checkpoint);
console.log(`Verification overallValid: ${report.overallValid}`);

// 6. Safe idempotent retry (safe against network timeouts and process crashes)
const retryResult = await adapter.safeRetryAnchor(checkpoint);
if (retryResult.alreadyAnchored) {
  console.log(`Checkpoint was already anchored at block ${retryResult.blockNumber}`);
}
```

---

## 8. Failure Handling & Error Codes

All errors are normalized into `BlockchainError` with structured codes (`BlockchainErrorCode`):

| Error Code | Trigger Condition | Recommended Recovery |
|------------|-------------------|----------------------|
| `NETWORK` | RPC unreachable, timeout, or DNS failure | Check node daemon, retry network connection |
| `CHAIN_ID` | RPC connected to unexpected chain ID | Verify network configuration |
| `CONTRACT_NOT_FOUND` | No contract code at target address | Deploy contract or update `CONTRACT_ADDRESS` |
| `INVALID_ADDRESS` | Malformed address format | Correct address format |
| `INSUFFICIENT_FUNDS` | Submitter account has zero/insufficient ETH | Fund the submitter account |
| `INVALID_CHECKPOINT` | Corrupt or invalid sequence range / count | Review log window inputs |
| `INVALID_SIGNATURE` | Checkpoint signature check failed | Re-sign with active key |
| `DUPLICATE` | Checkpoint ID already anchored on-chain | Idempotency guard; use `safeRetryAnchor` |
| `UNAUTHORIZED` | Submitter not in `authorizedSubmitters` | Call `setSubmitter(addr, true)` as contract owner |
| `TIMEOUT` | Transaction not mined within timeout window | Check gas price or call `safeRetryAnchor` |
| `NOT_FOUND` | `getCommitment` called for unanchored ID | Check checkpoint ID or anchor first |
| `MERKLE_MISMATCH` | On-chain root does not match checkpoint root | Evidence tampering alert |

---

## 9. Directory Structure

```
security/
├── src/
│   ├── crypto/
│   │   ├── canonicalJson.js     ← LOGN-HASH-v1 deterministic serializer
│   │   ├── hashing.js           ← SHA-256, hashLogEvent, GENESIS_HASH
│   │   └── hashChain.js         ← buildChain, verifyHashChain
│   ├── merkle/
│   │   └── merkleTree.js        ← buildMerkleTree, proofs, domain separation
│   ├── keys/
│   │   └── keyManager.js        ← Ed25519 key lifecycle, AES-GCM at rest, rotation
│   ├── checkpoints/
│   │   └── checkpointService.js ← createCheckpoint, verifyCheckpoint, anchorSignedCheckpoint
│   ├── verification/
│   │   └── verifier.js          ← Unified off-chain & on-chain verification engine
│   ├── blockchain/
│   │   ├── blockchainService.js ← ethers.js v6 client for SecureLogAnchor
│   │   ├── contractAbi.js       ← Contract ABI and parameter formatters
│   │   └── errors.js            ← Structured BlockchainError and BlockchainErrorCode
│   ├── adapter/
│   │   └── backendAdapter.js    ← Backend integration adapter (safe retry, dual verify)
│   └── index.js                 ← Unified module entrypoint
├── contracts/
│   └── SecureLogAnchor.sol      ← Solidity smart contract & ISecureLogAnchor interface
├── blockchain/
│   ├── hardhat.config.js        ← Hardhat 3 configuration (Solidity 0.8.20, EVM shanghai)
│   └── scripts/
│       └── deploy.js            ← Contract deployment script
├── test/
│   ├── SecureLogAnchor.test.js  ← 22 smart contract unit tests
│   ├── BlockchainService.test.js← 16 blockchain client integration tests
│   └── BackendAdapter.test.js   ← 10 backend adapter tests
├── tests/
│   ├── canonicalJson.test.js    ← 13 serializer tests
│   ├── hashing.test.js          ← 11 hashing tests
│   ├── hashChain.test.js        ← 10 chain tests
│   ├── merkleTree.test.js       ← 11 Merkle tree tests
│   ├── keyManager.test.js       ← 9 key management tests
│   ├── checkpointService.test.js← 8 checkpoint tests
│   └── verifier.test.js         ← 3 comprehensive verification tests
├── docs/
├── .env.example                 ← Clean environment variable template
├── .gitignore
├── package.json
└── README.md
```
