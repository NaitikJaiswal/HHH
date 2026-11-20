# Operational Runbook: Security + Blockchain Module

> **HHH (Hash. Hunt. Harden.) — SecureLog Forensic Platform**  
> **Module:** Security & Blockchain  
> **Reference Contract:** `docs/technical-integration-contract.md`

---

## 1. System Overview & Prerequisites

The Security module provides cryptographic guarantees of immutability, tamper evidence, and non-repudiation for log streams. It produces canonical hashes, constructs sequential hash chains, builds Merkle trees, signs periodic checkpoints using Ed25519, and anchors checkpoint commitments into the `SecureLogAnchor` EVM smart contract.

### Prerequisites
- **Node.js**: v18.0.0 or higher (v20+ recommended)
- **npm**: v9.0.0 or higher
- **POSIX-compliant environment**: macOS or Linux (enforces `0600` file permissions on encrypted private key files)
- **Local EVM Node or RPC Endpoint**: Hardhat network, Ganache, or an external Ethereum/EVM RPC provider.

---

## 2. Configuration & Environment Variables

All configuration is governed via environment variables. For local development, copy the provided template:

```bash
cd security
cp .env.example .env
```

### Configuration Parameters

| Variable | Required | Default | Description |
|---|---|---|---|
| `LOGN_RPC_URL` / `RPC_URL` | Yes | `http://127.0.0.1:8545` | JSON-RPC provider URL for the EVM blockchain |
| `LOGN_CHAIN_ID` / `EXPECTED_CHAIN_ID` | Yes | `31337` | Network chain ID (Hardhat = 31337, Sepolia = 11155111) |
| `LOGN_CONTRACT_ADDRESS` / `CONTRACT_ADDRESS` | Yes | `0x5FbDB2315678afecb367f032d93F642f64180aa3` | Deployed address of `SecureLogAnchor` |
| `LOGN_SUBMITTER_PRIVATE_KEY` / `BLOCKCHAIN_PRIVATE_KEY` | Yes | *(Hardhat Account #0)* | Secp256k1 private key of the authorized submitter wallet |
| `LOGN_TX_TIMEOUT_SECONDS` | No | `60` | Max seconds to await transaction inclusion before timeout |
| `LOGN_KEY_PASSPHRASE` | Yes | — | Secret passphrase used to derive AES-256-GCM key for Ed25519 |
| `LOGN_KEYS_DIR` | No | `./keys` | Local directory for storing encrypted Ed25519 keys and registry |

> [!CAUTION]
> **Production Key Security**: Never store raw unencrypted private keys in configuration files or code repositories. Ensure `.env` is listed in `.gitignore` and never committed.

---

## 3. Local Blockchain Lifecycle

### 3.1 Start Local Node
Run a dedicated local Hardhat node in a background process or terminal tab:

```bash
cd security
npx hardhat node
```
This initializes a local node listening on `127.0.0.1:8545` with 20 pre-funded test accounts (10,000 ETH each).

### 3.2 Compile Smart Contracts
Compile the Solidity contracts and verify bytecode and ABI generation:

```bash
npm run compile
```
Artifacts are emitted to `security/artifacts/contracts/SecureLogAnchor.sol/SecureLogAnchor.json`.

### 3.3 Deploy `SecureLogAnchor`
Deploy the contract to the running node:

```bash
npm run deploy:local
```
This runs `scripts/deploy.js`, deploys `SecureLogAnchor`, registers the deployer in `authorizedSubmitters`, and outputs the contract address. Ensure this address matches `CONTRACT_ADDRESS` in `.env`.

---

## 4. Key Management Operations

The Security module uses **Ed25519** for checkpoint signatures. The private key is encrypted at rest using **AES-256-GCM** with a key derived via **scrypt**.

### 4.1 Key Generation
When the security service starts, `KeyManager.loadOrGenerate(passphrase)` checks `keys/ed25519-private.enc`:
- If missing, it generates a fresh Ed25519 keypair.
- It encrypts the private key with AES-256-GCM using `passphrase`.
- It writes the encrypted key to disk with strict `0600` POSIX permissions.
- It registers the corresponding public key in `keys/public-key-registry.json`.

### 4.2 Key Rotation Workflow
To rotate the signing key while maintaining verification capability for older checkpoints:
1. Trigger key rotation programmatically or via administrative CLI:
   ```javascript
   const { KeyManager } = require('@hhh/security');
   const km = new KeyManager(process.env.LOGN_KEYS_DIR || './keys');
   const { newPublicKey, oldPublicKey } = await km.rotateKey(process.env.LOGN_KEY_PASSPHRASE);
   ```
2. The old public key is preserved in `public-key-registry.json` along with its activation and retirement timestamps.
3. Subsequent checkpoints are signed with `newPublicKey`.
4. Forensic verifiers will check `public-key-registry.json` or query the backend's key registry to confirm that the key was active when the checkpoint was created.

---

## 5. Checkpoint Anchoring Operations

Checkpoints are anchored by the Backend calling `BackendAdapter.anchorCheckpointForBackend(checkpoint)`:

```
[Backend] ───────────────────────► [BackendAdapter]
                                          │
                                          ▼
                                 verifyCheckpoint()
                                 (Off-chain sanity check)
                                          │
                                          ▼
                                 BlockchainService
                                 .anchorCheckpoint()
                                          │
                                          ▼
                                [EVM Smart Contract]
```

### 5.1 Anchoring Execution Steps
1. The checkpoint structure and Ed25519 signature are verified.
2. `checkpoint_id` (UUID v4) is converted to `bytes32`.
3. Merkle root (`0x` + 64 hex chars) is converted to `bytes32`.
4. Transaction parameters (`startSequence`, `endSequence`, `eventCount`, `timestamp`) are packed and broadcast.
5. Receipt is awaited (`receipt.status === 1`).
6. Contract commitment is re-verified via view call `getCommitment`.
7. Enriched metadata is returned to the Backend for MongoDB persistence.

---

## 6. Forensic Verification Operations

To audit evidence and verify that logs have not been tampered with:

### 6.1 Dual Verification (Recommended)
```javascript
const { createBackendAdapter } = require('@hhh/security');
const adapter = createBackendAdapter();
const report = await adapter.verifyCheckpointOnChain(checkpointDocument);

if (!report.overallValid) {
  console.error('Tampering detected:', report.errors);
} else {
  console.log('Checkpoint mathematically and cryptographically verified!');
}
```

### 6.2 Log-Level Merkle Proof Verification
To verify that an individual log event was included in an anchored checkpoint without inspecting all logs:
```javascript
const { verifyMerkleProof } = require('@hhh/security');

const isValid = verifyMerkleProof(
  targetLeafHash,
  proof.proof,
  proof.leafIndex,
  anchoredMerkleRoot
);
```

---

## 7. Troubleshooting & Incident Response

### 7.1 RPC Connectivity / Network Failures
- **Symptom**: `BlockchainError: Provider connection failed` or `RpcTimeoutError: Transaction timed out`.
- **Diagnosis**: Check if Hardhat node is running (`curl http://127.0.0.1:8545`).
- **Mitigation**:
  - Verify `LOGN_RPC_URL` is accessible.
  - Call `adapter.safeRetryAnchor(checkpoint, 3, 2000)`.
  - Check whether transaction actually mined using `blockchainService.commitmentExists(checkpoint.checkpoint_id)`.

### 7.2 Transaction Reverts
- **Revert: "SecureLog: Checkpoint already anchored"**:
  - The checkpoint ID was already recorded on-chain. Checkpoints are immutable.
  - Call `adapter.getAnchoringStatus(checkpoint.checkpoint_id)`. If confirmed, retrieve on-chain block metadata and do not re-anchor.
- **Revert: "SecureLog: Caller not authorized"**:
  - The private key used in `LOGN_SUBMITTER_PRIVATE_KEY` is not authorized in `authorizedSubmitters`. Authorize it by calling `setSubmitter(address, true)` from the contract owner wallet.

### 7.3 Tampered Log Incident Response
If `verifyHashChain` or `verifyCheckpointOnChain` reports an error:
1. **Locate Anomaly**: Identify the exact `sequenceNumber` and `index` reported in `report.errors`.
2. **Determine Scope**: Check whether the anomaly is a modified field (`hash mismatch`), an event deletion (`sequence gap`), or an insertion (`broken chain link`).
3. **Compare Against On-Chain Anchor**:
   - Off-chain root $\neq$ On-chain root: Database log was retroactively altered after checkpoint anchoring.
   - Off-chain signature invalid: Checkpoint document or signature was manipulated.
4. **Export Forensic Audit Report**: Generate the structured JSON report according to Contract §9.5 for incident evidence documentation.
