# Backend Integration Guide: Security Module & Blockchain Anchoring

> **HHH (Hash. Hunt. Harden.) — SecureLog Forensic Platform**  
> **Target Audience:** Backend Developers (Node.js / Express / MongoDB)  
> **Module Import:** `@hhh/security` (or direct path `security/src/index.js`)  
> **Reference Contract:** `docs/technical-integration-contract.md`

---

## 1. Architectural Role & Responsibilities

The Security module acts as the cryptographic enforcement layer for the SecureLog platform. The Backend module is responsible for receiving HTTP log payloads, authenticating sources, and storing records in MongoDB. The Security module provides the algorithms and interfaces to:

1. Compute deterministic canonical hashes for log events (`LOGN-HASH-v1`).
2. Maintain and verify hash-chained sequence links.
3. Aggregate log sequences into Merkle trees and sign periodic checkpoints.
4. Anchor checkpoint commitments onto the EVM blockchain.
5. Provide high-level idempotent adapters for anchoring and forensic auditing.

---

## 2. Log Ingestion & Hashing Specification

Every log event ingested by the Backend must be canonically serialized and hashed before insertion into MongoDB.

### 2.1 The 9-Field LOGN-HASH-v1 Schema
The hash is computed strictly over these 9 fields:
1. `event_id` (string)
2. `event_time` (string, ISO 8601 UTC `YYYY-MM-DDTHH:MM:SSZ`)
3. `event_type` (string)
4. `message` (string)
5. `metadata` (object, sorted keys; default `{}`)
6. `previous_hash` (string, 64 hex chars; 64 zeros for genesis)
7. `sequence_number` (integer $\ge 1$)
8. `severity` (string, e.g., `"INFO"`, `"WARN"`, `"ERROR"`)
9. `source_id` (string)

### 2.2 Backend Code Example: Ingesting an Event
```javascript
import { hashLogEvent, GENESIS_HASH } from '../security/src/index.js';

// Retrieve last event from MongoDB for this source
const lastEvent = await LogModel.findOne({ source_id: sourceId }).sort({ sequence_number: -1 });
const sequenceNumber = lastEvent ? lastEvent.sequence_number + 1 : 1;
const previousHash = lastEvent ? lastEvent.current_hash : GENESIS_HASH;

const logPayload = {
  event_id: uuidv4(),
  event_time: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
  event_type: 'AUTH_LOGIN',
  message: 'User authentication successful',
  metadata: { userId: '1092', ip: '192.168.1.50' },
  previous_hash: previousHash,
  sequence_number: sequenceNumber,
  severity: 'INFO',
  source_id: sourceId
};

// Compute authoritative hash
const currentHash = hashLogEvent(logPayload);

// Persist to MongoDB
await LogModel.create({
  ...logPayload,
  current_hash: currentHash
});
```

---

## 3. Checkpoint Creation

At regular intervals (e.g., every 100 events or every 5 minutes), the Backend triggers checkpoint creation.

### 3.1 Checkpoint Generation Flow
```javascript
import {
  createCheckpoint,
  KeyManager
} from '../security/src/index.js';

// 1. Fetch sequence window from MongoDB
const events = await LogModel.find({
  source_id: sourceId,
  sequence_number: { $gte: startSeq, $lte: endSeq }
}).sort({ sequence_number: 1 });

// 2. Load signing key manager
const keyManager = new KeyManager(process.env.LOGN_KEYS_DIR);
await keyManager.loadOrGenerate(process.env.LOGN_KEY_PASSPHRASE);

// 3. Create signed checkpoint
const checkpoint = createCheckpoint(events, keyManager);

// 4. Save unanchored checkpoint to MongoDB
await CheckpointModel.create(checkpoint);
```

### 3.2 Checkpoint Document Structure
```json
{
  "checkpoint_id": "a540ca85-4848-4394-bb97-5b65f042617f",
  "version": "1.0",
  "source_id": "node-auth-01",
  "sequence_range": { "start": 1, "end": 100 },
  "event_count": 100,
  "timestamp": 1700000000,
  "merkle_root": "0x3f5c...",
  "merkle_leaf_hashes": ["0x...", "0x..."],
  "signature": "3a01...",
  "public_key": "e04b...",
  "signature_algorithm": "ed25519",
  "blockchain": null
}
```

---

## 4. Blockchain Anchoring via `BackendAdapter`

The `BackendAdapter` wraps low-level blockchain interactions, transaction monitoring, and error handling.

### 4.1 Initializing the Adapter
```javascript
import { createBackendAdapter } from '../security/src/index.js';

const adapter = createBackendAdapter({
  rpcUrl: process.env.LOGN_RPC_URL,
  chainId: Number(process.env.LOGN_CHAIN_ID),
  contractAddress: process.env.LOGN_CONTRACT_ADDRESS,
  privateKey: process.env.LOGN_SUBMITTER_PRIVATE_KEY,
  timeoutSeconds: 60
});
```

### 4.2 Anchoring a Checkpoint
```javascript
try {
  // Anchors commitment and returns receipt metadata
  const anchorResult = await adapter.anchorCheckpointForBackend(checkpoint);

  // Update MongoDB checkpoint document with blockchain metadata
  await CheckpointModel.updateOne(
    { checkpoint_id: checkpoint.checkpoint_id },
    {
      $set: {
        'blockchain.status': 'CONFIRMED',
        'blockchain.tx_hash': anchorResult.txHash,
        'blockchain.block_number': anchorResult.blockNumber,
        'blockchain.contract_address': anchorResult.contractAddress,
        'blockchain.chain_id': anchorResult.chainId,
        'blockchain.anchored_at': anchorResult.timestamp,
        'blockchain.gas_used': anchorResult.gasUsed
      }
    }
  );
} catch (err) {
  console.error('Anchoring failed:', err.message);
  // Mark as PENDING_RETRY in MongoDB for background worker
}
```

### 4.3 Safe Retry Mechanism
If network turbulence causes timeouts or connection drops, call `safeRetryAnchor`:
```javascript
// Automatically checks if already anchored before retrying with exponential backoff
const result = await adapter.safeRetryAnchor(checkpoint, 3, 2000);
```

---

## 5. Dual Verification API

When a forensic auditor or dashboard user requests verification of a checkpoint:

```javascript
// 1. Fetch checkpoint from MongoDB
const checkpoint = await CheckpointModel.findOne({ checkpoint_id: id });

// 2. Perform dual off-chain + on-chain verification
const report = await adapter.verifyCheckpointOnChain(checkpoint);

// 3. Return structured report to frontend/auditor
res.json(report);
```

### 5.1 Verification Report Response (§9.5)
```json
{
  "checkpointId": "a540ca85-4848-4394-bb97-5b65f042617f",
  "sourceId": "node-auth-01",
  "sequenceRange": { "start": 1, "end": 100 },
  "eventCount": 100,
  "storedRoot": "0x3f5c...",
  "recomputedRoot": "0x3f5c...",
  "onChainRoot": "0x3f5c...",
  "signatureValid": true,
  "keyRegistered": true,
  "merkleRootMatch": true,
  "onChainStatus": "CONFIRMED",
  "onChainBlockNumber": 1284,
  "overallValid": true,
  "errors": []
}
```

---

## 6. Recommended MongoDB Schemas & Indexes

To ensure high performance and forensic query integrity, create the following indexes in MongoDB:

```javascript
// Logs Collection
db.logs.createIndex({ source_id: 1, sequence_number: 1 }, { unique: true });
db.logs.createIndex({ current_hash: 1 }, { unique: true });
db.logs.createIndex({ event_time: 1 });

// Checkpoints Collection
db.checkpoints.createIndex({ checkpoint_id: 1 }, { unique: true });
db.checkpoints.createIndex({ source_id: 1, "sequence_range.start": 1, "sequence_range.end": 1 });
db.checkpoints.createIndex({ merkle_root: 1 });
db.checkpoints.createIndex({ "blockchain.status": 1 });
```

---

## 7. Error Handling Guide

| Error Type | Meaning | Recommended Backend Action |
|---|---|---|
| `TypeError` (Missing Field) | Log event is missing one of the 9 required fields | Reject log ingestion with HTTP 400 |
| `VerificationError` | Checkpoint signature or Merkle root computation failed | Flag checkpoint as corrupted; do not anchor |
| `BlockchainError` | Smart contract call reverted | Check revert reason; check if already anchored |
| `RpcTimeoutError` | Blockchain transaction took longer than `timeoutSeconds` | Call `safeRetryAnchor` or queue for retry |
| `IdempotencyError` | Attempted duplicate anchor with conflicting parameters | Reject operation; inspect security incident |
