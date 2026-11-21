# Quai Network Blockchain Anchoring Architecture & Guide

## 1. Network Identity & Specifications

The HHH platform anchors tamper-evident log checkpoints into the **Quai Network Orchard Testnet**, specifically targeting the **Cyprus-1 (`cyprus1`)** execution zone.

| Parameter | Specification |
| :--- | :--- |
| **Network Name** | Quai Network Orchard Testnet |
| **Zone Name** | Cyprus-1 (`cyprus1`) |
| **Chain ID** | `15000` (`0x3a98`) |
| **RPC Endpoint** | `https://orchard.rpc.quai.network/cyprus1` |
| **Block Explorer** | `https://quaiscan.io` |
| **Hardhat Network Identifier** | `quai_cyprus1` |
| **Consensus Protocol** | Proof-of-Entropy-Minima (PoEM) |
| **Anchor Contract** | `SecureLogAnchor` |

---

## 2. Anchoring Smart Contract Architecture

The smart contract `SecureLogAnchor` is located at:
`security/blockchain/contracts/SecureLogAnchor.sol`

### Core Data Structures

```solidity
struct CheckpointRecord {
    bytes32 merkleRoot;
    string sourceId;
    uint64 startSequence;
    uint64 endSequence;
    uint64 timestamp;
    address anchoredBy;
    uint256 blockNumber;
}
```

### Core Functions

- `anchorCheckpoint(bytes32 root, string calldata sourceId, uint64 startSeq, uint64 endSeq)`:
  Anchors a new Merkle root for a sequence window of logs from a specific source.
  Emits `CheckpointAnchored(checkpointId, sourceId, root, startSeq, endSeq, timestamp)`.

- `verifyLeafInclusion(bytes32 root, bytes32 leaf, bytes32[] calldata proof, uint256 index, uint256 totalLeaves)`:
  Smart contract verification of leaf inclusion adhering to `HHH-CONTRACT-DUP-v1` odd-node duplication rules.

- `getCheckpoint(bytes32 root)`:
  Retrieves on-chain confirmation details for a given Merkle root.

---

## 3. Off-Chain to On-Chain Anchoring Workflow

```
┌─────────────────┐       ┌────────────────────┐       ┌─────────────────────┐
│  Log Collection │ ───▶  │ Merkle Tree Engine │ ───▶  │  FSS Signing Engine │
│  & Hash Chaining│       │  Leaf Hashes Root  │       │  Bound to Epoch Key │
└─────────────────┘       └────────────────────┘       └──────────┬──────────┘
                                                                  │
                                                                  ▼
┌─────────────────┐       ┌────────────────────┐       ┌─────────────────────┐
│ Independent CLI │ ◀───  │ On-Chain Anchor Tx │ ◀───  │ Quai Network Cyprus1│
│ Verification    │       │ SecureLogAnchor.sol│       │ (Chain ID 15000)    │
└─────────────────┘       └────────────────────┘       └─────────────────────┘
```

1. **Window Accumulation:** The backend accumulates logs for a source until the event count (e.g. 50 events) or time threshold is reached.
2. **Merkle Root Calculation:** The Merkle tree is computed over canonical leaf hashes using `HHH-CONTRACT-DUP-v1`.
3. **FSS Checkpoint Creation:** The checkpoint is signed with the active epoch key and bound to the Master Public Key (MPK).
4. **Blockchain Transaction Dispatch:** The Merkle root, source ID, and sequence range are submitted to `SecureLogAnchor.anchorCheckpoint()`.
5. **Confirmation & Receipt Storage:** Once mined on Quai Cyprus-1, the transaction hash, block number, and gas receipt are permanently linked to the checkpoint document in MongoDB.

---

## 4. Local Hardhat Configuration

In `security/blockchain/hardhat.config.js`:

```javascript
module.exports = {
  solidity: "0.8.20",
  networks: {
    quai_cyprus1: {
      url: process.env.QUAI_RPC_URL || "https://orchard.rpc.quai.network/cyprus1",
      chainId: 15000,
      accounts: process.env.QUAI_PRIVATE_KEY ? [process.env.QUAI_PRIVATE_KEY] : [],
    },
    hardhat: {
      chainId: 1337,
    },
  },
};
```

---

## 5. Verification on Quai Block Explorer

Every anchored checkpoint docket includes a public verification receipt:
- View transactions at: `https://quaiscan.io/tx/<tx_hash>`
- Verify `SecureLogAnchor` contract events for immutable proof timestamps.
