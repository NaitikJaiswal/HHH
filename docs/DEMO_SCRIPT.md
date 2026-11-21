# HHH (Hash. Hunt. Harden.) — Live Demonstration Script

This script guides presenters, evaluators, and engineers through a step-by-step live demonstration of the completed HHH cybersecurity and digital forensics product.

---

## 1. Prerequisites & Service Bring-Up

Ensure MongoDB, the Express backend, and the React frontend are running:

```bash
# Terminal 1: Backend Server (Port 5000)
cd backend
npm run dev

# Terminal 2: Frontend Dashboard (Port 5173)
cd frontend
npm run dev

# Open Browser: http://localhost:5173
```

---

## Act 1: Live Log Ingestion & Hash Chaining

**Objective:** Demonstrate continuous SHA-256 hash chaining and sequence number monotonicity in real time.

1. Navigate to **Overview Dashboard** (`/`).
   - Point out the active health status, total ingested events, and forward-secure epoch counter.
2. Navigate to **Log Explorer** (`/logs`).
   - Show live ingested security logs from collector hosts (`workstation-forensic-01`, `auth-srv-01`).
   - Expand an event row: point out the authoritative 9-field canonical hash (`LOGN-HASH-v1`), `previousHash`, and `currentHash`.
   - Explain how each event's hash binds to the previous event, forming a tamper-evident chain.

---

## Act 2: Forward-Secure Checkpoints & Merkle Trees

**Objective:** Demonstrate periodic checkpointing and tree-based Forward-Secure Signatures (MKT-FSS).

1. Navigate to **Integrity Verifier** (`/integrity`).
   - Point out the list of signed checkpoints.
   - Click **Run Live Cryptographic Audit**: watch the backend verify all active hash chains against signed checkpoints.
2. Explain the FSS guarantee:
   - "Even if an attacker compromises the server right now, they cannot forge signatures for past epochs because past private keys have been securely overwritten."
3. Point out the Merkle roots and leaf count for each checkpoint window.

---

## Act 3: Quai Network Blockchain Anchoring

**Objective:** Demonstrate public blockchain anchoring on the Quai Network Orchard Cyprus-1 Testnet.

1. Navigate to **Blockchain Ledger** (`/blockchain`).
   - Show network status: **Quai Network Orchard Testnet (Zone: cyprus1, Chain ID: 15000)**.
   - Show smart contract: `SecureLogAnchor` (`0x000000000000000000000000000000000000dead` or testnet deployment).
   - Review confirmed anchored transactions with block numbers and Merkle roots.
   - Explain that anyone with access to QuaiScan can independently verify that the log hash existed at that exact block timestamp.

---

## Act 4: Tamper Detection & Incident Response

**Objective:** Demonstrate real-time adversary detection and incident response workflows.

1. Trigger or review an automated incident:
   - Navigate to **Security Incidents** (`/incidents`) or **Forensic Investigations** (`/investigations`).
   - Open case **Operation DarkVessel** or create a new case docket with **New Case Docket**.
   - Show how the platform correlates failed logins, memory injections, and sequence continuity warnings.
2. In **Investigations**, click on a case to inspect the **Reconstructed Attack Timeline**.
   - Show the chronologically ordered events annotated with MITRE ATT&CK phases (`CREDENTIAL_ACCESS`, `PRIVILEGE_ESCALATION`).
   - Show the green **VERIFIED** badge on untampered events.

---

## Act 5: Independent Verification with `hhh` CLI

**Objective:** Demonstrate that verification requires zero trust in the server.

Open a terminal and run the verification commands:

```bash
# 1. Verify single event hash
node bin/hhh verify-log '{"eventId":"ev-1","sequenceNumber":1,"previousHash":"0000000000000000000000000000000000000000000000000000000000000000","currentHash":"6e7b1fc824ee557d9d5f19ef4269cfebec855b8e53fe08ed3ec168a73d61e97e"}'

# 2. Run full 20-step automated E2E lifecycle test
node --test tests/e2eProductWorkflow.test.js

# Point out that all 24 tests pass, including adversary threat simulations:
# - Tampered event detection
# - Merkle inclusion failure on forged leaf
# - Sequence gap detection
# - Evolved epoch mathematical rejection
```

---

## Act 6: Evidence Vault Sealing & Court-Ready Forensic Dossier

**Objective:** Export a sealed evidence package and court-ready forensic report.

1. Navigate to **Evidence Vault** (`/evidence`).
   - Click **Seal Evidence Bundle**: the enclave bundles events, checkpoints, inclusion proofs, manifest, and chain of custody.
   - Click **Verify** on an evidence row: watch the modal confirm all cryptographic proofs.
   - Click **Export**: download the sealed evidence package JSON.
2. Navigate to **Forensic Reports** (`/reports`).
   - Point out the available report templates.
   - Click **Markdown** to download a GitHub-Flavored Markdown report dossier.
   - Click **JSON Package** to download the machine-readable evidence attestation.
   - Open the Markdown report: highlight the Executive Summary, Attack Timeline, Cryptographic Attestation, Quai Blockchain Anchor receipt, and Chain of Custody.

---

## Summary for Evaluators

HHH fulfills the complete vision of **Hash. Hunt. Harden.** by delivering:
- **Hash:** Continuous canonical SHA-256 chaining and dual-algorithm Merkle trees.
- **Hunt:** Automated anomaly detection, sequence gap identification, and timeline reconstruction.
- **Harden:** Forward-secure key evolution (MKT-FSS), emergency revocation boundaries, and Quai blockchain-anchored evidence.
