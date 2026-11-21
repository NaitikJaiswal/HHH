
# HHH (Hash. Hunt. Harden.) – SecureLog

**Tamper-Evident Security Logging, Digital Forensics, and Incident Response Platform.**

---

## 1. Project Overview

HHH (SecureLog) is a security logging and digital forensics platform designed to protect security event logs against unauthorized modification, deletion, and reordering.

The project combines secure log collection, cryptographic integrity verification, resilient evidence storage, incident detection, and forensic analysis.

### Core Capabilities

1. **Cryptographic Hash Chaining:** Logs are sequentially hashed using authoritative `LOGN-HASH-v1` (RFC 8785 canonical JSON + SHA-256) to guarantee immutable sequence continuity.
2. **Adaptive Forward-Secure Checkpoints (MKT-FSS):** Checkpoints are signed with Malkin-Katz-Salil tree-based forward-secure keys. Compromise of an active epoch key mathematically prevents forgery of past epochs.
3. **Quai Network Blockchain Anchoring:** Merkle roots are permanently anchored to the Quai Network Orchard Cyprus-1 Testnet (Chain ID 15000) via `SecureLogAnchor.sol`.
4. **Dual-Algorithm Merkle Proofs:** Independent inclusion proofs supporting both smart contract odd-node duplication (`HHH-CONTRACT-DUP-v1`) and Certificate Transparency (`RFC-6962`).
5. **Independent Verification CLI:** Command-line tool (`bin/hhh`) for zero-trust offline verification of logs, chains, checkpoints, Merkle proofs, evidence packages, and forensic reports.
6. **Immutable Evidence Vault & Court-Ready Dossiers:** Sealed evidence bundles with cryptographic manifests, full chain-of-custody tracking, and incident dossiers exported in JSON and Markdown.
7. **Tamper Detection and Incident Management:** Real-time detection of sequence gaps, broken hash chains, altered payloads, and collector disconnections.
8. **Python Edge Collector:** High-resilience collector with local SQLite WAL queuing, exponential retry backoff, and heartbeat monitoring.
9. **React Forensics Dashboard:** Production-grade 14-page dashboard for real-time monitoring, 3D evidence graph inspection, and operational control.

---

## 2. System Architecture

The project consists of the following major components:

### Backend – Express.js

The backend provides REST APIs, database connectivity, authentication, log management, integrity verification, and incident management.

### Security Engine

The security component implements SHA-256 hash chaining, Ed25519 digital signatures, signed checkpoints, and integrity verification.

### Storage and Resilience – LOGN

LOGN is the intelligent log collection, secure storage, resilience, backup, recovery, and forensic subsystem developed for the HHH project.

Its responsibilities include:

- Durable local queuing using SQLite Write-Ahead Logging (WAL).
- Log collection, normalization, and sensitive-data sanitization.
- Batched log transmission with exponential retry backoff.
- SHA-256 hash chaining and Ed25519 checkpoint signatures.
- Primary and secondary storage vaults with failover.
- Backup archives, recovery, and retention management.
- Event correlation, anomaly detection, and forensic reports.

### Frontend – React

The frontend provides the dashboard and interfaces for authentication, log exploration, integrity verification, and incident management.

---

## 3. Repository Structure

```text
HHH/
│
├── backend/
│   ├── src/
│   │   ├── config/
│   │   ├── models/
│   │   ├── controllers/
│   │   ├── routes/
│   │   ├── middleware/
│   │   ├── services/
│   │   ├── utils/
│   │   └── tests/
│   ├── .env.example
│   ├── package.json
│   └── README.md
│
├── frontend/
│   ├── src/
│   ├── public/
│   └── package.json
│
├── log-agent/
│   ├── collector.py
│   ├── event_normalizer.py
│   ├── offline_queue.py
│   ├── log_sender.py
│   ├── heartbeat.py
│   ├── gap_detector.py
│   ├── config.py
│   ├── requirements.txt
│   └── adapters/
│       ├── windows_adapter.py
│       ├── linux_adapter.py
│       └── application_adapter.py
│
├── evidence-engine/
│   ├── checkpoint_manager.py
│   ├── evidence_packager.py
│   └── evidence_verifier.py
│
├── storage/
│   ├── storageService.js
│   ├── backupService.js
│   ├── multiVault.js
│   ├── retentionManager.js
│   ├── retrieveLogs.js
│   └── recoveryService.js
│
├── forensic-engine/
│   ├── event_correlator.py
│   ├── attack_timeline.py
│   ├── anomaly_detector.py
│   └── report_generator.py
│
├── docs/
│   ├── architecture.md
│   ├── api-contract.md
│   └── security-design.md
│
├── tests/
└── demonstration.py
```

*Note: This is the combined logical project structure. Keep only directories and files that actually exist in the repository.*

---

## 4. LOGN – Storage, Resilience and Forensics

LOGN provides the evidence collection and storage subsystem.

### Log Agent

- `collector.py` – Multi-source log collection and sensitive-data sanitization.
- `event_normalizer.py` – Log normalization and validation.
- `offline_queue.py` – SQLite WAL-based offline queue.
- `log_sender.py` – Batched HTTP/HTTPS log transmission with exponential backoff.
- `heartbeat.py` – Collector health monitoring.
- `gap_detector.py` – Detection of sequence jumps and missing evidence.
- `adapters/` – Windows, Linux, and application log adapters.

### Evidence Engine

- `checkpoint_manager.py` – SHA-256 hash chaining and Ed25519 checkpoint signing.
- `evidence_packager.py` – Evidence bundle creation and cryptographic manifests.
- `evidence_verifier.py` – Hash-chain and signature verification.

### Storage Engine

- `storageService.js` – Atomic file writes and SHA-256 sidecar checksums.
- `backupService.js` – Backup archives and manifest verification.
- `multiVault.js` – Primary and secondary storage with failover.
- `retentionManager.js` – Retention policies and legal hold handling.
- `retrieveLogs.js` – Log retrieval with integrity verification.
- `recoveryService.js` – Recovery procedures and audit logging.

### Forensic Engine

- `event_correlator.py` – Multi-source event correlation.
- `attack_timeline.py` – Chronological attack timeline reconstruction.
- `anomaly_detector.py` – Statistical and off-hours anomaly detection.
- `report_generator.py` – Forensic incident report generation.

---

## 5. Quick Start

### Backend

```bash
cd backend
npm install
npm run dev
```

The backend development server is configured to run on port 5000.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

### Python Log Agent

Install Python dependencies:

```bash
cd log-agent
pip install -r requirements.txt
```

Run the collector using its configured entry point.

### End-to-End Demonstration

If `demonstration.py` is available at the repository root:

```bash
python demonstration.py
```

---

## 6. Comprehensive Verification & Testing

### 1. 20-Step End-to-End Product Lifecycle Suite
```bash
node --test tests/e2eProductWorkflow.test.js
```

### 2. Independent Verification CLI Suite
```bash
node --test tests/cli.test.js
```

### 3. Backend Integration Suite (13 Vitest Suites, 99 Tests)
```bash
cd backend && npm test
```

### 4. Cryptographic Security Engine Suite (138 Tests)
```bash
cd security && node --test tests/*.test.js
```

### 5. Smart Contract Suite (110 Hardhat Tests)
```bash
cd security && npm run test:contracts
```

### 6. Python Agent & Forensic Telemetry Suite (68 Tests)
```bash
.venv/bin/python3 -m unittest discover -s tests -p "test_*.py"
```

### 7. Frontend Production Build
```bash
cd frontend && npm run build
```

---

## 7. Documentation & Reference Manuals

- [CLI Reference Manual](docs/CLI_REFERENCE.md) – Commands, exit codes, and examples for `bin/hhh`.
- [Quai Network Blockchain Anchoring](docs/BLOCKCHAIN_ANCHORING.md) – Smart contract, Cyprus-1 testnet (Chain ID 15000), and receipts.
- [Forward-Secure Logging Specification](docs/FORWARD_SECURE_LOGGING.md) – MKT-FSS tree design, key derivation, and revocation.
- [Live Demonstration Script](docs/DEMO_SCRIPT.md) – Step-by-step walkthrough for live evaluator demonstrations.
- [Architecture Specification](docs/architecture.md)
- [Backend API Contract](docs/api-contract.md)
- [Security and Cryptographic Design](docs/security-design.md)

---

## 8. Technology Stack

| Component | Technology |
|---|---|
| Backend | Node.js, Express.js |
| Frontend | React.js, Tailwind CSS, Lucide Icons, Three.js |
| Blockchain Anchoring | Quai Network Orchard Cyprus-1 Testnet (Chain ID 15000, `SecureLogAnchor.sol`) |
| Forward-Secure Signatures | Malkin-Katz-Salil (MKT-FSS) Tree Signatures with HKDF-SHA256 ratcheting |
| Cryptographic Verification | HHH Verification CLI (`bin/hhh`) |
| Canonical Hashing | RFC 8785 Canonical JSON + SHA-256 (`LOGN-HASH-v1`) |
| Merkle Trees | Dual-Algorithm: `HHH-CONTRACT-DUP-v1` & `RFC-6962` |
| Database | MongoDB & Mongoose |
| Edge Log Collection | Python 3, SQLite WAL Queuing |
| Evidence Storage | Sealed JSONL/ZIP Enclaves & AWS S3 Object Lock Compliance |
| Version Control | Git and GitHub (`feature/forward-secure-logging`) |

---

## 9. Project Objective

The primary objective of HHH SecureLog is to build a system that makes security logs more trustworthy and useful for incident investigation.

By combining secure collection, cryptographic verification, resilient storage, and forensic analysis, the platform aims to help organizations identify suspicious activity and preserve reliable digital evidence.
