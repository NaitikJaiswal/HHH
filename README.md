
# HHH (Hash. Hunt. Harden.) – SecureLog

**Tamper-Evident Security Logging, Digital Forensics, and Incident Response Platform.**

---

## 1. Project Overview

HHH (SecureLog) is a security logging and digital forensics platform designed to protect security event logs against unauthorized modification, deletion, and reordering.

The project combines secure log collection, cryptographic integrity verification, resilient evidence storage, incident detection, and forensic analysis.

### Core Capabilities

1. **Cryptographic Hash Chaining:** Logs are sequentially hashed using SHA-256 to help detect modifications and broken log sequences.
2. **Ed25519 Signed Checkpoints:** Periodic checkpoints use asymmetric digital signatures to verify the authenticity of recorded chain states.
3. **Immutable Evidence Storage:** The architecture supports AWS S3 Object Lock for protected evidence retention.
4. **Tamper Detection and Incident Management:** Detects suspicious sequence gaps, broken hash chains, altered payloads, and collector disconnections.
5. **Python Log Collector:** Collects logs and supports local SQLite queuing, retry mechanisms, and heartbeat monitoring.
6. **React Dashboard:** Provides an interface for viewing security logs, incidents, system metrics, and forensic information.
7. **Forensic Analysis:** Supports event correlation, attack timeline reconstruction, anomaly detection, and report generation.

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

## 6. Testing

### Backend

```bash
cd backend
npm test
```

### Python Tests

```bash
python -m unittest discover tests
```

### Storage Tests

```bash
node --test tests/test_storage.js
node --test tests/test_recovery.js
```

Run the commands from the appropriate project directory and verify that the corresponding test files exist.

---

## 7. Documentation

- [Architecture Specification](docs/architecture.md)
- [Backend API Contract](docs/api-contract.md)
- [Security and Cryptographic Design](docs/security-design.md)
- [Backend Documentation](backend/README.md)

---

## 8. Technology Stack

| Component | Technology |
|---|---|
| Backend | Node.js, Express.js |
| Frontend | React.js |
| Database | MongoDB |
| Log Collection | Python |
| Local Queue | SQLite |
| Cryptographic Hashing | SHA-256 |
| Digital Signatures | Ed25519 |
| Evidence Storage | AWS S3 Object Lock (planned/integrated as configured) |
| Version Control | Git and GitHub |

---

## 9. Project Objective

The primary objective of HHH SecureLog is to build a system that makes security logs more trustworthy and useful for incident investigation.

By combining secure collection, cryptographic verification, resilient storage, and forensic analysis, the platform aims to help organizations identify suspicious activity and preserve reliable digital evidence.
