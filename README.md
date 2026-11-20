# HHH - LOGN: Intelligent Log Collection, Resilience & Forensic Platform

[![Status](https://img.shields.io/badge/status-active-success.svg)]()
[![License](https://img.shields.io/badge/license-MIT-blue.svg)]()
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)]()
[![Node](https://img.shields.io/badge/node-20%2B-green)]()

## 1. Overview

**LOGN** (*Intelligent Log Collection, Secure Storage, Resilience, Backup, Recovery, and Forensic Analysis*) is the core evidentiary subsystem developed for the **HHH** project by **Member 4** (*Storage, Resilience & Forensics Engineer*).

It guarantees:
* **Zero Data Loss:** Durable local queuing via SQLite Write-Ahead Logging (`WAL` mode) across network partitions or host outages.
* **Cryptographic Tamper-Evidence:** SHA-256 hash chaining ($H_i = \text{SHA-256}(H_{i-1} \parallel \text{canonical}(E_i))$) and asymmetric Ed25519 digital signatures on periodic checkpoints.
* **Dual-Tier Resilient Storage:** Synchronous primary vault storage and secondary failover replication with atomic writes and `.sha256` sidecar checksums.
* **Disaster Recovery & Retention:** Gzip backup archives, overwrite collision protection, persistent recovery audit logs, and legal hold policy preservation.
* **Defensible Digital Forensics:** Objective multi-source event correlation, MITRE ATT&CK timeline attribution, and explainable anomaly detection.

---

## 2. Directory Structure

```
HHH/
├── docs/                           # Architecture and design documentation
│   ├── architecture.md             # Complete component and data flow architecture
│   ├── api-contract.md             # REST API specifications with Member 2 backend
│   └── security-design.md          # Threat model, cryptographic chain, and privacy design
├── log-agent/                      # Intelligent collection and local resilience
│   ├── collector.py                # Multi-source log collection & sensitive data sanitization
│   ├── event_normalizer.py         # LOGN Schema 1.0 normalization & validation
│   ├── offline_queue.py            # SQLite WAL durable offline queue with FIFO ordering
│   ├── log_sender.py               # Batched HTTP/HTTPS log transport with exponential backoff
│   ├── heartbeat.py                # Telemetry monitoring and collector health reporting
│   ├── gap_detector.py             # Phantom evidence and sequence jump detector
│   ├── config.py                   # Environment configuration with safe defaults
│   ├── requirements.txt            # Python dependencies (cryptography, pydantic)
│   └── adapters/                   # Platform log adapters
│       ├── windows_adapter.py      # Windows Event Log XML adapter
│       ├── linux_adapter.py        # Linux syslog (RFC 3164) adapter
│       └── application_adapter.py  # JSON and Combined Log Format application adapter
├── evidence-engine/                # Cryptographic integrity and packaging
│   ├── checkpoint_manager.py       # SHA-256 hash chaining & Ed25519 signature generator
│   ├── evidence_packager.py        # Sealed ZIP bundle creation with cryptographic manifests
│   └── evidence_verifier.py        # Independent hash chain and signature verifier
├── storage/                        # Node.js resilient vault and disaster recovery layer
│   ├── storageService.js           # Atomic file writes (.tmp rename) and SHA-256 sidecars
│   ├── backupService.js            # Gzip backup archives and manifest verification
│   ├── multiVault.js               # Primary and secondary dual-tier storage with failover
│   ├── retentionManager.js         # Configurable TTL retention with legal hold protection
│   ├── retrieveLogs.js             # Multi-criteria filtering with integrity verification
│   └── recoveryService.js          # Disaster recovery with overwrite guards and audit logs
├── forensic-engine/                # Explainable incident reconstruction & reporting
│   ├── event_correlator.py         # Multi-stage attack chain correlation engine
│   ├── attack_timeline.py          # Chronological timeline and MITRE phase reconstructor
│   ├── anomaly_detector.py         # Explainable statistical and off-hours anomaly detector
│   └── report_generator.py         # 9-part forensic incident dossier (JSON & Markdown)
├── tests/                          # Comprehensive unit, integration, and E2E test suites
│   ├── test_collector.py           # Collector and redaction tests
│   ├── test_normalizer.py          # Schema 1.0 normalization tests
│   ├── test_adapters.py            # Windows, Linux, and App adapter tests
│   ├── test_offline_queue.py       # SQLite WAL durable queue tests
│   ├── test_log_sender.py          # LogSender transport tests
│   ├── test_heartbeat.py           # Telemetry and heartbeat tests
│   ├── test_gap_detector.py        # Sequence jump and regression tests
│   ├── test_integrity.py           # SHA-256 chaining and Ed25519 signature tests
│   ├── test_storage.js             # StorageService, MultiVault, and Retention tests
│   ├── test_recovery.js            # BackupService and RecoveryService tests
│   ├── test_event_correlator.py    # Forensic correlation rule tests
│   ├── test_attack_timeline.py     # Attack timeline reconstruction tests
│   ├── test_anomaly_detector.py    # Statistical and schedule anomaly tests
│   ├── test_report_generator.py    # Forensic dossier synthesis tests
│   └── test_e2e_pipeline.py        # Complete end-to-end integration pipeline test
└── demonstration.py                # Interactive 15-step end-to-end platform demonstration
```

---

## 3. Quickstart & Testing

### Running the End-to-End Demonstration
To execute the complete 15-step verification workflow:
```bash
python demonstration.py
```

### Running Test Suites
Run all Python unit and integration tests (68 tests):
```bash
python -m unittest discover tests
```

Run all Node.js storage, vault, and recovery tests (8 tests):
```bash
node --test tests/test_storage.js
node --test tests/test_recovery.js
```

---

## 4. Documentation Links
* [Architecture Specification](docs/architecture.md)
* [Backend API Contract](docs/api-contract.md)
* [Security & Cryptographic Design](docs/security-design.md)
