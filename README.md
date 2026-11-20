# HHH (Hash. Hunt. Harden.) – SecureLog

**Tamper-Evident Security Logging, Digital Forensics, and Incident Response Platform.**

---

## Project Overview

HHH (SecureLog) is a distributed digital forensics platform designed to protect security event logs against modification, deletion, reordering, and root compromise.

### Core Architecture & Capabilities

1. **Cryptographic Hash Chaining**: Logs are sequentially hashed using SHA-256 and RFC 8785 deterministic canonical JSON serialization.
2. **Ed25519 Signed Checkpoints**: Periodic chain heads are signed using asymmetric digital signatures, proving mathematical chain continuity even if an adversary compromises root database access.
3. **AWS S3 Object Lock (Compliance Mode WORM)**: Immutable batch evidence storage prevents alteration or deletion even by the AWS account root during the retention period.
4. **Automated Tamper Detection & Incidents**: Detection engine automatically identifies sequence gaps, broken chains, altered payloads, and collector disconnects, triggering security incidents.
5. **Python Log Collector (`log-agent/`)**: Edge log collector featuring SQLite offline queuing, exponential retry backoff, and periodic heartbeat telemetry.
6. **React Dashboard**: Modern web interface displaying real-time security alerts, forensic audit logs, and system metrics.

---

## Repository Structure

```
HHH/
├── backend/                  # Express.js REST API & Cryptographic Engine
│   ├── src/
│   │   ├── config/           # Database & AWS S3 WORM configuration
│   │   ├── controllers/      # REST API route controllers
│   │   ├── middleware/       # JWT auth, RBAC, collector auth, error handlers
│   │   ├── models/           # Mongoose schemas (User, Log, Checkpoint, Incident, AuditEvent, Source)
│   │   ├── routes/           # Express API routers
│   │   ├── services/         # Core business logic (auth, log, integrity, checkpoint, storage, incident)
│   │   ├── utils/            # Canonicalization, SHA-256, Ed25519 digital signatures
│   │   └── tests/            # Automated test suite (Vitest + Supertest)
│   ├── HHH_SecureLog.postman_collection.json  # Postman test collection
│   ├── .env.example          # Environment template
│   └── README.md             # Detailed backend guide
└── log-agent/                # Python edge log collector (Member 4 integration)
```

---

## Quick Start (Backend)

```bash
cd backend
npm install
npm test       # Run the 63-test automated verification suite
npm run dev    # Start development server on port 5000
```

Refer to the [Backend Documentation](./backend/README.md) for full REST API specifications and setup details.
