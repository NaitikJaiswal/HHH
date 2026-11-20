# LOGN API Contract Specification

## 1. Overview & Authentication

This document specifies the REST interface contract between **Member 4** (*Log Agent, Storage & Evidence Engine*) and **Member 2** (*Backend API & Ingestion Server*).

### 1.1 Authentication & Transport
* **Protocol:** HTTPS (TLS 1.2 or TLS 1.3 required in production).
* **Authentication Scheme:** HTTP Bearer Token.
* **Header Format:**
  ```http
  Authorization: Bearer <LOGN_API_KEY>
  Content-Type: application/json
  Accept: application/json
  ```
* **Environment Variable:** `LOGN_API_KEY` (configured on collector instances; defaults to empty string or dev token in testing environments).

---

## 2. Ingestion Endpoint

### `POST /api/v1/logs/ingest`
Ingests a batch of normalized log events from a registered collector agent.

#### Request Headers
| Header | Value | Description |
|---|---|---|
| `Authorization` | `Bearer <token>` | Shared secret or agent JWT |
| `Content-Type` | `application/json` | JSON payload encoding |
| `User-Agent` | `LOGN-Collector/<version>` | Client identification header |

#### Request Body
```json
{
  "events": [
    {
      "event_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
      "timestamp": "2026-11-20T10:15:30.123456Z",
      "source": "host-alpha.internal",
      "event_type": "AUTHENTICATION",
      "severity": "WARN",
      "message": "Failed SSH login attempt for user root from 192.168.1.50",
      "data": {
        "user": "root",
        "remote_ip": "192.168.1.50",
        "auth_method": "publickey",
        "attempt": 3
      },
      "sequence_number": 1042
    }
  ]
}
```

#### Field Specifications (LOGN Schema 1.0)
| Field | Type | Required | Description |
|---|---|---|---|
| `event_id` | `string (UUIDv4)` | Yes | Globally unique event identifier |
| `timestamp` | `string (ISO 8601 UTC)` | Yes | UTC timestamp formatted as `YYYY-MM-DDTHH:MM:SS.ffffffZ` |
| `source` | `string` | Yes | Hostname, IP, or logical system identifier |
| `event_type` | `string` | Yes | One of: `AUTHENTICATION`, `AUTHORIZATION`, `NETWORK`, `FILE_SYSTEM`, `PROCESS`, `SECURITY`, `SYSTEM` |
| `severity` | `string` | Yes | One of: `DEBUG`, `INFO`, `WARN`, `ERROR`, `CRITICAL` |
| `message` | `string` | Yes | Human-readable log description (sensitive tokens redacted) |
| `data` | `object` | No | Structured key-value context payload |
| `sequence_number`| `integer` | Yes | Monotonically increasing sequence number per source instance |

#### Response Codes
* **`200 OK` / `201 Created`**: All events in the batch were accepted.
  ```json
  {
    "status": "success",
    "accepted": 1,
    "failed": 0,
    "ingested_at": "2026-11-20T10:15:30.150Z"
  }
  ```
* **`400 Bad Request`**: Malformed JSON or schema validation failure.
  ```json
  {
    "status": "error",
    "code": "SCHEMA_VALIDATION_FAILED",
    "message": "Field 'event_type' contains invalid category 'LOGIN'"
  }
  ```
* **`401 Unauthorized`**: Missing or invalid Bearer token.
* **`429 Too Many Requests`**: Rate limit exceeded. The client will back off exponentially.
* **`500 / 503 Internal Server Error`**: Backend storage or ingestion queue unavailable. The client retains records in its local SQLite queue for subsequent retry.

---

## 3. Collector Heartbeat Endpoint

### `POST /api/v1/collectors/heartbeat`
Transmits periodic health, queue status, and operational metrics from the collector agent.

#### Request Body
```json
{
  "collector_id": "collector-agent-01",
  "hostname": "prod-srv-01",
  "timestamp": "2026-11-20T10:15:35.000000Z",
  "status": "HEALTHY",
  "queue_pending": 0,
  "queue_failed": 0,
  "delivered_count": 5240,
  "uptime_seconds": 86400,
  "sequence_number": 1440
}
```

#### Field Specifications
| Field | Type | Description |
|---|---|---|
| `collector_id` | `string` | Unique collector agent instance identifier |
| `hostname` | `string` | Host machine running the agent |
| `timestamp` | `string (ISO 8601)` | Timestamp when heartbeat was dispatched |
| `status` | `string` | `HEALTHY` (normal queue status) or `DEGRADED` (failed retries > 0) |
| `queue_pending` | `integer` | Number of events currently waiting in local SQLite queue |
| `queue_failed` | `integer` | Number of events exceeding max retries |
| `delivered_count`| `integer` | Lifetime count of successfully delivered events |
| `uptime_seconds` | `integer` | Duration the collector process has been running |
| `sequence_number`| `integer` | Monotonic heartbeat sequence number |

#### Response
* **`200 OK`**:
  ```json
  {
    "status": "acknowledged",
    "timestamp": "2026-11-20T10:15:35.012Z"
  }
  ```

---

## 4. Evidence Checkpoint & Verification Interfaces

### 4.1 Checkpoint Data Model
When batching evidence, the evidence engine signs periodic checkpoints containing the cryptographic state:
```json
{
  "checkpoint_id": "cp-8f0a1c3b",
  "timestamp": "2026-11-20T10:20:00.000Z",
  "record_count": 100,
  "root_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "public_key_hex": "4a5b6c...32bytes",
  "signature_hex": "7d8e9f...64bytes"
}
```

### 4.2 Sealed Evidence Bundle Structure
Evidence packages exported via `evidence_packager.py` follow this standard structure:
```
evidence_bundle_<timestamp>.zip
├── manifest.json            # Overall bundle metadata and SHA-256 manifest
├── checkpoints.json         # Signed Ed25519 checkpoints
├── events/
│   ├── batch_00001.json     # Ordered event batches
│   └── batch_00002.json
└── verification_key.pub     # Public key in hexadecimal format
```

---

## 5. Storage Layer Internal Query Contract

For inter-component retrieval by the forensic analysis engine, `retrieveLogs.js` supports the following query structure:

```javascript
const results = await retriever.query({
  source: 'host-alpha.internal',       // Filter by host source
  eventType: 'AUTHENTICATION',         // Filter by event category
  severity: 'WARN',                    // Filter by severity level
  startTime: '2026-11-20T00:00:00Z',   // Time range start bound
  endTime: '2026-11-20T23:59:59Z',     // Time range end bound
  search: 'failed password',           // Free-text substring search
  limit: 50                            // Maximum records to return
});
```

All returned log records are validated against their sidecar SHA-256 checksums before inclusion in results. Any corrupted or tampered record raises a security alert.
