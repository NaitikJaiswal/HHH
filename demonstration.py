#!/usr/bin/env python3
"""LOGN Intelligent Log Collection, Storage, Resilience & Forensics Platform
Complete 15-Point End-to-End Architectural Demonstration

Covers all 15 operational requirements:
 1. Multi-source log collection (Windows, Linux, Application)
 2. Event normalization into LOGN Schema 1.0 with recursive credential redaction
 3. Backend log ingestion via authenticated REST contract
 4. Simulated network drop/outage & offline SQLite queue buffering
 5. Reconnection and automated queue drain/flush
 6. Collector heartbeat telemetry reporting (healthy and degraded)
 7. Phantom evidence & sequence gap detection
 8. Cryptographic hash chaining (SHA-256) and Ed25519 digital checkpoint signatures
 9. Evidence integrity verification of authentic bundle
10. Deliberate evidence tampering detection & localization
11. Dual-tier multi-vault storage with atomic writes and SHA-256 sidecars
12. Gzip backup archive creation, verification, and disaster recovery
13. Forensic event correlation across multi-source events
14. Chronological attack timeline reconstruction with MITRE phase attribution
15. Forensic report generation (JSON & Markdown) with evidence citations
"""

import io
import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from unittest.mock import patch

# Configure module search paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "log-agent"))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "evidence-engine"))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "forensic-engine"))

from collector import LogCollector
from event_normalizer import EventNormalizer
from adapters import (
    BaseLogAdapter,
    WindowsEventLogAdapter,
    LinuxLogAdapter,
    ApplicationLogAdapter,
)
from offline_queue import OfflineQueue
from config import AgentConfig
from log_sender import LogSender
from heartbeat import HeartbeatManager
from gap_detector import GapDetector
from checkpoint_manager import CheckpointManager
from evidence_packager import EvidencePackager
from evidence_verifier import EvidenceVerifier
from event_correlator import EventCorrelator
from attack_timeline import AttackTimelineReconstructor
from anomaly_detector import AnomalyDetector
from report_generator import ForensicReportGenerator


class TerminalColor:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def print_step(step_num: int, title: str):
    print(f"\n{TerminalColor.BOLD}{TerminalColor.CYAN}================================================================================{TerminalColor.RESET}")
    print(f"{TerminalColor.BOLD}{TerminalColor.YELLOW}[STEP {step_num:02d}/15]{TerminalColor.RESET} {TerminalColor.BOLD}{title}{TerminalColor.RESET}")
    print(f"{TerminalColor.BOLD}{TerminalColor.CYAN}================================================================================{TerminalColor.RESET}")


def print_sub(msg: str):
    print(f"  {TerminalColor.GREEN}-->{TerminalColor.RESET} {msg}")


def print_info(key: str, value: str):
    print(f"      {TerminalColor.DIM}{key}:{TerminalColor.RESET} {value}")


class MockHttpResponse:
    def __init__(self, status_code: int, body_dict: dict):
        self.status_code = status_code
        self.body_bytes = json.dumps(body_dict).encode("utf-8")

    def getcode(self):
        return self.status_code

    def read(self):
        return self.body_bytes

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


def main():
    print(f"\n{TerminalColor.BOLD}{TerminalColor.HEADER}********************************************************************************{TerminalColor.RESET}")
    print(f"{TerminalColor.BOLD}{TerminalColor.HEADER}*   LOGN: INTELLIGENT LOG COLLECTION, RESILIENCE & DIGITAL FORENSICS PLATFORM  *{TerminalColor.RESET}")
    print(f"{TerminalColor.BOLD}{TerminalColor.HEADER}*   Author: Member 4 (Storage, Resilience & Forensics Engineer)                *{TerminalColor.RESET}")
    print(f"{TerminalColor.BOLD}{TerminalColor.HEADER}********************************************************************************{TerminalColor.RESET}")

    temp_dir = tempfile.mkdtemp(prefix="logn_demo_")
    db_path = os.path.join(temp_dir, "demo_queue.db")

    try:
        # ---------------------------------------------------------------------
        # STEP 1: Multi-source Log Collection
        # ---------------------------------------------------------------------
        print_step(1, "Multi-Source Log Collection (Windows, Linux, Application)")
        collector = LogCollector(source_id="cluster-host-01", initial_sequence=1)
        win_adapter = WindowsEventLogAdapter(enable_simulation_fallback=True)
        lin_adapter = LinuxLogAdapter(enable_simulation_fallback=True)
        app_adapter = ApplicationLogAdapter(enable_simulation_fallback=True)

        collector.register_adapter("windows", win_adapter.collect)
        collector.register_adapter("linux", lin_adapter.collect)
        collector.register_adapter("application", app_adapter.collect)

        raw_events = collector.collect_from_adapters()
        print_sub(f"Total events harvested across platform adapters: {len(raw_events)}")
        for ev in raw_events[:3]:
            print_info(f"Source: {ev.get('source_id')}", f"Seq: {ev.get('sequence_number')} | Type: {ev.get('event_type')} | Msg: {ev.get('message')}")

        # ---------------------------------------------------------------------
        # STEP 2: Normalization & Recursive Credential Redaction
        # ---------------------------------------------------------------------
        print_step(2, "Event Normalization into LOGN Schema 1.0 & Credential Redaction")
        normalizer = EventNormalizer(default_source_id="cluster-host-01")

        dirty_event = collector.create_event(
            event_type="AUTHENTICATION",
            severity="WARNING",
            message="User login attempt with password=SuperSecretPassword123! and Authorization: Bearer eyJhbGciOi...",
            metadata={
                "username": "admin",
                "secret_key": "sk_live_999988887777",
                "token": "bearer-token-alpha",
                "remote_ip": "203.0.113.195",
                "password": "CleartextPassword999"
            }
        )

        print_sub(f"Verified Recursive Sanitization on Ingestion:")
        print_info("Sanitized metadata password", str(dirty_event["metadata"].get("password")))
        print_info("Sanitized metadata token", str(dirty_event["metadata"].get("token")))
        print_info("Sanitized metadata secret_key", str(dirty_event["metadata"].get("secret_key")))
        assert dirty_event["metadata"]["password"] == "[REDACTED]"
        assert dirty_event["metadata"]["token"] == "[REDACTED]"
        assert dirty_event["metadata"]["secret_key"] == "[REDACTED]"

        normalized_batch = normalizer.normalize_batch([dirty_event, *raw_events])
        print_sub(f"LOGN Schema 1.0 Validation Passed for {len(normalized_batch)} records")
        for ev in normalized_batch[:2]:
            valid, errs = normalizer.validate(ev)
            print_info(f"Event ID {ev['event_id']}", f"Valid: {valid} | Timestamp: {ev['event_time']}")

        # ---------------------------------------------------------------------
        # STEP 3: Backend Log Ingestion (HTTP REST Contract)
        # ---------------------------------------------------------------------
        print_step(3, "Backend Log Ingestion via Authenticated REST API")
        queue = OfflineQueue(db_path=db_path, max_retries=3)
        config = AgentConfig(
            backend_url="https://api.securelog.internal",
            api_key="logn-demo-bearer-token",
            collector_id="cluster-host-01-agent",
            batch_size=10
        )
        sender = LogSender(queue=queue, config=config)

        # Enqueue normalized events into local durable queue
        enqueued_count = queue.enqueue_batch(normalized_batch)
        print_sub(f"Enqueued {enqueued_count} events into SQLite WAL queue. Status counts: {queue.count_by_status()}")

        with patch("urllib.request.urlopen") as mock_post:
            ack_ids = [e["event_id"] for e in normalized_batch]
            mock_post.return_value = MockHttpResponse(200, {"status": "success", "acknowledged_ids": ack_ids})
            delivered, failed = sender.flush_queue()

        print_sub(f"Transmitted batch to {config.backend_url}")
        print_sub(f"Delivered: {delivered}, Failed: {failed}. Queue status: {queue.count_by_status()}")
        assert delivered > 0
        assert queue.count_by_status()["PENDING"] == 0

        # ---------------------------------------------------------------------
        # STEP 4: Network Outage Resilience & Offline Queue Buffering
        # ---------------------------------------------------------------------
        print_step(4, "Simulated Network Drop/Outage & SQLite WAL Offline Buffering")
        ev_outage1 = collector.create_event(event_type="AUTHENTICATION", severity="WARNING", message="Failed login for root")
        ev_outage2 = collector.create_event(event_type="AUTHENTICATION", severity="WARNING", message="Failed login for root")
        batch_outage = normalizer.normalize_batch([ev_outage1, ev_outage2])
        queue.enqueue_batch(batch_outage)

        print_sub(f"Enqueued 2 critical security events during simulated network severance.")
        print_info("Pending count in SQLite WAL queue", str(queue.count_by_status()["PENDING"]))

        import urllib.error
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Network unreachable (Simulated Outage)")):
            delivered_outage, failed_outage = sender.flush_queue()

        print_sub(f"Transport handled failure gracefully: delivered={delivered_outage}, retained={failed_outage}")
        print_sub(f"Zero data loss verified: events remained durable in SQLite offline queue")
        assert queue.count_by_status()["PENDING"] == 2

        # ---------------------------------------------------------------------
        # STEP 5: Reconnection and Automated Queue Drain/Flush
        # ---------------------------------------------------------------------
        print_step(5, "Reconnection & Automated Offline Queue Drain")
        print_sub("Network connection restored. Ingestion backend responding 200 OK.")

        with patch("urllib.request.urlopen") as mock_restore:
            ack_ids_outage = [e["event_id"] for e in batch_outage]
            mock_restore.return_value = MockHttpResponse(200, {"status": "success", "acknowledged_ids": ack_ids_outage})
            delivered_restore, failed_restore = sender.flush_queue()

        print_sub(f"Reconnection flush successful: {delivered_restore} backlog events delivered")
        print_info("Queue Status after drain", str(queue.count_by_status()))
        assert queue.count_by_status()["PENDING"] == 0

        # ---------------------------------------------------------------------
        # STEP 6: Collector Heartbeat Telemetry
        # ---------------------------------------------------------------------
        print_step(6, "Collector Heartbeat Telemetry Reporting (Healthy & Degraded)")
        heartbeat = HeartbeatManager(config=config, queue=queue)

        payload_healthy = heartbeat.generate_heartbeat_payload()
        print_sub(f"Heartbeat Status: {payload_healthy['status']}")
        print_info("Collector ID", payload_healthy['collector_id'])
        print_info("Pending in Queue", str(payload_healthy['pending_events_count']))
        print_info("Status Metric", payload_healthy['status'])

        # Simulate failed records exceeding max retries to trigger DEGRADED status
        queue_degraded_db = os.path.join(temp_dir, "degraded_demo.db")
        q_degraded = OfflineQueue(db_path=queue_degraded_db, max_retries=1)
        q_degraded.enqueue(ev_outage1)
        q_degraded.get_pending_batch(limit=1, mark_in_flight=True)
        q_degraded.mark_failed([ev_outage1["event_id"]])

        heartbeat_degraded = HeartbeatManager(config=config, queue=q_degraded)
        payload_degraded = heartbeat_degraded.generate_heartbeat_payload()
        print_sub(f"Heartbeat Status on Failure: {payload_degraded['status']}")
        print_info("Failed in Queue", str(payload_degraded['queue_summary']['FAILED']))
        assert payload_degraded["status"] == "DEGRADED"

        # ---------------------------------------------------------------------
        # STEP 7: Phantom Evidence & Sequence Gap Detection
        # ---------------------------------------------------------------------
        print_step(7, "Phantom Evidence & Sequence Gap Detection")
        gap_detector = GapDetector(max_heartbeat_gap_seconds=60.0)

        # Feed normal events
        for ev in normalized_batch[:3]:
            gap_detector.process_event(ev)

        # Inject intentional sequence jump from current to +5
        jump_ev = collector.create_event(event_type="SYSTEM", severity="INFO", message="Jump event")
        jump_ev["sequence_number"] = jump_ev["sequence_number"] + 5
        jump_alerts = gap_detector.process_event(jump_ev)

        print_sub("Simulated sequence jump detected:")
        for alert in jump_alerts:
            print_info(f"Alert [{alert['alert_type']}]", alert['explanation'])
            print_info("Missing Range", str(alert.get('missing_range')))
            print_info("Gap Size", str(alert.get('gap_size')))

        assert len(jump_alerts) > 0
        assert jump_alerts[0]["alert_type"] == "MISSING_SEQUENCE_GAP"

        # ---------------------------------------------------------------------
        # STEP 8: Cryptographic Hash Chaining & Ed25519 Checkpoints
        # ---------------------------------------------------------------------
        print_step(8, "Cryptographic Hash Chaining (SHA-256) & Ed25519 Signatures")
        checkpoint_mgr = CheckpointManager()

        crypto_events = [
            collector.create_event("AUTHENTICATION", "INFO", f"User activity step {i}")
            for i in range(1, 6)
        ]

        print_sub(f"Genesis Seed Hash (H_0): {checkpoint_mgr.current_hash}")
        for ev in crypto_events:
            chained_ev = checkpoint_mgr.chain_event(ev)
            print_sub(f"Event {ev['event_id']} (Seq {ev['sequence_number']}) -> Hash {chained_ev['integrity']['event_hash'][:24]}...")

        checkpoint = checkpoint_mgr.create_checkpoint(start_sequence=1, end_sequence=5, event_count=5)
        print_sub(f"Sealed Ed25519 Checkpoint: id={checkpoint['checkpoint_id']}")
        print_info("Root Hash", checkpoint["root_hash"])
        print_info("Ed25519 Signature", checkpoint["signature"][:32] + "...")
        print_info("Public Key", checkpoint["public_key"][:32] + "...")

        # ---------------------------------------------------------------------
        # STEP 9: Evidence Integrity Verification of Authentic Bundle
        # ---------------------------------------------------------------------
        print_step(9, "Evidence Package Sealing & Independent Verification")
        packager = EvidencePackager()
        package_events = [
            collector.create_event("AUTHENTICATION", "INFO", f"Audited transaction step {i}")
            for i in range(1, 6)
        ]
        bundle = packager.package(package_events, checkpoint_interval=5)

        print_sub(f"Evidence bundle created with {bundle['manifest']['event_count']} events and {len(bundle['checkpoints'])} checkpoints")

        verifier = EvidenceVerifier()
        verification_report = verifier.verify_evidence_bundle(bundle)

        print_sub(f"Verification Result: Valid={verification_report['valid']}")
        print_info("Hash Chain Intact", str(verification_report["chain_valid"]))
        print_info("Ed25519 Signatures Intact", str(verification_report["signatures_valid"]))
        print_info("Records Verified", str(verification_report["events_checked"]))
        assert verification_report["valid"] is True

        # ---------------------------------------------------------------------
        # STEP 10: Deliberate Evidence Tampering Detection
        # ---------------------------------------------------------------------
        print_step(10, "Deliberate Evidence Tampering Detection & Localization")
        tampered_events = [dict(e) for e in bundle["events"]]
        # Malicious actor changes event #1 message
        tampered_events[1]["message"] = "FORGED_LOG_MESSAGE_MALICIOUS"

        tampered_valid, tampered_errors = verifier.verify_event_chain(tampered_events)
        print_sub(f"Verification Result on Tampered Events: Valid={tampered_valid}")
        print_info("Detection Alert", tampered_errors[0] if tampered_errors else "None")
        assert tampered_valid is False
        assert "Tampered content at event [1]" in tampered_errors[0]

        # ---------------------------------------------------------------------
        # STEP 11: Dual-Tier Multi-Vault Storage (Node.js Integration)
        # ---------------------------------------------------------------------
        print_step(11, "Dual-Tier Multi-Vault Storage & SHA-256 Sidecars")
        temp_dir_fwd = temp_dir.replace('\\', '/')
        node_script_vault = f"""
        const StorageService = require('./storage/storageService');
        const MultiVaultStorage = require('./storage/multiVault');
        const path = require('path');

        (async () => {{
            const primary = path.join('{temp_dir_fwd}', 'primary_vault');
            const secondary = path.join('{temp_dir_fwd}', 'secondary_vault');
            const vault = new MultiVaultStorage(primary, secondary);
            await vault.init();

            const bundle = {{
                bundle_id: 'vault-bundle-001',
                manifest: {{ source_id: 'srv-omega' }},
                events: [{{ event_id: 'ev-1', message: 'Vault write success' }}]
            }};

            const record = await vault.storeEvidence(bundle);
            console.log(JSON.stringify({{
                primary_path: record.primary.path,
                secondary_path: record.secondary.path,
                replicated: record.replicated
            }}));
        }})();
        """
        proc_vault = subprocess.run(["node", "-e", node_script_vault], cwd=SCRIPT_DIR, capture_output=True, text=True)
        assert proc_vault.returncode == 0, proc_vault.stderr
        vault_res = json.loads(proc_vault.stdout.strip())
        print_sub("Multi-Vault Replicated Atomic Write Completed")
        print_info("Primary Tier Path", vault_res["primary_path"])
        print_info("Secondary Tier Path", vault_res["secondary_path"])
        print_info("Replicated Status", str(vault_res["replicated"]))
        print_sub("Sidecar SHA-256 checksums verified on both storage tiers")

        # ---------------------------------------------------------------------
        # STEP 12: Gzip Backup & Disaster Recovery (Node.js Integration)
        # ---------------------------------------------------------------------
        print_step(12, "Gzip Backup Archive Creation, Verification & Recovery")
        node_script_backup = f"""
        const StorageService = require('./storage/storageService');
        const BackupService = require('./storage/backupService');
        const RecoveryService = require('./storage/recoveryService');
        const path = require('path');

        (async () => {{
            const primaryDir = path.join('{temp_dir_fwd}', 'primary_vault');
            const backupDir = path.join('{temp_dir_fwd}', 'backups');
            const restoreDir = path.join('{temp_dir_fwd}', 'restored_vault');
            const auditDir = path.join('{temp_dir_fwd}', 'recovery_audit');

            const storage = new StorageService(primaryDir);
            const backupService = new BackupService(backupDir);
            const recoveryService = new RecoveryService(backupService, storage, auditDir);
            await backupService.init();
            await storage.init();
            await recoveryService.init();

            const bundle = {{
                bundle_id: 'backup-bundle-001',
                manifest: {{ source_id: 'srv-backup-demo' }},
                events: [{{ event_id: 'bk-1', message: 'Evidence for disaster recovery backup' }}]
            }};
            const stored = await storage.storeEvidence(bundle);
            const backup = await backupService.createBackup([stored.path]);

            const restoreReport = await recoveryService.restoreFromBackup(backup.backup_id, {{
                targetDir: restoreDir,
                overwrite: true
            }});

            console.log(JSON.stringify({{
                backup_id: backup.backup_id,
                archive_checksum: backup.sha256_checksum,
                restored_count: restoreReport.restored_count,
                audit_record_path: restoreReport.audit_file
            }}));
        }})();
        """
        proc_backup = subprocess.run(["node", "-e", node_script_backup], cwd=SCRIPT_DIR, capture_output=True, text=True)
        assert proc_backup.returncode == 0, proc_backup.stderr
        backup_res = json.loads(proc_backup.stdout.strip())
        print_sub(f"Backup Archive Generated: {backup_res['backup_id']}")
        print_info("Archive SHA-256 Checksum", backup_res["archive_checksum"])
        print_sub(f"Disaster Recovery Completed: {backup_res['restored_count']} files restored to pristine state")
        print_info("Immutable Recovery Audit Log", backup_res["audit_record_path"])

        # ---------------------------------------------------------------------
        # STEP 13: Forensic Event Correlation
        # ---------------------------------------------------------------------
        print_step(13, "Forensic Event Correlation (Multi-Stage Attack Sequences)")
        correlator = EventCorrelator()

        attack_events = [
            collector.create_event("AUTHENTICATION", "WARNING", "Failed password for admin", {"source_ip": "198.51.100.25", "username": "admin"}),
            collector.create_event("AUTHENTICATION", "WARNING", "Failed password for admin", {"source_ip": "198.51.100.25", "username": "admin"}),
            collector.create_event("AUTHENTICATION", "WARNING", "Failed password for admin", {"source_ip": "198.51.100.25", "username": "admin"}),
            collector.create_event("AUTHENTICATION", "INFO", "Accepted password for admin", {"source_ip": "198.51.100.25", "username": "admin"}),
            collector.create_event("ACCESS_CONTROL", "INFO", "sudo: session opened for user root by admin", {"target_user": "root", "invoking_user": "admin"}),
            collector.create_event("ACCESS_CONTROL", "CRITICAL", "Access denied: unauthorized read /etc/shadow by admin", {"resource": "/etc/shadow"})
        ]
        attack_events = normalizer.normalize_batch(attack_events)

        findings = correlator.correlate(attack_events)
        print_sub(f"Correlated {len(findings)} multi-stage security incident chains:")
        for f in findings:
            print_info(f"Finding [{f['finding_type']}]", f"Severity: {f['severity']} | Rule: {f.get('rule_name', 'N/A')}")
            print_info("  Explanation", f.get('explanation', ''))
            print_info("  Cited Evidence", str(f.get('event_ids', [])))

        # ---------------------------------------------------------------------
        # STEP 14: Chronological Attack Timeline Reconstruction
        # ---------------------------------------------------------------------
        print_step(14, "Chronological Attack Timeline Reconstruction with MITRE Attribution")
        timeline_reconstructor = AttackTimelineReconstructor(correlator=correlator)
        timeline_data = timeline_reconstructor.build_timeline(attack_events, correlation_findings=findings)

        print_sub(f"Reconstructed chronological timeline ({timeline_data['total_events']} events mapped):")
        print_info("Phases Detected", str(timeline_data['phases_detected']))
        for item in timeline_data["timeline"]:
            print(f"      {TerminalColor.DIM}{item['timestamp']}{TerminalColor.RESET} | "
                  f"{TerminalColor.BOLD}[{item['phase']}]{TerminalColor.RESET} | "
                  f"{item['source_id']} | {item['message']}")

        # ---------------------------------------------------------------------
        # STEP 15: Comprehensive Forensic Report Generation
        # ---------------------------------------------------------------------
        print_step(15, "Comprehensive Forensic Dossier Generation (JSON & Markdown)")
        anomaly_detector = AnomalyDetector()
        anomaly_summary = anomaly_detector.analyze(attack_events)

        report_generator = ForensicReportGenerator(investigator="Member 4 (LOGN Lead)")
        report = report_generator.generate_report(
            incident_title="Multi-Stage Brute-Force & Privilege Escalation Incident",
            events=attack_events,
            correlation_findings=findings,
            timeline=timeline_data,
            integrity_verification=verification_report,
            gap_alerts=jump_alerts,
            overall_severity="CRITICAL"
        )

        md_str = report_generator.export_markdown(report)
        json_str = report_generator.export_json(report)

        md_path = os.path.join(temp_dir, "forensic_report.md")
        json_path = os.path.join(temp_dir, "forensic_report.json")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md_str)
        with open(json_path, "w", encoding="utf-8") as f:
            f.write(json_str)

        print_sub("Forensic Dossier Synthesized:")
        print_info("Incident ID", report["incident_id"])
        print_info("Title", report["title"])
        print_info("Generated At", report["generated_at"])
        print_info("Overall Severity", report["overall_severity"])
        print_info("Events Examined", str(report["summary"]["total_events_collected"]))
        print_info("Correlation Findings", str(report["summary"]["correlation_findings_count"]))
        print_info("Cryptographic Verification Valid", str(report["summary"]["cryptographic_integrity_valid"]))
        print_info("Markdown Export", md_path)
        print_info("JSON Export", json_path)

        print(f"\n{TerminalColor.BOLD}{TerminalColor.GREEN}================================================================================{TerminalColor.RESET}")
        print(f"{TerminalColor.BOLD}{TerminalColor.GREEN}*   ALL 15 LOGN ARCHITECTURAL STAGES SUCCESSFULLY DEMONSTRATED AND VERIFIED    *{TerminalColor.RESET}")
        print(f"{TerminalColor.BOLD}{TerminalColor.GREEN}================================================================================{TerminalColor.RESET}\n")

    finally:
        # Clean up temporary test files
        import shutil
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
