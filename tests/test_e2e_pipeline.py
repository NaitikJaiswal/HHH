"""End-to-End Integration Pipeline Test for LOGN Platform

Exercises the full lifecycle from multi-source collection, event normalization,
durable offline queuing, backend failure resilience, reconnection flush,
heartbeat telemetry, sequence gap monitoring, SHA-256 hash chaining with Ed25519
checkpoints, tamper verification, forensic correlation, timeline reconstruction,
and report generation.
"""

import json
import os
import sys
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)

sys.path.insert(0, os.path.join(PROJECT_ROOT, "log-agent"))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "evidence-engine"))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "forensic-engine"))

from collector import LogCollector
from event_normalizer import EventNormalizer
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


class TestE2EPipeline(unittest.TestCase):
    """Full end-to-end integration test of the LOGN architecture."""

    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()

        self.queue = OfflineQueue(db_path=self.temp_db.name, max_retries=3)
        self.collector = LogCollector(source_id="prod-gateway-01", initial_sequence=1)
        self.normalizer = EventNormalizer(default_source_id="prod-gateway-01")
        self.config = AgentConfig(
            backend_url="https://api.securelog.internal",
            api_key="internal-test-key-001",
            collector_id="prod-gateway-01-agent",
            batch_size=10,
        )
        self.sender = LogSender(queue=self.queue, config=self.config)
        self.heartbeat = HeartbeatManager(config=self.config, queue=self.queue)
        self.gap_detector = GapDetector(max_heartbeat_gap_seconds=60.0)

        self.checkpoint_manager = CheckpointManager()
        self.packager = EvidencePackager(checkpoint_manager=self.checkpoint_manager)
        self.verifier = EvidenceVerifier()
        self.correlator = EventCorrelator()
        self.timeline_reconstructor = AttackTimelineReconstructor(correlator=self.correlator)
        self.anomaly_detector = AnomalyDetector()
        self.report_generator = ForensicReportGenerator(investigator="Member 4 (LOGN Lead)")

    def tearDown(self):
        self.heartbeat.stop()
        self.queue.close()
        if os.path.exists(self.temp_db.name):
            try:
                os.remove(self.temp_db.name)
            except OSError:
                pass

    def test_complete_e2e_lifecycle(self):
        """Execute complete lifecycle from collection to report generation."""

        # -------------------------------------------------------------
        # STEP 1: Collection & Sensitive Data Sanitization
        # -------------------------------------------------------------
        raw_events = [
            # 3 failed logins from malicious actor
            self.collector.create_event(
                event_type="AUTHENTICATION",
                severity="WARNING",
                message="Failed password for invalid user admin",
                metadata={"username": "admin", "source_ip": "198.51.100.25", "password": "SensitiveAttempt1"},
            ),
            self.collector.create_event(
                event_type="AUTHENTICATION",
                severity="WARNING",
                message="Failed password for invalid user admin",
                metadata={"username": "admin", "source_ip": "198.51.100.25", "password": "SensitiveAttempt2"},
            ),
            self.collector.create_event(
                event_type="AUTHENTICATION",
                severity="WARNING",
                message="Failed password for invalid user admin",
                metadata={"username": "admin", "source_ip": "198.51.100.25", "password": "SensitiveAttempt3"},
            ),
            # 1 success
            self.collector.create_event(
                event_type="AUTHENTICATION",
                severity="INFO",
                message="Accepted password for admin",
                metadata={"username": "admin", "source_ip": "198.51.100.25", "token": "sensitive-bearer-tok"},
            ),
            # 1 sudo privilege escalation
            self.collector.create_event(
                event_type="ACCESS_CONTROL",
                severity="INFO",
                message="sudo: pam_unix(sudo:session): session opened for user root by admin",
                metadata={"target_user": "root", "invoking_user": "admin", "client_ip": "198.51.100.25"},
            ),
        ]

        # Verify sensitive password and token fields were automatically redacted
        for ev in raw_events:
            self.assertNotIn("SensitiveAttempt", str(ev["metadata"]))
            self.assertNotIn("sensitive-bearer-tok", str(ev["metadata"]))

        # -------------------------------------------------------------
        # STEP 2: Normalization & Schema Validation
        # -------------------------------------------------------------
        normalized_events = self.normalizer.normalize_batch(raw_events)
        self.assertEqual(len(normalized_events), 5)
        for ev in normalized_events:
            valid, errs = self.normalizer.validate(ev)
            self.assertTrue(valid, f"Schema validation failed: {errs}")

        # -------------------------------------------------------------
        # STEP 3: Enqueue in Offline SQLite Queue
        # -------------------------------------------------------------
        enqueued_count = self.queue.enqueue_batch(normalized_events)
        self.assertEqual(enqueued_count, 5)
        self.assertEqual(self.queue.count_by_status()["PENDING"], 5)

        # -------------------------------------------------------------
        # STEP 4: Backend Unavailable Simulation -> Events Retained Safe
        # -------------------------------------------------------------
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = urllib.error.URLError("Ingestion server unreachable (Connection Refused)")

            delivered, failed = self.sender.flush_queue()
            self.assertEqual(delivered, 0)
            self.assertEqual(failed, 5)

            # Events MUST remain in queue, zero data loss
            counts = self.queue.count_by_status()
            self.assertEqual(counts["PENDING"], 5)
            self.assertEqual(counts["DELIVERED"], 0)

        # -------------------------------------------------------------
        # STEP 5: Backend Available Simulation -> Flush & Deliver
        # -------------------------------------------------------------
        with patch("urllib.request.urlopen") as mock_urlopen:
            ack_ids = [e["event_id"] for e in normalized_events]
            mock_urlopen.return_value = MockHttpResponse(200, {"status": "success", "acknowledged_ids": ack_ids})

            delivered, failed = self.sender.flush_queue()
            self.assertEqual(delivered, 5)
            self.assertEqual(failed, 0)

            # Queue verified DELIVERED
            counts = self.queue.count_by_status()
            self.assertEqual(counts["DELIVERED"], 5)
            self.assertEqual(counts["PENDING"], 0)

        # -------------------------------------------------------------
        # STEP 6: Heartbeat Telemetry
        # -------------------------------------------------------------
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value = MockHttpResponse(200, {"status": "ok"})
            self.heartbeat.set_last_delivered_sequence(5)
            hb_result = self.heartbeat.send_heartbeat()
            self.assertTrue(hb_result["success"])
            self.assertEqual(hb_result["payload_sent"]["last_delivered_sequence"], 5)
            self.assertEqual(hb_result["payload_sent"]["status"], "HEALTHY")

        # -------------------------------------------------------------
        # STEP 7: Sequence Gap & Continuity Monitoring
        # -------------------------------------------------------------
        gap_alerts = []
        for ev in normalized_events:
            gap_alerts.extend(self.gap_detector.process_event(ev))
        # Normal consecutive sequence 1..5 produces zero gap alerts
        self.assertEqual(len(gap_alerts), 0)

        # Inject intentional sequence jump from 5 to 10
        jump_event = self.collector.create_event(
            event_type="SYSTEM",
            severity="INFO",
            message="Event after jump",
        )
        jump_event["sequence_number"] = 10
        jump_alerts = self.gap_detector.process_event(jump_event)
        self.assertEqual(len(jump_alerts), 1)
        self.assertEqual(jump_alerts[0]["alert_type"], "MISSING_SEQUENCE_GAP")
        self.assertEqual(jump_alerts[0]["missing_range"], [6, 9])
        self.assertEqual(jump_alerts[0]["gap_size"], 4)

        # -------------------------------------------------------------
        # STEP 8: Cryptographic Evidence Packaging & Verification
        # -------------------------------------------------------------
        bundle = self.packager.package(normalized_events, checkpoint_interval=5)
        self.assertEqual(bundle["manifest"]["event_count"], 5)
        self.assertGreaterEqual(len(bundle["checkpoints"]), 1)

        # Verify pristine evidence bundle
        verification_report = self.verifier.verify_evidence_bundle(bundle)
        self.assertTrue(verification_report["valid"])
        self.assertTrue(verification_report["chain_valid"])
        self.assertTrue(verification_report["signatures_valid"])

        # -------------------------------------------------------------
        # STEP 9: Tamper Detection Verification
        # -------------------------------------------------------------
        tampered_events = [dict(e) for e in bundle["events"]]
        tampered_events[1]["message"] = "TAMPERED_BY_MALICIOUS_ACTOR"
        tampered_valid, tampered_errors = self.verifier.verify_event_chain(tampered_events)
        self.assertFalse(tampered_valid)
        self.assertIn("Tampered content at event [1]", tampered_errors[0])

        # -------------------------------------------------------------
        # STEP 10: Forensic Correlation & Attack Timeline
        # -------------------------------------------------------------
        findings = self.correlator.correlate(normalized_events)
        # Should detect brute force and compromise sequence
        finding_types = [f["finding_type"] for f in findings]
        self.assertIn("REPEATED_AUTHENTICATION_FAILURES", finding_types)
        self.assertIn("AUTHENTICATION_COMPROMISE_SEQUENCE", finding_types)

        timeline_data = self.timeline_reconstructor.build_timeline(
            normalized_events, correlation_findings=findings
        )
        self.assertEqual(timeline_data["total_events"], 5)
        self.assertIn("INITIAL_ACCESS", timeline_data["phases_detected"])
        self.assertIn("PRIVILEGE_ESCALATION", timeline_data["phases_detected"])

        # -------------------------------------------------------------
        # STEP 11: Forensic Report Generation (JSON & Markdown)
        # -------------------------------------------------------------
        report = self.report_generator.generate_report(
            incident_title="E2E Incident: Brute-Force & Privilege Escalation on prod-gateway-01",
            events=normalized_events,
            correlation_findings=findings,
            timeline=timeline_data,
            integrity_verification=verification_report,
            gap_alerts=jump_alerts,
            overall_severity="CRITICAL",
        )

        self.assertEqual(report["overall_severity"], "CRITICAL")
        self.assertEqual(report["summary"]["cryptographic_integrity_valid"], True)

        # Export JSON & Markdown
        json_str = self.report_generator.export_json(report)
        md_str = self.report_generator.export_markdown(report)

        self.assertIn("INC-", json_str)
        self.assertIn("# FORENSIC INCIDENTIAL REPORT", md_str)
        self.assertIn("AUTHENTICATION_COMPROMISE_SEQUENCE", md_str)
        self.assertIn("MISSING_SEQUENCE_GAP", md_str)


if __name__ == "__main__":
    unittest.main()
