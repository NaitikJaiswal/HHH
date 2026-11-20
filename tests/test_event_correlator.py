"""Unit tests for LOGN Forensic Event Correlator (forensic-engine/event_correlator.py)"""

import os
import sys
import unittest

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "forensic-engine"))

from event_correlator import (
    EventCorrelator,
    BruteForceAuthenticationRule,
    CompromiseSequenceRule,
    AccessDeniedBurstRule,
)


class TestEventCorrelator(unittest.TestCase):
    """Test suite for EventCorrelator multi-stage rule detection."""

    def setUp(self):
        self.correlator = EventCorrelator()

    def test_brute_force_authentication_detection(self):
        """Verify repeated failed logins generate REPEATED_AUTHENTICATION_FAILURES finding."""
        events = [
            {
                "event_id": f"fail-{i}",
                "event_type": "AUTHENTICATION",
                "severity": "WARNING",
                "event_time": f"2026-11-20T10:0{i}:00Z",
                "message": "Failed login attempt",
                "metadata": {"username": "admin", "source_ip": "198.51.100.5"},
            }
            for i in range(1, 5)
        ]

        findings = self.correlator.correlate(events)
        brute_force_findings = [f for f in findings if f["finding_type"] == "REPEATED_AUTHENTICATION_FAILURES"]

        self.assertEqual(len(brute_force_findings), 1)
        f = brute_force_findings[0]
        self.assertEqual(f["entities"]["target_user"], "admin")
        self.assertEqual(f["entities"]["source_ip"], "198.51.100.5")
        self.assertEqual(f["event_count"], 3)
        self.assertIn("fail-1", f["event_ids"])
        self.assertIn("Consistent with credential guessing", f["explanation"])

    def test_compromise_sequence_detection(self):
        """Verify brute force failures followed immediately by successful logon triggers CRITICAL alert."""
        events = [
            {
                "event_id": "fail-1",
                "event_type": "AUTHENTICATION",
                "severity": "WARNING",
                "event_time": "2026-11-20T10:00:00Z",
                "message": "Invalid password for user root",
                "metadata": {"username": "root", "source_ip": "203.0.113.19"},
            },
            {
                "event_id": "fail-2",
                "event_type": "AUTHENTICATION",
                "severity": "WARNING",
                "event_time": "2026-11-20T10:01:00Z",
                "message": "Invalid password for user root",
                "metadata": {"username": "root", "source_ip": "203.0.113.19"},
            },
            {
                "event_id": "success-3",
                "event_type": "AUTHENTICATION",
                "severity": "INFO",
                "event_time": "2026-11-20T10:02:00Z",
                "message": "Accepted password for root",
                "metadata": {"username": "root", "source_ip": "203.0.113.19"},
            },
        ]

        findings = self.correlator.correlate(events)
        comp_findings = [f for f in findings if f["finding_type"] == "AUTHENTICATION_COMPROMISE_SEQUENCE"]

        self.assertEqual(len(comp_findings), 1)
        comp = comp_findings[0]
        self.assertEqual(comp["severity"], "CRITICAL")
        self.assertEqual(comp["entities"]["target_user"], "root")
        self.assertEqual(comp["entities"]["source_ip"], "203.0.113.19")
        self.assertEqual(comp["success_event_id"], "success-3")
        self.assertIn("fail-1", comp["event_ids"])
        self.assertIn("success-3", comp["event_ids"])
        self.assertIn("Indicates probable successful unauthorized access", comp["explanation"])

    def test_access_denied_burst_detection(self):
        """Verify burst of 403 / ACCESS_CONTROL errors triggers ACCESS_DENIED_BURST finding."""
        events = [
            {
                "event_id": f"acl-{i}",
                "event_type": "ACCESS_CONTROL",
                "severity": "WARNING",
                "event_time": f"2026-11-20T12:00:0{i}Z",
                "message": f"GET /api/v1/vault/secret_{i} - HTTP 403",
                "metadata": {"status_code": 403, "client_ip": "10.0.0.99"},
            }
            for i in range(1, 5)
        ]

        findings = self.correlator.correlate(events)
        acl_findings = [f for f in findings if f["finding_type"] == "ACCESS_DENIED_BURST"]

        self.assertEqual(len(acl_findings), 1)
        self.assertEqual(acl_findings[0]["severity"], "WARNING")
        self.assertEqual(len(acl_findings[0]["event_ids"]), 3)
        self.assertIn("May indicate privilege boundary testing", acl_findings[0]["explanation"])

    def test_benign_traffic_generates_zero_findings(self):
        """Verify ordinary healthy events generate no correlation findings."""
        events = [
            {
                "event_id": "ok-1",
                "event_type": "SYSTEM",
                "severity": "INFO",
                "event_time": "2026-11-20T10:00:00Z",
                "message": "Service heartbeat normal",
            },
            {
                "event_id": "ok-2",
                "event_type": "AUTHENTICATION",
                "severity": "INFO",
                "event_time": "2026-11-20T10:01:00Z",
                "message": "Single user bob logged in successfully",
                "metadata": {"username": "bob"},
            },
        ]

        findings = self.correlator.correlate(events)
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
