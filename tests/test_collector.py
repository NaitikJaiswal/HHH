"""Unit tests for LOGN Log Collector (log-agent/collector.py)"""

import os
import re
import sys
import tempfile
import unittest

# Ensure log-agent module is importable
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "log-agent"))

from collector import LogCollector, REDACTED_VALUE


class TestLogCollector(unittest.TestCase):
    """Test suite for LogCollector functionality and security requirements."""

    def setUp(self):
        self.collector = LogCollector(source_id="test-host-01", initial_sequence=100)

    def test_event_creation_structure(self):
        """Verify created event adheres to schema with required fields."""
        event = self.collector.create_event(
            event_type="AUTHENTICATION",
            severity="WARNING",
            message="Failed login attempt",
            metadata={"username": "alice", "source_ip": "192.168.1.10"},
        )

        self.assertEqual(event["schema_version"], "1.0")
        self.assertEqual(event["source_id"], "test-host-01")
        self.assertEqual(event["sequence_number"], 100)
        self.assertEqual(event["event_type"], "AUTHENTICATION")
        self.assertEqual(event["severity"], "WARNING")
        self.assertEqual(event["message"], "Failed login attempt")
        self.assertEqual(event["metadata"]["username"], "alice")
        self.assertEqual(event["metadata"]["source_ip"], "192.168.1.10")

        # Verify UUID format
        uuid_pattern = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            re.IGNORECASE,
        )
        self.assertTrue(uuid_pattern.match(event["event_id"]))

        # Verify UTC ISO 8601 timestamps ending in 'Z'
        self.assertTrue(event["event_time"].endswith("Z"))
        self.assertTrue(event["observed_at"].endswith("Z"))

    def test_sequence_number_increment(self):
        """Verify sequence numbers increment monotonically with each created event."""
        e1 = self.collector.create_event("SYSTEM", "INFO", "First event")
        e2 = self.collector.create_event("SYSTEM", "INFO", "Second event")
        e3 = self.collector.create_event("SYSTEM", "INFO", "Third event")

        self.assertEqual(e1["sequence_number"], 100)
        self.assertEqual(e2["sequence_number"], 101)
        self.assertEqual(e3["sequence_number"], 102)
        self.assertEqual(self.collector.current_sequence, 103)

    def test_sensitive_metadata_redaction(self):
        """Verify passwords, tokens, API keys and credentials are automatically scrubbed."""
        metadata = {
            "username": "admin",
            "password": "SuperSecretPassword123!",
            "api_key": "live_key_99999",
            "access_token": "bearer_jwt_token_xyz",
            "nested": {
                "auth_header": "Bearer secret_token",
                "safe_field": "visible_value",
            },
            "list_data": [
                {"private_key": "-----BEGIN RSA PRIVATE KEY-----"},
                "regular_item",
            ],
        }

        sanitized = self.collector.sanitize_metadata(metadata)

        self.assertEqual(sanitized["username"], "admin")
        self.assertEqual(sanitized["password"], REDACTED_VALUE)
        self.assertEqual(sanitized["api_key"], REDACTED_VALUE)
        self.assertEqual(sanitized["access_token"], REDACTED_VALUE)
        self.assertEqual(sanitized["nested"]["auth_header"], REDACTED_VALUE)
        self.assertEqual(sanitized["nested"]["safe_field"], "visible_value")
        self.assertEqual(sanitized["list_data"][0]["private_key"], REDACTED_VALUE)
        self.assertEqual(sanitized["list_data"][1], "regular_item")

    def test_invalid_severity_and_event_type_fallback(self):
        """Verify unknown severity and event type safely fall back to defaults."""
        event = self.collector.create_event(
            event_type="NON_EXISTENT_TYPE",
            severity="SUPER_PANIC",
            message="Test fallback",
        )
        self.assertEqual(event["event_type"], "SYSTEM")
        self.assertEqual(event["severity"], "INFO")

    def test_collect_from_missing_file_graceful_handling(self):
        """Verify collecting from non-existent file produces a warning event without crashing."""
        events = self.collector.collect_from_file("/path/to/definitely/nonexistent.log")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["severity"], "WARNING")
        self.assertEqual(events[0]["metadata"]["status"], "FILE_NOT_FOUND")

    def test_collect_from_file_success(self):
        """Verify reading log lines from a temporary log file."""
        with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8") as f:
            f.write("Line 1: Service started\n")
            f.write("Line 2: Client connected\n")
            temp_path = f.name

        try:
            events = self.collector.collect_from_file(
                temp_path, event_type="APPLICATION", severity="INFO"
            )
            self.assertEqual(len(events), 2)
            self.assertEqual(events[0]["message"], "Line 1: Service started")
            self.assertEqual(events[1]["message"], "Line 2: Client connected")
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_adapter_registration_and_error_handling(self):
        """Verify adapters are executed and failures are captured as ERROR events."""
        def good_adapter():
            return [
                {
                    "event_type": "AUDIT",
                    "severity": "INFO",
                    "message": "User checked status",
                    "metadata": {"user": "bob"},
                }
            ]

        def faulty_adapter():
            raise RuntimeError("Adapter subsystem timed out")

        self.collector.register_adapter("good_source", good_adapter)
        self.collector.register_adapter("failing_source", faulty_adapter)

        events = self.collector.collect_from_adapters()
        self.assertEqual(len(events), 2)

        # Check successful event from good adapter
        self.assertEqual(events[0]["event_type"], "AUDIT")
        self.assertEqual(events[0]["message"], "User checked status")

        # Check graceful error event from faulty adapter
        self.assertEqual(events[1]["severity"], "ERROR")
        self.assertIn("Adapter failing_source encountered an error", events[1]["message"])
        self.assertEqual(events[1]["metadata"]["adapter_name"], "failing_source")


if __name__ == "__main__":
    unittest.main()
