"""Unit tests for LOGN Event Normalizer (log-agent/event_normalizer.py)"""

import json
import os
import sys
import unittest

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "log-agent"))

from event_normalizer import (
    EventNormalizer,
    NormalizationError,
    SCHEMA_VERSION,
    parse_to_utc_iso8601,
)


class TestEventNormalizer(unittest.TestCase):
    """Test suite for EventNormalizer validating schema conformance and robustness."""

    def setUp(self):
        self.normalizer = EventNormalizer(default_source_id="gateway-node-01")

    def test_normalize_valid_conforming_record(self):
        """Verify already compliant records pass validation intact."""
        raw = {
            "schema_version": "1.0",
            "event_id": "550e8400-e29b-41d4-a716-446655440000",
            "source_id": "server-01",
            "sequence_number": 1001,
            "event_time": "2026-11-20T10:30:00Z",
            "observed_at": "2026-11-20T10:30:01Z",
            "event_type": "AUTHENTICATION",
            "severity": "WARNING",
            "message": "Multiple failed login attempts",
            "metadata": {
                "username": "admin",
                "source_ip": "192.0.2.10",
            },
        }

        norm = self.normalizer.normalize(raw, strict=True)
        is_valid, errors = self.normalizer.validate(norm)

        self.assertTrue(is_valid, f"Validation failed: {errors}")
        self.assertEqual(norm["event_id"], "550e8400-e29b-41d4-a716-446655440000")
        self.assertEqual(norm["source_id"], "server-01")
        self.assertEqual(norm["sequence_number"], 1001)
        self.assertEqual(norm["event_type"], "AUTHENTICATION")
        self.assertEqual(norm["severity"], "WARNING")
        self.assertEqual(norm["metadata"]["username"], "admin")

    def test_severity_and_type_aliases(self):
        """Verify common abbreviations and aliases are mapped to standard values."""
        raw = {
            "type": "AUTH",
            "level": "WARN",
            "msg": "Invalid password",
        }
        norm = self.normalizer.normalize(raw)
        self.assertEqual(norm["event_type"], "AUTHENTICATION")
        self.assertEqual(norm["severity"], "WARNING")
        self.assertEqual(norm["message"], "Invalid password")

        raw_fatal = {"level": "FATAL", "type": "APP", "msg": "Out of memory"}
        norm_fatal = self.normalizer.normalize(raw_fatal)
        self.assertEqual(norm_fatal["severity"], "CRITICAL")
        self.assertEqual(norm_fatal["event_type"], "APPLICATION")

    def test_timestamp_parsing_epoch_and_iso(self):
        """Verify numeric epoch and ISO timestamps are properly converted to UTC Z format."""
        # Epoch in seconds: 1700000000 -> 2023-11-14T22:13:20Z
        parsed_epoch = parse_to_utc_iso8601(1700000000)
        self.assertEqual(parsed_epoch, "2023-11-14T22:13:20Z")

        # Epoch in milliseconds: 1700000000000 -> 2023-11-14T22:13:20Z
        parsed_epoch_ms = parse_to_utc_iso8601(1700000000000)
        self.assertEqual(parsed_epoch_ms, "2023-11-14T22:13:20Z")

        # ISO string with offset: 2026-11-20T12:00:00+02:00 -> 2026-11-20T10:00:00Z
        parsed_offset = parse_to_utc_iso8601("2026-11-20T12:00:00+02:00")
        self.assertEqual(parsed_offset, "2026-11-20T10:00:00Z")

    def test_json_string_normalization(self):
        """Verify JSON string inputs are parsed and normalized properly."""
        json_str = json.dumps({
            "hostname": "db-prod-02",
            "timestamp": "2026-11-20T08:00:00Z",
            "level": "ERR",
            "message": "Connection reset by peer",
            "client_ip": "10.0.0.5",
        })

        norm = self.normalizer.normalize(json_str)
        self.assertEqual(norm["source_id"], "db-prod-02")
        self.assertEqual(norm["severity"], "ERROR")
        self.assertEqual(norm["metadata"]["client_ip"], "10.0.0.5")

    def test_malformed_input_resilience_in_lenient_mode(self):
        """Verify corrupt strings or unparseable objects do not crash in lenient mode."""
        corrupt_str = "NOT_JSON_LOG_ENTRY [ERROR] disk corrupted"
        norm = self.normalizer.normalize(corrupt_str, strict=False)

        self.assertEqual(norm["schema_version"], SCHEMA_VERSION)
        self.assertEqual(norm["message"], corrupt_str)
        self.assertTrue(norm["event_time"].endswith("Z"))
        self.assertEqual(norm["source_id"], "gateway-node-01")

        is_valid, errors = self.normalizer.validate(norm)
        self.assertTrue(is_valid, f"Validation errors on resilient object: {errors}")

    def test_strict_mode_rejection_of_invalid_fields(self):
        """Verify strict mode raises NormalizationError on unparseable JSON."""
        with self.assertRaises(NormalizationError):
            self.normalizer.normalize("NOT_JSON", strict=True)

    def test_batch_normalization(self):
        """Verify batch normalization maintains sequence numbers."""
        records = [
            {"message": "Event 1"},
            {"message": "Event 2"},
            {"message": "Event 3"},
        ]
        batch = self.normalizer.normalize_batch(records, start_sequence=500)
        self.assertEqual(len(batch), 3)
        self.assertEqual(batch[0]["sequence_number"], 500)
        self.assertEqual(batch[1]["sequence_number"], 501)
        self.assertEqual(batch[2]["sequence_number"], 502)


if __name__ == "__main__":
    unittest.main()
