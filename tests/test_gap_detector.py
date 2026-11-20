"""Unit tests for LOGN Sequence Gap & Collector Monitoring (log-agent/gap_detector.py)"""

import datetime
import os
import sys
import unittest

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "log-agent"))

from gap_detector import GapDetector


class TestGapDetector(unittest.TestCase):
    """Test suite for GapDetector sequence and heartbeat analysis."""

    def setUp(self):
        self.detector = GapDetector(
            max_heartbeat_gap_seconds=60.0,
            max_transmission_delay_seconds=120.0,
        )

    def test_normal_consecutive_sequences_generate_zero_alerts(self):
        """Verify normal sequence numbers produce no alerts."""
        alerts = []
        for seq in range(1, 10):
            event = {
                "source_id": "srv-01",
                "sequence_number": seq,
                "event_time": "2026-11-20T10:00:00Z",
                "observed_at": "2026-11-20T10:00:01Z",
            }
            alerts.extend(self.detector.process_event(event))

        self.assertEqual(len(alerts), 0)
        summary = self.detector.get_stream_summary("srv-01")
        self.assertEqual(summary["last_sequence"], 9)
        self.assertEqual(summary["total_gaps_detected"], 0)

    def test_missing_sequence_gap_detection(self):
        """Verify sequence jump generates MISSING_SEQUENCE_GAP alert with exact missing range."""
        e1 = {"source_id": "srv-01", "sequence_number": 100, "event_time": "2026-11-20T10:00:00Z", "observed_at": "2026-11-20T10:00:00Z"}
        self.detector.process_event(e1)

        # Jump from 100 to 105 (missing 101, 102, 103, 104)
        e2 = {"source_id": "srv-01", "sequence_number": 105, "event_time": "2026-11-20T10:00:05Z", "observed_at": "2026-11-20T10:00:05Z"}
        alerts = self.detector.process_event(e2)

        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert["alert_type"], "MISSING_SEQUENCE_GAP")
        self.assertEqual(alert["source_id"], "srv-01")
        self.assertEqual(alert["expected_sequence"], 101)
        self.assertEqual(alert["observed_sequence"], 105)
        self.assertEqual(alert["missing_range"], [101, 104])
        self.assertEqual(alert["gap_size"], 4)
        self.assertIn("Sequence gap of 4 missing event(s)", alert["explanation"])

        summary = self.detector.get_stream_summary("srv-01")
        self.assertEqual(summary["total_gaps_detected"], 4)

    def test_duplicate_sequence_detection(self):
        """Verify duplicate sequence numbers generate DUPLICATE_SEQUENCE alert."""
        e1 = {"source_id": "srv-01", "sequence_number": 50, "event_time": "2026-11-20T10:00:00Z", "observed_at": "2026-11-20T10:00:00Z"}
        self.detector.process_event(e1)

        # Repeat sequence 50
        e2 = {"source_id": "srv-01", "sequence_number": 50, "event_time": "2026-11-20T10:00:01Z", "observed_at": "2026-11-20T10:00:01Z"}
        alerts = self.detector.process_event(e2)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_type"], "DUPLICATE_SEQUENCE")
        self.assertEqual(alerts[0]["sequence_number"], 50)

    def test_transmission_delay_detection(self):
        """Verify significant latency between event_time and observed_at triggers TRANSMISSION_DELAY."""
        event = {
            "source_id": "srv-01",
            "sequence_number": 1,
            "event_time": "2026-11-20T10:00:00Z",
            "observed_at": "2026-11-20T10:10:00Z",  # 600 seconds delay (> threshold 120s)
        }
        alerts = self.detector.process_event(event)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_type"], "TRANSMISSION_DELAY")
        self.assertEqual(alerts[0]["delay_seconds"], 600.0)

    def test_heartbeat_gap_detection_with_cautious_attribution(self):
        """Verify gap between heartbeats triggers alert with non-accusatory explanation."""
        hb1 = {"host_id": "node-alpha", "timestamp": "2026-11-20T12:00:00Z"}
        self.detector.process_heartbeat(hb1)

        # Heartbeat 120 seconds later (> 60s threshold)
        hb2 = {"host_id": "node-alpha", "timestamp": "2026-11-20T12:02:00Z"}
        alerts = self.detector.process_heartbeat(hb2)

        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert["alert_type"], "HEARTBEAT_GAP")
        self.assertEqual(alert["gap_seconds"], 120.0)
        # Verify the key requirement: "A heartbeat gap indicates a possible collection interruption. It does not independently prove an attack or intentional tampering."
        self.assertIn("A heartbeat gap indicates a possible collection interruption", alert["explanation"])
        self.assertIn("does not independently prove an attack", alert["explanation"])

    def test_collector_silence_detection(self):
        """Verify silent collectors beyond threshold trigger COLLECTOR_SILENCE alert."""
        t0 = datetime.datetime(2026, 11, 20, 10, 0, 0, tzinfo=datetime.timezone.utc)
        self.detector.process_heartbeat({"host_id": "node-beta", "timestamp": t0.strftime("%Y-%m-%dT%H:%M:%SZ")})

        # Check silence at t0 + 100s (> 60s threshold)
        t_check = t0 + datetime.timedelta(seconds=100)
        alerts = self.detector.check_stale_collectors(current_time=t_check)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_type"], "COLLECTOR_SILENCE")
        self.assertEqual(alerts[0]["source_id"], "node-beta")
        self.assertEqual(alerts[0]["elapsed_seconds"], 100.0)

    def test_multi_source_stream_isolation(self):
        """Verify multiple source streams are tracked independently without false gaps."""
        # Host 1 sequence 1..3
        self.detector.process_event({"source_id": "host-1", "sequence_number": 1})
        self.detector.process_event({"source_id": "host-1", "sequence_number": 2})

        # Host 2 sequence 100..101
        self.detector.process_event({"source_id": "host-2", "sequence_number": 100})
        alerts = self.detector.process_event({"source_id": "host-2", "sequence_number": 101})

        # No gaps should be falsely detected between host-1 and host-2
        self.assertEqual(len(alerts), 0)
        self.assertEqual(self.detector.get_stream_summary("host-1")["last_sequence"], 2)
        self.assertEqual(self.detector.get_stream_summary("host-2")["last_sequence"], 101)


if __name__ == "__main__":
    unittest.main()
