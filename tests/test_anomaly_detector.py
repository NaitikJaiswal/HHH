"""Unit tests for LOGN Explainable Anomaly Detector (forensic-engine/anomaly_detector.py)"""

import os
import sys
import unittest

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "forensic-engine"))

from anomaly_detector import AnomalyDetector


class TestAnomalyDetector(unittest.TestCase):
    """Test suite for AnomalyDetector explainable behavioral and volume detection."""

    def setUp(self):
        self.detector = AnomalyDetector(
            business_hours_start=8,
            business_hours_end=18,
            allow_weekends=False,
            volume_surge_multiplier=2.5,
            min_surge_events=5,
            max_failure_rate_threshold=0.5,
            min_events_for_rate=4,
        )

    def test_off_hours_activity_detection(self):
        """Verify events occurring outside business hours are flagged with clear rationale."""
        events = [
            # 02:30:00 UTC on a Wednesday (2026-11-18 is Wednesday)
            {
                "event_id": "ev-night",
                "source_id": "srv-prod-01",
                "event_type": "ACCESS_CONTROL",
                "severity": "WARNING",
                "event_time": "2026-11-18T02:30:00Z",
                "message": "Sudo privilege escalation executed",
            },
            # 14:00:00 UTC on Wednesday (normal business hour)
            {
                "event_id": "ev-day",
                "source_id": "srv-prod-01",
                "event_type": "APPLICATION",
                "severity": "INFO",
                "event_time": "2026-11-18T14:00:00Z",
                "message": "Normal application request",
            },
        ]

        anomalies = self.detector.detect_off_hours_activity(events)
        self.assertEqual(len(anomalies), 1)
        a = anomalies[0]
        self.assertEqual(a["anomaly_type"], "OFF_HOURS_ACTIVITY")
        self.assertEqual(a["event_id"], "ev-night")
        self.assertIn("02:00", a["explanation"])
        self.assertIn("outside window 08:00-18:00", a["explanation"])

    def test_weekend_activity_detection(self):
        """Verify weekend events are flagged when weekends are disallowed."""
        # 2026-11-21 is Saturday
        events = [
            {
                "event_id": "ev-sat",
                "source_id": "srv-finance",
                "event_type": "AUTHENTICATION",
                "severity": "INFO",
                "event_time": "2026-11-21T12:00:00Z",
                "message": "User login on weekend",
            }
        ]

        anomalies = self.detector.detect_off_hours_activity(events)
        self.assertEqual(len(anomalies), 1)
        self.assertIn("Saturday", anomalies[0]["explanation"])

    def test_volume_surge_detection(self):
        """Verify sudden spike in event count triggers EVENT_VOLUME_SURGE anomaly."""
        events = []
        # Normal baseline: 2 events in bucket 1 (10:00), 2 events in bucket 2 (10:10)
        for i in range(2):
            events.append({"event_id": f"b1-{i}", "event_time": "2026-11-18T10:02:00Z"})
            events.append({"event_id": f"b2-{i}", "event_time": "2026-11-18T10:12:00Z"})

        # Surge bucket: 15 events in bucket 3 (10:20)
        for i in range(15):
            events.append({"event_id": f"surge-{i}", "event_time": "2026-11-18T10:25:00Z"})

        anomalies = self.detector.detect_volume_surges(events, bucket_minutes=10)
        self.assertEqual(len(anomalies), 1)
        a = anomalies[0]
        self.assertEqual(a["anomaly_type"], "EVENT_VOLUME_SURGE")
        self.assertEqual(a["observed_count"], 15)
        self.assertIn("Event surge detected", a["explanation"])

    def test_unusual_failure_rate_detection(self):
        """Verify stream with excessive failure ratio triggers UNUSUAL_FAILURE_FREQUENCY."""
        events = [
            # 4 failures out of 5 events (80% > 50% threshold)
            {"event_id": "e1", "source_id": "srv-api", "severity": "ERROR", "message": "Connection refused"},
            {"event_id": "e2", "source_id": "srv-api", "severity": "WARNING", "message": "Auth failure"},
            {"event_id": "e3", "source_id": "srv-api", "severity": "ERROR", "message": "Database query failed"},
            {"event_id": "e4", "source_id": "srv-api", "severity": "WARNING", "message": "Permission denied"},
            {"event_id": "e5", "source_id": "srv-api", "severity": "INFO", "message": "Heartbeat OK"},
        ]

        anomalies = self.detector.detect_unusual_failure_rate(events)
        self.assertEqual(len(anomalies), 1)
        a = anomalies[0]
        self.assertEqual(a["anomaly_type"], "UNUSUAL_FAILURE_FREQUENCY")
        self.assertEqual(a["failure_count"], 4)
        self.assertEqual(a["failure_rate"], 0.8)
        self.assertIn("80.0%", a["explanation"])

    def test_full_analysis_report(self):
        """Verify analyze() combines all detections into a structured breakdown."""
        events = [
            {"event_id": "e-off", "source_id": "s1", "event_time": "2026-11-18T01:00:00Z", "severity": "INFO"},
        ]
        report = self.detector.analyze(events)
        self.assertEqual(report["total_events_analyzed"], 1)
        self.assertEqual(report["anomaly_count"], 1)
        self.assertEqual(report["breakdown"]["off_hours_activity"], 1)


if __name__ == "__main__":
    unittest.main()
