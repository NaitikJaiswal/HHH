"""Unit tests for LOGN Attack Timeline Reconstruction (forensic-engine/attack_timeline.py)"""

import os
import sys
import unittest

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "forensic-engine"))

from attack_timeline import (
    AttackTimelineReconstructor,
    parse_timestamp_safe,
    infer_attack_phase,
)


class TestAttackTimeline(unittest.TestCase):
    """Test suite for AttackTimelineReconstructor chronological and enrichment capabilities."""

    def setUp(self):
        self.reconstructor = AttackTimelineReconstructor()

    def test_chronological_ordering_of_events(self):
        """Verify events arriving out of order are sorted chronologically on the timeline."""
        events = [
            {"event_id": "ev-3", "event_time": "2026-11-20T10:30:00Z", "message": "Third event"},
            {"event_id": "ev-1", "event_time": "2026-11-20T10:10:00Z", "message": "First event"},
            {"event_id": "ev-2", "event_time": "2026-11-20T10:20:00Z", "message": "Second event"},
        ]

        result = self.reconstructor.build_timeline(events)
        timeline = result["timeline"]

        self.assertEqual(len(timeline), 3)
        self.assertEqual(timeline[0]["event_id"], "ev-1")
        self.assertEqual(timeline[1]["event_id"], "ev-2")
        self.assertEqual(timeline[2]["event_id"], "ev-3")
        self.assertEqual(result["duration_seconds"], 1200.0) # 20 minutes

    def test_malformed_timestamp_graceful_handling(self):
        """Verify events with invalid or missing timestamps do not crash timeline generation."""
        events = [
            {"event_id": "ev-valid", "event_time": "2026-11-20T10:00:00Z", "message": "Normal time"},
            {"event_id": "ev-bad", "event_time": "NOT_AN_ISO_TIMESTAMP", "message": "Corrupt time"},
            {"event_id": "ev-none", "event_time": None, "message": "Missing time"},
        ]

        result = self.reconstructor.build_timeline(events)
        self.assertEqual(result["total_events"], 3)
        self.assertEqual(result["milestone_count"], 3)

        bad_milestones = [m for m in result["timeline"] if m["timestamp_inferred"]]
        self.assertEqual(len(bad_milestones), 2)

    def test_correlation_enrichment_and_related_events(self):
        """Verify timeline milestones are enriched with correlation findings and related event IDs."""
        events = [
            {
                "event_id": "fail-1",
                "event_type": "AUTHENTICATION",
                "severity": "WARNING",
                "event_time": "2026-11-20T11:00:00Z",
                "message": "Failed login attempt",
                "metadata": {"username": "admin", "source_ip": "198.51.100.1"},
            },
            {
                "event_id": "fail-2",
                "event_type": "AUTHENTICATION",
                "severity": "WARNING",
                "event_time": "2026-11-20T11:01:00Z",
                "message": "Failed login attempt",
                "metadata": {"username": "admin", "source_ip": "198.51.100.1"},
            },
            {
                "event_id": "fail-3",
                "event_type": "AUTHENTICATION",
                "severity": "WARNING",
                "event_time": "2026-11-20T11:02:00Z",
                "message": "Failed login attempt",
                "metadata": {"username": "admin", "source_ip": "198.51.100.1"},
            },
            {
                "event_id": "success-4",
                "event_type": "AUTHENTICATION",
                "severity": "INFO",
                "event_time": "2026-11-20T11:03:00Z",
                "message": "Accepted password for admin",
                "metadata": {"username": "admin", "source_ip": "198.51.100.1"},
            },
        ]

        result = self.reconstructor.build_timeline(events)
        self.assertGreaterEqual(result["correlation_findings_count"], 1)

        # Verify last milestone is correlated to the compromise sequence
        success_milestone = [m for m in result["timeline"] if m["event_id"] == "success-4"][0]
        self.assertIsNotNone(success_milestone["correlation_explanation"])
        self.assertIn("fail-1", success_milestone["related_event_ids"])
        self.assertIn("INITIAL_ACCESS", result["phases_detected"])

    def test_empty_events_list(self):
        """Verify empty event input returns valid empty timeline object."""
        result = self.reconstructor.build_timeline([])
        self.assertEqual(result["total_events"], 0)
        self.assertEqual(result["milestone_count"], 0)
        self.assertEqual(len(result["timeline"]), 0)


if __name__ == "__main__":
    unittest.main()
