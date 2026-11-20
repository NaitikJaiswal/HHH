"""Unit tests for LOGN Forensic Incident Report Generator (forensic-engine/report_generator.py)"""

import json
import os
import sys
import unittest

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "forensic-engine"))

from report_generator import ForensicReportGenerator


class TestReportGenerator(unittest.TestCase):
    """Test suite for ForensicReportGenerator JSON and Markdown dossier compilation."""

    def setUp(self):
        self.generator = ForensicReportGenerator(investigator="Member 4 - LOGN Analyst")

    def test_complete_report_generation_structure(self):
        """Verify report compiles all 9 required forensic dossier sections."""
        events = [
            {"event_id": "ev-1", "source_id": "srv-01", "event_time": "2026-11-20T10:00:00Z", "message": "Login fail"},
            {"event_id": "ev-2", "source_id": "srv-01", "event_time": "2026-11-20T10:01:00Z", "message": "Login success"},
        ]
        correlations = [
            {
                "finding_type": "AUTHENTICATION_COMPROMISE_SEQUENCE",
                "severity": "CRITICAL",
                "explanation": "Failed login followed by success.",
                "event_ids": ["ev-1", "ev-2"],
                "entities": {"target_user": "admin"},
            }
        ]
        timeline = {
            "incident_start": "2026-11-20T10:00:00Z",
            "incident_end": "2026-11-20T10:01:00Z",
            "duration_seconds": 60.0,
            "affected_sources": ["srv-01"],
            "milestone_count": 2,
            "timeline": [
                {"timestamp": "2026-11-20T10:00:00Z", "source_id": "srv-01", "phase": "CREDENTIAL_ACCESS", "severity": "WARNING", "message": "Login fail"},
                {"timestamp": "2026-11-20T10:01:00Z", "source_id": "srv-01", "phase": "INITIAL_ACCESS", "severity": "CRITICAL", "message": "Login success"},
            ],
        }
        integrity = {
            "valid": True,
            "chain_valid": True,
            "signatures_valid": True,
            "errors": [],
            "events_checked": 2,
        }
        gaps = [
            {
                "alert_type": "HEARTBEAT_GAP",
                "explanation": "A heartbeat gap indicates a possible collection interruption. It does not independently prove an attack.",
            }
        ]

        report = self.generator.generate_report(
            incident_title="Suspicious Credential Compromise on srv-01",
            events=events,
            correlation_findings=correlations,
            timeline=timeline,
            integrity_verification=integrity,
            gap_alerts=gaps,
            overall_severity="HIGH",
        )

        # 1. Verify top-level metadata
        self.assertTrue(report["incident_id"].startswith("INC-"))
        self.assertEqual(report["title"], "Suspicious Credential Compromise on srv-01")
        self.assertEqual(report["investigator"], "Member 4 - LOGN Analyst")
        self.assertEqual(report["overall_severity"], "HIGH")

        # 2. Verify all sections
        self.assertEqual(report["summary"]["total_events_collected"], 2)
        self.assertEqual(report["time_range"]["duration_seconds"], 60.0)
        self.assertEqual(len(report["correlation_findings"]), 1)
        self.assertEqual(len(report["attack_timeline"]), 2)
        self.assertEqual(report["integrity_verification"]["status"], "VERIFIED")
        self.assertEqual(len(report["missing_evidence_warnings"]), 1)
        self.assertGreaterEqual(len(report["recommended_investigation_steps"]), 3)

    def test_json_export_validity(self):
        """Verify export_json() generates valid parseable JSON."""
        report = self.generator.generate_report(
            incident_title="Routine Test Report",
            events=[],
        )
        json_output = self.generator.export_json(report)
        parsed = json.loads(json_output)
        self.assertEqual(parsed["title"], "Routine Test Report")
        self.assertEqual(parsed["schema_version"], "1.0")

    def test_markdown_export_rendering(self):
        """Verify export_markdown() generates readable Markdown with key sections."""
        report = self.generator.generate_report(
            incident_title="Incident Alpha",
            events=[{"event_id": "e1", "message": "test"}],
            overall_severity="CRITICAL",
        )
        md = self.generator.export_markdown(report)
        self.assertIn("# FORENSIC INCIDENTIAL REPORT: Incident Alpha", md)
        self.assertIn("## 1. Executive Summary", md)
        self.assertIn("## 2. Event Correlation Findings", md)
        self.assertIn("## 3. Reconstructed Attack Timeline", md)
        self.assertIn("## 4. Cryptographic Evidence Integrity", md)
        self.assertIn("## 6. Recommended Action Items", md)


if __name__ == "__main__":
    unittest.main()
