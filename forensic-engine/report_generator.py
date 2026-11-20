"""LOGN Forensic Incident Report Generator

Synthesizes event correlations, attack timelines, cryptographic verification results,
sequence gap detections, and recovery records into comprehensive forensic incident reports
in JSON and Markdown formats.
"""

from __future__ import annotations

import datetime
import json
import uuid
from typing import Any, Dict, List, Optional


class ForensicReportGenerator:
    """Generates structured forensic reports synthesizing all LOGN engine telemetry."""

    def __init__(self, investigator: str = "Member 4 (LOGN Lead Analyst)") -> None:
        self.investigator = investigator

    def generate_report(
        self,
        incident_title: str,
        events: List[Dict[str, Any]],
        correlation_findings: Optional[List[Dict[str, Any]]] = None,
        timeline: Optional[Dict[str, Any]] = None,
        integrity_verification: Optional[Dict[str, Any]] = None,
        gap_alerts: Optional[List[Dict[str, Any]]] = None,
        recovery_info: Optional[Dict[str, Any]] = None,
        overall_severity: str = "MEDIUM",
        recommended_actions: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Compile a complete forensic incident dossier dictionary.

        :return: Comprehensive structured report dictionary.
        """
        now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        incident_id = f"INC-{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

        correlations = correlation_findings or []
        timeline_data = timeline or {}
        integrity = integrity_verification or {"valid": True, "chain_valid": True, "signatures_valid": True, "errors": []}
        gaps = gap_alerts or []

        # Derive time window
        start_time = timeline_data.get("incident_start")
        end_time = timeline_data.get("incident_end")
        duration = timeline_data.get("duration_seconds", 0.0)

        # Default recommended steps if not provided
        recommendations = recommended_actions or [
            "Review authentication failure entities and isolate affected source IP addresses.",
            "Verify cryptographic evidence chain and preserve signed checkpoints in secondary vault.",
            "Validate system accounts that experienced privilege escalation or multiple failed logins.",
            "Inspect sequence gaps and review network logs during collector communication interruptions.",
            "Retain affected evidence bundles under legal hold in the storage vault.",
        ]

        report = {
            "schema_version": "1.0",
            "incident_id": incident_id,
            "title": incident_title,
            "generated_at": now_utc,
            "investigator": self.investigator,
            "overall_severity": overall_severity,
            "summary": {
                "total_events_collected": len(events),
                "affected_sources": timeline_data.get("affected_sources", []),
                "correlation_findings_count": len(correlations),
                "timeline_milestones_count": timeline_data.get("milestone_count", 0),
                "missing_evidence_warnings_count": len(gaps),
                "cryptographic_integrity_valid": integrity.get("valid", False),
            },
            "time_range": {
                "start_time": start_time,
                "end_time": end_time,
                "duration_seconds": duration,
            },
            "correlation_findings": correlations,
            "attack_timeline": timeline_data.get("timeline", []),
            "integrity_verification": {
                "status": "VERIFIED" if integrity.get("valid") else "INTEGRITY_COMPROMISED",
                "events_checked": integrity.get("events_checked", len(events)),
                "chain_valid": integrity.get("chain_valid", False),
                "signatures_valid": integrity.get("signatures_valid", False),
                "errors": integrity.get("errors", []),
            },
            "missing_evidence_warnings": gaps,
            "recovery_information": recovery_info or {
                "backup_status": "AVAILABLE",
                "restoration_performed": False,
            },
            "recommended_investigation_steps": recommendations,
        }

        return report

    def export_json(self, report: Dict[str, Any], indent: int = 2) -> str:
        """Serialize forensic report to a clean JSON string."""
        return json.dumps(report, indent=indent, sort_keys=False)

    def export_markdown(self, report: Dict[str, Any]) -> str:
        """Render forensic report to human-readable GitHub-Flavored Markdown."""
        lines = [
            f"# FORENSIC INCIDENTIAL REPORT: {report.get('title', 'LOGN Forensic Analysis')}",
            "",
            f"**Incident ID:** `{report.get('incident_id')}`  ",
            f"**Date Generated:** {report.get('generated_at')}  ",
            f"**Lead Investigator:** {report.get('investigator')}  ",
            f"**Overall Severity:** **{report.get('overall_severity')}**  ",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            "",
            f"- **Total Events Analyzed:** {report['summary']['total_events_collected']}",
            f"- **Affected Sources:** {', '.join(report['summary']['affected_sources']) if report['summary']['affected_sources'] else 'N/A'}",
            f"- **Correlation Findings:** {report['summary']['correlation_findings_count']}",
            f"- **Attack Timeline Milestones:** {report['summary']['timeline_milestones_count']}",
            f"- **Missing Sequence Warnings:** {report['summary']['missing_evidence_warnings_count']}",
            f"- **Cryptographic Integrity:** {'✅ VERIFIED' if report['summary']['cryptographic_integrity_valid'] else '❌ COMPROMISED'}",
            "",
            f"**Incident Window:** {report['time_range'].get('start_time', 'N/A')} to {report['time_range'].get('end_time', 'N/A')} ({report['time_range'].get('duration_seconds', 0)}s duration)",
            "",
            "---",
            "",
            "## 2. Event Correlation Findings",
            "",
        ]

        findings = report.get("correlation_findings", [])
        if findings:
            for idx, f in enumerate(findings, 1):
                lines.append(f"### Finding {idx}: {f.get('finding_type')} [{f.get('severity')}]")
                lines.append(f"- **Explanation:** {f.get('explanation')}")
                if "entities" in f:
                    lines.append(f"- **Entities Involved:** `{f.get('entities')}`")
                lines.append(f"- **Cited Event IDs:** {', '.join(f.get('event_ids', []))}")
                lines.append("")
        else:
            lines.append("*No malicious correlation patterns triggered.*")
            lines.append("")

        lines.extend([
            "---",
            "",
            "## 3. Reconstructed Attack Timeline",
            "",
            "| Timestamp | Source | Phase | Severity | Event Summary |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ])

        milestones = report.get("attack_timeline", [])
        if milestones:
            for m in milestones:
                ts = m.get("timestamp", "N/A")
                src = m.get("source_id", "N/A")
                phase = m.get("phase", "GENERAL")
                sev = m.get("severity", "INFO")
                msg = m.get("message", "").replace("|", "\\|")[:80]
                lines.append(f"| {ts} | {src} | {phase} | {sev} | {msg} |")
        else:
            lines.append("| - | - | No Milestones | - | - |")

        lines.extend([
            "",
            "---",
            "",
            "## 4. Cryptographic Evidence Integrity",
            "",
            f"- **Integrity Status:** `{report['integrity_verification']['status']}`",
            f"- **SHA-256 Hash Chain:** {'Valid' if report['integrity_verification']['chain_valid'] else 'BROKEN / TAMPERED'}",
            f"- **Ed25519 Checkpoint Signatures:** {'Valid' if report['integrity_verification']['signatures_valid'] else 'INVALID SIGNATURE'}",
        ])
        if report['integrity_verification']['errors']:
            lines.append("- **Verification Discrepancies:**")
            for err in report['integrity_verification']['errors']:
                lines.append(f"  - ⚠️ {err}")
        lines.append("")

        lines.extend([
            "---",
            "",
            "## 5. Missing Evidence & Sequence Continuity Warnings",
            "",
        ])
        gaps = report.get("missing_evidence_warnings", [])
        if gaps:
            for g in gaps:
                lines.append(f"- ⚠️ **{g.get('alert_type')}**: {g.get('explanation')}")
        else:
            lines.append("✅ *Zero sequence gaps or collector silence anomalies observed.*")
        lines.append("")

        lines.extend([
            "---",
            "",
            "## 6. Recommended Action Items",
            "",
        ])
        for step in report.get("recommended_investigation_steps", []):
            lines.append(f"1. {step}")
        lines.append("")

        return "\n".join(lines)
