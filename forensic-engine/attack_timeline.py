"""LOGN Attack Timeline Reconstruction Engine

Reconstructs chronological forensic attack timelines from collected log events
and correlation findings, linking multi-stage activities with explainable milestones.
"""

from __future__ import annotations

import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from event_correlator import EventCorrelator


def parse_timestamp_safe(event: Dict[str, Any]) -> Tuple[datetime.datetime, bool]:
    """Parse timestamp into UTC datetime, returning (datetime_obj, is_valid)."""
    t_str = event.get("event_time") or event.get("observed_at")
    if isinstance(t_str, str):
        clean = t_str.strip()
        try:
            if clean.endswith("Z"):
                return datetime.datetime.fromisoformat(clean[:-1] + "+00:00"), True
            return datetime.datetime.fromisoformat(clean), True
        except ValueError:
            pass

    # Fallback for missing/corrupted timestamp: return epoch 1970
    return datetime.datetime.fromtimestamp(0, tz=datetime.timezone.utc), False


def infer_attack_phase(event: Dict[str, Any], finding_type: Optional[str] = None) -> str:
    """Classify event or milestone into an explainable forensic phase."""
    if finding_type:
        if "REPEATED_AUTHENTICATION" in finding_type or "SPRAY" in finding_type:
            return "CREDENTIAL_ACCESS"
        if "COMPROMISE" in finding_type:
            return "INITIAL_ACCESS"
        if "ACCESS_DENIED" in finding_type:
            return "RECONNAISSANCE"

    event_type = str(event.get("event_type", "")).upper()
    message = str(event.get("message", "")).lower()

    if event_type == "ACCESS_CONTROL":
        if "session opened" in message or "root" in message or "admin" in message:
            return "PRIVILEGE_ESCALATION"
        return "RECONNAISSANCE"

    if event_type == "AUTHENTICATION":
        if "fail" in message or "invalid" in message:
            return "CREDENTIAL_ACCESS"
        if "accepted" in message or "success" in message:
            return "INITIAL_ACCESS"

    if event_type == "SYSTEM":
        if any(term in message for term in ("panic", "segfault", "shutdown", "terminated", "kill")):
            return "IMPACT"
        return "EXECUTION"

    return "GENERAL_ACTIVITY"


class TimelineMilestone:
    """Represents a single consolidated node on the attack timeline."""

    def __init__(
        self,
        timestamp: str,
        source_id: str,
        event_type: str,
        severity: str,
        message: str,
        phase: str,
        event_id: Optional[str] = None,
        related_event_ids: Optional[List[str]] = None,
        correlation_explanation: Optional[str] = None,
        is_corrupted_timestamp: bool = False,
    ) -> None:
        self.timestamp = timestamp
        self.source_id = source_id
        self.event_type = event_type
        self.severity = severity
        self.message = message
        self.phase = phase
        self.event_id = event_id
        self.related_event_ids = related_event_ids or []
        self.correlation_explanation = correlation_explanation
        self.is_corrupted_timestamp = is_corrupted_timestamp

    def to_dict(self) -> Dict[str, Any]:
        """Convert milestone to JSON-serializable dictionary."""
        return {
            "timestamp": self.timestamp,
            "source_id": self.source_id,
            "event_type": self.event_type,
            "severity": self.severity,
            "message": self.message,
            "phase": self.phase,
            "event_id": self.event_id,
            "related_event_ids": self.related_event_ids,
            "correlation_explanation": self.correlation_explanation,
            "timestamp_inferred": self.is_corrupted_timestamp,
        }


class AttackTimelineReconstructor:
    """Reconstructs, enriches, and structures attack timelines from logs and findings."""

    def __init__(self, correlator: Optional[EventCorrelator] = None) -> None:
        self.correlator = correlator or EventCorrelator()

    def build_timeline(
        self,
        events: List[Dict[str, Any]],
        correlation_findings: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Generate a structured, chronological attack timeline.

        :param events: Raw or normalized log events.
        :param correlation_findings: Optional precomputed correlation findings.
        :return: Timeline structure with metrics, phases, and chronological milestones.
        """
        if not events:
            return {
                "total_events": 0,
                "milestone_count": 0,
                "affected_sources": [],
                "duration_seconds": 0.0,
                "timeline": [],
                "phases_detected": [],
            }

        # 1. Sort events chronologically (handling malformed/missing timestamps safely)
        sorted_events = sorted(
            events,
            key=lambda ev: parse_timestamp_safe(ev)[0],
        )

        # 2. Correlate if findings not explicitly provided
        findings = (
            correlation_findings
            if correlation_findings is not None
            else self.correlator.correlate(sorted_events)
        )

        # Index findings by event_id for fast enrichment
        finding_by_event_id: Dict[str, Dict[str, Any]] = {}
        for f in findings:
            for eid in f.get("event_ids", []):
                finding_by_event_id[eid] = f

        # 3. Construct chronological timeline nodes
        milestones: List[TimelineMilestone] = []
        phases_detected: Set[str] = set()
        affected_sources: Set[str] = set()
        valid_timestamps: List[datetime.datetime] = []

        for ev in sorted_events:
            dt, is_valid_ts = parse_timestamp_safe(ev)
            if is_valid_ts:
                valid_timestamps.append(dt)

            eid = ev.get("event_id")
            source_id = str(ev.get("source_id", "unknown-source"))
            affected_sources.add(source_id)

            associated_finding = finding_by_event_id.get(eid)
            finding_type = associated_finding.get("finding_type") if associated_finding else None
            phase = infer_attack_phase(ev, finding_type=finding_type)
            phases_detected.add(phase)

            related_ids = (
                [x for x in associated_finding.get("event_ids", []) if x != eid]
                if associated_finding
                else []
            )
            explanation = (
                associated_finding.get("explanation")
                if associated_finding
                else None
            )

            ts_str = (
                dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                if is_valid_ts
                else "UNKNOWN_OR_MALFORMED"
            )

            milestone = TimelineMilestone(
                timestamp=ts_str,
                source_id=source_id,
                event_type=str(ev.get("event_type", "SYSTEM")),
                severity=str(ev.get("severity", "INFO")),
                message=str(ev.get("message", "")),
                phase=phase,
                event_id=eid,
                related_event_ids=related_ids,
                correlation_explanation=explanation,
                is_corrupted_timestamp=not is_valid_ts,
            )
            milestones.append(milestone)

        # 4. Compute timeline duration
        duration_seconds = 0.0
        start_time_str = None
        end_time_str = None
        if valid_timestamps:
            first_ts = valid_timestamps[0]
            last_ts = valid_timestamps[-1]
            duration_seconds = max(0.0, (last_ts - first_ts).total_seconds())
            start_time_str = first_ts.strftime("%Y-%m-%dT%H:%M:%SZ")
            end_time_str = last_ts.strftime("%Y-%m-%dT%H:%M:%SZ")

        return {
            "total_events": len(events),
            "milestone_count": len(milestones),
            "affected_sources": sorted(affected_sources),
            "incident_start": start_time_str,
            "incident_end": end_time_str,
            "duration_seconds": round(duration_seconds, 2),
            "phases_detected": sorted(phases_detected),
            "correlation_findings_count": len(findings),
            "timeline": [m.to_dict() for m in milestones],
        }
