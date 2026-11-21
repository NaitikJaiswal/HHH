"""LOGN Forensic Event Correlation Engine

Identifies related log events, correlates multi-stage suspicious activity
across sources and time windows, and produces transparent, evidence-backed findings.
"""

from __future__ import annotations

import datetime
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Set, Tuple


def _parse_event_time(event: Dict[str, Any]) -> datetime.datetime:
    """Extract and parse event_time or observed_at to UTC datetime."""
    t_str = event.get("event_time") or event.get("observed_at")
    if isinstance(t_str, str):
        clean = t_str.strip()
        try:
            if clean.endswith("Z"):
                return datetime.datetime.fromisoformat(clean[:-1] + "+00:00")
            return datetime.datetime.fromisoformat(clean)
        except ValueError:
            pass
    return datetime.datetime.fromtimestamp(0, tz=datetime.timezone.utc)


def _get_entity_ip(event: Dict[str, Any]) -> Optional[str]:
    """Extract client/source IP from metadata if present."""
    metadata = event.get("metadata", {})
    if isinstance(metadata, dict):
        return (
            metadata.get("source_ip")
            or metadata.get("client_ip")
            or metadata.get("IpAddress")
            or metadata.get("ip")
        )
    return None


def _get_entity_user(event: Dict[str, Any]) -> Optional[str]:
    """Extract username from metadata if present."""
    metadata = event.get("metadata", {})
    if isinstance(metadata, dict):
        return (
            metadata.get("username")
            or metadata.get("user")
            or metadata.get("TargetUserName")
            or metadata.get("target_user")
        )
    return None


class BaseCorrelationRule(ABC):
    """Abstract base class for transparent correlation rules."""

    def __init__(self, name: str) -> None:
        self.name = name

    @abstractmethod
    def evaluate(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Evaluate chronologically sorted events and return correlation findings."""
        raise NotImplementedError


class BruteForceAuthenticationRule(BaseCorrelationRule):
    """Detects repeated authentication failures from the same IP or targeting the same user."""

    def __init__(
        self,
        failure_threshold: int = 3,
        window_seconds: float = 300.0,
    ) -> None:
        super().__init__(name="repeated_authentication_failures")
        self.failure_threshold = failure_threshold
        self.window_seconds = window_seconds

    def evaluate(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        # Filter authentication failures
        auth_failures: List[Tuple[datetime.datetime, Dict[str, Any]]] = []
        for ev in events:
            if ev.get("event_type") == "AUTHENTICATION":
                sev = ev.get("severity", "INFO")
                msg = str(ev.get("message", "")).lower()
                meta = ev.get("metadata", {})
                is_fail = (
                    sev in ("WARNING", "ERROR")
                    or "fail" in msg
                    or "invalid" in msg
                    or meta.get("status") == "FAILED"
                )
                if is_fail:
                    auth_failures.append((_parse_event_time(ev), ev))

        # Group by IP and user
        grouped: Dict[str, List[Tuple[datetime.datetime, Dict[str, Any]]]] = {}
        for dt, ev in auth_failures:
            ip = _get_entity_ip(ev) or "unknown_ip"
            user = _get_entity_user(ev) or "unknown_user"
            key = f"ip:{ip}|user:{user}"
            grouped.setdefault(key, []).append((dt, ev))

        for key, records in grouped.items():
            if len(records) < self.failure_threshold:
                continue

            # Sliding window check
            for i in range(len(records) - self.failure_threshold + 1):
                window_slice = records[i : i + self.failure_threshold]
                t_start = window_slice[0][0]
                t_end = window_slice[-1][0]
                duration = (t_end - t_start).total_seconds()

                if duration <= self.window_seconds:
                    event_ids = [r[1].get("event_id") for r in window_slice if r[1].get("event_id")]
                    first_ev = window_slice[0][1]
                    ip = _get_entity_ip(first_ev) or "unknown"
                    user = _get_entity_user(first_ev) or "unknown"

                    findings.append({
                        "finding_type": "REPEATED_AUTHENTICATION_FAILURES",
                        "rule_name": self.name,
                        "severity": "WARNING",
                        "entities": {"source_ip": ip, "target_user": user},
                        "event_count": len(window_slice),
                        "window_seconds": round(duration, 2),
                        "start_time": t_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "end_time": t_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "event_ids": event_ids,
                        "explanation": (
                            f"Observed {len(window_slice)} failed authentication attempts "
                            f"targeting user '{user}' from IP '{ip}' within {round(duration, 1)}s. "
                            "Consistent with credential guessing, password spraying, or misconfigured client."
                        ),
                    })
                    break  # Emit finding once per group to prevent redundant overlapping alerts

        return findings


class CompromiseSequenceRule(BaseCorrelationRule):
    """Detects multi-stage activity: authentication failures followed by successful authentication."""

    def __init__(self, failure_count: int = 2, max_gap_seconds: float = 300.0) -> None:
        super().__init__(name="brute_force_followed_by_success")
        self.failure_count = failure_count
        self.max_gap_seconds = max_gap_seconds

    def evaluate(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        # Track failure history per (ip, user)
        failures_by_key: Dict[str, List[Tuple[datetime.datetime, Dict[str, Any]]]] = {}

        for ev in events:
            if ev.get("event_type") != "AUTHENTICATION":
                continue

            dt = _parse_event_time(ev)
            sev = ev.get("severity", "INFO")
            msg = str(ev.get("message", "")).lower()
            ip = _get_entity_ip(ev) or "unknown_ip"
            user = _get_entity_user(ev) or "unknown_user"
            key = f"ip:{ip}|user:{user}"

            is_fail = sev in ("WARNING", "ERROR") or "fail" in msg or "invalid" in msg
            is_success = not is_fail and ("success" in msg or "accepted" in msg or "logged in" in msg or sev == "INFO")

            if is_fail:
                failures_by_key.setdefault(key, []).append((dt, ev))
            elif is_success and key in failures_by_key:
                recent_fails = failures_by_key[key]
                # Filter failures within max_gap_seconds of success
                applicable_fails = [
                    (f_dt, f_ev) for f_dt, f_ev in recent_fails
                    if 0 <= (dt - f_dt).total_seconds() <= self.max_gap_seconds
                ]

                if len(applicable_fails) >= self.failure_count:
                    fail_ids = [f[1].get("event_id") for f in applicable_fails]
                    success_id = ev.get("event_id")

                    findings.append({
                        "finding_type": "AUTHENTICATION_COMPROMISE_SEQUENCE",
                        "rule_name": self.name,
                        "severity": "CRITICAL",
                        "entities": {"source_ip": ip, "target_user": user},
                        "failure_count": len(applicable_fails),
                        "success_event_id": success_id,
                        "event_ids": [*fail_ids, success_id],
                        "timestamp": dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "explanation": (
                            f"Suspicious sequence on user '{user}' from IP '{ip}': "
                            f"{len(applicable_fails)} failed attempts immediately followed by successful logon. "
                            "Indicates probable successful unauthorized access after brute force or credential compromise."
                        ),
                    })
                    # Reset failure history for this entity
                    failures_by_key[key] = []

        return findings


class AccessDeniedBurstRule(BaseCorrelationRule):
    """Detects bursts of access denied / permission errors indicating unauthorized probing."""

    def __init__(self, threshold: int = 3, window_seconds: float = 120.0) -> None:
        super().__init__(name="access_denied_burst")
        self.threshold = threshold
        self.window_seconds = window_seconds

    def evaluate(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        denials: List[Tuple[datetime.datetime, Dict[str, Any]]] = []

        for ev in events:
            event_type = ev.get("event_type")
            sev = ev.get("severity")
            msg = str(ev.get("message", "")).lower()
            meta = ev.get("metadata", {})
            status_code = meta.get("status_code")

            if (
                event_type == "ACCESS_CONTROL"
                or sev in ("WARNING", "ERROR")
                or status_code in (401, 403)
                or "denied" in msg
                or "forbidden" in msg
            ):
                denials.append((_parse_event_time(ev), ev))

        if len(denials) >= self.threshold:
            for i in range(len(denials) - self.threshold + 1):
                slice_records = denials[i : i + self.threshold]
                t_start = slice_records[0][0]
                t_end = slice_records[-1][0]
                dur = (t_end - t_start).total_seconds()

                if dur <= self.window_seconds:
                    event_ids = [r[1].get("event_id") for r in slice_records if r[1].get("event_id")]
                    sources = list({r[1].get("source_id", "unknown") for r in slice_records})

                    findings.append({
                        "finding_type": "ACCESS_DENIED_BURST",
                        "rule_name": self.name,
                        "severity": "WARNING",
                        "event_count": len(slice_records),
                        "window_seconds": round(dur, 2),
                        "sources": sources,
                        "event_ids": event_ids,
                        "explanation": (
                            f"Burst of {len(slice_records)} access denied / authorization failures "
                            f"across source(s) {sources} within {round(dur, 1)}s. "
                            "May indicate privilege boundary testing, unauthorized access attempts, or expired credentials."
                        ),
                    })
                    break

        return findings


class EventCorrelator:
    """Forensic event correlation engine evaluating rule chains against log events."""

    def __init__(self, rules: Optional[List[BaseLogAdapter]] = None) -> None:
        self.rules: List[BaseCorrelationRule] = rules or [
            BruteForceAuthenticationRule(),
            CompromiseSequenceRule(),
            AccessDeniedBurstRule(),
        ]

    def add_rule(self, rule: BaseCorrelationRule) -> None:
        """Register an additional correlation rule."""
        self.rules.append(rule)

    def correlate(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Sort events chronologically and execute all correlation rules.

        :param events: List of standardized log events.
        :return: List of correlation findings with evidence citations.
        """
        if not events:
            return []

        # Sort chronologically by event_time
        sorted_events = sorted(events, key=_parse_event_time)

        all_findings: List[Dict[str, Any]] = []
        for rule in self.rules:
            try:
                rule_findings = rule.evaluate(sorted_events)
                all_findings.extend(rule_findings)
            except Exception as exc:
                all_findings.append({
                    "finding_type": "CORRELATION_ERROR",
                    "rule_name": rule.name,
                    "severity": "INFO",
                    "explanation": f"Rule evaluation encountered an error: {exc}",
                })

        return all_findings
