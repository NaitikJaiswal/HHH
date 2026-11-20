"""LOGN Explainable Anomaly Detection Engine

Detects behavioral and statistical log anomalies using transparent rules
and configurable thresholds. Avoids black-box claims and provides clear,
evidence-grounded explanations for every anomaly detection.
"""

from __future__ import annotations

import datetime
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple


def _parse_event_time(event: Dict[str, Any]) -> datetime.datetime:
    """Parse event_time or observed_at into UTC datetime."""
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


class AnomalyDetector:
    """Explainable anomaly detection with configurable statistical and schedule thresholds."""

    def __init__(
        self,
        business_hours_start: int = 8,
        business_hours_end: int = 18,
        allow_weekends: bool = False,
        volume_surge_multiplier: float = 3.0,
        min_surge_events: int = 10,
        max_failure_rate_threshold: float = 0.5,
        min_events_for_rate: int = 5,
    ) -> None:
        self.business_hours_start = business_hours_start
        self.business_hours_end = business_hours_end
        self.allow_weekends = allow_weekends
        self.volume_surge_multiplier = volume_surge_multiplier
        self.min_surge_events = min_surge_events
        self.max_failure_rate_threshold = max_failure_rate_threshold
        self.min_events_for_rate = min_events_for_rate

    def detect_off_hours_activity(
        self, events: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Identify events occurring outside configured business hours or on weekends."""
        anomalies: List[Dict[str, Any]] = []

        for ev in events:
            dt = _parse_event_time(ev)
            # Skip epoch fallback events
            if dt.year <= 1970:
                continue

            hour = dt.hour
            weekday = dt.weekday()  # 5 = Saturday, 6 = Sunday

            is_weekend = weekday >= 5
            is_off_hour = not (self.business_hours_start <= hour < self.business_hours_end)

            if (not self.allow_weekends and is_weekend) or is_off_hour:
                severity = "WARNING" if ev.get("severity") in ("WARNING", "ERROR", "CRITICAL") else "INFO"
                reason_parts = []
                if is_off_hour:
                    reason_parts.append(
                        f"occurred at hour {hour:02d}:00 UTC (outside window {self.business_hours_start:02d}:00-{self.business_hours_end:02d}:00)"
                    )
                if not self.allow_weekends and is_weekend:
                    reason_parts.append(f"occurred on weekend day {dt.strftime('%A')}")

                reason_str = " and ".join(reason_parts)
                anomalies.append({
                    "anomaly_type": "OFF_HOURS_ACTIVITY",
                    "severity": severity,
                    "event_id": ev.get("event_id"),
                    "source_id": ev.get("source_id"),
                    "event_type": ev.get("event_type"),
                    "timestamp": dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "observed_value": dt.strftime("%H:%M:%S UTC (%A)"),
                    "expected_threshold": f"{self.business_hours_start:02d}:00-{self.business_hours_end:02d}:00 UTC Mon-Fri",
                    "explanation": (
                        f"Event '{ev.get('message', '')}' from '{ev.get('source_id')}' {reason_str}. "
                        "Off-hours activities may represent scheduled batch tasks, remote user activity, or unauthorized operations."
                    ),
                })

        return anomalies

    def detect_volume_surges(
        self,
        events: List[Dict[str, Any]],
        bucket_minutes: int = 10,
    ) -> List[Dict[str, Any]]:
        """Identify sudden increases in event volume exceeding baseline multipliers."""
        anomalies: List[Dict[str, Any]] = []
        if len(events) < self.min_surge_events:
            return anomalies

        # Bucket events into discrete time windows
        bucket_counts: Dict[datetime.datetime, List[Dict[str, Any]]] = defaultdict(list)
        for ev in events:
            dt = _parse_event_time(ev)
            if dt.year <= 1970:
                continue
            bucket_minute = (dt.minute // bucket_minutes) * bucket_minutes
            bucket_key = dt.replace(minute=bucket_minute, second=0, microsecond=0)
            bucket_counts[bucket_key].append(ev)

        if len(bucket_counts) < 2:
            return anomalies

        sorted_buckets = sorted(bucket_counts.keys())

        for bucket in sorted_buckets:
            bucket_events = bucket_counts[bucket]
            count = len(bucket_events)

            # Calculate baseline from all other buckets
            other_counts = [len(bucket_counts[b]) for b in sorted_buckets if b != bucket]
            if not other_counts:
                continue
            avg_baseline = sum(other_counts) / len(other_counts)
            threshold = avg_baseline * self.volume_surge_multiplier

            if count >= self.min_surge_events and count >= threshold:
                surge_factor = round(count / (avg_baseline if avg_baseline > 0 else 1), 2)
                anomalies.append({
                    "anomaly_type": "EVENT_VOLUME_SURGE",
                    "severity": "WARNING",
                    "timestamp": bucket.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "window_minutes": bucket_minutes,
                    "observed_count": count,
                    "baseline_average": round(avg_baseline, 1),
                    "surge_factor": surge_factor,
                    "event_ids": [e.get("event_id") for e in bucket_events[:10] if e.get("event_id")],
                    "explanation": (
                        f"Event surge detected at {bucket.strftime('%Y-%m-%dT%H:%M:%SZ')}: "
                        f"Observed {count} events in a {bucket_minutes}-minute window "
                        f"({surge_factor}x baseline average of {round(avg_baseline, 1)}). "
                        "May indicate high-volume logging, brute-force scanning, or active service malfunction."
                    ),
                })

        return anomalies

    def detect_unusual_failure_rate(
        self,
        events: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Identify streams or sources exhibiting an abnormally high proportion of failure events."""
        anomalies: List[Dict[str, Any]] = []

        events_by_source: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for ev in events:
            source = str(ev.get("source_id", "unknown"))
            events_by_source[source].append(ev)

        for source, src_events in events_by_source.items():
            if len(src_events) < self.min_events_for_rate:
                continue

            failure_events = []
            for ev in src_events:
                sev = ev.get("severity")
                msg = str(ev.get("message", "")).lower()
                if sev in ("WARNING", "ERROR", "CRITICAL") or "fail" in msg or "error" in msg:
                    failure_events.append(ev)

            fail_rate = len(failure_events) / len(src_events)
            if fail_rate >= self.max_failure_rate_threshold:
                anomalies.append({
                    "anomaly_type": "UNUSUAL_FAILURE_FREQUENCY",
                    "severity": "WARNING",
                    "source_id": source,
                    "total_events": len(src_events),
                    "failure_count": len(failure_events),
                    "failure_rate": round(fail_rate, 2),
                    "threshold_rate": self.max_failure_rate_threshold,
                    "event_ids": [e.get("event_id") for e in failure_events[:10] if e.get("event_id")],
                    "explanation": (
                        f"Abnormally high failure frequency on source '{source}': "
                        f"{len(failure_events)} of {len(src_events)} events ({round(fail_rate * 100, 1)}%) "
                        f"were failures (threshold: {round(self.max_failure_rate_threshold * 100)}%). "
                        "Indicates repeated authentication failures, service degradation, or permission errors."
                    ),
                })

        return anomalies

    def analyze(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Run all explainable anomaly checks across a log event collection.

        :param events: List of log event dictionaries.
        :return: Summary dictionary of all detected anomalies with explanations.
        """
        off_hours = self.detect_off_hours_activity(events)
        surges = self.detect_volume_surges(events)
        failures = self.detect_unusual_failure_rate(events)

        all_anomalies = [*off_hours, *surges, *failures]

        return {
            "total_events_analyzed": len(events),
            "anomaly_count": len(all_anomalies),
            "breakdown": {
                "off_hours_activity": len(off_hours),
                "volume_surges": len(surges),
                "unusual_failure_frequency": len(failures),
            },
            "anomalies": all_anomalies,
        }
