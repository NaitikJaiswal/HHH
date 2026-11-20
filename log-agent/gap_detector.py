"""LOGN Sequence Gap and Collector Monitoring Detector

Monitors log sequence numbers and collector heartbeats to identify missing
sequence numbers, unexpected sequence jumps, transmission delays, and collector
interruptions. Produces objective diagnostic alerts without premature attribution.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


def _parse_iso_utc(ts_str: Optional[str]) -> Optional[datetime.datetime]:
    """Safely parse an ISO 8601 UTC timestamp string."""
    if not ts_str or not isinstance(ts_str, str):
        return None
    clean = ts_str.strip()
    try:
        if clean.endswith("Z"):
            return datetime.datetime.fromisoformat(clean[:-1] + "+00:00")
        return datetime.datetime.fromisoformat(clean)
    except ValueError:
        return None


@dataclass
class SourceStreamState:
    """State tracked for an individual log source stream."""

    source_id: str
    last_sequence: Optional[int] = None
    last_event_time: Optional[datetime.datetime] = None
    last_heartbeat_time: Optional[datetime.datetime] = None
    total_events_processed: int = 0
    total_gaps_detected: int = 0
    recent_sequences: Set[int] = field(default_factory=set)


class GapDetector:
    """Detects sequence anomalies, missing event ranges, and heartbeat interruptions."""

    def __init__(
        self,
        max_heartbeat_gap_seconds: float = 90.0,
        max_transmission_delay_seconds: float = 300.0,
        recent_window_size: int = 500,
    ) -> None:
        self.max_heartbeat_gap_seconds = max_heartbeat_gap_seconds
        self.max_transmission_delay_seconds = max_transmission_delay_seconds
        self.recent_window_size = recent_window_size
        self._streams: Dict[str, SourceStreamState] = {}

    def get_or_create_stream(self, source_id: str) -> SourceStreamState:
        """Get or initialize the tracking state for a source."""
        if source_id not in self._streams:
            self._streams[source_id] = SourceStreamState(source_id=source_id)
        return self._streams[source_id]

    def process_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Evaluate an incoming event for sequence gaps, regressions, and latency delays.

        :param event: Standardized log event.
        :return: List of diagnostic alert dictionaries (empty if normal).
        """
        alerts: List[Dict[str, Any]] = []
        if not isinstance(event, dict):
            return alerts

        source_id = str(event.get("source_id") or "unknown-source")
        seq = event.get("sequence_number")
        if not isinstance(seq, int):
            return alerts

        stream = self.get_or_create_stream(source_id)
        stream.total_events_processed += 1
        now_utc_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # 1. Sequence Gap & Continuity Analysis
        if stream.last_sequence is None:
            # First event observed for this stream
            stream.last_sequence = seq
            stream.recent_sequences.add(seq)
        elif seq == stream.last_sequence + 1:
            # Expected normal consecutive sequence
            stream.last_sequence = seq
            stream.recent_sequences.add(seq)
        elif seq > stream.last_sequence + 1:
            # Sequence Jump / Missing Gap
            missing_start = stream.last_sequence + 1
            missing_end = seq - 1
            gap_size = seq - stream.last_sequence - 1
            stream.total_gaps_detected += gap_size

            alerts.append({
                "alert_type": "MISSING_SEQUENCE_GAP",
                "severity": "WARNING",
                "source_id": source_id,
                "event_id": event.get("event_id"),
                "expected_sequence": missing_start,
                "observed_sequence": seq,
                "missing_range": [missing_start, missing_end],
                "gap_size": gap_size,
                "timestamp": now_utc_str,
                "explanation": (
                    f"Sequence gap of {gap_size} missing event(s) detected on '{source_id}'. "
                    f"Expected sequence {missing_start}, received {seq}. "
                    "Indicates possible network interruption, log-agent crash, or uncollected event."
                ),
            })
            stream.last_sequence = seq
            stream.recent_sequences.add(seq)
        elif seq in stream.recent_sequences:
            # Duplicate sequence number
            alerts.append({
                "alert_type": "DUPLICATE_SEQUENCE",
                "severity": "WARNING",
                "source_id": source_id,
                "event_id": event.get("event_id"),
                "sequence_number": seq,
                "timestamp": now_utc_str,
                "explanation": (
                    f"Duplicate sequence number {seq} received from '{source_id}'. "
                    "May indicate queue re-transmission or redundant delivery."
                ),
            })
        else:
            # Out of order or sequence regression
            alerts.append({
                "alert_type": "SEQUENCE_REGRESSION",
                "severity": "WARNING",
                "source_id": source_id,
                "event_id": event.get("event_id"),
                "observed_sequence": seq,
                "current_high_sequence": stream.last_sequence,
                "timestamp": now_utc_str,
                "explanation": (
                    f"Sequence regression on '{source_id}'. Received sequence {seq} "
                    f"after having already processed sequence {stream.last_sequence}. "
                    "Indicates out-of-order delivery or collector restart with reset counter."
                ),
            })

        # Trim recent sequences set
        if len(stream.recent_sequences) > self.recent_window_size:
            stream.recent_sequences.clear()
            stream.recent_sequences.add(seq)

        # 2. Transmission Latency / Delay Analysis
        event_time = _parse_iso_utc(event.get("event_time"))
        observed_at = _parse_iso_utc(event.get("observed_at"))
        if event_time and observed_at:
            stream.last_event_time = event_time
            delay_seconds = (observed_at - event_time).total_seconds()
            if delay_seconds > self.max_transmission_delay_seconds:
                alerts.append({
                    "alert_type": "TRANSMISSION_DELAY",
                    "severity": "INFO",
                    "source_id": source_id,
                    "event_id": event.get("event_id"),
                    "sequence_number": seq,
                    "delay_seconds": round(delay_seconds, 2),
                    "threshold_seconds": self.max_transmission_delay_seconds,
                    "timestamp": now_utc_str,
                    "explanation": (
                        f"Event from '{source_id}' was delayed by {round(delay_seconds, 1)} seconds "
                        f"before ingestion. Consistent with offline queue buffering or network delay."
                    ),
                })

        return alerts

    def process_heartbeat(self, heartbeat: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Evaluate a collector heartbeat for communication gaps.

        Note: A heartbeat gap indicates a possible collection interruption;
        it does not independently prove an attack or intentional tampering.
        """
        alerts: List[Dict[str, Any]] = []
        if not isinstance(heartbeat, dict):
            return alerts

        host_id = str(heartbeat.get("host_id") or heartbeat.get("collector_id") or "unknown-host")
        hb_timestamp = _parse_iso_utc(heartbeat.get("timestamp"))
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        now_utc_str = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

        stream = self.get_or_create_stream(host_id)

        if hb_timestamp and stream.last_heartbeat_time:
            gap_seconds = (hb_timestamp - stream.last_heartbeat_time).total_seconds()
            if gap_seconds > self.max_heartbeat_gap_seconds:
                alerts.append({
                    "alert_type": "HEARTBEAT_GAP",
                    "severity": "WARNING",
                    "source_id": host_id,
                    "gap_seconds": round(gap_seconds, 2),
                    "threshold_seconds": self.max_heartbeat_gap_seconds,
                    "timestamp": now_utc_str,
                    "explanation": (
                        f"Collector heartbeat gap of {round(gap_seconds, 1)} seconds detected for '{host_id}'. "
                        "A heartbeat gap indicates a possible collection interruption or network partition. "
                        "It does not independently prove an attack or intentional tampering."
                    ),
                })

        if hb_timestamp:
            stream.last_heartbeat_time = hb_timestamp
        else:
            stream.last_heartbeat_time = now_utc

        return alerts

    def check_stale_collectors(
        self, current_time: Optional[datetime.datetime] = None
    ) -> List[Dict[str, Any]]:
        """Check all registered streams for missing heartbeats (collector silence)."""
        alerts: List[Dict[str, Any]] = []
        now = current_time or datetime.datetime.now(datetime.timezone.utc)
        now_utc_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")

        for source_id, stream in self._streams.items():
            if stream.last_heartbeat_time:
                elapsed = (now - stream.last_heartbeat_time).total_seconds()
                if elapsed > self.max_heartbeat_gap_seconds:
                    alerts.append({
                        "alert_type": "COLLECTOR_SILENCE",
                        "severity": "WARNING",
                        "source_id": source_id,
                        "elapsed_seconds": round(elapsed, 2),
                        "threshold_seconds": self.max_heartbeat_gap_seconds,
                        "timestamp": now_utc_str,
                        "explanation": (
                            f"Collector '{source_id}' has been silent for {round(elapsed, 1)}s "
                            f"(exceeds threshold of {self.max_heartbeat_gap_seconds}s). "
                            "Indicates potential agent downtime, host shutdown, or communication failure."
                        ),
                    })

        return alerts

    def get_stream_summary(self, source_id: str) -> Optional[Dict[str, Any]]:
        """Return diagnostic metrics for a specific source stream."""
        stream = self._streams.get(source_id)
        if not stream:
            return None

        return {
            "source_id": stream.source_id,
            "last_sequence": stream.last_sequence,
            "total_events_processed": stream.total_events_processed,
            "total_gaps_detected": stream.total_gaps_detected,
            "last_heartbeat_time": (
                stream.last_heartbeat_time.strftime("%Y-%m-%dT%H:%M:%SZ")
                if stream.last_heartbeat_time
                else None
            ),
        }
