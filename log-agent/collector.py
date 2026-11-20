"""LOGN Intelligent Log Collector

Collects structured system and application log events with reliable metadata,
UTC timestamps, source machine identification, sequence tracking, and automatic
redaction of sensitive fields.
"""

from __future__ import annotations

import datetime
import os
import re
import socket
import uuid
from typing import Any, Callable, Dict, List, Optional, Pattern, Set

# Standard severity levels recognized by LOGN
VALID_SEVERITIES: Set[str] = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}

# Standard event types
VALID_EVENT_TYPES: Set[str] = {
    "AUTHENTICATION",
    "AUTHORIZATION",
    "SYSTEM",
    "APPLICATION",
    "NETWORK",
    "ACCESS_CONTROL",
    "INTEGRITY",
    "AUDIT",
}

# Sensitive keys that must be redacted automatically from metadata
DEFAULT_SENSITIVE_PATTERNS: List[Pattern[str]] = [
    re.compile(r"pass(word)?", re.IGNORECASE),
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"token", re.IGNORECASE),
    re.compile(r"api[_-]?key", re.IGNORECASE),
    re.compile(r"auth(orization)?", re.IGNORECASE),
    re.compile(r"private[_-]?key", re.IGNORECASE),
    re.compile(r"credential", re.IGNORECASE),
    re.compile(r"ssn", re.IGNORECASE),
]

REDACTED_VALUE: str = "[REDACTED]"


class LogCollector:
    """Intelligent log collector responsible for gathering, enriching,
    and sanitizing log events from system and application sources.
    """

    def __init__(
        self,
        source_id: Optional[str] = None,
        initial_sequence: int = 1,
        redact_sensitive_fields: bool = True,
    ) -> None:
        """Initialize the LogCollector.

        :param source_id: Unique identifier for this host/machine (defaults to hostname).
        :param initial_sequence: Starting sequence number for sequence tracking.
        :param redact_sensitive_fields: Whether to scrub sensitive values from metadata.
        """
        self.source_id = source_id or socket.gethostname() or "unknown-host"
        self._sequence_number = initial_sequence
        self.redact_sensitive_fields = redact_sensitive_fields
        self._adapters: Dict[str, Callable[[], List[Dict[str, Any]]]] = {}

    @property
    def current_sequence(self) -> int:
        """Return the current sequence number."""
        return self._sequence_number

    def register_adapter(
        self, name: str, adapter_fn: Callable[[], List[Dict[str, Any]]]
    ) -> None:
        """Register a source adapter function that returns raw log records."""
        self._adapters[name] = adapter_fn

    def sanitize_metadata(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively scrub sensitive keys and credential patterns from metadata."""
        if not self.redact_sensitive_fields or not isinstance(metadata, dict):
            return metadata

        sanitized: Dict[str, Any] = {}
        for key, value in metadata.items():
            if any(pattern.search(str(key)) for pattern in DEFAULT_SENSITIVE_PATTERNS):
                sanitized[key] = REDACTED_VALUE
            elif isinstance(value, dict):
                sanitized[key] = self.sanitize_metadata(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    self.sanitize_metadata(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                sanitized[key] = value
        return sanitized

    def create_event(
        self,
        event_type: str,
        severity: str,
        message: str,
        metadata: Optional[Dict[str, Any]] = None,
        event_time: Optional[datetime.datetime] = None,
    ) -> Dict[str, Any]:
        """Create a single standardized, sanitized, and sequenced log event.

        :param event_type: Classification (e.g. AUTHENTICATION, SYSTEM).
        :param severity: Severity level (e.g. INFO, WARNING, ERROR).
        :param message: Human-readable description of the log event.
        :param metadata: Contextual dictionary (IP addresses, usernames, etc.).
        :param event_time: Time of the event occurrence (defaults to current UTC).
        :return: Standardized log event dictionary.
        """
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        event_timestamp = event_time or now_utc

        # Normalize severity and event type
        norm_severity = severity.upper() if isinstance(severity, str) else "INFO"
        if norm_severity not in VALID_SEVERITIES:
            norm_severity = "INFO"

        norm_event_type = event_type.upper() if isinstance(event_type, str) else "SYSTEM"
        if norm_event_type not in VALID_EVENT_TYPES:
            norm_event_type = "SYSTEM"

        clean_metadata = self.sanitize_metadata(metadata or {})

        event = {
            "schema_version": "1.0",
            "event_id": str(uuid.uuid4()),
            "source_id": self.source_id,
            "sequence_number": self._sequence_number,
            "event_time": event_timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "observed_at": now_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_type": norm_event_type,
            "severity": norm_severity,
            "message": str(message),
            "metadata": clean_metadata,
        }

        self._sequence_number += 1
        return event

    def collect_from_file(
        self,
        filepath: str,
        event_type: str = "APPLICATION",
        severity: str = "INFO",
        max_lines: int = 100,
    ) -> List[Dict[str, Any]]:
        """Safely read lines from a local log file and convert them to structured events.

        Gracefully handles missing files, permission errors, or IO failures.
        """
        events: List[Dict[str, Any]] = []

        if not os.path.exists(filepath):
            # Graceful warning event instead of unhandled crash
            events.append(
                self.create_event(
                    event_type="SYSTEM",
                    severity="WARNING",
                    message=f"Log file not found: {filepath}",
                    metadata={"filepath": filepath, "status": "FILE_NOT_FOUND"},
                )
            )
            return events

        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
                for line in lines[-max_lines:]:
                    stripped = line.strip()
                    if stripped:
                        events.append(
                            self.create_event(
                                event_type=event_type,
                                severity=severity,
                                message=stripped,
                                metadata={"filepath": filepath, "source_type": "file"},
                            )
                        )
        except (IOError, PermissionError) as exc:
            events.append(
                self.create_event(
                    event_type="SYSTEM",
                    severity="ERROR",
                    message=f"Failed to read log file {filepath}: {exc}",
                    metadata={"filepath": filepath, "error": str(exc)},
                )
            )

        return events

    def collect_from_adapters(self) -> List[Dict[str, Any]]:
        """Execute all registered source adapters and collect generated events safely."""
        collected: List[Dict[str, Any]] = []
        for name, adapter_fn in self._adapters.items():
            try:
                raw_records = adapter_fn()
                for record in raw_records:
                    event = self.create_event(
                        event_type=record.get("event_type", "SYSTEM"),
                        severity=record.get("severity", "INFO"),
                        message=record.get("message", ""),
                        metadata=record.get("metadata", {}),
                    )
                    collected.append(event)
            except Exception as exc:  # pylint: disable=broad-except
                collected.append(
                    self.create_event(
                        event_type="SYSTEM",
                        severity="ERROR",
                        message=f"Adapter {name} encountered an error: {exc}",
                        metadata={"adapter_name": name, "error": str(exc)},
                    )
                )
        return collected
