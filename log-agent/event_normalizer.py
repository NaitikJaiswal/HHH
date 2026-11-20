"""LOGN Event Normalizer

Normalizes heterogeneous and platform-specific log entries into the standard
LOGN JSON schema. Validates fields, normalizes timestamps and severity levels,
and handles malformed records safely without data loss.
"""

from __future__ import annotations

import datetime
import json
import re
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple, Union

SCHEMA_VERSION: str = "1.0"

# Standard valid event types
VALID_EVENT_TYPES: Set[str] = {
    "AUTHENTICATION",
    "AUTHORIZATION",
    "SYSTEM",
    "APPLICATION",
    "NETWORK",
    "ACCESS_CONTROL",
    "INTEGRITY",
    "AUDIT",
    "MALFORMED_RECORD",
}

# Standard valid severity levels
VALID_SEVERITIES: Set[str] = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}

# Mapping common alias representations to canonical severity levels
SEVERITY_ALIASES: Dict[str, str] = {
    "WARN": "WARNING",
    "ERR": "ERROR",
    "CRIT": "CRITICAL",
    "FATAL": "CRITICAL",
    "EMERG": "CRITICAL",
    "ALERT": "CRITICAL",
    "NOTICE": "INFO",
    "INFORMATIONAL": "INFO",
    "TRACE": "DEBUG",
    "VERBOSE": "DEBUG",
}

# Mapping common event type aliases
EVENT_TYPE_ALIASES: Dict[str, str] = {
    "AUTH": "AUTHENTICATION",
    "LOGIN": "AUTHENTICATION",
    "LOGON": "AUTHENTICATION",
    "APP": "APPLICATION",
    "SYS": "SYSTEM",
    "NET": "NETWORK",
    "SEC": "ACCESS_CONTROL",
    "ACL": "ACCESS_CONTROL",
}

UUID_REGEX: re.Pattern[str] = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


class NormalizationError(ValueError):
    """Raised when an event fails schema validation under strict mode."""


def parse_to_utc_iso8601(val: Any) -> str:
    """Parse various timestamp formats (datetime, ISO string, or numeric epoch)

    into strict ISO 8601 UTC string format: YYYY-MM-DDTHH:MM:SSZ.
    """
    if val is None:
        return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if isinstance(val, (int, float)):
        # Treat as Unix epoch timestamp (seconds or milliseconds)
        # If timestamp is > 1e11, it is in milliseconds
        seconds = val / 1000.0 if val > 1e11 else float(val)
        dt = datetime.datetime.fromtimestamp(seconds, tz=datetime.timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    if isinstance(val, datetime.datetime):
        if val.tzinfo is None:
            # Assume UTC if naive
            dt = val.replace(tzinfo=datetime.timezone.utc)
        else:
            dt = val.astimezone(datetime.timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    if isinstance(val, str):
        val_clean = val.strip()
        # Common ISO format with trailing Z
        if val_clean.endswith("Z"):
            try:
                dt = datetime.datetime.fromisoformat(val_clean[:-1] + "+00:00")
                return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            except ValueError:
                pass

        try:
            dt = datetime.datetime.fromisoformat(val_clean)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            else:
                dt = dt.astimezone(datetime.timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            pass

    # If parsing completely fails, return current UTC timestamp
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class EventNormalizer:
    """Validator and normalizer converting diverse log records to standard LOGN schema."""

    def __init__(self, default_source_id: str = "unknown-source") -> None:
        self.default_source_id = default_source_id

    def normalize_severity(self, severity_val: Any) -> str:
        """Normalize severity strings/aliases to canonical levels."""
        if not isinstance(severity_val, str):
            return "INFO"
        upper = severity_val.strip().upper()
        if upper in VALID_SEVERITIES:
            return upper
        return SEVERITY_ALIASES.get(upper, "INFO")

    def normalize_event_type(self, event_type_val: Any) -> str:
        """Normalize event types/aliases to canonical types."""
        if not isinstance(event_type_val, str):
            return "SYSTEM"
        upper = event_type_val.strip().upper()
        if upper in VALID_EVENT_TYPES:
            return upper
        return EVENT_TYPE_ALIASES.get(upper, "SYSTEM")

    def validate(self, event: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate whether a dictionary strictly conforms to the LOGN schema.

        Returns (is_valid, list_of_errors).
        """
        errors: List[str] = []

        if not isinstance(event, dict):
            return False, ["Event must be a dictionary object"]

        if event.get("schema_version") != SCHEMA_VERSION:
            errors.append(f"schema_version must be '{SCHEMA_VERSION}'")

        event_id = event.get("event_id")
        if not isinstance(event_id, str) or not UUID_REGEX.match(event_id):
            errors.append("event_id must be a valid UUID string")

        source_id = event.get("source_id")
        if not isinstance(source_id, str) or not source_id.strip():
            errors.append("source_id must be a non-empty string")

        seq_num = event.get("sequence_number")
        if not isinstance(seq_num, int) or seq_num < 0:
            errors.append("sequence_number must be a non-negative integer")

        for time_field in ("event_time", "observed_at"):
            t_val = event.get(time_field)
            if not isinstance(t_val, str) or not t_val.endswith("Z"):
                errors.append(f"{time_field} must be an ISO 8601 UTC string ending in 'Z'")

        if event.get("event_type") not in VALID_EVENT_TYPES:
            errors.append(f"event_type must be one of {sorted(VALID_EVENT_TYPES)}")

        if event.get("severity") not in VALID_SEVERITIES:
            errors.append(f"severity must be one of {sorted(VALID_SEVERITIES)}")

        if not isinstance(event.get("message"), str):
            errors.append("message must be a string")

        if not isinstance(event.get("metadata"), dict):
            errors.append("metadata must be a dictionary")

        return len(errors) == 0, errors

    def normalize(
        self,
        record: Union[Dict[str, Any], str],
        sequence_number: Optional[int] = None,
        strict: bool = False,
    ) -> Dict[str, Any]:
        """Normalize an arbitrary record into the LOGN schema.

        :param record: Raw log dictionary or JSON string.
        :param sequence_number: Sequence number to assign if missing in record.
        :param strict: When True, raises NormalizationError on unrecoverable input.
        :return: Standardized schema dictionary.
        """
        parsed_record: Dict[str, Any]

        if isinstance(record, str):
            try:
                parsed = json.loads(record)
                if isinstance(parsed, dict):
                    parsed_record = parsed
                else:
                    parsed_record = {"message": str(record)}
            except json.JSONDecodeError:
                if strict:
                    raise NormalizationError(f"Invalid JSON string: {record[:100]}")
                parsed_record = {"message": str(record)}
        elif isinstance(record, dict):
            parsed_record = record
        else:
            if strict:
                raise NormalizationError(f"Unsupported record type: {type(record)}")
            parsed_record = {"message": str(record)}

        # Resolve or generate event_id
        raw_id = parsed_record.get("event_id") or parsed_record.get("id")
        if isinstance(raw_id, str) and UUID_REGEX.match(raw_id):
            event_id = raw_id
        else:
            event_id = str(uuid.uuid4())

        # Resolve source_id
        source_id = str(
            parsed_record.get("source_id")
            or parsed_record.get("host")
            or parsed_record.get("hostname")
            or self.default_source_id
        ).strip()
        if not source_id:
            source_id = self.default_source_id

        # Resolve sequence number
        raw_seq = parsed_record.get("sequence_number") or sequence_number or 0
        try:
            seq_int = int(raw_seq)
            if seq_int < 0:
                seq_int = 0
        except (ValueError, TypeError):
            seq_int = 0

        # Resolve timestamps
        raw_event_time = (
            parsed_record.get("event_time")
            or parsed_record.get("timestamp")
            or parsed_record.get("@timestamp")
            or parsed_record.get("time")
        )
        event_time = parse_to_utc_iso8601(raw_event_time)

        raw_observed_at = parsed_record.get("observed_at")
        observed_at = parse_to_utc_iso8601(raw_observed_at)

        # Resolve type and severity
        raw_type = parsed_record.get("event_type") or parsed_record.get("type") or "SYSTEM"
        event_type = self.normalize_event_type(raw_type)

        raw_severity = (
            parsed_record.get("severity")
            or parsed_record.get("level")
            or parsed_record.get("loglevel")
            or "INFO"
        )
        severity = self.normalize_severity(raw_severity)

        # Resolve message
        message = str(
            parsed_record.get("message")
            or parsed_record.get("msg")
            or parsed_record.get("log")
            or ""
        )

        # Resolve metadata
        raw_metadata = parsed_record.get("metadata")
        if isinstance(raw_metadata, dict):
            metadata = dict(raw_metadata)
        else:
            # Capture non-standard keys as metadata
            standard_keys = {
                "schema_version",
                "event_id",
                "source_id",
                "sequence_number",
                "event_time",
                "observed_at",
                "event_type",
                "severity",
                "message",
                "metadata",
                "timestamp",
                "@timestamp",
                "host",
                "hostname",
                "level",
                "type",
            }
            metadata = {
                str(k): v
                for k, v in parsed_record.items()
                if k not in standard_keys
            }

        normalized_event = {
            "schema_version": SCHEMA_VERSION,
            "event_id": event_id,
            "source_id": source_id,
            "sequence_number": seq_int,
            "event_time": event_time,
            "observed_at": observed_at,
            "event_type": event_type,
            "severity": severity,
            "message": message,
            "metadata": metadata,
        }

        if strict:
            is_valid, validation_errors = self.validate(normalized_event)
            if not is_valid:
                raise NormalizationError(f"Validation failed: {', '.join(validation_errors)}")

        return normalized_event

    def normalize_batch(
        self,
        records: List[Any],
        start_sequence: Optional[int] = None,
        strict: bool = False,
    ) -> List[Dict[str, Any]]:
        """Normalize an iterable collection of records, maintaining continuous sequence."""
        normalized_list: List[Dict[str, Any]] = []
        current_seq = start_sequence

        for record in records:
            norm = self.normalize(record, sequence_number=current_seq, strict=strict)
            normalized_list.append(norm)
            if current_seq is not None:
                current_seq += 1

        return normalized_list
