"""Application Log Adapter for LOGN

Collects and parses application logs, web server access logs (Common/Combined Log Format),
and JSON-structured application logs.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional

from . import BaseLogAdapter

# Combined Log Format regex for Apache / Nginx
# 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
COMBINED_LOG_REGEX = re.compile(
    r'^(?P<client_ip>\S+)\s+\S+\s+(?P<auth_user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<uri>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\S+)'
)


class ApplicationLogAdapter(BaseLogAdapter):
    """Adapter for ingesting and structuring application and web service logs."""

    def __init__(
        self,
        log_files: Optional[List[str]] = None,
        max_lines_per_file: int = 50,
        enable_simulation_fallback: bool = True,
    ) -> None:
        super().__init__(name="application_log")
        self.log_files = log_files or []
        self.max_lines_per_file = max_lines_per_file
        self.enable_simulation_fallback = enable_simulation_fallback

    def is_available(self) -> bool:
        """Available if any configured application log file exists or if simulation is enabled."""
        if any(os.path.exists(p) for p in self.log_files):
            return True
        return self.enable_simulation_fallback

    def parse_line(self, line: str, source_path: str = "app.log") -> Dict[str, Any]:
        """Parse a single log line (JSON, Combined Log Format, or plain text)."""
        stripped = line.strip()

        # Try parsing as JSON first
        if stripped.startswith("{") and stripped.endswith("}"):
            try:
                data = json.loads(stripped)
                if isinstance(data, dict):
                    severity = str(data.get("level") or data.get("severity") or "INFO").upper()
                    message = str(data.get("message") or data.get("msg") or stripped)
                    return {
                        "event_type": "APPLICATION",
                        "severity": severity if severity in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL") else "INFO",
                        "message": message,
                        "metadata": {
                            "source_file": source_path,
                            "format": "json",
                            **{k: v for k, v in data.items() if k not in ("level", "severity", "message", "msg")},
                        },
                    }
            except json.JSONDecodeError:
                pass

        # Try parsing as Web Server Combined Log Format
        clf_match = COMBINED_LOG_REGEX.match(stripped)
        if clf_match:
            groups = clf_match.groupdict()
            status_code = int(groups["status"])
            severity = "WARNING" if 400 <= status_code < 500 else ("ERROR" if status_code >= 500 else "INFO")
            event_type = "ACCESS_CONTROL" if status_code in (401, 403) else "APPLICATION"
            message = f"{groups['method']} {groups['uri']} - HTTP {status_code}"

            return {
                "event_type": event_type,
                "severity": severity,
                "message": message,
                "metadata": {
                    "source_file": source_path,
                    "format": "combined_log",
                    "client_ip": groups["client_ip"],
                    "http_method": groups["method"],
                    "uri": groups["uri"],
                    "status_code": status_code,
                    "bytes_sent": groups["bytes"],
                },
            }

        # Plain text log line
        upper = stripped.upper()
        severity = "INFO"
        if "ERROR" in upper or "EXCEPTION" in upper or "CRITICAL" in upper:
            severity = "ERROR"
        elif "WARN" in upper:
            severity = "WARNING"
        elif "DEBUG" in upper:
            severity = "DEBUG"

        return {
            "event_type": "APPLICATION",
            "severity": severity,
            "message": stripped,
            "metadata": {
                "source_file": source_path,
                "format": "plain_text",
            },
        }

    def get_simulated_events(self) -> List[Dict[str, Any]]:
        """Return simulated application log events for demonstrations or standalone testing."""
        return [
            {
                "event_type": "APPLICATION",
                "severity": "INFO",
                "message": "POST /api/v1/auth/login - HTTP 200",
                "metadata": {
                    "source_file": "access.log",
                    "format": "combined_log",
                    "client_ip": "192.0.2.100",
                    "http_method": "POST",
                    "uri": "/api/v1/auth/login",
                    "status_code": 200,
                    "simulated": True,
                },
            },
            {
                "event_type": "ACCESS_CONTROL",
                "severity": "WARNING",
                "message": "GET /api/v1/admin/vault - HTTP 403",
                "metadata": {
                    "source_file": "access.log",
                    "format": "combined_log",
                    "client_ip": "198.51.100.22",
                    "http_method": "GET",
                    "uri": "/api/v1/admin/vault",
                    "status_code": 403,
                    "simulated": True,
                },
            },
        ]

    def collect(self) -> List[Dict[str, Any]]:
        """Collect events from configured files, falling back to simulated records if unavailable."""
        all_events: List[Dict[str, Any]] = []

        for path in self.log_files:
            if os.path.exists(path) and os.access(path, os.R_OK):
                try:
                    with open(path, "r", encoding="utf-8", errors="replace") as f:
                        lines = f.readlines()
                        for line in lines[-self.max_lines_per_file:]:
                            stripped = line.strip()
                            if stripped:
                                all_events.append(self.parse_line(stripped, source_path=path))
                except (IOError, PermissionError):
                    continue

        if not all_events and self.enable_simulation_fallback:
            all_events = self.get_simulated_events()

        return all_events
