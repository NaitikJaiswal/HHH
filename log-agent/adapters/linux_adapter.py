"""Linux Log Adapter for LOGN

Collects system and authentication events from standard Linux log files
(/var/log/syslog, /var/log/auth.log, /var/log/messages) or systemd journalctl,
with robust regex parsing and graceful simulated fallbacks.
"""

from __future__ import annotations

import os
import re
import sys
from typing import Any, Dict, List, Optional

from . import BaseLogAdapter

# Standard RFC 3164 syslog format: "Oct 11 22:14:15 mymachine su[123]: 'su root' failed for lonvick"
SYSLOG_REGEX = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<program>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)


class LinuxLogAdapter(BaseLogAdapter):
    """Adapter for reading and parsing Linux syslog and authentication logs."""

    DEFAULT_LOG_PATHS = [
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/syslog",
        "/var/log/messages",
    ]

    def __init__(
        self,
        log_paths: Optional[List[str]] = None,
        max_lines: int = 50,
        enable_simulation_fallback: bool = True,
    ) -> None:
        super().__init__(name="linux_log")
        self.log_paths = log_paths or self.DEFAULT_LOG_PATHS
        self.max_lines = max_lines
        self.enable_simulation_fallback = enable_simulation_fallback

    def is_available(self) -> bool:
        """Check if running on Linux or if any configured log paths exist and are readable."""
        if sys.platform.startswith("linux"):
            return True
        return any(os.path.exists(p) and os.access(p, os.R_OK) for p in self.log_paths)

    def parse_syslog_line(self, line: str, source_path: str = "syslog") -> Dict[str, Any]:
        """Parse a single syslog line into a structured record."""
        match = SYSLOG_REGEX.match(line.strip())
        if match:
            groups = match.groupdict()
            msg = groups["message"]
            program = groups["program"]
            pid = groups.get("pid")
            host = groups["hostname"]
        else:
            msg = line.strip()
            program = "kernel"
            pid = None
            host = "localhost"

        # Determine event type and severity based on content keywords
        msg_lower = msg.lower()
        if any(term in msg_lower for term in ("failed password", "authentication failure", "invalid user", "accepted password")):
            event_type = "AUTHENTICATION"
            severity = "WARNING" if "fail" in msg_lower or "invalid" in msg_lower else "INFO"
        elif any(term in msg_lower for term in ("sudo:", "su:", "session opened", "session closed")):
            event_type = "ACCESS_CONTROL"
            severity = "INFO"
        elif any(term in msg_lower for term in ("error", "segfault", "panic", "critical")):
            event_type = "SYSTEM"
            severity = "ERROR"
        else:
            event_type = "SYSTEM"
            severity = "INFO"

        return {
            "event_type": event_type,
            "severity": severity,
            "message": f"{program}: {msg}",
            "metadata": {
                "source_file": source_path,
                "program": program,
                "pid": pid,
                "hostname": host,
            },
        }

    def read_log_file(self, path: str) -> List[Dict[str, Any]]:
        """Safely read trailing lines from a Linux log file."""
        if not os.path.exists(path) or not os.access(path, os.R_OK):
            return []

        events: List[Dict[str, Any]] = []
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
                for line in lines[-self.max_lines:]:
                    stripped = line.strip()
                    if stripped:
                        events.append(self.parse_syslog_line(stripped, source_path=path))
        except (IOError, PermissionError):
            return []

        return events

    def get_simulated_events(self) -> List[Dict[str, Any]]:
        """Generate simulated Linux authentication and system events for testing."""
        return [
            {
                "event_type": "AUTHENTICATION",
                "severity": "WARNING",
                "message": "sshd: Failed password for invalid user admin from 192.0.2.45 port 54322 ssh2",
                "metadata": {
                    "source_file": "/var/log/auth.log",
                    "program": "sshd",
                    "pid": "10432",
                    "source_ip": "192.0.2.45",
                    "username": "admin",
                    "simulated": True,
                },
            },
            {
                "event_type": "ACCESS_CONTROL",
                "severity": "INFO",
                "message": "sudo: pam_unix(sudo:session): session opened for user root by ubuntu(uid=1000)",
                "metadata": {
                    "source_file": "/var/log/auth.log",
                    "program": "sudo",
                    "pid": "10550",
                    "target_user": "root",
                    "invoking_user": "ubuntu",
                    "simulated": True,
                },
            },
        ]

    def collect(self) -> List[Dict[str, Any]]:
        """Collect events from readable log files, falling back to simulated records if unavailable."""
        all_events: List[Dict[str, Any]] = []

        for path in self.log_paths:
            events = self.read_log_file(path)
            all_events.extend(events)

        if not all_events and self.enable_simulation_fallback:
            all_events = self.get_simulated_events()

        return all_events
