"""Windows Event Log Adapter for LOGN

Collects event records from Windows channels (Application, System, Security)
using wevtutil or PowerShell, with graceful fallbacks and simulated event generation.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from . import BaseLogAdapter


class WindowsEventLogAdapter(BaseLogAdapter):
    """Adapter for querying and normalizing Windows Event Logs."""

    def __init__(
        self,
        channels: Optional[List[str]] = None,
        max_events_per_channel: int = 10,
        enable_simulation_fallback: bool = True,
    ) -> None:
        super().__init__(name="windows_event_log")
        self.channels = channels or ["Application", "System"]
        self.max_events_per_channel = max_events_per_channel
        self.enable_simulation_fallback = enable_simulation_fallback

    def is_available(self) -> bool:
        """Return True if running on Windows and wevtutil CLI tool is discoverable."""
        if not sys.platform.startswith("win"):
            return False
        return shutil.which("wevtutil") is not None

    def _parse_xml_event(self, xml_string: str) -> Optional[Dict[str, Any]]:
        """Parse an individual Windows Event XML block into a structured record."""
        try:
            root = ET.fromstring(xml_string)
            # Remove XML namespace prefix if present
            ns = ""
            if root.tag.startswith("{"):
                ns = root.tag.split("}")[0] + "}"

            system_node = root.find(f"{ns}System")
            if system_node is None:
                return None

            event_id_elem = system_node.find(f"{ns}EventID")
            event_id = event_id_elem.text if event_id_elem is not None else "0"

            provider_elem = system_node.find(f"{ns}Provider")
            provider_name = (
                provider_elem.attrib.get("Name", "UnknownProvider")
                if provider_elem is not None
                else "UnknownProvider"
            )

            channel_elem = system_node.find(f"{ns}Channel")
            channel = channel_elem.text if channel_elem is not None else "UnknownChannel"

            level_elem = system_node.find(f"{ns}Level")
            level_code = level_elem.text if level_elem is not None else "4"

            # Map Windows event level codes
            severity_map = {
                "1": "CRITICAL",
                "2": "ERROR",
                "3": "WARNING",
                "4": "INFO",
                "5": "DEBUG",
                "0": "INFO",
            }
            severity = severity_map.get(level_code, "INFO")

            # Determine high-level event type
            if channel.lower() == "security" or event_id in ("4624", "4625", "4672", "4720"):
                event_type = "AUTHENTICATION"
            elif severity in ("ERROR", "CRITICAL"):
                event_type = "SYSTEM"
            else:
                event_type = "APPLICATION" if channel.lower() == "application" else "SYSTEM"

            message = f"[{channel}] {provider_name} Event ID {event_id}"

            # Extract optional event data strings
            event_data_dict: Dict[str, Any] = {
                "windows_event_id": event_id,
                "provider_name": provider_name,
                "channel": channel,
                "level_code": level_code,
            }

            event_data_node = root.find(f"{ns}EventData")
            if event_data_node is not None:
                for data_child in event_data_node.findall(f"{ns}Data"):
                    data_name = data_child.attrib.get("Name")
                    if data_name and data_child.text:
                        event_data_dict[data_name] = data_child.text

            return {
                "event_type": event_type,
                "severity": severity,
                "message": message,
                "metadata": event_data_dict,
            }
        except ET.ParseError:
            return None

    def query_channel_events(self, channel: str) -> List[Dict[str, Any]]:
        """Query recent events from a specific Windows Event Log channel using wevtutil."""
        if not self.is_available():
            return []

        cmd = [
            "wevtutil",
            "qe",
            channel,
            f"/c:{self.max_events_per_channel}",
            "/rd:true",
            "/f:RenderedXml",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode != 0 or not result.stdout.strip():
                return []

            # wevtutil returns multiple <Event ...> tags wrapped or adjacent
            xml_content = result.stdout
            events: List[Dict[str, Any]] = []

            # Split adjacent XML roots by matching <Event ... </Event>
            event_matches = re_xml_events(xml_content)
            for event_xml in event_matches:
                parsed = self._parse_xml_event(event_xml)
                if parsed:
                    events.append(parsed)

            return events
        except (subprocess.SubprocessError, OSError):
            return []

    def get_simulated_events(self) -> List[Dict[str, Any]]:
        """Generate simulated Windows Event Log events for non-elevated or cross-platform testing."""
        return [
            {
                "event_type": "AUTHENTICATION",
                "severity": "WARNING",
                "message": "[Security] Microsoft-Windows-Security-Auditing Event ID 4625",
                "metadata": {
                    "windows_event_id": "4625",
                    "provider_name": "Microsoft-Windows-Security-Auditing",
                    "channel": "Security",
                    "TargetUserName": "Administrator",
                    "FailureReason": "Unknown user name or bad password",
                    "simulated": True,
                },
            },
            {
                "event_type": "SYSTEM",
                "severity": "INFO",
                "message": "[System] Service Control Manager Event ID 7036",
                "metadata": {
                    "windows_event_id": "7036",
                    "provider_name": "Service Control Manager",
                    "channel": "System",
                    "param1": "Windows Defender Antivirus Service",
                    "param2": "running",
                    "simulated": True,
                },
            },
        ]

    def collect(self) -> List[Dict[str, Any]]:
        """Collect events across configured channels, falling back to simulated records if unavailable."""
        all_events: List[Dict[str, Any]] = []

        if self.is_available():
            for channel in self.channels:
                channel_events = self.query_channel_events(channel)
                all_events.extend(channel_events)

        if not all_events and self.enable_simulation_fallback:
            all_events = self.get_simulated_events()

        return all_events


def re_xml_events(xml_text: str) -> List[str]:
    """Helper to extract individual <Event ... </Event> blocks from raw XML output."""
    blocks: List[str] = []
    start_tag = "<Event"
    end_tag = "</Event>"

    pos = 0
    while True:
        start_idx = xml_text.find(start_tag, pos)
        if start_idx == -1:
            break
        end_idx = xml_text.find(end_tag, start_idx)
        if end_idx == -1:
            break
        end_idx += len(end_tag)
        blocks.append(xml_text[start_idx:end_idx])
        pos = end_idx

    return blocks
