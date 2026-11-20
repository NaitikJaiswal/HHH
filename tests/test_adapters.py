"""Unit tests for LOGN Log Adapters (Windows, Linux, Application)"""

import os
import sys
import tempfile
import unittest

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "log-agent"))

from adapters import (
    BaseLogAdapter,
    WindowsEventLogAdapter,
    LinuxLogAdapter,
    ApplicationLogAdapter,
    get_system_adapter,
)
from collector import LogCollector


class TestLogAdapters(unittest.TestCase):
    """Test suite for platform-specific and application log adapters."""

    def test_get_system_adapter_returns_base_adapter(self):
        """Verify the factory function returns a valid BaseLogAdapter."""
        adapter = get_system_adapter()
        self.assertIsInstance(adapter, BaseLogAdapter)
        self.assertTrue(isinstance(adapter.name, str))

    def test_windows_adapter_xml_parsing(self):
        """Verify Windows Event XML is properly parsed into structured record."""
        adapter = WindowsEventLogAdapter()
        sample_xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <Provider Name="Microsoft-Windows-Security-Auditing"/>
                <EventID>4625</EventID>
                <Level>3</Level>
                <Channel>Security</Channel>
            </System>
            <EventData>
                <Data Name="TargetUserName">Administrator</Data>
                <Data Name="IpAddress">10.0.0.15</Data>
            </EventData>
        </Event>"""

        parsed = adapter._parse_xml_event(sample_xml)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["event_type"], "AUTHENTICATION")
        self.assertEqual(parsed["severity"], "WARNING")
        self.assertEqual(parsed["metadata"]["windows_event_id"], "4625")
        self.assertEqual(parsed["metadata"]["TargetUserName"], "Administrator")
        self.assertEqual(parsed["metadata"]["IpAddress"], "10.0.0.15")

    def test_windows_adapter_simulation_fallback(self):
        """Verify Windows adapter returns simulated records when offline or on fallback."""
        adapter = WindowsEventLogAdapter(enable_simulation_fallback=True)
        events = adapter.get_simulated_events()
        self.assertGreaterEqual(len(events), 2)
        self.assertEqual(events[0]["event_type"], "AUTHENTICATION")
        self.assertEqual(events[0]["metadata"]["windows_event_id"], "4625")

    def test_linux_adapter_syslog_parsing(self):
        """Verify parsing of standard RFC 3164 Linux syslog records."""
        adapter = LinuxLogAdapter()

        # Test auth failure line
        auth_line = "Oct 11 22:14:15 srv-01 sshd[1234]: Failed password for invalid user root from 192.168.1.100 port 22 ssh2"
        record = adapter.parse_syslog_line(auth_line, source_path="/var/log/auth.log")

        self.assertEqual(record["event_type"], "AUTHENTICATION")
        self.assertEqual(record["severity"], "WARNING")
        self.assertEqual(record["metadata"]["program"], "sshd")
        self.assertEqual(record["metadata"]["pid"], "1234")
        self.assertEqual(record["metadata"]["hostname"], "srv-01")

        # Test sudo session line
        sudo_line = "Oct 11 22:15:00 srv-01 sudo[5678]: session opened for user root by admin(uid=1000)"
        sudo_rec = adapter.parse_syslog_line(sudo_line)
        self.assertEqual(sudo_rec["event_type"], "ACCESS_CONTROL")
        self.assertEqual(sudo_rec["severity"], "INFO")

    def test_linux_adapter_file_reading(self):
        """Verify reading syslog lines from a temporary file."""
        with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8") as f:
            f.write("Nov 20 10:00:00 node-a kernel: [123.45] segfault at 0 ip 0000 sp 7ff error 4\n")
            temp_path = f.name

        try:
            adapter = LinuxLogAdapter(log_paths=[temp_path], enable_simulation_fallback=False)
            records = adapter.read_log_file(temp_path)
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["event_type"], "SYSTEM")
            self.assertEqual(records[0]["severity"], "ERROR")
            self.assertIn("segfault", records[0]["message"])
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_application_adapter_json_and_combined_log(self):
        """Verify parsing of JSON and Combined Log Format in application logs."""
        adapter = ApplicationLogAdapter()

        # Test JSON format
        json_line = '{"level": "ERROR", "message": "Database pool exhausted", "active_conns": 50}'
        rec_json = adapter.parse_line(json_line)
        self.assertEqual(rec_json["severity"], "ERROR")
        self.assertEqual(rec_json["message"], "Database pool exhausted")
        self.assertEqual(rec_json["metadata"]["active_conns"], 50)

        # Test Combined Log Format
        clf_line = '192.168.1.50 - frank [20/Nov/2026:10:00:00 +0000] "POST /api/v1/auth HTTP/1.1" 403 520'
        rec_clf = adapter.parse_line(clf_line)
        self.assertEqual(rec_clf["event_type"], "ACCESS_CONTROL")
        self.assertEqual(rec_clf["severity"], "WARNING")
        self.assertEqual(rec_clf["metadata"]["status_code"], 403)
        self.assertEqual(rec_clf["metadata"]["client_ip"], "192.168.1.50")
        self.assertEqual(rec_clf["metadata"]["http_method"], "POST")

    def test_collector_integration_with_adapters(self):
        """Verify LogCollector executes registered adapters and generates sequenced events."""
        collector = LogCollector(source_id="cluster-host-01", initial_sequence=1)
        win_adapter = WindowsEventLogAdapter(enable_simulation_fallback=True)
        app_adapter = ApplicationLogAdapter(enable_simulation_fallback=True)

        collector.register_adapter("win", win_adapter.collect)
        collector.register_adapter("app", app_adapter.collect)

        events = collector.collect_from_adapters()
        self.assertGreaterEqual(len(events), 4)

        # Verify each event has sequence number incremented and source ID set
        for i, ev in enumerate(events):
            self.assertEqual(ev["source_id"], "cluster-host-01")
            self.assertEqual(ev["sequence_number"], i + 1)
            self.assertTrue(ev["event_id"])
            self.assertTrue(ev["event_time"].endswith("Z"))


if __name__ == "__main__":
    unittest.main()
