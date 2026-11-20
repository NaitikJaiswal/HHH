"""Unit tests for LOGN Heartbeat Manager (log-agent/heartbeat.py)"""

import json
import os
import sys
import tempfile
import time
import unittest
import urllib.error
from unittest.mock import MagicMock, patch

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "log-agent"))

from config import AgentConfig
from heartbeat import HeartbeatManager
from offline_queue import OfflineQueue


class MockResponse:
    def __init__(self, status_code: int, body_dict: dict):
        self.status_code = status_code
        self.body_bytes = json.dumps(body_dict).encode("utf-8")

    def getcode(self):
        return self.status_code

    def read(self):
        return self.body_bytes

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


class TestHeartbeatManager(unittest.TestCase):
    """Test suite for HeartbeatManager telemetry and transmission."""

    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        self.queue = OfflineQueue(db_path=self.temp_db.name, max_retries=1)

        self.config = AgentConfig(
            backend_url="https://api.example.com",
            api_key="secret-hb-key",
            collector_id="test-agent-99",
            source_id="test-server-01",
            request_timeout=2.0,
            heartbeat_interval=0.1,
        )
        self.manager = HeartbeatManager(config=self.config, queue=self.queue)

    def tearDown(self):
        self.manager.stop()
        self.queue.close()
        if os.path.exists(self.temp_db.name):
            try:
                os.remove(self.temp_db.name)
            except OSError:
                pass

    def test_payload_generation_healthy(self):
        """Verify heartbeat payload has required fields and indicates HEALTHY with empty queue."""
        self.manager.set_last_delivered_sequence(1050)
        payload = self.manager.generate_heartbeat_payload()

        self.assertEqual(payload["collector_id"], "test-agent-99")
        self.assertEqual(payload["host_id"], "test-server-01")
        self.assertEqual(payload["status"], "HEALTHY")
        self.assertEqual(payload["last_delivered_sequence"], 1050)
        self.assertEqual(payload["pending_events_count"], 0)
        self.assertEqual(payload["queue_summary"]["PENDING"], 0)
        self.assertTrue(payload["timestamp"].endswith("Z"))
        self.assertGreaterEqual(payload["uptime_seconds"], 0.0)

    def test_payload_status_degraded_on_failed_records(self):
        """Verify heartbeat indicates DEGRADED status when queue contains failed items."""
        # Enqueue item and force it to FAILED (since max_retries=1)
        self.queue.enqueue({"event_id": "bad-ev", "sequence_number": 1, "message": "Failed item"})
        self.queue.get_pending_batch(limit=1, mark_in_flight=True)
        self.queue.mark_failed(["bad-ev"])

        payload = self.manager.generate_heartbeat_payload()
        self.assertEqual(payload["status"], "DEGRADED")
        self.assertEqual(payload["queue_summary"]["FAILED"], 1)

    def test_last_delivered_sequence_monotonicity(self):
        """Verify last_delivered_sequence only increases monotonically."""
        self.manager.set_last_delivered_sequence(100)
        self.assertEqual(self.manager.last_delivered_sequence, 100)

        # Attempt to regress sequence number
        self.manager.set_last_delivered_sequence(50)
        self.assertEqual(self.manager.last_delivered_sequence, 100)

        # Increment sequence number
        self.manager.set_last_delivered_sequence(120)
        self.assertEqual(self.manager.last_delivered_sequence, 120)

    @patch("urllib.request.urlopen")
    def test_send_heartbeat_success(self, mock_urlopen):
        """Verify HTTP POST transmission of heartbeat payload to configured endpoint."""
        mock_urlopen.return_value = MockResponse(200, {"status": "heartbeat_acknowledged"})

        self.manager.set_last_delivered_sequence(500)
        result = self.manager.send_heartbeat()

        self.assertTrue(result["success"])
        self.assertEqual(result["status_code"], 200)

        mock_urlopen.assert_called_once()
        req = mock_urlopen.call_args[0][0]
        self.assertEqual(req.full_url, "https://api.example.com/api/v1/collectors/heartbeat")
        self.assertEqual(req.headers.get("Authorization"), "Bearer secret-hb-key")
        self.assertEqual(req.headers.get("X-api-key"), "secret-hb-key")

        payload = json.loads(req.data.decode("utf-8"))
        self.assertEqual(payload["collector_id"], "test-agent-99")
        self.assertEqual(payload["last_delivered_sequence"], 500)

    @patch("urllib.request.urlopen")
    def test_send_heartbeat_network_failure_resilience(self, mock_urlopen):
        """Verify that network error in heartbeat does not crash and returns failure dict."""
        mock_urlopen.side_effect = urllib.error.URLError("Backend down")

        result = self.manager.send_heartbeat()
        self.assertFalse(result["success"])
        self.assertIn("Backend down", result["error"])
        self.assertIsNotNone(self.manager.last_heartbeat_time)

    @patch("urllib.request.urlopen")
    def test_background_heartbeat_thread_start_and_stop(self, mock_urlopen):
        """Verify background heartbeat thread runs periodically and terminates on stop()."""
        mock_urlopen.return_value = MockResponse(200, {"status": "ok"})

        self.manager.start(interval=0.05)
        # Give thread time to execute at least one heartbeat
        time.sleep(0.12)
        self.manager.stop()

        self.assertGreaterEqual(mock_urlopen.call_count, 1)
        self.assertFalse(self.manager._running)


if __name__ == "__main__":
    unittest.main()
