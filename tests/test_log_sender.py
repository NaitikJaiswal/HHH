"""Unit tests for LOGN Secure Log Sender and Configuration (log-agent/log_sender.py)"""

import io
import json
import os
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from unittest.mock import MagicMock, patch

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "log-agent"))

from config import AgentConfig, load_config
from offline_queue import OfflineQueue
from log_sender import LogSender, TransmissionError


class MockHTTPResponse:
    """Mock urllib response object."""

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


class TestLogSender(unittest.TestCase):
    """Test suite for LogSender and AgentConfig without external socket dependencies."""

    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        self.queue = OfflineQueue(db_path=self.temp_db.name, max_retries=3)

        self.config = AgentConfig(
            backend_url="https://api.example.com",
            api_key="test-secret-token-xyz",
            collector_id="test-agent-01",
            batch_size=10,
            request_timeout=2.0,
        )
        self.sender = LogSender(queue=self.queue, config=self.config)

    def tearDown(self):
        self.queue.close()
        if os.path.exists(self.temp_db.name):
            try:
                os.remove(self.temp_db.name)
            except OSError:
                pass

    def test_config_defaults_and_properties(self):
        """Verify configuration object loads with defaults and valid properties."""
        cfg = AgentConfig()
        self.assertEqual(cfg.ingest_endpoint, "/api/v1/logs/ingest")
        self.assertTrue(cfg.ingest_url.endswith("/api/v1/logs/ingest"))
        self.assertTrue(cfg.heartbeat_url.endswith("/api/v1/collectors/heartbeat"))
        self.assertEqual(cfg.api_key, "")

    @patch("urllib.request.urlopen")
    def test_send_batch_success_and_auth_headers(self, mock_urlopen):
        """Verify successful batch transmission and authentication header propagation."""
        events = [
            {"event_id": "ev-001", "sequence_number": 1, "message": "Auth success"},
            {"event_id": "ev-002", "sequence_number": 2, "message": "User session created"},
        ]
        self.queue.enqueue_batch(events)

        # Mock successful 200 response
        mock_urlopen.return_value = MockHTTPResponse(
            status_code=200,
            body_dict={"status": "success", "acknowledged_ids": ["ev-001", "ev-002"]},
        )

        delivered, failed = self.sender.flush_queue()
        self.assertEqual(delivered, 2)
        self.assertEqual(failed, 0)

        # Check queue status: events marked DELIVERED
        counts = self.queue.count_by_status()
        self.assertEqual(counts["DELIVERED"], 2)
        self.assertEqual(counts["PENDING"], 0)

        # Verify request headers and URL
        mock_urlopen.assert_called_once()
        req = mock_urlopen.call_args[0][0]
        self.assertEqual(req.full_url, "https://api.example.com/api/v1/logs/ingest")
        self.assertEqual(req.headers.get("Authorization"), "Bearer test-secret-token-xyz")
        self.assertEqual(req.headers.get("X-api-key"), "test-secret-token-xyz")

        # Verify payload content
        payload = json.loads(req.data.decode("utf-8"))
        self.assertEqual(payload["collector_id"], "test-agent-01")
        self.assertEqual(payload["batch_size"], 2)
        self.assertEqual(len(payload["events"]), 2)

    @patch("urllib.request.urlopen")
    def test_offline_backend_retains_events_in_queue(self, mock_urlopen):
        """Verify that when backend is offline/unreachable, events remain safely queued."""
        # Simulate connection refused
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

        event = {"event_id": "ev-offline-1", "sequence_number": 50, "message": "Queued event"}
        self.queue.enqueue(event)

        delivered, failed = self.sender.flush_queue()
        self.assertEqual(delivered, 0)
        self.assertEqual(failed, 1)

        # Events must remain in the queue (retried or pending), NOT lost
        counts = self.queue.count_by_status()
        self.assertEqual(counts["PENDING"], 1)
        self.assertEqual(counts["DELIVERED"], 0)

    @patch("urllib.request.urlopen")
    def test_backend_500_error_retains_events_for_retry(self, mock_urlopen):
        """Verify that HTTP 500 error preserves events in queue for backoff retry."""
        # Simulate HTTP 500
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://api.example.com/api/v1/logs/ingest",
            code=500,
            msg="Internal Server Error",
            hdrs={},
            fp=io.BytesIO(b'{"status":"error","message":"Database unavailable"}'),
        )

        event = {"event_id": "ev-err-500", "sequence_number": 1, "message": "Retry me"}
        self.queue.enqueue(event)

        delivered, failed = self.sender.flush_queue()
        self.assertEqual(delivered, 0)
        self.assertEqual(failed, 1)

        counts = self.queue.count_by_status()
        self.assertEqual(counts["PENDING"], 1)
        self.assertEqual(counts["DELIVERED"], 0)

    @patch("urllib.request.urlopen")
    def test_partial_acknowledgement_handling(self, mock_urlopen):
        """Verify handling when backend acknowledges only a subset of batched events."""
        events = [
            {"event_id": "ack-1", "sequence_number": 1, "message": "Accepted"},
            {"event_id": "reject-2", "sequence_number": 2, "message": "Requires re-transmission"},
        ]
        self.queue.enqueue_batch(events)

        # Mock backend only acknowledging ack-1
        mock_urlopen.return_value = MockHTTPResponse(
            status_code=200,
            body_dict={"status": "partial", "acknowledged_ids": ["ack-1"]},
        )

        delivered, failed = self.sender.flush_queue()
        self.assertEqual(delivered, 1)
        self.assertEqual(failed, 1)

        counts = self.queue.count_by_status()
        self.assertEqual(counts["DELIVERED"], 1)
        self.assertEqual(counts["PENDING"], 1)


if __name__ == "__main__":
    unittest.main()
