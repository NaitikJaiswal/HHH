"""LOGN Collector Heartbeat Manager

Emits periodic collector heartbeat and health telemetry messages to the backend
API, tracking collector ID, host ID, sequence numbers, queue volume, and agent health.
"""

from __future__ import annotations

import datetime
import json
import logging
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

from config import AgentConfig, load_config
from offline_queue import OfflineQueue

logger = logging.getLogger("logn.heartbeat")


class HeartbeatManager:
    """Manages periodic heartbeat telemetry reporting agent health and queue status."""

    def __init__(
        self,
        config: Optional[AgentConfig] = None,
        queue: Optional[OfflineQueue] = None,
    ) -> None:
        self.config = config or load_config()
        self.queue = queue
        self._start_time = time.time()
        self._last_heartbeat_time: Optional[str] = None
        self._last_delivered_sequence: int = 0
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def set_last_delivered_sequence(self, sequence_number: int) -> None:
        """Update the last sequence number successfully acknowledged by the backend."""
        if sequence_number > self._last_delivered_sequence:
            self._last_delivered_sequence = sequence_number

    @property
    def last_delivered_sequence(self) -> int:
        """Return the highest delivered sequence number tracked."""
        return self._last_delivered_sequence

    @property
    def last_heartbeat_time(self) -> Optional[str]:
        """Return ISO timestamp of last attempted or successful heartbeat."""
        return self._last_heartbeat_time

    def generate_heartbeat_payload(self) -> Dict[str, Any]:
        """Generate current heartbeat telemetry payload."""
        now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        uptime = round(time.time() - self._start_time, 2)

        queue_counts = {"PENDING": 0, "IN_FLIGHT": 0, "DELIVERED": 0, "FAILED": 0}
        if self.queue:
            try:
                queue_counts = self.queue.count_by_status()
            except Exception as exc:
                logger.warning("Could not query queue count for heartbeat: %s", exc)

        pending_count = queue_counts.get("PENDING", 0) + queue_counts.get("IN_FLIGHT", 0)
        failed_count = queue_counts.get("FAILED", 0)

        # Determine operational health status
        if failed_count > 0:
            status = "DEGRADED"
        elif pending_count > 500:
            status = "DEGRADED"
        else:
            status = "HEALTHY"

        return {
            "collector_id": self.config.collector_id,
            "host_id": self.config.source_id,
            "timestamp": now_utc,
            "status": status,
            "last_delivered_sequence": self._last_delivered_sequence,
            "pending_events_count": pending_count,
            "queue_summary": queue_counts,
            "uptime_seconds": uptime,
        }

    def send_heartbeat(self) -> Dict[str, Any]:
        """Send a single heartbeat request to the backend.

        :return: Response status dictionary.
        """
        payload = self.generate_heartbeat_payload()
        self._last_heartbeat_time = payload["timestamp"]

        data_bytes = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "LOGN-Heartbeat/1.0",
        }

        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
            headers["X-API-Key"] = self.config.api_key

        req = urllib.request.Request(
            url=self.config.heartbeat_url,
            data=data_bytes,
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.config.request_timeout) as resp:
                status_code = resp.getcode()
                response_text = resp.read().decode("utf-8")
                parsed_resp: Dict[str, Any] = {}
                if response_text:
                    try:
                        parsed_resp = json.loads(response_text)
                    except json.JSONDecodeError:
                        pass

                return {
                    "success": 200 <= status_code < 300,
                    "status_code": status_code,
                    "response": parsed_resp,
                    "payload_sent": payload,
                }

        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError) as exc:
            logger.warning("Heartbeat delivery to %s failed: %s", self.config.heartbeat_url, exc)
            return {
                "success": False,
                "error": str(exc),
                "payload_sent": payload,
            }

    def _heartbeat_loop(self, interval: float) -> None:
        """Background worker loop executing periodic heartbeat checks."""
        while not self._stop_event.is_set():
            self.send_heartbeat()
            # Wait with interruptible event
            self._stop_event.wait(timeout=interval)

    def start(self, interval: Optional[float] = None) -> None:
        """Start the background heartbeat reporter daemon thread."""
        if self._running:
            return

        check_interval = interval or self.config.heartbeat_interval
        self._stop_event.clear()
        self._running = True
        self._thread = threading.Thread(
            target=self._heartbeat_loop,
            args=(check_interval,),
            daemon=True,
            name="logn-heartbeat-thread",
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop the background heartbeat thread cleanly."""
        if not self._running:
            return

        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self._running = False
