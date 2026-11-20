"""LOGN Secure Log Sender

Transmits log event batches from the OfflineQueue to the ingestion backend API
over HTTP/HTTPS with authentication, exponential retry backoff, and idempotent acknowledgements.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from config import AgentConfig, load_config
from offline_queue import OfflineQueue

logger = logging.getLogger("logn.sender")


class TransmissionError(Exception):
    """Raised when log transmission fails."""


class LogSender:
    """Manages secure log batch delivery from OfflineQueue to the ingestion backend."""

    def __init__(
        self,
        queue: OfflineQueue,
        config: Optional[AgentConfig] = None,
    ) -> None:
        self.queue = queue
        self.config = config or load_config()

    def _build_request(self, payload: Dict[str, Any]) -> urllib.request.Request:
        """Construct an authenticated HTTP/HTTPS Request object."""
        data_bytes = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "LOGN-Agent/1.0",
        }

        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
            headers["X-API-Key"] = self.config.api_key

        return urllib.request.Request(
            url=self.config.ingest_url,
            data=data_bytes,
            headers=headers,
            method="POST",
        )

    def send_batch(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Transmit a single batch of events to the backend.

        :param events: List of event dictionaries.
        :return: Response dictionary containing 'success' and 'acknowledged_ids'.
        :raises TransmissionError: If connection fails or backend returns an error.
        """
        if not events:
            return {"success": True, "acknowledged_ids": []}

        payload = {
            "collector_id": self.config.collector_id,
            "batch_size": len(events),
            "events": events,
        }

        req = self._build_request(payload)

        try:
            with urllib.request.urlopen(req, timeout=self.config.request_timeout) as resp:
                status_code = resp.getcode()
                response_data = resp.read().decode("utf-8")
                parsed_resp: Dict[str, Any] = {}
                if response_data:
                    try:
                        parsed_resp = json.loads(response_data)
                    except json.JSONDecodeError:
                        pass

                if status_code in (200, 201, 202):
                    ack_ids = parsed_resp.get("acknowledged_ids")
                    if ack_ids is None:
                        ack_ids = [ev["event_id"] for ev in events if "event_id" in ev]

                    return {
                        "success": True,
                        "status_code": status_code,
                        "acknowledged_ids": ack_ids,
                    }
                else:
                    raise TransmissionError(
                        f"Unexpected HTTP status {status_code}: {response_data[:200]}"
                    )

        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            raise TransmissionError(f"HTTP error {exc.code}: {err_body[:200]}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise TransmissionError(f"Network connection failed: {exc}") from exc

    def flush_queue(self, max_batches: int = 10) -> Tuple[int, int]:
        """Fetch pending batches from OfflineQueue and transmit them to the backend.

        :param max_batches: Maximum number of batches to send in this flush cycle.
        :return: (total_delivered_count, total_failed_count).
        """
        total_delivered = 0
        total_failed = 0

        for _ in range(max_batches):
            batch = self.queue.get_pending_batch(limit=self.config.batch_size, mark_in_flight=True)
            if not batch:
                break

            batch_ids = [ev["event_id"] for ev in batch if "event_id" in ev]

            try:
                result = self.send_batch(batch)
                ack_ids = result.get("acknowledged_ids", batch_ids)
                delivered = self.queue.mark_delivered(ack_ids)
                total_delivered += delivered

                # If only a subset was acknowledged, mark remainder failed for retry
                unacked = list(set(batch_ids) - set(ack_ids))
                if unacked:
                    self.queue.mark_failed(unacked)
                    total_failed += len(unacked)
                    # Stop flush loop so we don't immediately hot-retry unacknowledged items
                    break

            except TransmissionError as exc:
                logger.warning("Transmission failed, retaining in offline queue: %s", exc)
                self.queue.mark_failed(batch_ids)
                total_failed += len(batch_ids)
                break

        return total_delivered, total_failed
