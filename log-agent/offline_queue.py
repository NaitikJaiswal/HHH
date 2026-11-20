"""LOGN Durable SQLite Offline Log Queue

Provides persistent, atomic, and ordered queuing of log events when the remote
ingestion backend is offline. Tracks pending, in-flight, delivered, and failed
states with safe retry backoff and restart recovery.
"""

from __future__ import annotations

import datetime
import json
import os
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Tuple


class OfflineQueueError(Exception):
    """Base exception for OfflineQueue operations."""


class OfflineQueue:
    """Thread-safe SQLite-backed durable queue for reliable event delivery."""

    def __init__(
        self,
        db_path: str = "offline_queue.db",
        max_retries: int = 5,
        auto_recover_in_flight: bool = True,
    ) -> None:
        """Initialize the durable SQLite queue.

        :param db_path: Path to the SQLite database file or ':memory:'.
        :param max_retries: Max transmission attempts before an event is marked FAILED.
        :param auto_recover_in_flight: Revert abandoned IN_FLIGHT events to PENDING on startup.
        """
        self.db_path = db_path
        self.max_retries = max_retries
        self._lock = threading.Lock()

        # Ensure directory exists if not memory database
        if db_path != ":memory:":
            dirname = os.path.dirname(db_path)
            if dirname:
                os.makedirs(dirname, exist_ok=True)

        self._conn = sqlite3.connect(
            self.db_path,
            check_same_thread=False,
            timeout=15.0,
        )
        self._conn.row_factory = sqlite3.Row

        self._init_db()

        if auto_recover_in_flight:
            self.recover_in_flight()

    def _init_db(self) -> None:
        """Initialize SQLite database settings and schema."""
        with self._lock, self._conn:
            # Enable WAL mode for high concurrency if file-based
            if self.db_path != ":memory:":
                self._conn.execute("PRAGMA journal_mode=WAL;")
                self._conn.execute("PRAGMA synchronous=NORMAL;")

            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS queue_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE NOT NULL,
                    source_id TEXT NOT NULL,
                    sequence_number INTEGER NOT NULL,
                    event_time TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'PENDING',
                    retry_count INTEGER NOT NULL DEFAULT 0,
                    max_retries INTEGER NOT NULL DEFAULT 5,
                    last_attempt_at TEXT,
                    created_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );
            """)

            self._conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_queue_status_seq 
                ON queue_events(status, sequence_number, id);
            """)

            self._conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_queue_event_id 
                ON queue_events(event_id);
            """)

    def enqueue(self, event: Dict[str, Any]) -> bool:
        """Enqueue a single normalized log event.

        :param event: Standardized event dictionary.
        :return: True if enqueued, False if duplicate event_id was ignored.
        """
        if not isinstance(event, dict):
            raise OfflineQueueError("Event must be a dictionary")

        event_id = str(event.get("event_id") or "")
        if not event_id:
            raise OfflineQueueError("Event missing required 'event_id'")

        source_id = str(event.get("source_id") or "unknown")
        sequence_number = int(event.get("sequence_number") or 0)
        event_time = str(event.get("event_time") or datetime.datetime.now(datetime.timezone.utc).isoformat())
        created_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        payload_json = json.dumps(event)

        with self._lock, self._conn:
            cursor = self._conn.execute(
                """
                INSERT OR IGNORE INTO queue_events (
                    event_id, source_id, sequence_number, event_time,
                    status, retry_count, max_retries, created_at, payload_json
                ) VALUES (?, ?, ?, ?, 'PENDING', 0, ?, ?, ?);
                """,
                (
                    event_id,
                    source_id,
                    sequence_number,
                    event_time,
                    self.max_retries,
                    created_at,
                    payload_json,
                ),
            )
            return cursor.rowcount > 0

    def enqueue_batch(self, events: List[Dict[str, Any]]) -> int:
        """Enqueue multiple events in a single transaction.

        :param events: List of standardized event dictionaries.
        :return: Count of newly inserted events (duplicates ignored).
        """
        inserted_count = 0
        created_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        with self._lock, self._conn:
            for ev in events:
                if not isinstance(ev, dict) or not ev.get("event_id"):
                    continue
                cursor = self._conn.execute(
                    """
                    INSERT OR IGNORE INTO queue_events (
                        event_id, source_id, sequence_number, event_time,
                        status, retry_count, max_retries, created_at, payload_json
                    ) VALUES (?, ?, ?, ?, 'PENDING', 0, ?, ?, ?);
                    """,
                    (
                        str(ev["event_id"]),
                        str(ev.get("source_id", "unknown")),
                        int(ev.get("sequence_number", 0)),
                        str(ev.get("event_time", created_at)),
                        self.max_retries,
                        created_at,
                        json.dumps(ev),
                    ),
                )
                if cursor.rowcount > 0:
                    inserted_count += 1

        return inserted_count

    def get_pending_batch(
        self,
        limit: int = 50,
        mark_in_flight: bool = True,
    ) -> List[Dict[str, Any]]:
        """Fetch oldest pending events strictly ordered by sequence number.

        :param limit: Maximum number of events to fetch.
        :param mark_in_flight: When True, transition status from PENDING to IN_FLIGHT.
        :return: Deserialized list of event dictionaries.
        """
        events: List[Dict[str, Any]] = []
        now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        with self._lock, self._conn:
            cursor = self._conn.execute(
                """
                SELECT id, event_id, retry_count, payload_json
                FROM queue_events
                WHERE status = 'PENDING'
                ORDER BY sequence_number ASC, id ASC
                LIMIT ?;
                """,
                (limit,),
            )
            rows = cursor.fetchall()
            if not rows:
                return []

            row_ids: List[int] = []
            for row in rows:
                try:
                    payload = json.loads(row["payload_json"])
                    events.append(payload)
                    row_ids.append(row["id"])
                except json.JSONDecodeError:
                    continue

            if mark_in_flight and row_ids:
                placeholders = ",".join("?" for _ in row_ids)
                self._conn.execute(
                    f"""
                    UPDATE queue_events
                    SET status = 'IN_FLIGHT',
                        retry_count = retry_count + 1,
                        last_attempt_at = ?
                    WHERE id IN ({placeholders});
                    """,
                    [now_utc, *row_ids],
                )

        return events

    def mark_delivered(self, event_ids: List[str]) -> int:
        """Mark successfully transmitted events as DELIVERED.

        :param event_ids: List of unique event IDs.
        :return: Number of rows updated.
        """
        if not event_ids:
            return 0

        placeholders = ",".join("?" for _ in event_ids)
        with self._lock, self._conn:
            cursor = self._conn.execute(
                f"""
                UPDATE queue_events
                SET status = 'DELIVERED'
                WHERE event_id IN ({placeholders});
                """,
                event_ids,
            )
            return cursor.rowcount

    def mark_failed(self, event_ids: List[str]) -> int:
        """Mark events whose transmission failed.

        If retry_count >= max_retries, sets status to 'FAILED'.
        Otherwise, resets status to 'PENDING' for safe retry backoff.
        :param event_ids: List of event IDs.
        :return: Total number of affected rows.
        """
        if not event_ids:
            return 0

        placeholders = ",".join("?" for _ in event_ids)
        with self._lock, self._conn:
            cursor = self._conn.execute(
                f"""
                UPDATE queue_events
                SET status = CASE
                    WHEN retry_count >= max_retries THEN 'FAILED'
                    ELSE 'PENDING'
                END
                WHERE event_id IN ({placeholders});
                """,
                event_ids,
            )
            return cursor.rowcount

    def recover_in_flight(self) -> int:
        """Revert abandoned IN_FLIGHT events back to PENDING.

        Crucial for recovering unacknowledged events after an application crash/restart.
        """
        with self._lock, self._conn:
            cursor = self._conn.execute(
                """
                UPDATE queue_events
                SET status = 'PENDING'
                WHERE status = 'IN_FLIGHT';
                """
            )
            return cursor.rowcount

    def count_by_status(self) -> Dict[str, int]:
        """Return the current counts of events categorized by status."""
        counts = {"PENDING": 0, "IN_FLIGHT": 0, "DELIVERED": 0, "FAILED": 0}
        with self._lock, self._conn:
            cursor = self._conn.execute(
                """
                SELECT status, COUNT(*) as cnt
                FROM queue_events
                GROUP BY status;
                """
            )
            for row in cursor.fetchall():
                st = row["status"]
                if st in counts:
                    counts[st] = row["cnt"]
        return counts

    def purge_delivered(self, retention_hours: Optional[int] = None) -> int:
        """Delete delivered records to reclaim storage space.

        :param retention_hours: If provided, delete delivered records older than N hours.
        :return: Number of deleted rows.
        """
        with self._lock, self._conn:
            if retention_hours is not None:
                cutoff = (
                    datetime.datetime.now(datetime.timezone.utc)
                    - datetime.timedelta(hours=retention_hours)
                ).strftime("%Y-%m-%dT%H:%M:%SZ")
                cursor = self._conn.execute(
                    """
                    DELETE FROM queue_events
                    WHERE status = 'DELIVERED' AND created_at < ?;
                    """,
                    (cutoff,),
                )
            else:
                cursor = self._conn.execute(
                    "DELETE FROM queue_events WHERE status = 'DELIVERED';"
                )
            return cursor.rowcount

    def close(self) -> None:
        """Close the SQLite database connection safely."""
        with self._lock:
            if self._conn:
                self._conn.close()

    def __enter__(self) -> OfflineQueue:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()
