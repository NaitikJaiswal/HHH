"""Unit tests for LOGN Durable SQLite Offline Queue (log-agent/offline_queue.py)"""

import os
import sys
import tempfile
import unittest

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "log-agent"))

from offline_queue import OfflineQueue, OfflineQueueError


class TestOfflineQueue(unittest.TestCase):
    """Test suite for OfflineQueue durability, ordering, and restart recovery."""

    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        self.queue = OfflineQueue(db_path=self.temp_db.name, max_retries=3)

    def tearDown(self):
        self.queue.close()
        if os.path.exists(self.temp_db.name):
            try:
                os.remove(self.temp_db.name)
            except OSError:
                pass

    def test_enqueue_and_fifo_sequence_ordering(self):
        """Verify events are returned strictly in ascending sequence number order."""
        # Enqueue out-of-order sequence numbers
        e20 = {"event_id": "id-20", "sequence_number": 20, "message": "Seq 20"}
        e10 = {"event_id": "id-10", "sequence_number": 10, "message": "Seq 10"}
        e30 = {"event_id": "id-30", "sequence_number": 30, "message": "Seq 30"}

        self.assertTrue(self.queue.enqueue(e20))
        self.assertTrue(self.queue.enqueue(e10))
        self.assertTrue(self.queue.enqueue(e30))

        pending = self.queue.get_pending_batch(limit=10, mark_in_flight=False)
        self.assertEqual(len(pending), 3)
        self.assertEqual(pending[0]["event_id"], "id-10")
        self.assertEqual(pending[1]["event_id"], "id-20")
        self.assertEqual(pending[2]["event_id"], "id-30")

    def test_duplicate_rejection_idempotency(self):
        """Verify duplicate event IDs are rejected and not duplicated in the queue."""
        event = {"event_id": "duplicate-uuid-1", "sequence_number": 1, "message": "First attempt"}
        self.assertTrue(self.queue.enqueue(event))

        # Attempt duplicate insertion
        duplicate_event = {"event_id": "duplicate-uuid-1", "sequence_number": 1, "message": "Second attempt"}
        self.assertFalse(self.queue.enqueue(duplicate_event))

        counts = self.queue.count_by_status()
        self.assertEqual(counts["PENDING"], 1)

    def test_state_transitions_delivered_and_failed(self):
        """Verify transitions: PENDING -> IN_FLIGHT -> DELIVERED or FAILED."""
        events = [
            {"event_id": f"ev-{i}", "sequence_number": i, "message": f"Msg {i}"}
            for i in range(1, 4)
        ]
        self.assertEqual(self.queue.enqueue_batch(events), 3)

        # Batch fetch marks IN_FLIGHT
        in_flight = self.queue.get_pending_batch(limit=3, mark_in_flight=True)
        self.assertEqual(len(in_flight), 3)
        counts = self.queue.count_by_status()
        self.assertEqual(counts["IN_FLIGHT"], 3)
        self.assertEqual(counts["PENDING"], 0)

        # Mark first event DELIVERED
        self.assertEqual(self.queue.mark_delivered(["ev-1"]), 1)
        self.assertEqual(self.queue.count_by_status()["DELIVERED"], 1)

        # Mark remaining events failed: retry backoff resets them to PENDING
        self.assertEqual(self.queue.mark_failed(["ev-2", "ev-3"]), 2)
        counts_after_fail = self.queue.count_by_status()
        self.assertEqual(counts_after_fail["PENDING"], 2)

    def test_max_retries_triggers_failed_status(self):
        """Verify that exceeding max_retries marks an event permanently FAILED."""
        event = {"event_id": "persistent-failure", "sequence_number": 99, "message": "Will fail"}
        self.queue.enqueue(event)

        # Attempt 1: retry_count becomes 1
        b1 = self.queue.get_pending_batch(limit=1, mark_in_flight=True)
        self.queue.mark_failed(["persistent-failure"])

        # Attempt 2: retry_count becomes 2
        b2 = self.queue.get_pending_batch(limit=1, mark_in_flight=True)
        self.queue.mark_failed(["persistent-failure"])

        # Attempt 3: retry_count becomes 3 (equals max_retries = 3)
        b3 = self.queue.get_pending_batch(limit=1, mark_in_flight=True)
        self.queue.mark_failed(["persistent-failure"])

        counts = self.queue.count_by_status()
        self.assertEqual(counts["FAILED"], 1)
        self.assertEqual(counts["PENDING"], 0)

    def test_restart_recovery_of_in_flight_events(self):
        """Simulate application crash with events IN_FLIGHT; verify recovery on restart."""
        events = [
            {"event_id": "crash-1", "sequence_number": 1, "message": "Pending delivery"},
            {"event_id": "crash-2", "sequence_number": 2, "message": "Pending delivery"},
        ]
        self.queue.enqueue_batch(events)

        # Fetch and mark IN_FLIGHT
        _ = self.queue.get_pending_batch(limit=2, mark_in_flight=True)
        self.assertEqual(self.queue.count_by_status()["IN_FLIGHT"], 2)

        # Simulate process termination: close DB connection
        self.queue.close()

        # Simulate new application instance starting up with the same DB
        restarted_queue = OfflineQueue(db_path=self.temp_db.name, auto_recover_in_flight=True)
        try:
            # IN_FLIGHT events must have been automatically restored to PENDING
            counts = restarted_queue.count_by_status()
            self.assertEqual(counts["PENDING"], 2)
            self.assertEqual(counts["IN_FLIGHT"], 0)

            # Events can now be fetched again
            recovered_events = restarted_queue.get_pending_batch(limit=2, mark_in_flight=False)
            self.assertEqual(len(recovered_events), 2)
            self.assertEqual(recovered_events[0]["event_id"], "crash-1")
        finally:
            restarted_queue.close()

    def test_purge_delivered_records(self):
        """Verify purging delivered events preserves pending events."""
        self.queue.enqueue({"event_id": "del-1", "sequence_number": 1, "message": "Done"})
        self.queue.enqueue({"event_id": "pend-1", "sequence_number": 2, "message": "Waiting"})

        self.queue.get_pending_batch(limit=1, mark_in_flight=True)
        self.queue.mark_delivered(["del-1"])

        self.assertEqual(self.queue.count_by_status()["DELIVERED"], 1)
        self.assertEqual(self.queue.count_by_status()["PENDING"], 1)

        purged = self.queue.purge_delivered()
        self.assertEqual(purged, 1)
        self.assertEqual(self.queue.count_by_status()["DELIVERED"], 0)
        self.assertEqual(self.queue.count_by_status()["PENDING"], 1)


if __name__ == "__main__":
    unittest.main()
