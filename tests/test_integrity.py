"""Unit tests for LOGN Cryptographic Evidence Integrity (evidence-engine/)"""

import os
import sys
import unittest

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "evidence-engine"))

from checkpoint_manager import CheckpointManager, GENESIS_HASH
from evidence_packager import EvidencePackager
from evidence_verifier import EvidenceVerifier


class TestCryptographicIntegrity(unittest.TestCase):
    """Test suite for hash chaining, Ed25519 signed checkpoints, and tamper detection."""

    def setUp(self):
        self.checkpoint_manager = CheckpointManager()
        self.packager = EvidencePackager(checkpoint_manager=self.checkpoint_manager)
        self.verifier = EvidenceVerifier()

        # Sample events
        self.sample_events = [
            {
                "schema_version": "1.0",
                "event_id": f"ev-00{i}",
                "source_id": "server-alpha",
                "sequence_number": 100 + i,
                "event_time": f"2026-11-20T10:0{i}:00Z",
                "observed_at": f"2026-11-20T10:0{i}:01Z",
                "event_type": "AUTHENTICATION",
                "severity": "INFO",
                "message": f"User login step {i}",
                "metadata": {"step": i},
            }
            for i in range(1, 6)
        ]

    def test_sha256_hash_chain_continuity(self):
        """Verify sequential events link previous_hash to preceding event_hash."""
        chained = []
        for ev in self.sample_events:
            chained.append(self.checkpoint_manager.chain_event(ev))

        # Check first event links to genesis
        self.assertEqual(chained[0]["integrity"]["previous_hash"], GENESIS_HASH)
        self.assertNotEqual(chained[0]["integrity"]["event_hash"], GENESIS_HASH)

        # Check consecutive linkages
        for i in range(1, len(chained)):
            self.assertEqual(
                chained[i]["integrity"]["previous_hash"],
                chained[i - 1]["integrity"]["event_hash"],
            )

        # Verifier confirms chain is valid
        is_valid, errors = self.verifier.verify_event_chain(chained)
        self.assertTrue(is_valid, f"Verification failed with errors: {errors}")

    def test_ed25519_checkpoint_signature_validity(self):
        """Verify Ed25519 signatures on checkpoints pass, and tampering fails."""
        # Chain events
        for ev in self.sample_events:
            self.checkpoint_manager.chain_event(ev)

        checkpoint = self.checkpoint_manager.create_checkpoint(
            start_sequence=101,
            end_sequence=105,
            event_count=5,
        )

        # 1. Valid signature passes
        is_valid, err = self.verifier.verify_checkpoint(checkpoint)
        self.assertTrue(is_valid)
        self.assertIsNone(err)

        # 2. Tampering with root hash invalidates signature
        tampered_cp = dict(checkpoint)
        tampered_cp["root_hash"] = "f" * 64
        tampered_valid, tampered_err = self.verifier.verify_checkpoint(tampered_cp)
        self.assertFalse(tampered_valid)
        self.assertIn("signature verification failed", tampered_err)

    def test_tamper_detection_modified_payload(self):
        """Verify modification of event content breaks hash chain verification."""
        bundle = self.packager.package(self.sample_events, checkpoint_interval=5)
        events = bundle["events"]

        # Tamper with event #2 message
        events[2]["message"] = "TAMPERED: Attacker modified event message"

        is_valid, errors = self.verifier.verify_event_chain(events)
        self.assertFalse(is_valid)
        self.assertEqual(len(errors), 1)
        self.assertIn("Tampered content at event [2]", errors[0])

    def test_tamper_detection_event_deletion(self):
        """Verify deleting an intermediate event breaks hash chain verification."""
        bundle = self.packager.package(self.sample_events, checkpoint_interval=5)
        events = bundle["events"]

        # Delete event #1 (leaving 0, 2, 3, 4)
        deleted_chain = [events[0], events[2], events[3], events[4]]

        is_valid, errors = self.verifier.verify_event_chain(deleted_chain)
        self.assertFalse(is_valid)
        self.assertIn("Chain break at event [1]", errors[0])

    def test_tamper_detection_event_reordering(self):
        """Verify reordering events breaks the hash chain."""
        bundle = self.packager.package(self.sample_events, checkpoint_interval=5)
        events = bundle["events"]

        # Swap event 1 and event 2
        swapped = [events[0], events[2], events[1], events[3], events[4]]

        is_valid, errors = self.verifier.verify_event_chain(swapped)
        self.assertFalse(is_valid)
        self.assertIn("Chain break", errors[0])

    def test_end_to_end_evidence_bundle_verification(self):
        """Verify full evidence bundle packaging and complete verification."""
        bundle = self.packager.package(self.sample_events, checkpoint_interval=2)
        report = self.verifier.verify_evidence_bundle(bundle)

        self.assertTrue(report["valid"])
        self.assertEqual(report["events_checked"], 5)
        self.assertEqual(report["checkpoints_checked"], 3)  # intervals at 2, 4, and final 5
        self.assertTrue(report["chain_valid"])
        self.assertTrue(report["signatures_valid"])
        self.assertEqual(len(report["errors"]), 0)


if __name__ == "__main__":
    unittest.main()
