"""LOGN Evidence Packager

Packages sequences of normalized log events into verifiable evidence bundles
with SHA-256 hash chains, Ed25519 signed checkpoints, and tamper-evident manifests.
"""

from __future__ import annotations

import datetime
import uuid
from typing import Any, Dict, List, Optional

from checkpoint_manager import CheckpointManager, GENESIS_HASH


class EvidencePackager:
    """Seals log events into cryptographically verifiable evidence packages."""

    def __init__(
        self,
        checkpoint_manager: Optional[CheckpointManager] = None,
        initial_hash: str = GENESIS_HASH,
    ) -> None:
        self.checkpoint_manager = checkpoint_manager or CheckpointManager(initial_hash=initial_hash)

    def package(
        self,
        events: List[Dict[str, Any]],
        checkpoint_interval: int = 50,
    ) -> Dict[str, Any]:
        """Process and seal a list of normalized events into an evidence package.

        :param events: List of standardized log events.
        :param checkpoint_interval: Number of events per signed checkpoint.
        :return: Complete evidence bundle with chained events, signed checkpoints, and manifest.
        """
        now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        bundle_id = str(uuid.uuid4())

        if not events:
            return {
                "schema_version": "1.0",
                "bundle_id": bundle_id,
                "created_at": now_utc,
                "manifest": {
                    "event_count": 0,
                    "genesis_hash": self.checkpoint_manager.current_hash,
                    "final_root_hash": self.checkpoint_manager.current_hash,
                },
                "events": [],
                "checkpoints": [],
            }

        genesis_hash = self.checkpoint_manager.current_hash
        chained_events: List[Dict[str, Any]] = []
        checkpoints: List[Dict[str, Any]] = []

        last_checkpoint_idx = 0
        for idx, event in enumerate(events):
            chained = self.checkpoint_manager.chain_event(event)
            chained_events.append(chained)

            # Check if interval threshold reached
            if (idx + 1) % checkpoint_interval == 0:
                start_seq = events[last_checkpoint_idx].get("sequence_number", last_checkpoint_idx)
                end_seq = event.get("sequence_number", idx)
                cp = self.checkpoint_manager.create_checkpoint(
                    start_sequence=start_seq,
                    end_sequence=end_seq,
                    event_count=(idx + 1 - last_checkpoint_idx),
                )
                checkpoints.append(cp)
                last_checkpoint_idx = idx + 1

        # Emit final closing checkpoint if trailing events remain uncheckpointed
        if last_checkpoint_idx < len(events):
            start_seq = events[last_checkpoint_idx].get("sequence_number", last_checkpoint_idx)
            end_seq = events[-1].get("sequence_number", len(events) - 1)
            cp = self.checkpoint_manager.create_checkpoint(
                start_sequence=start_seq,
                end_sequence=end_seq,
                event_count=(len(events) - last_checkpoint_idx),
            )
            checkpoints.append(cp)

        source_id = str(events[0].get("source_id", "unknown"))
        manifest = {
            "bundle_id": bundle_id,
            "source_id": source_id,
            "event_count": len(chained_events),
            "checkpoint_count": len(checkpoints),
            "first_sequence": events[0].get("sequence_number", 0),
            "last_sequence": events[-1].get("sequence_number", len(events) - 1),
            "genesis_hash": genesis_hash,
            "final_root_hash": self.checkpoint_manager.current_hash,
            "signer_public_key": self.checkpoint_manager.public_key_hex,
            "created_at": now_utc,
        }

        return {
            "schema_version": "1.0",
            "bundle_id": bundle_id,
            "created_at": now_utc,
            "manifest": manifest,
            "events": chained_events,
            "checkpoints": checkpoints,
        }
