"""LOGN Checkpoint Manager & SHA-256 Hash Chaining with Ed25519 Signatures

Maintains a cryptographic hash chain over sequential log events and issues
Ed25519 digitally signed checkpoints to prevent retroactive history rewriting.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import uuid
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519

GENESIS_HASH = "0" * 64


def canonical_json(data: Any) -> str:
    """Produce deterministic canonical JSON representation with sorted keys and no whitespace."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_sha256(data_str: str) -> str:
    """Compute SHA-256 hex digest for a UTF-8 string."""
    return hashlib.sha256(data_str.encode("utf-8")).hexdigest()


class CheckpointManager:
    """Manages event hash chaining and produces Ed25519 signed checkpoints."""

    def __init__(
        self,
        signing_key: Optional[ed25519.Ed25519PrivateKey] = None,
        initial_hash: str = GENESIS_HASH,
    ) -> None:
        self._private_key = signing_key or ed25519.Ed25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()
        self._current_hash = initial_hash

    @property
    def current_hash(self) -> str:
        """Return the current hash chain tip."""
        return self._current_hash

    @property
    def public_key_bytes(self) -> bytes:
        """Return the raw 32-byte Ed25519 public verification key."""
        return self._public_key.public_bytes_raw()

    @property
    def public_key_hex(self) -> str:
        """Return the hex-encoded Ed25519 public key."""
        return self.public_key_bytes.hex()

    def calculate_event_hash(self, prev_hash: str, event_data: Dict[str, Any]) -> str:
        """Calculate event hash chained to previous hash:

        H_i = SHA-256( H_{i-1} || ':' || canonical_json(E_i) )
        Note: strips any existing 'integrity' block so calculation is deterministic.
        """
        clean_event = {k: v for k, v in event_data.items() if k != "integrity"}
        payload_canonical = canonical_json(clean_event)
        combined = f"{prev_hash}:{payload_canonical}"
        return compute_sha256(combined)

    def chain_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Attach SHA-256 hash chaining block to an event and advance the chain tip.

        :param event: The normalized log event dictionary.
        :return: Enriched event containing an 'integrity' dictionary.
        """
        prev_h = self._current_hash
        event_h = self.calculate_event_hash(prev_h, event)

        event_copy = dict(event)
        event_copy["integrity"] = {
            "previous_hash": prev_h,
            "event_hash": event_h,
            "algorithm": "SHA-256",
        }

        self._current_hash = event_h
        return event_copy

    def create_checkpoint(
        self,
        start_sequence: int,
        end_sequence: int,
        event_count: int,
    ) -> Dict[str, Any]:
        """Generate a signed cryptographic checkpoint over the current chain tip.

        :param start_sequence: First sequence number covered by this checkpoint.
        :param end_sequence: Last sequence number covered by this checkpoint.
        :param event_count: Number of events covered.
        :return: Signed checkpoint record.
        """
        now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        checkpoint_id = str(uuid.uuid4())

        checkpoint_data = {
            "checkpoint_id": checkpoint_id,
            "start_sequence": start_sequence,
            "end_sequence": end_sequence,
            "event_count": event_count,
            "root_hash": self._current_hash,
            "timestamp": now_utc,
            "public_key": self.public_key_hex,
        }

        # Deterministically sign the canonical checkpoint data
        canonical_bytes = canonical_json(checkpoint_data).encode("utf-8")
        signature_bytes = self._private_key.sign(canonical_bytes)

        return {
            **checkpoint_data,
            "signature": signature_bytes.hex(),
            "signature_algorithm": "Ed25519",
        }
