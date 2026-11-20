"""LOGN Cryptographic Evidence Verifier

Verifies SHA-256 hash chains and validates Ed25519 digital signatures on checkpoints,
detecting any modification, deletion, reordering, or insertion of evidence.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from checkpoint_manager import (
    GENESIS_HASH,
    canonical_json,
    compute_sha256,
)


class EvidenceVerifier:
    """Verifies evidence integrity across hash chains and signed checkpoints."""

    @staticmethod
    def calculate_event_hash(prev_hash: str, event_data: Dict[str, Any]) -> str:
        """Deterministically calculate expected event hash."""
        clean_event = {k: v for k, v in event_data.items() if k != "integrity"}
        payload_canonical = canonical_json(clean_event)
        combined = f"{prev_hash}:{payload_canonical}"
        return compute_sha256(combined)

    def verify_event_chain(
        self,
        events: List[Dict[str, Any]],
        initial_hash: str = GENESIS_HASH,
    ) -> Tuple[bool, List[str]]:
        """Verify the integrity of a sequence of chained events.

        :param events: List of events with 'integrity' metadata.
        :param initial_hash: Hash preceding the first event (defaults to genesis).
        :return: (is_valid, list_of_error_descriptions).
        """
        errors: List[str] = []
        if not events:
            return True, []

        expected_prev_hash = initial_hash

        for idx, event in enumerate(events):
            integrity = event.get("integrity")
            event_id = event.get("event_id", f"idx-{idx}")
            seq = event.get("sequence_number", idx)

            if not isinstance(integrity, dict):
                errors.append(
                    f"Event [{idx}] (ID: {event_id}, Seq: {seq}) is missing an 'integrity' block."
                )
                break

            recorded_prev = integrity.get("previous_hash")
            recorded_curr = integrity.get("event_hash")

            # 1. Verify link to previous event
            if recorded_prev != expected_prev_hash:
                errors.append(
                    f"Chain break at event [{idx}] (ID: {event_id}, Seq: {seq}): "
                    f"previous_hash mismatch. Recorded '{recorded_prev}', expected '{expected_prev_hash}'."
                )
                break

            # 2. Recalculate event hash to detect payload tampering
            computed_curr = self.calculate_event_hash(expected_prev_hash, event)
            if recorded_curr != computed_curr:
                errors.append(
                    f"Tampered content at event [{idx}] (ID: {event_id}, Seq: {seq}): "
                    f"event_hash mismatch. Recorded '{recorded_curr}', computed '{computed_curr}'."
                )
                break

            expected_prev_hash = computed_curr

        return len(errors) == 0, errors

    def verify_checkpoint(
        self,
        checkpoint: Dict[str, Any],
        public_key_override: Optional[bytes] = None,
    ) -> Tuple[bool, Optional[str]]:
        """Verify the cryptographic Ed25519 signature on a checkpoint record.

        :param checkpoint: Signed checkpoint record.
        :param public_key_override: Optional public key bytes to verify against.
        :return: (is_valid, optional_error_message).
        """
        if not isinstance(checkpoint, dict):
            return False, "Checkpoint must be a dictionary object."

        signature_hex = checkpoint.get("signature")
        if not signature_hex or not isinstance(signature_hex, str):
            return False, "Checkpoint missing 'signature'."

        pub_key_hex = checkpoint.get("public_key")
        if public_key_override:
            pub_bytes = public_key_override
        elif pub_key_hex and isinstance(pub_key_hex, str):
            try:
                pub_bytes = bytes.fromhex(pub_key_hex)
            except ValueError:
                return False, f"Invalid hex in checkpoint public_key: {pub_key_hex}"
        else:
            return False, "No valid public key provided for verification."

        try:
            signature_bytes = bytes.fromhex(signature_hex)
        except ValueError:
            return False, f"Invalid signature hex: {signature_hex}"

        # Reconstruct canonical signed payload (excluding signature fields)
        signed_fields = {
            k: v
            for k, v in checkpoint.items()
            if k not in ("signature", "signature_algorithm")
        }
        canonical_bytes = canonical_json(signed_fields).encode("utf-8")

        try:
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
            public_key.verify(signature_bytes, canonical_bytes)
            return True, None
        except InvalidSignature:
            return False, "Ed25519 signature verification failed: signature does not match checkpoint data."
        except Exception as exc:
            return False, f"Cryptographic verification error: {exc}"

    def verify_evidence_bundle(self, bundle: Dict[str, Any]) -> Dict[str, Any]:
        """Perform end-to-end integrity verification on an entire evidence bundle.

        Verifies:
        1. Continuous SHA-256 hash chaining across all events.
        2. Cryptographic validity of all Ed25519 checkpoint signatures.
        3. Alignment between event chain tip and checkpoint root hashes.
        """
        all_errors: List[str] = []
        events = bundle.get("events", [])
        checkpoints = bundle.get("checkpoints", [])

        # 1. Verify event chain
        chain_valid, chain_errors = self.verify_event_chain(events)
        all_errors.extend(chain_errors)

        # 2. Verify all checkpoints
        signatures_valid = True
        for cp in checkpoints:
            cp_valid, cp_err = self.verify_checkpoint(cp)
            if not cp_valid:
                signatures_valid = False
                all_errors.append(f"Checkpoint '{cp.get('checkpoint_id')}': {cp_err}")

        # 3. Match checkpoints root_hash against event chain
        if chain_valid and events and checkpoints:
            last_event_hash = events[-1].get("integrity", {}).get("event_hash")
            last_checkpoint_root = checkpoints[-1].get("root_hash")
            if last_event_hash != last_checkpoint_root:
                all_errors.append(
                    f"Final event hash '{last_event_hash}' does not match latest checkpoint root_hash '{last_checkpoint_root}'."
                )

        is_fully_valid = len(all_errors) == 0 and chain_valid and signatures_valid

        return {
            "valid": is_fully_valid,
            "events_checked": len(events),
            "checkpoints_checked": len(checkpoints),
            "chain_valid": chain_valid,
            "signatures_valid": signatures_valid,
            "errors": all_errors,
        }
