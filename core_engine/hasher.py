"""
Universal Log Pre-processing Framework (ULPF)
Cryptographic Provenance & Pre-Parsing Hashing Engine
Compliance: Section 65B Indian Evidence Act / Bharatiya Sakshya Adhiniyam 2023
"""

import hashlib
import uuid
import datetime
from typing import Dict, Any, Tuple


class ForensicHasher:
    """
    Computes pre-parsing hardware-accelerated cryptographic digests
    and binds immutable provenance metadata to incoming log events.
    """

    @staticmethod
    def compute_sha256(raw_bytes: bytes) -> str:
        """
        Compute SHA-256 hexadecimal digest on exact raw wire bytes before
        any string decoding, stripping, or mutation occurs.
        """
        if not isinstance(raw_bytes, bytes):
            if isinstance(raw_bytes, str):
                raw_bytes = raw_bytes.encode("utf-8")
            else:
                raw_bytes = bytes(raw_bytes)
        return hashlib.sha256(raw_bytes).hexdigest()

    @staticmethod
    def generate_event_id() -> str:
        """Generate an RFC 4122 compliant UUIDv4 identifier."""
        return str(uuid.uuid4())

    @staticmethod
    def get_iso_timestamp() -> str:
        """Generate microsecond-precision UTC timestamp."""
        return datetime.datetime.now(datetime.timezone.utc).isoformat()

    @classmethod
    def create_provenance_envelope(cls, raw_bytes: bytes) -> Tuple[str, str, str, str]:
        """
        Produce complete cryptographic envelope: (event_id, raw_string, sha256_hash, timestamp)
        """
        digest = cls.compute_sha256(raw_bytes)
        event_id = cls.generate_event_id()
        timestamp = cls.get_iso_timestamp()
        
        # Decode lossless string (replace malformed bytes gracefully without crashing)
        try:
            raw_str = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            raw_str = raw_bytes.decode("latin-1", errors="replace")

        return event_id, raw_str, digest, timestamp

    @classmethod
    def verify_integrity(cls, raw_data: str, recorded_hash: str) -> bool:
        """
        Section 65B Forensic Integrity Equation:
        Status = VALID if SHA256(raw_data) == recorded_hash else TAMPERED
        """
        if not raw_data or not recorded_hash:
            return False
        computed_hash = hashlib.sha256(raw_data.encode("utf-8")).hexdigest()
        return computed_hash.lower() == recorded_hash.lower()

    @classmethod
    def generate_audit_receipt(cls, event_id: str, raw_data: str, recorded_hash: str) -> Dict[str, Any]:
        """
        Generate legal Section 65B forensic audit verification receipt.
        """
        is_valid = cls.verify_integrity(raw_data, recorded_hash)
        computed = hashlib.sha256(raw_data.encode("utf-8")).hexdigest()
        return {
            "event_id": event_id,
            "verification_status": "VERIFIED_AUTHENTIC" if is_valid else "TAMPERED_INVALID",
            "is_valid": is_valid,
            "recorded_hash": recorded_hash,
            "computed_hash": computed,
            "verified_at": cls.get_iso_timestamp(),
            "standard_compliance": "Section 65B Indian Evidence Act (BSA 2023)"
        }
