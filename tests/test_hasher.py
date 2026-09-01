"""
Unit Tests for Track 1: ForensicHasher & Section 65B Cryptographic Provenance
"""

import hashlib
import uuid
from core_engine.hasher import ForensicHasher



def test_compute_sha256_exact_bytes():
    raw_payload = b"%ASA-4-106023: Deny tcp src outside:203.0.113.15/44123 dst inside:192.168.1.50/80"
    expected = hashlib.sha256(raw_payload).hexdigest()
    computed = ForensicHasher.compute_sha256(raw_payload)
    assert computed == expected
    assert len(computed) == 64


def test_uuid_v4_validity():
    event_id = ForensicHasher.generate_event_id()
    parsed_uuid = uuid.UUID(event_id, version=4)
    assert str(parsed_uuid) == event_id


def test_provenance_envelope():
    raw = b'devname="FGT60D" srcip=192.168.1.50 dstip=10.0.0.5 action="accept"'
    event_id, raw_str, digest, ts = ForensicHasher.create_provenance_envelope(raw)

    assert event_id is not None
    assert raw_str == 'devname="FGT60D" srcip=192.168.1.50 dstip=10.0.0.5 action="accept"'
    assert digest == hashlib.sha256(raw).hexdigest()
    assert "T" in ts  # ISO format


def test_section_65b_verification_valid():
    raw_text = "%ASA-6-302013: Built inbound TCP connection 1234"
    valid_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
    assert ForensicHasher.verify_integrity(raw_text, valid_hash) is True


def test_section_65b_verification_tampered():
    original_text = "%ASA-6-302013: Built inbound TCP connection 1234"
    tampered_text = "%ASA-6-302013: Deny inbound TCP connection 1234"  # Mutated action
    original_hash = hashlib.sha256(original_text.encode("utf-8")).hexdigest()
    
    # Tampering MUST fail forensic integrity check
    assert ForensicHasher.verify_integrity(tampered_text, original_hash) is False


def test_generate_audit_receipt():
    raw_text = "test raw payload"
    h = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
    receipt = ForensicHasher.generate_audit_receipt("test-uuid", raw_text, h)

    assert receipt["event_id"] == "test-uuid"
    assert receipt["verification_status"] == "VERIFIED_AUTHENTIC"
    assert receipt["is_valid"] is True
    assert receipt["recorded_hash"] == h
    assert receipt["computed_hash"] == h
    assert "Section 65B" in receipt["standard_compliance"]
