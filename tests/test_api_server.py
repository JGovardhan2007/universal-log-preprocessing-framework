"""
Unit Tests for Phase 2: REST API Ingestion & Verification Server
"""

import hashlib
from core_engine.api_server import (
    get_health,
    list_parsers,
    ingest_log,
    ingest_batch,
    verify_log_integrity,
    IngestSingleRequest,
    IngestBatchRequest,
    VerifyRequest
)



def test_api_health():
    data = get_health()
    assert data["status"] == "HEALTHY"
    assert "metrics" in data
    assert data["active_parsers_count"] >= 5


def test_api_list_parsers():
    data = list_parsers()
    assert data["total_parsers"] >= 5
    assert "cisco_asa" in data["parsers"]
    assert "fortinet_fortigate" in data["parsers"]


def test_api_ingest_single():
    raw_log = "%ASA-4-106023: Deny tcp src outside:203.0.113.15/44123 dst inside:192.168.1.50/80"
    payload = IngestSingleRequest(raw_log=raw_log, source_ip="10.0.0.1")

    data = ingest_log(payload)
    assert data["status"] == "PROCESSED"
    assert "event_id" in data
    assert "sha256_hash" in data
    assert data["sha256_hash"] == hashlib.sha256(raw_log.encode("utf-8")).hexdigest()
    assert data["class_uid"] == 4001
    assert data["disposition"] == "Blocked"


def test_api_ingest_batch():
    logs = [
        "%ASA-4-106023: Deny tcp src outside:203.0.113.15/44123 dst inside:192.168.1.50/80",
        'date=2026-09-01 time=08:30:00 devname="FGT60D" srcip=192.168.1.50 dstip=10.0.0.5 action="accept"'
    ]
    payload = IngestBatchRequest(logs=logs, source_ip="127.0.0.1")
    data = ingest_batch(payload)

    assert data["status"] == "BATCH_PROCESSED"
    assert data["count"] == 2
    assert len(data["results"]) == 2


def test_api_verify_authentic():
    raw = "%ASA-6-302013: Built inbound TCP connection 9999"
    h = hashlib.sha256(raw.encode("utf-8")).hexdigest()

    verify_payload = VerifyRequest(
        event_id="test-uuid-1",
        raw_data=raw,
        expected_hash=h
    )
    res = verify_log_integrity(verify_payload)
    assert res["is_valid"] is True
    assert res["verification_status"] == "VERIFIED_AUTHENTIC"


def test_api_verify_tampered():
    raw = "%ASA-6-302013: Built inbound TCP connection 9999"
    wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000"

    verify_payload = VerifyRequest(
        event_id="test-uuid-2",
        raw_data=raw,
        expected_hash=wrong_hash
    )
    res = verify_log_integrity(verify_payload)
    assert res["is_valid"] is False
    assert res["verification_status"] == "TAMPERED_INVALID"
