"""
Unit Tests for 3-Tier Classifier & OCSF v1.1.0 (Class 4001) Normalizer
"""

import pytest
from core_engine.parser_loader import ParserLoader
from core_engine.classifier import Classifier
from core_engine.ocsf_normalizer import OCSFNormalizer
from core_engine.hasher import ForensicHasher


@pytest.fixture
def classifier():
    loader = ParserLoader("parsers")
    return Classifier(loader)


def test_tier1_classification(classifier):
    raw = "%ASA-4-106023: Deny tcp src outside:203.0.113.15/44123 dst inside:192.168.1.50/80"
    tier, format_name, tokens, parser = classifier.classify_and_extract(raw)

    assert tier == 1
    assert "Cisco" in format_name
    assert parser is not None
    assert tokens.get("src_ip") == "203.0.113.15"


def test_tier2_json_classification(classifier):
    raw = '{"custom_event": "traffic", "src_ip": "10.0.0.1", "dest_ip": "10.0.0.2", "proto": "UDP"}'
    tier, format_name, tokens, parser = classifier.classify_and_extract(raw)

    assert tier == 2
    assert "JSON" in format_name
    assert tokens.get("src_ip") == "10.0.0.1"


def test_tier2_key_value_classification(classifier):
    raw = "timestamp=123456 app=custom_proxy client_ip=192.168.10.1 server_ip=10.20.30.40 status=blocked"
    tier, format_name, tokens, parser = classifier.classify_and_extract(raw)

    assert tier == 2
    assert "KeyValue" in format_name
    assert tokens.get("client_ip") == "192.168.10.1"
    assert tokens.get("server_ip") == "10.20.30.40"


def test_tier3_heuristic_fallback(classifier):
    # Completely unstructured log with raw text
    raw = "CRITICAL ALERT: Connection from 198.51.100.99 to 192.168.1.1 on port 8080 was blocked by firewall"
    tier, format_name, tokens, parser = classifier.classify_and_extract(raw)

    assert tier == 3
    assert "HeuristicFallback" in format_name
    assert tokens.get("src_ip") == "198.51.100.99"
    assert tokens.get("dst_ip") == "192.168.1.1"
    assert tokens.get("action") == "blocked"


def test_ocsf_normalization_class_4001(classifier):
    raw = "%ASA-4-106023: Deny tcp src outside:203.0.113.15/44123 dst inside:192.168.1.50/80"
    event_id, raw_str, digest, ts = ForensicHasher.create_provenance_envelope(raw.encode("utf-8"))
    tier, format_name, tokens, parser = classifier.classify_and_extract(raw_str)

    ocsf = OCSFNormalizer.normalize(
        event_id=event_id,
        raw_data=raw_str,
        sha256_hash=digest,
        ingest_timestamp=ts,
        tier=tier,
        format_name=format_name,
        tokens=tokens,
        parser=parser
    )

    # Validate standard OCSF Class 4001 properties
    assert ocsf["class_uid"] == 4001
    assert ocsf["category_uid"] == 4
    assert ocsf["activity_id"] == 1
    assert ocsf["disposition"] == "Blocked"
    assert ocsf["disposition_id"] == 2
    assert ocsf["src_endpoint"]["ip"] == "203.0.113.15"
    assert ocsf["src_endpoint"]["port"] == 44123
    assert ocsf["src_endpoint"]["zone"] == "outside"
    assert ocsf["dst_endpoint"]["ip"] == "192.168.1.50"
    assert ocsf["dst_endpoint"]["port"] == 80
    assert ocsf["dst_endpoint"]["zone"] == "inside"
    assert ocsf["connection_info"]["protocol_name"] == "TCP"
    assert ocsf["metadata"]["hash"] == digest
    assert ocsf["metadata"]["product"]["vendor_name"] == "Cisco"
    assert ocsf["raw_data"] == raw
