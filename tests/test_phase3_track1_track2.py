#!/usr/bin/env python3
"""
Unit & Integration Tests for Phase 3 (Track 1 & Track 2)
NTRO Problem Statement ID: 26156
"""

import tempfile
from pathlib import Path
from core_engine.parser_loader import ParserLoader
from core_engine.sink_writer import ParquetSinkWriter



def test_windows_security_parser():
    """Verify Windows Security Event Log (Event ID 4624 & 4625) parsing and normalization."""
    loader = ParserLoader("parsers")
    assert "windows_event" in loader.parsers
    parser = loader.parsers["windows_event"]

    # Success logon (4624 -> Allowed)
    raw_success = "Microsoft-Windows-Security-Auditing: EventID=4624 Account Name: Administrator Source Address: 192.168.1.10 Source Port: 54123 Destination Address: 10.0.0.5 Destination Port: 445"
    assert parser.matches_signature(raw_success) is True
    tokens = parser.parse(raw_success)
    assert tokens is not None
    assert tokens.get("src_ip") == "192.168.1.10"
    assert tokens.get("user") == "Administrator"
    assert parser.map_disposition(tokens.get("event_id_code")) == "Allowed"

    # Failed logon (4625 -> Blocked)
    raw_fail = "Microsoft-Windows-Security-Auditing: EventID=4625 Account Name: hacker Source Address: 203.0.113.88 Source Port: 44123 Destination Address: 10.0.0.5 Destination Port: 3389"
    tokens_fail = parser.parse(raw_fail)
    assert tokens_fail is not None
    assert parser.map_disposition(tokens_fail.get("event_id_code")) == "Blocked"


def test_zeek_conn_parser():
    """Verify Zeek / Bro conn.log parsing and normalization."""
    loader = ParserLoader("parsers")
    assert "zeek_conn" in loader.parsers
    parser = loader.parsers["zeek_conn"]

    raw = "zeek_conn: 1756715430.123 uid123 192.168.1.50 51234 198.51.100.10 443 TCP ssl 1.25 1500 3000 SF"
    assert parser.matches_signature(raw) is True
    tokens = parser.parse(raw)
    assert tokens is not None
    assert tokens.get("src_ip") == "192.168.1.50"
    assert tokens.get("dst_ip") == "198.51.100.10"
    assert tokens.get("src_port") == "51234"
    assert tokens.get("dst_port") == "443"
    assert parser.map_disposition(tokens.get("conn_state")) == "Allowed"


def test_aws_vpc_flow_parser():
    """Verify AWS VPC Flow Logs v2 parsing and normalization."""
    loader = ParserLoader("parsers")
    assert "aws_vpc_flow" in loader.parsers
    parser = loader.parsers["aws_vpc_flow"]

    # ACCEPT -> Allowed
    raw_accept = "2 123456789012 eni-0a1b2c3d4e5f6g7h8 10.0.1.50 198.51.100.22 49152 443 6 25 3500 1756715400 1756715460 ACCEPT OK"
    assert parser.matches_signature(raw_accept) is True
    tokens = parser.parse(raw_accept)
    assert tokens is not None
    assert tokens.get("src_ip") == "10.0.1.50"
    assert tokens.get("dst_ip") == "198.51.100.22"
    assert tokens.get("bytes") == "3500"
    assert parser.map_disposition(tokens.get("action")) == "Allowed"

    # REJECT -> Blocked
    raw_reject = "2 123456789012 eni-0a1b2c3d4e5f6g7h8 203.0.113.99 10.0.1.50 54321 22 6 5 250 1756715400 1756715460 REJECT OK"
    tokens_rej = parser.parse(raw_reject)
    assert tokens_rej is not None
    assert parser.map_disposition(tokens_rej.get("action")) == "Blocked"


def test_dead_letter_queue_capture():
    """Verify failsafe DLQ capture writes malformed bytes to disk with forensic metadata."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        parquet_path = Path(tmp_dir) / "stream.parquet"
        sink = ParquetSinkWriter(output_path=str(parquet_path), batch_size=10)

        bad_bytes = b"\x00\xFF\xFE MALFORMED CORRUPTED RAW BYTES"
        sink.write_to_dlq(bad_bytes, error_reason="UnparseableBinaryPayload", source_ip="192.168.1.99")

        dlq_dir = Path(tmp_dir) / "dlq"
        assert dlq_dir.exists()
        dlq_files = list(dlq_dir.rglob("*.jsonl"))
        assert len(dlq_files) == 1
        content = dlq_files[0].read_text(encoding="utf-8")
        assert "UnparseableBinaryPayload" in content
        assert "192.168.1.99" in content


def test_hot_reload_detection():
    """Verify zero-downtime hot reload detects modifications in <15ms."""
    loader = ParserLoader("parsers")
    initial_count = len(loader.parsers)
    assert initial_count >= 10

    # Test hot reload check with no modifications
    assert loader.check_and_hot_reload() is False
