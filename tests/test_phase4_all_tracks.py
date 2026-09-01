#!/usr/bin/env python3
"""
Unit & Integration Tests for Phase 4 Final Hardening & Delivery
NTRO Problem Statement ID: 26156
"""

import os
from core_engine.parser_loader import ParserLoader
from core_engine.engine import Engine
from core_engine.metrics_exporter import MetricsExporter
from parsers.create_parser import scaffold_parser
from test_tools.stress_100k_benchmark import run_100k_scale_benchmark, generate_10_vendor_synthetic_log, ALL_10_VENDORS


def test_all_10_vendor_corpus_generation():
    """Verify log generators produce non-empty strings across all 10 supported vendors."""
    assert len(ALL_10_VENDORS) >= 10
    for v in ALL_10_VENDORS:
        log_str = generate_10_vendor_synthetic_log(v)
        assert isinstance(log_str, str)
        assert len(log_str) > 15


def test_metrics_exporter_telemetry():
    """Verify system telemetry exporter collects accurate operational stats."""
    engine = Engine(parsers_dir="parsers", parquet_path="data/stream_buffer.parquet")
    engine.process_single(b"%ASA-4-106023: Deny tcp src outside:203.0.113.15/44123 dst inside:192.168.1.50/80")
    
    exporter = MetricsExporter(engine)
    stats = exporter.get_system_telemetry()
    
    assert stats["status"] == "OPERATIONAL_AIR_GAPPED"
    assert stats["traffic_stats"]["total_events_normalized"] >= 1
    assert "latency_profiling_ms" in stats
    assert stats["compliance"]["ocsf_version"] == "1.1.0 (Class 4001 Network Activity)"


def test_parser_sdk_scaffolding():
    """Verify Parser Creator SDK generates valid, loadable YAML parser specifications."""
    test_yaml_name = "test_temp_firewall.yaml"
    created_path = scaffold_parser(
        vendor="SonicWall",
        product="NSa 2700",
        signature_pattern="sn=123456789",
        regex_pattern=r"sn=123456789\s+src=(?P<src_ip>[0-9\.]+):(?P<src_port>\d+)\s+dst=(?P<dst_ip>[0-9\.]+):(?P<dst_port>\d+)\s+proto=(?P<proto>\w+)\s+action=(?P<action>\w+)",
        output_filename=test_yaml_name
    )
    
    try:
        assert os.path.exists(created_path)
        loader = ParserLoader("parsers")
        assert "test_temp_firewall" in loader.parsers
        parser = loader.parsers["test_temp_firewall"]
        raw = "sn=123456789 src=192.168.1.50:54123 dst=203.0.113.10:443 proto=TCP action=Deny"
        assert parser.matches_signature(raw) is True
        tokens = parser.parse(raw)
        assert tokens is not None
        assert tokens.get("src_ip") == "192.168.1.50"
        assert parser.map_disposition(tokens.get("action")) == "Blocked"
    finally:
        if os.path.exists(created_path):
            os.remove(created_path)



def test_100k_scale_benchmark_execution():
    """Verify 100k scale benchmark harness runs and generates formal report JSON."""
    report = run_100k_scale_benchmark(target_events=400, batch_size=500)
    assert report["total_events_processed"] == 400
    assert report["throughput_eps"] > 200.0
    assert report["supported_vendors_count"] >= 10
    assert report["latency_profile_ms"]["p95"] < 10.0
    assert report["air_gapped_verified"] is True

