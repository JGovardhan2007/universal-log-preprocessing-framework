#!/usr/bin/env python3
"""
Unit & Integration Tests for Phase 3 (Track 3 & Track 4)
NTRO Problem Statement ID: 26156
"""

import os
from test_tools.stress_tester import run_in_memory_stress, generate_extended_synthetic_log, SUPPORTED_VENDORS
from test_tools.adversarial_campaign import AttackCampaignRunner
from test_tools.audit_chain_of_custody import audit_parquet_buffer


def test_extended_synthetic_log_all_vendors():
    """Verify log generators produce valid non-empty payloads for all 7 supported formats."""
    assert len(SUPPORTED_VENDORS) >= 7
    for vendor in SUPPORTED_VENDORS:
        raw_log = generate_extended_synthetic_log(vendor)
        assert isinstance(raw_log, str)
        assert len(raw_log) > 15


def test_stress_tester_execution():
    """Verify in-memory stress test runs across all 7 vendors with high throughput."""
    summary = run_in_memory_stress(event_count=350, batch_size=50)
    assert summary["event_count"] == 350
    assert summary["throughput_eps"] > 1000.0
    assert summary["vendors_tested"] >= 7
    assert summary["p95_latency_ms"] < 5.0


def test_adversarial_campaign_execution():
    """Verify 5-stage cyber attack campaign executes, normalizes and commits to Parquet."""
    runner = AttackCampaignRunner()
    summary = runner.run_campaign()
    assert summary["campaign_status"] == "SUCCESSFUL_COMPLETION"
    assert summary["total_attack_events_injected"] >= 90
    assert summary["stages_executed"] == 5


def test_audit_chain_of_custody_execution():
    """Verify 100% mathematical Section 65B SHA-256 verification across stored Parquet records."""
    audit_report = audit_parquet_buffer("data/stream_buffer.parquet")
    assert audit_report["total_records_audited"] > 0
    assert audit_report["verification_rate_percent"] == 100.0
    assert audit_report["tampered_records"] == 0
    assert audit_report["chain_of_custody_status"] == "COMPLIANT_COURT_ADMISSIBLE"
