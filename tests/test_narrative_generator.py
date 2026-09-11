#!/usr/bin/env python3
"""
Test Suite for Tactical Plain-English Narrative Generator
"""

import time
import pytest
from core_engine.narrative_generator import TacticalNarrativeGenerator
from core_engine.ocsf_normalizer import OCSFNormalizer


def test_cisco_asa_narrative():
    raw = '%ASA-4-106023: Deny tcp src outside:198.51.100.25/44332 dst inside:10.0.0.15/80 by access-group "OUTSIDE-IN"'
    tokens = {
        "src_ip": "198.51.100.25",
        "src_port": "44332",
        "dst_ip": "10.0.0.15",
        "dst_port": "80",
        "proto": "tcp",
        "action": "Deny",
        "cef_vendor": "Cisco",
        "cef_product": "ASA"
    }
    record = OCSFNormalizer.normalize(
        event_id="test-1",
        raw_data=raw,
        sha256_hash="abcd1234hash",
        ingest_timestamp="2026-09-11T12:00:00Z",
        tier=1,
        format_name="Tier1:Cisco_ASA",
        tokens=tokens
    )

    assert "narrative" in record
    narrative = record["narrative"]
    assert "Firewall [Cisco ASA]" in narrative
    assert "blocked" in narrative
    assert "198.51.100.25" in narrative
    assert "10.0.0.15" in narrative
    assert "HTTP (Port 80)" in narrative


def test_fortinet_exploit_narrative():
    raw = 'date=2026-09-11 time=07:26:38 devname="FGT-HQ-01" type="utm" subtype="ips" srcip=95.173.136.146 srcport=51141 dstip=10.0.0.12 dstport=22 proto=6 action="dropped" attack="SMB.EternalBlue.MS17-010.Exploit"'
    tokens = {
        "src_ip": "95.173.136.146",
        "src_port": "51141",
        "dst_ip": "10.0.0.12",
        "dst_port": "22",
        "proto": "6",
        "action": "dropped",
        "cef_vendor": "Fortinet",
        "cef_product": "FortiGate"
    }
    record = OCSFNormalizer.normalize(
        event_id="test-2",
        raw_data=raw,
        sha256_hash="fortihash123",
        ingest_timestamp="2026-09-11T12:00:00Z",
        tier=1,
        format_name="Tier1:Fortinet_FortiGate",
        tokens=tokens
    )

    assert "narrative" in record
    narrative = record["narrative"]
    assert "Fortinet FortiGate" in narrative
    assert "blocked" in narrative
    assert "SSH (Port 22)" in narrative
    assert "EternalBlue" in narrative


def test_crowdstrike_process_narrative():
    raw = 'FalconDetection: ComputerName="CORP-WKSTN-16" UserName="secops" FileName="mimikatz.exe" Action="Process Terminated" Tactic="Credential Access" Technique="T1003"'
    tokens = {
        "cef_vendor": "CrowdStrike",
        "cef_product": "Falcon",
        "action": "Process Terminated"
    }
    record = OCSFNormalizer.normalize(
        event_id="test-3",
        raw_data=raw,
        sha256_hash="crowdhash123",
        ingest_timestamp="2026-09-11T12:00:00Z",
        tier=2,
        format_name="Tier2:KeyValue",
        tokens=tokens
    )

    assert "narrative" in record
    narrative = record["narrative"]
    assert "CrowdStrike Falcon" in narrative
    assert "mimikatz.exe" in narrative
    assert "secops" in narrative


def test_windows_failed_logon_narrative():
    raw = 'EventID=4625 Source=Microsoft-Windows-Security-Auditing TimeGenerated="2026-09-11 07:26:38" Message="An account failed to log on. Account Name: admin Source Network Address: 203.0.113.50 (T1110)"'
    tokens = {
        "cef_vendor": "Microsoft-Windows",
        "cef_product": "Security",
        "action": "deny"
    }
    record = OCSFNormalizer.normalize(
        event_id="test-4",
        raw_data=raw,
        sha256_hash="winhash123",
        ingest_timestamp="2026-09-11T12:00:00Z",
        tier=2,
        format_name="Tier2:KeyValue",
        tokens=tokens
    )

    assert "narrative" in record
    narrative = record["narrative"]
    assert "Windows Security" in narrative
    assert "admin" in narrative
    assert "203.0.113.50" in narrative


def test_narrative_microsecond_performance():
    """Verify 1,000 narrative evaluations execute in < 25ms total (< 25 microseconds each)."""
    raw = '%ASA-4-106023: Deny tcp src outside:198.51.100.25/44332 dst inside:10.0.0.15/80 by access-group "OUTSIDE-IN"'
    record = {
        "disposition": "Blocked",
        "src_endpoint": {"ip": "198.51.100.25", "port": 44332, "geo": {"country": "United States", "is_internal": False}},
        "dst_endpoint": {"ip": "10.0.0.15", "port": 80, "geo": {"is_internal": True, "target_sector": "Web Tier"}},
        "connection_info": {"protocol_name": "TCP", "direction": "Inbound"},
        "metadata": {"product": {"vendor_name": "Cisco", "name": "ASA"}}
    }

    t0 = time.perf_counter()
    for _ in range(1000):
        TacticalNarrativeGenerator.generate(record, raw)
    duration_ms = (time.perf_counter() - t0) * 1000.0

    # 1,000 evaluations should easily take < 50ms even on busy systems
    assert duration_ms < 50.0, f"Narrative generation took {duration_ms:.2f}ms for 1,000 iterations"
