#!/usr/bin/env python3
"""
Unit & Integration Tests for Phase 2 (Track 3 & Track 4)
NTRO Problem ID 26156
"""

import pandas as pd
import numpy as np
from dashboard.ai_anomaly import ThreatAnomalyDetector
from test_tools.log_generator import generate_attack_log
from test_tools.benchmark import run_pipeline_benchmark



def test_ai_anomaly_detector_scoring():
    """Verify Isolation Forest anomaly detector trains and scores OCSF data correctly."""
    detector = ThreatAnomalyDetector(contamination=0.1)
    
    # Create sample OCSF DataFrame
    data = []
    for i in range(100):
        # Benign web traffic
        data.append({
            "src_port": 50000 + i,
            "dst_port": 443,
            "disposition": "Allowed",
            "protocol_name": "TCP"
        })
    # Add clear attack anomalies (brute force on port 22, port scan)
    data.append({"src_port": 40123, "dst_port": 22, "disposition": "Blocked", "protocol_name": "TCP"})
    data.append({"src_port": 40124, "dst_port": 445, "disposition": "Blocked", "protocol_name": "TCP"})
    data.append({"src_port": 23, "dst_port": 3389, "disposition": "Blocked", "protocol_name": "TCP"})
    
    df = pd.DataFrame(data)
    df_scored = detector.fit_predict(df)
    
    assert "anomaly_score" in df_scored.columns
    assert "is_anomaly" in df_scored.columns
    assert (df_scored["anomaly_score"] >= 0.0).all()
    assert (df_scored["anomaly_score"] <= 1.0).all()
    
    # The administrative port anomalies should have higher scores
    attack_scores = df_scored.tail(3)["anomaly_score"].values
    normal_scores = df_scored.head(20)["anomaly_score"].values
    assert np.mean(attack_scores) > np.mean(normal_scores)


def test_ai_anomaly_explainability():
    """Verify explainability reasons are returned for high-risk anomalies."""
    detector = ThreatAnomalyDetector()
    row = pd.Series({
        "dst_port": 22,
        "src_port": 500,
        "disposition": "Blocked",
        "anomaly_score": 0.92
    })
    reasons = detector.explain_anomaly(row)
    assert len(reasons) >= 2
    assert any("port 22" in r.lower() or "administrative" in r.lower() for r in reasons)


def test_attack_log_generation_scenarios():
    """Verify all cyber attack log scenarios generate valid string payloads."""
    scenarios = ["port_scan", "ssh_brute_force", "dns_exfiltration", "malformed"]
    for sc in scenarios:
        log_str = generate_attack_log(sc)
        assert isinstance(log_str, str)
        assert len(log_str) > 10


def test_benchmark_profiler_execution():
    """Verify automated benchmark harness runs and generates valid report."""
    report = run_pipeline_benchmark(event_count=200)
    assert report["total_events_processed"] == 200
    assert report["throughput_eps"] > 1000.0
    assert "p95" in report["latency_ms"]
    assert report["latency_ms"]["p95"] < 5.0  # sub-5ms P95 latency
