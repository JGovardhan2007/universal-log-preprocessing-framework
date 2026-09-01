#!/usr/bin/env python3
"""
ULPF Phase 3 Multi-Vendor High-Throughput Stress Test Suite
Track 4 (Phase 3): 7-Vendor Concurrent Load Testing & Pipeline Synchronization
NTRO Problem Statement ID: 26156
"""

import socket
import time
import argparse
import random
import sys
import threading
from datetime import datetime, timezone
from typing import Dict, Any, List

# Ensure UTF-8 console output
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from core_engine.engine import Engine
from test_tools.log_generator import generate_synthetic_log, generate_attack_log

SUPPORTED_VENDORS = [
    "cisco_asa",
    "palo_alto",
    "fortinet",
    "checkpoint",
    "pfsense",
    "linux_auth",
    "suricata_ids"
]


def generate_extended_synthetic_log(vendor: str) -> str:
    """Generates synthetic logs across all 7 supported vendor formats."""
    now = datetime.now(timezone.utc)
    src_ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
    dst_ip = f"198.51.{random.randint(1, 254)}.{random.randint(1, 254)}"
    src_port = random.randint(1024, 65535)
    dst_port = random.choice([80, 443, 22, 53, 3389, 8080, 8443, 445])
    
    if vendor == "linux_auth":
        user = random.choice(["root", "admin", "deploy", "secops", "guest"])
        if random.random() > 0.4:
            return f"{now.strftime('%b %d %H:%M:%S')} server-hq-01 sshd[{random.randint(10000, 60000)}]: Failed password for invalid user {user} from {src_ip} port {src_port} ssh2"
        else:
            return f"{now.strftime('%b %d %H:%M:%S')} server-hq-01 sshd[{random.randint(10000, 60000)}]: Accepted password for {user} from {src_ip} port {src_port} ssh2"

    elif vendor == "suricata_ids":
        sig = random.choice([
            "ET EXPLOIT Apache Struts RCE",
            "ET SCAN Potential SSH Scan",
            "ET TROJAN Cobalt Strike Beacon",
            "ET POLICY Suspicious Inbound SMB"
        ])
        act = "blocked" if "EXPLOIT" in sig or "TROJAN" in sig else "alert"
        return f'{{"timestamp":"{now.isoformat()}","event_type":"alert","src_ip":"{src_ip}","src_port":{src_port},"dest_ip":"{dst_ip}","dest_port":{dst_port},"proto":"TCP","alert":{{"action":"{act}","signature":"{sig}","category":"Threat Alert","severity":1}}}}'

    return generate_synthetic_log(vendor)


def run_in_memory_stress(event_count: int = 10000, batch_size: int = 1000) -> Dict[str, Any]:
    """Executes high-speed in-memory pipeline stress test across all 7 vendors."""
    print(f"🔥 [Track 4 Phase 3] Starting In-Memory Stress Benchmark ({event_count:,} events)...")
    engine = Engine(parsers_dir="parsers", parquet_path="data/stream_buffer.parquet", batch_size=max(batch_size, event_count))
    
    latencies_ms = []

    vendor_distribution: Dict[str, int] = {v: 0 for v in SUPPORTED_VENDORS}
    
    start_time = time.perf_counter()
    for i in range(event_count):
        v = SUPPORTED_VENDORS[i % len(SUPPORTED_VENDORS)]
        vendor_distribution[v] += 1
        raw_log = generate_extended_synthetic_log(v)
        
        t0 = time.perf_counter()
        engine.process_single(raw_log.encode("utf-8"))
        t1 = time.perf_counter()
        
        latencies_ms.append((t1 - t0) * 1000.0)

    engine.sink_writer.flush()
    total_time = max(0.0001, time.perf_counter() - start_time)
    avg_eps = event_count / total_time
    
    latencies_sorted = sorted(latencies_ms)
    p50 = latencies_sorted[int(len(latencies_sorted) * 0.50)]
    p95 = latencies_sorted[int(len(latencies_sorted) * 0.95)]
    p99 = latencies_sorted[int(len(latencies_sorted) * 0.99)]
    avg_lat = sum(latencies_ms) / len(latencies_ms)
    
    summary = {
        "event_count": event_count,
        "total_time_sec": round(total_time, 4),
        "throughput_eps": round(avg_eps, 2),
        "avg_latency_ms": round(avg_lat, 4),
        "p50_latency_ms": round(p50, 4),
        "p95_latency_ms": round(p95, 4),
        "p99_latency_ms": round(p99, 4),
        "vendors_tested": len(SUPPORTED_VENDORS),
        "distribution": vendor_distribution
    }
    
    print("=" * 65)
    print(f"🏆 [Phase 3 Stress Results]")
    print(f"   Processed : {event_count:,} events across {len(SUPPORTED_VENDORS)} vendors")
    print(f"   Duration  : {total_time:.3f} seconds")
    print(f"   Speed     : {avg_eps:,.1f} EPS")
    print(f"   Avg Lat   : {avg_lat:.4f} ms | P95: {p95:.4f} ms | P99: {p99:.4f} ms")
    print("=" * 65)
    return summary


def run_live_udp_stress(host: str = "127.0.0.1", port: int = 5140, total_events: int = 5000, threads: int = 4):
    """Fires concurrent multi-threaded UDP syslog packets across all 7 vendors to a live socket."""
    print(f"📡 [Track 4 Phase 3] Firing {total_events:,} UDP syslog packets across {threads} threads -> {host}:{port}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    events_per_thread = total_events // threads
    
    def _worker():
        for _ in range(events_per_thread):
            v = random.choice(SUPPORTED_VENDORS)
            raw = generate_extended_synthetic_log(v)
            sock.sendto(raw.encode("utf-8"), (host, port))
            
    thread_pool = [threading.Thread(target=_worker) for _ in range(threads)]
    t0 = time.time()
    for t in thread_pool:
        t.start()
    for t in thread_pool:
        t.join()
    t1 = time.time()
    
    sock.close()
    duration = max(0.001, t1 - t0)
    eps = total_events / duration
    print(f"✅ [UDP Complete] Sent {total_events:,} packets in {duration:.2f}s (~{eps:,.0f} EPS)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ULPF Phase 3 Stress Testing Suite")
    parser.add_argument("--mode", choices=["in-memory", "udp"], default="in-memory", help="Stress test mode")
    parser.add_argument("--count", type=int, default=5000, help="Total event count")
    parser.add_argument("--threads", type=int, default=4, help="Thread count for UDP streaming")
    args = parser.parse_args()
    
    if args.mode == "in-memory":
        run_in_memory_stress(event_count=args.count)
    else:
        run_live_udp_stress(total_events=args.count, threads=args.threads)
