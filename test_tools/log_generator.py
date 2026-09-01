#!/usr/bin/env python3
"""
ULPF Multi-Threaded UDP Log Streamer & Attack Injection Suite
Track 4 (Phase 2): High-Throughput Benchmarking & Cyber-Attack Vectors (NTRO Problem ID 26156)
"""

import socket
import time
import argparse
import random
import os
import glob
import sys
import threading
from datetime import datetime, timezone

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5140
SAMPLE_LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "sample_logs")
VENDORS = ["cisco_asa", "palo_alto", "fortinet", "checkpoint", "pfsense"]


def generate_synthetic_log(vendor: str) -> str:
    now = datetime.now(timezone.utc)
    src_ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
    dst_ip = f"198.51.{random.randint(1, 254)}.{random.randint(1, 254)}"
    src_port = random.randint(1024, 65535)
    dst_port = random.choice([80, 443, 22, 53, 3389, 8080, 8443, 445])
    proto = random.choice(["TCP", "UDP", "ICMP"])
    
    if vendor == "cisco_asa":
        action = random.choice(["Deny", "Built", "Teardown"])
        msg_id = random.choice([106023, 302013, 302014, 106001])
        return f"%ASA-4-{msg_id}: {action} {proto.lower()} src outside:{src_ip}/{src_port} dst inside:{dst_ip}/{dst_port} by access-group \"OUTSIDE-IN\" [0x0, 0x0]"

    elif vendor == "palo_alto":
        action = random.choice(["allow", "deny", "drop"])
        return f"1,{now.strftime('%Y/%m/%d %H:%M:%S')},001801000001,TRAFFIC,{action},1,{now.strftime('%Y/%m/%d %H:%M:%S')},{src_ip},{dst_ip},0.0.0.0,0.0.0.0,Rule-Policy,,,ssl,vsys1,untrust,trust,ethernet1/1,ethernet1/2,Log-Forwarder,{now.strftime('%Y/%m/%d %H:%M:%S')},12345,1,{src_port},{dst_port},0,0,0x0,{proto.lower()},{action},{random.randint(100, 5000)},{random.randint(100, 2500)},{random.randint(0, 2500)},1,{now.strftime('%Y/%m/%d %H:%M:%S')},0,any,0,0,0,0,,US,IN,0,1,0"

    elif vendor == "fortinet":
        action = random.choice(["accept", "deny", "close"])
        return f"date={now.strftime('%Y-%m-%d')} time={now.strftime('%H:%M:%S')} devname=\"FGT-HQ-01\" devid=\"FGT60D4614041234\" logid=\"0000000013\" type=\"traffic\" subtype=\"forward\" level=\"notice\" vd=\"root\" srcip={src_ip} srcport={src_port} srcintf=\"port1\" dstip={dst_ip} dstport={dst_port} dstintf=\"port2\" proto={6 if proto == 'TCP' else 17} action=\"{action}\" policyid=1 service=\"HTTPS\" duration={random.randint(1, 120)} sentbyte={random.randint(60, 4000)} rcvdbyte={random.randint(60, 8000)}"

    elif vendor == "checkpoint":
        action = random.choice(["accept", "drop", "reject"])
        return f"time={int(now.timestamp())}|hostname=cp-fw01|product=VPN-1 & FireWall-1|action={action}|src={src_ip}|dst={dst_ip}|proto={proto.lower()}|s_port={src_port}|service={dst_port}|rule=12|reason=Policy match evaluation"

    elif vendor == "pfsense":
        act = random.choice(["pass", "block"])
        return f"{now.strftime('%b %d %H:%M:%S')} pfsense filterlog[28410]: 4,,,1000000103,igb0,match,{act},in,4,0x0,,64,0,0,DF,{6 if proto == 'TCP' else 17},{proto.lower()},60,{src_ip},{dst_ip},{src_port},{dst_port},0,S,12345678,,65535,,mss;sackOK;TS"

    return f"UNKNOWN_RAW_LOG timestamp={now.isoformat()} src={src_ip} dst={dst_ip} port={dst_port}"


def generate_attack_log(attack_type: str) -> str:
    """Generates synthetic adversarial log events simulating live cyber attacks."""
    now = datetime.now(timezone.utc)
    target_ip = "192.168.1.50"
    attacker_ip = f"203.0.113.{random.randint(100, 200)}"
    
    if attack_type == "port_scan":
        # Rapid port scanning across consecutive ports
        scan_port = random.randint(1, 1024)
        return f"%ASA-4-106023: Deny tcp src outside:{attacker_ip}/{random.randint(40000, 65000)} dst inside:{target_ip}/{scan_port} by access-group \"OUTSIDE-IN\" [0x0, 0x0]"
        
    elif attack_type == "ssh_brute_force":
        # Sustained failed SSH login attempts
        return f"date={now.strftime('%Y-%m-%d')} time={now.strftime('%H:%M:%S')} devname=\"FGT-HQ-01\" logid=\"0000000020\" type=\"traffic\" subtype=\"forward\" level=\"warning\" srcip={attacker_ip} srcport={random.randint(40000, 65000)} dstip={target_ip} dstport=22 proto=6 action=\"deny\" msg=\"SSH authentication failure threshold exceeded\""

    elif attack_type == "dns_exfiltration":
        # High-entropy DNS exfiltration queries
        subdomain = "".join(random.choices("abcdef0123456789", k=24))
        return f"1,{now.strftime('%Y/%m/%d %H:%M:%S')},001801000001,TRAFFIC,allow,1,{now.strftime('%Y/%m/%d %H:%M:%S')},{target_ip},8.8.8.8,0.0.0.0,0.0.0.0,Rule-DNS,,,dns,vsys1,trust,untrust,ethernet1/2,ethernet1/1,Log-Forwarder,{now.strftime('%Y/%m/%d %H:%M:%S')},9999,1,{random.randint(40000, 65000)},53,0,0,0x0,udp,allow,512,256,256,1,{now.strftime('%Y/%m/%d %H:%M:%S')},0,any,0,0,0,0,,IN,US,0,1,1"

    elif attack_type == "malformed":
        # Truncated or corrupt payload testing fallback safety
        return f"CORRUPTED_PACKET_#%@! raw_data_segment_null_byte_err 192.168.1.99 -> 10.0.0.1 ???"

    return generate_synthetic_log("cisco_asa")


def _worker_thread(thread_id: int, host: str, port: int, rate_per_thread: int, duration_sec: int, vendor: str, attack_mode: str, stats: dict, stop_event: threading.Event):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    start_time = time.time()
    
    while not stop_event.is_set():
        elapsed = time.time() - start_time
        if duration_sec > 0 and elapsed >= duration_sec:
            break

        sec_start = time.time()
        for _ in range(rate_per_thread):
            if attack_mode and attack_mode != "none":
                raw_msg = generate_attack_log(attack_mode)
            else:
                v = random.choice(VENDORS) if vendor == "all" else vendor
                raw_msg = generate_synthetic_log(v)

            data = raw_msg.encode("utf-8")
            sock.sendto(data, (host, port))
            stats["packets_sent"] += 1
            stats["bytes_sent"] += len(data)

        sec_elapsed = time.time() - sec_start
        sleep_time = 1.0 - sec_elapsed
        if sleep_time > 0:
            time.sleep(sleep_time)

    sock.close()


def run_benchmark_streamer(host: str, port: int, target_eps: int, duration_sec: int, threads: int, vendor: str, attack_mode: str):
    print(f"🚀 [Track 4 Phase 2] Multi-Threaded UDP Streamer -> {host}:{port}")
    print(f"   Target Rate: {target_eps:,} EPS | Threads: {threads} | Duration: {duration_sec}s | Attack: {attack_mode}")
    
    rate_per_thread = max(1, target_eps // threads)
    stats = {"packets_sent": 0, "bytes_sent": 0}
    stop_event = threading.Event()
    
    thread_pool = []
    for i in range(threads):
        t = threading.Thread(
            target=_worker_thread,
            args=(i, host, port, rate_per_thread, duration_sec, vendor, attack_mode, stats, stop_event),
            daemon=True
        )
        thread_pool.append(t)
        t.start()

    start_time = time.time()
    last_count = 0
    next_report = start_time + 1.0

    try:
        while True:
            elapsed = time.time() - start_time
            if duration_sec > 0 and elapsed >= duration_sec:
                break

            time.sleep(0.2)
            now = time.time()
            if now >= next_report:
                current_total = stats["packets_sent"]
                interval_eps = (current_total - last_count) / (now - (next_report - 1.0))
                last_count = current_total
                mb_sent = stats["bytes_sent"] / (1024 * 1024)
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Total Sent: {current_total:,} ({mb_sent:.2f} MB) | Throughput: {interval_eps:,.0f} EPS")
                next_report = now + 1.0

    except KeyboardInterrupt:
        print("\n🛑 Terminating worker threads...")
    finally:
        stop_event.set()
        for t in thread_pool:
            t.join(timeout=1.0)
        total_time = max(0.001, time.time() - start_time)
        avg_eps = stats["packets_sent"] / total_time
        print(f"\n📊 [Benchmark Complete] {stats['packets_sent']:,} logs sent in {total_time:.2f}s (Average: {avg_eps:,.0f} EPS)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ULPF Multi-Threaded UDP Log Streamer & Attack Injector")
    parser.add_argument("--host", type=str, default=DEFAULT_HOST, help="Target Host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Target Port (default: 5140)")
    parser.add_argument("--rate", type=int, default=1000, help="Target Total EPS (default: 1000)")
    parser.add_argument("--duration", type=int, default=10, help="Duration in seconds (default: 10)")
    parser.add_argument("--threads", type=int, default=4, help="Worker thread count (default: 4)")
    parser.add_argument("--vendor", type=str, default="all", choices=["all", "cisco_asa", "palo_alto", "fortinet", "checkpoint", "pfsense"])
    parser.add_argument("--attack", type=str, default="none", choices=["none", "port_scan", "ssh_brute_force", "dns_exfiltration", "malformed"], help="Inject cyber attack scenario")

    args = parser.parse_args()
    run_benchmark_streamer(args.host, args.port, args.rate, args.duration, args.threads, args.vendor, args.attack)
