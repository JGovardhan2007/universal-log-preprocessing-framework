#!/usr/bin/env python3
"""
Universal Log Pre-processing Framework (ULPF)
Live Pipeline Demonstration & Verification Tool
"""

import sys
from core_engine.engine import Engine
from core_engine.hasher import ForensicHasher


if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


def run_demo():
    print("=" * 80)
    print("   UNIVERSAL LOG PRE-PROCESSING FRAMEWORK (ULPF) - LIVE DEMO")
    print("   Target: NTRO Problem Statement 26156 | OCSF v1.1.0 | Section 65B SHA-256")
    print("=" * 80)

    engine = Engine(parsers_dir="parsers", parquet_path="data/stream_buffer.parquet")

    sample_logs = [
        ("Cisco ASA", b"%ASA-4-106023: Deny tcp src outside:203.0.113.15/44123 dst inside:192.168.1.50/80 by access-group 'outside_in'"),
        ("Palo Alto PAN-OS", b"1,2026/09/01 08:30:15,001801000001,TRAFFIC,drop,1,2026/09/01 08:30:15,192.168.1.100,10.0.0.1,0.0.0.0,0.0.0.0,Rule-Block,trust,untrust,ethernet1/1,ethernet1/2,Log-Forward,2026/09/01 08:30:15,12345,1,54321,80,0,0,0x0,tcp,deny,120,60,60,1,2026/09/01 08:30:00,15,any,0,0,0,0,,US,IN,0,1,0"),
        ("Fortinet FortiGate", b'date=2026-09-01 time=08:30:00 devname="FGT60D" srcip=192.168.1.50 srcport=54321 srcintf="port1" dstip=10.0.0.5 dstport=443 dstintf="port2" proto=6 action="accept" sentbyte=1200'),
        ("Suricata JSON", b'{"timestamp":"2026-09-01T08:30:00.123456+0000","event_type":"alert","src_ip":"192.168.1.50","src_port":54321,"dest_ip":"203.0.113.80","dest_port":80,"proto":"TCP","alert":{"action":"blocked"}}'),
        ("Unstructured Fallback", b"CRITICAL: Raw syslog event from 198.51.100.22 to 192.168.1.1 port 8080 was dropped by edge router")
    ]

    for vendor, raw_bytes in sample_logs:
        print(f"\n[+] Processing: {vendor}")
        print(f"    Raw Input Wire Bytes: {raw_bytes.decode('latin-1')[:75]}...")

        # Process through core engine
        ocsf_record = engine.process_single(raw_bytes)

        print(f"    [1] Event ID (UUIDv4)    : {ocsf_record['event_id']}")
        print(f"    [2] SHA-256 Hash Digest  : {ocsf_record['metadata']['hash']}")
        print(f"    [3] Classification Tier  : Tier {ocsf_record['metadata']['tier']} ({ocsf_record['metadata']['format_name']})")
        print(f"    [4] OCSF Standard Class  : {ocsf_record['class_uid']} ({ocsf_record['class_name']})")
        print(f"    [5] Normalized Endpoints : {ocsf_record['src_endpoint']['ip']}:{ocsf_record['src_endpoint']['port']} -> {ocsf_record['dst_endpoint']['ip']}:{ocsf_record['dst_endpoint']['port']}")
        print(f"    [6] Standard Disposition : {ocsf_record['disposition']} (ID: {ocsf_record['disposition_id']})")
        
        # Live Section 65B verification check
        is_authentic = ForensicHasher.verify_integrity(ocsf_record['raw_data'], ocsf_record['metadata']['hash'])
        print(f"    [7] Section 65B Audit    : {'[VERIFIED AUTHENTIC]' if is_authentic else '[TAMPERED]'}")

    # Flush sink to Parquet
    flushed = engine.sink_writer.flush()
    print("\n" + "=" * 80)
    print(f"[*] Flushed {flushed} normalized records into Apache Parquet sink at:")
    print(f"    '{engine.sink_writer.output_path}'")
    print("=" * 80)


if __name__ == "__main__":
    run_demo()
