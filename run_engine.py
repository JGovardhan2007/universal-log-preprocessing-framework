#!/usr/bin/env python3
"""
ULPF - Universal Log Pre-processing Framework
Track 1 (Phase 4): Master Production Engine Daemon Entrypoint
NTRO Problem Statement ID: 26156
"""

import sys
import os
import asyncio
import signal
import argparse

# Ensure project root in sys.path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core_engine.engine import Engine
from core_engine.metrics_exporter import MetricsExporter

# Ensure UTF-8 output
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


def print_banner():
    banner = """
================================================================================
  🛡️  UNIVERSAL LOG PRE-PROCESSING FRAMEWORK (ULPF) - PRODUCTION DAEMON
  National Technical Research Organisation (NTRO) • Problem Statement ID: 26156
================================================================================
  [✓] OCSF v1.1.0 (Class 4001 Network Activity) Target Schema Active
  [✓] Bit-for-Bit SHA-256 Pre-Parsing Digital Chain-of-Custody (BSA 2023 / 65B)
  [✓] 3-Tier Zero-Drop Classification: Declarative -> Structural -> Regex
  [✓] High-Throughput Columnar Snappy Parquet Sink (/data/stream_buffer.parquet)
  [✓] Partitioned Historical Data Lake Active (/data/lake/)
  [✓] Fail-Safe Dead-Letter Queue (DLQ) Active (/data/dlq/)
================================================================================
"""
    print(banner)


async def main_async(udp_host: str, udp_port: int, batch_size: int):
    print_banner()
    engine = Engine(
        parsers_dir="parsers",
        parquet_path="data/stream_buffer.parquet",
        batch_size=batch_size,
        flush_interval_sec=1.0
    )
    exporter = MetricsExporter(engine)
    
    print(f"[*] Initialized {len(engine.parser_loader.parsers)} active declarative vendor parsers:")
    for p in sorted(engine.parser_loader.parsers.keys()):
        print(f"    - {p}")

    print(f"\n[🚀] Binding Syslog UDP Listener on {udp_host}:{udp_port}...")
    try:
        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: engine.SyslogUDPProtocol(engine),
            local_addr=(udp_host, udp_port)
        )
        print(f"[✓] Engine listening for live packets on UDP {udp_host}:{udp_port}")
        
        # Start worker and periodic flush tasks
        worker_task = asyncio.create_task(engine._worker())
        flush_task = asyncio.create_task(engine._periodic_flusher())
        
        print("[✓] High-speed ingestion pipeline active. Press Ctrl+C to terminate.")
        await asyncio.gather(worker_task, flush_task)
    except KeyboardInterrupt:
        print("\n[!] Shutting down daemon gracefully...")
    finally:
        engine.sink_writer.flush()
        print("[✓] Parquet buffers committed. Shutdown complete.")


def run():
    parser = argparse.ArgumentParser(description="ULPF Production Engine Daemon")
    parser.add_argument("--host", default="0.0.0.0", help="Syslog bind host")
    parser.add_argument("--port", type=int, default=5140, help="Syslog bind port (UDP)")
    parser.add_argument("--batch", type=int, default=1000, help="Parquet batch buffer size")
    args = parser.parse_args()

    try:
        asyncio.run(main_async(args.host, args.port, args.batch))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    run()
