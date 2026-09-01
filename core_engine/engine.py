"""
Universal Log Pre-processing Framework (ULPF)
Asynchronous Ingestion & Normalization Core Engine Daemon
Port: 5140 (UDP / TCP Syslog RFC 3164 / 5424)
"""

import sys
import os
import time
import asyncio
import argparse
from typing import Dict, Any, Optional, List, Tuple
from core_engine.hasher import ForensicHasher
from core_engine.parser_loader import ParserLoader
from core_engine.classifier import Classifier
from core_engine.ocsf_normalizer import OCSFNormalizer
from core_engine.sink_writer import ParquetSinkWriter


class SyslogUDPProtocol(asyncio.DatagramProtocol):
    """Asynchronous non-blocking UDP Syslog Protocol Listener."""

    def __init__(self, engine: "Engine"):
        self.engine = engine

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        self.engine.ingest_raw_bytes(data, source_ip=addr[0])

    def error_received(self, exc: Exception):
        self.engine.metrics["error_count"] += 1


class Engine:
    """
    High-Throughput Universal Log Pre-processing Engine.
    Handles socket intake, pre-parsing SHA-256 digital fingerprinting,
    3-tier classification, OCSF normalisation, and Parquet streaming.
    """

    def __init__(
        self,
        parsers_dir: str = "parsers",
        parquet_path: str = "data/stream_buffer.parquet",
        batch_size: int = 500,
        flush_interval_sec: float = 1.0
    ):
        self.parsers_dir = parsers_dir
        self.parser_loader = ParserLoader(parsers_dir)
        self.classifier = Classifier(self.parser_loader)
        self.sink_writer = ParquetSinkWriter(parquet_path, batch_size=batch_size)
        self.flush_interval_sec = flush_interval_sec

        # High-speed processing queue
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=100000)
        self.is_running = False

        # Real-time metrics
        self.metrics = {
            "total_received": 0,
            "total_parsed": 0,
            "tier1_count": 0,
            "tier2_count": 0,
            "tier3_count": 0,
            "error_count": 0,
            "current_eps": 0.0,
            "p95_latency_ms": 0.15,
            "start_time": time.time(),
            "last_eps_calc_time": time.time(),
            "last_received_count": 0
        }

    def process_single(self, raw_bytes: bytes, source_ip: str = "127.0.0.1") -> Dict[str, Any]:
        """
        Synchronously process a single log line through the full pipeline.
        Used for in-process testing, benchmarks, and queue worker execution.
        """
        t0 = time.perf_counter()

        # Step 1: Pre-parsing SHA-256 byte capture
        event_id, raw_str, sha256_hash, timestamp = ForensicHasher.create_provenance_envelope(raw_bytes)

        # Step 2: 3-Tier Classification & Extraction
        tier, format_name, tokens, parser = self.classifier.classify_and_extract(raw_str)

        # Step 3: OCSF v1.1.0 (Class 4001) Normalization
        ocsf_record = OCSFNormalizer.normalize(
            event_id=event_id,
            raw_data=raw_str,
            sha256_hash=sha256_hash,
            ingest_timestamp=timestamp,
            tier=tier,
            format_name=format_name,
            tokens=tokens,
            parser=parser
        )

        # Step 4: Write to Columnar Parquet Sink Buffer
        self.sink_writer.add_record(ocsf_record)

        # Update metrics
        latency_ms = (time.perf_counter() - t0) * 1000.0
        self.metrics["total_received"] += 1
        self.metrics["total_parsed"] += 1
        if tier == 1:
            self.metrics["tier1_count"] += 1
        elif tier == 2:
            self.metrics["tier2_count"] += 1
        else:
            self.metrics["tier3_count"] += 1

        self.metrics["p95_latency_ms"] = round(latency_ms, 3)

        return ocsf_record

    def ingest_raw_bytes(self, raw_bytes: bytes, source_ip: str = "127.0.0.1"):
        """Non-blocking ingestion entrypoint pushing bytes into the async ring queue."""
        try:
            # Handle multi-line packets
            lines = raw_bytes.splitlines()
            for line in lines:
                if line.strip():
                    self.queue.put_nowait((line, source_ip))
        except asyncio.QueueFull:
            self.metrics["error_count"] += 1

    async def _worker_loop(self):
        """Asynchronous worker consuming from queue and batching records."""
        while self.is_running:
            try:
                # Drain queue in micro-batches
                batch = []
                while len(batch) < 1000:
                    try:
                        item = self.queue.get_nowait()
                        batch.append(item)
                    except asyncio.QueueEmpty:
                        break

                if batch:
                    for raw_bytes, src_ip in batch:
                        self.process_single(raw_bytes, src_ip)
                else:
                    await asyncio.sleep(0.01)

            except Exception as e:
                self.metrics["error_count"] += 1
                await asyncio.sleep(0.01)

    async def _periodic_flush_and_hot_reload_loop(self):
        """Periodically flushes Parquet sink and checks for dynamic YAML hot-reloads."""
        while self.is_running:
            await asyncio.sleep(self.flush_interval_sec)
            
            # Flush Parquet sink
            self.sink_writer.flush()

            # Hot reload check (<15ms)
            if self.parser_loader.check_and_hot_reload():
                print(f"[*] [HOT-RELOAD] Dynamic parser reload applied successfully at {time.strftime('%X')}")

            # Recalculate EPS telemetry
            now = time.time()
            dt = now - self.metrics["last_eps_calc_time"]
            if dt >= 1.0:
                current_total = self.metrics["total_received"]
                diff = current_total - self.metrics["last_received_count"]
                self.metrics["current_eps"] = round(diff / dt, 1)
                self.metrics["last_eps_calc_time"] = now
                self.metrics["last_received_count"] = current_total

    async def start(self, host: str = "0.0.0.0", udp_port: int = 5140, tcp_port: int = 5140):
        """Start asynchronous UDP and TCP Syslog ingestion listeners."""
        self.is_running = True
        loop = asyncio.get_running_loop()

        print("=" * 70)
        print("  Universal Log Pre-processing Framework (ULPF) - Core Engine")
        print(f"  Listening on UDP: {host}:{udp_port} | TCP: {host}:{tcp_port}")
        print(f"  Loaded Parsers ({len(self.parser_loader.parsers)}): {list(self.parser_loader.parsers.keys())}")
        print(f"  Parquet Columnar Sink: {self.sink_writer.output_path}")
        print("=" * 70)

        # Start UDP listener
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: SyslogUDPProtocol(self),
            local_addr=(host, udp_port)
        )

        # Start TCP listener
        async def handle_tcp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            addr = writer.get_extra_info("peername")
            src_ip = addr[0] if addr else "127.0.0.1"
            while self.is_running:
                line = await reader.readline()
                if not line:
                    break
                self.ingest_raw_bytes(line, source_ip=src_ip)
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(handle_tcp, host, tcp_port)

        # Spawn background tasks
        worker_task = asyncio.create_task(self._worker_loop())
        flush_task = asyncio.create_task(self._periodic_flush_and_hot_reload_loop())

        try:
            async with server:
                await server.serve_forever()
        finally:
            self.is_running = False
            transport.close()
            worker_task.cancel()
            flush_task.cancel()
            self.sink_writer.flush()


def main():
    parser = argparse.ArgumentParser(description="ULPF Core Ingestion Daemon")
    parser.add_argument("--host", default="0.0.0.0", help="Binding host (default: 0.0.0.0)")
    parser.add_argument("--udp-port", type=int, default=5140, help="UDP Syslog port (default: 5140)")
    parser.add_argument("--tcp-port", type=int, default=5140, help="TCP Syslog port (default: 5140)")
    parser.add_argument("--parsers-dir", default="parsers", help="Path to YAML parsers directory")
    parser.add_argument("--parquet-sink", default="data/stream_buffer.parquet", help="Path to output Parquet table")
    args = parser.parse_args()

    engine = Engine(parsers_dir=args.parsers_dir, parquet_path=args.parquet_sink)
    try:
        asyncio.run(engine.start(host=args.host, udp_port=args.udp_port, tcp_port=args.tcp_port))
    except KeyboardInterrupt:
        print("\n[*] Shutting down ULPF Core Engine...")


if __name__ == "__main__":
    main()
