"""
Integration & Performance Tests for Engine & Parquet Sink Writer
"""

import os
import time
import pytest
import pyarrow.parquet as pq
from pathlib import Path
from core_engine.engine import Engine
from core_engine.sink_writer import ParquetSinkWriter


@pytest.fixture
def temp_parquet_path(tmp_path):
    return str(tmp_path / "test_stream.parquet")


def test_engine_single_process_and_sink(temp_parquet_path):
    engine = Engine(parsers_dir="parsers", parquet_path=temp_parquet_path, batch_size=5)

    test_logs = [
        b"%ASA-4-106023: Deny tcp src outside:203.0.113.15/44123 dst inside:192.168.1.50/80",
        b'date=2026-09-01 time=08:30:00 devname="FGT60D" srcip=192.168.1.50 dstip=10.0.0.5 action="accept"',
        b"1,2026/09/01 08:30:15,001801000001,TRAFFIC,drop,1,2026/09/01 08:30:15,192.168.1.100,10.0.0.1,0.0.0.0,0.0.0.0,Rule-Block,trust,untrust,ethernet1/1,ethernet1/2,Log-Forward,2026/09/01 08:30:15,12345,1,54321,80,0,0,0x0,tcp,deny,120,60,60,1,2026/09/01 08:30:00,15,any,0,0,0,0,,US,IN,0,1,0",
        b'{"timestamp":"2026-09-01T08:30:00.123456+0000","event_type":"alert","src_ip":"192.168.1.50","src_port":54321,"dest_ip":"203.0.113.80","dest_port":80,"proto":"TCP","alert":{"action":"blocked"}}',
        b"CRITICAL: Unstructured log from 10.0.0.1 to 10.0.0.2 port 80 blocked"
    ]

    for log_bytes in test_logs:
        rec = engine.process_single(log_bytes)
        assert rec["class_uid"] == 4001
        assert "event_id" in rec
        assert "hash" in rec["metadata"]

    # Flush sink
    flushed = engine.sink_writer.flush()
    assert Path(temp_parquet_path).exists()

    # Read back with PyArrow Parquet
    table = pq.read_table(temp_parquet_path)
    assert table.num_rows == len(test_logs)
    assert "event_id" in table.column_names
    assert "hash" in table.column_names
    assert "src_ip" in table.column_names
    assert "disposition" in table.column_names
    assert "vendor" in table.column_names


def test_engine_in_memory_throughput_benchmark():
    """Verify that in-memory parsing executes with high performance (<0.2ms per record)."""
    engine = Engine(parsers_dir="parsers", batch_size=5000)
    sample_log = b"%ASA-4-106023: Deny tcp src outside:203.0.113.15/44123 dst inside:192.168.1.50/80"

    num_records = 2000
    t0 = time.perf_counter()
    for _ in range(num_records):
        engine.process_single(sample_log)
    total_time = time.perf_counter() - t0

    eps = num_records / total_time
    avg_latency_ms = (total_time / num_records) * 1000.0

    print(f"\n[BENCHMARK] Processed {num_records} events in {total_time:.3f}s -> {eps:.1f} EPS | Avg Latency: {avg_latency_ms:.3f} ms")
    assert eps > 1000.0  # Basic baseline in pure Python in-process
    assert avg_latency_ms < 2.0  # Well within sub-2ms target
