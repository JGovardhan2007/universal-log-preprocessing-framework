#!/usr/bin/env python3
"""
Unit & Integration Tests for Kafka Ingestion Connector
NTRO Problem ID: 26156
"""

import pytest
import os
import sys
from pathlib import Path

# Ensure project root in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core_engine.engine import Engine
from core_engine.kafka_ingestion import KafkaIngestionConsumer, KafkaSystemLogProducer, KAFKA_AVAILABLE


def test_kafka_library_availability():
    """Verify that Kafka connector dependencies are cleanly loaded."""
    assert KAFKA_AVAILABLE is True


def test_kafka_consumer_process_raw_message(tmp_path):
    """Verify Kafka consumer correctly ingests raw bytes and extracts OCSF record."""
    parquet_path = str(tmp_path / "kafka_test.parquet")
    eng = Engine(parsers_dir="parsers", parquet_path=parquet_path)
    consumer = KafkaIngestionConsumer(
        bootstrap_servers="localhost:9092",
        topic="test-system-logs",
        engine=eng
    )

    sample_raw = b"%ASA-4-106023: Deny tcp src outside:198.51.100.25/44123 dst inside:10.0.0.5/22"
    record = consumer.process_raw_message(sample_raw)

    assert record is not None
    assert record["class_uid"] == 4001
    assert record["src_endpoint"]["ip"] == "198.51.100.25"
    assert record["dst_endpoint"]["port"] == 22
    assert record["disposition"] == "Blocked"
    assert consumer.metrics["messages_consumed"] == 1
    assert consumer.metrics["bytes_processed"] == len(sample_raw)


def test_kafka_consumer_start_stop_lifecycle():
    """Verify non-blocking start/stop behavior of Kafka consumer worker."""
    consumer = KafkaIngestionConsumer(
        bootstrap_servers="127.0.0.1:9092",
        topic="test-lifecycle"
    )
    # Start (will attempt connection in background)
    consumer.start()
    assert consumer.is_running is True

    # Stop gracefully
    consumer.stop()
    assert consumer.is_running is False
    assert consumer.metrics["connection_status"] == "STOPPED"
