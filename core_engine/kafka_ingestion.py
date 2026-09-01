#!/usr/bin/env python3
"""
Universal Log Pre-processing Framework (ULPF)
Apache Kafka Ingestion & System Log Streaming Connector
Developed for NTRO / NCIIPC (Problem Statement ID: 26156)
"""

import os
import sys
import time
import json
import logging
import threading
from typing import Dict, Any, Optional, Callable, List

# Ensure project root in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core_engine.engine import Engine

logger = logging.getLogger("ULPF_Kafka")

try:
    from kafka import KafkaConsumer, KafkaProducer
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False


class KafkaIngestionConsumer:
    """
    High-throughput Apache Kafka consumer for ULPF.
    Streams raw system/network logs from Kafka topics directly into the
    forensic hasher, 3-tier classifier, OCSF normalizer, and Parquet sink.
    """

    def __init__(
        self,
        bootstrap_servers: str = "localhost:9092",
        topic: str = "system-logs",
        group_id: str = "ulpf-ingestion-group",
        engine: Optional[Engine] = None,
        auto_offset_reset: str = "latest",
        batch_flush_interval: float = 1.0,
    ):
        self.bootstrap_servers = bootstrap_servers
        self.topic = topic
        self.group_id = group_id
        self.engine = engine or Engine(parsers_dir="parsers", parquet_path="data/stream_buffer.parquet")
        self.auto_offset_reset = auto_offset_reset
        self.batch_flush_interval = batch_flush_interval

        self.consumer: Optional[Any] = None
        self.is_running = False
        self._thread: Optional[threading.Thread] = None

        self.metrics = {
            "messages_consumed": 0,
            "bytes_processed": 0,
            "errors": 0,
            "last_active_timestamp": None,
            "connection_status": "DISCONNECTED",
        }

    def initialize_consumer(self) -> bool:
        """Initializes the underlying Kafka consumer connection."""
        if not KAFKA_AVAILABLE:
            self.metrics["connection_status"] = "KAFKA_LIBRARY_MISSING"
            return False

        try:
            self.consumer = KafkaConsumer(
                self.topic,
                bootstrap_servers=self.bootstrap_servers.split(","),
                group_id=self.group_id,
                auto_offset_reset=self.auto_offset_reset,
                enable_auto_commit=True,
                consumer_timeout_ms=1000,
                value_deserializer=lambda x: x  # Raw bytes preservation
            )
            self.metrics["connection_status"] = "CONNECTED"
            return True
        except Exception as e:
            self.metrics["connection_status"] = f"ERROR: {str(e)[:40]}"
            logger.error(f"Failed to connect to Kafka brokers at {self.bootstrap_servers}: {e}")
            return False

    def process_raw_message(self, raw_bytes: bytes) -> Dict[str, Any]:
        """Runs a single Kafka message payload through the forensic normalization engine."""
        try:
            record = self.engine.process_single(raw_bytes)
            self.metrics["messages_consumed"] += 1
            self.metrics["bytes_processed"] += len(raw_bytes)
            self.metrics["last_active_timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            return record
        except Exception as e:
            self.metrics["errors"] += 1
            logger.error(f"Error processing Kafka message: {e}")
            raise

    def _consume_loop(self):
        """Background worker thread consuming messages from Kafka topic."""
        last_flush = time.time()
        while self.is_running:
            if not self.consumer:
                time.sleep(1.0)
                continue

            try:
                for message in self.consumer:
                    if not self.is_running:
                        break
                    raw_val = message.value
                    if isinstance(raw_val, str):
                        raw_val = raw_val.encode("utf-8")
                    self.process_raw_message(raw_val)

                    if time.time() - last_flush > self.batch_flush_interval:
                        self.engine.sink_writer.flush()
                        last_flush = time.time()

            except Exception as e:
                if self.is_running:
                    self.metrics["errors"] += 1
                    time.sleep(0.5)

            # Flush remaining buffer at interval
            if time.time() - last_flush > self.batch_flush_interval:
                self.engine.sink_writer.flush()
                last_flush = time.time()

        if self.engine:
            self.engine.sink_writer.flush()

    def start(self) -> bool:
        """Starts the Kafka consumer in a non-blocking background thread."""
        if self.is_running:
            return True

        self.is_running = True
        connected = self.initialize_consumer()
        self._thread = threading.Thread(target=self._consume_loop, daemon=True)
        self._thread.start()
        return connected

    def stop(self):
        """Stops the Kafka consumer gracefully."""
        self.is_running = False
        if self.consumer:
            try:
                self.consumer.close()
            except Exception:
                pass
            self.consumer = None
        self.metrics["connection_status"] = "STOPPED"
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)


class KafkaSystemLogProducer:
    """
    Producer utility to ship real local system logs or test events directly into Kafka.
    """

    def __init__(self, bootstrap_servers: str = "localhost:9092"):
        self.bootstrap_servers = bootstrap_servers
        self.producer: Optional[Any] = None

    def connect(self) -> bool:
        if not KAFKA_AVAILABLE:
            return False
        try:
            self.producer = KafkaProducer(
                bootstrap_servers=self.bootstrap_servers.split(","),
                value_serializer=lambda v: v.encode("utf-8") if isinstance(v, str) else v
            )
            return True
        except Exception as e:
            logger.error(f"Kafka Producer connection error: {e}")
            return False

    def send_log(self, topic: str, log_payload: str or bytes) -> bool:
        """Publishes a raw log string or bytes to Kafka topic."""
        if not self.producer:
            if not self.connect():
                return False
        try:
            self.producer.send(topic, log_payload)
            self.producer.flush()
            return True
        except Exception as e:
            logger.error(f"Failed to publish log to Kafka topic {topic}: {e}")
            return False
