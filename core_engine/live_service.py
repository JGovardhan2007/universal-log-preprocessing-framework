#!/usr/bin/env python3
"""
Universal Log Pre-processing Framework (ULPF)
Live Log Generator, Socket Receiver, Formatter, AI Analyzer & Dual-File Storage Engine
"""

import os
import sys
import time
import json
import socket
import hashlib
import random
import threading
from collections import deque
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

# Ensure project root in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core_engine.engine import Engine
from test_tools.stress_tester import generate_extended_synthetic_log, SUPPORTED_VENDORS
from test_tools.log_generator import generate_attack_log

RAW_STORAGE_DIR = os.path.join(PROJECT_ROOT, "data", "storage", "raw")
FORMATTED_STORAGE_DIR = os.path.join(PROJECT_ROOT, "data", "storage", "formatted")
PARQUET_PATH = os.path.join(PROJECT_ROOT, "data", "stream_buffer.parquet")

os.makedirs(RAW_STORAGE_DIR, exist_ok=True)
os.makedirs(FORMATTED_STORAGE_DIR, exist_ok=True)


class LiveLogPipelineService:
    """
    Unified Live Streaming Architecture:
    1. Generator: Continuously produces raw strings and transmits to UDP Port 5140.
    2. Receiver & Hasher: Listens on Port 5140, generates SHA-256 wire hash.
    3. Formatter: Normalizes raw strings into standardized JSON (OCSF format).
    4. Batch Storage: Writes separate raw log file (.log) and formatted JSON file (.json).
    5. Live Stream Buffer: Maintains scrolling sliding window for Frontend Live Streamer.
    """

    _instance = None
    _lock = threading.Lock()

    @classmethod
    def get_instance(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def __init__(self, port: int = 5140, batch_size_threshold: int = 200):
        self.port = port
        self.batch_size_threshold = batch_size_threshold
        self.engine = Engine(parsers_dir=os.path.join(PROJECT_ROOT, "parsers"), parquet_path=PARQUET_PATH)

        # Threading flags
        self.is_running = False
        self.generator_thread: Optional[threading.Thread] = None
        self.receiver_thread: Optional[threading.Thread] = None

        # Speed control (logs per second)
        self.logs_per_second = 10

        # In-memory sliding window for Page 2 (Live Streamer) - keeps last 60 records
        self.live_stream_queue = deque(maxlen=60)

        # Batch buffers for dual-file storage
        self.raw_batch_buffer: List[str] = []
        self.formatted_batch_buffer: List[Dict[str, Any]] = []
        self.batch_lock = threading.Lock()
        self.last_flush_time = time.time()

        # Telemetry metrics
        self.stats = {
            "total_generated": 0,
            "total_received": 0,
            "total_formatted": 0,
            "total_files_created": 0,
            "current_eps": 0.0,
            "anomalies_detected": 0,
            "start_time": None
        }

    def start(self, eps: int = 10):
        """Starts the generator and receiver background threads."""
        if self.is_running:
            self.logs_per_second = eps
            return

        self.is_running = True
        self.logs_per_second = eps
        self.stats["start_time"] = time.time()

        # Start Receiver thread (listening on UDP port 5140)
        self.receiver_thread = threading.Thread(target=self._receiver_worker, daemon=True)
        self.receiver_thread.start()

        # Start Generator thread (sending to UDP port 5140)
        self.generator_thread = threading.Thread(target=self._generator_worker, daemon=True)
        self.generator_thread.start()

    def stop(self):
        """Stops the generator and receiver threads and flushes pending buffers."""
        self.is_running = False
        self._flush_batch_to_files(force=True)

    def set_speed(self, eps: int):
        """Dynamically adjusts generator logs-per-second rate."""
        self.logs_per_second = max(1, min(eps, 200))

    def _generator_worker(self):
        """Continuously generates raw log strings and sends them to UDP 5140."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        all_vendors = SUPPORTED_VENDORS + ["windows_security", "zeek_conn", "aws_vpc_flow"]
        attack_types = ["port_scan", "ssh_brute_force", "dns_exfiltration", "malformed"]

        while self.is_running:
            try:
                # 15% probability of generating an attack log for AI anomaly detection
                if random.random() < 0.15:
                    attack = random.choice(attack_types)
                    raw_log = generate_attack_log(attack)
                else:
                    vendor = random.choice(all_vendors)
                    raw_log = generate_extended_synthetic_log(vendor)

                # Send raw string over UDP to local port 5140
                sock.sendto(raw_log.encode("utf-8"), ("127.0.0.1", self.port))
                self.stats["total_generated"] += 1

                # Rate limiting sleep based on configured logs_per_second
                time.sleep(1.0 / self.logs_per_second)
            except Exception as e:
                time.sleep(0.1)

        sock.close()

    def _receiver_worker(self):
        """Listens on UDP 5140, hashes, formats to JSON, and manages live stream queue."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(("0.0.0.0", self.port))
        except Exception as e:
            # Fallback if port already bound
            pass

        sock.settimeout(0.5)
        eps_counter = 0
        eps_timer = time.time()

        while self.is_running:
            try:
                data, addr = sock.recvfrom(65535)
                raw_str = data.decode("utf-8", errors="ignore").strip()
                if not raw_str:
                    continue

                # Step 1: Compute SHA-256 Hash immediately
                sha256_key = hashlib.sha256(raw_str.encode("utf-8")).hexdigest()

                # Step 2: Format & Normalize into JSON (OCSF)
                formatted_record = self.engine.process_single(raw_str.encode("utf-8"))

                # Step 3: Append to Live Stream Queue for Page 2
                stream_item = {
                    "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3],
                    "raw_string": raw_str,
                    "sha256_key": sha256_key,
                    "formatted_json": formatted_record,
                    "vendor": formatted_record.get("vendor", "Generic"),
                    "disposition": formatted_record.get("disposition", "Unknown")
                }
                self.live_stream_queue.append(stream_item)

                # Step 4: Add to Batch Buffer for Dual-File Storage
                with self.batch_lock:
                    self.raw_batch_buffer.append(raw_str)
                    self.formatted_batch_buffer.append(formatted_record)

                    # Check constraint (e.g. 200 lines or 60 seconds)
                    if len(self.raw_batch_buffer) >= self.batch_size_threshold or (time.time() - self.last_flush_time > 60.0):
                        self._flush_batch_to_files()

                self.stats["total_received"] += 1
                self.stats["total_formatted"] += 1
                eps_counter += 1

                # Calculate live EPS
                if time.time() - eps_timer >= 1.0:
                    self.stats["current_eps"] = round(eps_counter / (time.time() - eps_timer), 1)
                    eps_counter = 0
                    eps_timer = time.time()

            except socket.timeout:
                # Check periodic flush on timeout
                with self.batch_lock:
                    if self.raw_batch_buffer and (time.time() - self.last_flush_time > 30.0):
                        self._flush_batch_to_files()
                continue
            except Exception as e:
                time.sleep(0.05)

        sock.close()

    def _flush_batch_to_files(self, force: bool = False):
        """Flushes batch buffer into separate raw (.log) and formatted (.json) files."""
        if not self.raw_batch_buffer and not force:
            return

        if not self.raw_batch_buffer:
            return

        ts_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")[:19]
        raw_file_name = f"raw_batch_{ts_str}.log"
        formatted_file_name = f"formatted_batch_{ts_str}.json"

        raw_path = os.path.join(RAW_STORAGE_DIR, raw_file_name)
        formatted_path = os.path.join(FORMATTED_STORAGE_DIR, formatted_file_name)

        # Write Raw Log File
        with open(raw_path, "w", encoding="utf-8") as f_raw:
            f_raw.write("\n".join(self.raw_batch_buffer) + "\n")

        # Write Formatted JSON File
        with open(formatted_path, "w", encoding="utf-8") as f_json:
            json.dump(self.formatted_batch_buffer, f_json, indent=2)

        # Flush Parquet Sink
        self.engine.sink_writer.flush()

        self.stats["total_files_created"] += 2
        self.raw_batch_buffer.clear()
        self.formatted_batch_buffer.clear()
        self.last_flush_time = time.time()

    def get_live_stream(self) -> List[Dict[str, Any]]:
        """Returns the current sliding window of live streaming records."""
        return list(self.live_stream_queue)

    def get_stored_files(self) -> Dict[str, List[Dict[str, Any]]]:
        """Returns a list of all created raw log files and formatted JSON files."""
        raw_files = []
        if os.path.exists(RAW_STORAGE_DIR):
            for fname in sorted(os.listdir(RAW_STORAGE_DIR), reverse=True):
                if fname.endswith(".log"):
                    fpath = os.path.join(RAW_STORAGE_DIR, fname)
                    size_kb = round(os.path.getsize(fpath) / 1024.0, 2)
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        lines = len(f.readlines())
                    raw_files.append({
                        "filename": fname,
                        "size_kb": size_kb,
                        "records": lines,
                        "path": fpath,
                        "timestamp": datetime.fromtimestamp(os.path.getmtime(fpath)).strftime("%Y-%m-%d %H:%M:%S")
                    })

        formatted_files = []
        if os.path.exists(FORMATTED_STORAGE_DIR):
            for fname in sorted(os.listdir(FORMATTED_STORAGE_DIR), reverse=True):
                if fname.endswith(".json"):
                    fpath = os.path.join(FORMATTED_STORAGE_DIR, fname)
                    size_kb = round(os.path.getsize(fpath) / 1024.0, 2)
                    try:
                        with open(fpath, "r", encoding="utf-8") as f:
                            data = json.load(f)
                            count = len(data) if isinstance(data, list) else 1
                    except Exception:
                        count = 0
                    formatted_files.append({
                        "filename": fname,
                        "size_kb": size_kb,
                        "records": count,
                        "path": fpath,
                        "timestamp": datetime.fromtimestamp(os.path.getmtime(fpath)).strftime("%Y-%m-%d %H:%M:%S")
                    })

        return {"raw_files": raw_files, "formatted_files": formatted_files}
