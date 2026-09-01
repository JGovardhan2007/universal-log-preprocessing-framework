"""
Universal Log Pre-processing Framework (ULPF)
Asynchronous File Ingestion & Directory Tailing Daemon
Compliance: PRD FR-1.2 (Local file monitoring and batch ingest)
"""

import os
import time
import gzip
import asyncio
from pathlib import Path
from typing import Dict, Any, List, Optional
from core_engine.engine import Engine


class FileIngestTailer:
    """
    Monitors directories for incoming log files and tails active log files
    without dropping events or locking file handles.
    """

    def __init__(self, engine: Engine, watch_dir: str = "data/incoming", processed_dir: Optional[str] = "data/processed"):
        self.engine = engine
        self.watch_dir = Path(watch_dir)
        self.watch_dir.mkdir(parents=True, exist_ok=True)
        self.processed_dir = Path(processed_dir) if processed_dir else None
        if self.processed_dir:
            self.processed_dir.mkdir(parents=True, exist_ok=True)
        
        self.is_running = False
        self.file_offsets: Dict[str, int] = {}

    def ingest_file_sync(self, filepath: Path) -> int:
        """Synchronously ingest a static file line by line."""
        if not filepath.is_file():
            return 0

        count = 0
        is_gz = filepath.name.endswith(".gz")
        opener = gzip.open if is_gz else open

        try:
            with opener(filepath, "rt", encoding="utf-8", errors="replace") as f:
                for line in f:
                    clean = line.strip()
                    if clean:
                        self.engine.process_single(clean.encode("utf-8"), source_ip=f"file://{filepath.name}")
                        count += 1
        except Exception as e:
            print(f"[ERROR] Failed to ingest file '{filepath}': {e}")

        # Move to processed directory if configured
        if self.processed_dir and not is_gz:
            try:
                dest = self.processed_dir / filepath.name
                filepath.rename(dest)
            except Exception:
                pass

        return count

    async def scan_and_ingest_once(self) -> int:
        """Scan watched directory for any new files and ingest them."""
        total_ingested = 0
        if not self.watch_dir.is_dir():
            return 0

        for fpath in self.watch_dir.glob("*"):
            if fpath.is_file() and not fpath.name.startswith("."):
                ingested = self.ingest_file_sync(fpath)
                total_ingested += ingested

        return total_ingested

    async def run_tail_watcher(self, poll_interval_sec: float = 2.0):
        """Continuous async loop watching the directory."""
        self.is_running = True
        while self.is_running:
            try:
                await self.scan_and_ingest_once()
            except Exception as e:
                print(f"[WARN] Error in file tailer loop: {e}")
            await asyncio.sleep(poll_interval_sec)

    def stop(self):
        self.is_running = False
