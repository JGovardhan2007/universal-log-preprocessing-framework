"""
Unit Tests for Phase 2: File Ingestion & Tailer (PRD FR-1.2)
"""

import tempfile
from pathlib import Path
from core_engine.engine import Engine
from core_engine.file_tailer import FileIngestTailer


def test_file_tailer_sync_ingest():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        incoming_dir = tmp_path / "incoming"
        processed_dir = tmp_path / "processed"
        incoming_dir.mkdir(parents=True, exist_ok=True)
        processed_dir.mkdir(parents=True, exist_ok=True)

        engine = Engine(parsers_dir="parsers", parquet_path=str(tmp_path / "stream.parquet"))
        tailer = FileIngestTailer(engine=engine, watch_dir=str(incoming_dir), processed_dir=str(processed_dir))

        # Create dummy log file
        sample_file = incoming_dir / "test_firewall.log"
        sample_file.write_text(
            "%ASA-4-106023: Deny tcp src outside:203.0.113.15/44123 dst inside:192.168.1.50/80\n"
            'date=2026-09-01 time=08:30:00 devname="FGT60D" srcip=192.168.1.50 dstip=10.0.0.5 action="accept"\n',
            encoding="utf-8"
        )

        ingested = tailer.ingest_file_sync(sample_file)
        assert ingested == 2
        assert engine.metrics["total_received"] >= 2

