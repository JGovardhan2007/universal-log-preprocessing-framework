"""
Universal Log Pre-processing Framework (ULPF)
High-Speed REST API Ingestion & Verification Server
Compliance: PRD FR-1.3 (REST Webhook Ingest) & Section 65B Audit API
"""

import os
import time
from typing import Dict, Any, List, Optional, Union
from pydantic import BaseModel, Field
from fastapi import FastAPI, HTTPException, BackgroundTasks, status
from fastapi.middleware.cors import CORSMiddleware
from core_engine.engine import Engine
from core_engine.hasher import ForensicHasher


# Pydantic Request & Response Models
class IngestSingleRequest(BaseModel):
    raw_log: str = Field(..., description="Raw log string to ingest and normalize")
    source_ip: Optional[str] = Field("127.0.0.1", description="Source client/socket IP")


class IngestBatchRequest(BaseModel):
    logs: List[str] = Field(..., description="Batch of raw log strings")
    source_ip: Optional[str] = Field("127.0.0.1", description="Source IP for batch")


class VerifyRequest(BaseModel):
    event_id: str = Field(..., description="RFC 4122 UUID of the event")
    raw_data: str = Field(..., description="Exact raw text to verify")
    expected_hash: str = Field(..., description="Pre-parsing SHA-256 hash recorded in metadata")


# Initialize FastAPI App
app = FastAPI(
    title="ULPF REST Ingestion & Forensic API",
    description="High-Throughput Log Pre-processing & Section 65B Verification API for NTRO/NCIIPC",
    version="1.1.0",
)

# Enable CORS for dashboard web access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global Engine Instance
_engine_instance: Optional[Engine] = None


def get_engine() -> Engine:
    """Get or initialize singleton engine instance."""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = Engine(
            parsers_dir=os.environ.get("ULPF_PARSERS_DIR", "parsers"),
            parquet_path=os.environ.get("ULPF_PARQUET_PATH", "data/stream_buffer.parquet")
        )
    return _engine_instance


@app.get("/api/v1/health", tags=["Telemetry"])
def get_health() -> Dict[str, Any]:
    """Retrieve engine real-time metrics, buffer status, and uptime."""
    engine = get_engine()
    now = time.time()
    uptime_sec = round(now - engine.metrics["start_time"], 2)
    return {
        "status": "HEALTHY",
        "framework": "ULPF-NTRO-v1.1",
        "uptime_seconds": uptime_sec,
        "metrics": engine.metrics,
        "active_parsers_count": len(engine.parser_loader.parsers),
        "parquet_sink_path": str(engine.sink_writer.output_path),
        "total_flushed_to_parquet": engine.sink_writer.total_written
    }


@app.get("/api/v1/parsers", tags=["Parsers"])
def list_parsers() -> Dict[str, Any]:
    """List all active declarative YAML parsers and their metadata."""
    engine = get_engine()
    # Check for hot reloads
    engine.parser_loader.check_and_hot_reload()

    parsers_info = {}
    for name, parser in engine.parser_loader.parsers.items():
        parsers_info[name] = {
            "vendor": parser.vendor,
            "product": parser.product,
            "version": parser.version,
            "description": parser.description,
            "sig_type": parser.sig_type,
            "extraction_type": parser.ext_type
        }
    return {
        "total_parsers": len(parsers_info),
        "last_reload_time": engine.parser_loader.last_reload_time,
        "parsers": parsers_info
    }


@app.post("/api/v1/ingest", status_code=status.HTTP_200_OK, tags=["Ingestion"])
def ingest_log(payload: IngestSingleRequest) -> Dict[str, Any]:
    """
    Ingest a single raw log event over HTTP webhook.
    Computes pre-parsing SHA-256, classifies into 3-tier taxonomy,
    normalizes to OCSF Class 4001, and queues to Parquet sink.
    """
    if not payload.raw_log:
        raise HTTPException(status_code=400, detail="raw_log payload cannot be empty")

    engine = get_engine()
    raw_bytes = payload.raw_log.encode("utf-8")
    ocsf_record = engine.process_single(raw_bytes, source_ip=payload.source_ip or "127.0.0.1")

    return {
        "status": "PROCESSED",
        "event_id": ocsf_record["event_id"],
        "sha256_hash": ocsf_record["metadata"]["hash"],
        "class_uid": ocsf_record["class_uid"],
        "disposition": ocsf_record["disposition"],
        "ocsf_record": ocsf_record
    }


@app.post("/api/v1/ingest/batch", status_code=status.HTTP_200_OK, tags=["Ingestion"])
def ingest_batch(payload: IngestBatchRequest) -> Dict[str, Any]:
    """
    Ingest a batch of raw log lines over HTTP.
    """
    if not payload.logs:
        raise HTTPException(status_code=400, detail="logs batch cannot be empty")

    engine = get_engine()
    results = []
    t0 = time.perf_counter()

    for line in payload.logs:
        if line.strip():
            rec = engine.process_single(line.encode("utf-8"), source_ip=payload.source_ip or "127.0.0.1")
            results.append({
                "event_id": rec["event_id"],
                "hash": rec["metadata"]["hash"],
                "vendor": rec["metadata"]["product"]["vendor_name"],
                "disposition": rec["disposition"]
            })

    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return {
        "status": "BATCH_PROCESSED",
        "count": len(results),
        "elapsed_ms": round(elapsed_ms, 2),
        "results": results
    }


@app.post("/api/v1/verify", tags=["Forensics"])
def verify_log_integrity(payload: VerifyRequest) -> Dict[str, Any]:
    """
    Execute Section 65B forensic verification on any raw log payload.
    Checks SHA256(raw_data) == expected_hash and returns a legal audit receipt.
    """
    receipt = ForensicHasher.generate_audit_receipt(
        event_id=payload.event_id,
        raw_data=payload.raw_data,
        recorded_hash=payload.expected_hash
    )
    return receipt
