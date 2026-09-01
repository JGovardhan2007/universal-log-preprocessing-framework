#!/usr/bin/env python3
"""
Universal Log Pre-processing Framework (ULPF)
Production FastAPI Modern Web Server & Ingestion Controller
Serves the High-Performance Obsidian & Neon Ember Cyber Web App
"""

import os
import sys
import json
from typing import Optional
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Ensure project root in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core_engine.live_service import LiveLogPipelineService, RAW_STORAGE_DIR, FORMATTED_STORAGE_DIR

app = FastAPI(
    title="ULPF Cyber Web Application",
    description="High-Performance Frontend & Forensic Ingestion Subsystem for NTRO 26156",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

service = LiveLogPipelineService.get_instance()

# Static web directory
WEB_DIR = os.path.join(PROJECT_ROOT, "web")


class SpeedRequest(BaseModel):
    eps: int = 10


@app.get("/api/v1/stats")
def get_stats():
    """Returns live telemetry and buffer status."""
    buf = service.get_buffer_status()
    files = service.get_stored_files()
    return {
        "total_ingested": service.stats["total_received"],
        "current_eps": service.stats["current_eps"],
        "anomalies": service.stats["anomalies_detected"],
        "total_batches": len(files["raw_files"]),
        "is_running": service.is_running,
        "speed": service.logs_per_second,
        "buffer_raw_count": buf["raw_count"],
        "buffer_threshold": buf["threshold"],
        "buffer_percentage": buf["percentage"]
    }


@app.post("/api/v1/stream/start")
def start_stream(req: SpeedRequest = SpeedRequest(eps=10)):
    """Starts the continuous UDP 5140 live ingestion stream."""
    service.start(eps=req.eps)
    return {"status": "started", "eps": req.eps}


@app.post("/api/v1/stream/stop")
def stop_stream():
    """Stops the live ingestion stream."""
    service.stop()
    return {"status": "stopped"}


@app.post("/api/v1/stream/speed")
def set_speed(req: SpeedRequest):
    """Adjusts live stream generation speed."""
    service.set_speed(req.eps)
    return {"status": "speed_updated", "eps": req.eps}


@app.post("/api/v1/stream/flush")
def flush_buffer():
    """Forces immediate flush of in-memory dual-buffers into .log and .json files."""
    service.flush_now()
    return {"status": "flushed"}


@app.get("/api/v1/files")
def list_files():
    """Returns all stored raw and formatted files."""
    return service.get_stored_files()


@app.get("/api/v1/files/content")
def get_file_content(filename: str):
    """Fetches side-by-side content for the selected batch."""
    raw_path = os.path.join(RAW_STORAGE_DIR, filename)
    fmt_filename = filename.replace("raw_batch_", "formatted_batch_").replace(".log", ".json")
    fmt_path = os.path.join(FORMATTED_STORAGE_DIR, fmt_filename)

    raw_content = ""
    fmt_content = None

    if os.path.exists(raw_path):
        with open(raw_path, "r", encoding="utf-8", errors="ignore") as f:
            raw_content = f.read()

    if os.path.exists(fmt_path):
        with open(fmt_path, "r", encoding="utf-8", errors="ignore") as f:
            try:
                fmt_content = json.load(f)
            except Exception:
                fmt_content = f.read()

    return {
        "filename": filename,
        "raw_content": raw_content,
        "formatted_content": fmt_content
    }


from fastapi.responses import FileResponse

@app.get("/api/v1/files/download")
def download_file(filename: str):
    """Downloads a stored raw .log or formatted .json file."""
    if filename.endswith(".log"):
        target_path = os.path.join(RAW_STORAGE_DIR, filename)
    elif filename.endswith(".json"):
        target_path = os.path.join(FORMATTED_STORAGE_DIR, filename)
    else:
        raise HTTPException(status_code=400, detail="Invalid file type")

    if not os.path.exists(target_path):
        raise HTTPException(status_code=404, detail="File not found")

    return FileResponse(
        path=target_path,
        filename=filename,
        media_type="application/octet-stream"
    )


# Mount the modern static web app at root
if os.path.exists(WEB_DIR):
    app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="static")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)

