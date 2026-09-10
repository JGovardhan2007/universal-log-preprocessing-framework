# ==============================================================================
# Universal Log Pre-processing Framework (ULPF) - Production Container
# Compliant with NTRO Problem Statement 26156 & OCSF v1.1.0 Standard
# ==============================================================================
FROM python:3.12-slim

# System metadata
LABEL maintainer="ULPF Development Team"
LABEL description="Universal Log Pre-processing Framework with 4-Model AI Ensemble, Section 65B Forensics, and SOC Web Console"

# Set environment flags
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Install core runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy source tree and configuration assets
COPY core_engine /app/core_engine
COPY parsers /app/parsers
COPY schemas /app/schemas
COPY rules /app/rules
COPY tests /app/tests
COPY web /app/web
COPY data /app/data

# Ensure data directories exist for dual-buffer and forensic outputs
RUN mkdir -p /app/data/raw /app/data/formatted /app/data/dlq

# Expose Web Console / REST API (8080) and Wire Syslog UDP Intake (5140)
EXPOSE 8080/tcp
EXPOSE 5140/udp

# Healthcheck to verify FastAPI service uptime
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/api/v1/stats || exit 1

# Launch production server daemon
CMD ["python", "core_engine/web_server.py"]
