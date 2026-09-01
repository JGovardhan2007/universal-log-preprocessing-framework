# ==============================================================================
# Universal Log Pre-processing Framework (ULPF) - Production Containerfile
# Problem Statement ID: 26156 (Air-Gapped Containerized Image)
# ==============================================================================

FROM python:3.12-slim-bookworm

# Set container environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DEBIAN_FRONTEND=noninteractive \
    ULPF_ENV=production

# Install essential build & networking packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    g++ \
    libsnappy-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy dependency requirements
COPY requirements.txt .
COPY dashboard/requirements.txt dashboard_requirements.txt
COPY test_tools/requirements.txt test_requirements.txt

# Install all Python dependencies into the image
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir -r dashboard_requirements.txt \
    && pip install --no-cache-dir -r test_requirements.txt \
    && pip install --no-cache-dir kafka-python-ng pytest

# Copy codebase
COPY . .

# Create persistent storage directories
RUN mkdir -p data/lake data/dlq data/incoming sample_logs

# Expose all operational ports:
# 5140/udp - Syslog Wire Ingest
# 8000/tcp - REST Ingestion API
# 8501/tcp - Streamlit SOC Forensic Control Center
EXPOSE 5140/udp 8000/tcp 8501/tcp

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# Default Entrypoint: Launch ULPF Production Engine
CMD ["python", "run_engine.py", "--port", "5140", "--api-port", "8000", "--dashboard"]
