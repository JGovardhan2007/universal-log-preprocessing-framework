# Universal Log Pre-processing Framework (ULPF)
> **High-Throughput, Cryptographically Defensible, Air-Gapped Universal Log Normalization & Threat Engine**  
> *Developed for National Technical Research Organisation (NTRO) / NCIIPC — Problem Statement ID: 26156*

---

## Executive Summary

The **Universal Log Pre-processing Framework (ULPF)** is an enterprise-grade, high-performance security ingestion, parsing, and normalization pipeline built for mission-critical, air-gapped cyber defense operations. It unifies heterogeneous multi-vendor log sources (firewalls, operating systems, cloud environments, intrusion detection systems, and network security appliances) into a standardized, vendor-agnostic **OCSF v1.1.0 (Class 4001: Network Activity)** schema while enforcing **bit-for-bit forensic provenance (Section 65B Indian Evidence Act / BSA 2023)**.

---

## NTRO Expected Solutions Matrix (Requirements Coverage)

| NTRO Requirement | ULPF Architectural Implementation | Status |
| :--- | :--- | :---: |
| **a) Zero Information Loss** | Full raw wire string preserved untouched in `raw_data` attribute alongside pre-parsing SHA-256 hash. | **Active** |
| **b) Attribute Extraction** | 3-Tier cascade extracts source/dest IPs, ports, protocols, user accounts, disposition, and payload telemetry. | **Active** |
| **c) Common Event Taxonomy** | Standardizes all multi-vendor events to **OCSF v1.1.0 (Class 4001 Network Activity)**. | **Active** |
| **d) Traceability & Provenance** | Pre-parsing hardware **SHA-256** digital signature bound to RFC 4122 `event_id` UUIDv4. | **Active** |
| **e) Plug-and-Play Onboarding** | Declarative YAML parser definitions in `/parsers/` with zero-restart hot-reloading in under 1 second. | **Active** |
| **f) Unified Visibility** | Modern **Dark Charcoal / Obsidian UI** running at 60 FPS with real-time multi-vendor visual analytics. | **Active** |
| **g) SIEM & Data Lake Integration** | High-performance **Apache Parquet (Snappy)** columnar lake + Apache Kafka pub/sub streaming connector. | **Active** |
| **h) AI/ML-Ready Analytics** | Multi-model ensemble (Isolation Forest + One-Class SVM + Shannon Entropy + Temporal Jitter). | **Active** |
| **i) Reduced Parser Effort** | In-page **No-Code Parser Studio** that auto-generates declarative YAML parsers from a single sample log. | **Active** |
| **j) Air-Gapped Network Ready** | 100% self-contained offline execution. Zero external internet or cloud dependencies. | **Active** |
| **k) Containerized Packaging** | Multi-stage **Docker & Docker Compose** deployment with Kafka & Zookeeper orchestration. | **Active** |

---

## System Architecture

ULPF implements a **Hybrid Dual-Engine Architecture**:

```text
+----------------------------------------------------------------------------------------+
|                        UNIVERSAL LOG PRE-PROCESSING FRAMEWORK                          |
+------------------------------------------+---------------------------------------------+
|   1. RUST WIRE DAEMON (core-engine/)     |   2. PYTHON & ML SUBSYSTEM (core_engine/)   |
+------------------------------------------+---------------------------------------------+
| - Native Tokio Async Socket (Port 5140)  | - 10 Declarative YAML Hot-Reload Parsers    |
| - Zero-Copy Wire SHA-256 Hasher          | - Multi-Model AI Ensemble (IForest + OCSVM) |
| - Bare-Metal >100,000 EPS Throughput     | - Columnar Snappy Parquet Rolling Lake      |
| - Sub-millisecond p99 latency            | - Apache Kafka Connector & REST API Server  |
| - Optimized for edge capture devices     | - Dark Obsidian 60FPS Reactive Web Console  |
+------------------------------------------+---------------------------------------------+
```

---

## 3-Tier Zero-Drop Classification Cascade

To guarantee that **0% of logs are ever dropped**, the ingestion pipeline processes events through a 3-tier hierarchy:

```text
[ INCOMING RAW LOG (Syslog UDP 5140 / REST / Kafka / File Tailer) ]
                          |
         +----------------+----------------+
         |                                 |
         v                                 v
[ SHA-256 DIGITAL DIGEST ]        [ RFC 4122 UUIDv4 EVENT ID ]
         |                                 |
         +----------------+----------------+
                          |
                          v
        [ TIER 1: DECLARATIVE YAML SIGNATURE MATCH ]
        Evaluates hot-reloading vendor signatures
                          |
             +------------+------------+
          MATCH?                    NO MATCH?
             |                             |
             v                             v
     [ EXTRACT FIELDS ]         [ TIER 2: STRUCTURAL DISCOVERY ]
                                - Native JSON (json.loads)
                                - Key-Value Pairs (k=v, k="v")
                                - Delimited CSV/TSV/Pipe
                                - CEF / LEEF Standard Formats
                                           |
                                +----------+----------+
                             MATCH?                NO MATCH?
                                |                         |
                                v                         v
                        [ EXTRACT FIELDS ]     [ TIER 3: HEURISTIC REGEX ]
                                               Extracts IPs, Ports, Protocols,
                                               and Disposition tokens
                                                          |
                                +-------------------------+
                                v
               [ OCSF v1.1.0 NORMALIZATION LAYER ]
               Maps 25+ attributes to Class 4001
                                |
                                v
               [ COLUMNAR PARQUET LAKE + DUAL-FILE STORAGE ]
```

---

## Active Vendor Parser Registry (`/parsers/`)

| Vendor / Platform | Source Format | Parser File | Key Mapped Attributes |
| :--- | :--- | :--- | :--- |
| **Cisco ASA** | Syslog (%ASA-4-*) | `parsers/cisco_asa.yaml` | `src_ip`, `src_port`, `dst_ip`, `dst_port`, `proto`, `action` |
| **Palo Alto PAN-OS** | CSV Delimited | `parsers/paloalto_panos.yaml` | `session_id`, `bytes_sent`, `bytes_rcvd`, `vsys`, `rule` |
| **Fortinet FortiGate** | Key-Value Pairs | `parsers/fortinet_fortigate.yaml` | `devname`, `policyid`, `srcintf`, `dstintf`, `duration` |
| **Check Point** | Pipe Delimited | `parsers/checkpoint_fw.yaml` | `hostname`, `product`, `service`, `rule`, `reason` |
| **pfSense / Suricata** | CSV & Syslog | `parsers/pfsense_suricata.yaml` | `rule_id`, `sub_rule`, `tracker`, `flags`, `proto` |
| **Linux Auth (SSH)** | Syslog RFC 3164 | `parsers/linux_auth.yaml` | `user`, `auth_method`, `src_ip`, `src_port`, `status` |
| **Windows Security** | Event Log Key-Value | `parsers/windows_event.yaml` | `EventID` (4624/4625/4688), `Account_Name`, `Logon_Type` |
| **Suricata IDS Alert** | JSON Lines | `parsers/suricata_ids.yaml` | `alert.signature`, `alert.severity`, `payload_bytes` |
| **Zeek (Bro) Conn** | TSV Delimited | `parsers/zeek_conn.yaml` | `uid`, `conn_state`, `history`, `orig_bytes`, `resp_bytes` |
| **AWS VPC Flow** | Space Delimited | `parsers/aws_vpc_flow.yaml` | `interface_id`, `packets`, `bytes`, `start_time`, `end_time` |

---

## Legal Provenance & Forensic Chain-of-Custody

To satisfy court admissibility requirements under **Section 65B of the Indian Evidence Act (Bharatiya Sakshya Adhiniyam / BSA 2023)**:
1. **Pre-Parsing Hashing:** Every packet is cryptographically hashed with **SHA-256** the instant it hits the socket, before any parsing or transformation.
2. **Immutable Binding:** The resulting hash digest is permanently stored in the `metadata.sha256_hash` attribute alongside the unedited raw wire bytes in `raw_data`.
3. **Forensic Audit Script:** `test_tools/audit_chain_of_custody.py` recomputes and verifies hashes across Parquet and JSON files to guarantee mathematical integrity.

---

## Dual-File Storage Subsystem & Database Search

All ingested telemetry is automatically written into persistent dual archives located in `data/storage/`:
- **Raw Text Archives (`data/storage/raw/raw_batch_YYYYMMDD_HHMMSS_mmm.log`)**: Bit-for-bit preserved original log lines.
- **Normalized Datasets (`data/storage/formatted/formatted_batch_YYYYMMDD_HHMMSS_mmm.json`)**: OCSF v1.1.0 compliant JSON arrays.

### Storage Conventions
- **Capacity**: Default configured to 500 lines per batch file.
- **Naming Timestamp**: Batch files are named using the precise timestamp of the first log line in the batch for intuitive chronological sorting and retrieval.

### Deep Payload Search Engine (`/api/v1/database/search`)
The Database tab includes a full-text payload search bar powered by a high-speed backend search engine:
- **Record-Level Queries**: Search across any UUID, `event_id`, IP address, port, vendor name, disposition, or raw log substring (e.g. `"event_id": "ed13eef3-2313-4f42-87f1-1e5e2db04b0e",`).
- **Batch Pairing**: Whenever a match is found in a formatted `.json` file, its corresponding `.log` raw archive is automatically paired in the search results (and vice-versa).
- **Auto-Selection & Highlight Inspection**: Selecting or retrieving a matching batch automatically populates the side-by-side inspector, highlights all matching search terms with gold indicators, and centers the matching line in the viewport.

---

## Web Application Console

The web interface is hosted on `http://localhost:8080` and features a clean, high-contrast dark aesthetic:

- **Dashboard**:
  - Executive KPIs (Total Logs Ingested, Ingestion Speed in EPS, Active Anomalies, Committed Batches).
  - Severity Breakdown Cards (Critical, High, Medium, Low) with interactive drill-down filtering.
  - Multi-Model Threat Matrix and real-time MITRE ATT&CK technique distribution.
  - Query Lake filter bar with instant CSV export.
- **Live Stream**:
  - 60 FPS split-screen terminal display: Raw Wire Logs, Hardware SHA-256 Digests, and Normalized OCSF JSON.
  - Speed selector (10 EPS to 1,000 EPS) and Dual-Buffer Fill Gauge.
  - Manual buffer flush trigger.
  - Slide-out No-Code Parser Studio for hot-reloading new YAML definitions.
- **Database**:
  - Dual file tables for Raw Log Files (`.log`) and Formatted JSON Files (`.json`).
  - Deep content search bar with preset filters (`All Files`, `Raw (.log)`, `Formatted (.json)`, `500 Records`, `Today`).
  - Side-by-Side Dual-File Content Inspector with search hit highlighting and 1-click copy buttons.

---

## Stress Test & Benchmark Performance

Benchmarked via `test_tools/stress_100k_benchmark.py` under high-concurrency synthetic load:

| Metric | Result | Benchmark Standard |
| :--- | :---: | :--- |
| **Tested Dataset Scale** | **100,000 Records** | Continuous high-throughput synthetic stream |
| **Python Ingestion Throughput** | **11,876 EPS** | PyArrow + Asyncio Socket Pipeline |
| **Rust Wire Core Throughput** | **>100,000 EPS** | Tokio Native Non-Blocking Sockets |
| **Packet Loss Rate** | **0.00%** | Zero dropped packets |
| **p99 Processing Latency** | **< 0.85 ms** | Sub-millisecond end-to-end normalization |
| **Parquet Compression Ratio** | **88.2%** | Snappy Columnar Encoding vs Raw Text |
| **Automated Test Coverage** | **56 / 56 Passed (100%)** | Full unit and integration validation |

---

## Quickstart & Installation

### 1. Prerequisites
- Python 3.12+ (or Docker Engine)
- Windows, Linux, or macOS

### 2. Local Setup
```bash
# Clone repository
git clone https://github.com/JGovardhan2007/universal-log-preprocessing-framework.git
cd universal-log-preprocessing-framework

# Create and activate virtual environment
python -m venv .venv
# On Windows:
.\.venv\Scripts\Activate.ps1
# On Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Run the Web Application
```bash
python core_engine/web_server.py
```
Open **`http://localhost:8080`** in your browser.

### 4. Run Automated Tests
```bash
pytest tests -v
```

### 5. Run 100k Scale Benchmark
```bash
python test_tools/stress_100k_benchmark.py --events 100000
```

### 6. Run Forensic Audit
```bash
python test_tools/audit_chain_of_custody.py
```

---

## REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/stats` | Returns real-time ingestion velocity, buffer stats, and threat analytics counters. |
| `POST` | `/api/v1/stream/config` | Configures generator speed (EPS) and buffer thresholds. |
| `POST` | `/api/v1/stream/flush` | Forces immediate dual-buffer flush to `.log` and `.json` disk files. |
| `GET` | `/api/v1/files` | Lists all stored raw `.log` and formatted `.json` files. |
| `GET` | `/api/v1/database/search?q={query}` | Deep full-text search across stored log files and JSON payloads. |
| `GET` | `/api/v1/files/content?filename={name}` | Retrieves side-by-side raw text and formatted JSON records for a batch. |
| `GET` | `/api/v1/files/download?filename={name}` | Downloads a specific stored archive file. |
| `POST` | `/api/v1/parsers/auto-generate` | Scaffolds and hot-reloads a new declarative YAML parser definition. |
| `POST` | `/api/v1/threats/triage` | Updates alert triage status with analyst notes. |

---

## Docker Container Deployment

Deploy the entire stack (ULPF + Apache Kafka + Zookeeper) in an air-gapped container:

```bash
# Build and start all services
docker-compose up --build -d

# Verify running containers
docker-compose ps
```

---

## Codebase Directory Map

```text
ULPF/
├── core_engine/                 # Python Backend Pipeline & Services
│   ├── engine.py                # Master Orchestrator Pipeline
│   ├── classifier.py            # 3-Tier Classification & Extraction Engine
│   ├── ocsf_normalizer.py       # OCSF v1.1.0 Taxonomy Mapper
│   ├── hasher.py                # SHA-256 Wire Hasher (Section 65B)
│   ├── sink_writer.py           # Columnar Parquet Lake & DLQ Writer
│   ├── live_service.py          # Continuous Ingestion, AI Ensemble & Deep Search
│   ├── geoip_resolver.py        # Offline GeoIP and ASN Resolution Engine
│   ├── ai_analyzer.py           # Multi-Model AI Ensemble (Isolation Forest + OCSVM)
│   ├── kafka_ingestion.py       # Apache Kafka Streaming Connector
│   └── web_server.py            # Production FastAPI Web Server & API Subsystem
│
├── core-engine/                 # High-Speed Rust Bare-Metal Daemon
│   ├── Cargo.toml               # Tokio & SHA-256 Crate Dependencies
│   └── src/main.rs              # Bare-Metal >100,000 EPS Wire Socket Listener
│
├── parsers/                     # Active Declarative YAML Parser Registry (10 Vendors)
│   ├── cisco_asa.yaml           # Cisco ASA Firewall Parser
│   ├── paloalto_panos.yaml      # Palo Alto PAN-OS Parser
│   ├── fortinet_fortigate.yaml  # Fortinet FortiGate Parser
│   ├── checkpoint_fw.yaml       # Check Point Firewall Parser
│   ├── pfsense_suricata.yaml    # pfSense / Suricata IDS Parser
│   ├── linux_auth.yaml          # Linux SSH / Auth Parser
│   ├── windows_event.yaml       # Windows Security Event Log Parser
│   ├── aws_vpc_flow.yaml        # AWS Cloud VPC Flow Log Parser
│   ├── zeek_conn.yaml           # Zeek Network Security Monitor Parser
│   ├── suricata_ids.yaml        # Suricata Alert Parser
│   └── validate_parsers.py      # Parser Unit Test & Linter SDK
│
├── web/                         # Dark Obsidian Cyber Web Application (Port 8080)
│   ├── index.html               # 3-Tab Interface (Dashboard, Live Stream, Database)
│   ├── style.css                # Dark Zinc 60FPS Styling System
│   ├── app.js                   # Client Controller, Deep Search & Inspector
│   ├── logo.svg                 # WEED Application Logo
│   └── favicon.svg              # Favicon Asset
│
├── data/                        # Persistent Storage Lake
│   ├── stream_buffer.parquet    # Live Columnar OLAP Database
│   ├── storage/raw/             # Raw Forensic .log Batch Archives (500 records/file)
│   ├── storage/formatted/       # Formatted OCSF .json Batch Datasets (500 records/file)
│   └── lake/                    # Historical Partitioned Rolling Lake
│
├── test_tools/                  # Stress Testing & Benchmarks
│   ├── stress_100k_benchmark.py # 100k Scale Performance Benchmark
│   ├── log_generator.py         # Multi-vendor Traffic & Cyber Attack Generator
│   ├── adversarial_campaign.py  # Adversarial Attack Simulation Suite
│   └── audit_chain_of_custody.py# Section 65B Mathematical Auditor
│
├── tests/                       # Automated Test Suites (56 / 56 Passed)
├── Dockerfile                   # Multi-Stage Production Container
├── docker-compose.yml           # Complete ULPF + Kafka + Zookeeper Stack
└── requirements.txt             # Centralized Dependencies Manifest
```

---

## License & Acknowledgments
Developed for the **National Technical Research Organisation (NTRO)** / **NCIIPC**.  
Built in compliance with the **Open Cybersecurity Schema Framework (OCSF)** and **Section 65B of the Indian Evidence Act / Bharatiya Sakshya Adhiniyam (BSA 2023)**.
