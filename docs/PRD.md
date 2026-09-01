# Product Requirements Document (PRD)
## Universal Log Pre-processing Framework (ULPF)
**Target Organization:** National Technical Research Organisation (NTRO) / NCIIPC  
**Problem Statement ID:** 26156 (Theme: Blockchain & Cybersecurity)  
**Document Version:** 1.0.0  
**Status:** Approved / Engineering Baseline  

---

## 1. Executive Summary & Vision

Modern cybersecurity infrastructure relies heavily on perimeter and endpoint telemetry. Enterprise and defense networks ingest gigabytes to terabytes of heterogeneous logs daily from firewalls (Cisco, Palo Alto, Fortinet, Check Point), intrusion detection systems (Snort, Suricata), operating systems (Linux Syslog, Windows Event Logs), and network appliances.

Each vendor formats logs differently (Syslog RFC 5424/3164, CSV, Key-Value, JSON, CEF, LEEF, proprietary binary/text). Security Operations Centers (SOCs) currently suffer from:
1. **Parser Hell:** Security engineers spend 30–40% of their operational bandwidth writing, updating, and fixing fragile regex parsers.
2. **Lossy Pre-processing:** Mainstream tools alter timestamps, strip headers, or discard unparsed fields, rendering logs legally useless for judicial forensics under national evidence acts.
3. **Resource Inefficiency:** Legacy JVM-based log processors (e.g., Logstash) demand gigabytes of RAM and choke during traffic spikes (>20k EPS).
4. **Air-Gap Incompatibility:** Modern cloud-native log tools depend on telemetry pings and external SaaS licensing servers, violating strict air-gapped defense enclaves.

**The Vision:**  
The **Universal Log Pre-processing Framework (ULPF)** is a sovereign, high-throughput, memory-safe pre-processing pipeline built in **Rust** with a **Python AI & Forensic Control Layer**. It delivers **lossless ingestion**, **cryptographic chain-of-custody (SHA-256)**, **instant declarative YAML onboarding**, **OCSF v1.1.0 standard taxonomy normalization**, and **AI/ML columnar streaming (Apache Arrow / Parquet)** inside 100% offline, air-gapped networks.

---

## 2. Target Personas & Use Cases

```
┌─────────────────────────┬────────────────────────────────────────────────────────────────────────┐
│ Persona                 │ Primary Needs & System Interactions                                   │
├─────────────────────────┼────────────────────────────────────────────────────────────────────────┤
│ SOC Tier 1/2 Analyst    │ Needs normalized, human-readable security logs across all vendors     │
│                         │ without manual query syntax translations (single unified OCSF schema). │
├─────────────────────────┼────────────────────────────────────────────────────────────────────────┤
│ Forensic Investigator   │ Requires absolute proof that logs have not been tampered with;        │
│ & Legal Auditor         │ verifies SHA-256 checksums of original raw payloads for court proof.   │
├─────────────────────────┼────────────────────────────────────────────────────────────────────────┤
│ SOC Platform Engineer   │ Onboards new firewall models in <5 minutes using declarative YAML      │
│                         │ without restarting daemons or dropping live UDP packets.              │
├─────────────────────────┼────────────────────────────────────────────────────────────────────────┤
│ Security Data Scientist │ Loads high-speed network event streams directly into PyTorch/Pandas    │
│                         │ without ETL lag using columnar Apache Arrow memory buffers.            │
└─────────────────────────┴────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Scope of the System

### 3.1 In Scope
- **Multi-Protocol Ingestion:** UDP/TCP Syslog (RFC 3164 / 5424), Local File Watcher, REST Webhook endpoints, and batch forensic log imports.
- **Lossless Raw Preservation:** Exact raw byte capture paired with an immutable UUID and SHA-256 digest.
- **3-Tier Classification Engine:**
  1. *Tier 1 (Signature Match):* Cisco ASA/FTD, Palo Alto PAN-OS, Fortinet FortiGate, Check Point.
  2. *Tier 2 (Structural Formats):* Auto-extracts JSON, Key-Value pairs, CEF, LEEF, CSV.
  3. *Tier 3 (Heuristic Fallback):* Regex extraction for IP, Port, Protocol, and Timestamp with zero packet drop.
- **Standard Taxonomy Normalization:** OCSF (Open Cybersecurity Schema Framework) v1.1.0 Class 4001 (Network Activity).
- **Declarative Hot-Reload Rules:** YAML parser rules loaded dynamically into memory without service disruption.
- **Air-Gapped Offline Operations:** Embedded MaxMind GeoIP (`GeoLite2-City.mmdb`) and pre-bundled taxonomy definitions.
- **Downstream Analytics Ready:** Real-time columnar Parquet / Apache Arrow streaming + JSON sinks.
- **Forensic & Control Dashboard:** Live split-screen normalizer, one-click SHA-256 evidence integrity verifier, and parser manager.

### 3.2 Out of Scope
- Full enterprise SIEM dashboarding (ULPF acts as the ultra-fast pre-processor and data layer for SIEMs like Wazuh, Elastic, or ClickHouse).
- Direct remote firewall firmware configuration/management.

---

## 4. Detailed Functional Requirements (FR)

### FR-1: High-Speed Multi-Channel Ingestion
- **FR-1.1:** The engine must bind to UDP/TCP sockets (default port `5140` / `514`) and handle non-blocking asynchronous event intake.
- **FR-1.2:** The engine must monitor designated directories (`/test_logs/` or `/data/incoming/`) for continuous file-tailing and batch log drops.
- **FR-1.3:** The engine must support REST API log submission (`POST /api/v1/ingest`).

### FR-2: Lossless Raw Preservation & Cryptographic Hashing
- **FR-2.1:** Upon receipt of an event byte array, the engine must immediately compute a **SHA-256** hash before any string parsing or mutation.
- **FR-2.2:** An RFC 4122 compliant **UUIDv4** `event_id` must be assigned to every record.
- **FR-2.3:** The original, unmutated string must be preserved in the `.raw_data` field of the normalized schema.
- **FR-2.4:** Ingestion metadata (reception timestamp `ingest_timestamp`, collector ID, source socket IP) must be recorded.

### FR-3: 3-Tier Multi-Format Auto-Detection
- **FR-3.1:** **Tier 1 (Vendor Signature):** Identify distinct headers (e.g., `%ASA-`, `%FTD-`, `TRAFFIC,`, `date=... devname=`).
- **FR-3.2:** **Tier 2 (Structured Encodings):** Auto-tokenize JSON payloads (`{...}`), Key-Value pairs (`key=value`), and CEF headers (`CEF:0|...`).
- **FR-3.3:** **Tier 3 (Safe Fallback):** For unrecognized text, extract IPv4/IPv6, port numbers, protocols, and actions using heuristic regex. Store unrecognized tokens under `.unmapped.*` with zero data loss.

### FR-4: OCSF v1.1.0 Standard Schema Normalization
- **FR-4.1:** All perimeter security events must map to **OCSF Class 4001 (Network Activity)**:
  - `class_uid`: `4001`
  - `category_uid`: `4` (Network Activity)
  - `activity_id`: `1` (Network Traffic) / `2` (Connection Attempt) / `6` (Traffic Drop)
  - `src_endpoint`: `{ "ip": "...", "port": 1234, "zone": "outside", "geo": {...} }`
  - `dst_endpoint`: `{ "ip": "...", "port": 80, "zone": "inside", "geo": {...} }`
  - `connection_info`: `{ "protocol_name": "TCP|UDP|ICMP", "direction": "Inbound|Outbound" }`
  - `disposition`: `"Allowed" | "Blocked" | "Dropped" | "Unknown"`
  - `metadata`: `{ "product": { "vendor_name": "...", "name": "..." }, "hash": "...", "version": "1.1.0" }`
  - `raw_data`: `"<exact raw string>"`

### FR-5: Declarative Hot-Reload Parser System
- **FR-5.1:** Parsers must be defined in human-readable YAML specification files located in `/parsers/`.
- **FR-5.2:** The engine must watch the `/parsers/` directory using file-system notifications and reload modified/new parser rules into memory within `<50ms` without restarting the process.
- **FR-5.3:** Parser configurations must allow regex extraction, field aliases, string transformations, and disposition mapping dictionaries.

### FR-6: Offline Air-Gapped Context Enrichment
- **FR-6.1:** System must perform IP-to-Country / City resolution using a local embedded MaxMind `.mmdb` binary file.
- **FR-6.2:** Zero network queries (DNS, external HTTP) are permitted during the enrichment phase.

### FR-7: Columnar Data Lake & AI/ML Streaming
- **FR-7.1:** Normalized OCSF events must be streamed into **Apache Arrow** IPC shared memory buffers and written as compressed **Parquet** files (`/output/events_*.parquet`).
- **FR-7.2:** Downstream Python AI pipelines must be able to load Parquet files directly via PyArrow/Pandas for anomaly detection without ETL overhead.

### FR-8: Forensic Verification & Interactive Dashboard
- **FR-8.1:** Web-based control dashboard (Streamlit/Python) displaying:
  - Live split-screen (Raw Incoming Stream $\leftrightarrow$ Normalized OCSF Stream).
  - Real-time performance meters (EPS counter, active memory usage, buffer lag).
  - Forensic Hash Inspector: Lookup by `event_id`, view byte comparison, and execute live SHA-256 verification.
  - Parser Manager: Live upload of new YAML configuration rules.
  - AI Anomaly Detector view: Visualizing cluster anomalies and threat scores.

---

## 5. Non-Functional Requirements (NFR)

```
┌─────────────────────────┬────────────────────────────────────────────────────────────────────────┐
│ Metric / Property       │ Target Specification                                                   │
├─────────────────────────┼────────────────────────────────────────────────────────────────────────┤
│ Throughput (Single Node)│ >= 100,000 Events Per Second (EPS) on 4 vCPU, 8 GB RAM                 │
├─────────────────────────┼────────────────────────────────────────────────────────────────────────┤
│ Processing Latency      │ P95 < 2.0 ms, P99 < 5.0 ms from socket receive to normalized sink      │
├─────────────────────────┼────────────────────────────────────────────────────────────────────────┤
│ Memory Footprint        │ <= 60 MB RAM at idle; <= 150 MB RAM under sustained 80k EPS load       │
├─────────────────────────┼────────────────────────────────────────────────────────────────────────┤
│ Zero Data Loss (Lossless│ 100% of raw bytes preserved in output payload with cryptographic proof  │
├─────────────────────────┼────────────────────────────────────────────────────────────────────────┤
│ Air-Gapped Isolation    │ 0 outbound internet requests; 100% self-contained OCI container image │
├─────────────────────────┼────────────────────────────────────────────────────────────────────────┤
│ System Availability     │ 99.999% uptime with crash-resilient asynchronous Tokio worker pool     │
└─────────────────────────┴────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Verification & Evaluation Criteria

| Deliverable | Evaluation Criteria | Target Metric / Format |
|---|---|---|
| **Source Code** | Clean, modular Rust engine + Python UI + YAML rules | GitHub repository, strict linting, zero warnings |
| **README** | Clear setup & 1-click execution guide | `docker compose up` starts entire stack offline |
| **Architecture Doc** | Comprehensive, technical 2-page document | Complete system design, data flows, and OCSF mapping |
| **2-Minute Demo Video** | Clear proof of multi-stream normalization, hot-reload, and forensic hash check | MP4 / WebM with live demo walkthrough |
| **Technical Presentation** | 5-slide high-impact architectural pitch | Problem $\rightarrow$ Sovereign Rust Engine $\rightarrow$ OCSF/Forensics $\rightarrow$ Benchmarks $\rightarrow$ Roadmap |
