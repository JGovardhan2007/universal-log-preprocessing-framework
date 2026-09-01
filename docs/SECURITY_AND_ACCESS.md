# Security, Governance & Access Control Policy Document
## Universal Log Pre-processing Framework (ULPF)
**Organization:** National Technical Research Organisation (NTRO) / NCIIPC  
**Problem Statement ID:** 26156 | **Theme:** Blockchain & Cybersecurity  
**Document Version:** 1.0.0 | **Classification:** Official / Defense Technical Document  

---

## 1. Governance & Regulatory Compliance Alignment

The **Universal Log Pre-processing Framework (ULPF)** is architected to satisfy the stringent cybersecurity, evidentiary, and privacy standards mandated by Indian national security bodies and international standards:

```
┌───────────────────────────────┬────────────────────────────────────────────────────────────────────────┐
│ Regulatory Standard           │ Specific Framework Compliance Mapping                                  │
├───────────────────────────────┼────────────────────────────────────────────────────────────────────────┤
│ Section 65B, Indian Evidence  │ Preserves bit-for-bit raw log payloads and binds them with cryptographic│
│ Act (Bharatiya Sakshya 2023)  │ SHA-256 digests, establishing legally defensible chain-of-custody.     │
├───────────────────────────────┼────────────────────────────────────────────────────────────────────────┤
│ CERT-In Directions            │ Supports mandated 180-day forensic log retention in high-compression   │
│ (Cybersecurity Directives)    │ Parquet columnar format with unalterable timestamps.                   │
├───────────────────────────────┼────────────────────────────────────────────────────────────────────────┤
│ NCIIPC Guidelines             │ 100% air-gapped execution for Critical Information Infrastructure (CII)│
│ (Critical Infrastructure)     │ without outbound internet connectivity or remote telemetry.            │
├───────────────────────────────┼────────────────────────────────────────────────────────────────────────┤
│ NIST SP 800-92                │ Standardized computer security log management, integrity verification, │
│ (Log Management Standard)     │ and consistent taxonomy mapping (OCSF Class 4001).                     │
└───────────────────────────────┴────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Cryptographic Chain-of-Custody & Forensic Integrity

### 2.1 The Lossless Proof-of-Evidence Protocol
To ensure that normalized telemetry is admissible in judicial courts, incident response tribunals, and audit proceedings:

```
 Incoming Wire Bytes
         │
         ▼
 ┌────────────────────────────────────────────────────────┐
 │ Step 1: Ingestion Byte Capture                         │
 │ Capture exact byte slice BEFORE string decoding.       │
 └───────────────────────┬────────────────────────────────┘
                         │
                         ▼
 ┌────────────────────────────────────────────────────────┐
 │ Step 2: Cryptographic Hashing (Hardware SHA-256)       │
 │ H_raw = SHA-256(byte_array)                            │
 └───────────────────────┬────────────────────────────────┘
                         │
                         ▼
 ┌────────────────────────────────────────────────────────┐
 │ Step 3: Provenance Binding                             │
 │ Attach H_raw, RFC 4122 UUIDv4, and Ingest Timestamp    │
 │ into immutable metadata object.                        │
 └───────────────────────┬────────────────────────────────┘
                         │
                         ▼
 ┌────────────────────────────────────────────────────────┐
 │ Step 4: Normalization to OCSF                          │
 │ Standardize fields while embedding original string     │
 │ into .raw_data attribute.                              │
 └────────────────────────────────────────────────────────┘
```

### 2.2 Mathematical Verification Model
Any downstream consumer, auditor, or judge can independently verify the payload integrity at any time using the verification equation:

$$\text{Status} = \begin{cases} 
\mathbf{VALID} & \text{if } \text{SHA256}(\text{record.raw\_data}) \equiv \text{record.metadata.hash} \\
\mathbf{CORRUPTED / TAMPERED} & \text{if } \text{SHA256}(\text{record.raw\_data}) \not\equiv \text{record.metadata.hash}
\end{cases}$$

---

## 3. Air-Gapped Network Isolation Model

ULPF is designed to operate in **Level-4 Air-Gapped Enclaves** (nuclear facilities, power grid SCADA, military communication nodes) where physical and logical isolation is absolute.

```
┌───────────────────────────────────────────────────────────────────────────────┐
│                       AIR-GAPPED DEFENSE ENCLAVE                              │
│                                                                               │
│   [ Perimeter Devices ]  ──(UDP/TCP 5140)──▶  [ ULPF Ingestion Engine ]       │
│                                                       │                       │
│                                           (No Internet Connectivity)          │
│                                                       │                       │
│   [ Local MMDB Database ] ───────────────────────────▶ ├──▶ [ Parquet Sink ]   │
│   [ Local Schema Rules  ] ───────────────────────────▶ └──▶ [ Streamlit UI ]   │
│                                                                               │
│   ✖ ZERO Outbound DNS Requests                                                │
│   ✖ ZERO External SaaS / Cloud Telemetry                                      │
│   ✖ ZERO Remote License Key Validation Checks                                 │
└───────────────────────────────────────────────────────────────────────────────┘
```

### 3.1 Offline Asset Packaging
1. **Embedded GeoIP Engine:** Local binary MaxMind database (`GeoLite2-City.mmdb`) bundled in the container root filesystem.
2. **Static Schema Dictionaries:** All OCSF v1.1.0 category tables and parser rules are locally stored in `/parsers/*.yaml`.
3. **Signed Offline Update Bundles:** Firmware or parser updates are ingested exclusively via cryptographically signed offline archive packages (`.tar.gz.sig`).

---

## 4. Threat Modeling & Risk Mitigation (STRIDE Analysis)

```
┌─────────────────────┬───────────────────────────┬──────────────────────────────────────────────────────────┐
│ STRIDE Category     │ Threat Description        │ ULPF Native Security Mitigation                          │
├─────────────────────┼───────────────────────────┼──────────────────────────────────────────────────────────┤
│ Spoofing (S)        │ Forged source IP addresses│ Collects physical socket metadata, collector IDs, and    │
│                     │ on UDP Syslog streams.    │ ingress interface tags alongside payload metadata.       │
├─────────────────────┼───────────────────────────┼──────────────────────────────────────────────────────────┤
│ Tampering (T)       │ Modification of log events│ Pre-parsing SHA-256 hashing permanently binds the        │
│                     │ in transit or in storage. │ evidentiary hash; any alteration fails hash verification.│
├─────────────────────┼───────────────────────────┼──────────────────────────────────────────────────────────┤
│ Repudiation (R)     │ Adversary denies action by│ Raw bytes preserved 1:1 in forensic vault; immutable     │
│                     │ deleting security records.│ UUID ensures audit traceability across all pipelines.    │
├─────────────────────┼───────────────────────────┼──────────────────────────────────────────────────────────┤
│ Information         │ PII or credentials leaked │ Optional regex masking filters (PII scrubbers) for PII   │
│ Disclosure (I)      │ in normalized fields.     │ while isolating raw payloads in access-restricted indices│
├─────────────────────┼───────────────────────────┼──────────────────────────────────────────────────────────┤
│ Denial of           │ Log flooding / ReDoS      │ • Rust regex crate executes in linear $O(n)$ time.       │
│ Service (D)         │ (Regular Expression DoS). │ • Socket ring buffers prevent CPU memory exhaustion.     │
├─────────────────────┼───────────────────────────┼──────────────────────────────────────────────────────────┤
│ Elevation of        │ Container breakout /      │ Daemon runs as unprivileged user (`uid:gid 10001:10001`) │
│ Privilege (E)       │ binary exploit.           │ with `CAP_DROP_ALL` and a read-only root filesystem.     │
└─────────────────────┴───────────────────────────┴──────────────────────────────────────────────────────────┘
```

---

## 5. Role-Based Access Control (RBAC) Matrix

Access to the framework's interfaces, raw data vaults, and parser configuration files is strictly governed:

```
┌──────────────────────────────┬──────────────────┬─────────────┬─────────────┬─────────────┐
│ Functional Capability        │ Legal Auditor /  │ Senior SOC  │ AI / Data   │ System      │
│                              │ Forensic Lead    │ Analyst     │ Scientist   │ Admin       │
├──────────────────────────────┼──────────────────┼─────────────┼─────────────┼─────────────┤
│ View Normalized OCSF Streams │ ✔ READ           │ ✔ READ      │ ✔ READ      │ ✔ READ      │
├──────────────────────────────┼──────────────────┼─────────────┼─────────────┼─────────────┤
│ Run Hash Integrity Checks    │ ✔ VERIFY         │ ✔ VERIFY    │ ✖ DENY      │ ✔ VERIFY    │
├──────────────────────────────┼──────────────────┼─────────────┼─────────────┼─────────────┤
│ View Raw Unmutated Payloads  │ ✔ FULL ACCESS    │ ⚠ MASKED    │ ✖ DENY      │ ⚠ AUDITED   │
├──────────────────────────────┼──────────────────┼─────────────┼─────────────┼─────────────┤
│ Upload / Hot-Reload Parsers  │ ✖ DENY           │ ✖ DENY      │ ✖ DENY      │ ✔ FULL WRITE│
├──────────────────────────────┼──────────────────┼─────────────┼─────────────┼─────────────┤
│ Export Columnar Parquet / ML │ ✖ DENY           │ ✔ EXPORT    │ ✔ EXPORT    │ ✔ EXPORT    │
├──────────────────────────────┼──────────────────┼─────────────┼─────────────┼─────────────┤
│ View System Telemetry (EPS)  │ ✔ READ           │ ✔ READ      │ ✔ READ      │ ✔ READ      │
└──────────────────────────────┴──────────────────┴─────────────┴─────────────┴─────────────┘
```

---

## 6. System Hardening & Memory Safety

### 6.1 Rust Memory Safety Guarantees
- **Zero Buffer Overflows:** Rust enforces strict bounds checking on all slices and allocations at compile time.
- **Zero Use-After-Free & Double Free:** The ownership and borrow checker prevent dangling pointers and race conditions.
- **Panic Isolation:** Malformed packets or parser exceptions trigger graceful recovery without terminating worker threads.

### 6.2 Container & OS Hardening
- **Unprivileged Execution:** Runs under dedicated `ulpf` user (`UID 10001`).
- **Dropped Linux Capabilities:** All kernel capabilities are dropped (`--cap-drop=ALL`).
- **Read-Only Root Filesystem:** Root container filesystem is mounted as read-only (`read_only: true`), with ephemeral write access restricted exclusively to `/tmp` and `/data`.

---

## 7. Audit Logging & Internal Event Traceability

All operational actions within ULPF generate internal audit events:
1. **Parser Changes:** Any modification, creation, or deletion of a YAML rule in `/parsers/` logs an audit record containing author identity, timestamp, and SHA-256 checksum of the YAML file.
2. **Forensic Queries:** Every execution of a raw payload hash verification is recorded with query parameters and analyst credentials.
3. **Buffer Overflows:** High-watermark memory threshold alerts are emitted when queue capacity reaches 85%.
