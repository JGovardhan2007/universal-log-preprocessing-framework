# Universal Log Pre-processing Framework (ULPF)
> **High-Throughput, Cryptographically Defensible, Air-Gapped Log Pre-processing Engine**  
> *Developed for National Technical Research Organisation (NTRO) / NCIIPC — Problem Statement ID: 26156*

---

## 🌟 Key Capabilities

- ⚡ **100k+ Events Per Second (EPS):** Native asynchronous Rust ingestion engine with sub-millisecond latency and $<60\text{ MB}$ RAM footprint.
- 🛡️ **Cryptographic Chain of Custody:** Pre-parsing hardware **SHA-256** digital fingerprinting permanently bound to RFC 4122 `event_id` UUIDs for legal admissibility under **Section 65B of the Indian Evidence Act**.
- 🔄 **OCSF Standard Normalization:** Standardizes multi-vendor firewall and perimeter logs (Cisco, Palo Alto, Fortinet, Check Point, pfSense) to **OCSF v1.1.0 (Class 4001 Network Activity)**.
- 🔌 **Zero-Downtime Hot-Reload Parsers:** Onboard new firewall formats in $<5\text{ minutes}$ by dropping human-readable declarative YAML rules into `/parsers/`.
- 📦 **100% Air-Gapped / Offline Native:** Bundled with embedded offline MaxMind GeoIP (`GeoLite2-City.mmdb`) and static schema dictionaries. Zero external internet calls.
- 📊 **Columnar AI/ML Ready:** Streams normalized records directly into **Apache Arrow** IPC shared memory and compressed **Parquet** data lake tables.

---

## 📁 Repository Structure

```plaintext
ULPF/
├── docs/                           # Architecture, PRD, and Security Specs
│   ├── PRD.md                      # Product Requirements Document
│   ├── TECHNICAL_ARCHITECTURE.md   # Hybrid Rust + Python Technical Architecture
│   └── SECURITY_AND_ACCESS.md      # Air-gap, Forensic Chain-of-Custody & RBAC
│
├── .agents/                        # AI Agent Customizations & Skills
│   ├── rules/                      # Workspace collaboration & development rules
│   └── skills/                     # Design, motion, and optimization toolsets
│
├── parsers/                        # Declarative YAML Parser Specifications (Hot-Reloaded)
├── core-engine/                    # High-Performance Rust Ingestion & Normalization Daemon
├── dashboard/                      # Real-time Streamlit Forensic & Control Dashboard
├── test_tools/                     # High-Speed Synthetic UDP Traffic Generator & Benchmarks
│
├── rules.md                        # Multi-Developer Collaboration Protocols
├── conversation.md                 # Agent-to-Agent Shared State & Memory Log
└── .gitignore                      # Clean Git hygiene configuration
```

---

## 📚 Documentation
- [Product Requirements Document (PRD)](docs/PRD.md)
- [Technical Architecture Document](docs/TECHNICAL_ARCHITECTURE.md)
- [Security, Governance & Access Control Policy](docs/SECURITY_AND_ACCESS.md)
- [Agent Collaboration Protocol](rules.md)
- [Agent Conversation & State Log](conversation.md)

---

## 👥 Team Collaboration Protocol
All agents and developers collaborating on this project must follow [`rules.md`](rules.md) and record every push in [`conversation.md`](conversation.md) with explicit username attribution.
