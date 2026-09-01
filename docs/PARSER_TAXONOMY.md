# 📚 ULPF Declarative Parser Taxonomy & Field Specification
> **NTRO / NCIIPC Problem Statement ID:** 26156  
> **Schema Standard:** Open Cybersecurity Schema Framework (OCSF) v1.1.0 — **Class 4001: Network Activity**  
> **Evidentiary Standard:** Section 65B Indian Evidence Act / Bharatiya Sakshya Adhiniyam (BSA) 2023  

---

## 🌐 Supported Parser Matrix (10 Active Formats)

| # | Vendor / Source | Product / Module | Extraction Tier | Input Format | Primary Action Mappings |
|---|-----------------|-------------------|-----------------|--------------|-------------------------|
| 1 | **Cisco** | ASA / Firepower FTD | Tier 1 (YAML) | Syslog | Deny $\rightarrow$ Blocked, Built $\rightarrow$ Allowed |
| 2 | **Palo Alto Networks** | PAN-OS Firewall | Tier 1 (YAML) | CSV (Comma-Separated) | drop/deny $\rightarrow$ Blocked, allow $\rightarrow$ Allowed |
| 3 | **Fortinet** | FortiOS (FortiGate) | Tier 1 (YAML) | Key-Value Pairs | deny $\rightarrow$ Blocked, accept $\rightarrow$ Allowed |
| 4 | **Check Point** | Quantum Gateway | Tier 1 (YAML) | Key-Value / Syslog | drop/reject $\rightarrow$ Blocked, accept $\rightarrow$ Allowed |
| 5 | **pfSense** | Suricata / Filterlog | Tier 1 (YAML) | JSON & Filterlog CSV | block $\rightarrow$ Blocked, pass $\rightarrow$ Allowed |
| 6 | **Linux OS** | Syslog & SSH / PAM | Tier 1 (YAML) | Syslog | Failed $\rightarrow$ Blocked, Accepted $\rightarrow$ Allowed |
| 7 | **Suricata** | IDS / IPS Alert Engine | Tier 1 (YAML) | EVE JSON | blocked $\rightarrow$ Blocked, alert $\rightarrow$ Allowed |
| 8 | **Microsoft** | Windows Security Audit | Tier 1 (YAML) | Event ID 4624/4625/5156 | 4625 $\rightarrow$ Blocked, 4624 $\rightarrow$ Allowed |
| 9 | **Zeek (Bro)** | Network Monitor | Tier 1 (YAML) | `conn.log` TSV / KV | S0/REJ/RSTO $\rightarrow$ Blocked, SF $\rightarrow$ Allowed |
| 10 | **Amazon Web Services** | VPC Flow Logs v2 | Tier 1 (YAML) | Space-Delimited Log | REJECT $\rightarrow$ Blocked, ACCEPT $\rightarrow$ Allowed |

---

## 🎯 OCSF Class 4001 Canonical Target Schema

Every incoming byte stream across all 10 formats is normalized strictly to the following schema before Parquet columnar serialization:

```json
{
  "class_uid": 4001,
  "category_uid": 4,
  "activity_id": 1,
  "disposition": "Allowed | Blocked | Unknown",
  "src_endpoint": {
    "ip": "192.168.1.50",
    "port": 54123,
    "zone": "trust | lan | wan | monitored_lan",
    "geo": {
      "country": "India",
      "country_code": "IN",
      "city": "Bengaluru",
      "is_internal": false
    }
  },
  "dst_endpoint": {
    "ip": "203.0.113.15",
    "port": 443,
    "zone": "untrust | external | wan",
    "geo": {
      "country": "United States",
      "country_code": "US",
      "city": "Unknown",
      "is_internal": false
    }
  },
  "connection_info": {
    "protocol_name": "TCP | UDP | ICMP",
    "direction": "Inbound | Outbound"
  },
  "traffic": {
    "bytes": 4500,
    "packets": 15
  },
  "metadata": {
    "version": "1.1.0",
    "product": {
      "vendor_name": "Cisco",
      "name": "ASA"
    },
    "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "tier": 1,
    "ingest_timestamp": "2026-09-01T08:30:00.123456+00:00"
  },
  "raw_data": "%ASA-4-106023: Deny tcp src outside:203.0.113.15/44123 dst inside:192.168.1.50/80"
}
```

---

## 🔒 Section 65B Chain-of-Custody Invariant

Under the *Bharatiya Sakshya Adhiniyam 2023* (formerly Section 65B of the Indian Evidence Act 1872), the electronic evidence rule requires:
1. `raw_data` field contains the exact original byte stream without trimming or alteration.
2. `metadata.hash` contains the hardware SHA-256 digest computed *before* any regex parsing occurs.
3. The cryptographic relation `SHA256(raw_data) == metadata.hash` is invariant and verified automatically on 100% of stored records.
