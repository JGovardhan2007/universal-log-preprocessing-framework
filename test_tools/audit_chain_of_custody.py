#!/usr/bin/env python3
"""
ULPF Phase 3 Section 65B Cryptographic Chain-of-Custody Auditor
Track 4 (Phase 3): Automated End-to-End Cryptographic Evidence Verification
NTRO Problem Statement ID: 26156 | Bharatiya Sakshya Adhiniyam 2023
"""

import os
import sys
import hashlib
import json
import pyarrow.parquet as pq
from datetime import datetime, timezone
from typing import Dict, Any

# Ensure UTF-8 console output
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


def audit_parquet_buffer(parquet_path: str = "data/stream_buffer.parquet") -> Dict[str, Any]:
    """Audits 100% of records in a Parquet table for SHA-256 mathematical non-tampering."""
    print("=" * 75)
    print("  ⚖️  ULPF SECTION 65B CRYPTOGRAPHIC AUDIT VERIFIER (BSA 2023)")
    print(f"  Target Parquet Table: {parquet_path}")
    print("=" * 75)
    
    if not os.path.exists(parquet_path):
        print(f"[ERROR] Parquet file not found at: {parquet_path}")
        return {"status": "FILE_NOT_FOUND", "records_audited": 0, "verification_rate_percent": 0.0}

    table = pq.read_table(parquet_path)
    df = table.to_pandas()
    
    total_records = len(df)
    if total_records == 0:
        print("[WARN] Table is empty. No records to verify.")
        return {"status": "EMPTY_TABLE", "records_audited": 0, "verification_rate_percent": 100.0}

    valid_count = 0
    tampered_count = 0
    unique_uuids = set()
    duplicate_uuids = 0
    
    for idx, row in df.iterrows():
        raw_str = str(row.get("raw_data", ""))
        stored_hash = str(row.get("hash", "")).lower()
        uuid_str = str(row.get("event_id", ""))
        
        # UUID uniqueness assertion
        if uuid_str in unique_uuids:
            duplicate_uuids += 1
        else:
            unique_uuids.add(uuid_str)
            
        # SHA-256 byte-for-byte mathematical proof
        recomputed = hashlib.sha256(raw_str.encode("utf-8")).hexdigest().lower()
        if recomputed == stored_hash:
            valid_count += 1
        else:
            tampered_count += 1

    verification_rate = (valid_count / total_records) * 100.0
    is_fully_authentic = (tampered_count == 0 and duplicate_uuids == 0)
    
    report = {
        "audit_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "standard": "Section 65B Indian Evidence Act / BSA 2023",
        "cryptographic_algorithm": "SHA-256 (FIPS 180-4)",
        "total_records_audited": total_records,
        "valid_authentic_records": valid_count,
        "tampered_records": tampered_count,
        "unique_uuids_count": len(unique_uuids),
        "duplicate_uuids_count": duplicate_uuids,
        "verification_rate_percent": round(verification_rate, 2),
        "chain_of_custody_status": "COMPLIANT_COURT_ADMISSIBLE" if is_fully_authentic else "INTEGRITY_VIOLATION_DETECTED"
    }
    
    report_path = os.path.join(os.path.dirname(parquet_path), "audit_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
        
    print(f"\n📊 [Audit Results Summary]")
    print(f"   Total Audited Records : {total_records:,}")
    print(f"   Valid & Authentic     : {valid_count:,} ({verification_rate:.2f}%)")
    print(f"   Tampered Records      : {tampered_count}")
    print(f"   Duplicate UUIDs       : {duplicate_uuids}")
    print(f"   Legal Status          : {report['chain_of_custody_status']}")
    print(f"   Formal Report Saved   : {report_path}")
    print("=" * 75)
    return report


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "data/stream_buffer.parquet"
    audit_parquet_buffer(target)
