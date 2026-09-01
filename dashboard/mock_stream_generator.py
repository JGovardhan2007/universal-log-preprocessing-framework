import os
import sys
import uuid
import hashlib
import random
from datetime import datetime, timezone, timedelta
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
PARQUET_PATH = os.path.join(DATA_DIR, "stream_buffer.parquet")

VENDORS = [
    ("Cisco", "ASA", "%ASA-4-106023: Deny tcp src outside:{src_ip}/{src_port} dst inside:{dst_ip}/{dst_port}", "Blocked"),
    ("Palo Alto", "PAN-OS", "1,2026/09/01 08:30:00,001801000001,TRAFFIC,allow,1,{src_ip},{dst_ip},{src_port},{dst_port},TCP", "Allowed"),
    ("Fortinet", "FortiGate", "date=2026-09-01 time=08:30:00 devname=\"FGT-HQ\" srcip={src_ip} srcport={src_port} dstip={dst_ip} dstport={dst_port} proto=6 action=deny", "Blocked"),
    ("Check Point", "Quantum", "time=1756715430|hostname=cp-fw01|action=drop|src={src_ip}|dst={dst_ip}|s_port={src_port}|service={dst_port}", "Blocked"),
    ("pfSense", "filterlog", "Sep 1 08:30:00 pfsense filterlog: 4,,,match,pass,in,4,,TCP,{src_ip},{dst_ip},{src_port},{dst_port}", "Allowed"),
]

COUNTRIES = [
    ("India", "New Delhi", "IN"),
    ("United States", "Dallas", "US"),
    ("Germany", "Frankfurt", "DE"),
    ("Singapore", "Singapore", "SG"),
    ("United Kingdom", "London", "GB"),
    ("Japan", "Tokyo", "JP"),
]


def generate_mock_ocsf_dataset(count: int = 250) -> pd.DataFrame:
    os.makedirs(DATA_DIR, exist_ok=True)
    records = []
    base_time = datetime.now(timezone.utc) - timedelta(minutes=15)

    for i in range(count):
        event_time = base_time + timedelta(seconds=i * 3 + random.uniform(0.1, 1.5))
        vendor, product, raw_tmpl, default_disp = random.choice(VENDORS)
        
        src_ip = f"192.168.{random.randint(1, 20)}.{random.randint(1, 250)}"
        dst_ip = f"198.51.{random.randint(1, 20)}.{random.randint(1, 250)}"
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 22, 53, 3389, 8080, 445])
        proto = random.choice(["TCP", "UDP"])
        disp = random.choice(["Allowed", "Blocked", "Dropped"]) if random.random() > 0.8 else default_disp

        raw_str = raw_tmpl.format(src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port)
        sha256_hash = hashlib.sha256(raw_str.encode("utf-8")).hexdigest()
        event_id = str(uuid.uuid4())

        src_geo = random.choice(COUNTRIES)
        dst_geo = random.choice(COUNTRIES)

        # Anomaly simulation (brute-force or port scan signature)
        is_anomaly = (dst_port in [22, 3389, 445] and disp == "Blocked") or (random.random() < 0.05)
        anomaly_score = round(random.uniform(0.78, 0.96), 3) if is_anomaly else round(random.uniform(0.05, 0.42), 3)

        records.append({
            "event_id": event_id,
            "ingest_timestamp": event_time.isoformat(),
            "class_uid": 4001,
            "category_uid": 4,
            "activity_id": 1,
            "disposition": disp,
            "vendor_name": vendor,
            "product_name": product,
            "src_ip": src_ip,
            "src_port": src_port,
            "src_country": src_geo[0],
            "src_city": src_geo[1],
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "dst_country": dst_geo[0],
            "dst_city": dst_geo[1],
            "protocol_name": proto,
            "hash": sha256_hash,
            "raw_data": raw_str,
            "anomaly_score": anomaly_score,
            "is_anomaly": is_anomaly
        })

    df = pd.DataFrame(records)
    table = pa.Table.from_pandas(df)
    pq.write_table(table, PARQUET_PATH, compression="SNAPPY")
    print(f"[OK] Generated {count} mock OCSF events -> {PARQUET_PATH}")
    return df


if __name__ == "__main__":
    generate_mock_ocsf_dataset(300)

