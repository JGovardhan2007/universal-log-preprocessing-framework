"""
Universal Log Pre-processing Framework (ULPF)
Columnar Apache Arrow / Parquet Streaming Sink Writer
"""

import os
import threading
import pyarrow as pa
import pyarrow.parquet as pq
from pathlib import Path
from typing import Dict, Any, List, Optional


class ParquetSinkWriter:
    """
    Asynchronously flushes batches of normalized OCSF records into
    Snappy-compressed Apache Parquet tables for zero-ETL AI consumption.
    """

    def __init__(self, output_path: str = "data/stream_buffer.parquet", lake_dir: str = "data/lake", batch_size: int = 1000):
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.lake_dir = Path(lake_dir) if lake_dir else None
        if self.lake_dir:
            self.lake_dir.mkdir(parents=True, exist_ok=True)
        self.batch_size = batch_size
        self.buffer: List[Dict[str, Any]] = []
        self.lock = threading.Lock()
        self.total_written = 0


    def flatten_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Flatten nested OCSF structure into flat columnar dictionary."""
        src_ep = record.get("src_endpoint", {})
        dst_ep = record.get("dst_endpoint", {})
        conn = record.get("connection_info", {})
        meta = record.get("metadata", {})
        prod = meta.get("product", {})
        traffic = record.get("traffic", {})
        vendor_val = str(prod.get("vendor_name", "Generic"))
        product_val = str(prod.get("name", "Firewall"))

        return {
            "event_id": str(record.get("event_id", "")),
            "ingest_timestamp": str(meta.get("ingest_timestamp", "")),
            "class_uid": int(record.get("class_uid", 4001)),
            "category_uid": int(record.get("category_uid", 4)),
            "activity_id": int(record.get("activity_id", 1)),
            "vendor_name": vendor_val,
            "product_name": product_val,
            "vendor": vendor_val,
            "product": product_val,
            "disposition": str(record.get("disposition", "Unknown")),
            "disposition_id": int(record.get("disposition_id", 99)),
            "src_ip": str(src_ep.get("ip", "0.0.0.0")),
            "src_port": int(src_ep.get("port", 0)),
            "src_zone": str(src_ep.get("zone", "unknown")),
            "src_country": str(src_ep.get("geo", {}).get("country", "Unknown")),
            "src_city": str(src_ep.get("geo", {}).get("city", "Unknown")),
            "dst_ip": str(dst_ep.get("ip", "0.0.0.0")),
            "dst_port": int(dst_ep.get("port", 0)),
            "dst_zone": str(dst_ep.get("zone", "unknown")),
            "dst_country": str(dst_ep.get("geo", {}).get("country", "Unknown")),
            "dst_city": str(dst_ep.get("geo", {}).get("city", "Unknown")),
            "protocol_name": str(conn.get("protocol_name", "TCP")),
            "direction": str(conn.get("direction", "Inbound")),
            "bytes": int(traffic.get("bytes", 0)),
            "packets": int(traffic.get("packets", 0)),
            "hash": str(meta.get("hash", "")),
            "tier": int(meta.get("tier", 1)),
            "raw_data": str(record.get("raw_data", "")),
            "anomaly_score": float(record.get("anomaly_score", 0.1)),
            "is_anomaly": bool(record.get("is_anomaly", False))
        }


    def add_record(self, record: Dict[str, Any]) -> Optional[int]:
        """Add normalized record to in-memory buffer, flushing if threshold reached."""
        flat = self.flatten_record(record)
        with self.lock:
            self.buffer.append(flat)
            if len(self.buffer) >= self.batch_size:
                return self._flush_locked()
        return None

    def add_batch(self, records: List[Dict[str, Any]]) -> int:
        """Add a batch of records and flush."""
        flats = [self.flatten_record(r) for r in records]
        with self.lock:
            self.buffer.extend(flats)
            return self._flush_locked()

    def flush(self) -> int:
        """Manually trigger flush of all buffered records to Parquet."""
        with self.lock:
            return self._flush_locked()

    def _flush_locked(self) -> int:
        """Flush buffer to disk under lock."""
        if not self.buffer:
            return 0

        count = len(self.buffer)
        try:
            table = pa.Table.from_pylist(self.buffer)
            if self.output_path.exists():
                # Read existing table and append (or write rolling file)
                try:
                    existing_table = pq.read_table(self.output_path)
                    combined_table = pa.concat_tables([existing_table, table])
                    # Keep max 50,000 recent rows in buffer for live UI performance
                    if combined_table.num_rows > 50000:
                        combined_table = combined_table.slice(combined_table.num_rows - 50000)
                    pq.write_table(combined_table, self.output_path, compression="snappy")
                except Exception:
                    pq.write_table(table, self.output_path, compression="snappy")
            else:
                pq.write_table(table, self.output_path, compression="snappy")

            self.total_written += count
            self.buffer.clear()
            return count
        except Exception as e:
            print(f"[ERROR] Parquet flush failed: {e}")
            return 0
