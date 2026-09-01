"""
Universal Log Pre-processing Framework (ULPF)
OCSF v1.1.0 Standard Schema Normalizer (Class 4001 Network Activity)
"""

import os
from typing import Dict, Any, Optional
from core_engine.parser_loader import CompiledParser
from core_engine.geoip_resolver import GeoIPResolver


# Common IP protocol number to name mapping
IP_PROTO_MAP = {
    "1": "ICMP",
    "6": "TCP",
    "17": "UDP",
    "47": "GRE",
    "50": "ESP",
    "51": "AH",
    "58": "ICMPv6"
}

_GEO_RESOLVER = GeoIPResolver()


class OCSFNormalizer:
    """
    Normalizes multi-vendor perimeter log tokens into OCSF v1.1.0 Class 4001 (Network Activity).
    """

    @staticmethod
    def resolve_geo(ip: Optional[str]) -> Dict[str, Any]:
        """Perform offline IP-to-Country/City lookup with zero network calls."""
        return _GEO_RESOLVER.resolve(ip)


    @classmethod
    def normalize(
        cls,
        event_id: str,
        raw_data: str,
        sha256_hash: str,
        ingest_timestamp: str,
        tier: int,
        format_name: str,
        tokens: Dict[str, Any],
        parser: Optional[CompiledParser] = None
    ) -> Dict[str, Any]:
        """
        Construct a fully compliant OCSF v1.1.0 Class 4001 record.
        """
        # Determine vendor/product
        if parser:
            vendor_name = parser.vendor
            product_name = parser.product
            product_version = parser.version
        else:
            vendor_name = tokens.get("cef_vendor", tokens.get("vendor", "Generic"))
            product_name = tokens.get("cef_product", tokens.get("product", "Network Appliance"))
            product_version = "1.0.0"

        # Apply parser field mappings if available
        src_ip = None
        dst_ip = None
        src_port = None
        dst_port = None
        src_zone = None
        dst_zone = None
        protocol_name = None
        direction = None
        bytes_count = None
        packets_count = None
        raw_action = None

        if parser and parser.field_mapping:
            fm = parser.field_mapping
            for target_field, src_expr in fm.items():
                if isinstance(src_expr, str) and src_expr.startswith("$"):
                    var_expr = src_expr[1:]
                    transform = None
                    if ":" in var_expr:
                        var_name, transform = var_expr.split(":", 1)
                    else:
                        var_name = var_expr

                    val = tokens.get(var_name)
                    if val is not None:
                        if transform == "integer":
                            try:
                                val = int(val)
                            except (ValueError, TypeError):
                                val = 0
                        elif transform == "upper":
                            val = str(val).upper()
                        elif transform == "proto_name":
                            val = IP_PROTO_MAP.get(str(val), str(val).upper())

                        if target_field == "src_endpoint.ip":
                            src_ip = str(val)
                        elif target_field == "src_endpoint.port":
                            src_port = int(val) if isinstance(val, int) else None
                        elif target_field == "src_endpoint.zone":
                            src_zone = str(val)
                        elif target_field == "dst_endpoint.ip":
                            dst_ip = str(val)
                        elif target_field == "dst_endpoint.port":
                            dst_port = int(val) if isinstance(val, int) else None
                        elif target_field == "dst_endpoint.zone":
                            dst_zone = str(val)
                        elif target_field == "connection_info.protocol_name":
                            protocol_name = str(val)
                        elif target_field == "connection_info.direction":
                            direction = str(val).capitalize() if val else None
                        elif target_field == "traffic.bytes":
                            bytes_count = int(val) if isinstance(val, int) else None
                        elif target_field == "traffic.packets":
                            packets_count = int(val) if isinstance(val, int) else None

            raw_action = tokens.get("action")
        else:
            # Direct token extraction fallbacks
            src_ip = tokens.get("src_ip", tokens.get("srcip", tokens.get("src", tokens.get("source_ip"))))
            dst_ip = tokens.get("dst_ip", tokens.get("dstip", tokens.get("dst", tokens.get("dest_ip"))))
            
            p_src = tokens.get("src_port", tokens.get("srcport", tokens.get("s_port")))
            src_port = int(p_src) if p_src and str(p_src).isdigit() else None
            
            p_dst = tokens.get("dst_port", tokens.get("dstport", tokens.get("service", tokens.get("dest_port"))))
            dst_port = int(p_dst) if p_dst and str(p_dst).isdigit() else None
            
            src_zone = tokens.get("src_zone", tokens.get("srcintf"))
            dst_zone = tokens.get("dst_zone", tokens.get("dstintf"))
            
            proto_val = tokens.get("proto", tokens.get("protocol", "TCP"))
            protocol_name = IP_PROTO_MAP.get(str(proto_val), str(proto_val).upper())
            
            raw_action = tokens.get("action", tokens.get("act"))

        # Map disposition
        if parser:
            disposition = parser.map_disposition(raw_action)
        else:
            act_str = str(raw_action).lower() if raw_action else ""
            if act_str in ("allow", "allowed", "accept", "permit", "pass", "built"):
                disposition = "Allowed"
            elif act_str in ("deny", "denied", "drop", "dropped", "block", "blocked", "reject"):
                disposition = "Blocked"
            elif act_str in ("alert", "match"):
                disposition = "Alert"
            else:
                disposition = "Unknown"

        disp_id_map = {"Allowed": 1, "Blocked": 2, "Alert": 3, "Unknown": 99}
        disposition_id = disp_id_map.get(disposition, 99)

        # Build OCSF structure
        ocsf_record: Dict[str, Any] = {
            "event_id": event_id,
            "class_uid": 4001,
            "class_name": "Network Activity",
            "category_uid": 4,
            "category_name": "Network Activity",
            "activity_id": 1,
            "activity_name": "Traffic",
            "disposition": disposition,
            "disposition_id": disposition_id,
            "src_endpoint": {
                "ip": src_ip or "0.0.0.0",
                "port": src_port or 0,
                "zone": src_zone or "unknown",
                "geo": cls.resolve_geo(src_ip)
            },
            "dst_endpoint": {
                "ip": dst_ip or "0.0.0.0",
                "port": dst_port or 0,
                "zone": dst_zone or "unknown",
                "geo": cls.resolve_geo(dst_ip)
            },
            "connection_info": {
                "protocol_name": protocol_name or "TCP",
                "direction": direction or "Inbound"
            },
            "metadata": {
                "framework": "ULPF-NTRO-v1.1",
                "version": "1.1.0",
                "tier": tier,
                "format_name": format_name,
                "product": {
                    "vendor_name": vendor_name,
                    "name": product_name,
                    "version": str(product_version)
                },
                "ingest_timestamp": ingest_timestamp,
                "hash": sha256_hash
            },
            "raw_data": raw_data
        }

        if bytes_count is not None or packets_count is not None:
            ocsf_record["traffic"] = {
                "bytes": bytes_count or 0,
                "packets": packets_count or 0
            }

        return ocsf_record
