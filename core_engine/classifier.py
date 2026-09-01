"""
Universal Log Pre-processing Framework (ULPF)
3-Tier Classification & Auto-Detection Engine
"""

import re
import json
from typing import Dict, Any, Optional, Tuple
from core_engine.parser_loader import ParserLoader, CompiledParser


class Classifier:
    """
    3-Tier Classification Engine:
      Tier 1: Vendor Signature Match (Cisco, Palo Alto, Fortinet, Check Point, etc.)
      Tier 2: Structural Formats (JSON, Key-Value, CEF, LEEF)
      Tier 3: Safe Heuristic Regex Fallback (extracts IP/Port/Protocol with zero drop)
    """

    IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    PORT_PATTERN = re.compile(r'(?:port|pt|:|\/)\s*(\d{1,5})\b', re.IGNORECASE)
    PROTO_PATTERN = re.compile(r'\b(TCP|UDP|ICMP|IP|GRE|ESP|AH)\b', re.IGNORECASE)
    ACTION_PATTERN = re.compile(r'\b(allow|allowed|permit|accept|pass|deny|denied|drop|dropped|block|blocked|reject)\b', re.IGNORECASE)
    KV_PATTERN = re.compile(r'(\w+)=(?:"([^"]*)"|([^\s,;]+))')

    def __init__(self, parser_loader: ParserLoader):
        self.parser_loader = parser_loader

    def classify_and_extract(self, raw_str: str) -> Tuple[int, str, Dict[str, Any], Optional[CompiledParser]]:
        """
        Execute 3-tier classification and token extraction.
        Returns: (tier_level, format_name, extracted_tokens, compiled_parser_or_none)
        """
        # -------------------------------------------------------------
        # Tier 1: Declarative Signature Match
        # -------------------------------------------------------------
        matched_parser = self.parser_loader.match_parser(raw_str)
        if matched_parser:
            tokens = matched_parser.parse(raw_str)
            if tokens:
                return (1, f"Tier1:{matched_parser.vendor}_{matched_parser.product}", tokens, matched_parser)

        # -------------------------------------------------------------
        # Tier 2: Structural Auto-Extraction (JSON, Key-Value, CEF)
        # -------------------------------------------------------------
        # 2a: JSON Object
        trimmed = raw_str.strip()
        if trimmed.startswith("{") and trimmed.endswith("}"):
            try:
                json_data = json.loads(trimmed)
                if isinstance(json_data, dict):
                    return (2, "Tier2:JSON", json_data, None)
            except Exception:
                pass

        # 2b: Key-Value Structure (at least 3 key=value pairs)
        kv_matches = self.KV_PATTERN.findall(raw_str)
        if len(kv_matches) >= 3:
            kv_tokens = {}
            for match in self.KV_PATTERN.finditer(raw_str):
                k = match.group(1)
                v = match.group(2) if match.group(2) is not None else match.group(3)
                kv_tokens[k] = v
            return (2, "Tier2:KeyValue", kv_tokens, None)

        # 2c: CEF Format
        if "CEF:0|" in raw_str:
            cef_parts = raw_str.split("|")
            if len(cef_parts) >= 7:
                cef_tokens = {
                    "cef_vendor": cef_parts[1],
                    "cef_product": cef_parts[2],
                    "cef_version": cef_parts[3],
                    "cef_signature_id": cef_parts[4],
                    "cef_name": cef_parts[5],
                    "cef_severity": cef_parts[6],
                }
                # Parse extension pairs if present
                if len(cef_parts) > 7:
                    ext_str = "|".join(cef_parts[7:])
                    for match in self.KV_PATTERN.finditer(ext_str):
                        k = match.group(1)
                        v = match.group(2) if match.group(2) is not None else match.group(3)
                        cef_tokens[k] = v
                return (2, "Tier2:CEF", cef_tokens, None)

        # -------------------------------------------------------------
        # Tier 3: Heuristic Regex Fallback
        # -------------------------------------------------------------
        heuristic_tokens: Dict[str, Any] = {}

        # Extract IPs (first is assumed src, second is dst)
        ips = self.IP_PATTERN.findall(raw_str)
        if len(ips) >= 1:
            heuristic_tokens["src_ip"] = ips[0]
        if len(ips) >= 2:
            heuristic_tokens["dst_ip"] = ips[1]

        # Extract Protocol
        proto_match = self.PROTO_PATTERN.search(raw_str)
        if proto_match:
            heuristic_tokens["proto"] = proto_match.group(1).upper()

        # Extract Action
        action_match = self.ACTION_PATTERN.search(raw_str)
        if action_match:
            heuristic_tokens["action"] = action_match.group(1)

        # Extract potential ports
        ports = self.PORT_PATTERN.findall(raw_str)
        if len(ports) >= 1:
            heuristic_tokens["src_port"] = ports[0]
        if len(ports) >= 2:
            heuristic_tokens["dst_port"] = ports[1]

        heuristic_tokens["_raw_unmapped"] = raw_str

        return (3, "Tier3:HeuristicFallback", heuristic_tokens, None)
