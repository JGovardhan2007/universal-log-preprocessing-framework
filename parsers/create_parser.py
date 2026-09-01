#!/usr/bin/env python3
"""
ULPF Declarative Parser Creator & SDK Scaffolder
Track 2 (Phase 4): 60-Second Vendor Onboarding Tool
NTRO Problem Statement ID: 26156
"""

import os
import sys
import yaml
import argparse
from pathlib import Path

# Ensure UTF-8 output
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


def scaffold_parser(
    vendor: str,
    product: str,
    signature_pattern: str,
    regex_pattern: str,
    output_filename: str = None
) -> str:
    """Scaffolds a new declarative YAML parser definition."""
    safe_name = output_filename or f"{vendor.lower().replace(' ', '_')}_{product.lower().replace(' ', '_')}.yaml"
    if not safe_name.endswith(('.yaml', '.yml')):
        safe_name += ".yaml"
        
    parser_def = {
        "vendor": vendor,
        "product": product,
        "version": "1.0.0",
        "description": f"Declarative OCSF parser for {vendor} {product}",
        "signature_match": {
            "type": "contains",
            "patterns": [signature_pattern]
        },
        "extraction": {
            "type": "regex",
            "patterns": [regex_pattern]
        },

        "field_mapping": {
            "src_endpoint.ip": "$src_ip",
            "src_endpoint.port": "$src_port:integer",
            "src_endpoint.zone": "lan",
            "dst_endpoint.ip": "$dst_ip",
            "dst_endpoint.port": "$dst_port:integer",
            "dst_endpoint.zone": "wan",
            "connection_info.protocol_name": "$proto:upper"
        },
        "disposition_map": {
            "Allow": "Allowed",
            "Pass": "Allowed",
            "Accept": "Allowed",
            "Deny": "Blocked",
            "Drop": "Blocked",
            "Block": "Blocked",
            "default": "Allowed"
        }
    }
    
    target_dir = Path("parsers")
    target_dir.mkdir(parents=True, exist_ok=True)
    target_file = target_dir / safe_name
    
    with open(target_file, "w", encoding="utf-8") as f:
        yaml.dump(parser_def, f, sort_keys=False)
        
    print(f"✅ [Parser Scaffolded] Created: {target_file}")
    return str(target_file)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ULPF Parser Generator SDK")
    parser.add_argument("--vendor", required=True, help="Vendor name (e.g., SonicWall)")
    parser.add_argument("--product", required=True, help="Product name (e.g., TZ-400)")
    parser.add_argument("--signature", required=True, help="Signature match substring")
    parser.add_argument("--regex", required=True, help="Named regex extraction pattern")
    parser.add_argument("--out", default=None, help="Output YAML filename")
    args = parser.parse_args()
    
    scaffold_parser(args.vendor, args.product, args.signature, args.regex, args.out)
