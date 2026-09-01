#!/usr/bin/env python3
"""
Universal Log Pre-processing Framework (ULPF)
Parser Validation & Syntax Verification Tool
Track 2: Declarative Parser Specifications
"""

import re
import sys
import yaml
from pathlib import Path
from typing import Dict, Any, Tuple


if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass



SAMPLE_TEST_LOGS = {
    "cisco_asa": [
        "%ASA-4-106023: Deny tcp src outside:203.0.113.15/44123 dst inside:192.168.1.50/80 by access-group 'outside_in'",
        "%ASA-6-302013: Built inbound TCP connection 987654 for outside:198.51.100.22/52140 (198.51.100.22/52140) to inside:10.0.0.5/443 (10.0.0.5/443)",
        "%ASA-6-302014: Teardown TCP connection 987654 for outside:198.51.100.22/52140 to inside:10.0.0.5/443 duration 0:00:30 bytes 5412 TCP FINs"
    ],
    "paloalto_panos": [
        "1,2026/09/01 08:30:15,001801000001,TRAFFIC,drop,1,2026/09/01 08:30:15,192.168.1.100,10.0.0.1,0.0.0.0,0.0.0.0,Rule-Block,trust,untrust,ethernet1/1,ethernet1/2,Log-Forward,2026/09/01 08:30:15,12345,1,54321,80,0,0,0x0,tcp,deny,120,60,60,1,2026/09/01 08:30:00,15,any,0,0,0,0,,US,IN,0,1,0",
        "1,2026/09/01 08:30:20,001801000001,TRAFFIC,end,1,2026/09/01 08:30:20,10.10.10.50,172.16.0.20,0.0.0.0,0.0.0.0,Allow-Web,trust,dmz,ethernet1/1,ethernet1/3,Log-Forward,2026/09/01 08:30:20,98765,1,49152,443,0,0,0x0,tcp,allow,4500,1500,3000,25,2026/09/01 08:30:00,20,web-browsing,0,0,0,0,,IN,US,0,1,0"
    ],
    "fortinet_fortigate": [
        'date=2026-09-01 time=08:30:00 devname="FGT60D" devid="FGT60D12345678" logid="0000000013" type="traffic" subtype="forward" level="notice" srcip=192.168.1.50 srcport=54321 srcintf="port1" dstip=10.0.0.5 dstport=443 dstintf="port2" proto=6 action="accept" policyid=1 duration=30 sentbyte=1200 rcvdbyte=4500 sentpkt=10 rcvdpkt=15 app="HTTPS"',
        'date=2026-09-01 time=08:30:05 devname="FGT60D" devid="FGT60D12345678" logid="0000000014" type="traffic" subtype="forward" level="warning" srcip=203.0.113.88 srcport=33891 srcintf="wan1" dstip=192.168.1.10 dstport=22 dstintf="lan" proto=6 action="deny" policyid=99 duration=0 sentbyte=0 rcvdbyte=0 sentpkt=0 rcvdpkt=0 msg="Deny by policy"'
    ],
    "checkpoint_fw": [
        "Sep 1 08:30:15 fw1 CheckPoint: 1Sep2026 8:30:15 accept 192.168.1.10 >eth0 rule: 12; rule_name: Allow_Web; src: 192.168.1.50; s_port: 51234; dst: 203.0.113.80; service: 443; proto: tcp; product: VPN-1 & FireWall-1;",
        "src=192.168.10.5 dst=10.20.30.40 s_port=60000 service=80 proto=tcp action=drop product=VPN-1"
    ],
    "pfsense_suricata": [
        '{"timestamp":"2026-09-01T08:30:00.123456+0000","event_type":"alert","src_ip":"192.168.1.50","src_port":54321,"dest_ip":"203.0.113.80","dest_port":80,"proto":"TCP","alert":{"action":"blocked","signature":"ET SCAN Potential SSH Scan"}}',
        'filterlog[12345]: 4,,,1000000103,em0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,192.168.1.100,203.0.113.50,49152,443,0,S,123456789,,1024,,'
    ]
}


def validate_yaml_file(filepath: Path) -> Tuple[bool, str, Dict[str, Any]]:
    """Validate the syntax and schema completeness of a YAML parser specification."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
    except Exception as e:
        return False, f"YAML Syntax Error: {e}", {}

    if not isinstance(config, dict):
        return False, "Root of YAML must be a dictionary/mapping", {}

    required_keys = ["vendor", "product", "version", "signature_match", "extraction", "field_mapping", "disposition_map"]
    missing = [k for k in required_keys if k not in config]
    if missing:
        return False, f"Missing required configuration sections: {missing}", config

    # Validate regex patterns
    sig = config.get("signature_match", {})
    if sig.get("type") == "regex":
        for p in sig.get("patterns", []):
            try:
                re.compile(p)
            except re.error as err:
                return False, f"Invalid signature regex '{p}': {err}", config

    ext = config.get("extraction", {})
    for p in ext.get("patterns", []):
        try:
            re.compile(p)
        except re.error as err:
            return False, f"Invalid extraction regex '{p}': {err}", config

    return True, "Valid YAML specification & schema", config


def run_all_validations(parsers_dir: str = "parsers") -> int:
    """Run verification against all YAML files in the given directory."""
    print("=" * 70)
    print("  Universal Log Pre-processing Framework (ULPF)")
    print("  Track 2: Declarative Parser Specifications Validator")
    print("=" * 70)

    p_dir = Path(parsers_dir)
    if not p_dir.is_dir():
        print(f"[ERROR] Directory '{parsers_dir}' not found.")
        return 1

    yaml_files = sorted(list(p_dir.glob("*.yaml")) + list(p_dir.glob("*.yml")))
    if not yaml_files:
        print(f"[WARN] No YAML files found in '{parsers_dir}'.")
        return 1

    passed_count = 0
    failed_count = 0

    for yf in yaml_files:
        stem = yf.stem
        print(f"\n[*] Checking: {yf.name}")
        valid, msg, config = validate_yaml_file(yf)
        if not valid:
            print(f"    [FAIL] {msg}")
            failed_count += 1
            continue

        print(f"    [PASS] Schema Syntax Valid (Vendor: {config.get('vendor')} | Product: {config.get('product')})")

        # Test against sample logs if available
        test_samples = SAMPLE_TEST_LOGS.get(stem, [])
        if test_samples:
            print(f"    [INFO] Testing {len(test_samples)} sample payloads...")
            for i, sample in enumerate(test_samples, 1):
                # Verify signature match
                sig = config.get("signature_match", {})
                sig_type = sig.get("type")
                matched = False
                if sig_type == "contains":
                    matched = any(pat in sample for pat in sig.get("patterns", []))
                elif sig_type == "regex":
                    matched = any(re.search(pat, sample) for pat in sig.get("patterns", []))
                
                status_icon = "[OK]" if matched else "[FAIL]"
                print(f"      {status_icon} Sample #{i}: Signature match = {matched}")
        else:
            print(f"    [NOTE] No automated sample logs defined for key '{stem}'.")

        passed_count += 1

    print("\n" + "=" * 70)
    print(f"  Summary: {passed_count} Passed | {failed_count} Failed | Total: {len(yaml_files)}")
    print("=" * 70)

    return 0 if failed_count == 0 else 1


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "parsers"
    sys.exit(run_all_validations(target))
