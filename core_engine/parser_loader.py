"""
Universal Log Pre-processing Framework (ULPF)
Declarative YAML Parser Loader & Dynamic Hot-Reload Engine
"""

import os
import re
import csv
import io
import json
import time
import yaml
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple


class CompiledParser:
    """Represents a compiled, in-memory declarative YAML parser specification."""

    def __init__(self, filepath: Path, config: Dict[str, Any]):
        self.filepath = filepath
        self.name = filepath.stem
        self.vendor = config.get("vendor", "Generic")
        self.product = config.get("product", "Firewall")
        self.version = config.get("version", "1.0.0")
        self.description = config.get("description", "")
        self.raw_config = config
        
        # Signature matching setup
        self.sig_config = config.get("signature_match", {})
        self.sig_type = self.sig_config.get("type", "contains")
        raw_sig_pats = self.sig_config.get("patterns", [])
        if not raw_sig_pats and "pattern" in self.sig_config:
            raw_sig_pats = [self.sig_config["pattern"]]
        self.sig_patterns = raw_sig_pats
        self.compiled_sig_regexes = [
            re.compile(p) for p in self.sig_patterns if self.sig_type == "regex"
        ]

        # Extraction setup
        self.ext_config = config.get("extraction", {})
        self.ext_type = self.ext_config.get("type", "regex")
        raw_ext_pats = self.ext_config.get("patterns", [])
        if not raw_ext_pats and "pattern" in self.ext_config:
            raw_ext_pats = [self.ext_config["pattern"]]
        self.compiled_ext_regexes = []
        for p in raw_ext_pats:
            try:
                self.compiled_ext_regexes.append(re.compile(p))
            except re.error:
                pass


        # Field mapping and disposition
        self.field_mapping = config.get("field_mapping", {})
        self.disposition_map = config.get("disposition_map", {})

    def matches_signature(self, raw_str: str) -> bool:
        """Check if incoming raw payload matches this parser's signature."""
        if self.sig_type == "contains":
            for pat in self.sig_patterns:
                if pat in raw_str:
                    return True
            return False
        elif self.sig_type == "regex":
            for creg in self.compiled_sig_regexes:
                if creg.search(raw_str):
                    return True
            return False
        return False

    def parse(self, raw_str: str) -> Optional[Dict[str, Any]]:
        """Extract tokens from raw log string based on extraction configuration."""
        tokens: Dict[str, Any] = {}

        if self.ext_type == "regex":
            for creg in self.compiled_ext_regexes:
                match = creg.search(raw_str)
                if match:
                    tokens.update(match.groupdict())
                    break

        elif self.ext_type == "csv":
            delimiter = self.ext_config.get("delimiter", ",")
            field_indices = self.ext_config.get("fields", {})
            try:
                # Parse single CSV line
                reader = csv.reader(io.StringIO(raw_str), delimiter=delimiter)
                row = next(reader)
                for idx_str, key_name in field_indices.items():
                    idx = int(idx_str)
                    if idx < len(row):
                        tokens[key_name] = row[idx].strip()
            except Exception:
                pass

        elif self.ext_type == "key_value":
            # Extract key=value or key="value" pairs
            kv_pattern = re.compile(r'(\w+)=(?:"([^"]*)"|([^\s,;]+))')
            for match in kv_pattern.finditer(raw_str):
                k = match.group(1)
                v = match.group(2) if match.group(2) is not None else match.group(3)
                tokens[k] = v

        elif self.ext_type in ("json", "json_or_regex"):
            # Attempt JSON decode first
            try:
                # Find start of JSON object
                start = raw_str.find("{")
                if start != -1:
                    json_data = json.loads(raw_str[start:])
                    json_fields = self.ext_config.get("json_fields", {})
                    for out_key, json_path in json_fields.items():
                        # Extract nested dot-separated json keys
                        val = json_data
                        for part in json_path.split("."):
                            if isinstance(val, dict):
                                val = val.get(part)
                            else:
                                val = None
                                break
                        if val is not None:
                            tokens[out_key] = val
            except Exception:
                pass

            # Fallback to regex if JSON was not applicable
            if not tokens and self.compiled_ext_regexes:
                for creg in self.compiled_ext_regexes:
                    match = creg.search(raw_str)
                    if match:
                        tokens.update(match.groupdict())
                        break

        if not tokens:
            return None

        return tokens

    def map_disposition(self, raw_action: Optional[str]) -> str:
        """Map extracted vendor action string to OCSF standard disposition."""
        if not raw_action:
            return self.disposition_map.get("default", "Unknown")
        # Direct lookup or case-insensitive match
        if raw_action in self.disposition_map:
            return self.disposition_map[raw_action]
        for k, v in self.disposition_map.items():
            if k.lower() == str(raw_action).lower():
                return v
        return self.disposition_map.get("default", "Unknown")


class ParserLoader:
    """
    Manages declarative YAML parser specifications and dynamic zero-downtime hot-reloading.
    """

    def __init__(self, parsers_dir: str = "parsers"):
        self.parsers_dir = Path(parsers_dir)
        self.parsers: Dict[str, CompiledParser] = {}
        self.file_mtimes: Dict[str, float] = {}
        self.last_reload_time: float = 0.0
        self.load_all_parsers()

    def load_all_parsers(self) -> int:
        """Load and compile all YAML files from the parsers directory."""
        if not self.parsers_dir.is_dir():
            return 0

        yaml_files = list(self.parsers_dir.glob("*.yaml")) + list(self.parsers_dir.glob("*.yml"))
        loaded_count = 0

        for yf in yaml_files:
            try:
                mtime = os.path.getmtime(yf)
                with open(yf, "r", encoding="utf-8") as f:
                    config = yaml.safe_load(f)
                if isinstance(config, dict) and "vendor" in config:
                    parser = CompiledParser(yf, config)
                    self.parsers[yf.stem] = parser
                    self.file_mtimes[str(yf)] = mtime
                    loaded_count += 1
            except Exception as e:
                print(f"[WARN] Failed to load parser '{yf}': {e}")

        self.last_reload_time = time.time()
        return loaded_count

    load_parsers = load_all_parsers

    def check_and_hot_reload(self) -> bool:
        """
        Check for added, modified, or deleted YAML parser rules and reload them in <15ms.
        Returns True if any parser changes were detected and applied.
        """
        if not self.parsers_dir.is_dir():
            return False

        yaml_files = list(self.parsers_dir.glob("*.yaml")) + list(self.parsers_dir.glob("*.yml"))
        current_files = {str(f): os.path.getmtime(f) for f in yaml_files}
        changed = False

        # Check for modified or new files
        for fpath_str, mtime in current_files.items():
            if fpath_str not in self.file_mtimes or self.file_mtimes[fpath_str] != mtime:
                try:
                    fpath = Path(fpath_str)
                    with open(fpath, "r", encoding="utf-8") as f:
                        config = yaml.safe_load(f)
                    if isinstance(config, dict) and "vendor" in config:
                        self.parsers[fpath.stem] = CompiledParser(fpath, config)
                        self.file_mtimes[fpath_str] = mtime
                        changed = True
                except Exception:
                    pass

        # Check for deleted files
        for old_fpath in list(self.file_mtimes.keys()):
            if old_fpath not in current_files:
                stem = Path(old_fpath).stem
                self.parsers.pop(stem, None)
                self.file_mtimes.pop(old_fpath, None)
                changed = True

        if changed:
            self.last_reload_time = time.time()

        return changed

    def match_parser(self, raw_str: str) -> Optional[CompiledParser]:
        """Find the matching compiled parser for an incoming raw log line."""
        for parser in self.parsers.values():
            if parser.matches_signature(raw_str):
                return parser
        return None
