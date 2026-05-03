"""
YARA Enricher — AiSOC Reference Plugin
========================================
Scans a file against YARA rules. Returns matched rules with metadata.

Payload keys:
  file_path   (str)  : Absolute path to the file to scan.
  file_bytes  (bytes): Raw bytes (alternative to file_path).
  rules_dir   (str)  : Optional override for the rules directory.

Config keys:
  rules_dir         — Directory of .yar / .yara rule files.
  max_file_size_mb  — Refuse files larger than this (default: 50).

Returns:
  {
    "matched": [
      {
        "rule": "RansomwareConti_v3",
        "tags": ["ransomware", "conti"],
        "meta": {"description": "...", "author": "..."},
        "strings": [{"identifier": "$a", "offset": 1024, "data": "hex..."}]
      }
    ],
    "match_count": 1,
    "scanned_bytes": 204800,
  }
"""
from __future__ import annotations

import os
import glob
from pathlib import Path
from typing import Any

try:
    import yara  # type: ignore
    _YARA = True
except ModuleNotFoundError:
    _YARA = False


class Plugin:
    """YARA file enricher plugin."""

    _compiled: Any = None
    _rules_dir: str = ""

    def _get_rules(self, context: dict) -> Any:
        cfg = context.get("config", {})
        rules_dir = cfg.get("rules_dir") or os.getenv("YARA_RULES_DIR", "/opt/aisoc/yara-rules")

        if self._compiled and self._rules_dir == rules_dir:
            return self._compiled

        rule_files = glob.glob(str(Path(rules_dir) / "**" / "*.yar"), recursive=True)
        rule_files += glob.glob(str(Path(rules_dir) / "**" / "*.yara"), recursive=True)

        if not rule_files:
            raise FileNotFoundError(f"No .yar/.yara files found in {rules_dir}")

        filepaths = {str(i): p for i, p in enumerate(rule_files)}
        self._compiled = yara.compile(filepaths=filepaths)
        self._rules_dir = rules_dir
        return self._compiled

    async def run(self, payload: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        if not _YARA:
            return {"error": "yara-python not installed; run `pip install yara-python`"}

        cfg = context.get("config", {})
        max_mb = int(cfg.get("max_file_size_mb", 50))

        file_bytes: bytes | None = payload.get("file_bytes")
        file_path: str | None = payload.get("file_path")

        if file_bytes is None and file_path:
            p = Path(file_path)
            if not p.exists():
                return {"error": f"File not found: {file_path}"}
            size_mb = p.stat().st_size / (1024 * 1024)
            if size_mb > max_mb:
                return {"error": f"File too large ({size_mb:.1f} MB > {max_mb} MB limit)"}
            file_bytes = p.read_bytes()

        if file_bytes is None:
            return {"error": "Provide either 'file_path' or 'file_bytes' in the payload"}

        rules = self._get_rules(context)
        matches = rules.match(data=file_bytes)

        results = []
        for m in matches:
            results.append(
                {
                    "rule": m.rule,
                    "tags": list(m.tags),
                    "meta": dict(m.meta),
                    "strings": [
                        {
                            "identifier": s.identifier,
                            "offset": s.instances[0].offset if s.instances else 0,
                            "data": s.instances[0].matched_data.hex() if s.instances else "",
                        }
                        for s in m.strings
                    ],
                }
            )

        return {
            "matched": results,
            "match_count": len(results),
            "scanned_bytes": len(file_bytes),
        }
