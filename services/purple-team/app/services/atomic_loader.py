"""Load and parse Atomic Red Team YAML test definitions."""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import yaml

LOG = logging.getLogger(__name__)


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        with open(path) as f:
            return yaml.safe_load(f) or {}
    except Exception as exc:
        LOG.warning("Failed to parse YAML %s: %s", path, exc)
        return {}


def load_atomics(atomics_path: str) -> list[dict[str, Any]]:
    """Walk the Atomic Red Team atomics/ directory and return parsed tests.

    Each entry contains:
        technique_id, technique_name, tactic, tests (list of atomic tests)
    """
    root = Path(atomics_path)
    if not root.exists():
        LOG.warning("Atomics path %s does not exist — returning empty list", atomics_path)
        return []

    results: list[dict[str, Any]] = []

    for technique_dir in sorted(root.iterdir()):
        if not technique_dir.is_dir():
            continue
        yaml_file = technique_dir / f"{technique_dir.name}.yaml"
        if not yaml_file.exists():
            continue

        data = _read_yaml(yaml_file)
        if not data:
            continue

        technique_id: str = data.get("attack_technique", technique_dir.name)
        technique_name: str = data.get("display_name", "")

        for test in data.get("atomic_tests", []):
            results.append(
                {
                    "technique_id": technique_id,
                    "technique_name": technique_name,
                    "tactic": _infer_tactic(technique_id),
                    "test_guid": test.get("auto_generated_guid", ""),
                    "test_name": test.get("name", ""),
                    "test_description": test.get("description", ""),
                    "platform": ",".join(test.get("supported_platforms", [])),
                    "executor": test.get("executor", {}).get("name", ""),
                    "input_arguments": test.get("input_arguments", {}),
                    "raw_yaml": test,
                }
            )

    LOG.info("Loaded %d atomic tests from %s", len(results), atomics_path)
    return results


def _infer_tactic(technique_id: str) -> str:
    """Very rough tactic inference by technique prefix. A full mapping needs the STIX bundle."""
    prefix_map = {
        "T1059": "execution",
        "T1055": "defense-evasion",
        "T1003": "credential-access",
        "T1078": "initial-access",
        "T1190": "initial-access",
        "T1021": "lateral-movement",
        "T1041": "exfiltration",
        "T1098": "persistence",
        "T1543": "persistence",
        "T1082": "discovery",
        "T1057": "discovery",
        "T1018": "discovery",
    }
    for prefix, tactic in prefix_map.items():
        if technique_id.startswith(prefix):
            return tactic
    return "unknown"
