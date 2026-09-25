#!/usr/bin/env python3
"""Prompt-lock drift gate (Phase 8 — LLMOps).

Fails CI when a production prompt's text changed without a version bump + lock
regeneration. This is what makes the AGENTS.md "prompt change ⇒ re-grade the
eval harness" rule enforceable: you cannot quietly edit a prompt.

Usage:
    python3 scripts/check_prompt_lock.py           # fail on drift
    python3 scripts/check_prompt_lock.py --write     # regenerate the lock
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

ROOT = repo_root()


def _load_prompt_registry_module():
    """Load prompt_registry.py by path so we don't trigger app/llm/__init__.py
    (which imports contract → structlog). This gate runs in the dep-light lint
    job, which installs only ruff + mypy; prompt_registry.py is stdlib-only."""
    path = ROOT / "services" / "agents" / "app" / "llm" / "prompt_registry.py"
    spec = importlib.util.spec_from_file_location("aisoc_prompt_registry_under_check", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


_pr = _load_prompt_registry_module()
default_registry = _pr.default_registry
load_lock = _pr.load_lock
write_lock = _pr.write_lock


def main() -> int:
    registry = default_registry()
    if "--write" in sys.argv:
        write_lock(registry)
        print("prompt lock regenerated")
        return 0

    drifts = registry.verify_against_lock(load_lock())
    if drifts:
        print("ERROR: prompt lock drift detected:", file=sys.stderr)
        for d in drifts:
            print(f"  - {d}", file=sys.stderr)
        print(
            "\nA production prompt changed. Bump its version in "
            "services/agents/app/llm/prompt_registry.py, re-grade the eval harness, "
            "then run: python3 scripts/check_prompt_lock.py --write",
            file=sys.stderr,
        )
        return 1
    print(f"OK: prompt lock current ({len(registry.names())} prompts)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
