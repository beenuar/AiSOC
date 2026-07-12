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

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "services" / "agents"))

from app.llm.prompt_registry import default_registry, load_lock, write_lock  # noqa: E402


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
