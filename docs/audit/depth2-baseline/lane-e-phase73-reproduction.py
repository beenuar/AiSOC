"""Lane E reproduction: what wave-2 7.3 claims is missing, measured.

Run from the repository root:

    python3 docs/audit/depth2-baseline/lane-e-phase73-reproduction.py

7.3 is depth 6.4, which is parity 6.7, and it has two halves. This measures
both against the tree, so the "before" is a recorded command and not a grep
in a progress file.

Half A — agent identity
    Parity 6.7: "Give each internal agent its own identity, with short-lived
    credentials and least-privilege tool scopes, visible in the audit log."

Half B — per-agent baselines
    Depth 6.4: "per-agent baselines (tools, resources, volume, token spend,
    hours) ... through the Phase 3.4 baseline module."

Half B is also the dependency under four of 7.4's remaining targets, which
is why a partial version of it would be worse than none: it would produce
rules that cannot fire.
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[3]

BASELINES = ROOT / "services/fusion/app/services/baselines.py"
REGISTRY = ROOT / "services/agents/app/tools/registry.py"
AGENTS_APP = ROOT / "services/agents/app"


def _derived_fields() -> set[str]:
    """The baseline module's own DERIVED_FIELDS set, read without importing.

    Read textually rather than imported because this script has to run from
    a bare checkout with no service virtualenv, which is the state a
    reviewer reproducing the gap will be in.
    """
    source = BASELINES.read_text()
    block = source.split("DERIVED_FIELDS: frozenset[str] = frozenset(", 1)[1].split("\n)", 1)[0]
    rarity = source.split("RARITY_FIELDS: dict[str, tuple[str, ...]] = {", 1)[1].split("\n}", 1)[0]
    return set(re.findall(r'"(baseline_[a-z_]+)"', block)) | set(re.findall(r'"(baseline_[a-z_]+)"', rarity))


def main() -> int:
    print("== Half A: agent identity ==")
    modules = sorted(
        p.relative_to(ROOT).as_posix()
        for p in AGENTS_APP.rglob("*.py")
        if re.search(r"AgentIdentity|agent_identity|agent_principal", p.read_text())
    )
    print(f"  modules defining an agent identity: {modules or 'NONE'}")

    registry = REGISTRY.read_text()
    execute = registry.split("async def execute(", 1)[1].split("\n    def ", 1)[0] if "async def execute(" in registry else ""
    print(f"  ToolRegistry.execute takes a caller identity: {'identity' in execute or 'principal' in execute}")
    print(f"  ToolRegistry declares per-agent tool scopes:  {'scope' in registry.lower()}")
    print(f"  ToolRegistry writes an audit row per call:    {'audit' in registry.lower()}")

    print("\n== Half B: per-agent baselines ==")
    fields = _derived_fields()
    print(f"  derived baseline fields in total: {len(fields)}")
    for name in sorted(fields):
        print(f"    {name}")

    agent_fields = sorted(f for f in fields if "agent" in f)
    print(f"  of those, keyed on an AI agent: {agent_fields or 'NONE'}")

    source = BASELINES.read_text()
    print(f"  a generic sub-principal mechanism exists:  {'SUB_PRINCIPAL' in source}")
    print(f"  the only sub-principal kind is hardcoded:  {'OAUTH_APP_FIELDS' in source and 'SUB_PRINCIPAL' not in source}")

    print("\n== What 7.4 needs from Half B ==")
    needed = {
        "a *new* high-risk tool (novelty per agent)": "baseline_agent_tool_rarity",
        "guardrail-violation rate per agent": "baseline_agent_guardrail_rate_z",
        "token spend per agent": "baseline_agent_token_spend_z",
        "token spend per provider key": "baseline_provider_key_token_spend_z",
    }
    for label, field in needed.items():
        print(f"  {'HAVE' if field in fields else 'MISS'}  {label}  ({field})")

    return 0


if __name__ == "__main__":
    sys.exit(main())
