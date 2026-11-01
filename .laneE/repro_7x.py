"""Lane E reproduction: what Phase 7.1-7.4 claims is missing, measured."""

from __future__ import annotations

import json
import pathlib
import sys
from collections import Counter

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load(name: str) -> list[dict]:
    blob = json.loads((ROOT / "services/fusion/app/data" / name).read_text())
    return blob["rules"] if isinstance(blob, dict) and "rules" in blob else blob


def main() -> int:
    native = load("detection_ruleset.json")
    imported = load("detection_ruleset_imported.json")
    windowed = load("windowed_ruleset.json")

    print("== compiled corpus ==")
    print(f"native   {len(native)}")
    print(f"imported {len(imported)}")
    print(f"windowed {len(windowed)}")

    ai_products = {"ai", "llm", "openai", "anthropic"}
    print("\n== AI-family executable rules (native) ==")
    for r in native:
        if r.get("product") in ai_products:
            print(f"  {r['id']:24s} {r.get('product'):10s} {r.get('slug')}")
    print(f"  total: {sum(1 for r in native if r.get('product') in ai_products)}")

    print("\n== products present (AI-adjacent check) ==")
    c = Counter(r.get("product") for r in native)
    for p in ("ai", "llm", "github", "google-workspace", "m365", "azure", "entra"):
        print(f"  {p:20s} {c.get(p, 0)}")

    print("\n== 7.1: llm_usage provider coverage ==")
    src = (ROOT / "services/connectors/app/connectors/llm_usage.py").read_text()
    providers = [p for p in ("openai", "anthropic", "gemini", "google", "copilot", "m365", "github", "entra") if f'"{p}"' in src]
    print(f"  provider literals in llm_usage.py: {providers}")

    print("\n== 7.1: AI-chat compliance tables ==")
    migs = sorted((ROOT / "services/api/migrations").glob("*.sql"))
    hits = [m.name for m in migs if "compliance" in m.read_text().lower() and "ai" in m.name.lower()]
    print(f"  migrations with an AI chat compliance table: {hits or 'NONE'}")

    print("\n== 7.2: asset kinds ==")
    model = (ROOT / "services/api/app/models/ai_asset.py").read_text()
    kinds = [k for k in model.split("AI_ASSET_KINDS")[1].split(")")[0].split('"') if k.islower() and "_" in k or k in ("ai_app",)]
    print(f"  AI_ASSET_KINDS: {sorted(set(kinds))}")
    print(f"  hosted_agent present: {'hosted_agent' in model}")
    print(f"  repo artefact kind present: {'repo_ai_artifact' in model}")

    print("\n== 7.3: agent identity + per-agent baselines ==")
    base = (ROOT / "services/fusion/app/services/baselines.py").read_text()
    print(f"  baseline_oauth_app_volume_z present: {'baseline_oauth_app_volume_z' in base}")
    print(f"  per-agent baseline fn present: {'agent' in base.lower() and 'def baseline_agent' in base}")
    ident = list((ROOT / "services/agents/app").rglob("*identity*.py"))
    print(f"  agents-side identity modules: {[p.relative_to(ROOT).as_posix() for p in ident]}")

    print("\n== 7.4: rule pack targets ==")
    want = {
        "provider key used from a new ASN": "asn",
        "agent invoking a new high-risk tool": "high_risk_tool",
        "MCP server from an unvetted source": "unvetted",
        "coding agent with prompts disabled": "permission_prompts_disabled",
        "bulk data access by an OAuth AI app": "bulk",
        "guardrail violation rise": "guardrail",
        "token-spend anomaly": "token_spend",
        "secrets/PII labelled in AI chats": "chat_label",
        "agent reading browser cookie store": "cookie",
        "write-scope OAuth grant to unsanctioned AI app": "write_scope",
    }
    blob = json.dumps(native)
    for label, needle in want.items():
        print(f"  {'HIT ' if needle in blob else 'MISS'} {label}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
