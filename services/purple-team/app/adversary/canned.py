"""The canned demo campaign — `pnpm aisoc:selfplay`.

Runs a deterministic 5-stage attack chain against a seeded *lab* environment,
offline (in-memory telemetry + a canned detection oracle), prints a live-ledger-
style trace + a scoreboard, and shows the Detection-as-Code proposals it would
file for the misses. Zero external dependencies so it runs in demo CI and on a
laptop in seconds.

Run: ``python -m app.adversary.canned`` (from ``services/purple-team``) or
``pnpm aisoc:selfplay`` from the repo root.
"""

from __future__ import annotations

import json
import sys

from app.adversary.campaign import CannedOracle, InMemoryEmitter, run_campaign
from app.adversary.dac import InMemoryFiler, auto_file_gaps
from app.adversary.planner import InventoryTechnique, plan_campaign
from app.adversary.scope_guard import Asset
from app.adversary.scoreboard import build_scoreboard_row

# A small ART/Caldera-style inventory, one+ per stage.
CANNED_INVENTORY: list[InventoryTechnique] = [
    InventoryTechnique("T1566.001", "Spearphishing Attachment", "initial-access", frozenset({"windows"}), 90),
    InventoryTechnique("T1059.001", "PowerShell", "execution", frozenset({"windows"}), 95),
    InventoryTechnique("T1547.001", "Registry Run Keys / Startup Folder", "persistence", frozenset({"windows"}), 80),
    InventoryTechnique("T1055", "Process Injection", "privilege-escalation", frozenset({"windows"}), 85),
    InventoryTechnique("T1048", "Exfiltration Over Alternative Protocol", "exfiltration", frozenset({"windows", "linux"}), 88),
]

# The seeded lab range (note the lab/sandbox tags — the scope guard requires them).
CANNED_TARGETS: list[Asset] = [
    Asset.of("lab-win-01", "lab", "windows"),
    Asset.of("sandbox-win-02", "sandbox", "windows"),
]

# The canned defense catches 3 of 5; the other two are coverage gaps.
CANNED_DETECTED = {"T1059.001", "T1055", "T1048"}


def run(as_json: bool = False) -> dict:
    campaign = plan_campaign("nightly-self-play (canned)", CANNED_INVENTORY, CANNED_TARGETS)
    emitter = InMemoryEmitter()
    oracle = CannedOracle(CANNED_DETECTED)
    report = run_campaign(campaign, emitter, oracle)

    filer = InMemoryFiler()
    filed = auto_file_gaps(report, filer)
    row = build_scoreboard_row(report, new_detections_filed=len(filed), synthetic=True)

    result = {
        "report": report.to_dict(),
        "dac_proposals_filed": [d.name for d in filer.filed],
        "scoreboard_row": row,
    }

    if not as_json:
        print("── AiSOC self-play campaign (canned, offline) ──\n")
        for r in report.results:
            mark = "✓ DETECTED" if r.detected else "✗ MISSED  "
            lat = f" ({r.latency_s}s)" if r.latency_s else ""
            print(f"  [{r.order}] {r.stage:<22} {r.technique_id:<12} {mark}{lat}  {r.technique_name}")
        print(
            f"\n  {len(report.detected)}/{len(report.results)} techniques detected "
            f"({int(report.detection_rate * 100)}%) · MTTV {report.mean_time_to_verdict_s}s"
        )
        if filer.filed:
            print(f"\n  Auto-filed {len(filed)} Detection-as-Code proposal(s) for the misses (eval-gated review):")
            for d in filer.filed:
                print(f"    · {d.name}")
        print("\n  Synthetic canned campaign — the nightly live run scores against the seeded range.")
    return result


def main() -> int:
    as_json = "--json" in sys.argv
    result = run(as_json=as_json)
    if as_json:
        print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
