#!/usr/bin/env python3
"""
AiSOC Pillar-1 Unified Eval Runner
===================================
Runs all four offline evaluation suites against the 200-incident benchmark
dataset and emits a single JSON report (and a human-readable summary).

Suites:
    1. MITRE ATT&CK tactic accuracy   (services/agents/tests/test_mitre_accuracy.py)
    2. Alert reduction ratio          (services/agents/tests/test_alert_reduction.py)
    3. Investigation completeness     (services/agents/tests/test_investigation_completeness.py)
    4. Response-plan quality          (services/agents/tests/test_response_quality.py)

Each substrate suite reports two metrics:

  * **Per-case mean**     – classic average across all 200 incidents.
  * **Per-template macro** – equal-weight average across the ~55 distinct
    incident templates.  Because each template is cycled 3-4× through
    `{user}/{host}/{ip}/{campaign}` permutations, a single broken template
    moves per-case mean by ~0.5% but per-template macro by ~1.5-1.8% — so
    the macro is the regression-signal-preserving metric we gate on.

The runner also dumps the synthetic-telemetry coverage summary so connector
and Sigma-rule PRs can pin against a stable corpus.

Usage:
    python3 scripts/run_evals.py                  # human-readable + writes report
    python3 scripts/run_evals.py --json           # JSON to stdout
    python3 scripts/run_evals.py --out path.json  # write to a custom path
    python3 scripts/run_evals.py --ci             # exit non-zero on regression

Exit codes:
    0  All gates passed (or --ci not set)
    1  At least one suite below its target floor (only with --ci)
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_AGENTS_ROOT = _REPO_ROOT / "services" / "agents"
sys.path.insert(0, str(_AGENTS_ROOT))

from tests.test_mitre_accuracy import evaluate_mitre_accuracy  # type: ignore
from tests.test_alert_reduction import (  # type: ignore
    compute_reduction,
    fuse_alerts,
    generate_noisy_alert_stream,
)
from tests.test_investigation_completeness import (  # type: ignore
    evaluate_completeness,
)
from tests.test_response_quality import (  # type: ignore
    evaluate_response_quality,
)


# Per-suite floors (must match what tests assert)
_TARGETS = {
    "mitre_accuracy": 0.80,
    "alert_reduction": 0.70,
    "investigation_completeness": 0.85,
    "response_quality": 0.80,
}

# Per-template macro floors (kept slightly below per-case floors because each
# template contributes ~1/55 of the macro vs. ~1/200 of the per-case mean).
_TEMPLATE_TARGETS = {
    "mitre_accuracy": 0.80,
    "investigation_completeness": 0.80,
    "response_quality": 0.75,
}

_TELEMETRY_PATH = (
    _AGENTS_ROOT / "tests" / "eval_data" / "synthetic_telemetry.jsonl"
)


def _run_mitre() -> dict:
    t0 = time.perf_counter()
    res = evaluate_mitre_accuracy(threshold=_TARGETS["mitre_accuracy"])
    dur = (time.perf_counter() - t0) * 1000
    tpl = res.per_template_summary() if hasattr(res, "per_template_summary") else None
    out: dict = {
        "metric": "accuracy",
        "value": round(res.accuracy, 4),
        "target": _TARGETS["mitre_accuracy"],
        "passed": res.accuracy >= _TARGETS["mitre_accuracy"],
        "duration_ms": round(dur, 1),
        "details": {
            "incidents": res.total,
            "correct": res.correct,
            "precision": round(res.precision, 4),
            "recall": round(res.recall, 4),
            "f1": round(res.f1, 4),
        },
    }
    if tpl:
        macro = tpl.get("template_macro_accuracy", 0.0)
        target = _TEMPLATE_TARGETS["mitre_accuracy"]
        out["per_template"] = {
            "metric": "macro_accuracy",
            "value": round(macro, 4),
            "target": target,
            "passed": macro >= target,
            "template_count": tpl.get("template_count", 0),
            "failing_templates": [t["template_id"] for t in tpl.get("failing_templates", [])],
        }
        out["passed"] = out["passed"] and out["per_template"]["passed"]
    return out


def _run_alert_reduction(stream_size: int = 1000) -> dict:
    t0 = time.perf_counter()
    alerts = generate_noisy_alert_stream(count=stream_size)
    incidents = fuse_alerts(alerts)
    metrics = compute_reduction(alerts, incidents)
    dur = (time.perf_counter() - t0) * 1000
    storm = sum(1 for i in incidents if i.host.startswith("<storm:"))
    return {
        "metric": "reduction_ratio",
        "value": float(metrics["reduction"]),
        "target": _TARGETS["alert_reduction"],
        "passed": metrics["reduction"] >= _TARGETS["alert_reduction"],
        "duration_ms": round(dur, 1),
        "details": {
            "alerts_in": metrics["alerts_in"],
            "incidents_out": metrics["incidents_out"],
            "reduction_pct": metrics["reduction_pct"],
            "storm_incidents": storm,
        },
    }


def _run_completeness() -> dict:
    t0 = time.perf_counter()
    res = evaluate_completeness(keep_per_incident=True)
    dur = (time.perf_counter() - t0) * 1000
    out: dict = {
        "metric": "mean_keyword_coverage",
        "value": round(res.mean, 4),
        "target": _TARGETS["investigation_completeness"],
        "passed": res.mean >= _TARGETS["investigation_completeness"],
        "duration_ms": round(dur, 1),
        "details": {
            "incidents": res.incidents,
            "fully_covered": res.full_coverage,
            "fully_covered_pct": round(res.full_coverage_pct, 4),
        },
    }
    tpl = res.per_template_summary()
    macro = tpl.get("template_macro_mean", 0.0)
    target = _TEMPLATE_TARGETS["investigation_completeness"]
    out["per_template"] = {
        "metric": "macro_completeness",
        "value": round(macro, 4),
        "target": target,
        "passed": macro >= target,
        "template_count": tpl.get("template_count", 0),
        "failing_templates": [t["template_id"] for t in tpl.get("failing_templates", [])],
    }
    out["passed"] = out["passed"] and out["per_template"]["passed"]
    return out


def _run_response_quality() -> dict:
    t0 = time.perf_counter()
    res = evaluate_response_quality(keep_per_incident=True)
    dur = (time.perf_counter() - t0) * 1000
    out: dict = {
        "metric": "mean_rubric_score",
        "value": round(res.mean_score, 4),
        "target": _TARGETS["response_quality"],
        "passed": res.mean_score >= _TARGETS["response_quality"],
        "duration_ms": round(dur, 1),
        "details": {
            "incidents": res.incidents,
            "criteria": {k: round(res.crit_mean(k), 4) for k in res.crit_sum},
        },
    }
    tpl = res.per_template_summary()
    macro = tpl.get("template_macro_score", 0.0)
    target = _TEMPLATE_TARGETS["response_quality"]
    out["per_template"] = {
        "metric": "macro_score",
        "value": round(macro, 4),
        "target": target,
        "passed": macro >= target,
        "template_count": tpl.get("template_count", 0),
        "failing_templates": [t["template_id"] for t in tpl.get("failing_templates", [])],
    }
    out["passed"] = out["passed"] and out["per_template"]["passed"]
    return out


def _summarise_telemetry() -> dict:
    """Summarise the synthetic-telemetry corpus produced alongside the dataset.

    Returned shape stays small (no per-event payloads) so the eval report
    remains diff-friendly. If the JSONL is missing, returns a stub so the
    runner stays usable for hosts that strip out telemetry artefacts.
    """
    if not _TELEMETRY_PATH.exists():
        return {"present": False, "events": 0, "sources": {}, "incidents_with_telemetry": 0}
    sources: dict[str, int] = {}
    incidents: set[str] = set()
    total = 0
    for line in _TELEMETRY_PATH.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            evt = json.loads(line)
        except json.JSONDecodeError:
            continue
        total += 1
        src = evt.get("source", "unknown")
        sources[src] = sources.get(src, 0) + 1
        inc_id = evt.get("incident_id")
        if inc_id:
            incidents.add(inc_id)
    return {
        "present": True,
        "events": total,
        "sources": dict(sorted(sources.items())),
        "incidents_with_telemetry": len(incidents),
        "path": str(_TELEMETRY_PATH.relative_to(_REPO_ROOT)),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="AiSOC Pillar-1 unified evaluation runner.")
    parser.add_argument("--json", action="store_true", help="Print JSON report to stdout.")
    parser.add_argument(
        "--out",
        type=Path,
        default=_REPO_ROOT / "eval_report.json",
        help="Write JSON report to this path.",
    )
    parser.add_argument(
        "--ci",
        action="store_true",
        help="Exit non-zero if any suite is below its target floor.",
    )
    args = parser.parse_args()

    summary: dict = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset": "synthetic_incidents.json (200 cases, deterministic)",
        "suites": {
            "mitre_accuracy": _run_mitre(),
            "alert_reduction": _run_alert_reduction(),
            "investigation_completeness": _run_completeness(),
            "response_quality": _run_response_quality(),
        },
        "telemetry": _summarise_telemetry(),
    }
    summary["all_passed"] = all(s["passed"] for s in summary["suites"].values())

    args.out.write_text(json.dumps(summary, indent=2))

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print()
        print("=" * 78)
        print("  AiSOC Pillar-1 Eval - 200-incident synthetic benchmark")
        print("=" * 78)
        for name, suite in summary["suites"].items():
            mark = "PASS" if suite["passed"] else "FAIL"
            print(
                f"  [{mark}] {name:<28} {suite['metric']:<22} "
                f"{suite['value']:.3f}  (target >= {suite['target']:.2f})"
            )
            tpl = suite.get("per_template")
            if tpl:
                tpl_mark = "PASS" if tpl["passed"] else "FAIL"
                fail_count = len(tpl.get("failing_templates", []))
                fail_note = f" ({fail_count} failing templates)" if fail_count else ""
                print(
                    f"         per-template macro       "
                    f"{tpl['value']:.3f}  (target >= {tpl['target']:.2f}, "
                    f"n={tpl.get('template_count', 0)} templates) [{tpl_mark}]"
                    f"{fail_note}"
                )
                if fail_count:
                    failing = ", ".join(tpl["failing_templates"][:5])
                    suffix = "..." if fail_count > 5 else ""
                    print(f"           regressions: {failing}{suffix}")
        print("-" * 78)
        tele = summary["telemetry"]
        if tele.get("present"):
            print(
                f"  Synthetic telemetry: {tele['events']} events across "
                f"{len(tele['sources'])} sources, "
                f"{tele['incidents_with_telemetry']} incidents wired up "
                f"({tele['path']})"
            )
        else:
            print("  Synthetic telemetry: <not generated>")
        print("=" * 78)
        verdict = "ALL GATES PASSED" if summary["all_passed"] else "REGRESSION DETECTED"
        print(f"  {verdict}")
        try:
            rel = args.out.relative_to(_REPO_ROOT)
        except ValueError:
            rel = args.out
        print(f"  Report written to: {rel}")
        print()

    sys.exit(0 if (summary["all_passed"] or not args.ci) else 1)


if __name__ == "__main__":
    main()
