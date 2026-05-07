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
    5. Hunt corpus coverage           (services/agents/tests/test_hunt_corpus.py)
    6. AI-vs-AI adversary degradation (services/agents/tests/test_adversary_eval.py)

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
    python3 scripts/run_evals.py \
        --baseline eval_baseline.json \
        --max-regression-pp 1.0                   # gate against a saved baseline

Exit codes:
    0  All gates passed (or --ci not set)
    1  At least one suite below its target floor (only with --ci)
    2  MITRE accuracy regressed by ≥ --max-regression-pp vs baseline (w2-dac)
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
from tests.test_adversary_eval import (  # type: ignore
    evaluate_adversary_accuracy,
    _OVERALL_FLOOR as _ADVERSARY_OVERALL_FLOOR,
    _LIGHT_BUCKET_FLOOR as _ADVERSARY_LIGHT_FLOOR,
    _HEAVY_BUCKET_CEILING as _ADVERSARY_HEAVY_CEILING,
)
from tests.test_hunt_corpus import (  # type: ignore
    evaluate_hunt_corpus,
    _POSITIVE_FLOOR as _HUNT_POSITIVE_FLOOR,
    _NEGATIVE_CEILING as _HUNT_NEGATIVE_CEILING,
)
from tests.test_confidence_calibration import (  # type: ignore
    BRIER_THRESHOLD_INVESTIGATION as _CALIB_BRIER_INV,
    BRIER_THRESHOLD_TRIAGE as _CALIB_BRIER_TRIAGE,
    ECE_THRESHOLD_INVESTIGATION as _CALIB_ECE_INV,
    ECE_THRESHOLD_TRIAGE as _CALIB_ECE_TRIAGE,
    run_evaluation as _run_calibration_eval,
)
from tests.test_memory_recall import (  # type: ignore
    RECALL_ACCURACY_FLOOR as _RECALL_FLOOR,
    run_evaluation as _run_memory_recall_eval,
)
from tests.test_override_accuracy import (  # type: ignore
    OVERRIDE_ACCURACY_FLOOR as _OVERRIDE_FLOOR,
    run_evaluation as _run_override_accuracy_eval,
)


# Per-suite floors (must match what tests assert)
_TARGETS = {
    "mitre_accuracy": 0.80,
    "alert_reduction": 0.70,
    "investigation_completeness": 0.85,
    "response_quality": 0.80,
    "hunt_corpus": _HUNT_POSITIVE_FLOOR,
    "adversary_eval": _ADVERSARY_OVERALL_FLOOR,
    # Calibration target is "Brier score *at or below* this value", so the
    # display logic in main() inverts the pass condition for this suite.
    "confidence_calibration": _CALIB_BRIER_INV,
    "memory_recall": _RECALL_FLOOR,
    "override_accuracy": _OVERRIDE_FLOOR,
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


def _run_hunt_corpus() -> dict:
    """Fifth gate (w2-hac): hunt-as-code coverage against the synthetic
    hunt telemetry corpus.

    The hunt corpus is small and hand-authored, so we hold ourselves to
    perfect scenario coverage rather than a percentage floor:

      * every hunt MUST fire on its declared positive scenario (positive
        rate at or above ``_HUNT_POSITIVE_FLOOR``);
      * no hunt may fire on its declared negative scenario (false-positive
        rate at or below ``_HUNT_NEGATIVE_CEILING``);
      * every ``INC-HUNT-*`` event in the telemetry must be referenced by
        at least one hunt YAML — orphan telemetry is a regression.
    """
    t0 = time.perf_counter()
    res = evaluate_hunt_corpus()
    dur = (time.perf_counter() - t0) * 1000

    positive_pass = res.positive_rate >= _HUNT_POSITIVE_FLOOR
    negative_pass = res.false_positive_rate <= _HUNT_NEGATIVE_CEILING
    no_orphans = not res.orphan_incident_ids

    return {
        "metric": "positive_scenario_catch_rate",
        "value": round(res.positive_rate, 4),
        "target": _HUNT_POSITIVE_FLOOR,
        "passed": positive_pass and negative_pass and no_orphans,
        "duration_ms": round(dur, 1),
        "details": {
            "hunts": res.hunts_total,
            "positives_expected": res.positives_expected,
            "positives_caught": res.positives_caught,
            "negatives_expected": res.negatives_expected,
            "false_positives": res.false_positives,
            "false_positive_rate": round(res.false_positive_rate, 4),
            "negative_ceiling": _HUNT_NEGATIVE_CEILING,
            "orphan_incident_ids": res.orphan_incident_ids,
            "misses": res.misses,
            "false_positive_details": res.false_positive_details,
            "positive_pass": positive_pass,
            "negative_pass": negative_pass,
            "no_orphans": no_orphans,
        },
    }


def _run_adversary() -> dict:
    """Sixth gate (w2-aivai): graceful degradation under attacker-LLM mutation.

    The adversary corpus is generated by ``scripts/generate_adversary_incidents.py``
    and rewrites every defender-known keyword into evasive synonyms, character
    obfuscation, and fragmentation across heavy/medium/light buckets. The gate
    enforces three things at once:

      * overall catch rate stays at or above ``_ADVERSARY_OVERALL_FLOOR`` —
        the substrate must degrade gracefully, not fall off a cliff;
      * the light (control) bucket stays at or above ``_ADVERSARY_LIGHT_FLOOR``
        — leetspeak alone shouldn't break the keyword extractor;
      * the heavy bucket stays *at or below* ``_ADVERSARY_HEAVY_CEILING`` —
        if heavy is catching too much, the dataset isn't actually adversarial
        and the suite has lost its signal.
    """
    t0 = time.perf_counter()
    res = evaluate_adversary_accuracy()
    dur = (time.perf_counter() - t0) * 1000

    light_acc = res.bucket_accuracy("light")
    heavy_acc = res.bucket_accuracy("heavy")
    overall_pass = res.accuracy >= _ADVERSARY_OVERALL_FLOOR
    light_pass = light_acc >= _ADVERSARY_LIGHT_FLOOR
    heavy_pass = heavy_acc <= _ADVERSARY_HEAVY_CEILING

    return {
        "metric": "graceful_degradation_catch_rate",
        "value": round(res.accuracy, 4),
        "target": _ADVERSARY_OVERALL_FLOOR,
        "passed": overall_pass and light_pass and heavy_pass,
        "duration_ms": round(dur, 1),
        "details": {
            "incidents": res.total,
            "correct": res.correct,
            "lost_all_tactics": res.lost_all_tactics,
            "buckets": res.to_summary()["buckets"],
            "light_floor": _ADVERSARY_LIGHT_FLOOR,
            "heavy_ceiling": _ADVERSARY_HEAVY_CEILING,
            "light_pass": light_pass,
            "heavy_pass": heavy_pass,
        },
    }


def _run_confidence_calibration() -> dict:
    """Seventh gate (tier1-confidence): Brier-score gate over 200 positive +
    200 deterministic benign cases.

    Calibration is a *lower-is-better* metric, so unlike the other suites the
    pass condition is "value <= target" for both Brier score and ECE. We
    surface the investigation Brier as the headline number because it's the
    end-to-end agent verdict; triage gates are exposed via ``details``.
    """
    t0 = time.perf_counter()
    res = _run_calibration_eval()
    dur = (time.perf_counter() - t0) * 1000

    inv_brier = res["investigation"]["brier"]
    inv_ece = res["investigation"]["ece"]
    triage_brier = res["triage"]["brier"]
    triage_ece = res["triage"]["ece"]

    inv_brier_pass = inv_brier <= _CALIB_BRIER_INV
    inv_ece_pass = inv_ece <= _CALIB_ECE_INV
    triage_brier_pass = triage_brier <= _CALIB_BRIER_TRIAGE
    triage_ece_pass = triage_ece <= _CALIB_ECE_TRIAGE

    return {
        "metric": "investigation_brier_score",
        "value": inv_brier,
        "target": _CALIB_BRIER_INV,
        # Lower-is-better: passed iff *all* sub-gates pass.
        "passed": (
            inv_brier_pass
            and inv_ece_pass
            and triage_brier_pass
            and triage_ece_pass
            and bool(res.get("passed", False))
        ),
        "duration_ms": round(dur, 1),
        "details": {
            "lower_is_better": True,
            "investigation_brier": inv_brier,
            "investigation_brier_max": _CALIB_BRIER_INV,
            "investigation_ece": inv_ece,
            "investigation_ece_max": _CALIB_ECE_INV,
            "triage_brier": triage_brier,
            "triage_brier_max": _CALIB_BRIER_TRIAGE,
            "triage_ece": triage_ece,
            "triage_ece_max": _CALIB_ECE_TRIAGE,
            "investigation_separation": res["investigation"]["separation"],
            "triage_separation": res["triage"]["separation"],
            "mean_confidence_positive_investigation": res["investigation"][
                "mean_confidence_positive"
            ],
            "mean_confidence_benign_investigation": res["investigation"][
                "mean_confidence_benign"
            ],
            "investigation_brier_pass": inv_brier_pass,
            "investigation_ece_pass": inv_ece_pass,
            "triage_brier_pass": triage_brier_pass,
            "triage_ece_pass": triage_ece_pass,
        },
    }


def _run_memory_recall() -> dict:
    """Memory-recall gate: validates three-tier memory fidelity, priority,
    isolation, and override ingestion using offline in-process fallbacks."""
    t0 = time.perf_counter()
    res = _run_memory_recall_eval()
    dur = (time.perf_counter() - t0) * 1000
    return {
        "metric": "memory_recall_accuracy",
        "value": res["recall_accuracy"],
        "target": _RECALL_FLOOR,
        "passed": res["passed"],
        "duration_ms": round(dur, 1),
        "details": {
            "total_cases": res["total_cases"],
            "passed_cases": res["passed_cases"],
            "failed_cases": res.get("failed_cases", []),
        },
    }


def _run_override_accuracy() -> dict:
    """Override-accuracy gate: validates analyst-feedback ingestion, retrieval,
    idempotent upsert, and cross-tenant isolation using offline fallbacks."""
    t0 = time.perf_counter()
    res = _run_override_accuracy_eval()
    dur = (time.perf_counter() - t0) * 1000
    return {
        "metric": "override_accuracy",
        "value": res["override_accuracy"],
        "target": _OVERRIDE_FLOOR,
        "passed": res["passed"],
        "duration_ms": round(dur, 1),
        "details": {
            "total_cases": res["total_cases"],
            "passed_cases": res["passed_cases"],
            "failed_cases": res.get("failed_cases", []),
        },
    }


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
    parser.add_argument(
        "--baseline",
        type=Path,
        default=None,
        help=(
            "Compare results against a saved baseline JSON (Wave 2 — w2-dac). "
            "When set, fail with exit code 2 if MITRE accuracy regresses by "
            "≥ --max-regression-pp percentage points."
        ),
    )
    parser.add_argument(
        "--max-regression-pp",
        type=float,
        default=1.0,
        help="Allowed MITRE accuracy regression vs baseline, in percentage points.",
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
            "hunt_corpus": _run_hunt_corpus(),
            "adversary_eval": _run_adversary(),
            "confidence_calibration": _run_confidence_calibration(),
            "memory_recall": _run_memory_recall(),
            "override_accuracy": _run_override_accuracy(),
        },
        "telemetry": _summarise_telemetry(),
    }
    summary["all_passed"] = all(s["passed"] for s in summary["suites"].values())

    regression_failure = False
    if args.baseline is not None:
        if not args.baseline.exists():
            summary["baseline_compare"] = {
                "baseline_path": str(args.baseline),
                "available": False,
                "note": "baseline file not found; treating as no-op",
            }
        else:
            try:
                baseline = json.loads(args.baseline.read_text())
            except json.JSONDecodeError as exc:
                summary["baseline_compare"] = {
                    "baseline_path": str(args.baseline),
                    "available": False,
                    "error": f"invalid baseline JSON: {exc}",
                }
            else:
                deltas: dict[str, dict] = {}
                worst_mitre_drop_pp = 0.0
                for name, suite in summary["suites"].items():
                    base_suite = baseline.get("suites", {}).get(name) or {}
                    base_value = float(base_suite.get("value", suite["value"]))
                    delta_pp = round((suite["value"] - base_value) * 100, 4)
                    deltas[name] = {
                        "candidate": suite["value"],
                        "baseline": base_value,
                        "delta_pp": delta_pp,
                    }
                    if name == "mitre_accuracy" and delta_pp < -worst_mitre_drop_pp:
                        worst_mitre_drop_pp = -delta_pp
                regression_failure = worst_mitre_drop_pp >= args.max_regression_pp
                summary["baseline_compare"] = {
                    "baseline_path": str(args.baseline),
                    "available": True,
                    "max_regression_pp": args.max_regression_pp,
                    "mitre_drop_pp": round(worst_mitre_drop_pp, 4),
                    "regressed": regression_failure,
                    "deltas": deltas,
                }

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
            lower_is_better = bool(suite.get("details", {}).get("lower_is_better"))
            comparator = "<=" if lower_is_better else ">="
            print(
                f"  [{mark}] {name:<28} {suite['metric']:<28} "
                f"{suite['value']:.3f}  (target {comparator} {suite['target']:.2f})"
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
        cmp = summary.get("baseline_compare")
        if cmp and cmp.get("available"):
            arrow = "DROP" if cmp["regressed"] else "OK"
            print(
                f"  Baseline compare: MITRE Δ = "
                f"{cmp['deltas']['mitre_accuracy']['delta_pp']:+.2f} pp "
                f"(allowed drop ≤ {cmp['max_regression_pp']:.2f} pp) [{arrow}]"
            )
        try:
            rel = args.out.relative_to(_REPO_ROOT)
        except ValueError:
            rel = args.out
        print(f"  Report written to: {rel}")
        print()

    if regression_failure:
        sys.exit(2)
    sys.exit(0 if (summary["all_passed"] or not args.ci) else 1)


if __name__ == "__main__":
    main()
