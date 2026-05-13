#!/usr/bin/env python3
"""
AiSOC Public Eval — chart / markdown renderer
==============================================
Consumes the JSON report produced by ``scripts/run_evals.py`` and writes a
small bundle of human-readable artefacts that the docs site, dashboard
widgets, and PR comments can include directly:

* ``eval/results/charts/summary.md``    — substrate suite scoreboard
* ``eval/results/charts/wet_eval.md``   — latency / tokens / USD tables
                                          (placeholder when T2.4 telemetry
                                          is not yet present)
* ``eval/results/charts/provenance.md`` — commit SHA / dataset SHA /
                                          eval mode / generated_at row

This script is the public entry point's "render" half:

    pnpm eval:public
    # → python3 scripts/run_evals.py  + python3 scripts/render_eval_charts.py

It is deliberately defensive: if the JSON report has no ``wet_eval`` block,
we render a placeholder note rather than fabricating numbers. Workspace
rule — never present substrate timings as live agent performance.

Usage
-----
::

    python3 scripts/render_eval_charts.py [REPORT_PATH] [--out-dir DIR]

When called with no arguments, it reads ``eval_report.json`` from the repo
root and writes to ``eval/results/charts/`` next to it.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_REPORT = _REPO_ROOT / "eval_report.json"
_DEFAULT_OUT = _REPO_ROOT / "eval" / "results" / "charts"

_DATASET_INPUTS = (
    _REPO_ROOT / "services" / "agents" / "tests" / "eval_data" / "synthetic_incidents.json",
    _REPO_ROOT / "services" / "agents" / "tests" / "eval_data" / "synthetic_telemetry.jsonl",
)


def _sha256_of(paths: tuple[Path, ...]) -> str:
    """Combined SHA-256 over the dataset inputs.

    Files that don't exist on disk are skipped (preserves runnability on
    partial clones); the hash still differs deterministically per-input
    set.
    """
    digest = hashlib.sha256()
    for path in paths:
        if not path.is_file():
            digest.update(f"<missing:{path.name}>".encode())
            continue
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _git_head_sha() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=_REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return "unknown"
    return result.stdout.strip() or "unknown"


def _fmt_pct(value: float) -> str:
    return f"{value * 100:.1f} %"


def _fmt_value(value: Any, *, as_pct: bool) -> str:
    if not isinstance(value, (int, float)):
        return "—"
    if as_pct:
        return _fmt_pct(float(value))
    return f"{float(value):.3f}"


def _render_substrate_summary(report: dict[str, Any]) -> str:
    suites: dict[str, dict[str, Any]] = report.get("suites", {}) or {}
    if not suites:
        return "_(no substrate suites in report)_\n"

    lines = [
        "# Substrate suite summary",
        "",
        "These are **substrate self-checks** (per-PR, no LLM, no DB). They",
        "gate substrate consistency, not live agent performance. See the",
        "[methodology page](../../../apps/docs/docs/benchmark-methodology.md)",
        "for the substrate-vs-wet distinction.",
        "",
        "| Suite | Metric | Value | Per-template macro | Target | Verdict |",
        "|-------|--------|------:|-------------------:|-------:|:-------:|",
    ]

    for name, suite in suites.items():
        metric = suite.get("metric", "—")
        target = suite.get("target")
        details = suite.get("details") or {}
        as_pct = bool(details.get("display_as_pct", True))
        if metric in {"reduction_ratio", "reduction"}:
            as_pct = True
        if "rubric" in metric or "score" in metric:
            as_pct = False
        value_cell = _fmt_value(suite.get("value"), as_pct=as_pct)
        target_cell = _fmt_value(target, as_pct=as_pct) if target is not None else "—"
        per_tpl = suite.get("per_template") or {}
        per_tpl_cell = _fmt_value(per_tpl.get("value"), as_pct=as_pct) if per_tpl else "n/a"
        verdict = "PASS" if suite.get("passed") else "FAIL"
        lines.append(
            f"| `{name}` | {metric} | {value_cell} | {per_tpl_cell} | {target_cell} | **{verdict}** |"
        )

    overall = "ALL GATES PASSED" if report.get("all_passed") else "REGRESSION DETECTED"
    lines += ["", f"**Overall:** {overall}", ""]
    return "\n".join(lines)


def _render_per_investigation_block(per_inv: dict[str, Any]) -> str:
    """Render the T2.4 deterministic-substrate budget projection.

    This block exists in ``eval_report.json -> per_investigation`` once
    T2.4 has landed. It is **not** wet eval — it is a deterministic
    budget projection. We label it as such so consumers don't quote it as
    live agent performance (workspace rule).
    """
    tok = per_inv.get("tokens_per_investigation") or {}
    usd = per_inv.get("usd_per_investigation") or {}
    lat = per_inv.get("latency_per_investigation_ms") or {}
    rate = per_inv.get("rate_card_per_m_tokens_usd") or {}
    model = per_inv.get("model", "?")

    lines = [
        "# Wet eval — latency / tokens / USD",
        "",
        ":::warning Deterministic-substrate budget, not wet eval",
        "The figures below come from `per_investigation` in the JSON report.",
        "They are a **deterministic-substrate budget projection** computed by",
        "T2.4 (no LLM call), not a wet-eval measurement. Do not quote them",
        "as live agent performance. Wet eval (real LLM, real money) replaces",
        "this block once T5.5's weekly job runs.",
        ":::",
        "",
        f"_Model assumed for the rate-card projection: `{model}`_  ",
        f"_Rate (USD per 1M tokens): input ${rate.get('input', 0):.2f}, "
        f"output ${rate.get('output', 0):.2f}_",
        "",
        "## Tokens per investigation (substrate budget)",
        "",
        "| Statistic | Value |",
        "|-----------|------:|",
        f"| mean      | {tok.get('mean', 0):.0f} |",
        f"| median    | {tok.get('median', 0):.0f} |",
        f"| p95       | {tok.get('p95', 0):.0f} |",
        f"| p99       | {tok.get('p99', 0):.0f} |",
        f"| prompt mean | {tok.get('prompt_mean', 0):.0f} |",
        f"| completion mean | {tok.get('completion_mean', 0):.0f} |",
        "",
        "## USD per investigation (substrate budget)",
        "",
        "| Statistic | Value |",
        "|-----------|------:|",
        f"| mean   | ${usd.get('mean', 0):.5f} |",
        f"| median | ${usd.get('median', 0):.5f} |",
        f"| p95    | ${usd.get('p95', 0):.5f} |",
        f"| p99    | ${usd.get('p99', 0):.5f} |",
        "",
        "## Latency per investigation (substrate path, ms)",
        "",
        "| Statistic | Value |",
        "|-----------|------:|",
        f"| p50 | {lat.get('p50', 0):.4f} ms |",
        f"| p95 | {lat.get('p95', 0):.4f} ms |",
        f"| p99 | {lat.get('p99', 0):.4f} ms |",
        f"| mean | {lat.get('mean', 0):.4f} ms |",
        "",
        "_(substrate path — not wet-eval; expect orders-of-magnitude lower than agent timings)_",
        "",
    ]
    return "\n".join(lines)


def _render_wet_eval(report: dict[str, Any]) -> str:
    """Render the latency / tokens / USD bundle.

    Three modes:

    * ``wet_eval`` block present → render real wet-eval numbers (T5.5).
    * ``per_investigation`` block present → render T2.4 deterministic
      substrate budget, clearly labelled as a projection, not a wet
      measurement.
    * Neither → emit a placeholder, never imputed numbers.
    """
    wet = report.get("wet_eval")
    if wet:
        return _render_wet_eval_real(wet)

    per_inv = report.get("per_investigation")
    if per_inv:
        return _render_per_investigation_block(per_inv)

    return (
        "# Wet eval — latency / tokens / USD\n"
        "\n"
        "_(no wet-eval block in this report)_\n"
        "\n"
        "Wet-eval telemetry (latency, tokens, USD) requires the live agent\n"
        "and a real LLM key. It is added by T2.4 in the v8.0 plan and run\n"
        "weekly by the wet-eval CI job (T5.5). This run is substrate-only,\n"
        "so per-investigation latency / token / cost numbers are not\n"
        "available — and are not imputed.\n"
        "\n"
        "To run wet eval locally once T2.4 lands::\n"
        "\n"
        "    export AISOC_BENCH_PROVIDER=openai\n"
        "    export OPENAI_API_KEY=sk-...\n"
        "    python scripts/run_evals.py --wet --out wet-eval.json\n"
        "    python scripts/render_eval_charts.py wet-eval.json\n"
    )


def _render_wet_eval_real(wet: dict[str, Any]) -> str:
    """Render an actual wet-eval block (T5.5)."""

    sections: list[str] = [
        "# Wet eval — latency / tokens / USD",
        "",
        ":::tip Wet eval (live agent, real LLM)",
        "Numbers below are from a real `services/agents` LangGraph run with"
        " live LLM calls. See the [methodology page](../../../apps/docs/docs/benchmark-methodology.md)"
        " for the substrate-vs-wet distinction.",
        ":::",
        "",
    ]

    latency = wet.get("latency") or {}
    if latency:
        sections.append("## Latency (seconds)")
        sections.append("")
        sections.append("| Template family | p50 | p95 | p99 | n |")
        sections.append("|-----------------|----:|----:|----:|--:|")
        for family, stats in latency.items():
            if not isinstance(stats, dict):
                continue
            sections.append(
                f"| {family} | "
                f"{stats.get('p50_s', '—')} | "
                f"{stats.get('p95_s', '—')} | "
                f"{stats.get('p99_s', '—')} | "
                f"{stats.get('n', '—')} |"
            )
        sections.append("")

    tokens = wet.get("tokens") or {}
    if tokens:
        sections.append("## Tokens per investigation")
        sections.append("")
        sections.append("| Template family | mean | median | p95 | n |")
        sections.append("|-----------------|-----:|-------:|----:|--:|")
        for family, stats in tokens.items():
            if not isinstance(stats, dict):
                continue
            sections.append(
                f"| {family} | "
                f"{stats.get('mean', '—')} | "
                f"{stats.get('median', '—')} | "
                f"{stats.get('p95', '—')} | "
                f"{stats.get('n', '—')} |"
            )
        sections.append("")

    usd = wet.get("usd") or {}
    if usd:
        sections.append("## USD per investigation (rate-card-multiplied)")
        sections.append("")
        rate_card = usd.get("rate_card_at_run")
        if rate_card:
            sections.append(f"_Rate card snapshot at run time: `{rate_card}`._")
            sections.append("")
        per_family = usd.get("per_family") or {}
        sections.append("| Template family | mean ($) | median ($) | p95 ($) | n |")
        sections.append("|-----------------|---------:|-----------:|--------:|--:|")
        for family, stats in per_family.items():
            if not isinstance(stats, dict):
                continue
            sections.append(
                f"| {family} | "
                f"{stats.get('mean', '—')} | "
                f"{stats.get('median', '—')} | "
                f"{stats.get('p95', '—')} | "
                f"{stats.get('n', '—')} |"
            )
        sections.append("")

    if len(sections) == 2:
        sections.append(
            "_(wet_eval block is present but contains no latency / tokens /"
            " usd sub-blocks; nothing to render)_"
        )
        sections.append("")
    return "\n".join(sections)


def _render_provenance(report: dict[str, Any], report_path: Path) -> str:
    dataset_sha = _sha256_of(_DATASET_INPUTS)
    commit_sha = _git_head_sha()
    mode = "wet" if report.get("wet_eval") else "substrate"
    generated_at = report.get("generated_at", "—")

    return "\n".join(
        [
            "# Provenance",
            "",
            "| Field | Value |",
            "|-------|-------|",
            f"| Commit SHA | `{commit_sha}` |",
            f"| Generated at (UTC) | `{generated_at}` |",
            f"| Dataset SHA-256 | `{dataset_sha}` |",
            f"| Eval mode | `{mode}` |",
            f"| Source report | `{report_path.relative_to(_REPO_ROOT) if report_path.is_relative_to(_REPO_ROOT) else report_path}` |",
            f"| Renderer | `scripts/render_eval_charts.py` |",
            "",
            "These fields are pulled from the JSON report and the local",
            "checkout. They appear in the [benchmark provenance footer](../../../apps/docs/docs/benchmark.md#provenance)",
            "on the docs site.",
            "",
        ]
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Render the AiSOC eval JSON report into shareable markdown.",
    )
    parser.add_argument(
        "report",
        nargs="?",
        type=Path,
        default=_DEFAULT_REPORT,
        help=f"Path to the eval JSON report (default: {_DEFAULT_REPORT}).",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=_DEFAULT_OUT,
        help=f"Directory to write rendered artefacts into (default: {_DEFAULT_OUT}).",
    )
    args = parser.parse_args()

    if not args.report.is_file():
        raise SystemExit(
            f"eval report not found at {args.report}. Run "
            f"'python3 scripts/run_evals.py --out {args.report}' first."
        )

    report = json.loads(args.report.read_text())
    args.out_dir.mkdir(parents=True, exist_ok=True)

    summary = _render_substrate_summary(report)
    wet = _render_wet_eval(report)
    prov = _render_provenance(report, args.report)

    (args.out_dir / "summary.md").write_text(summary)
    (args.out_dir / "wet_eval.md").write_text(wet)
    (args.out_dir / "provenance.md").write_text(prov)

    try:
        rel = args.out_dir.relative_to(_REPO_ROOT)
    except ValueError:
        rel = args.out_dir
    print(f"render_eval_charts: wrote summary.md, wet_eval.md, provenance.md to {rel}/")


if __name__ == "__main__":
    main()
