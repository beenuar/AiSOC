#!/usr/bin/env python3
"""
AiSOC Public Eval — chart / markdown renderer
==============================================
Consumes the JSON report produced by ``scripts/run_evals.py`` and writes
two parallel bundles:

* **Markdown** (``eval/results/charts/``) — substrate scoreboard,
  latency/tokens/USD tables, provenance row. Used by PR comments, the
  dashboard widget, and the eval-results branch.
* **SVG** (``apps/docs/docs/benchmark-charts/``) — four charts wired
  inline into ``apps/docs/docs/benchmark.md`` via T2.4: tail-latency
  bars, tokens histogram, USD histogram, and per-template latency.

This script is the public entry point's "render" half::

    pnpm eval:public
    # → python3 scripts/run_evals.py  + python3 scripts/render_eval_charts.py

It is deliberately defensive: if the JSON report has no ``wet_eval`` block,
we render a placeholder note rather than fabricating numbers. Workspace
rule — never present substrate timings as live agent performance.

Usage
-----
::

    python3 scripts/render_eval_charts.py [REPORT_PATH]
    python3 scripts/render_eval_charts.py --no-svg      # markdown only
    python3 scripts/render_eval_charts.py --no-markdown # SVGs only
    python3 scripts/render_eval_charts.py --svg-out custom_dir/

When called with no arguments, it reads ``eval_report.json`` from the repo
root and writes the markdown bundle to ``eval/results/charts/`` and the
SVG charts to ``apps/docs/docs/benchmark-charts/``.

The SVG renderer is stdlib-only (hand-rolled emitter, no matplotlib) so
it runs in any CI box that has Python.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Iterable

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "scripts"))

from eval_telemetry import (  # type: ignore  # noqa: E402
    DEFAULT_INCIDENTS_PATH,
    DEFAULT_MODEL,
    compute_per_investigation_telemetry,
)

_DEFAULT_REPORT = _REPO_ROOT / "eval_report.json"
_DEFAULT_OUT = _REPO_ROOT / "eval" / "results" / "charts"
_DEFAULT_SVG_OUT = _REPO_ROOT / "apps" / "docs" / "docs" / "benchmark-charts"

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
        (
            "Numbers below are from a real `services/agents` LangGraph run with"
            " live LLM calls. See the [methodology page](../../../apps/docs/docs/benchmark-methodology.md)"
            " for the substrate-vs-wet distinction."
        ),
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


# ---------------------------------------------------------------------------
# SVG chart emitters (T2.4) — hand-rolled, stdlib-only.
# ---------------------------------------------------------------------------
_SVG_W = 720
_SVG_H = 360
_SVG_PAD = {"top": 64, "right": 32, "bottom": 64, "left": 88}

# Colour-blind-friendly palette pinned to the Docusaurus light theme. The
# charts read fine on dark themes too because the background is explicit.
_SVG_PALETTE = {
    "primary":    "#3b82f6",
    "accent":     "#10b981",
    "warn":       "#f59e0b",
    "danger":     "#ef4444",
    "axis":       "#94a3b8",
    "label":      "#0f172a",
    "label_muted": "#475569",
    "grid":       "#e2e8f0",
    "bg":         "#ffffff",
}


def _svg_open(width: int, height: int, *, title: str) -> list[str]:
    title_xml = (
        f'<title>{html.escape(title)}</title>\n  '
        f'<desc>{html.escape("Generated by scripts/render_eval_charts.py — AiSOC eval harness.")}</desc>\n  '
    )
    return [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'viewBox="0 0 {width} {height}" '
        f'width="{width}" height="{height}" '
        f'role="img" aria-labelledby="title">',
        f'  {title_xml}',
        f'  <rect width="{width}" height="{height}" fill="{_SVG_PALETTE["bg"]}"/>',
    ]


def _svg_text(
    x: float, y: float, label: str, *,
    size: float = 12.0,
    color: str = _SVG_PALETTE["label"],
    anchor: str = "start",
    weight: str = "normal",
) -> str:
    return (
        f'  <text x="{x:.1f}" y="{y:.1f}" font-family="ui-sans-serif, system-ui, sans-serif" '
        f'font-size="{size}" fill="{color}" text-anchor="{anchor}" '
        f'font-weight="{weight}">{html.escape(label)}</text>'
    )


def _svg_line(x1: float, y1: float, x2: float, y2: float, color: str, width: float = 1.0) -> str:
    return (
        f'  <line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
        f'stroke="{color}" stroke-width="{width}"/>'
    )


def _svg_rect(x: float, y: float, w: float, h: float, fill: str, *, opacity: float = 1.0) -> str:
    return (
        f'  <rect x="{x:.1f}" y="{y:.1f}" width="{max(w, 0):.1f}" height="{max(h, 0):.1f}" '
        f'fill="{fill}" fill-opacity="{opacity:.2f}"/>'
    )


def _format_axis(value: float, kind: str) -> str:
    if kind == "usd":
        return f"${value:.4f}" if value < 0.1 else f"${value:.3f}"
    if kind == "ms":
        return f"{value:.3f} ms" if value < 1.0 else f"{value:.1f} ms"
    if kind == "tokens":
        if value >= 1000:
            return f"{value / 1000:.1f}k"
        return f"{value:.0f}"
    return f"{value:.2f}"


def _y_ticks(max_value: float, ticks: int = 5) -> list[float]:
    if max_value <= 0:
        return [0.0]
    step = max_value / ticks
    return [step * i for i in range(ticks + 1)]


def _histogram(values: Iterable[float], bins: int = 20) -> tuple[list[tuple[float, float, int]], int]:
    """Linear-bin histogram. Empty input returns ``([], 0)``.

    Single-pass; safe for non-numeric values (they get coerced to float and
    skipped on conversion error).
    """
    vals: list[float] = []
    for v in values:
        try:
            vals.append(float(v))
        except (TypeError, ValueError):
            continue
    vals.sort()
    if not vals:
        return [], 0
    lo, hi = vals[0], vals[-1]
    if hi == lo:
        return [(lo, lo, len(vals))], len(vals)
    width = (hi - lo) / bins
    buckets = [0] * bins
    for v in vals:
        idx = int((v - lo) / width)
        if idx >= bins:
            idx = bins - 1
        buckets[idx] += 1
    return [
        (lo + i * width, lo + (i + 1) * width, count)
        for i, count in enumerate(buckets)
    ], max(buckets)


def render_latency_p50_p95_p99(report: dict, out_path: Path) -> Path:
    """Headline tail-latency bar chart.

    Pulls ``per_investigation.latency_per_investigation_ms`` and renders
    p50/p95/p99/mean side by side. Used inline on the benchmark page.
    """
    pi = report.get("per_investigation") or {}
    lat = pi.get("latency_per_investigation_ms") or {}
    series = [
        ("p50",  float(lat.get("p50", 0.0)),  _SVG_PALETTE["primary"]),
        ("p95",  float(lat.get("p95", 0.0)),  _SVG_PALETTE["accent"]),
        ("p99",  float(lat.get("p99", 0.0)),  _SVG_PALETTE["warn"]),
        ("mean", float(lat.get("mean", 0.0)), _SVG_PALETTE["label_muted"]),
    ]
    max_value = max(v for _, v, _ in series) or 1.0

    title = "Per-investigation latency (deterministic substrate)"
    lines = _svg_open(_SVG_W, _SVG_H, title=title)
    lines.append(_svg_text(_SVG_W / 2, 28, title, size=16, anchor="middle", weight="bold"))
    lines.append(_svg_text(
        _SVG_W / 2, 48,
        f"model={pi.get('model', '?')} · n={pi.get('incidents', 0)} incidents · "
        "substrate path; wet-eval lands in T5.5",
        size=11, color=_SVG_PALETTE["label_muted"], anchor="middle",
    ))

    pl_left = _SVG_PAD["left"]
    pl_right = _SVG_W - _SVG_PAD["right"]
    pl_top = _SVG_PAD["top"]
    pl_bottom = _SVG_H - _SVG_PAD["bottom"]
    pl_w = pl_right - pl_left
    pl_h = pl_bottom - pl_top

    for tick in _y_ticks(max_value):
        y = pl_bottom - (tick / max_value) * pl_h
        lines.append(_svg_line(pl_left, y, pl_right, y, _SVG_PALETTE["grid"]))
        lines.append(_svg_text(
            pl_left - 8, y + 4, _format_axis(tick, "ms"),
            size=10, color=_SVG_PALETTE["label_muted"], anchor="end",
        ))
    lines.append(_svg_line(pl_left, pl_bottom, pl_right, pl_bottom, _SVG_PALETTE["axis"], 1.5))

    bar_count = len(series)
    gap = pl_w / (bar_count * 2 + 1)
    bar_w = gap * 1.6
    for i, (label, value, color) in enumerate(series):
        x = pl_left + gap + i * (bar_w + gap)
        bar_h = (value / max_value) * pl_h
        y = pl_bottom - bar_h
        lines.append(_svg_rect(x, y, bar_w, bar_h, color))
        lines.append(_svg_text(
            x + bar_w / 2, pl_bottom + 18, label,
            size=12, anchor="middle",
        ))
        lines.append(_svg_text(
            x + bar_w / 2, y - 8, _format_axis(value, "ms"),
            size=11, color=_SVG_PALETTE["label"], anchor="middle", weight="bold",
        ))

    lines.append("</svg>")
    out_path.write_text("\n".join(lines))
    return out_path


def _render_histogram(
    report: dict,
    *,
    extractor: Callable[[dict], list[float]],
    title: str,
    subtitle: str,
    axis_kind: str,
    bar_color: str,
    median_value: float,
    p95_value: float,
    out_path: Path,
    bins: int = 20,
) -> Path:
    values = list(extractor(report))
    hist, peak = _histogram(values, bins=bins)
    if not hist:
        peak = 1
        hist = [(0.0, 0.0, 0)]

    lines = _svg_open(_SVG_W, _SVG_H, title=title)
    lines.append(_svg_text(_SVG_W / 2, 28, title, size=16, anchor="middle", weight="bold"))
    lines.append(_svg_text(
        _SVG_W / 2, 48, subtitle,
        size=11, color=_SVG_PALETTE["label_muted"], anchor="middle",
    ))

    pl_left = _SVG_PAD["left"]
    pl_right = _SVG_W - _SVG_PAD["right"]
    pl_top = _SVG_PAD["top"]
    pl_bottom = _SVG_H - _SVG_PAD["bottom"]
    pl_w = pl_right - pl_left
    pl_h = pl_bottom - pl_top

    for tick in _y_ticks(peak, ticks=4):
        y = pl_bottom - (tick / peak) * pl_h
        lines.append(_svg_line(pl_left, y, pl_right, y, _SVG_PALETTE["grid"]))
        lines.append(_svg_text(
            pl_left - 8, y + 4, f"{tick:.0f}",
            size=10, color=_SVG_PALETTE["label_muted"], anchor="end",
        ))
    lines.append(_svg_line(pl_left, pl_bottom, pl_right, pl_bottom, _SVG_PALETTE["axis"], 1.5))

    bar_w = pl_w / max(len(hist), 1)
    for i, (lo, _, count) in enumerate(hist):
        bar_h = (count / peak) * pl_h
        x = pl_left + i * bar_w
        y = pl_bottom - bar_h
        lines.append(_svg_rect(x + 1, y, bar_w - 2, bar_h, bar_color))
        if i == 0 or i == len(hist) - 1 or i == len(hist) // 2:
            lines.append(_svg_text(
                x + bar_w / 2, pl_bottom + 18, _format_axis(lo, axis_kind),
                size=10, color=_SVG_PALETTE["label_muted"], anchor="middle",
            ))

    lo, hi = hist[0][0], hist[-1][1]
    span = hi - lo if hi > lo else 1.0
    for value, label, color in [
        (median_value, "median", _SVG_PALETTE["primary"]),
        (p95_value, "p95", _SVG_PALETTE["danger"]),
    ]:
        if value is None:
            continue
        x = pl_left + ((value - lo) / span) * pl_w
        x = max(pl_left, min(pl_right, x))
        lines.append(_svg_line(x, pl_top, x, pl_bottom, color, 1.5))
        lines.append(_svg_text(
            x + 6, pl_top + 14, f"{label} = {_format_axis(value, axis_kind)}",
            size=10, color=color, weight="bold",
        ))

    lines.append("</svg>")
    out_path.write_text("\n".join(lines))
    return out_path


def _records_or_synthesised(report: dict, *, key: str, agg_path: tuple[str, ...]) -> list[float]:
    """Return per-incident ``key`` values, or a synthesised fallback array.

    The fallback exists for reports built with ``--no-telemetry-records``:
    histograms still render a recognisable shape from the aggregate stats
    instead of an empty axis. Anchored at median/mean/p95 so the chart
    visually reflects the same headline numbers shown in the markdown
    tables.
    """
    pi = report.get("per_investigation") or {}
    records = pi.get("incident_records") or []
    if records:
        return [float(r.get(key, 0)) for r in records]
    cursor: Any = pi.get("aggregate", {})
    for step in agg_path:
        cursor = (cursor or {}).get(step, {})
    if not cursor:
        return []
    median = float(cursor.get("median", 0))
    mean = float(cursor.get("mean", median))
    p95 = float(cursor.get("p95", mean))
    return [median, mean, p95, p95, p95, mean, median, median]


def render_tokens_distribution(report: dict, out_path: Path) -> Path:
    pi = report.get("per_investigation") or {}
    tok_block = pi.get("tokens_per_investigation", {})

    return _render_histogram(
        report,
        extractor=lambda rep: _records_or_synthesised(
            rep, key="total_tokens", agg_path=("tokens", "total"),
        ),
        title="Tokens per investigation (deterministic substrate)",
        subtitle=(
            f"prompt + completion · estimator = 4 chars/token · "
            f"system-prompt budget = {pi.get('system_prompt_tokens', 0)} tokens"
        ),
        axis_kind="tokens",
        bar_color=_SVG_PALETTE["primary"],
        median_value=float(tok_block.get("median", 0)),
        p95_value=float(tok_block.get("p95", 0)),
        out_path=out_path,
    )


def render_usd_distribution(report: dict, out_path: Path) -> Path:
    pi = report.get("per_investigation") or {}
    usd_block = pi.get("usd_per_investigation", {})
    rate = pi.get("rate_card_per_m_tokens_usd", {})
    rate_label = (
        f"input ${rate.get('input', 0):.2f}/M, output ${rate.get('output', 0):.2f}/M"
        if rate else "rate card per M tokens"
    )

    return _render_histogram(
        report,
        extractor=lambda rep: _records_or_synthesised(
            rep, key="usd", agg_path=("usd",),
        ),
        title=f"USD per investigation · model={pi.get('model', '?')} (illustrative)",
        subtitle=f"{rate_label} · public 2025-era list pricing — substitute your own",
        axis_kind="usd",
        bar_color=_SVG_PALETTE["accent"],
        median_value=float(usd_block.get("median", 0)),
        p95_value=float(usd_block.get("p95", 0)),
        out_path=out_path,
    )


def render_latency_by_template(report: dict, out_path: Path, *, top_n: int = 20) -> Path:
    """Horizontal bar chart of slowest ``top_n`` templates by p95 latency."""
    pi = report.get("per_investigation") or {}
    per_tpl = list(pi.get("per_template") or [])
    per_tpl.sort(key=lambda t: t.get("latency_ms", {}).get("p95", 0.0), reverse=True)
    per_tpl = per_tpl[:top_n]

    height = max(_SVG_H, 80 + 22 * len(per_tpl))
    title = f"Latency p95 by template (top {len(per_tpl)} of {pi.get('templates', 0)})"
    lines = _svg_open(_SVG_W, height, title=title)
    lines.append(_svg_text(_SVG_W / 2, 28, title, size=16, anchor="middle", weight="bold"))
    lines.append(_svg_text(
        _SVG_W / 2, 48,
        "deterministic substrate path; wet-eval (T5.5) replaces these with real-LLM wall-clock",
        size=11, color=_SVG_PALETTE["label_muted"], anchor="middle",
    ))

    pl_left = 240
    pl_right = _SVG_W - _SVG_PAD["right"]
    pl_top = _SVG_PAD["top"]
    pl_bottom = height - _SVG_PAD["bottom"] / 2
    pl_w = pl_right - pl_left

    if not per_tpl:
        lines.append(_svg_text(
            _SVG_W / 2, height / 2, "no per-template data in report",
            size=12, color=_SVG_PALETTE["label_muted"], anchor="middle",
        ))
        lines.append("</svg>")
        out_path.write_text("\n".join(lines))
        return out_path

    max_p95 = max(t["latency_ms"]["p95"] for t in per_tpl) or 1.0
    row_h = (pl_bottom - pl_top) / len(per_tpl)
    for i, tpl in enumerate(per_tpl):
        p95 = float(tpl["latency_ms"]["p95"])
        p50 = float(tpl["latency_ms"].get("p50", 0.0))
        bar_w_p95 = (p95 / max_p95) * pl_w
        bar_w_p50 = (p50 / max_p95) * pl_w
        y = pl_top + i * row_h + 4
        lines.append(_svg_text(
            pl_left - 12, y + row_h / 2 + 4, str(tpl["template_id"])[:38],
            size=11, color=_SVG_PALETTE["label"], anchor="end",
        ))
        lines.append(_svg_rect(pl_left, y, bar_w_p95, row_h - 8, _SVG_PALETTE["accent"], opacity=0.35))
        lines.append(_svg_rect(pl_left, y, bar_w_p50, row_h - 8, _SVG_PALETTE["primary"], opacity=0.85))
        lines.append(_svg_text(
            pl_left + bar_w_p95 + 6, y + row_h / 2 + 4,
            f"p95={_format_axis(p95, 'ms')}  p50={_format_axis(p50, 'ms')}  n={tpl.get('incidents', 0)}",
            size=10, color=_SVG_PALETTE["label_muted"],
        ))

    lx = pl_left
    ly = height - _SVG_PAD["bottom"] / 2 + 12
    lines.append(_svg_rect(lx, ly, 14, 10, _SVG_PALETTE["primary"], opacity=0.85))
    lines.append(_svg_text(lx + 20, ly + 9, "p50", size=10, color=_SVG_PALETTE["label_muted"]))
    lines.append(_svg_rect(lx + 70, ly, 14, 10, _SVG_PALETTE["accent"], opacity=0.35))
    lines.append(_svg_text(lx + 90, ly + 9, "p95", size=10, color=_SVG_PALETTE["label_muted"]))

    lines.append("</svg>")
    out_path.write_text("\n".join(lines))
    return out_path


def render_all_svgs(report: dict, out_dir: Path) -> list[Path]:
    """Render the four T2.4 charts. Returns the list of written paths."""
    out_dir.mkdir(parents=True, exist_ok=True)
    return [
        render_latency_p50_p95_p99(report, out_dir / "latency-p50-p95-p99.svg"),
        render_tokens_distribution(report, out_dir / "tokens-distribution.svg"),
        render_usd_distribution(report, out_dir / "usd-distribution.svg"),
        render_latency_by_template(report, out_dir / "latency-by-template.svg"),
    ]


# ---------------------------------------------------------------------------
# Report loader — falls back to on-the-fly telemetry if no JSON is on disk.
# ---------------------------------------------------------------------------
def _load_report_or_compute(path: Path) -> dict[str, Any]:
    if path.is_file():
        return json.loads(path.read_text())
    print(
        f"[render_eval_charts] {path} not found; "
        "computing per-investigation block on the fly from the dataset.",
        file=sys.stderr,
    )
    pi = compute_per_investigation_telemetry(
        DEFAULT_INCIDENTS_PATH,
        model=DEFAULT_MODEL,
        keep_records=True,
    )
    block = pi.to_dict(include_records=True)
    total = block["aggregate"]["tokens"]["total"]
    usd = block["aggregate"]["usd"]
    latency = block["aggregate"]["latency_ms"]
    block["tokens_per_investigation"] = {
        "mean": total["mean"], "median": total["median"],
        "p95": total["p95"],   "p99": total["p99"],
        "prompt_mean": block["aggregate"]["tokens"]["prompt"]["mean"],
        "completion_mean": block["aggregate"]["tokens"]["completion"]["mean"],
    }
    block["usd_per_investigation"] = {
        "mean": usd["mean"], "median": usd["median"],
        "p95": usd["p95"],   "p99": usd["p99"],
    }
    block["latency_per_investigation_ms"] = {
        "p50": latency["p50"], "p95": latency["p95"],
        "p99": latency["p99"], "mean": latency["mean"],
    }
    return {"per_investigation": block}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Render the AiSOC eval JSON report into shareable markdown + SVG charts.",
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
        help=f"Directory to write markdown artefacts into (default: {_DEFAULT_OUT}).",
    )
    parser.add_argument(
        "--svg-out",
        type=Path,
        default=_DEFAULT_SVG_OUT,
        help=f"Directory to write SVG charts into (default: {_DEFAULT_SVG_OUT}).",
    )
    parser.add_argument(
        "--no-markdown",
        action="store_true",
        help="Skip the markdown bundle (summary.md / wet_eval.md / provenance.md).",
    )
    parser.add_argument(
        "--no-svg",
        action="store_true",
        help="Skip the SVG charts.",
    )
    args = parser.parse_args()

    report = _load_report_or_compute(args.report)

    if not args.no_markdown:
        if not args.report.is_file():
            print(
                f"[render_eval_charts] {args.report} not found; markdown bundle "
                "needs the substrate-suite report — pass --no-markdown to skip.",
                file=sys.stderr,
            )
            raise SystemExit(
                f"eval report not found at {args.report}. Run "
                f"'python3 scripts/run_evals.py --out {args.report}' first, "
                "or pass --no-markdown."
            )
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

    if not args.no_svg:
        written = render_all_svgs(report, args.svg_out)
        try:
            rel_svg = args.svg_out.relative_to(_REPO_ROOT)
        except ValueError:
            rel_svg = args.svg_out
        names = ", ".join(p.name for p in written)
        print(f"render_eval_charts: wrote {names} to {rel_svg}/")


if __name__ == "__main__":
    main()
