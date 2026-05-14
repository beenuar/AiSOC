#!/usr/bin/env python3
"""
Wet-eval benchmark.md table writer (T5.5).

Read a wet-eval JSON block (produced by ``run_evals.py --wet [--dry-run]
--wet-out path``) and substitute the ``<!-- T2.4 populates -->`` cells
in ``apps/docs/docs/benchmark.md`` with real numbers.

The placeholders were intentionally scaffolded by T5.1 across three
markdown tables — Latency, Tokens, USD — with one row per template
family plus an aggregate row. This script knows that exact shape and
walks the file line-by-line. It is a one-way writer: never reads
existing values, always sources from the JSON. That keeps historical
re-runs reproducible — pass an old report.json from the eval-results
branch and the markdown returns to that snapshot.

Stdlib-only so the workflow can run it without `pip install`.

Usage::

    python scripts/wet_eval_update_benchmark.py \\
        --wet-block path/to/wet-block.json \\
        --benchmark-md apps/docs/docs/benchmark.md
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

# Family ordering must match what's in ``apps/docs/docs/benchmark.md``:
# Aggregate row first, then the five family rows in this exact order.
_FAMILY_ORDER: tuple[tuple[str, str], ...] = (
    ("aggregate",   "Aggregate (all 200)"),
    ("endpoint",    "Endpoint compromise"),
    ("identity",    "Identity / OAuth phish"),
    ("cloud",       "Cloud (AWS / Azure / GCP)"),
    ("network",     "Network / WAF / DNS"),
    ("application", "Application / SaaS"),
)

# Each table is identified by the markdown H3 heading directly above it.
# We anchor on the heading and then rewrite the next 8 non-blank rows
# (1 header + 1 separator + 6 data rows) of the table.
_TABLE_HEADINGS = (
    "Wet eval — Table 1 — Latency per investigation",
    "Wet eval — Table 2 — Tokens per investigation",
    "Wet eval — Table 3 — USD per investigation",
)


def _by_family(block: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Index ``per_template_family`` by family identifier."""
    return {row["family"]: row for row in block.get("per_template_family", [])}


def _aggregate_latency_row(block: dict[str, Any]) -> str:
    lat = block["latency_seconds"]
    return (
        f"| Aggregate (all 200)        |  {lat['p50']:.2f} |  {lat['p95']:.2f} | "
        f" {lat['p99']:.2f} | 200 |"
    )


def _family_latency_row(label: str, fam: dict[str, Any]) -> str:
    return (
        f"| {label:<26} |  {fam['latency_p50_s']:.2f} |  {fam['latency_p95_s']:.2f} | "
        f" {fam['latency_p99_s']:.2f} | {fam['n']:>3} |"
    )


def _aggregate_tokens_row(block: dict[str, Any]) -> str:
    tot = block["tokens"]["total"]
    return (
        f"| Aggregate (all 200)        | {tot['mean']:>5.0f} | {tot['median']:>6.0f} | "
        f"{tot['p95']:>4.0f} | 200 |"
    )


def _family_tokens_row(label: str, fam: dict[str, Any]) -> str:
    return (
        f"| {label:<26} | {fam['tokens_mean']:>5.0f} | {fam['tokens_median']:>6.0f} | "
        f"{fam['tokens_p95']:>4.0f} | {fam['n']:>3} |"
    )


def _aggregate_usd_row(block: dict[str, Any]) -> str:
    usd = block["usd"]
    return (
        f"| Aggregate (all 200)        | ${usd['mean']:.5f} | ${usd['median']:.5f} | "
        f"${usd['p95']:.5f} | 200 |"
    )


def _family_usd_row(label: str, fam: dict[str, Any]) -> str:
    return (
        f"| {label:<26} | ${fam['usd_mean']:.5f} | ${fam['usd_median']:.5f} | "
        f"${fam['usd_p95']:.5f} | {fam['n']:>3} |"
    )


def _build_rows(
    block: dict[str, Any],
    *,
    kind: str,
) -> list[str]:
    """Build the 6 rows (1 aggregate + 5 family) for a given table kind.

    ``kind`` ∈ {"latency", "tokens", "usd"}.
    """
    by_fam = _by_family(block)
    rows: list[str] = []
    for fam_id, label in _FAMILY_ORDER:
        if fam_id == "aggregate":
            if kind == "latency":
                rows.append(_aggregate_latency_row(block))
            elif kind == "tokens":
                rows.append(_aggregate_tokens_row(block))
            else:
                rows.append(_aggregate_usd_row(block))
            continue
        fam = by_fam.get(fam_id)
        if not fam:
            # Family with zero incidents in this run — emit a clean
            # ``n=0`` row instead of leaving a placeholder behind. The
            # workflow logs flag this so we notice if a family ever
            # disappears from the corpus.
            placeholder = {
                "n": 0,
                "latency_p50_s": 0.0, "latency_p95_s": 0.0, "latency_p99_s": 0.0,
                "tokens_mean": 0, "tokens_median": 0, "tokens_p95": 0,
                "usd_mean": 0.0, "usd_median": 0.0, "usd_p95": 0.0,
            }
            fam = placeholder
        if kind == "latency":
            rows.append(_family_latency_row(label, fam))
        elif kind == "tokens":
            rows.append(_family_tokens_row(label, fam))
        else:
            rows.append(_family_usd_row(label, fam))
    return rows


_HEADINGS_TO_KIND = {
    _TABLE_HEADINGS[0]: ("latency", "| Template family            | p50 (s) | p95 (s) | p99 (s) | n  |"),
    _TABLE_HEADINGS[1]: ("tokens",  "| Template family            | mean | median | p95  | n  |"),
    _TABLE_HEADINGS[2]: ("usd",     "| Template family            | mean ($) | median ($) | p95 ($) | n  |"),
}

# Match a row that starts with a known family label or "Aggregate" so
# we can rewrite exactly the six data rows under each table heading
# without disturbing the surrounding prose.
_ROW_PREFIX = re.compile(
    r"^\|\s*(Aggregate \(all 200\)|"
    r"Endpoint compromise|"
    r"Identity / OAuth phish|"
    r"Cloud \(AWS / Azure / GCP\)|"
    r"Network / WAF / DNS|"
    r"Application / SaaS)\s*\|"
)


def _rewrite(md_text: str, block: dict[str, Any]) -> tuple[str, dict[str, int]]:
    """Walk ``md_text`` line-by-line, rewriting the 3 wet-eval tables.

    Returns ``(new_text, stats)`` where ``stats`` is a dict of
    ``{table_heading: rows_replaced}`` so the caller can verify all
    three tables landed.
    """
    lines = md_text.splitlines()
    out: list[str] = []
    stats: dict[str, int] = {h: 0 for h in _TABLE_HEADINGS}

    i = 0
    while i < len(lines):
        line = lines[i]
        out.append(line)

        stripped = line.strip()
        # Heading lines look like ``### Wet eval — Table 1 — ...``
        for heading, (kind, _expected_header) in _HEADINGS_TO_KIND.items():
            if stripped == f"### {heading}":
                # Walk forward to the table opener (the first ``| ... |``
                # line). Then rewrite up to 6 data rows by matching on
                # ``_ROW_PREFIX``.
                j = i + 1
                while j < len(lines) and not lines[j].lstrip().startswith("|"):
                    out.append(lines[j])
                    j += 1
                # Copy the header + separator rows verbatim — we only
                # ever rewrite the data rows so column widths in the
                # source markdown stay author-controlled.
                if j < len(lines):
                    out.append(lines[j]); j += 1   # header row
                if j < len(lines):
                    out.append(lines[j]); j += 1   # separator row

                rows = _build_rows(block, kind=kind)
                family_idx = 0
                while j < len(lines) and family_idx < len(rows):
                    candidate = lines[j]
                    if _ROW_PREFIX.match(candidate):
                        out.append(rows[family_idx])
                        family_idx += 1
                        stats[heading] += 1
                    elif candidate.strip() == "" or not candidate.lstrip().startswith("|"):
                        # Table over before we filled all 6 rows —
                        # back up so the outer loop can continue
                        # processing this line normally.
                        break
                    else:
                        out.append(candidate)
                    j += 1
                i = j
                break
        else:
            i += 1
            continue
        # We hit a heading; ``i`` already advanced past the table.
        continue

    return "\n".join(out) + ("\n" if md_text.endswith("\n") else ""), stats


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Substitute the wet-eval placeholder cells in benchmark.md "
            "with the numbers from a wet-eval JSON block."
        ),
    )
    parser.add_argument(
        "--wet-block",
        type=Path,
        required=True,
        help="Path to the wet-eval JSON block (run_evals.py --wet-out).",
    )
    parser.add_argument(
        "--benchmark-md",
        type=Path,
        required=True,
        help="Path to apps/docs/docs/benchmark.md.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help=(
            "Exit non-zero if at least one of the three tables doesn't "
            "have all 6 rows replaced. Used by the workflow to catch "
            "drift between the JSON shape and the markdown scaffold."
        ),
    )
    parser.add_argument(
        "--print-summary",
        action="store_true",
        help="Print a small summary of the rewrite to stdout.",
    )
    args = parser.parse_args(argv)

    block = json.loads(args.wet_block.read_text())
    if "wet_eval" in block:
        # Accept either the full ``eval_report.json`` or just the
        # wet-eval block on disk. Run_evals.py --wet-out writes the
        # block directly; --out wraps it in a top-level summary.
        block = block["wet_eval"]

    md_text = args.benchmark_md.read_text()
    new_text, stats = _rewrite(md_text, block)

    if new_text != md_text:
        args.benchmark_md.write_text(new_text)

    if args.print_summary:
        print(f"[wet-eval-md] mode={block.get('mode')} "
              f"model={block.get('model')} incidents={block.get('incidents')}")
        for heading, replaced in stats.items():
            print(f"  {heading}: {replaced} rows replaced")

    if args.check:
        # Each of the three tables should have replaced exactly 6 rows
        # (1 aggregate + 5 families). Anything less means the markdown
        # scaffold drifted away from the wet-eval shape and the next
        # weekly cron will silently miss numbers.
        for heading, replaced in stats.items():
            if replaced != 6:
                print(
                    f"[wet-eval-md] FAIL: '{heading}' had {replaced} rows "
                    f"replaced (expected 6). The benchmark.md scaffold "
                    f"may have drifted; see scripts/wet_eval.py for the "
                    f"expected family list.",
                    file=sys.stderr,
                )
                return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
