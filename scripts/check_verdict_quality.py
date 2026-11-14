#!/usr/bin/env python3
"""Depth plan 1.6: publish verdict quality, and refuse to publish a number nobody measured.

The page this writes replaces a section that said verdict accuracy was *not*
measured here. That section was true when it was written and the corpus (item
1.1) is what made it false, so the honest move is to publish the measurement
rather than to delete the caveat.

Everything this script publishes comes out of a committed scorecard file,
which is itself the output of ``scripts/run_verdict_eval.py``. There is no
scoring in this file and there must never be: a second definition of "verdict
accuracy" would drift from the one the eval produces, which is the defect the
alert-reduction suite already shipped once.

What this gate is actually for
------------------------------
A table on a public page is a claim, and the failure mode is not that a
number is wrong — it is that a number is *absent* and renders as ``0.000``,
which a reader cannot distinguish from a model that was graded and scored
zero. That is the single rule this enforces, in both directions:

* a row with no measurement must carry a reason and render as
  ``not measured — <reason>``; a row that tries to publish a bare number
  without a measurement behind it is refused;
* a row claiming a live measurement must show that a model call was actually
  placed, because triage catches a provider error and falls through to a
  deterministic scorer, so a run against a dead endpoint produces a full set
  of confident verdicts and a scorecard that looks entirely normal.

Run:
    python3 scripts/check_verdict_quality.py --check
    python3 scripts/check_verdict_quality.py --write-benchmark
    python3 scripts/check_verdict_quality.py --self-test
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

BEGIN = "<!-- BEGIN:verdict-quality -->"
END = "<!-- END:verdict-quality -->"

#: Default location of the committed scorecard set.
SCORECARD_PATH = Path("docs/evaluation/verdict_scorecard.json")
BENCHMARK_PATH = Path("apps/docs/docs/benchmark.md")

#: Rendered in place of a number whenever a row carries no measurement. The
#: reason is mandatory and appended after it, because "not measured" alone
#: invites the reader to assume the measurement is merely pending.
NOT_MEASURED = "not measured"


class VerdictQualityError(RuntimeError):
    """A scorecard that cannot be published honestly."""


def _fmt(value: object, digits: int = 3) -> str:
    """Render a metric, or an em dash when the run did not produce one.

    A metric legitimately absent from a measured run (no auto-close candidate
    was considered, so there is no auto-close precision) is distinct from a
    row that was never measured at all, and the two must not look alike.
    """
    if value is None:
        return "–"
    if isinstance(value, bool):  # guard: bool is an int subclass
        return str(value)
    if isinstance(value, (int, float)):
        return f"{float(value):.{digits}f}"
    return str(value)


def validate_entry(entry: dict[str, Any]) -> None:
    """Refuse an entry that cannot be rendered without misleading a reader."""
    name = entry.get("model") or "<unnamed>"

    if not entry.get("model"):
        raise VerdictQualityError("a scorecard entry has no model name")

    if entry.get("measured") is False:
        reason = (entry.get("not_measured_reason") or "").strip()
        if not reason:
            raise VerdictQualityError(
                f"{name}: an unmeasured row must say why. Without a reason the row reads as "
                "pending, and a reader cannot tell an unfunded model from a failed one."
            )
        for field in ("balanced_accuracy", "malicious_recall", "headline_accuracy"):
            if entry.get(field) is not None:
                raise VerdictQualityError(
                    f"{name}: carries {field}={entry[field]!r} while declaring measured=false. "
                    "One of the two is wrong, and publishing the number would be the worse guess."
                )
        return

    mode = entry.get("mode")
    if mode not in {"live", "deterministic"}:
        raise VerdictQualityError(f"{name}: mode must be 'live' or 'deterministic', not {mode!r}")

    if mode == "live" and not entry.get("llm_calls_placed"):
        raise VerdictQualityError(
            f"{name}: claims a live measurement with llm_calls_placed={entry.get('llm_calls_placed')!r}. "
            "Triage falls through to a deterministic scorer on a provider error, so a run against a "
            "dead endpoint yields a full set of verdicts and a normal-looking scorecard. That is the "
            "one thing this gate exists to refuse."
        )

    if entry.get("provenance_status") == "serving_mismatch":
        raise VerdictQualityError(
            f"{name}: the scorecard records provenance_status=serving_mismatch — what answered the "
            "calls is not the model this row names. The scorecard is a valid diagnostic; a table row "
            "under the requested model's name is a false attribution, and it is refused."
        )

    if entry.get("balanced_accuracy") is None:
        raise VerdictQualityError(f"{name}: measured row carries no balanced_accuracy")


def _attribution_cell(entry: dict[str, Any]) -> str:
    """How the row's serving identity is known, or that it is not.

    A scorecard recorded before attribution existed carries no
    ``provenance_status`` and renders as **unverified** — the historical fact
    about those runs, never backfilled. A new scorecard carries the status its
    run earned (``verified`` from a gateway header, ``self_reported`` from the
    endpoint's own body, ``unattributed`` when calls were placed and nobody
    named the server). ``serving_mismatch`` never reaches this cell, because
    :func:`validate_entry` refuses the row outright.
    """
    status = entry.get("provenance_status")
    if not status:
        if entry.get("mode") == "deterministic":
            return "no calls"
        return "unverified (recorded before per-decision attribution existed)"
    if status == "no_calls":
        return "no calls"
    return str(status)


def render_table(scorecard: dict[str, Any]) -> str:
    """Render the published block from the committed scorecard."""
    entries: list[dict[str, Any]] = list(scorecard.get("entries") or [])
    if not entries:
        raise VerdictQualityError("the scorecard holds no entries; refusing to publish an empty table")
    for entry in entries:
        validate_entry(entry)

    corpus = scorecard.get("corpus") or {}
    lines: list[str] = [
        BEGIN,
        "",
        f"Corpus: **{corpus.get('items', '?')} items** in "
        f"**{corpus.get('pairs', '?')} twin pairs** "
        f"(`{corpus.get('name', 'verdict_corpus_v1')}`, digest `{corpus.get('digest', '?')}`). "
        "Twins share title, rule, severity, vendor and technique and differ only in the evidence, "
        "so severity alone separates nothing and a constant answer scores at most "
        f"**{_fmt(corpus.get('constant_answer_ceiling'))}**. Hand-authored and synthetic: "
        "no recorded customer telemetry is involved.",
        "",
        "| Model | Mode | Balanced accuracy | MCC | Malicious recall | Abstention | Hallucination rate | Calls placed | Attribution |",
        "|---|---|---|---|---|---|---|---|---|",
    ]

    for entry in entries:
        name = f"`{entry['model']}`"
        if entry.get("measured") is False:
            reason = entry["not_measured_reason"].strip().rstrip(".")
            # One spanning cell, not six copies of the same phrase: a reader
            # scanning the column must not see something that parses as a
            # score. The reason sits where the first number would.
            lines.append(f"| {name} | – | {NOT_MEASURED} — {reason} | – | – | – | – | 0 | – |")
            continue
        lines.append(
            "| {model} | {mode} | {ba} | {mcc} | {recall} | {abst} | {halluc} | {calls} | {attr} |".format(
                model=name,
                mode=entry["mode"],
                ba=_fmt(entry.get("balanced_accuracy")),
                mcc=_fmt(entry.get("matthews_corrcoef")),
                recall=(
                    f"{_fmt(entry.get('malicious_recall'))} / {entry.get('malicious_support', '?')}"
                    if entry.get("malicious_recall") is not None
                    else "–"
                ),
                abst=_fmt(entry.get("abstention_rate")),
                halluc=_fmt(entry.get("hallucination_rate")),
                calls=entry.get("llm_calls_placed") or 0,
                attr=_attribution_cell(entry),
            )
        )

    measured = [e for e in entries if e.get("measured") is not False]
    lines += [
        "",
        f"Malicious recall prints the count behind it: a rate over {measured[0].get('malicious_support', '?')} "
        "cases is a different claim from the same rate over four, and the figure alone cannot say which. "
        "Every measured row placed the model calls shown in the last column; a row that placed none is "
        "refused rather than published, because triage answers from a deterministic scorer when a "
        "provider fails and the resulting scorecard looks entirely normal."
        if measured
        else "",
        "",
    ]
    if winner := scorecard.get("default_model"):
        lines += [
            f"**Shipped default: `{winner}`.** " + (scorecard.get("default_rationale") or "").strip(),
            "",
        ]
    lines.append(END)
    return "\n".join(line for line in lines if line is not None)


def splice(markdown: str, block: str) -> str:
    """Replace the delimited block, leaving the rest of the page untouched."""
    if BEGIN not in markdown or END not in markdown:
        raise VerdictQualityError(f"{BENCHMARK_PATH} carries no {BEGIN} / {END} block to fill")
    head, _, rest = markdown.partition(BEGIN)
    _, _, tail = rest.partition(END)
    return head + block + tail


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="Fail when the published block is stale or dishonest.")
    parser.add_argument("--write-benchmark", action="store_true", help="Rewrite the block from the scorecard.")
    parser.add_argument("--scorecard", type=Path, default=None)
    parser.add_argument("--benchmark-md", type=Path, default=None)
    args = parser.parse_args(argv)

    root = repo_root()
    scorecard_path = args.scorecard or (root / SCORECARD_PATH)
    benchmark_path = args.benchmark_md or (root / BENCHMARK_PATH)

    if not scorecard_path.exists():
        print(f"verdict-quality: no scorecard at {scorecard_path}", file=sys.stderr)
        return 1

    try:
        scorecard = json.loads(scorecard_path.read_text(encoding="utf-8"))
        block = render_table(scorecard)
    except VerdictQualityError as exc:
        print(f"verdict-quality: REFUSED — {exc}", file=sys.stderr)
        return 1

    markdown = benchmark_path.read_text(encoding="utf-8")
    try:
        updated = splice(markdown, block)
    except VerdictQualityError as exc:
        print(f"verdict-quality: {exc}", file=sys.stderr)
        return 1

    if args.write_benchmark:
        benchmark_path.write_text(updated, encoding="utf-8")
        print(f"verdict-quality: wrote the block into {benchmark_path}")
        return 0

    if args.check:
        if updated != markdown:
            print(
                "verdict-quality: the published block does not match the committed scorecard.\n"
                "  Regenerate it with: python3 scripts/check_verdict_quality.py --write-benchmark",
                file=sys.stderr,
            )
            return 1
        print("verdict-quality: OK — the published table matches the committed scorecard")
        return 0

    print(block)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
