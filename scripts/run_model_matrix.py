#!/usr/bin/env python3
"""Grade the same corpus across several models and publish the comparison.

Phase 4's last open item. The wet eval runs one model — whichever the pins
resolve to — so the published numbers describe the agent *on that model*
and say nothing about whether the result is a property of the agent or of
the backend. Those are different claims, and only one of them is about
this project.

A matrix answers it: same corpus, same prompts, same grader, one variable.
If accuracy collapses on a cheaper model, that is a fact a reader deciding
what to self-host needs, and it is a fact no single-model run can produce.

Deliberately a wrapper, not a second evaluator. It sets the model pin and
invokes `scripts/run_evals.py --wet` per model, then collates the blocks
that script already emits. Reimplementing the eval would create a second
definition of "accuracy" that could drift from the one on the scoreboard —
the exact defect the alert-reduction suite had, where an in-test
reimplementation published a number the product did not produce.

Without a funded key it reports **not measured** and exits zero. It does
not emit zeros: a zero is a measurement, and "we did not run this" is not.

Run:  python3 scripts/run_model_matrix.py --models gpt-4o-mini,gpt-4o
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
RUN_EVALS = REPO_ROOT / "scripts" / "run_evals.py"
RUN_VERDICT_EVAL = REPO_ROOT / "scripts" / "run_verdict_eval.py"

#: Roles the pin override has to cover. Setting only one leaves the other
#: agents on their default model, which would make the matrix a comparison
#: of one role rather than of the system.
PIN_ROLES = ("triage", "investigation", "report", "recon")


def runtime_record() -> dict[str, Any]:
    """The host this matrix ran on, in terms two runs can be compared by.

    Generic by design: OS family, architecture, interpreter and core count
    say whether two matrices ran on comparable machines, and none of them
    identifies the machine. No hostname, no paths — a matrix artifact is a
    publishable file and must not carry anything that only describes one
    contributor's laptop. Latency differences between hosts are disclosed,
    never attributed to the models (same rule as the scorecards).
    """
    return {
        "os": platform.system(),
        "arch": platform.machine(),
        "python": platform.python_version(),
        "cpu_count": os.cpu_count(),
    }


@dataclass
class ModelResult:
    model: str
    measured: bool
    #: Populated only when measured. Absent rather than zeroed, because a
    #: zero accuracy and an unrun model must not render the same.
    metrics: dict[str, Any] = field(default_factory=dict)
    #: What was actually configured for this row: the pins applied, the
    #: endpoint, and — for verdict runs — the provenance status the scorecard
    #: earned. A row without its configuration cannot be reproduced, and two
    #: rows cannot be compared without knowing they were configured alike.
    configuration: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"model": self.model, "measured": self.measured}
        if self.measured:
            out["metrics"] = self.metrics
        if self.configuration:
            out["configuration"] = self.configuration
        if self.error:
            out["error"] = self.error
        return out


def has_live_key() -> bool:
    return bool((os.getenv("WET_EVAL_OPENAI_KEY") or os.getenv("OPENAI_API_KEY") or "").strip())


def run_one(model: str, *, limit: int | None, timeout: int) -> ModelResult:
    """Run the existing wet eval with every model pin set to `model`."""
    env = dict(os.environ)
    for role in PIN_ROLES:
        env[f"AISOC_MODEL_PIN_{role.upper()}"] = model
    # The agent's resolver reads OPENAI_API_KEY; the workflow supplies the
    # key under the wet-eval name.
    if env.get("WET_EVAL_OPENAI_KEY") and not env.get("OPENAI_API_KEY"):
        env["OPENAI_API_KEY"] = env["WET_EVAL_OPENAI_KEY"]

    with tempfile.TemporaryDirectory() as tmp:
        wet_out = Path(tmp) / "wet.json"
        cmd = [
            sys.executable,
            str(RUN_EVALS),
            "--wet",
            "--out",
            str(Path(tmp) / "report.json"),
            "--wet-out",
            str(wet_out),
        ]
        if limit:
            cmd += ["--limit", str(limit)]

        try:
            completed = subprocess.run(
                cmd,
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=REPO_ROOT,
            )
        except subprocess.TimeoutExpired:
            return ModelResult(
                model,
                measured=False,
                error=f"timed out after {timeout}s",
            )

        if completed.returncode != 0:
            # The model's own failure is a result about that model, not a
            # reason to abandon the matrix — a model that cannot complete
            # the corpus is exactly what a reader wants to know.
            tail = (completed.stderr or completed.stdout or "").strip().splitlines()
            return ModelResult(
                model,
                measured=False,
                error=tail[-1][:300] if tail else f"exit {completed.returncode}",
            )

        if not wet_out.exists():
            return ModelResult(model, measured=False, error="no wet block produced")

        block = json.loads(wet_out.read_text(encoding="utf-8"))

    return ModelResult(model, measured=True, metrics=_project(block))


def _project(block: dict[str, Any]) -> dict[str, Any]:
    """The comparable subset. A full wet block is large and most of it is
    identical across models; the point of the matrix is the part that is
    not."""
    latency = block.get("latency_seconds") or {}
    tokens = (block.get("tokens") or {}).get("total") or {}
    usd = block.get("usd") or {}
    return {
        "incidents": block.get("incidents"),
        "mitre_accuracy": block.get("mitre_accuracy"),
        "abstention_rate": block.get("abstention_rate"),
        "mean_groundedness": block.get("mean_groundedness"),
        "latency_p95_s": latency.get("p95"),
        "tokens_mean": tokens.get("mean"),
        "usd_total": usd.get("total"),
        "usd_per_incident": usd.get("mean"),
    }


def run_one_verdict(model: str, *, api_base: str, timeout: int) -> ModelResult:
    """Grade the verdict corpus on `model` through `run_verdict_eval.py`.

    The same thin-wrapper rule as the wet task: this collates a scorecard the
    verdict eval produced and computes nothing of its own. The scorecard's
    own refusals apply unchanged — a run that placed no model call, or whose
    serving identity mismatches the requested model, comes back as that
    row's error rather than as numbers.
    """
    with tempfile.TemporaryDirectory() as tmp:
        card_path = Path(tmp) / "scorecard.json"
        cmd = [
            sys.executable,
            str(RUN_VERDICT_EVAL),
            "--model",
            model,
            "--api-base",
            api_base,
            "--out",
            str(card_path),
        ]
        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=REPO_ROOT,
                env={**os.environ, "PYTHONPATH": str(REPO_ROOT / "services" / "agents")},
            )
        except subprocess.TimeoutExpired:
            return ModelResult(model, measured=False, error=f"timed out after {timeout}s")

        if not card_path.exists():
            tail = (completed.stderr or completed.stdout or "").strip().splitlines()
            return ModelResult(model, measured=False, error=tail[-1][:300] if tail else f"exit {completed.returncode}")

        card = json.loads(card_path.read_text(encoding="utf-8"))

    configuration = {
        "requested_model": model,
        "api_base": api_base,
        "pins": [f"AISOC_MODEL_PIN_{role.upper()}" for role in ("triage", "investigation", "report", "recon", "summary", "copilot")],
        "prompt": card.get("prompt"),
        "sampling": card.get("sampling"),
        "corpus_digest": card.get("corpus_digest"),
        "provenance_status": card.get("provenance_status"),
        "resolved_models": card.get("resolved_models"),
        "model_knowledge": card.get("model_knowledge"),
    }

    if completed.returncode != 0:
        # The scorecard exists and the eval still refused the run — a
        # serving mismatch, most likely. The card is kept as the row's
        # configuration evidence; the row is not published as measured.
        return ModelResult(
            model,
            measured=False,
            configuration=configuration,
            error=f"refused by run_verdict_eval (provenance: {card.get('provenance_status')})",
        )

    return ModelResult(
        model,
        measured=True,
        configuration=configuration,
        metrics={
            "balanced_accuracy": card.get("balanced_accuracy"),
            "matthews_corrcoef": card.get("matthews_corrcoef"),
            "malicious_recall": card.get("malicious_recall"),
            "malicious_support": card.get("malicious_support"),
            "abstention_rate": card.get("abstention_rate"),
            "hallucination_rate": card.get("hallucination_rate"),
            "auto_close_precision": card.get("auto_close_precision"),
            "auto_close_considered": card.get("auto_close_considered"),
            "majority_class_accuracy": card.get("majority_class_accuracy"),
            "llm_calls_placed": card.get("llm_calls_placed"),
            "time_to_verdict_p95_ms": card.get("time_to_verdict_p95_ms"),
            "total_tokens": card.get("total_tokens"),
        },
    )


def render_verdict_markdown(results: list[ModelResult]) -> str:
    lines = [
        "| Model | Balanced accuracy | MCC | Malicious recall | Abstention | Auto-close precision | Calls | Attribution |",
        "|-------|-------------------|-----|------------------|------------|----------------------|-------|-------------|",
    ]
    for result in results:
        if not result.measured:
            reason = result.error or "not measured"
            lines.append(f"| `{result.model}` | _not measured — {reason}_ |||||||")
            continue
        m = result.metrics

        def fmt(key: str, spec: str = "{:.3f}", metrics: dict = m) -> str:
            value = metrics.get(key)
            return spec.format(value) if isinstance(value, int | float) else "not measured"

        recall = (
            f"{fmt('malicious_recall')} / {m.get('malicious_support', '?')}" if m.get("malicious_recall") is not None else "not measured"
        )
        close = (
            f"{fmt('auto_close_precision')} over {m.get('auto_close_considered', 0)}"
            if m.get("auto_close_precision") is not None
            else "not measured"
        )
        lines.append(
            f"| `{result.model}` | {fmt('balanced_accuracy')} | {fmt('matthews_corrcoef')} | {recall} "
            f"| {fmt('abstention_rate', '{:.1%}')} | {close} | {m.get('llm_calls_placed', 0)} "
            f"| {result.configuration.get('provenance_status') or 'unattributed'} |"
        )
    lines.append("")
    lines.append(
        "_Baselines: a constant answer scores at most 0.250 balanced accuracy on this four-class corpus; "
        "compare plain accuracy against each row's majority_class_accuracy in the JSON._"
    )
    return "\n".join(lines)


def render_markdown(results: list[ModelResult]) -> str:
    lines = [
        "| Model | Incidents | MITRE accuracy | Abstention | Groundedness | p95 latency | Tokens/inv | $/incident |",
        "|-------|-----------|----------------|------------|--------------|-------------|------------|------------|",
    ]
    for result in results:
        if not result.measured:
            # One cell, spanning the intent: this row was not measured.
            # Filling the columns with dashes reads as zero at a glance.
            reason = result.error or "no live key configured"
            lines.append(f"| `{result.model}` | _not measured — {reason}_ |||||||")
            continue
        m = result.metrics

        # `m` is bound as a default rather than captured: the closure is
        # used inside this iteration, so capturing works today and breaks
        # the moment anyone defers the call.
        def fmt(key: str, spec: str = "{:.3f}", metrics: dict = m) -> str:
            value = metrics.get(key)
            return spec.format(value) if isinstance(value, int | float) else "—"

        lines.append(
            f"| `{result.model}` | {m.get('incidents') or '—'} "
            f"| {fmt('mitre_accuracy', '{:.1%}')} "
            f"| {fmt('abstention_rate', '{:.1%}')} "
            f"| {fmt('mean_groundedness')} "
            f"| {fmt('latency_p95_s', '{:.2f}s')} "
            f"| {fmt('tokens_mean', '{:.0f}')} "
            f"| {fmt('usd_per_incident', '${:.4f}')} |"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--models",
        default=os.getenv("AISOC_MATRIX_MODELS", "gpt-4o-mini,gpt-4o"),
        help="Comma-separated model names to grade.",
    )
    parser.add_argument(
        "--task",
        choices=("wet", "verdict"),
        default="wet",
        help=(
            "which evaluation each model is graded on: 'wet' drives the 200-incident wet eval "
            "(scripts/run_evals.py --wet); 'verdict' drives the balanced verdict corpus "
            "(scripts/run_verdict_eval.py), one task per run because a model qualified on one task "
            "is not qualified on every task."
        ),
    )
    parser.add_argument(
        "--api-base",
        default=os.getenv("OPENAI_BASE_URL") or "",
        help="OpenAI-compatible base URL for --task verdict (a local server works; any non-empty key).",
    )
    parser.add_argument("--out", type=Path, help="Write the JSON result here.")
    parser.add_argument("--markdown-out", type=Path, help="Write the table here.")
    parser.add_argument(
        "--limit",
        type=int,
        help="Grade only the first N incidents. For a smoke run; a limited matrix must not be published as a full one.",
    )
    parser.add_argument("--timeout", type=int, default=3600)
    args = parser.parse_args(argv)

    models = [m.strip() for m in args.models.split(",") if m.strip()]
    if not models:
        print("model-matrix: no models requested", file=sys.stderr)
        return 2

    if args.task == "verdict":
        # The verdict task needs an endpoint, not a hosted key: a locally
        # served model is a first-class subject here, and the per-run
        # scorecard carries the attribution that says who really answered.
        live = bool(args.api_base) or has_live_key()
        reason = "no --api-base and no live key configured"
    else:
        live = has_live_key()
        reason = "no live key configured"
    if not live:
        print(f"model-matrix: {reason} — reporting 'not measured' for every model rather than emitting zeros.")

    if args.task == "verdict":
        results = [
            run_one_verdict(model, api_base=args.api_base, timeout=args.timeout)
            if live
            else ModelResult(model, measured=False, error=reason)
            for model in models
        ]
    else:
        results = [
            run_one(model, limit=args.limit, timeout=args.timeout) if live else ModelResult(model, measured=False, error=reason)
            for model in models
        ]

    payload = {
        "task": args.task,
        "corpus": "verdict_corpus_v1.json" if args.task == "verdict" else "synthetic_incidents.json",
        "limit": args.limit,
        "partial": bool(args.limit),
        "live": live,
        # The host, in comparable-but-unidentifying terms, and the baselines a
        # verdict table is read against: with four classes a constant answer
        # scores 0.250 balanced accuracy, and each measured scorecard carries
        # its own majority_class_accuracy. Neither is a model result and
        # neither may be omitted from a published comparison.
        "runtime": runtime_record(),
        "baselines_note": (
            "Verdict task: a constant answer scores at most 0.250 balanced accuracy on the four-class "
            "corpus; majority_class_accuracy per row is what a reader compares plain accuracy against."
            if args.task == "verdict"
            else None
        ),
        "results": [r.to_dict() for r in results],
    }

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    table = render_verdict_markdown(results) if args.task == "verdict" else render_markdown(results)
    if args.markdown_out:
        args.markdown_out.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_out.write_text(table + "\n", encoding="utf-8")

    print()
    print(table)
    print()
    measured = sum(1 for r in results if r.measured)
    print(f"model-matrix: {measured}/{len(results)} model(s) measured")
    if args.limit:
        print(f"  PARTIAL: limited to {args.limit} incidents — not comparable with a full run and must not be published as one.")
    # Exit zero even with nothing measured: an absent key is a
    # configuration state, not a build failure, and failing here would
    # make every fork's CI red.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
