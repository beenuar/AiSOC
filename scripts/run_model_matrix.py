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
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
RUN_EVALS = REPO_ROOT / "scripts" / "run_evals.py"

#: Roles the pin override has to cover. Setting only one leaves the other
#: agents on their default model, which would make the matrix a comparison
#: of one role rather than of the system.
PIN_ROLES = ("triage", "investigation", "report", "recon")


@dataclass
class ModelResult:
    model: str
    measured: bool
    #: Populated only when measured. Absent rather than zeroed, because a
    #: zero accuracy and an unrun model must not render the same.
    metrics: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"model": self.model, "measured": self.measured}
        if self.measured:
            out["metrics"] = self.metrics
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

    live = has_live_key()
    if not live:
        print("model-matrix: no live LLM key configured — reporting 'not measured' for every model rather than emitting zeros.")

    results = [
        run_one(model, limit=args.limit, timeout=args.timeout)
        if live
        else ModelResult(model, measured=False, error="no live key configured")
        for model in models
    ]

    payload = {
        "corpus": "synthetic_incidents.json",
        "limit": args.limit,
        "partial": bool(args.limit),
        "live": live,
        "results": [r.to_dict() for r in results],
    }

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    table = render_markdown(results)
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
