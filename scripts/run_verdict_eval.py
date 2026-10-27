#!/usr/bin/env python3
"""Grade production triage against the balanced verdict corpus.

Depth plan 1.4. The corpus is `services/agents/tests/eval_data/verdict/`
(item 1.1): 72 hand-authored items in 36 twin pairs, where each pair shares
its title, rule, severity, vendor and ATT&CK technique and differs *only* in
the evidence. Severity alone therefore separates nothing, and a constant
answer scores at most 0.500.

What this is, and what it deliberately is not
----------------------------------------------
It is a **corpus loader and an honesty gate** in front of two things that
already exist:

* the decision is produced by :meth:`ReplayRunner.replay_window`, which
  drives the production :meth:`FusedAlertTriageWorker.triage` behind the
  shadow sinks, so nothing is written and no second triage exists;
* the score is produced by :func:`scripts.score_replay_set.grade`, which
  delegates to :func:`aisoc_benchmark.replay.score_replay` and carries the
  `assert_gradeable` refusal.

There is no scoring in this file. A second definition of "verdict accuracy"
would drift from the one on the scoreboard, which is the defect the
alert-reduction suite already shipped once, where an in-test
reimplementation published a figure the product did not produce.

The leak this file exists to prevent
-------------------------------------
Corpus ids end in ``-B`` or ``-M``. The envelope builder puts the finding id
into ``raw_alert["id"]``, which is in the triage prompt, so replaying the
corpus under its own ids would hand the model a one-character answer key and
publish the result as accuracy. Every item is therefore replayed under an
**opaque id** derived by hash, and the true id is restored on the decision
afterwards, where only the grader sees it.

That is not left to care. :func:`assert_no_leak` re-reads the built envelope
and fails the run if any held-out value — the corpus names them in its own
``held_out_from_the_model`` header — is reachable anywhere inside it.

Refusing a run that measured nothing
-------------------------------------
Triage catches a provider error and falls through to its deterministic
scorer. A run against an unreachable gateway therefore produces a full set
of confident-looking verdicts and a report that looks entirely normal. This
refuses to publish one: ``--require-live`` (the default) fails when no
decision placed a model call. ``--deterministic`` runs that path on purpose
and labels the scorecard with it, so the floor can be published as a floor.

Run:

    python3 scripts/run_verdict_eval.py \\
        --model llama3.1:8b-instruct-q4_K_M \\
        --api-base http://127.0.0.1:11435/v1 \\
        --out /tmp/scorecard.json
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import os
import subprocess
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS = REPO_ROOT / "services" / "agents" / "tests" / "eval_data" / "verdict" / "verdict_corpus_v1.json"

sys.path.insert(0, str(REPO_ROOT / "packages" / "aisoc-benchmark"))
sys.path.insert(0, str(REPO_ROOT / "scripts"))
sys.path.insert(0, str(REPO_ROOT / "services" / "agents"))

#: The roles a triage run can reach. Pinned together, because pinning one
#: leaves the rest on their default and the scorecard would name a model
#: that answered some of the calls.
PIN_ROLES = ("triage", "investigation", "report", "recon", "summary", "copilot")

#: Namespace for the opaque alert ids. Fixed, so a given corpus item replays
#: under the same opaque id on every run and two scorecards are comparable
#: row by row.
_OPAQUE_NS = uuid.UUID("6f1d0a1e-9c3b-4f6a-8d2e-7b5c4a3f1e20")


class VerdictEvalError(RuntimeError):
    """The run cannot produce a publishable number."""


def quieten_logs(level: int = logging.WARNING) -> None:
    """Keep per-alert triage logging out of the report on stdout.

    The report is Markdown a caller redirects into a file, and 72 alerts of
    structlog output through the same stream corrupts it. Raised to WARNING
    rather than silenced: a provider error has to stay visible, because it
    is the thing that turns a live run into a deterministic one.
    """
    import structlog

    logging.basicConfig(level=level, stream=sys.stderr, force=True)
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(sys.stderr),
    )


def opaque_alert_id(corpus_id: str) -> str:
    """A stable alert id that encodes nothing about the label.

    ``uuid5`` over a fixed namespace: deterministic, so the same item keeps
    the same id across runs and models, and one-way, so neither the ``-B``
    suffix nor the pair it belongs to survives into the prompt.
    """
    return str(uuid.uuid5(_OPAQUE_NS, corpus_id))


def load_corpus(path: Path) -> dict[str, Any]:
    corpus = json.loads(path.read_text(encoding="utf-8"))
    items = corpus.get("decisions") or []
    if not items:
        raise VerdictEvalError(f"{path} carries no `decisions`")
    return corpus


def corpus_digest(path: Path) -> str:
    """SHA-256 of the corpus bytes, so a published row names the data it used.

    Over the file as committed rather than over a normalised projection of
    it: the claim a reader checks is "this scorecard was produced from this
    file", and any re-serialisation would make that claim uncheckable.
    """
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_finding(item: dict[str, Any], *, closed_at: datetime) -> Any:
    """One corpus item as the finding shape replay already grades.

    Carries exactly the five fields the corpus README permits — ``evidence``,
    ``title``, ``severity``, ``vendor`` and ``rule_id`` — under an opaque id.
    The disposition rides along on the finding because the *grader* reads it
    off the decision; it never enters the envelope.
    """
    from app.replay.findings import HistoricalFinding

    return HistoricalFinding(
        vendor=str(item.get("vendor") or ""),
        finding_id=opaque_alert_id(str(item["id"])),
        title=str(item.get("title") or ""),
        disposition=str(item.get("expected_disposition") or "unlabeled"),
        vendor_disposition="",
        closed_at=closed_at,
        rule_id=item.get("rule_id"),
        severity=item.get("severity"),
        raw=dict(item.get("evidence") or {}),
    )


class CorpusEnvelopeNormalizer:
    """Pass-through, because a corpus item is already the agent's input.

    :mod:`app.replay.normalize` refuses to ship a fallback normalizer, and
    it is right to: replaying a *customer's* vendor rows through a mapping
    production does not use would publish a number about a pipeline nobody
    runs. This is the other case. There is no vendor row here and no mapping
    to perform — the corpus authors ``evidence`` as the facts the agent is
    given, and the README says to pass exactly that.

    So this performs no field mapping at all. It hands the evidence back as
    ``raw_event`` and lets :func:`to_fused_envelope` assemble the message,
    which keeps the envelope construction identical to the replay path. The
    limit that creates is stated in the scorecard rather than hidden here:
    this measures triage's judgement on given evidence, and says nothing
    about any connector's mapping.
    """

    connector_id = "verdict-corpus"

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        return {"raw_event": dict(raw)}


def _walk(node: Any) -> Any:
    """Every scalar reachable in a nested structure, keys included."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield key
            yield from _walk(value)
    elif isinstance(node, (list, tuple)):
        for value in node:
            yield from _walk(value)
    else:
        yield node


def assert_no_leak(envelope: dict[str, Any], item: dict[str, Any], held_out: list[str]) -> None:
    """Fail the run if a held-out value is reachable inside the envelope.

    Checked against the envelope that was actually built, not against the
    code that built it. A reviewer reading the builder can confirm it omits
    the answer today; only re-reading the output catches the field a later
    edit adds back.

    The corpus id is checked too. It is not in the corpus's own hold-out
    list because the list names *fields*, and the id is a leak for a
    different reason: its ``-B``/``-M`` suffix is the label.
    """
    reachable = {str(value) for value in _walk(envelope) if value not in (None, "")}

    if str(item["id"]) in reachable:
        raise VerdictEvalError(
            f"corpus id {item['id']!r} is reachable inside the envelope. Its suffix is the label, "
            "so the model would be able to read the answer off the alert id."
        )

    for field_name in held_out:
        if field_name in ("pair_id", "twin_of"):
            # Values, not names: a pair id is an id and would leak the twin.
            value = item.get(field_name)
            if value and str(value) in reachable:
                raise VerdictEvalError(f"held-out {field_name}={value!r} is reachable inside the envelope")
            continue
        value = item.get(field_name)
        if value in (None, "", [], {}):
            continue
        if isinstance(value, str):
            # Prose. Compare on a distinctive slice rather than exact
            # equality, so a value that was embedded into a longer string
            # is still caught.
            needle = value.strip()[:60].lower()
            haystack = json.dumps(envelope, sort_keys=True, default=str).lower()
            if needle and needle in haystack:
                raise VerdictEvalError(
                    f"held-out field {field_name!r} is reachable inside the envelope. "
                    "It states the analyst's reason, so a run that fed it to the model would measure nothing."
                )
        elif str(value) in reachable:
            raise VerdictEvalError(f"held-out field {field_name!r} is reachable inside the envelope")


async def replay_corpus(
    corpus: dict[str, Any],
    *,
    tenant_id: str,
) -> tuple[list[dict[str, Any]], dict[str, int], int]:
    """Replay every item through production triage and return graded decisions.

    Also returns what the shadow writer intercepted. Those counts are
    evidence rather than a fault: :class:`ShadowTriageWriter` records what
    production *would* have written and performs none of it, so a non-zero
    count is the interception working. Zero would be the surprising reading —
    it would mean triage reached no persistence path at all.
    """
    from app.replay.normalize import to_fused_envelope
    from app.replay.runner import ReplayRunner
    from app.replay.shadow import ContextSnapshot

    items = corpus["decisions"]
    held_out = list(corpus.get("held_out_from_the_model") or [])
    authored = str(corpus.get("authored_at") or "2026-01-01")
    closed_at = datetime.fromisoformat(authored).replace(tzinfo=UTC)

    normalizer = CorpusEnvelopeNormalizer()
    findings = [build_finding(item, closed_at=closed_at) for item in items]

    # The leak check runs on the envelope the runner will build, assembled
    # here through the same function, before a single model call is placed.
    # Failing after a 72-item run would be a worse time to find out.
    for item, finding in zip(items, findings, strict=True):
        envelope = to_fused_envelope(
            finding,
            normalizer.normalize(dict(finding.raw)),
            tenant_id=tenant_id,
            connector_id=normalizer.connector_id,
        )
        assert_no_leak(envelope, item, held_out)

    runner = ReplayRunner(
        normalizer=normalizer,
        tenant_id=tenant_id,
        connector_id=normalizer.connector_id,
    )
    window = await runner.replay_window(
        findings,
        # Empty: a hand-authored corpus has no history, so there are no
        # priors, statements or skills to freeze. An empty frozen context is
        # the honest one — seeding priors here would score the ground truth.
        snapshot=ContextSnapshot(split_at=closed_at),
    )

    decisions: list[dict[str, Any]] = []
    for item, decision in zip(items, window.decisions, strict=True):
        row = decision.as_dict()
        # The true id is restored only now, on the record the grader reads.
        # It was never in the prompt.
        row["finding_id"] = str(item["id"])
        row["corpus_id"] = str(item["id"])
        row["opaque_alert_id"] = opaque_alert_id(str(item["id"]))
        row["pair_id"] = item.get("pair_id")
        row["family"] = item.get("family")
        row["is_synthetic"] = bool(item.get("is_synthetic"))
        decisions.append(row)
    return decisions, dict(window.writes_attempted), window.total_writes


def prompt_provenance() -> dict[str, str]:
    """Which prompt produced the verdicts, by the registry's version and hash.

    A scorecard without it cannot be compared with the next one, and worse,
    cannot be promoted into `services/agents/app/confidence/
    autonomy_performance.json`: eligibility matches a measurement to a run on
    the prompt's version *and* content hash, so a row that does not carry them
    can never authorise anything. Read from the registry rather than hashed
    here, so these are the same pair `prompts.lock.json` pins.
    """
    try:
        from app.llm.prompt_registry import _shipped

        prompt = _shipped().get("triage.system")
    except Exception as exc:  # noqa: BLE001 - a scorecard must still be written
        return {"name": "triage.system", "version": "unknown", "sha256": "unknown", "error": str(exc)}
    return {"name": prompt.name, "version": prompt.version, "sha256": prompt.sha256}


def context_configuration(decisions: list[dict[str, Any]]) -> dict[str, Any]:
    """What the prompts carried besides the alert, so a reader knows the scope.

    The replay freezes an empty context on purpose — a hand-authored corpus
    has no history, and seeding priors would score the ground truth — so every
    one of these is false. Recorded rather than left implicit: a verdict
    accuracy measured with no organisation memory, no tenant skill and no
    runbooks does not describe a deployment that has them, and the only way a
    reader can know that is if the scorecard says so.
    """
    return {
        "organisation_memory": False,
        "tenant_skill": False,
        "knowledge_base_runbooks": False,
        "recent_dispositions": False,
        "identity_context": False,
        "injection_fence": True,
        "frozen_context_snapshot": True,
        "decisions_graded": len(decisions),
    }


def git_commit() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return out.stdout.strip() or "unknown"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--model",
        required=True,
        help=(
            "the model id to pin every role to, exactly as the endpoint at --api-base names it, "
            "e.g. llama3.1:8b-instruct-q4_K_M. A LiteLLM routing prefix such as ollama_chat/ "
            "belongs only in front of a LiteLLM gateway: an OpenAI-compatible server answers 404 "
            "for it, triage swallows that into its deterministic fallback, and the run is refused "
            "for measuring nothing."
        ),
    )
    parser.add_argument("--api-base", default=os.getenv("OPENAI_BASE_URL") or "", help="OpenAI-compatible base URL the model is served at")
    parser.add_argument(
        "--api-key",
        default=os.getenv("OPENAI_API_KEY") or "",
        help="key for that endpoint; local servers accept any non-empty string",
    )
    parser.add_argument("--corpus", type=Path, default=CORPUS)
    parser.add_argument("--out", type=Path, help="write the scorecard JSON here")
    parser.add_argument("--decisions-out", type=Path, help="write the per-item decisions here (stays local by default)")
    parser.add_argument("--tenant-id", default="00000000-0000-0000-0000-0000000000de")
    parser.add_argument(
        "--deterministic",
        action="store_true",
        help="run the offline deterministic path on purpose and label the scorecard as such",
    )
    parser.add_argument(
        "--allow-no-llm",
        action="store_true",
        help="do not refuse a run that placed no model call. Only honest with --deterministic.",
    )
    parser.add_argument("--verbose", action="store_true", help="keep per-alert triage logging on stderr")
    args = parser.parse_args(argv)

    quieten_logs(logging.DEBUG if args.verbose else logging.WARNING)

    if args.model and not args.deterministic:
        for role in PIN_ROLES:
            os.environ[f"AISOC_MODEL_PIN_{role.upper()}"] = args.model
        if args.api_base:
            os.environ["OPENAI_BASE_URL"] = args.api_base
            os.environ["AISOC_LLM_API_BASE"] = args.api_base
        if args.api_key:
            os.environ["OPENAI_API_KEY"] = args.api_key

    corpus = load_corpus(args.corpus)

    try:
        decisions, writes_intercepted, total_intercepted = asyncio.run(replay_corpus(corpus, tenant_id=args.tenant_id))
    except VerdictEvalError as exc:
        print(f"verdict-eval: REFUSED — {exc}", file=sys.stderr)
        return 2

    llm_calls = sum(int(d.get("llm_calls") or 0) for d in decisions)
    answered_by_model = sum(1 for d in decisions if d.get("resolved_models"))
    errored = sum(1 for d in decisions if d.get("error"))

    live = llm_calls > 0
    if not live and not (args.deterministic or args.allow_no_llm):
        print(
            "verdict-eval: REFUSED — not one decision placed a model call, so this run measured the "
            "deterministic fallback and not the model. Triage catches a provider error and falls through "
            "to its offline scorer, which is why the report would otherwise look entirely normal. "
            "Fix the endpoint, or pass --deterministic to publish the floor as a floor.",
            file=sys.stderr,
        )
        return 2

    from score_replay_set import CorpusNotGradeable, grade

    model_label = "deterministic" if args.deterministic else args.model
    try:
        report = grade(
            decisions,
            model=model_label,
            dataset=str(corpus.get("corpus_id") or "aisoc-verdict-v1"),
            commit=git_commit(),
            synthetic=True,
        )
    except CorpusNotGradeable as exc:
        print(f"verdict-eval: REFUSED — {exc}", file=sys.stderr)
        return 2

    score = report["score"]
    scorecard = {
        "model": model_label,
        "api_base": args.api_base if live else None,
        "mode": "deterministic" if args.deterministic else "live",
        "dataset": report["dataset"],
        "corpus_digest": f"sha256:{corpus_digest(args.corpus)}",
        "corpus_items": len(decisions),
        "commit": report["commit"],
        "measured_at": datetime.now(UTC).strftime("%Y-%m-%d"),
        "measured_at_utc": datetime.now(UTC).isoformat(timespec="seconds"),
        "synthetic": True,
        "provenance": report["provenance"],
        # Required before a row may be promoted into
        # `services/agents/app/confidence/autonomy_performance.json`:
        # eligibility matches on the prompt's version and content hash, so a
        # scorecard that does not name them can authorise nothing.
        "prompt": prompt_provenance(),
        "context_configuration": context_configuration(decisions),
        # The three numbers that decide whether the rest is worth reading.
        "llm_calls_placed": llm_calls,
        "decisions_answered_by_model": answered_by_model,
        "decisions_errored": errored,
        "resolved_models": score.get("models") or [],
        # Writes production would have made, every one intercepted. Published
        # because "side-effect free" is a claim, and this is the measurement
        # behind it.
        "writes_intercepted": total_intercepted,
        "writes_intercepted_by_sink": writes_intercepted,
        "limits": [
            # Parenthesised so the three fragments are visibly one element.
            # Bare adjacent literals inside a list are how a missing comma
            # silently merges two entries, which is exactly what the reader
            # of a limits list cannot afford to have happen.
            (
                "Measures triage's judgement on given evidence. The corpus authors each item as the "
                "facts the agent is handed, so no connector mapping is exercised and this says nothing "
                "about any vendor's field mapping."
            ),
            "Every item is hand-authored and synthetic. No recorded customer telemetry is involved.",
            "Latency is reported and never graded: it measures the host this ran on.",
        ],
        "balanced_accuracy": score.get("balanced_accuracy"),
        "matthews_corrcoef": score.get("matthews_corrcoef"),
        "majority_class_accuracy": score.get("majority_class_accuracy"),
        "headline_accuracy": score.get("headline_accuracy"),
        "malicious_support": score.get("malicious_support"),
        "malicious_recall": score.get("malicious_recall"),
        "malicious_recall_wilson": score.get("malicious_recall_wilson"),
        "malicious_precision": score.get("malicious_precision"),
        "false_negatives": score.get("false_negatives"),
        "false_negative_verdicts": score.get("false_negative_verdicts"),
        "abstention_rate": score.get("abstention_rate"),
        "auto_close_precision": score.get("auto_close_precision"),
        "auto_close_considered": score.get("auto_close_considered"),
        "hallucination_rate": score.get("hallucination_rate"),
        "indicators_checked": score.get("indicators_checked"),
        "expected_calibration_error": score.get("expected_calibration_error"),
        "time_to_verdict_p50_ms": score.get("time_to_verdict_p50_ms"),
        "time_to_verdict_p95_ms": score.get("time_to_verdict_p95_ms"),
        "total_tokens": score.get("total_tokens"),
    }

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(scorecard, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.decisions_out:
        args.decisions_out.parent.mkdir(parents=True, exist_ok=True)
        args.decisions_out.write_text(json.dumps(decisions, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(report["report_markdown"])
    print()
    print(f"verdict-eval: model={model_label} mode={scorecard['mode']} llm_calls={llm_calls} errored={errored}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
