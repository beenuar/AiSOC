#!/usr/bin/env python3
"""`make replay-eval` — grade AiSOC on your own closed alerts, on your host.

Phase 1.5, the design-partner kit. One command: it reads a window of
closed findings out of your SIEM through the readers in
`services/actions/app/services/alert_history.py`, replays them through
the same triage path a live alert takes, scores the result against what
your analysts actually decided, and writes one signed file.

What this program is *not* is a second implementation of any of that. It
drives `POST /api/v1/evaluations/replay`, which is the same job the
console's **Evaluate on your history** page and the `aisoc replay` CLI
start. A kit with its own reader, its own runner or its own scorer would
measure itself rather than the product, and would stop measuring the
product the first time one of them changed. Everything original here is
about the artefact: what it contains, that it cannot have been altered,
and that running it did not send your estate to anybody.

Egress is decided by what answered, not by what was configured
-------------------------------------------------------------
A preflight that reads a config file and concludes "this deployment uses
a local model" is a claim about an intention. This program instead reads
the models the run actually resolved, out of the score, and refuses to
write a bundle if a hosted model answered and `--hosted` was not passed.

There is a third state and it is the honest one to get right. Calling a
local Ollama directly, rather than through the bundled gateway, places
real model calls that carry no attribution header, so the run knows calls
happened and cannot name the model. That is recorded as `unverified` and
never as `none`: "nothing left your estate" and "I could not tell what
answered" are different facts, and only one of them is a privacy claim.

Nothing is written to your deployment. The replay runs in shadow mode,
and the count of writes it intercepted travels in the bundle so that a
replay that quietly stopped replaying can be told from one whose writes
were suppressed.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
# The bundle builder and the verifier live in the API tree, which is also
# where the vault and the redactor live. Importing one service's `app` is
# fine; importing two is not, because all three name their package `app`.
sys.path.insert(0, str(REPO_ROOT / "services" / "api"))

from app.services.evidence_bundle import (  # noqa: E402
    BundleVerificationError,
    canonical_bytes,
    verify_bundle,
)
from app.services.replay_evaluation.bundle import (  # noqa: E402
    build_replay_bundle,
    replay_bundle_filename,
)

#: Provider prefixes that run on hardware the partner controls. A model id
#: with none of these, and that is not the deterministic tier, is treated
#: as hosted — the safe direction, because a provider this list has not
#: heard of is more likely to be a new hosted one than a new local one.
LOCAL_PROVIDER_PREFIXES = (
    "ollama/",
    "ollama_chat/",
    "vllm/",
    "lm_studio/",
    "llamafile/",
    "text-completion-openai/",
    "huggingface/",
    "local/",
)

#: Not a model. Triage's offline floor, which places no call at all.
DETERMINISTIC = "deterministic"

DEFAULT_POLL_SECONDS = 5.0
DEFAULT_TIMEOUT_SECONDS = 3600.0


class ReplayEvalError(RuntimeError):
    """Something the operator can act on. Printed without a traceback."""


# --------------------------------------------------------------------------
# Talking to the deployment
# --------------------------------------------------------------------------


def _request(method: str, url: str, *, token: str, payload: dict | None = None, timeout: float = 120.0) -> Any:
    # urllib honours `file://`, `ftp://` and friends, so a base URL that
    # arrives from a flag or the environment can turn an HTTP client into a
    # file reader. Refuse anything that is not HTTP(S) before opening it,
    # rather than trusting the caller to have passed a URL at all.
    scheme = urllib.parse.urlsplit(url).scheme.lower()
    if scheme not in ("http", "https"):
        raise ReplayEvalError(
            f"refusing to request {url!r}: --api-url must be http:// or https://, got {scheme or 'no'} scheme. "
            "urllib would otherwise read local files through a file:// URL."
        )

    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(url, data=body, method=method)
    request.add_header("Authorization", f"Bearer {token}")
    if body is not None:
        request.add_header("Content-Type", "application/json")

    try:
        # The scheme is checked against an allow-list at the top of this
        # function, which is the condition the rule exists to ask for. It
        # matches on the call shape and cannot see a guard, so the
        # suppression is scoped to this one line: any *other* urlopen added
        # to this file still fails the scan.
        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - scheme checked above
            raw = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:400]
        raise ReplayEvalError(f"{method} {url} answered HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise ReplayEvalError(
            f"could not reach AiSOC at {url}: {exc.reason}. Is the stack up? `make status` shows what is running."
        ) from exc

    return json.loads(raw) if raw else None


def _start_run(base: str, token: str, args: argparse.Namespace) -> str:
    payload: dict[str, Any] = {"connector_id": args.connector_id, "vendor": args.vendor}
    if args.since:
        payload["window_start"] = args.since
    if args.until:
        payload["window_end"] = args.until
    if args.train_fraction is not None:
        payload["train_fraction"] = args.train_fraction

    started = _request("POST", f"{base}/api/v1/evaluations/replay", token=token, payload=payload)
    run_id = (started or {}).get("id")
    if not run_id:
        raise ReplayEvalError(f"the replay job did not return an id; it answered {started!r}")
    return str(run_id)


def _await_run(base: str, token: str, run_id: str, *, timeout: float, poll: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        state = _request("GET", f"{base}/api/v1/evaluations/replay/{run_id}", token=token) or {}
        status = str(state.get("status") or "")
        if status != last:
            print(f"  {status}", file=sys.stderr)
            last = status
        if status == "completed":
            return state
        if status == "failed":
            raise ReplayEvalError(f"the replay failed: {state.get('error') or 'no reason was recorded'}")
        time.sleep(poll)

    raise ReplayEvalError(
        f"the replay did not finish within {timeout:.0f}s. It is still running: collect it later with "
        f"`--collect {run_id}`, or raise --timeout."
    )


# --------------------------------------------------------------------------
# Egress
# --------------------------------------------------------------------------


def _is_local(model: str) -> bool:
    lowered = model.strip().lower()
    if not lowered or lowered == DETERMINISTIC:
        return True
    return lowered.startswith(LOCAL_PROVIDER_PREFIXES)


def classify_egress(score: dict[str, Any]) -> dict[str, Any]:
    """What left the estate, read from the models that actually answered.

    Three states, because collapsing the third into the first is the
    mistake that would turn a measurement into a false privacy claim.
    """
    models = [str(m) for m in (score.get("models") or [])]
    calls = int(score.get("llm_calls") or 0)
    hosted = sorted({m for m in models if not _is_local(m)})

    if hosted:
        return {
            "egress": "hosted",
            "hosted_models": hosted,
            "models": sorted(set(models)),
            "llm_calls": calls,
            "note": (
                "A hosted model answered, so the alert content triage reasoned over was sent to that provider, "
                "exactly as it is during live triage."
            ),
        }

    if calls > 0 and not models:
        return {
            "egress": "unverified",
            "hosted_models": [],
            "models": [],
            "llm_calls": calls,
            "note": (
                f"{calls} model call(s) were placed and none carried an attribution header, which is what a direct "
                f"call to a local runtime looks like when it does not go through the bundled gateway. This run "
                f"cannot prove which model answered, so it does not claim nothing left your estate. Route through "
                f"the gateway to have the model recorded."
            ),
        }

    if calls == 0:
        return {
            "egress": "none",
            "hosted_models": [],
            "models": sorted(set(models)),
            "llm_calls": 0,
            "note": (
                "No model call was placed at all: every verdict came from the deterministic floor. Nothing left "
                "your estate, and nothing measured a model either."
            ),
        }

    return {
        "egress": "none",
        "hosted_models": [],
        "models": sorted(set(models)),
        "llm_calls": calls,
        "note": "Every model that answered runs on hardware you control.",
    }


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------


def _signing_key() -> str:
    key = os.environ.get("AISOC_REPLAY_SIGNING_KEY") or os.environ.get("SECRET_KEY") or ""
    if not key:
        raise ReplayEvalError(
            "no signing key. Set AISOC_REPLAY_SIGNING_KEY (or SECRET_KEY) to this deployment's secret so the "
            "bundle can be verified here later. Signing with a default would produce a file that verifies for "
            "anyone, which is worse than an unsigned one because it reads as tamper-evident."
        )
    return key


def command_run(args: argparse.Namespace) -> int:
    base = args.api_url.rstrip("/")
    token = args.api_key or os.environ.get("AISOC_API_KEY") or ""
    if not token:
        raise ReplayEvalError("no credential. Pass --api-key or set AISOC_API_KEY. The tenant comes from the key.")
    key = _signing_key()

    if args.collect:
        run_id = args.collect
        print(f"Collecting replay {run_id}", file=sys.stderr)
    else:
        if not args.connector_id:
            raise ReplayEvalError("--connector-id is required. `aisoc connectors list` shows the ones you have saved.")
        print(f"Starting a replay against connector {args.connector_id}", file=sys.stderr)
        run_id = _start_run(base, token, args)

    # Everything past this point can fail on something that has nothing to do
    # with the replay — a credential that expires while a long window is
    # being graded is the ordinary case, not an exotic one. The run is server
    # side and survives, so the id and the command that resumes it are worth
    # more to the operator than the error alone.
    try:
        state = _await_run(base, token, run_id, timeout=args.timeout, poll=args.poll)

        report = _request("GET", f"{base}/api/v1/evaluations/replay/{run_id}/export?format=json", token=token) or {}
        score = dict(report.get("score") or {})
        method = dict(report.get("method") or {})
        if not score:
            raise ReplayEvalError("the completed run carried no score; there is nothing to publish")
    except ReplayEvalError as exc:
        raise ReplayEvalError(
            f'{exc}\n\nThe run itself is server side and was not lost. Collect it with:\n  make replay-eval ARGS="--collect {run_id}"'
        ) from exc

    egress = classify_egress(score)
    if egress["egress"] == "hosted" and not args.hosted:
        raise ReplayEvalError(
            "refusing to write a bundle: a hosted model answered ("
            + ", ".join(egress["hosted_models"])
            + ") and --hosted was not passed. The kit runs air-gapped on a local model by default. If you meant "
            "to use your own hosted key, re-run with --hosted; the bundle will record that the content was sent."
        )

    items = None
    if args.export_items:
        decisions = _request("GET", f"{base}/api/v1/evaluations/replay/{run_id}/decisions", token=token)
        # The route answers a bare array. Accept the enveloped shapes too
        # rather than pinning the one this was written against: a kit that
        # breaks on a route growing an envelope is a kit nobody can upgrade.
        if isinstance(decisions, list):
            items = decisions
        elif isinstance(decisions, dict):
            items = decisions.get("items") or decisions.get("decisions") or []
        else:
            raise ReplayEvalError(f"the decisions route answered {type(decisions).__name__}, which this kit cannot read")
        print(f"  exporting {len(items)} decision row(s), redacted", file=sys.stderr)

    bundle = build_replay_bundle(
        score=score,
        method=method,
        model=egress,
        items=items,
        signing_key=key,
        evaluation_id=run_id,
        tenant_id=str(state.get("tenant_id") or ""),
    )

    out = Path(args.output) if args.output else Path(replay_bundle_filename(run_id))
    out.write_bytes(canonical_bytes(bundle))

    # Every rate prints the count it was computed over. `0.0` beside a bare
    # `graded 0` reads as a broken run; `0.0 over 40 malicious cases, 40
    # abstained` is the same number saying what actually happened, which is
    # that the agent routed every one of them to a human rather than missing
    # them silently. The full report states this at length; a one-screen
    # summary that dropped the denominator would be the surface that
    # disagrees with it.
    graded = score.get("graded")
    recall = score.get("malicious_recall")
    support = score.get("malicious_support") or 0
    abstained = score.get("abstained") or 0
    recall_line = (
        f"{recall:.3f} over {support} malicious case(s)"
        if recall is not None
        else f"not measured — {support} malicious case(s) in the window"
    )
    print(f"\nWrote {out}", file=sys.stderr)
    print(f"  decisions         {score.get('decisions')} ({score.get('labelled')} labelled, {abstained} abstained)", file=sys.stderr)
    print(f"  graded            {graded}", file=sys.stderr)
    print(f"  malicious recall  {recall_line}", file=sys.stderr)
    print(f"  egress            {egress['egress']} — {egress['note']}", file=sys.stderr)
    print(f"  items             {'included, redacted' if items is not None else 'withheld (pass --export-items)'}", file=sys.stderr)
    print(f"\nVerify it with:\n  python3 scripts/run_replay_eval.py verify {out}", file=sys.stderr)
    return 0


def command_verify(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if not path.is_file():
        raise ReplayEvalError(f"no such bundle: {path}")
    key = _signing_key()

    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ReplayEvalError(f"{path} is not valid JSON: {exc}") from exc

    try:
        payload = verify_bundle(bundle, signing_key=key)
    except BundleVerificationError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    scores = payload.get("scores") or {}
    model = payload.get("model") or {}
    print(f"OK: {path} verifies against this deployment's key")
    print(f"  schema            {payload.get('bundle_schema_version')}")
    print(f"  generated         {payload.get('generated_at')}")
    print(f"  graded            {scores.get('graded')}")
    print(f"  malicious recall  {scores.get('malicious_recall') if scores.get('malicious_recall') is not None else 'not measured'}")
    print(f"  egress            {model.get('egress')}")
    print(f"  items             {'included' if 'items' in payload else 'withheld'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="run_replay_eval.py", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command")

    run = sub.add_parser("run", help="read history, replay it, write a signed bundle")
    run.add_argument("--api-url", default=os.environ.get("AISOC_API_URL", "http://localhost:8000"))
    run.add_argument("--api-key", default=None, help="defaults to $AISOC_API_KEY. The tenant comes from the key.")
    run.add_argument("--connector-id", default=os.environ.get("AISOC_REPLAY_CONNECTOR_ID"))
    run.add_argument("--vendor", default=None, help="override the vendor inferred from the connector")
    run.add_argument("--since", default=None, help="ISO-8601. Pin the window, or a second run covers a different one.")
    run.add_argument("--until", default=None, help="ISO-8601")
    run.add_argument("--train-fraction", type=float, default=None)
    run.add_argument("--output", default=None)
    run.add_argument(
        "--export-items",
        action="store_true",
        help="include per-decision rows, redacted. Without it only aggregates travel.",
    )
    run.add_argument(
        "--hosted",
        action="store_true",
        help="permit a hosted model. Without it the run is refused if one answered.",
    )
    run.add_argument("--collect", default=None, help="collect a run started earlier, by id")
    run.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    run.add_argument("--poll", type=float, default=DEFAULT_POLL_SECONDS)
    run.set_defaults(handler=command_run)

    verify = sub.add_parser("verify", help="check a bundle has not been altered")
    verify.add_argument("path")
    verify.set_defaults(handler=command_verify)

    args = parser.parse_args(argv)
    if not getattr(args, "handler", None):
        parser.print_help()
        return 2

    try:
        return int(args.handler(args))
    except ReplayEvalError as exc:
        print(f"\nFAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
