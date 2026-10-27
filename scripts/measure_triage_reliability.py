#!/usr/bin/env python3
"""Measure how often the local model returns usable auto-triage output.

The published figure for the bundled ``llama3.2:3b-instruct-q4_K_M`` was
"7 of 19", with no breakdown — so nobody could say which fix would help, or
prove that one had. This harness produces that number reproducibly and, for
every attempt that failed, records *why*.

It drives the production prompt and the production parser by importing them:
the system text comes from ``prompt_text("triage.system")`` in the versioned
prompt registry, and ``system_rule``, ``_build_alert_context`` and
``_parse_llm_response`` come from the modules production calls them in. A
harness that restated either would measure whether a copy agrees with itself.

That sentence used to name ``_SYSTEM_PROMPT``, an ``auto_triage_agent``
constant removed when production moved to the registry. The import raised
``ImportError`` on the first alert, so **this harness had not executed at all**
and the figures published from it ("44 of 50", "50 of 50") describe a run
nobody could have performed. The only test of this file parsed it with ``ast``
instead of importing it, which is correct for a dependency-light repository
gate and is why nothing noticed; ``services/agents/tests/
test_triage_reliability_harness_runs.py`` is the half that imports it.

Two things about the method, because they change what the number means:

* Every attempt uses a **different** alert. Production pins
  ``temperature=0.0``, so asking one alert twenty times measures one reply
  twenty times, not a rate.
* The alerts come from the committed synthetic corpus, so the sample is fixed
  and a before/after comparison is of the same work.

Every record carries its provenance — code revision, model requested and the
model the endpoint says it answered with, prompt name/version/sha256, corpus
digest, the context configuration the prompt was built under, timestamp, and
the counts of errors and unmeasured attempts. A reliability figure without
them cannot be compared with the next one, because a prompt edit is exactly
the change that moves it.

Usage::

    python3 scripts/measure_triage_reliability.py --attempts 20
    python3 scripts/measure_triage_reliability.py --json out.json

Exit status is 0 whenever the measurement ran. This reports a number; it does
not gate on one. With no reachable model it prints SKIPPED and exits 0 — a
skip is not a pass, and it says which it did, and the JSON it writes in that
case reports the rate as unmeasured rather than as zero.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

REPO_ROOT = Path(__file__).resolve().parent.parent
AGENTS_ROOT = REPO_ROOT / "services" / "agents"
sys.path.insert(0, str(AGENTS_ROOT))

CORPUS = AGENTS_ROOT / "tests" / "eval_data" / "synthetic_incidents.json"

# Production values, read from the call site in auto_triage_agent.run_auto_triage.
# If these drift from production the measurement stops describing production,
# so they are asserted against it in tests/test_triage_reliability_harness.py.
TEMPERATURE = 0.0
MAX_TOKENS = 512

DEFAULT_BASE_URL = "http://localhost:11434"
DEFAULT_MODEL = "llama3.2:3b-instruct-q4_K_M"

# Why an attempt did not yield a usable verdict. Ordered most to least
# specific: the first that matches is recorded.
OUTCOME_USABLE = "usable"
OUTCOME_EMPTY = "empty_response"
OUTCOME_INVALID_JSON = "invalid_json"
OUTCOME_NOT_OBJECT = "not_a_json_object"
OUTCOME_FIELD_TYPE = "field_wrong_type"
OUTCOME_OTHER = "other_error"


def _load_alerts(limit: int) -> list[dict[str, Any]]:
    """Fixed, deterministic alerts drawn from the committed synthetic corpus."""
    raw = json.loads(CORPUS.read_text())
    incidents = raw if isinstance(raw, list) else raw.get("incidents", raw)
    alerts: list[dict[str, Any]] = []
    for inc in incidents[:limit]:
        alerts.append(
            {
                "id": inc.get("id", ""),
                "title": inc.get("title", ""),
                "description": inc.get("description", ""),
                "severity": inc.get("severity", "medium"),
                "mitre_techniques": inc.get("expected_techniques", []),
            }
        )
    return alerts


#: The registered prompt production sends. Named here so the provenance
#: record and the message builder cannot disagree about which one was graded.
PROMPT_NAME = "triage.system"


def _build_state(alert: dict[str, Any]) -> tuple[Any, str]:
    """The production state object and the per-run nonce built over it.

    Returned together because they are one input: ``_build_alert_context``
    fences retrieved runbooks with the nonce and ``system_rule`` states the
    boundary the fence refers to, so a system message and a user message
    built under two different nonces are not the prompt production sends.
    """
    from app.models.state import InvestigationState
    from app.prompting.envelope import make_nonce

    state = InvestigationState(
        incident_id=uuid4(),
        tenant_id=uuid4(),
        alert_summary=f"{alert['title']} — {alert['description']}",
        raw_alert=alert,
    )
    return state, make_nonce()


def _messages_for(state: Any, nonce: str) -> list[dict[str, str]]:
    """The exact system and user content production sends, for one state.

    Mirrors ``run_auto_triage``: the registry's text plus ``system_rule`` for
    the system message, ``_build_alert_context(state, nonce=...)`` for the
    user message. Both halves are imported rather than restated.

    Split from :func:`_build_messages` so the nonce is an argument rather than
    something generated inside. ``make_nonce`` is random per call, so a
    builder that minted its own could hand the fence instruction one nonce and
    the fence markers another — a prompt whose boundary sentence points at
    markers that are not in it. Production passes one nonce to both; so does
    this, provably, because there is only one to pass.
    """
    from app.agents.auto_triage_agent import _build_alert_context
    from app.llm.prompt_registry import prompt_text
    from app.prompting.envelope import system_rule

    return [
        {"role": "system", "content": prompt_text(PROMPT_NAME) + "\n\n" + system_rule(nonce)},
        {"role": "user", "content": _build_alert_context(state, nonce=nonce)},
    ]


def _build_messages(alert: dict[str, Any]) -> list[dict[str, str]]:
    """One alert's prompt, under a fresh per-run nonce as production mints one."""
    return _messages_for(*_build_state(alert))


def _prompt_provenance() -> dict[str, str]:
    """Which prompt produced the number, by the registry's own version and hash.

    Read from the registry rather than hashed here. The lock file
    (`services/agents/app/llm/prompts.lock.json`) pins the same pair and
    `scripts/check_prompt_lock.py` fails when the text moves without a version
    bump, so these two fields are what makes two reliability runs comparable.
    """
    from app.llm.prompt_registry import _shipped

    prompt = _shipped().get(PROMPT_NAME)
    return {"name": prompt.name, "version": prompt.version, "sha256": prompt.sha256}


def _context_configuration() -> dict[str, Any]:
    """What the prompt builder was given, so a reader knows what was *not* in it.

    Every one of these is empty on this path, and that is the measurement's
    scope rather than an omission: the corpus is synthetic and belongs to no
    tenant, so there is no organisation memory, no tenant skill, no retrieved
    runbook, no prior disposition and no directory record to put in front of
    the model. Production carries all five. Recorded explicitly because a
    reliability figure measured without them does not describe a prompt that
    has them, and the only way a reader can know that is if it is written down.
    """
    return {
        "organisation_memory": False,
        "tenant_skill": False,
        "knowledge_base_runbooks": False,
        "recent_dispositions": False,
        "identity_context": False,
        "injection_fence": True,
    }


def _corpus_digest() -> str:
    """SHA-256 of the corpus bytes as committed, so a run names the data it used."""
    import hashlib

    return f"sha256:{hashlib.sha256(CORPUS.read_bytes()).hexdigest()}"


def _code_revision() -> str:
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


def _call_model(
    base_url: str,
    model: str,
    messages: list[dict[str, str]],
    timeout: float,
    json_mode: bool = False,
) -> tuple[str, str, str]:
    """Return (content, finish_reason, resolved_model). Raises on transport failure.

    ``resolved_model`` is what the endpoint says answered, which is not always
    what was asked for: a gateway alias resolves to some provider's model, and
    a figure attributed to the requested name would then name the wrong one.
    """
    payload: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": TEMPERATURE,
        "max_tokens": MAX_TOKENS,
    }
    if json_mode:
        # What the fix under test asks for: the gateway translates this to
        # Ollama's `format: json`, which constrains generation so the grammar
        # errors we measured (an unquoted value, an invalid escape) cannot be
        # emitted in the first place.
        payload["response_format"] = {"type": "json_object"}
    req = urllib.request.Request(  # noqa: S310 — operator-supplied localhost gateway
        f"{base_url.rstrip('/')}/v1/chat/completions",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "Authorization": "Bearer local"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        body = json.loads(resp.read())
    choice = (body.get("choices") or [{}])[0]
    return (
        choice.get("message", {}).get("content", ""),
        choice.get("finish_reason", ""),
        str(body.get("model") or ""),
    )


def _classify(raw_text: str) -> tuple[str, str]:
    """Run the production parser and say what happened. Returns (outcome, detail)."""
    from app.agents.auto_triage_agent import _parse_llm_response

    if not (raw_text or "").strip():
        return OUTCOME_EMPTY, "model returned no content"
    try:
        _parse_llm_response(raw_text)
    except json.JSONDecodeError as exc:
        return OUTCOME_INVALID_JSON, str(exc)
    except AttributeError as exc:
        # `.get` on a list or scalar: valid JSON, wrong shape.
        return OUTCOME_NOT_OBJECT, str(exc)
    except (ValueError, TypeError) as exc:
        # Reached `float(confidence)` or similar with something uncoercible.
        # The verdict and rationale may have been perfectly good.
        return OUTCOME_FIELD_TYPE, str(exc)
    except Exception as exc:  # noqa: BLE001 — anything else still counts as a failure
        return OUTCOME_OTHER, f"{type(exc).__name__}: {exc}"
    return OUTCOME_USABLE, ""


def _write_report(
    path: str | None,
    provenance: dict[str, Any],
    records: list[dict[str, Any]],
    counts: Counter[str],
    truncated: int,
    transport_errors: int,
    resolved_models: set[str],
    *,
    skipped: str | None = None,
) -> None:
    """Write the full per-attempt record, with the rate unmeasured when it is.

    ``usable_rate`` is deliberately a two-state object rather than a float.
    A run that placed no call has no rate, and serialising that as ``0.0``
    publishes "the model failed every time" about a model nobody reached —
    the failure mode this repository has shipped more than once. So an
    unmeasured run carries ``{"measured": false, "reason": ...}`` and there is
    no number for a formatter to pick up by mistake.
    """
    if path is None:
        return
    measured = len(records)
    usable = counts[OUTCOME_USABLE]
    if measured:
        rate: dict[str, Any] = {"measured": True, "value": round(usable / measured, 4), "numerator": usable, "denominator": measured}
    else:
        rate = {"measured": False, "reason": skipped or "no attempt completed"}
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(
        json.dumps(
            {
                "provenance": {**provenance, "models_resolved": sorted(resolved_models)},
                "usable_rate": rate,
                "attempts_requested": measured + transport_errors,
                "attempts_measured": measured,
                "usable": usable,
                "truncated": truncated,
                "transport_errors": transport_errors,
                "abstentions": counts[OUTCOME_EMPTY],
                "outcomes": dict(counts),
                "records": records,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attempts", type=int, default=20, help="Number of distinct alerts to triage (default 20).")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="OpenAI-compatible base URL of the local model.")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Model name to request.")
    parser.add_argument("--timeout", type=float, default=180.0, help="Per-call timeout in seconds.")
    parser.add_argument("--json", dest="json_out", help="Write the full per-attempt record here.")
    parser.add_argument(
        "--json-mode",
        action="store_true",
        help="Request response_format=json_object, constraining generation to valid JSON.",
    )
    args = parser.parse_args(argv)

    alerts = _load_alerts(args.attempts)
    if not alerts:
        print(f"refusing to report a rate over no alerts — {CORPUS} yielded none", file=sys.stderr)
        return 1

    provenance = {
        "code_revision": _code_revision(),
        "measured_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "model_requested": args.model,
        "endpoint": args.base_url,
        "prompt": _prompt_provenance(),
        "corpus": {"path": CORPUS.name, "digest": _corpus_digest(), "is_synthetic": True},
        "context_configuration": _context_configuration(),
        "sampling": {"temperature": TEMPERATURE, "max_tokens": MAX_TOKENS, "json_mode": bool(args.json_mode)},
    }

    records: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    truncated = 0
    transport_errors = 0
    resolved_models: set[str] = set()
    started = time.monotonic()

    for idx, alert in enumerate(alerts, start=1):
        messages = _build_messages(alert)
        try:
            content, finish, resolved = _call_model(args.base_url, args.model, messages, args.timeout, args.json_mode)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            transport_errors += 1
            if idx == 1:
                print(f"SKIPPED — no model reachable at {args.base_url}: {exc}")
                print("This is a skip, not a pass: nothing was measured.")
                _write_report(args.json_out, provenance, records, counts, truncated, transport_errors, resolved_models, skipped=str(exc))
                return 0
            print(f"  attempt {idx}: transport failure after {idx - 1} measured — {exc}", file=sys.stderr)
            break

        if resolved:
            resolved_models.add(resolved)
        outcome, detail = _classify(content)
        counts[outcome] += 1
        if finish == "length":
            truncated += 1
        record = {
            "alert_id": alert["id"],
            "outcome": outcome,
            "detail": detail,
            "finish_reason": finish,
            "response_chars": len(content or ""),
        }
        if outcome != OUTCOME_USABLE:
            # "Expecting value: line 4 column 16" is not diagnosable without the
            # text it indexes into. Production learned this and logs an excerpt
            # on failure; a harness whose whole job is explaining failures has
            # less excuse. Only failures, and only the model's own words about a
            # synthetic alert from the committed corpus.
            record["response"] = (content or "")[:1200]
        records.append(record)
        print(f"  [{idx:>2}/{len(alerts)}] {alert['id']:<14} {outcome}{(' — ' + detail[:70]) if detail else ''}")

    measured = len(records)
    usable = counts[OUTCOME_USABLE]
    elapsed = time.monotonic() - started

    print()
    print(f"usable triage output: {usable} of {measured}", end="")
    print(f"  ({usable / measured:.0%})" if measured else "   (not measured)")
    print(f"model                 {args.model}")
    if resolved_models:
        print(f"endpoint answered as  {', '.join(sorted(resolved_models))}")
    prompt = provenance["prompt"]
    print(f"prompt                {prompt['name']} v{prompt['version']} ({prompt['sha256'][:16]})")
    print(f"code revision         {provenance['code_revision'][:12]}")
    print(f"temperature/max_tokens {TEMPERATURE} / {MAX_TOKENS}  (production values)")
    print(f"structured output     {'response_format=json_object' if args.json_mode else 'not requested'}")
    print(f"alerts                {measured} distinct, from {CORPUS.name}")
    print(f"elapsed               {elapsed:.0f}s")
    if truncated:
        print(f"hit the token ceiling {truncated} time(s) — finish_reason=length")
    if measured - usable:
        print("\nwhy the rest failed:")
        for outcome, n in counts.most_common():
            if outcome != OUTCOME_USABLE:
                print(f"  {n:>3}  {outcome}")

    if args.json_out:
        _write_report(args.json_out, provenance, records, counts, truncated, transport_errors, resolved_models)
        print(f"\nwrote {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
