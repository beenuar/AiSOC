#!/usr/bin/env python3
"""Measure how often the local model returns usable auto-triage output.

The published figure for the bundled ``llama3.2:3b-instruct-q4_K_M`` was
"7 of 19", with no breakdown — so nobody could say which fix would help, or
prove that one had. This harness produces that number reproducibly and, for
every attempt that failed, records *why*.

It drives the production prompt and the production parser by importing them:
``_SYSTEM_PROMPT``, ``system_rule``, ``_build_alert_context`` and
``_parse_llm_response`` all come from ``auto_triage_agent``. A harness that
restated either would measure whether a copy agrees with itself.

Two things about the method, because they change what the number means:

* Every attempt uses a **different** alert. Production pins
  ``temperature=0.0``, so asking one alert twenty times measures one reply
  twenty times, not a rate.
* The alerts come from the committed synthetic corpus, so the sample is fixed
  and a before/after comparison is of the same work.

Usage::

    python3 scripts/measure_triage_reliability.py --attempts 20
    python3 scripts/measure_triage_reliability.py --json out.json

Exit status is 0 whenever the measurement ran. This reports a number; it does
not gate on one. With no reachable model it prints SKIPPED and exits 0 — a
skip is not a pass, and it says which it did.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
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


def _build_messages(alert: dict[str, Any]) -> list[dict[str, str]]:
    """The exact system and user content production sends."""
    from app.agents.auto_triage_agent import _SYSTEM_PROMPT, _build_alert_context
    from app.models.state import InvestigationState
    from app.prompting.envelope import make_nonce, system_rule

    state = InvestigationState(
        incident_id=uuid4(),
        tenant_id=uuid4(),
        alert_summary=f"{alert['title']} — {alert['description']}",
        raw_alert=alert,
    )
    nonce = make_nonce()
    return [
        {"role": "system", "content": _SYSTEM_PROMPT + "\n\n" + system_rule(nonce)},
        {"role": "user", "content": _build_alert_context(state)},
    ]


def _call_model(
    base_url: str,
    model: str,
    messages: list[dict[str, str]],
    timeout: float,
    json_mode: bool = False,
) -> tuple[str, str]:
    """Return (content, finish_reason). Raises on transport failure."""
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
    return choice.get("message", {}).get("content", ""), choice.get("finish_reason", "")


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

    records: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    truncated = 0
    started = time.monotonic()

    for idx, alert in enumerate(alerts, start=1):
        messages = _build_messages(alert)
        try:
            content, finish = _call_model(args.base_url, args.model, messages, args.timeout, args.json_mode)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            if idx == 1:
                print(f"SKIPPED — no model reachable at {args.base_url}: {exc}")
                print("This is a skip, not a pass: nothing was measured.")
                return 0
            print(f"  attempt {idx}: transport failure after {idx - 1} measured — {exc}", file=sys.stderr)
            break

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
    print(f"  ({usable / measured:.0%})" if measured else "")
    print(f"model                 {args.model}")
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
        Path(args.json_out).write_text(
            json.dumps(
                {
                    "model": args.model,
                    "temperature": TEMPERATURE,
                    "max_tokens": MAX_TOKENS,
                    "json_mode": args.json_mode,
                    "attempts": measured,
                    "usable": usable,
                    "truncated": truncated,
                    "outcomes": dict(counts),
                    "records": records,
                },
                indent=2,
            )
            + "\n"
        )
        print(f"\nwrote {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
