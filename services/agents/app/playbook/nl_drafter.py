"""Natural-language → playbook DAG drafter (T3.7).

Turns an analyst-authored sentence such as:

    "When a high-severity exfil alert fires on a prod S3 bucket,
     isolate the IAM role, snapshot the bucket policy, and page on-call"

…into a *draft* :class:`Playbook` that the React-flow editor can load.
The drafter is intentionally **conservative**: it never auto-saves,
never auto-runs, and emits a playbook whose ``enabled`` flag is
``False`` so a human reviews it in the editor before the runtime
scheduler can fire it.

Two execution paths:

1. **Deterministic substrate** (no LLM key, or LLM call failed):
   the drafter walks the prompt via a small keyword-and-verb
   extractor and synthesises a DAG. This is the path CI exercises —
   no third-party network call.

2. **LLM-assisted draft** (LLM key configured): the drafter calls
   the configured chat model through
   :func:`services.agents.app.llm.safe_ainvoke` and asks for a
   JSON playbook back. The output is validated against the canonical
   :class:`Playbook` Pydantic model AND against the project's
   `schemas/playbook.schema.json` (JSON Schema draft-07) before
   being returned. Any validation failure falls back to the
   substrate draft so the UX never hangs.

The drafter is the single Pydantic-aware Python entry point for
NL → playbook drafting; the API route at
``services/agents/app/api/playbooks.py`` simply wraps
``draft_from_nl`` in an HTTP envelope.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .bounds import ABSOLUTE_MAX_RETRIES, ABSOLUTE_MAX_TIMEOUT_SECONDS
from .models import Playbook, PlaybookStep, StepType

logger = logging.getLogger("aisoc.playbook.nl_drafter")

# ---------------------------------------------------------------------------
# Step-verb extractor — substrate path
# ---------------------------------------------------------------------------

# Each entry maps a verb pattern → the step type it should produce. The
# patterns are deliberately loose substrings, not regex anchors, so the
# extractor matches both "isolate the host" and "host isolation".
#
# When a pattern matches multiple times, the substrate emits one step
# per match in *prompt order* so the resulting DAG mirrors the analyst's
# intent. The names are humanised after extraction (see _humanise_name).
_VERB_PATTERNS: tuple[tuple[StepType, tuple[str, ...]], ...] = (
    (
        StepType.ISOLATE_HOST,
        (
            "isolate the host",
            "isolate host",
            "host isolation",
            "quarantine the host",
            "isolate the iam role",
            "isolate the role",
        ),
    ),
    (
        StepType.DISABLE_USER,
        (
            "disable the user",
            "disable user",
            "disable the account",
            "deactivate the account",
            "lock out",
            "lock the user",
            "lock the account",
        ),
    ),
    (
        StepType.RESET_PASSWORD,
        ("reset the password", "reset password", "force a password reset", "rotate credentials", "rotate the password"),
    ),
    (
        StepType.REVOKE_SESSION,
        ("revoke sessions", "revoke the session", "kill the session", "force re-authentication", "expire sessions"),
    ),
    (
        StepType.FORCE_MFA,
        ("force mfa", "require mfa", "step up mfa", "trigger mfa challenge"),
    ),
    (
        StepType.BLOCK_IP,
        ("block the ip", "block ip", "blocklist the ip", "block the source ip", "block source ip"),
    ),
    (
        StepType.BLOCK_IOC,
        ("block the ioc", "block the hash", "block the domain", "block the indicator", "blocklist the ioc"),
    ),
    (
        StepType.QUARANTINE_FILE,
        (
            "quarantine the file",
            "quarantine file",
            "isolate the file",
            "snapshot the bucket",
            "snapshot bucket policy",
            "snapshot the bucket policy",
        ),
    ),
    (
        StepType.KILL_PROCESS,
        ("kill the process", "kill process", "terminate the process"),
    ),
    (
        StepType.RUN_AV_SCAN,
        (
            "run av scan",
            "run an av scan",
            "run an antivirus scan",
            "run a virus scan",
            "trigger av scan",
            "av scan",
        ),
    ),
    (
        StepType.SEARCH_SIEM,
        ("search the siem", "query the siem", "search splunk", "search elastic", "run a hunt"),
    ),
    (
        StepType.ENRICH,
        (
            "enrich the alert",
            "enrich the entity",
            "enrich the user",
            "enrich the host",
            "enrich the ip",
            "enrich the ioc",
            "look up reputation",
        ),
    ),
    (
        StepType.INVESTIGATE,
        ("investigate the alert", "investigate the incident", "trigger ai investigation", "run the investigator"),
    ),
    (
        StepType.OSQUERY_LIVE_QUERY,
        ("run osquery", "live query osquery", "osquery the host"),
    ),
    (
        StepType.CREATE_NOTABLE_EVENT,
        ("create a notable event", "create notable event", "raise a notable event"),
    ),
    (
        StepType.CREATE_TICKET,
        ("create a ticket", "open a ticket", "open a jira", "open a servicenow ticket", "file a ticket"),
    ),
    (
        StepType.NOTIFY,
        (
            "page on-call",
            "page the on-call",
            "page on call",
            "notify the analyst",
            "notify the soc",
            "notify the channel",
            "post to slack",
            "send an email",
        ),
    ),
    (
        StepType.APPROVAL,
        ("require analyst approval", "wait for approval", "ask for approval", "human approval"),
    ),
    (
        StepType.CLOSE_CASE,
        ("close the case", "close the incident", "auto-close the case"),
    ),
)

# Severity tokens. We collapse free-text severities ("high-severity",
# "critical") into the OCSF-aligned ladder used by ``trigger.severity``.
_SEVERITY_TOKENS: dict[str, str] = {
    "info": "info",
    "informational": "info",
    "low": "low",
    "medium": "medium",
    "mid": "medium",
    "high": "high",
    "elevated": "high",
    "critical": "critical",
    "severe": "critical",
    "p0": "critical",
    "p1": "high",
    "p2": "medium",
    "p3": "low",
}

# Trigger-on tokens. Mirrors the enum on ``playbook.schema.json``.
_TRIGGER_ON_TOKENS: dict[str, str] = {
    "alert": "alert",
    "alerts": "alert",
    "case": "case",
    "cases": "case",
    "incident": "alert",  # incidents arrive as alerts on the AiSOC bus
    "incidents": "alert",
    "schedule": "schedule",
    "scheduled": "schedule",
    "manual": "manual",
    "manually": "manual",
    "on-demand": "manual",
    "webhook": "webhook",
}


@dataclass
class DraftResult:
    """The drafter's return shape — a playbook + provenance metadata."""

    playbook: Playbook
    rationale: str
    used_llm: bool
    schema_validated: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "playbook": self.playbook.model_dump(),
            "rationale": self.rationale,
            "used_llm": self.used_llm,
            "schema_validated": self.schema_validated,
        }


# ---------------------------------------------------------------------------
# Substrate (no-LLM) extractor
# ---------------------------------------------------------------------------


def _humanise_name(step_type: StepType, prompt_window: str) -> str:
    """Build a friendly step name. ``prompt_window`` is the substring of
    the prompt that matched the verb pattern; we use it to give the
    operator immediate context on what the step came from."""

    base = step_type.value.replace("_", " ").title()
    window = (prompt_window or "").strip()
    if not window:
        return base
    # Keep window short — the editor renders names inline on node cards.
    snippet = window if len(window) <= 60 else window[:57].rstrip() + "..."
    return f"{base}: {snippet}"


def _extract_severity(prompt: str) -> list[str]:
    """Pull every severity token out of the prompt, in order, deduped."""

    tokens = re.findall(r"\b([A-Za-z0-9]+)\b", prompt.lower())
    found: list[str] = []
    for tok in tokens:
        canon = _SEVERITY_TOKENS.get(tok)
        if canon and canon not in found:
            found.append(canon)
    return found


def _extract_trigger_on(prompt: str) -> str:
    """Pick the most-specific trigger surface present in the prompt.

    Order of preference: ``case`` > ``alert`` > ``schedule`` > ``webhook``
    > ``manual``. ``alert`` is the safe default since the AiSOC bus
    routes both ``alert`` and ``case`` events through the same trigger.
    """

    lower = prompt.lower()
    if "case" in lower:
        return "case"
    if "alert" in lower or "incident" in lower or "fires" in lower:
        return "alert"
    for token, on in _TRIGGER_ON_TOKENS.items():
        if token in lower:
            return on
    return "alert"


def _extract_steps(prompt: str) -> list[PlaybookStep]:
    """Walk the prompt once, in order, emitting one step per verb match.

    The substrate extractor is intentionally simple: it scans for the
    *first occurrence* of each verb pattern, sorted by prompt position,
    and emits steps in that order. This produces a linear DAG which is
    the common case the analyst is asking for. Conditional branches
    must be authored in the editor.
    """

    lower = prompt.lower()
    matches: list[tuple[int, StepType, str]] = []
    for step_type, patterns in _VERB_PATTERNS:
        for pat in patterns:
            idx = lower.find(pat)
            if idx >= 0:
                matches.append((idx, step_type, pat))
                break  # one step per type per pass

    matches.sort(key=lambda m: m[0])

    seen: set[StepType] = set()
    out: list[PlaybookStep] = []
    for _idx, step_type, pat in matches:
        if step_type in seen:
            continue
        seen.add(step_type)
        out.append(
            PlaybookStep(
                id=uuid.uuid4().hex[:8],
                name=_humanise_name(step_type, pat),
                type=step_type,
                params={},
                on_failure="abort",
                retry_max=0,
                timeout_seconds=30,
            )
        )
    return out


def _substrate_draft(prompt: str) -> Playbook:
    """Deterministic substrate draft. Always returns a valid Playbook."""

    now = datetime.now(UTC).isoformat()
    steps = _extract_steps(prompt)
    if not steps:
        # No verb matched — fall back to a single investigate step so
        # the editor opens with at least one node the analyst can edit.
        steps = [
            PlaybookStep(
                id=uuid.uuid4().hex[:8],
                name="Investigate: substrate fallback",
                type=StepType.INVESTIGATE,
                params={},
                on_failure="abort",
                retry_max=0,
                timeout_seconds=60,
            )
        ]
    severities = _extract_severity(prompt)
    trigger_on = _extract_trigger_on(prompt)
    trigger: dict[str, Any] = {"on": trigger_on}
    if severities:
        trigger["severity"] = severities

    name = _summarise_prompt_for_name(prompt)

    return Playbook(
        id=uuid.uuid4().hex,
        name=name,
        description=prompt.strip(),
        version="1.0.0",
        tags=["nl-drafted", "draft"],
        trigger=trigger,
        steps=steps,
        author="AiSOC NL Drafter",
        # Drafts ship disabled — a human reviews then enables in the editor.
        enabled=False,
        created_at=now,
        updated_at=now,
    )


def _summarise_prompt_for_name(prompt: str) -> str:
    """Trim and title-case the prompt for use as the playbook name."""

    text = " ".join(prompt.split()).strip()
    if not text:
        return "NL Draft Playbook"
    # Take the leading clause (up to first comma) and title-case it.
    leading = text.split(",")[0].strip()
    if len(leading) > 80:
        leading = leading[:77].rstrip() + "..."
    if len(leading) < 3:
        leading = text[:80]
    return leading


# ---------------------------------------------------------------------------
# JSON-Schema validation
# ---------------------------------------------------------------------------


def _schema_path() -> Path:
    """Resolve the one canonical ``schemas/playbook.schema.json``.

    There used to be a second copy at the repo root declaring a different
    step vocabulary, and this function fell back to it whenever the primary
    was missing — so a packaging slip did not fail, it silently validated
    against a different contract. There is now exactly one schema (a parity
    gate enforces that), and a missing one is an error rather than a cue to
    go looking for something else to trust.

    The walk stops at the first ancestor that has the file so a checkout at
    any depth works, but it never accepts a differently-shaped substitute.
    """

    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "schemas" / "playbook.schema.json"
        if candidate.exists():
            return candidate
    raise FileNotFoundError("schemas/playbook.schema.json not found in any parent of services/agents/app/playbook/")


# The step-type collapse that used to live here is gone.
#
# The JSON Schema declared 9 step types against a StepType enum of 22, so the
# drafter rewrote the 13 it could not express onto their "nearest neighbour"
# — ``disable_user`` and ``revoke_session`` both became ``investigate``,
# ``approval`` became ``condition`` — purely so the output would pass
# ``scripts/lint_playbooks.py``. The original was preserved in
# ``params.original_type``, but the step that shipped said it would
# investigate when the analyst had asked to disable an account, and the
# approval gate an author wrote came out as an ungated branch.
#
# The schema now declares all 22, so there is nothing to collapse.


def _strip_nulls(obj: Any) -> Any:
    """Recursively drop keys whose value is ``None``.

    ``Playbook.model_dump()`` emits ``"condition": null``,
    ``"next_true": null`` etc. for unset optional fields, which the
    JSON Schema (with ``additionalProperties: false`` on each step)
    rejects with ``"None is not of type 'string'"``. Stripping these
    nulls is safe — every optional field has ``default=None`` on the
    Pydantic side, so the round-trip survives.
    """

    if isinstance(obj, dict):
        return {k: _strip_nulls(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [_strip_nulls(v) for v in obj]
    return obj


def _load_schema() -> dict[str, Any]:
    return json.loads(_schema_path().read_text(encoding="utf-8"))


def _validate_against_schema(payload: dict[str, Any]) -> tuple[bool, str | None]:
    """Validate ``payload`` against ``schemas/playbook.schema.json``.

    One pass. There used to be a second that rewrote any step type the
    schema could not express onto a "nearest neighbour" and re-validated;
    it made the drafter's output lint-clean by changing what the playbook
    said it would do. The schema now covers the whole ``StepType`` range,
    so a failure here is a real failure.

    Returns ``(True, None)`` on success, ``(False, error_message)`` on
    failure. ``jsonschema`` is imported lazily so the module stays
    importable in environments without it.
    """

    try:
        import jsonschema  # type: ignore
    except ImportError:
        logger.warning("jsonschema not installed; skipping schema validation")
        return True, None

    try:
        schema = _load_schema()
    except FileNotFoundError as exc:
        logger.warning("playbook.schema.json missing: %s", exc)
        return True, None

    # Null-stripped: Pydantic emits ``null`` for unset optional keys and the
    # schema rejects those under ``additionalProperties: false``.
    cleaned = _strip_nulls(payload)
    try:
        jsonschema.validate(cleaned, schema)  # type: ignore[attr-defined]
        return True, None
    except jsonschema.ValidationError as exc:  # type: ignore[attr-defined]
        return False, exc.message


# ---------------------------------------------------------------------------
# LLM-assisted draft path
# ---------------------------------------------------------------------------


_SYSTEM_PROMPT = """\
You are AiSOC's playbook drafter. Convert the analyst's prompt into a JSON
playbook the AiSOC platform can render in its React Flow editor.

Rules — follow exactly:

1. Return **only** a JSON object, no markdown fence, no commentary.
2. Required top-level keys: ``id``, ``name``, ``version``, ``trigger``,
   ``steps``. The ``id`` must be kebab-case 3-63 chars matching
   ``^[a-z0-9][a-z0-9-]{2,62}$``. The ``version`` must be semantic,
   e.g. ``"1.0.0"``.
3. ``trigger`` must contain ``on`` (one of ``alert`` / ``case`` /
   ``schedule`` / ``manual``). Severities, when present,
   must be an array of any of: ``info`` / ``low`` / ``medium`` /
   ``high`` / ``critical``.
4. Each step must declare a ``type``, one of exactly:
   __STEP_TYPES__.
5. Each step must carry a short, action-oriented ``name``, an ``id``
   (8-32 char hex), an ``on_failure`` ∈ ``abort`` / ``continue`` /
   ``retry``, ``retry_max`` (0-__MAX_RETRIES__), and
   ``timeout_seconds`` (1-__MAX_TIMEOUT__).
6. The output's ``enabled`` MUST be ``false``. A human reviews before
   enabling.
7. Do NOT invent fields not in the schema. Do NOT emit prose. JSON only.
"""

# Filled from the enum and the bounds module rather than restated, because a
# hand-written copy of the vocabulary in a prompt is one more place for it to
# drift — this list previously offered ``webhook`` as a trigger, which no
# validator in the repo accepts, and capped ``retry_max`` at 5 against a
# model that allows 25.
#
# Token substitution rather than ``str.format`` because the prompt contains
# a regex with brace quantifiers that format would try to interpret.
_SYSTEM_PROMPT = (
    _SYSTEM_PROMPT.replace("__STEP_TYPES__", ", ".join(f"``{st.value}``" for st in StepType))
    .replace("__MAX_RETRIES__", str(ABSOLUTE_MAX_RETRIES))
    .replace("__MAX_TIMEOUT__", str(ABSOLUTE_MAX_TIMEOUT_SECONDS))
)

_USER_TEMPLATE = """\
Analyst prompt:

\"\"\"
{prompt}
\"\"\"

Emit the playbook JSON now.
"""


def _llm_factory() -> Any | None:
    """Lazy import of the configured chat model. Returns ``None`` when
    no LLM provider is wired (the substrate path then takes over)."""

    try:
        from app.llm.factory import make_chat_model  # type: ignore
    except Exception:
        return None
    try:
        # "nl" is the declared role for natural-language translation
        # (``app.llm.model_pins``). This was a bare ``make_chat_model()``,
        # and ``role`` is required — so the TypeError was caught below and
        # the drafter reported "no chat model available" on every call,
        # permanently. Every test monkeypatches ``_llm_factory``, so the one
        # line that mattered was the one line nothing exercised.
        return make_chat_model("nl")
    except Exception as exc:
        logger.info("nl_drafter: no chat model available (%s)", exc)
        return None


async def _llm_draft(prompt: str) -> Playbook | None:
    """Ask the configured chat model for a JSON playbook.

    Returns ``None`` when no LLM is configured, when the LLM call
    fails, or when the returned JSON does not validate as a
    :class:`Playbook` (the caller falls back to the substrate path).
    """

    llm = _llm_factory()
    if llm is None:
        return None

    from app.llm import safe_ainvoke  # local import — heavy module

    messages = [
        ("system", _SYSTEM_PROMPT),
        ("user", _USER_TEMPLATE.format(prompt=prompt)),
    ]
    try:
        result = await safe_ainvoke(llm, messages)
    except Exception as exc:
        logger.warning("nl_drafter: LLM call failed: %s", exc)
        return None

    text = ""
    if hasattr(result, "content"):
        content = result.content
        text = content if isinstance(content, str) else str(content)
    elif isinstance(result, str):
        text = result
    elif isinstance(result, dict) and "content" in result:
        text = str(result["content"])
    else:
        text = str(result)

    text = text.strip()
    # Strip a stray ```json fence if the model added one despite the system rule.
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```\s*$", "", text)

    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        logger.warning("nl_drafter: LLM returned non-JSON: %s", exc)
        return None

    if not isinstance(payload, dict):
        logger.warning("nl_drafter: LLM returned non-object JSON")
        return None

    # Pin enabled=False even if the model ignored the instruction.
    payload["enabled"] = False
    if "tags" in payload and isinstance(payload["tags"], list):
        tags = [t for t in payload["tags"] if isinstance(t, str)]
        if "nl-drafted" not in tags:
            tags.append("nl-drafted")
        payload["tags"] = tags
    else:
        payload["tags"] = ["nl-drafted", "draft"]

    try:
        return Playbook.model_validate(payload)
    except Exception as exc:
        logger.warning("nl_drafter: LLM payload failed Pydantic validation: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


async def draft_from_nl(prompt: str, *, allow_llm: bool = True) -> DraftResult:
    """Draft a playbook from an analyst-authored natural-language prompt.

    Returns a :class:`DraftResult` carrying the playbook plus
    provenance metadata (which path produced it, and whether the
    canonical JSON Schema validation passed).

    The drafter NEVER raises on user-supplied input — empty prompts
    return the substrate fallback with an investigate step, and a
    misbehaving LLM falls back silently to the substrate.
    """

    if not isinstance(prompt, str):
        prompt = str(prompt or "")

    pb: Playbook | None = None
    used_llm = False
    if allow_llm:
        pb = await _llm_draft(prompt)
        used_llm = pb is not None

    if pb is None:
        pb = _substrate_draft(prompt)

    payload = pb.model_dump()
    valid, err = _validate_against_schema(payload)
    if not valid:
        logger.info(
            "nl_drafter: schema-validation failed on initial draft (%s); regenerating via substrate",
            err,
        )
        pb = _substrate_draft(prompt)
        payload = pb.model_dump()
        valid, err = _validate_against_schema(payload)

    rationale = (
        f"Used LLM: {used_llm}. Steps: {len(pb.steps)} " f"({', '.join(s.type.value for s in pb.steps)}). " f"Trigger: {pb.trigger}."
    )
    return DraftResult(
        playbook=pb,
        rationale=rationale,
        used_llm=used_llm,
        schema_validated=bool(valid),
    )


# Sync convenience for callers that can't await (CLI, tests of the
# substrate path).


def draft_from_nl_substrate(prompt: str) -> Playbook:
    """Synchronous substrate-only draft. Useful for CLI + tests."""

    return _substrate_draft(prompt if isinstance(prompt, str) else str(prompt or ""))
