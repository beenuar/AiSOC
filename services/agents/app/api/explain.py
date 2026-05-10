"""
Explain endpoint — turns an alert into a grounded, human-readable answer to
"why did this fire and what should I do?".

Endpoint
--------

    POST /api/v1/explain          — NDJSON stream

Why this exists separately from ``copilot.py``
----------------------------------------------

Copilot is freeform chat. Explain is **structured grounding**: every
emitted frame is one of a small set of typed sections (summary, OCSF
mapping, MITRE technique cards pulled from the local corpus, evidence,
next-step recommendations). The frontend renders each frame
deterministically, so the analyst gets the same drawer shape whether the
LLM is enabled, disabled, or running locally — and so the UI can link
directly to attack.mitre.org without trusting the model not to
hallucinate IDs.

Air-gap behaviour
-----------------

- ``AISOC_AIRGAPPED=true``                  → no outbound LLM call, ever
- ``OPENAI_BASE_URL`` set to a non-OpenAI host (LiteLLM, Ollama, vLLM)
                                            → allowed in air-gap mode
- Otherwise                                 → openai.com, gated on the
                                              presence of ``OPENAI_API_KEY``

When the LLM path is skipped, the deterministic synthesizer fills the
``summary`` section from the alert payload itself, so the demo path
never breaks.

Rate limiting
-------------

Every explain request can fan out to one outbound LLM call, so a noisy
client (or a hostile script hammering Explain across every alert in
the grid) would burn token budget and stall every other analyst's
drawer behind queued LLM calls. We use a per-tenant token bucket
(``services/agents/app/core/rate_limit.py``):

* ``AISOC_EXPLAIN_BURST`` — bucket capacity (default 20)
* ``AISOC_EXPLAIN_RPM``   — refill, requests per minute (default 60).
                            Set to ``0`` to disable the limiter
                            entirely (used in tests and demos).

When the bucket is empty we return HTTP 429 with ``Retry-After`` and
the standard ``X-RateLimit-*`` headers, *and* emit a single NDJSON
``error`` frame so an EventSource-style client that has already
started reading still gets a structured failure to render.

BYOK / per-tenant LLM overrides
-------------------------------

Each tenant can override the process-wide LLM configuration by
storing a vault-encrypted row in ``tenant_llm_credentials``
(operator UI: Settings → Deployment & AI). On every request we call
:func:`app.security.llm_resolver.resolve_llm_config` to layer the
tenant overrides — base URL, model, API key — over the env baseline
(``OPENAI_API_KEY`` / ``OPENAI_BASE_URL`` / ``OPENAI_MODEL``) and
re-evaluate the air-gap policy against the *resolved* base URL. A
tenant who BYOKs a private LiteLLM gateway therefore stays allowed
under ``AISOC_AIRGAPPED=true``, exactly the same way the env-only
path does today.

The resolver is failure-tolerant: a missing ``DATABASE_URL``, an
unreachable database, an unconfigured ``AISOC_CREDENTIAL_KEY``, a
corrupt ciphertext, or a tenant row with ``enabled=false`` all
silently degrade to the env baseline. The single source of truth
for *which* config the path actually picked is the
``llm_resolve_*`` log lines emitted on failure paths and the
``X-LLM-Source`` header (``tenant`` | ``environment`` | ``mixed`` |
``none``) we emit on the response so an operator can confirm BYOK
is actually being applied.

NDJSON frame shapes
-------------------

Each line is a single JSON object. Frames are emitted in this order::

    {"kind": "section", "id": "summary",     "title": "What happened"}
    {"kind": "delta",   "section": "summary", "text": "..."}            (×N)
    {"kind": "section", "id": "ocsf",        "title": "OCSF mapping"}
    {"kind": "ocsf",    "category": "...", "category_uid": 3,
                        "class": "...",    "class_uid": 3002,
                        "activity": "...", "fields": {...}}
    {"kind": "section", "id": "mitre",       "title": "MITRE ATT&CK"}
    {"kind": "mitre",   "id": "T1078",       "name": "Valid Accounts",
                        "tactic_names": [...], "url": "...",
                        "description": "..."}                            (×N)
    {"kind": "section", "id": "evidence",    "title": "Key evidence"}
    {"kind": "evidence","label": "...",      "value": "...",
                        "annotation": "..."}                             (×N)
    {"kind": "section", "id": "next",        "title": "Next steps"}
    {"kind": "next_step","title": "...", "rationale": "...",
                         "playbook_id": null}                            (×N)
    {"kind": "done",    "alert_id": "..."}

The first ``error`` frame, if any, is fatal — the client should display
it and stop reading.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from collections.abc import AsyncIterator
from typing import Any

import structlog
from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.core.rate_limit import RateLimitDecision, TokenBucketLimiter
from app.security.llm_resolver import LlmConfig, resolve_llm_config

logger = structlog.get_logger()

router = APIRouter(prefix="/api/v1", tags=["explain"])


# ---------------------------------------------------------------------------
# Rate limiter (per-tenant token bucket)
# ---------------------------------------------------------------------------
#
# Lazy-initialised at first request so the env vars can be patched per-test
# without paying the cost of touching ``time.monotonic`` at import time.
# A value of 0 for ``AISOC_EXPLAIN_RPM`` short-circuits the limiter
# entirely — useful for the deterministic eval harness, where we want to
# stream the same 200 incidents back-to-back without throttling noise.

_DEFAULT_BURST = 20
_DEFAULT_RPM = 60

_explain_limiter: TokenBucketLimiter | None = None


def _get_explain_limiter() -> TokenBucketLimiter | None:
    """Return the process-wide explain limiter, or ``None`` if disabled.

    We re-read the env vars only on first construction; subsequent
    calls return the cached singleton. Tests that need a fresh
    limiter call :func:`_reset_explain_limiter` first.
    """
    global _explain_limiter
    if _explain_limiter is not None:
        return _explain_limiter
    try:
        rpm = int(os.environ.get("AISOC_EXPLAIN_RPM", _DEFAULT_RPM))
        burst = int(os.environ.get("AISOC_EXPLAIN_BURST", _DEFAULT_BURST))
    except ValueError:
        rpm, burst = _DEFAULT_RPM, _DEFAULT_BURST
    if rpm <= 0 or burst <= 0:
        return None
    _explain_limiter = TokenBucketLimiter(
        capacity=float(burst),
        refill_per_second=rpm / 60.0,
    )
    return _explain_limiter


def _reset_explain_limiter() -> None:
    """Drop the cached limiter — used by tests to pick up env changes."""
    global _explain_limiter
    _explain_limiter = None


def _rate_limit_key(req: ExplainRequest, request: Request | None) -> str:
    """Compose the bucket key for a request.

    Prefer the body-supplied tenant_id (fairness across analysts on
    the same tenant), fall back to client IP (hygiene against
    unauthenticated abuse). The agents service runs behind a reverse
    proxy in production, but ``request.client.host`` is good enough
    for in-process throttling — proxy spoofing only changes which
    bucket gets drained, never lets a caller bypass the bucket.
    """
    tenant = (req.tenant_id or "").strip()
    if tenant and tenant != "default":
        return f"tenant:{tenant}"
    ip = "unknown"
    if request is not None and request.client is not None:
        ip = request.client.host or "unknown"
    return f"ip:{ip}"


# ---------------------------------------------------------------------------
# Request shape
# ---------------------------------------------------------------------------


class ExplainRequest(BaseModel):
    """Body of POST /api/v1/explain.

    The frontend already has the full alert object in hand from the
    detail view, so we accept it verbatim rather than re-fetching by ID.
    Falls back to ``alert_id`` lookup later if needed.
    """

    alert: dict[str, Any] = Field(default_factory=dict)
    alert_id: str | None = None
    tenant_id: str = "default"


# ---------------------------------------------------------------------------
# OCSF heuristic mapping
# ---------------------------------------------------------------------------
#
# We do NOT re-implement the canonical OCSF normalizer here — that lives in
# ``services/ocsf``. The Explain drawer's job is to *label* the right OCSF
# class so an analyst knows where in the schema to look. Source-string
# heuristics are good enough for that and degrade gracefully (we always
# fall back to the generic Security Finding class).

_OCSF_BY_SOURCE: dict[str, dict[str, Any]] = {
    "okta": {
        "category": "Identity & Access Management",
        "category_uid": 3,
        "class": "Authentication",
        "class_uid": 3002,
        "activity": "Logon",
    },
    "azure-ad": {
        "category": "Identity & Access Management",
        "category_uid": 3,
        "class": "Authentication",
        "class_uid": 3002,
        "activity": "Logon",
    },
    "crowdstrike": {
        "category": "System Activity",
        "category_uid": 1,
        "class": "Process Activity",
        "class_uid": 1007,
        "activity": "Launch",
    },
    "defender": {
        "category": "System Activity",
        "category_uid": 1,
        "class": "Process Activity",
        "class_uid": 1007,
        "activity": "Launch",
    },
    "aws-guardduty": {
        "category": "Findings",
        "category_uid": 2,
        "class": "Security Finding",
        "class_uid": 2001,
        "activity": "Create",
    },
    "aws-cloudtrail": {
        "category": "Application Activity",
        "category_uid": 6,
        "class": "API Activity",
        "class_uid": 6003,
        "activity": "Create",
    },
    "github": {
        "category": "Application Activity",
        "category_uid": 6,
        "class": "API Activity",
        "class_uid": 6003,
        "activity": "Read",
    },
    "splunk": {
        "category": "Findings",
        "category_uid": 2,
        "class": "Security Finding",
        "class_uid": 2001,
        "activity": "Create",
    },
    "elastic": {
        "category": "Findings",
        "category_uid": 2,
        "class": "Security Finding",
        "class_uid": 2001,
        "activity": "Create",
    },
}

_OCSF_FALLBACK = {
    "category": "Findings",
    "category_uid": 2,
    "class": "Security Finding",
    "class_uid": 2001,
    "activity": "Create",
}


def _map_to_ocsf(alert: dict[str, Any]) -> dict[str, Any]:
    """Pick a sensible OCSF class label for the alert."""
    src = (alert.get("source") or "").lower().strip()
    for key, mapping in _OCSF_BY_SOURCE.items():
        if key in src:
            base = dict(mapping)
            break
    else:
        base = dict(_OCSF_FALLBACK)

    raw = alert.get("rawEvent") or alert.get("raw_event") or {}
    fields: dict[str, Any] = {}
    for key in (
        "user",
        "user_name",
        "username",
        "actor",
        "src_ip",
        "source_ip",
        "dest_ip",
        "destination_ip",
        "host",
        "hostname",
        "process",
        "process_name",
        "file_hash",
        "domain",
        "url",
    ):
        if isinstance(raw, dict) and raw.get(key):
            fields[key] = raw[key]

    base["fields"] = fields
    return base


# ---------------------------------------------------------------------------
# MITRE grounding — pull real technique cards from the loaded corpus
# ---------------------------------------------------------------------------

_MITRE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _extract_mitre_ids(alert: dict[str, Any]) -> list[str]:
    """Return ATT&CK technique IDs referenced by the alert.

    Looks at the structured ``mitreAttack`` field first (canonical),
    then scans tags and free-text fields with the T-ID regex so older
    detections still produce cards.
    """
    found: list[str] = []
    seen: set[str] = set()

    # Structured field — preferred
    mitre = alert.get("mitreAttack") or alert.get("mitre_attack") or []
    if isinstance(mitre, list):
        for item in mitre:
            tid = None
            if isinstance(item, dict):
                tid = item.get("techniqueId") or item.get("technique_id") or item.get("id")
            elif isinstance(item, str):
                tid = item
            if tid and tid not in seen:
                found.append(tid)
                seen.add(tid)

    # Regex sweep across tags + descriptive text
    text_pool = (
        " ".join(str(v) for v in (alert.get("tags") or []))
        + " "
        + str(alert.get("description") or "")
        + " "
        + str(alert.get("title") or "")
    )

    for tid in _MITRE_ID_RE.findall(text_pool):
        if tid not in seen:
            found.append(tid)
            seen.add(tid)

    return found[:5]  # cap so the drawer stays scannable


def _resolve_technique(technique_id: str) -> dict[str, Any]:
    """Return a MITRE card dict from the corpus, or a stub if unloaded.

    ``mitre_full.get_technique`` returns ``found=False`` for unknown
    IDs; we use that as the signal to emit a degraded card.
    """
    try:
        from app.tools.mitre_full import get_technique
    except Exception as exc:
        logger.debug("explain.mitre_corpus_unavailable", error=str(exc))
        return {
            "id": technique_id,
            "name": technique_id,
            "tactic_names": [],
            "description": "",
            "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
            "found": False,
        }

    raw = get_technique(technique_id)
    desc = (raw.get("description") or "").strip()
    return {
        "id": raw.get("id", technique_id),
        "name": raw.get("name", technique_id),
        "tactic_names": raw.get("tactic_names") or [],
        "description": desc[:280] + ("…" if len(desc) > 280 else ""),
        "url": raw.get("url") or f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
        "found": bool(raw.get("found")),
    }


# ---------------------------------------------------------------------------
# Evidence + next steps
# ---------------------------------------------------------------------------


def _extract_evidence(alert: dict[str, Any]) -> list[dict[str, str]]:
    """Pull a small, scannable list of observables from the alert."""
    items: list[dict[str, str]] = []
    raw = alert.get("rawEvent") or alert.get("raw_event") or {}

    def add(label: str, value: Any, annotation: str = "") -> None:
        if value in (None, "", [], {}):
            return
        items.append(
            {
                "label": label,
                "value": str(value)[:160],
                "annotation": annotation,
            }
        )

    add("Severity", alert.get("severity"))
    add("Risk score", alert.get("riskScore") or alert.get("risk_score"))
    add("Source", alert.get("source"))

    if isinstance(raw, dict):
        for label, key in (
            ("User", "user"),
            ("User", "user_name"),
            ("Source IP", "src_ip"),
            ("Source IP", "source_ip"),
            ("Destination IP", "dest_ip"),
            ("Destination IP", "destination_ip"),
            ("Host", "hostname"),
            ("Host", "host"),
            ("Process", "process_name"),
            ("Process", "process"),
            ("File hash", "file_hash"),
            ("Domain", "domain"),
            ("URL", "url"),
        ):
            if raw.get(key) and not any(it["label"] == label for it in items):
                add(label, raw[key])

    iocs = alert.get("iocs") or []
    if isinstance(iocs, list):
        for ioc in iocs[:3]:
            if isinstance(ioc, dict) and ioc.get("value"):
                add(f"IOC ({ioc.get('type', 'indicator')})", ioc["value"])

    return items[:8]


def _build_next_steps(alert: dict[str, Any], mitre_ids: list[str]) -> list[dict[str, Any]]:
    """Recommend concrete next moves grounded in alert tags / techniques.

    These are intentionally generic and link to the playbook engine so
    analysts can one-click run them. The list is curated, not generated,
    so the LLM can never hallucinate a non-existent playbook ID.
    """
    tags = {str(t).lower() for t in (alert.get("tags") or [])}
    severity = (alert.get("severity") or "").lower()
    steps: list[dict[str, Any]] = []

    if "account-takeover" in tags or "ato" in tags or "T1078" in mitre_ids:
        steps.append(
            {
                "title": "Run ATO containment playbook",
                "rationale": "Block sessions, force password reset, and require step-up MFA on the affected identity.",
                "playbook_id": "ato-impossible-travel-block-v1",
            }
        )

    if "ransomware" in tags or "T1486" in mitre_ids:
        steps.append(
            {
                "title": "Isolate the host",
                "rationale": "Suspected ransomware activity — quarantine the endpoint to stop encryption spread.",
                "playbook_id": "ransomware-host-isolate-v1",
            }
        )

    if "phishing" in tags or "bec" in tags:
        steps.append(
            {
                "title": "Pull the message and similar deliveries",
                "rationale": "Identify other recipients and remove the message from inboxes before clicks propagate.",
                "playbook_id": "phishing-message-pull-v1",
            }
        )

    if any(t.startswith("T1190") or t.startswith("T1133") for t in mitre_ids):
        steps.append(
            {
                "title": "Tighten perimeter exposure",
                "rationale": "Initial access vector points at an external-facing service — review WAF rules and patch level.",
                "playbook_id": None,
            }
        )

    # Always-applicable triage steps — only if we have nothing else.
    if not steps:
        steps.append(
            {
                "title": "Correlate with the last 24 h of alerts",
                "rationale": "Look for the same user, host, or IOC in adjacent detections to spot a multi-stage attack.",
                "playbook_id": None,
            }
        )

    if severity in ("high", "critical"):
        steps.append(
            {
                "title": "Open a case and notify on-call",
                "rationale": f"Severity is {severity}; promote to a tracked incident before further investigation.",
                "playbook_id": None,
            }
        )

    return steps[:4]


def _build_summary(alert: dict[str, Any], mitre_ids: list[str]) -> str:
    """Deterministic 2–3 sentence summary used when the LLM is disabled."""
    title = alert.get("title") or "Security alert"
    severity = (alert.get("severity") or "unknown").lower()
    source = alert.get("source") or "an unknown source"
    desc = (alert.get("description") or "").strip()

    technique_clause = ""
    if mitre_ids:
        technique_clause = f" The detection maps to {', '.join(mitre_ids[:3])}, which the technique cards below describe in full."

    base = f"{title} fired at {severity} severity from {source}.{technique_clause}"
    if desc:
        # Trim to keep the drawer scannable.
        snippet = desc if len(desc) <= 240 else desc[:237] + "…"
        base += f" {snippet}"
    return base


# ---------------------------------------------------------------------------
# LLM call (optional, best-effort)
# ---------------------------------------------------------------------------


async def _llm_summary(
    alert: dict[str, Any],
    mitre_techs: list[dict[str, Any]],
    fallback: str,
    llm_config: LlmConfig,
) -> str:
    """Ask the model for a tightly-scoped summary, with a hard fallback.

    The prompt deliberately forbids inventing technique IDs — the
    structured cards are emitted from the corpus, so the model only ever
    explains, never enumerates.

    The caller is responsible for resolving ``llm_config`` (typically via
    :func:`app.security.llm_resolver.resolve_llm_config`); we only honour
    its ``allowed`` flag, base URL, model, and api_key. This keeps all
    BYOK / air-gap layering decisions in one place and means this
    function has zero awareness of where the credentials came from.
    """
    if not llm_config.allowed or not llm_config.api_key:
        return fallback

    try:
        import httpx

        base = llm_config.base_url.rstrip("/")
        url = f"{base}/v1/chat/completions"
        model = llm_config.model

        tech_lines = [f"- {t['id']} {t['name']} ({', '.join(t.get('tactic_names') or []) or 'unknown tactic'})" for t in mitre_techs]
        prompt_alert = {
            "title": alert.get("title"),
            "severity": alert.get("severity"),
            "source": alert.get("source"),
            "description": alert.get("description"),
            "tags": alert.get("tags") or [],
        }

        messages = [
            {
                "role": "system",
                "content": (
                    "You are AiSOC's alert explainer. Given one security alert and a "
                    "list of MITRE ATT&CK techniques already pulled from the local "
                    "corpus, write a tight 2–4 sentence summary for an L1/L2 SOC "
                    "analyst. Be concrete about WHAT happened and WHY it matters. "
                    "Never invent technique IDs, vendor names, or IOCs that aren't "
                    "in the input. No bullet lists, no headings — just prose."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "alert": prompt_alert,
                        "mitre_techniques": tech_lines,
                    },
                    indent=2,
                ),
            },
        ]

        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(
                url,
                headers={"Authorization": f"Bearer {llm_config.api_key}"},
                json={"model": model, "messages": messages, "max_tokens": 320},
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"].strip()

    except Exception as exc:
        logger.warning("explain.llm_error", error=str(exc))
        return fallback


# ---------------------------------------------------------------------------
# Stream
# ---------------------------------------------------------------------------


def _frame(obj: dict[str, Any]) -> bytes:
    return (json.dumps(obj) + "\n").encode()


async def _stream_explanation(req: ExplainRequest, llm_config: LlmConfig) -> AsyncIterator[bytes]:
    alert = req.alert or {}
    alert_id = req.alert_id or alert.get("id") or "unknown"

    try:
        # ── 1. SUMMARY ────────────────────────────────────────────────────
        mitre_ids = _extract_mitre_ids(alert)
        mitre_cards = [_resolve_technique(t) for t in mitre_ids]

        fallback_summary = _build_summary(alert, mitre_ids)
        # Run the LLM call concurrently with the deterministic emissions
        # so the drawer paints fast even on a cold network.
        summary_task = asyncio.create_task(_llm_summary(alert, mitre_cards, fallback_summary, llm_config))

        yield _frame({"kind": "section", "id": "summary", "title": "What happened"})
        # Stream the summary word-by-word once it resolves.
        summary_text = await summary_task
        for word in summary_text.split(" "):
            yield _frame({"kind": "delta", "section": "summary", "text": word + " "})
            await asyncio.sleep(0.005)

        # ── 2. OCSF MAPPING ───────────────────────────────────────────────
        yield _frame({"kind": "section", "id": "ocsf", "title": "OCSF mapping"})
        ocsf = _map_to_ocsf(alert)
        yield _frame({"kind": "ocsf", **ocsf})

        # ── 3. MITRE CARDS ────────────────────────────────────────────────
        if mitre_cards:
            yield _frame({"kind": "section", "id": "mitre", "title": "MITRE ATT&CK"})
            for card in mitre_cards:
                yield _frame({"kind": "mitre", **card})

        # ── 4. EVIDENCE ───────────────────────────────────────────────────
        evidence = _extract_evidence(alert)
        if evidence:
            yield _frame({"kind": "section", "id": "evidence", "title": "Key evidence"})
            for item in evidence:
                yield _frame({"kind": "evidence", **item})

        # ── 5. NEXT STEPS ─────────────────────────────────────────────────
        next_steps = _build_next_steps(alert, mitre_ids)
        yield _frame({"kind": "section", "id": "next", "title": "Next steps"})
        for step in next_steps:
            yield _frame({"kind": "next_step", **step})

        # ── DONE ──────────────────────────────────────────────────────────
        yield _frame({"kind": "done", "alert_id": alert_id})

    except Exception as exc:  # noqa: BLE001 — frontend gets a structured error
        logger.exception("explain.stream_failed", error=str(exc))
        # Return a generic message to avoid exposing internal implementation details
        yield _frame({"kind": "error", "error": "An internal error occurred while generating the explanation."})


@router.post("/explain")
async def explain(req: ExplainRequest, request: Request) -> StreamingResponse:
    """Stream an OCSF + MITRE-grounded explanation of an alert as NDJSON.

    Each request consumes one token from a per-tenant bucket (see the
    "Rate limiting" section in the module docstring). When the bucket
    is empty we return HTTP 429 — *not* a 200 with an error frame —
    so generic HTTP clients and reverse proxies see a real
    throttle. The body is still NDJSON so an SSE/EventSource client
    that ignores status codes still gets a structured failure.
    """
    limiter = _get_explain_limiter()
    decision: RateLimitDecision | None = None
    if limiter is not None:
        key = _rate_limit_key(req, request)
        decision = await limiter.acquire(key)
        if not decision.allowed:
            logger.info(
                "explain.rate_limited",
                key=key,
                retry_after=decision.retry_after_seconds,
                remaining=decision.remaining,
            )
            headers = decision.to_headers()
            body = _frame(
                {
                    "kind": "error",
                    "error": (
                        "rate_limited: too many explain requests for this tenant; "
                        f"retry after ~{int(decision.retry_after_seconds + 0.999)}s"
                    ),
                }
            )
            return StreamingResponse(
                iter([body]),
                media_type="application/x-ndjson",
                status_code=429,
                headers=headers,
            )

    # Resolve the effective LLM config once per request so the stream
    # generator never has to reach into the database itself, and so
    # operators can see — via response headers — which knob took
    # effect (env / tenant / fallback). The resolver is async-safe and
    # already falls back to env-only if the database or vault is down.
    llm_config = await resolve_llm_config(req.tenant_id)

    response_headers: dict[str, str] = {}
    if decision is not None:
        response_headers.update(decision.to_headers())
    response_headers["X-LLM-Source"] = llm_config.source
    response_headers["X-LLM-Allowed"] = "1" if llm_config.allowed else "0"

    return StreamingResponse(
        _stream_explanation(req, llm_config),
        media_type="application/x-ndjson",
        headers=response_headers,
    )
