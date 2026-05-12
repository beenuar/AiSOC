"""POST ``/alerts/{alert_id}/explain`` — structured AI explainer.

This endpoint is the API-side counterpart to the existing NDJSON
streaming explainer in ``services/agents``. The agent service still
exists for the *streaming* console UX (token-by-token); this endpoint
exists so console clients, the case-summary PDF builder, and headless
SOAR playbooks can ask one question — *"what is this alert?"* — and
get back a structured JSON envelope with:

* ``rule_lineage``     — which detection rule fired (best-effort)
* ``contributing_events`` — the raw event signals that drove it
* ``mitre_techniques`` — resolved ATT&CK cards
* ``historical_fp_rate`` — per-rule (or per-category) FPR over the
  last 30 days
* ``suggested_actions``  — deterministic, hand-curated next steps
* ``summary``            — LLM-written or deterministic-fallback prose

The work itself lives in :mod:`app.services.alert_explain`; this
module is purely an HTTP shell. It is responsible for:

1. Permission gating (``alerts:read``).
2. Per-tenant rate limiting via :class:`ExplainRateLimiter`. Explain
   calls hit an LLM and run two analytic queries; without a cap a
   misbehaving frontend or a runaway agent loop can drain budget in
   minutes.
3. Loading the alert under the tenant-scoped session (RLS) so the
   downstream query helpers can safely run untenanted queries.
4. Emitting an audit event — explains are user-visible LLM calls and
   compliance auditors want a paper trail.

The endpoint is mounted under the existing alerts prefix, so the
final path is ``POST /api/v1/alerts/{alert_id}/explain``.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import asdict
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select

from app.api.v1.deps import AuthUser, require_permission
from app.db.rls import TenantDBSession
from app.models.alert import Alert
from app.services.alert_explain import (
    AlertExplanation,
    generate_alert_explanation,
)
from app.services.audit import emit_audit
from app.services.explain_rate_limit import (
    ExplainRateLimitDecision,
    get_explain_rate_limiter,
)

logger = logging.getLogger(__name__)

# Mount on the alerts prefix so the route reads
# ``POST /api/v1/alerts/{alert_id}/explain``. We could have hung this
# off the existing ``alerts.py`` module but that file is already 600+
# lines and the explain workflow has three collaborating helpers
# (resolver, service, rate limiter); a dedicated module keeps the
# blast radius small if we need to revisit it later.
router = APIRouter(prefix="/alerts", tags=["alerts"])


async def _acquire_or_429(
    *,
    response: Response,
    tenant_id: uuid.UUID,
    cost: float = 1.0,
) -> ExplainRateLimitDecision:
    """Charge the explain bucket; raise HTTP 429 on overflow.

    Mirrors the lake endpoint's ``_acquire_or_429`` so operators get
    consistent ``X-RateLimit-*`` semantics across both expensive APIs.
    The headers are stamped on both the allowed and the denied path
    so a polite client always knows where it stands without having to
    parse error envelopes.
    """
    limiter = get_explain_rate_limiter()
    decision = await limiter.acquire(tenant_id, cost=cost)

    headers = decision.to_headers()
    for name, value in headers.items():
        response.headers[name] = value

    if not decision.allowed:
        # INFO so a noisy tenant surfaces in standard ops dashboards
        # without flooding ERROR. The same headers are reused on the
        # error envelope so retry-after semantics survive the 429.
        logger.info(
            "explain.rate_limited tenant_id=%s cost=%.2f remaining=%.2f retry_after=%.2fs",
            tenant_id,
            cost,
            decision.remaining,
            decision.retry_after_seconds,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="explain endpoint rate limit exceeded",
            headers=headers,
        )
    return decision


def _explanation_to_payload(explanation: AlertExplanation) -> dict[str, Any]:
    """Serialise the dataclass tree to a plain JSON-able dict.

    ``dataclasses.asdict`` does the recursive walk for us, including
    the nested ``MitreTechnique``/``ContributingEvent``/``SuggestedAction``
    lists and the ``RuleLineage`` / ``HistoricalFpRate`` objects. We
    use it instead of a Pydantic model for two reasons: (1) the
    explain payload is read-only — we never validate it inbound — so
    Pydantic adds no value, and (2) the dataclass shape lives next to
    the business logic in ``alert_explain.py``, which keeps the
    contract close to its only producer.
    """
    return asdict(explanation)


@router.post(
    "/{alert_id}/explain",
    summary="Generate a structured AI explanation for an alert",
    response_description="Structured explanation payload (rule lineage, MITRE, FPR, actions, summary)",
)
async def explain_alert(
    alert_id: uuid.UUID,
    request: Request,
    response: Response,
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
    db: TenantDBSession,
) -> dict[str, Any]:
    """Return a structured explanation for one alert.

    This is the *single-shot* counterpart to the agent service's
    NDJSON stream. Use this when the client is a non-interactive
    consumer (PDF builder, SOAR playbook, mobile app) or when the
    UI just wants the final payload without rendering tokens.
    """
    # Rate-limit *before* hitting the database. The limiter is
    # asyncio-cheap (token-bucket math + a per-key lock) and shedding
    # at the door costs less than fetching the alert and then
    # discarding the work.
    await _acquire_or_429(
        response=response,
        tenant_id=current_user.tenant_id,
    )

    # The session is already RLS-scoped to ``current_user.tenant_id``,
    # but we add a redundant ``tenant_id`` filter on the alert lookup
    # so the 404 we return is not "row hidden by RLS" — it really is
    # "no such alert in your tenant". Defence in depth.
    result = await db.execute(
        select(Alert).where(
            Alert.id == alert_id,
            Alert.tenant_id == current_user.tenant_id,
        )
    )
    alert = result.scalar_one_or_none()
    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found",
        )

    try:
        explanation = await generate_alert_explanation(db, alert=alert)
    except Exception as exc:  # noqa: BLE001
        # The explain pipeline is defensive — it falls back to a
        # deterministic summary on LLM failure, swallows cost-tracking
        # errors, etc. — so reaching this branch means something
        # unexpected (e.g. database read failure mid-explain) blew up.
        # Log loudly and return a 502 so the client can retry; we do
        # *not* expose the exception text to the caller.
        logger.exception(
            "explain.failed tenant=%s alert=%s",
            current_user.tenant_id,
            alert_id,
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="failed to generate explanation",
        ) from exc

    # Audit *after* the explain succeeds so failures don't pollute
    # the audit stream with phantom events. We log enough context for
    # a compliance reviewer to recreate "who explained what, when, and
    # whether the LLM actually answered" without storing the prose
    # itself (which can leak event PII into the audit log).
    try:
        await emit_audit(
            db=db,
            tenant_id=current_user.tenant_id,
            actor_id=current_user.user_id,
            actor_email=current_user.email,
            action="alerts.explain",
            resource="alert",
            resource_id=str(alert_id),
            changes={
                "llm_used": explanation.llm_used,
                "llm_source": explanation.llm_source,
                "llm_reason": explanation.llm_reason,
                "rule_match_method": explanation.rule_lineage.match_method,
                "rule_id": explanation.rule_lineage.rule_id,
                "fp_rate_scope": explanation.historical_fp_rate.scope,
                "fp_rate_sample_size": explanation.historical_fp_rate.sample_size,
                "mitre_technique_count": len(explanation.mitre_techniques),
            },
            request=request,
        )
    except Exception as exc:  # noqa: BLE001
        # Audit-log failures must never break the explain response.
        # We log a warning so ops can investigate, but we do not
        # propagate — the user already got their answer.
        logger.warning(
            "explain.audit_failed tenant=%s alert=%s error=%s",
            current_user.tenant_id,
            alert_id,
            exc,
        )

    return _explanation_to_payload(explanation)
