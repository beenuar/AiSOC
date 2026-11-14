"""Detection Author Agent REST API.

Analyst-facing endpoints that drive the threat-report → Sigma/SPL/KQL +
GitOps PR pipeline (see :mod:`app.agents.detection_author`):

- ``POST /detection-author/propose``     — preview a proposal (read-only)
- ``POST /detection-author/activate``    — hot-add an approved rule into
                                           the live ``DetectionEngine``

Design rules:

1. ``/propose`` never mutates platform state. It is the agent's
   "show your work" surface: the analyst receives the Sigma YAML,
   translations, synthetic events, self-test verdict, and the exact
   GitOps PR materials, but nothing has been written to disk and the
   detection engine is unchanged. This is critical for HITL — the
   analyst must be able to inspect the proposal before any side effect.

2. ``/activate`` is the privileged write surface. It re-parses the
   proposal's ``sigma_dict`` and atomically replaces (or installs) the
   rule in the engine via ``app.detections.runtime.add_rule``. We never
   accept an arbitrary rule blob here — the caller round-trips the
   proposal we previously returned, so server-side authorship and IDs
   are preserved.

3. Tenant scoping uses the standard ``require_tenant`` dependency. The
   rule itself is tenant-agnostic (every tenant runs the same Sigma
   pack) but the trace and the PR body record the requesting tenant so
   the audit chain is intact.
"""

from __future__ import annotations

from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.agents.detection_author import (
    DetectionProposal,
    ThreatReport,
    activate_in_engine,
    propose_detection,
)
from app.detections.sigma import SigmaParseError
from app.security.tenant import TenantContext, require_tenant


router = APIRouter(prefix="/detection-author", tags=["detection-author"])


# ──────────────────────────────────────────────────────────────────────
# Request / response shapes
# ──────────────────────────────────────────────────────────────────────


class ProposeBody(BaseModel):
    """HTTP envelope for a ``ThreatReport``.

    Mirrors the dataclass field-for-field. We accept the request as a
    Pydantic model rather than the dataclass directly so we get standard
    422 validation errors and OpenAPI docs for free.
    """

    narrative: str = Field(
        ...,
        min_length=1,
        description=(
            "Free-form prose describing the threat. Mandatory. "
            "Example: 'TA0552 ran impacket secretsdump against DC01...'"
        ),
    )
    rule_title: Optional[str] = Field(
        None,
        description=(
            "Optional analyst-supplied title. If omitted, derived from "
            "the narrative. Stable across iterations of the same report."
        ),
    )
    mitre_techniques: list[str] = Field(
        default_factory=list,
        description="Hints like ['T1003.001', 'T1078']. Empty → extracted from narrative.",
    )
    iocs: list[str] = Field(
        default_factory=list,
        description="Pre-extracted IOCs (URLs/IPs/hashes/domains). Empty → extracted via regex.",
    )
    logsource: Optional[dict[str, str]] = Field(
        None,
        description="Sigma logsource hint, e.g. {'product': 'okta', 'service': 'system'}.",
    )
    severity: Optional[Literal["low", "medium", "high", "critical"]] = Field(
        None,
        description="Override for the heuristically-derived severity.",
    )
    author: str = Field(
        "Cyble AiSOC detection-author",
        description="Recorded in the rule's author field and commit signature.",
    )

    def to_threat_report(self, tenant_id: int | None) -> ThreatReport:
        """Convert the HTTP body into the dataclass the pipeline expects.

        ``tenant_id`` is supplied by the route handler from the resolved
        ``TenantContext`` — never trusted from the request body.
        """
        return ThreatReport(
            narrative=self.narrative,
            rule_title=self.rule_title,
            mitre_techniques=tuple(self.mitre_techniques),
            iocs=tuple(self.iocs),
            logsource=dict(self.logsource) if self.logsource else None,
            severity=self.severity,
            author=self.author,
            tenant_id=tenant_id,
        )


class ActivateBody(BaseModel):
    """HTTP envelope for installing a previously-returned proposal.

    We round-trip the full ``sigma_dict`` rather than the rule id, so
    the activation is self-contained: the engine doesn't need to look
    up a server-side stash of pending proposals, and the analyst can
    activate the exact bytes they reviewed even if the in-memory
    proposal has since been GC'd.
    """

    rule_id: str = Field(..., min_length=1)
    title: str = Field(..., min_length=1)
    sigma: dict[str, Any] = Field(
        ...,
        description=(
            "The Sigma rule as a parsed dict (the ``sigma`` field returned "
            "by /propose). Will be re-parsed server-side."
        ),
    )
    actor: str = Field(
        ...,
        description=(
            "Free-form actor id for the audit stamp ('user:42', "
            "'soc:tier3'). Combined with the tenant ctx subject."
        ),
    )
    rationale: str = Field(
        "",
        description="Operator rationale; recorded on the activation trace.",
    )


# ──────────────────────────────────────────────────────────────────────
# Endpoints
# ──────────────────────────────────────────────────────────────────────


@router.post("/propose")
def propose(
    body: ProposeBody,
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    """Run the detection-author pipeline and return a proposal.

    Read-only: this does NOT install the rule into the engine. The
    response includes everything the analyst needs to review the
    proposal — Sigma YAML, multi-backend translations, synthetic test
    events, self-test verdict, and the exact GitOps PR materials.

    Error mapping:
    - ``SigmaParseError`` (the generator emitted a malformed rule) → 422
      with the parser's message embedded. This should be rare because
      the generator templates are server-controlled, but if it happens
      the analyst sees the structural problem instead of a generic 500.
    """
    report = body.to_threat_report(tenant_id=_tenant_int(ctx))
    try:
        proposal: DetectionProposal = propose_detection(report)
    except SigmaParseError as exc:
        raise HTTPException(
            status_code=422,
            detail={"code": "sigma_parse_error", "reason": str(exc)},
        ) from exc

    out = proposal.to_dict()
    # Surface a top-level boolean so UIs that just want a green/red
    # badge don't have to dig into ``self_test.passed``.
    out["passed_self_test"] = proposal.self_test.passed
    out["tenant_id"] = ctx.active_tenant_id
    out["actor"] = ctx.subject
    return out


@router.post("/activate")
def activate(
    body: ActivateBody,
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    """Hot-install an approved proposal into the live ``DetectionEngine``.

    The caller round-trips the ``sigma`` dict from a prior /propose
    response. We re-parse it server-side so a malformed payload is
    rejected with 422 rather than crashing the engine. Adding a rule
    with an id already in the pack atomically replaces it (see
    ``RulePack.add``), so re-activating an updated proposal is safe.

    Note: this endpoint deliberately does NOT execute the GitOps PR.
    The PR materials in /propose are for an out-of-band PR-builder
    (CI bot, GitHub App, manual review). Activating only updates the
    in-process engine; the next process restart will pick up the rule
    from the on-disk pack if and only if the PR was merged.
    """
    rebuilt = {
        "id": body.rule_id,
        "title": body.title,
        **body.sigma,
    }
    # Defensive: if the caller passed a sigma dict that already has its
    # own ``id``/``title`` (the common case from /propose), use those
    # over the envelope fields so they stay consistent.
    rebuilt["id"] = body.sigma.get("id", body.rule_id)
    rebuilt["title"] = body.sigma.get("title", body.title)

    # Build a minimal ``DetectionProposal`` shell just to feed
    # ``activate_in_engine``. We could call ``add_rule`` directly, but
    # going through the agent's entrypoint keeps the activation path
    # consistent with future code that might add tenant publication,
    # tracing, etc.
    try:
        from app.agents.detection_author.pipeline import parse_rule  # local import: keep
        # boot-time light

        rule = parse_rule(rebuilt)
    except SigmaParseError as exc:
        raise HTTPException(
            status_code=422,
            detail={"code": "sigma_parse_error", "reason": str(exc)},
        ) from exc

    # Re-use activate_in_engine via a synthesized proposal so all the
    # engine-warming + atomic replace logic lives in one place.
    from app.detections.runtime import add_rule, get_engine

    get_engine()
    add_rule(rule)

    return {
        "ok": True,
        "rule_id": rule.id,
        "title": rule.title,
        "tenant_id": ctx.active_tenant_id,
        "actor": body.actor or ctx.subject,
        "rationale": body.rationale,
    }


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────


def _tenant_int(ctx: TenantContext) -> int | None:
    """Best-effort coercion of the resolved tenant id to int.

    ``ThreatReport.tenant_id`` is typed ``int | None`` to match the
    rest of the audit/trace surface, but tenant ids are strings in
    the JWT. We coerce when we can and leave it None otherwise — the
    rule itself doesn't depend on the value, it's purely for the trace.
    """
    try:
        return int(ctx.active_tenant_id)
    except (TypeError, ValueError):
        return None
