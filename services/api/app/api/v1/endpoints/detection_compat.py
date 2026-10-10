"""Frontend-compat detection rule endpoints under /api/v1/detection.

The analyst console (`apps/web/src/lib/api.ts → detectionApi`) talks to
``/api/v1/detection/rules`` and ``/api/v1/detection/test`` with a camelCase,
``enabled``-flag payload shape that pre-dates the v1 ``/api/v1/rules`` router
defined in :mod:`detection_rules`.

Rather than break the canonical backend contract (which other internal
callers, including the MCP server in ``services/mcp``, already rely on) we
publish a thin façade here that:

* GET  /api/v1/detection/rules            → list rules ``{ rules, total }``
* POST /api/v1/detection/rules            → create with frontend shape
* GET  /api/v1/detection/rules/{id}       → single rule frontend shape
* PATCH /api/v1/detection/rules/{id}      → update with frontend shape
* DELETE /api/v1/detection/rules/{id}     → delete tenant-owned rule
* POST /api/v1/detection/test             → execute body+language vs sample

The shim re-uses the SQLAlchemy ORM model and rule-engine helpers so storage,
permissions, and execution semantics stay identical to the canonical router.
"""

from __future__ import annotations

import json
import uuid
from collections import Counter, defaultdict
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select, update

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.models.detection_rule import DetectionRule
from app.services.builtin_rules import builtin_by_uuid
from app.services.detection_catalogue import (
    CatalogueFilters,
    RuleView,
    catalogue_page,
    materialise_builtin,
    resolve_rule,
)
from app.services.rule_engine import execute_rule

router = APIRouter(prefix="/detection", tags=["detection_rules"])

#: A rule from either store. The analytics helpers below read attributes that
#: a stored row and a compiled-catalogue projection both carry, and they have
#: to read both: scoping them to ORM rows is what made the MITRE heatmap draw
#: an empty grid over a library of 2,586 mapped rules.
RuleLike = DetectionRule | RuleView


# ─── Frontend wire models ────────────────────────────────────────────────────


class FrontendDetectionRule(BaseModel):
    """Mirrors `DetectionRule` in apps/web/src/lib/api.ts."""

    id: str
    name: str
    description: str | None = None
    language: str
    body: str
    enabled: bool = True
    tags: list[str] = Field(default_factory=list)
    mitre: list[str] = Field(default_factory=list)
    severity: str = "medium"
    createdAt: str
    updatedAt: str
    lastTriggeredAt: str | None = None
    hitCount: int = 0
    #: True when the fusion detection engine loads this rule from the compiled
    #: corpus. A tenant's own rule is not loaded by the engine, so disabling
    #: the two means different things and the console says which is which.
    isBuiltin: bool = False
    #: The engine's own rule id (``det-cloud-063``), for a built-in. This is
    #: the id that appears on an alert, so it is what an analyst searches for.
    sourceId: str | None = None
    #: Whether this tenant has stored a decision about the rule. A built-in
    #: with no decision is running at the corpus default.
    tuned: bool = False
    #: ``createdAt``/``updatedAt`` on a built-in are the timestamp of the
    #: compiled artefact this deployment carries, not an authoring date. Flagged
    #: so the console can label them rather than imply a history it does not have.
    timestampsFromArtefact: bool = False


class ListResponse(BaseModel):
    rules: list[FrontendDetectionRule]
    #: Rules matching the request's filters. Not the number returned — the
    #: library is 2,586 rules on a default install and the page is bounded.
    total: int
    #: The whole library before filters, split by origin. The header states
    #: library size; ``total`` states the size of the result.
    builtinTotal: int = 0
    customTotal: int = 0
    returned: int = 0
    offset: int = 0
    limit: int = 0
    #: Set when the compiled corpus could not be read at all. The console
    #: renders this as a failure, never as "no rules exist" — telling an
    #: operator their coverage is zero when the file is simply unreachable is
    #: the defect this whole surface was reported for.
    catalogError: str | None = None
    #: Artefacts that resolved nowhere while others did, so a partial read
    #: reports as partial rather than as a smaller library.
    missingArtefacts: list[str] = Field(default_factory=list)


class CreateBody(BaseModel):
    name: str
    description: str | None = None
    language: str
    body: str
    enabled: bool = True
    tags: list[str] = Field(default_factory=list)
    mitre: list[str] = Field(default_factory=list)
    severity: str = "medium"
    category: str = "custom"


class UpdateBody(BaseModel):
    name: str | None = None
    description: str | None = None
    language: str | None = None
    body: str | None = None
    enabled: bool | None = None
    tags: list[str] | None = None
    mitre: list[str] | None = None
    severity: str | None = None


class TestBody(BaseModel):
    language: str
    body: str
    sample: str | None = None


class HuntPreviewItem(BaseModel):
    id: str
    timestamp: str
    source: str
    severity: str | None = None
    fields: dict[str, Any] = Field(default_factory=dict)


class TestResponse(BaseModel):
    matches: int
    preview: list[HuntPreviewItem]


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _to_frontend(rule: DetectionRule | RuleView) -> FrontendDetectionRule:
    """Map an ORM row **or** a compiled-catalogue view → frontend shape.

    One function for both on purpose: a built-in and a tenant rule that
    rendered through two mappers would eventually disagree about the same
    rule, which is the shape #1273 reported (the page printed 2,511 in one
    tile and "No detection rules yet" in another, from two sources).
    """
    mitre: list[str] = []
    if rule.mitre_techniques:
        mitre.extend(str(t) for t in rule.mitre_techniques)
    if rule.mitre_tactics:
        mitre.extend(str(t) for t in rule.mitre_tactics)

    source_id = getattr(rule, "source_id", None)
    if source_id is None:
        provenance = getattr(rule, "provenance", None)
        if isinstance(provenance, dict):
            source_id = provenance.get("source_id") or None

    return FrontendDetectionRule(
        id=str(rule.id),
        name=rule.name,
        description=rule.description,
        language=rule.rule_language,
        body=rule.rule_body,
        enabled=(rule.status == "active"),
        tags=list(rule.tags or []),
        mitre=mitre,
        severity=rule.severity,
        createdAt=rule.created_at.isoformat() if rule.created_at else datetime.now(UTC).isoformat(),
        updatedAt=rule.updated_at.isoformat() if rule.updated_at else datetime.now(UTC).isoformat(),
        lastTriggeredAt=rule.last_triggered.isoformat() if rule.last_triggered else None,
        hitCount=rule.total_hits or 0,
        isBuiltin=bool(rule.is_builtin),
        sourceId=str(source_id) if source_id else None,
        tuned=bool(getattr(rule, "tuned", True)),
        timestampsFromArtefact=bool(rule.is_builtin) and not bool(getattr(rule, "tuned", True)),
    )


def _parse_sample_events(sample: str | None) -> list[dict[str, Any]]:
    """Best-effort parse of the optional sample blob into events.

    Accepts JSON arrays, NDJSON, or plain text (treated as a single event).
    The detection engine just needs a list of dicts; missing fields are fine.
    """
    if not sample:
        return [{}]

    text = sample.strip()
    if not text:
        return [{}]

    # Try JSON array first.
    if text.startswith("["):
        try:
            data = json.loads(text)
            if isinstance(data, list):
                return [d if isinstance(d, dict) else {"_raw": d} for d in data]
        except Exception:
            pass

    # Try NDJSON (one JSON object per line).
    events: list[dict[str, Any]] = []
    parsed_any = False
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            parsed_any = True
            events.append(obj if isinstance(obj, dict) else {"_raw": obj})
        except Exception:
            events.append({"message": line})

    if not parsed_any and not events:
        events = [{"message": text}]

    return events or [{}]


#: Fields of a built-in that this route must not pretend to change. The
#: engine reads the compiled artefact, so storing an edited body would show
#: the operator a rule the engine is not running — the exact class of defect
#: #1273 reported, inverted.
_BUILTIN_IMMUTABLE = ("body", "language", "mitre")


def _refuse_uneditable_builtin_fields(body: UpdateBody) -> None:
    offered = [name for name in _BUILTIN_IMMUTABLE if getattr(body, name, None) is not None]
    if offered:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"{', '.join(offered)} cannot be changed on a built-in rule: the detection engine loads it from the "
                "compiled corpus, so the edit would be stored and never applied. Disable it and author your own, or "
                "tune it with a suppression or a severity floor."
            ),
        )


# ─── Routes ──────────────────────────────────────────────────────────────────


@router.get("/rules", response_model=ListResponse)
async def list_rules_compat(
    current_user: Annotated[AuthUser, Depends(require_permission("rules:read"))],
    db: DBSession,
    search: str | None = Query(default=None, max_length=200),
    severity: str | None = Query(default=None),
    category: str | None = Query(default=None),
    mitre: str | None = Query(default=None, description="MITRE ATT&CK technique id, e.g. T1059.001"),
    enabled: bool | None = Query(default=None),
    source: Literal["all", "builtin", "custom"] = Query(default="all"),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> ListResponse:
    """The tenant's effective rule library: the compiled corpus plus its tuning.

    This used to read ``detection_rules`` alone and therefore answered with an
    empty list on every install, while fusion loaded and fired 2,586 rules
    (#1273). The filters and the page bound are not cosmetic: the whole
    library serialised is several megabytes, so an unbounded list would have
    traded an empty page for an unusable one.
    """
    page = await catalogue_page(
        db,
        current_user.tenant_id,
        filters=CatalogueFilters(
            search=search,
            severity=severity,
            category=category,
            mitre=mitre,
            enabled=enabled,
            include_builtin=source in ("all", "builtin"),
            include_custom=source in ("all", "custom"),
        ),
        limit=limit,
        offset=offset,
    )
    items = [_to_frontend(view) for view in page.rules]
    return ListResponse(
        rules=items,
        total=page.total,
        builtinTotal=page.builtin_total,
        customTotal=page.custom_total,
        returned=len(items),
        offset=offset,
        limit=limit,
        catalogError=page.catalogue_error,
        missingArtefacts=page.missing_artefacts,
    )


@router.post("/rules", response_model=FrontendDetectionRule, status_code=status.HTTP_201_CREATED)
async def create_rule_compat(
    body: CreateBody,
    current_user: Annotated[AuthUser, Depends(require_permission("rules:write"))],
    db: DBSession,
) -> FrontendDetectionRule:
    """Create a tenant-owned detection rule using the frontend shape."""
    rule = DetectionRule(
        tenant_id=current_user.tenant_id,
        name=body.name,
        description=body.description,
        rule_language=body.language,
        rule_body=body.body,
        category=body.category or "custom",
        severity=body.severity or "medium",
        confidence=50,
        mitre_tactics=[],
        mitre_techniques=list(body.mitre or []),
        tags=list(body.tags or []),
        status="active" if body.enabled else "inactive",
        created_by_id=current_user.user_id,
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return _to_frontend(rule)


@router.get("/rules/{rule_id}", response_model=FrontendDetectionRule)
async def get_rule_compat(
    rule_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("rules:read"))],
    db: DBSession,
) -> FrontendDetectionRule:
    """Fetch a single rule by ID in the frontend shape.

    Resolves a stored row first and the compiled catalogue second, so a
    built-in's detail page opens without a row having to exist for it. The
    read never creates one: a GET that materialised would put 2,586 rows per
    tenant in a table meant to hold decisions.
    """
    view = await resolve_rule(db, current_user.tenant_id, rule_id)
    if view is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    return _to_frontend(view)


@router.patch("/rules/{rule_id}", response_model=FrontendDetectionRule)
async def update_rule_compat(
    rule_id: uuid.UUID,
    body: UpdateBody,
    current_user: Annotated[AuthUser, Depends(require_permission("rules:write"))],
    db: DBSession,
) -> FrontendDetectionRule:
    """Update a tenant-owned rule, or record a tuning decision on a built-in.

    A built-in has no row until this point. The first write creates one under
    the rule's own id, carrying ``provenance.source_id`` — the key fusion's
    tenant overlay joins on — so disabling a rule in the console stops the
    engine firing it rather than setting a flag nothing reads. Before #1273
    this route answered 404 for every rule the engine was actually running.

    The compiled logic itself is not editable here: ``rule_body``,
    ``language`` and ``mitre`` are refused on a built-in rather than silently
    stored, because the engine loads the artefact and would ignore the edit
    while the console displayed it as applied.
    """
    stmt = select(DetectionRule).where(
        DetectionRule.id == rule_id,
        DetectionRule.tenant_id == current_user.tenant_id,
    )
    rule = (await db.execute(stmt)).scalar_one_or_none()

    if rule is None:
        builtin = builtin_by_uuid(rule_id)
        if builtin is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Rule not found or cannot be modified",
            )
        _refuse_uneditable_builtin_fields(body)
        rule = await materialise_builtin(
            db,
            builtin,
            tenant_id=current_user.tenant_id,
            actor_id=current_user.user_id,
            actor_email=current_user.email,
        )
    elif rule.is_builtin and (rule.provenance or {}).get("source_id"):
        _refuse_uneditable_builtin_fields(body)

    updates: dict[str, Any] = {}
    if body.name is not None:
        updates["name"] = body.name
    if body.description is not None:
        updates["description"] = body.description
    if body.language is not None:
        updates["rule_language"] = body.language
    if body.body is not None:
        updates["rule_body"] = body.body
    if body.severity is not None:
        updates["severity"] = body.severity
    if body.tags is not None:
        updates["tags"] = list(body.tags)
    if body.mitre is not None:
        updates["mitre_techniques"] = list(body.mitre)
    if body.enabled is not None:
        updates["status"] = "active" if body.enabled else "inactive"
    if updates:
        updates["author"] = current_user.email or str(current_user.user_id)

    if updates:
        updates["updated_at"] = datetime.now(UTC)
        updates["version"] = (rule.version or 1) + 1
        await db.execute(
            update(DetectionRule).where(DetectionRule.id == rule_id, DetectionRule.tenant_id == current_user.tenant_id).values(**updates)
        )
        await db.commit()
        await db.refresh(rule)

    return _to_frontend(rule)


@router.delete(
    "/rules/{rule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
)
async def delete_rule_compat(
    rule_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("rules:write"))],
    db: DBSession,
) -> None:
    """Delete a tenant-owned rule."""
    stmt = select(DetectionRule).where(
        DetectionRule.id == rule_id,
        DetectionRule.tenant_id == current_user.tenant_id,
    )
    rule = (await db.execute(stmt)).scalar_one_or_none()
    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found or cannot be deleted",
        )
    await db.delete(rule)
    await db.commit()


@router.post("/test", response_model=TestResponse)
async def test_rule_compat(
    body: TestBody,
    current_user: Annotated[AuthUser, Depends(require_permission("rules:read"))],
) -> TestResponse:
    """Run an ad-hoc rule body against an optional sample event blob.

    The detection IDE in the analyst console hits this with the rule body
    the user is actively editing, which has not been persisted yet, so the
    rule never needs to live in the database.
    """
    events = _parse_sample_events(body.sample)
    rid = f"adhoc-{uuid.uuid4()}"

    match = execute_rule(
        rule_id=rid,
        rule_name="ad-hoc",
        rule_language=body.language or "sigma",
        rule_body=body.body or "",
        severity="medium",
        events=events,
    )

    matched_events: list[dict[str, Any]] = match.match_details.get("matched_events", []) or []

    preview: list[HuntPreviewItem] = []
    now_iso = datetime.now(UTC).isoformat()
    for idx, evt in enumerate(matched_events[:25]):
        if not isinstance(evt, dict):
            evt = {"_raw": evt}
        ts = evt.get("@timestamp") or evt.get("timestamp") or now_iso
        src = evt.get("source") or evt.get("event", {}).get("module") or "sample"
        sev = evt.get("severity") or evt.get("event", {}).get("severity") or "medium"
        preview.append(
            HuntPreviewItem(
                id=str(evt.get("id") or evt.get("_id") or f"sample-{idx}"),
                timestamp=str(ts),
                source=str(src),
                severity=str(sev),
                fields=evt,
            )
        )

    if match.error and not preview:
        # Surface parser errors as a synthetic preview row so the IDE
        # tells the analyst something useful instead of "0 matches".
        preview.append(
            HuntPreviewItem(
                id="rule-error",
                timestamp=now_iso,
                source="rule-engine",
                severity="info",
                fields={"error": match.error, "engine_ms": match.execution_time_ms},
            )
        )

    return TestResponse(matches=len(matched_events), preview=preview)


# ─── WS-B3: Detection management UI ──────────────────────────────────────────
#
# Three pure-data endpoints power the detection management UI in
# ``apps/web/src/components/detections``:
#
# * ``GET  /api/v1/detection/coverage``     — MITRE ATT&CK heatmap data
# * ``POST /api/v1/detection/rules/bulk-toggle`` — enable/disable many rules
# * ``GET  /api/v1/detection/drift``        — rules drifting from baseline
#
# All three reuse the same ``DetectionRule`` ORM model and tenant scoping as
# the existing CRUD shim above so we don't fork the permission model. The
# heuristics are kept in pure helpers (``_build_coverage`` / ``_build_drift``)
# so they can be unit-tested without spinning up a database.


# ─── WS-B3 wire models ───────────────────────────────────────────────────────


class CoverageCell(BaseModel):
    """One technique cell in the rule-centric MITRE coverage heatmap.

    ``intensity`` is a 0-1 ratio that the heatmap uses to pick a color
    bucket; it's max(activeRules, 1) / max-active-in-grid normalized
    client-side so we don't have to know the global max here.
    """

    techniqueId: str
    tactic: str | None = None
    techniqueName: str | None = None
    totalRules: int
    activeRules: int
    inactiveRules: int


class CoverageSummary(BaseModel):
    totalRules: int
    activeRules: int
    inactiveRules: int
    techniques: int
    coveredTechniques: int  # techniques with at least one *active* rule


class CoverageResponse(BaseModel):
    tactics: list[str]
    cells: list[CoverageCell]
    summary: CoverageSummary
    generatedAt: str


class BulkToggleBody(BaseModel):
    """Bulk enable/disable payload from the analyst console.

    ``ruleIds`` are accepted as plain strings so the frontend can pass the
    same IDs it already renders from ``GET /rules`` without parsing UUIDs.
    """

    ruleIds: list[str] = Field(default_factory=list, min_length=1)
    enabled: bool


class BulkToggleResponse(BaseModel):
    updated: int
    skipped: list[str]  # rule IDs that weren't found or aren't tenant-owned


class DriftEntry(BaseModel):
    """One rule that has drifted from its tuning baseline.

    ``issues`` enumerates *which* heuristics flagged it; the UI renders one
    chip per issue so analysts see the reason without having to read the
    metric values.
    """

    ruleId: str
    name: str
    severity: str
    enabled: bool
    confidence: int
    fpRate: float
    lastTriggeredAt: str | None = None
    daysSinceTriggered: int | None = None
    issues: list[str]


class DriftSummary(BaseModel):
    total: int
    highFpRate: int
    lowConfidence: int
    stale: int
    #: Rules the drift heuristics cannot judge. Every heuristic here reads a
    #: column that only operator review and the rule IDE write — confidence,
    #: FP rate, last trigger — and the compiled corpus records none of them.
    #: Scoring 2,586 built-ins at a placeholder confidence of 0 would fill the
    #: inbox with "low confidence, stale" for every rule in the product.
    unscored: int = 0


class DriftResponse(BaseModel):
    entries: list[DriftEntry]
    summary: DriftSummary
    generatedAt: str


class ConfidenceBucket(BaseModel):
    """One column in the confidence histogram.

    ``label`` is the human-friendly bucket label rendered on the x-axis
    ("0–25", "26–50", …). ``floor`` / ``ceil`` are inclusive bounds so the
    UI can highlight the bucket a particular rule falls into without
    re-parsing the label.
    """

    label: str
    floor: int
    ceil: int
    count: int
    activeCount: int


class TacticConfidence(BaseModel):
    """Average rule confidence within one MITRE tactic.

    Useful for the "where is my coverage weakest?" question — analysts
    plot tactics as bars and immediately see that, e.g. *exfiltration*
    averages 38/100 while *execution* averages 78/100.
    """

    tactic: str
    rules: int
    activeRules: int
    avgConfidence: float
    avgConfidenceActive: float


class ConfidenceRuleEntry(BaseModel):
    """A rule highlighted in the worst/best lists."""

    ruleId: str
    name: str
    severity: str
    enabled: bool
    confidence: int
    fpRate: float
    primaryTactic: str | None = None


class ConfidenceSummary(BaseModel):
    totalRules: int
    activeRules: int
    avgConfidence: float
    avgConfidenceActive: float
    medianConfidence: int
    lowConfidence: int  # rules below ``DRIFT_LOW_CONFIDENCE_THRESHOLD``
    #: Rules excluded from every figure above because no confidence has ever
    #: been recorded for them. Published rather than dropped: a mean over 3
    #: rules beside a library of 2,586 is a different claim from a mean over
    #: 2,589, and the reader cannot tell which they are looking at otherwise.
    unscored: int = 0


class ConfidenceResponse(BaseModel):
    summary: ConfidenceSummary
    buckets: list[ConfidenceBucket]
    tactics: list[TacticConfidence]
    lowest: list[ConfidenceRuleEntry]
    highest: list[ConfidenceRuleEntry]
    generatedAt: str


# ─── WS-B3 pure helpers (unit-testable, no DB) ───────────────────────────────


# Drift heuristic thresholds — kept as module constants so tests can import
# them and so an operator can later expose them via env without rewriting
# the logic.
DRIFT_FP_RATE_THRESHOLD = 0.2
DRIFT_LOW_CONFIDENCE_THRESHOLD = 40
DRIFT_STALE_DAYS = 30


def _primary_tactic(rule: RuleLike) -> str | None:
    """Pick a single tactic to plot a rule's techniques against.

    A rule can map to multiple tactics (e.g. T1059 spans Execution and
    Initial Access). For the heatmap we just need *some* deterministic
    placement, so we take the first declared tactic and fall back to
    ``None`` (rendered as "unmapped" in the UI) if the rule didn't ship
    with a tactic at all.
    """
    if not rule.mitre_tactics:
        return None
    first = rule.mitre_tactics[0]
    return str(first) if first else None


def _build_coverage(rules: Sequence[RuleLike], *, now: datetime | None = None) -> CoverageResponse:
    """Compute MITRE ATT&CK coverage from a list of rules.

    Rules without any technique mapping are still counted in the totals so
    the summary line matches the rule count an analyst sees in the table —
    they just don't appear on the heatmap.
    """

    now = now or datetime.now(UTC)

    total_rules = len(rules)
    active_rules = sum(1 for r in rules if r.status == "active")

    # technique_id -> {"tactic": str|None, "active": int, "inactive": int}
    by_technique: dict[str, dict[str, Any]] = defaultdict(lambda: {"tactic": None, "active": 0, "inactive": 0})
    tactics_set: set[str] = set()

    for rule in rules:
        is_active = rule.status == "active"
        tactic = _primary_tactic(rule)
        if tactic:
            tactics_set.add(tactic)

        for tech in rule.mitre_techniques or []:
            tech_id = str(tech).strip()
            if not tech_id:
                continue
            cell = by_technique[tech_id]
            # Keep the first non-null tactic we see for stable plotting.
            if cell["tactic"] is None and tactic:
                cell["tactic"] = tactic
            if is_active:
                cell["active"] = int(cell["active"]) + 1
            else:
                cell["inactive"] = int(cell["inactive"]) + 1

    cells = [
        CoverageCell(
            techniqueId=tech_id,
            tactic=cell["tactic"],
            totalRules=int(cell["active"]) + int(cell["inactive"]),
            activeRules=int(cell["active"]),
            inactiveRules=int(cell["inactive"]),
        )
        for tech_id, cell in by_technique.items()
    ]
    cells.sort(key=lambda c: (c.tactic or "zzz-unmapped", c.techniqueId))

    covered = sum(1 for c in cells if c.activeRules > 0)

    return CoverageResponse(
        tactics=sorted(tactics_set),
        cells=cells,
        summary=CoverageSummary(
            totalRules=total_rules,
            activeRules=active_rules,
            inactiveRules=total_rules - active_rules,
            techniques=len(cells),
            coveredTechniques=covered,
        ),
        generatedAt=now.isoformat(),
    )


def _scoreable(rule: RuleLike) -> bool:
    """Whether any confidence or hit history has ever been recorded here.

    A compiled built-in carries none — the artefacts record a rule's logic,
    severity and ATT&CK mapping and nothing operational — so it is excluded
    from the two panels that average those columns rather than counted at the
    placeholder. ``confidence_measured`` defaults True, so an ORM row from any
    other path keeps its existing treatment.
    """
    return bool(getattr(rule, "confidence_measured", True))


def _build_drift(
    rules: Sequence[RuleLike],
    *,
    now: datetime | None = None,
    fp_threshold: float = DRIFT_FP_RATE_THRESHOLD,
    confidence_threshold: int = DRIFT_LOW_CONFIDENCE_THRESHOLD,
    stale_days: int = DRIFT_STALE_DAYS,
) -> DriftResponse:
    """Identify rules that have drifted from their tuning baseline.

    A rule lands in the inbox if *any* of these are true:

    * ``fp_rate`` exceeds the FP threshold (alert quality is degrading)
    * ``confidence`` is below the floor (analysts won't trust it anyway)
    * Rule is *enabled* but hasn't triggered in ``stale_days`` (silent
      detector — either the threat went away or the rule is broken)

    Disabled rules are never reported as "stale" since the absence of
    triggers is expected, but a disabled rule with high historical FP
    rate or low confidence still surfaces so analysts can clean it up.
    """

    now = now or datetime.now(UTC)
    stale_cutoff = now - timedelta(days=stale_days)

    entries: list[DriftEntry] = []
    counts: Counter[str] = Counter()

    unscored = sum(1 for rule in rules if not _scoreable(rule))
    for rule in rules:
        if not _scoreable(rule):
            continue
        issues: list[str] = []

        if rule.fp_rate is not None and rule.fp_rate >= fp_threshold:
            issues.append("high_fp_rate")
            counts["highFpRate"] += 1

        if rule.confidence is not None and rule.confidence < confidence_threshold:
            issues.append("low_confidence")
            counts["lowConfidence"] += 1

        is_active = rule.status == "active"
        last_trig = rule.last_triggered
        days_since: int | None = None
        if last_trig is not None:
            # Normalize to UTC if the column came back naive (depends on
            # backend driver) so the timedelta math doesn't crash on a
            # mix of aware / naive datetimes.
            ref = last_trig
            if ref.tzinfo is None:
                ref = ref.replace(tzinfo=UTC)
            days_since = max(0, (now - ref).days)

        # Stale only applies to active rules — a disabled rule with no
        # triggers is *expected* to be quiet.
        if is_active:
            if last_trig is None or last_trig.replace(tzinfo=last_trig.tzinfo or UTC) < stale_cutoff:
                issues.append("stale")
                counts["stale"] += 1

        if not issues:
            continue

        entries.append(
            DriftEntry(
                ruleId=str(rule.id),
                name=rule.name,
                severity=rule.severity or "medium",
                enabled=is_active,
                confidence=int(rule.confidence or 0),
                fpRate=float(rule.fp_rate or 0.0),
                lastTriggeredAt=last_trig.isoformat() if last_trig else None,
                daysSinceTriggered=days_since,
                issues=issues,
            )
        )

    # Worst offenders first: more issues -> higher severity -> higher FP rate.
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    entries.sort(
        key=lambda e: (
            -len(e.issues),
            -severity_rank.get(e.severity, 0),
            -e.fpRate,
            e.name,
        )
    )

    return DriftResponse(
        entries=entries,
        summary=DriftSummary(
            total=len(entries),
            highFpRate=counts["highFpRate"],
            lowConfidence=counts["lowConfidence"],
            stale=counts["stale"],
            unscored=unscored,
        ),
        generatedAt=now.isoformat(),
    )


# Confidence histogram is fixed at 4 buckets (0-25 / 26-50 / 51-75 / 76-100)
# so a tuning analyst can compare libraries across tenants without having to
# pick a binning scheme. Tweak with care: the frontend assumes 4 buckets when
# rendering the histogram component.
_CONFIDENCE_BUCKETS: tuple[tuple[str, int, int], ...] = (
    ("0–25", 0, 25),
    ("26–50", 26, 50),
    ("51–75", 51, 75),
    ("76–100", 76, 100),
)


def _build_confidence(
    rules: Sequence[RuleLike],
    *,
    now: datetime | None = None,
    top_n: int = 5,
    low_confidence_threshold: int = DRIFT_LOW_CONFIDENCE_THRESHOLD,
) -> ConfidenceResponse:
    """Compute the rule confidence distribution for the WS-B3 trends panel.

    The plan asks for *trends* but the schema doesn't snapshot confidence
    over time, so we surface the most useful trend-like cuts instead:

    * histogram across 4 fixed confidence buckets,
    * average confidence overall and per tactic — "where is my library
      weakest?" is the question analysts actually ask,
    * top-``top_n`` rules at each end so they have something concrete to
      tune (or trust) right now.

    All math is plain Python so it stays unit-testable without a database.
    """

    now = now or datetime.now(UTC)

    # Every figure below is an average or a histogram of `confidence`. A
    # compiled built-in has no confidence recorded anywhere, so including it
    # at the placeholder would publish a distribution shaped by the
    # placeholder rather than by the library.
    unscored = sum(1 for rule in rules if not _scoreable(rule))
    rules = [rule for rule in rules if _scoreable(rule)]

    total = len(rules)
    if total == 0:
        empty_buckets = [ConfidenceBucket(label=lbl, floor=lo, ceil=hi, count=0, activeCount=0) for lbl, lo, hi in _CONFIDENCE_BUCKETS]
        return ConfidenceResponse(
            summary=ConfidenceSummary(
                totalRules=0,
                activeRules=0,
                avgConfidence=0.0,
                avgConfidenceActive=0.0,
                medianConfidence=0,
                lowConfidence=0,
                unscored=unscored,
            ),
            buckets=empty_buckets,
            tactics=[],
            lowest=[],
            highest=[],
            generatedAt=now.isoformat(),
        )

    confidences = [int(r.confidence or 0) for r in rules]
    active_rules = [r for r in rules if r.status == "active"]
    active_confidences = [int(r.confidence or 0) for r in active_rules]

    avg_conf = sum(confidences) / total
    avg_active = sum(active_confidences) / len(active_confidences) if active_confidences else 0.0

    sorted_conf = sorted(confidences)
    mid = len(sorted_conf) // 2
    if len(sorted_conf) % 2:
        median = sorted_conf[mid]
    else:
        median = (sorted_conf[mid - 1] + sorted_conf[mid]) // 2

    low_count = sum(1 for c in confidences if c < low_confidence_threshold)

    # Histogram buckets.
    buckets: list[ConfidenceBucket] = []
    for label, floor, ceil in _CONFIDENCE_BUCKETS:
        count = sum(1 for c in confidences if floor <= c <= ceil)
        active = sum(1 for r in rules if r.status == "active" and floor <= int(r.confidence or 0) <= ceil)
        buckets.append(
            ConfidenceBucket(
                label=label,
                floor=floor,
                ceil=ceil,
                count=count,
                activeCount=active,
            )
        )

    # Per-tactic average confidence.
    by_tactic: dict[str, dict[str, Any]] = defaultdict(lambda: {"sum": 0, "count": 0, "active_sum": 0, "active_count": 0})
    for rule, conf in zip(rules, confidences, strict=False):
        tactic = _primary_tactic(rule)
        if not tactic:
            continue
        bucket = by_tactic[tactic]
        bucket["sum"] = int(bucket["sum"]) + conf
        bucket["count"] = int(bucket["count"]) + 1
        if rule.status == "active":
            bucket["active_sum"] = int(bucket["active_sum"]) + conf
            bucket["active_count"] = int(bucket["active_count"]) + 1

    tactics: list[TacticConfidence] = []
    for tactic, agg in by_tactic.items():
        rules_in = int(agg["count"])
        active_in = int(agg["active_count"])
        avg = (int(agg["sum"]) / rules_in) if rules_in else 0.0
        avg_active_t = (int(agg["active_sum"]) / active_in) if active_in else 0.0
        tactics.append(
            TacticConfidence(
                tactic=tactic,
                rules=rules_in,
                activeRules=active_in,
                avgConfidence=round(avg, 2),
                avgConfidenceActive=round(avg_active_t, 2),
            )
        )
    # Worst-first so the UI doesn't have to re-sort.
    tactics.sort(key=lambda t: (t.avgConfidence, t.tactic))

    def _entry(rule: RuleLike) -> ConfidenceRuleEntry:
        return ConfidenceRuleEntry(
            ruleId=str(rule.id),
            name=rule.name,
            severity=rule.severity or "medium",
            enabled=rule.status == "active",
            confidence=int(rule.confidence or 0),
            fpRate=float(rule.fp_rate or 0.0),
            primaryTactic=_primary_tactic(rule),
        )

    # Lowest / highest confidence rules. Stable secondary sort by name so
    # consecutive responses don't flip order on rules with identical scores.
    sorted_rules = sorted(rules, key=lambda r: (int(r.confidence or 0), r.name))
    lowest = [_entry(r) for r in sorted_rules[:top_n]]
    highest = [_entry(r) for r in list(reversed(sorted_rules))[:top_n]]

    return ConfidenceResponse(
        summary=ConfidenceSummary(
            totalRules=total,
            activeRules=len(active_rules),
            avgConfidence=round(avg_conf, 2),
            avgConfidenceActive=round(avg_active, 2),
            medianConfidence=int(median),
            lowConfidence=low_count,
            unscored=unscored,
        ),
        buckets=buckets,
        tactics=tactics,
        lowest=lowest,
        highest=highest,
        generatedAt=now.isoformat(),
    )


def _coerce_uuid(raw: str) -> uuid.UUID | None:
    """Best-effort cast of a frontend rule ID to ``uuid.UUID``.

    Returns ``None`` for malformed strings so the bulk-toggle endpoint can
    surface them as ``skipped`` instead of returning a 422 for the whole
    batch — a single bad ID shouldn't block the rest.
    """
    try:
        return uuid.UUID(raw)
    except (TypeError, ValueError, AttributeError):
        return None


# ─── WS-B3 routes ────────────────────────────────────────────────────────────


@router.get("/coverage", response_model=CoverageResponse)
async def get_detection_coverage(
    current_user: Annotated[AuthUser, Depends(require_permission("rules:read"))],
    db: DBSession,
) -> CoverageResponse:
    """Rule-centric MITRE ATT&CK coverage for the current tenant.

    Distinct from ``/api/v1/graph/mitre/coverage`` which derives coverage
    from *alerts* — this one is what an analyst opens before a tuning
    sprint to answer "which techniques is my rule library blind to?".

    Reads the whole effective library, built-ins included. It previously read
    the ``detection_rules`` table alone and therefore drew an empty heatmap
    over a product shipping ATT&CK mappings for 2,586 loaded rules — the
    strongest possible version of the "blind to everything" answer, and
    wrong.
    """
    page = await catalogue_page(db, current_user.tenant_id)
    return _build_coverage(page.rules)


@router.post("/rules/bulk-toggle", response_model=BulkToggleResponse)
async def bulk_toggle_rules(
    body: BulkToggleBody,
    current_user: Annotated[AuthUser, Depends(require_permission("rules:write"))],
    db: DBSession,
) -> BulkToggleResponse:
    """Enable or disable many rules in one round-trip, built-ins included.

    Built-ins used to be "silently skipped", which on a default install meant
    every rule in the library was skipped: there were no other rules. A
    built-in now materialises a tenant tuning row on first toggle, exactly as
    the single-rule PATCH does, so selecting a noisy category and turning it
    off reaches the engine.

    Ids that match nothing at all are still reported in ``skipped``, because
    an operator who selected forty rules and had one quietly dropped would
    have no way to find out which.
    """
    requested = body.ruleIds or []
    if not requested:
        return BulkToggleResponse(updated=0, skipped=[])

    parsed: dict[uuid.UUID, str] = {}  # uuid -> original string
    skipped: list[str] = []
    for raw in requested:
        as_uuid = _coerce_uuid(raw)
        if as_uuid is None:
            skipped.append(raw)
        else:
            parsed[as_uuid] = raw

    if not parsed:
        return BulkToggleResponse(updated=0, skipped=skipped)

    target_status = "active" if body.enabled else "inactive"

    stmt = select(DetectionRule.id).where(
        DetectionRule.id.in_(parsed.keys()),
        DetectionRule.tenant_id == current_user.tenant_id,
    )
    owned: set[uuid.UUID] = set((await db.execute(stmt)).scalars().all())

    actor = current_user.email or str(current_user.user_id)
    for rid, raw in parsed.items():
        if rid in owned:
            continue
        builtin = builtin_by_uuid(rid)
        if builtin is None:
            skipped.append(raw)
            continue
        await materialise_builtin(
            db,
            builtin,
            tenant_id=current_user.tenant_id,
            actor_id=current_user.user_id,
            actor_email=actor,
        )
        owned.add(rid)

    if not owned:
        return BulkToggleResponse(updated=0, skipped=skipped)

    now = datetime.now(UTC)
    await db.execute(update(DetectionRule).where(DetectionRule.id.in_(owned)).values(status=target_status, updated_at=now, author=actor))
    await db.commit()

    return BulkToggleResponse(updated=len(owned), skipped=skipped)


@router.get("/drift", response_model=DriftResponse)
async def get_detection_drift(
    current_user: Annotated[AuthUser, Depends(require_permission("rules:read"))],
    db: DBSession,
) -> DriftResponse:
    """Detection drift inbox — rules that need an analyst's attention.

    Surfaces rules with elevated FP rate, low confidence, or stale (no
    recent triggers despite being enabled). The UI renders this as a tab
    on the Detections page so analysts have a single queue to work
    instead of paginating the full library hunting for noise.

    Built-ins are counted in ``summary.unscored`` rather than judged: none of
    the three heuristics has an input for them.
    """
    page = await catalogue_page(db, current_user.tenant_id)
    return _build_drift(page.rules)


@router.get("/confidence", response_model=ConfidenceResponse)
async def get_detection_confidence(
    current_user: Annotated[AuthUser, Depends(require_permission("rules:read"))],
    db: DBSession,
) -> ConfidenceResponse:
    """Rule-confidence trend panel for the WS-B3 Detections UI.

    Returns a 4-bucket histogram of rule confidence, the per-tactic
    average, and the top/bottom rules so analysts can see at a glance
    where the rule library is brittle and which tactics need the most
    tuning love.

    No history table is needed — this view derives its trend signal from
    the current confidence/FP-rate columns set by the rule engine and
    operator review on every match.

    Rules with no recorded confidence are reported as ``summary.unscored``
    and left out of every average, so the histogram describes the rules an
    operator has actually scored rather than being flattened by a library of
    placeholders.
    """
    page = await catalogue_page(db, current_user.tenant_id)
    return _build_confidence(page.rules)
