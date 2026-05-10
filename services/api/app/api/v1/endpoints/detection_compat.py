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
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, or_, select, update

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.models.detection_rule import DetectionRule
from app.services.rule_engine import execute_rule

router = APIRouter(prefix="/detection", tags=["detection_rules"])


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


class ListResponse(BaseModel):
    rules: list[FrontendDetectionRule]
    total: int


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


def _to_frontend(rule: DetectionRule) -> FrontendDetectionRule:
    """Map ORM row → frontend shape."""
    mitre: list[str] = []
    if rule.mitre_techniques:
        mitre.extend(str(t) for t in rule.mitre_techniques)
    if rule.mitre_tactics:
        mitre.extend(str(t) for t in rule.mitre_tactics)

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


# ─── Routes ──────────────────────────────────────────────────────────────────


@router.get("/rules", response_model=ListResponse)
async def list_rules_compat(
    current_user: Annotated[AuthUser, Depends(require_permission("rules:read"))],
    db: DBSession,
) -> ListResponse:
    """List detection rules visible to the current tenant (built-ins + tenant-owned)."""
    tid = current_user.tenant_id
    stmt = (
        select(DetectionRule)
        .where(
            or_(
                DetectionRule.tenant_id == tid,
                and_(DetectionRule.tenant_id.is_(None), DetectionRule.is_builtin.is_(True)),
            )
        )
        .order_by(DetectionRule.name)
    )
    result = await db.execute(stmt)
    rules = result.scalars().all()
    items = [_to_frontend(r) for r in rules]
    return ListResponse(rules=items, total=len(items))


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
    """Fetch a single rule by ID in the frontend shape."""
    stmt = select(DetectionRule).where(
        DetectionRule.id == rule_id,
        or_(
            DetectionRule.tenant_id == current_user.tenant_id,
            DetectionRule.tenant_id.is_(None),
        ),
    )
    rule = (await db.execute(stmt)).scalar_one_or_none()
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    return _to_frontend(rule)


@router.patch("/rules/{rule_id}", response_model=FrontendDetectionRule)
async def update_rule_compat(
    rule_id: uuid.UUID,
    body: UpdateBody,
    current_user: Annotated[AuthUser, Depends(require_permission("rules:write"))],
    db: DBSession,
) -> FrontendDetectionRule:
    """Update a tenant-owned rule using the frontend shape."""
    stmt = select(DetectionRule).where(
        DetectionRule.id == rule_id,
        DetectionRule.tenant_id == current_user.tenant_id,
    )
    rule = (await db.execute(stmt)).scalar_one_or_none()
    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found or cannot be modified",
        )

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
        updates["updated_at"] = datetime.now(UTC)
        updates["version"] = (rule.version or 1) + 1
        await db.execute(update(DetectionRule).where(DetectionRule.id == rule_id).values(**updates))
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


def _primary_tactic(rule: DetectionRule) -> str | None:
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


def _build_coverage(rules: list[DetectionRule], *, now: datetime | None = None) -> CoverageResponse:
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


def _build_drift(
    rules: list[DetectionRule],
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

    for rule in rules:
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
    rules: list[DetectionRule],
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

    def _entry(rule: DetectionRule) -> ConfidenceRuleEntry:
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
    """
    tid = current_user.tenant_id
    stmt = select(DetectionRule).where(
        or_(
            DetectionRule.tenant_id == tid,
            and_(DetectionRule.tenant_id.is_(None), DetectionRule.is_builtin.is_(True)),
        )
    )
    rules = (await db.execute(stmt)).scalars().all()
    return _build_coverage(list(rules))


@router.post("/rules/bulk-toggle", response_model=BulkToggleResponse)
async def bulk_toggle_rules(
    body: BulkToggleBody,
    current_user: Annotated[AuthUser, Depends(require_permission("rules:write"))],
    db: DBSession,
) -> BulkToggleResponse:
    """Enable or disable many tenant-owned rules in one round-trip.

    Built-in / cross-tenant rules are silently skipped (returned in
    ``skipped``) so an MSSP analyst toggling a whole category from the UI
    doesn't get a 403 just because one of the rules is platform-provided.
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

    # Look up which of the requested IDs are actually tenant-owned. Built-in
    # rules (tenant_id IS NULL) and other-tenant rules get pushed onto
    # ``skipped`` rather than mutated.
    stmt = select(DetectionRule.id).where(
        DetectionRule.id.in_(parsed.keys()),
        DetectionRule.tenant_id == current_user.tenant_id,
    )
    owned_ids: list[uuid.UUID] = list((await db.execute(stmt)).scalars().all())
    owned_set = set(owned_ids)

    for rid in parsed.keys():
        if rid not in owned_set:
            skipped.append(parsed[rid])

    if not owned_ids:
        return BulkToggleResponse(updated=0, skipped=skipped)

    now = datetime.now(UTC)
    await db.execute(update(DetectionRule).where(DetectionRule.id.in_(owned_ids)).values(status=target_status, updated_at=now))
    await db.commit()

    return BulkToggleResponse(updated=len(owned_ids), skipped=skipped)


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
    """
    tid = current_user.tenant_id
    stmt = select(DetectionRule).where(
        or_(
            DetectionRule.tenant_id == tid,
            and_(DetectionRule.tenant_id.is_(None), DetectionRule.is_builtin.is_(True)),
        )
    )
    rules = (await db.execute(stmt)).scalars().all()
    return _build_drift(list(rules))


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
    """
    tid = current_user.tenant_id
    stmt = select(DetectionRule).where(
        or_(
            DetectionRule.tenant_id == tid,
            and_(DetectionRule.tenant_id.is_(None), DetectionRule.is_builtin.is_(True)),
        )
    )
    rules = (await db.execute(stmt)).scalars().all()
    return _build_confidence(list(rules))
