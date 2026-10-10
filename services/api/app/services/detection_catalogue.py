"""One view over the rules that run and the tuning a tenant has applied to them.

Two stores answer "what detection rules does this tenant have?" and before
#1273 only one of them was ever read:

* the compiled artefacts, which are what the fusion engine actually loads and
  fires (``app.services.builtin_rules``);
* ``detection_rules`` in Postgres, which holds rules a tenant authored *and*
  the tuning a tenant has applied to a built-in.

This module merges them, and the merge rule is one line: a stored row wins
over the compiled rule it names, because the row is the tenant's decision
about it. Everything else here exists to keep that honest.

Materialisation
---------------
A built-in has no row until somebody tunes it. The first write creates one,
under the rule's deterministic UUID and carrying ``provenance.source_id``, so:

* the id an operator sees never changes when they disable something;
* ``services/fusion/app/services/tenant_overlay.py`` selects it on its next
  reload — its query is
  ``SELECT COALESCE(provenance->>'source_id', name) … WHERE tenant_id = $1
  AND (status <> 'active' OR suppression_config <> '{}' OR threshold_config
  <> '{}')`` — so "disabled" in the console means the engine stops firing it
  rather than a flag nobody reads. That was the whole point of the report:
  the rules that run could not be viewed, disabled or tuned.

A read never materialises. A GET that writes a row for every rule it renders
would put 2,586 rows per tenant in the table on the first page load, and the
table is supposed to hold decisions, not inventory.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.detection_rule import DetectionRule
from app.services.builtin_rules import (
    RULE_LANGUAGE,
    BuiltinCatalogueUnavailable,
    BuiltinRule,
    builtin_catalogue,
    uuid_for,
)

#: Placeholder confidence for a rule nobody has scored. It travels with
#: ``confidence_measured=False`` and the two panels that average confidence
#: exclude it, because an unmeasured rule counted as 0 drags a published mean
#: toward a number no analyst chose.
UNMEASURED_CONFIDENCE = 0


@dataclass
class RuleView:
    """A detection rule as both response models read it.

    Field names mirror :class:`app.models.detection_rule.DetectionRule`, so
    ``DetectionRuleResponse.model_validate`` and ``_to_frontend`` accept a view
    and a row interchangeably and cannot drift into describing them
    differently.
    """

    id: uuid.UUID
    tenant_id: uuid.UUID | None
    name: str
    description: str | None
    rule_language: str
    rule_body: str
    category: str
    status: str
    severity: str
    confidence: int
    mitre_tactics: list[str]
    mitre_techniques: list[str]
    fp_rate: float
    total_hits: int
    last_triggered: datetime | None
    tags: list[str]
    is_builtin: bool
    version: int
    created_at: datetime
    updated_at: datetime
    #: The engine's own rule id, for a built-in. ``None`` for a rule a tenant
    #: authored, which the engine does not load.
    source_id: str | None = None
    #: Whether a measurement exists behind ``confidence``.
    confidence_measured: bool = True
    #: Whether this tenant has stored a decision about the rule.
    tuned: bool = False
    #: ``aisoc-engine`` when the fusion detection engine loads this rule,
    #: ``custom`` when it is a tenant's own rule that the engine does not. The
    #: distinction decides whether disabling it changes anything.
    engine: str = "custom"


@dataclass
class CatalogueFilters:
    search: str | None = None
    severity: str | None = None
    category: str | None = None
    rule_language: str | None = None
    mitre: str | None = None
    #: ``None`` for either, True for enabled only, False for disabled only.
    enabled: bool | None = None
    include_builtin: bool = True
    include_custom: bool = True


@dataclass
class CataloguePage:
    rules: list[RuleView]
    #: Rules matching the filters, which is not the number returned.
    total: int
    #: Rules before any filter, split by where they came from. The console
    #: header states the library size; the filtered total states the result.
    builtin_total: int
    custom_total: int
    #: Why the compiled corpus could not be read, when it could not be. Never
    #: collapsed into an empty list: "the engine runs nothing" and "this
    #: process cannot see the ruleset" are different answers.
    catalogue_error: str | None = None
    #: Artefacts that resolved nowhere, when some did.
    missing_artefacts: list[str] = field(default_factory=list)


def row_view(row: DetectionRule) -> RuleView:
    source_id = None
    provenance = row.provenance or {}
    if isinstance(provenance, dict):
        raw = provenance.get("source_id")
        source_id = str(raw) if raw else None
    return RuleView(
        id=row.id,
        tenant_id=row.tenant_id,
        name=row.name,
        description=row.description,
        rule_language=row.rule_language,
        rule_body=row.rule_body,
        category=row.category,
        status=row.status,
        severity=row.severity,
        confidence=int(row.confidence or 0),
        mitre_tactics=list(row.mitre_tactics or []),
        mitre_techniques=list(row.mitre_techniques or []),
        fp_rate=float(row.fp_rate or 0.0),
        total_hits=int(row.total_hits or 0),
        last_triggered=row.last_triggered,
        tags=list(row.tags or []),
        is_builtin=bool(row.is_builtin),
        version=int(row.version or 1),
        created_at=row.created_at,
        updated_at=row.updated_at,
        source_id=source_id,
        confidence_measured=not bool(row.is_builtin) or bool(row.confidence),
        tuned=True,
        engine="aisoc-engine" if source_id else "custom",
    )


def builtin_view(rule: BuiltinRule, *, tenant_id: uuid.UUID, installed_at: datetime) -> RuleView:
    """Project a compiled rule into the shape both response models read.

    ``installed_at`` is the artefact's modification time — when *this*
    deployment's copy of the compiled ruleset was written. It is reported as
    the rule's created/updated timestamp because both fields are non-nullable
    in the published schema and the artefact's timestamp is the only real date
    the catalogue knows. It is not the date the rule was authored and the
    console labels it accordingly.
    """
    return RuleView(
        id=uuid_for(rule.source_id, tenant_id),
        tenant_id=None,
        name=rule.name,
        description=rule.description,
        rule_language=RULE_LANGUAGE,
        rule_body=rule.rule_body,
        category=rule.category,
        # The engine loads every rule in the artefact and evaluates it against
        # every event, so an untuned built-in is running. Anything else here
        # would be the console reporting a posture the engine does not hold.
        status="active",
        severity=rule.severity,
        confidence=UNMEASURED_CONFIDENCE,
        mitre_tactics=[],
        mitre_techniques=list(rule.mitre_techniques),
        fp_rate=0.0,
        total_hits=0,
        last_triggered=None,
        tags=rule.tags,
        is_builtin=True,
        version=1,
        created_at=installed_at,
        updated_at=installed_at,
        source_id=rule.source_id,
        confidence_measured=False,
        tuned=False,
        engine="aisoc-engine",
    )


def _matches(view: RuleView, filters: CatalogueFilters) -> bool:
    if filters.severity and view.severity != filters.severity:
        return False
    if filters.category and view.category != filters.category:
        return False
    if filters.rule_language and view.rule_language != filters.rule_language:
        return False
    if filters.enabled is not None and (view.status == "active") != filters.enabled:
        return False
    if filters.mitre:
        wanted = filters.mitre.upper()
        if not any(wanted == t.upper() for t in view.mitre_techniques):
            return False
    if filters.search:
        needle = filters.search.lower()
        haystack = " ".join(
            [
                view.name,
                view.description or "",
                view.source_id or "",
                view.category,
                " ".join(view.tags),
                " ".join(view.mitre_techniques),
            ]
        ).lower()
        if needle not in haystack:
            return False
    return True


async def _stored_rows(db: AsyncSession, tenant_id: uuid.UUID) -> list[DetectionRule]:
    """Rules this tenant can see: its own, plus any platform-wide built-ins.

    The second half has never matched a row in Postgres —
    ``detection_rules.tenant_id`` is ``NOT NULL`` — and is kept because the
    predicate is what the readers have always used and a deployment migrated
    from somewhere else may hold such rows.
    """
    stmt = select(DetectionRule).where(
        or_(
            DetectionRule.tenant_id == tenant_id,
            DetectionRule.tenant_id.is_(None),
        )
    )
    return list((await db.execute(stmt)).scalars().all())


def _installed_at(sources: tuple[str, ...]) -> datetime:
    """When this deployment's copy of the compiled corpus was last written."""
    newest = 0.0
    for source in sources:
        try:
            newest = max(newest, Path(source).stat().st_mtime)
        except OSError:
            continue
    if not newest:
        return datetime.now(UTC)
    return datetime.fromtimestamp(newest, tz=UTC)


async def catalogue_page(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    *,
    filters: CatalogueFilters | None = None,
    limit: int | None = None,
    offset: int = 0,
) -> CataloguePage:
    """The tenant's effective rule library, filtered and paged.

    Ordering is deterministic — built-ins after the tenant's own rules, then
    by name — because a page boundary over an unordered set silently drops and
    repeats rows between requests.
    """
    filters = filters or CatalogueFilters()
    rows = await _stored_rows(db, tenant_id)

    views: list[RuleView] = []
    tuned_source_ids: set[str] = set()
    custom_total = 0
    for row in rows:
        view = row_view(row)
        if view.source_id:
            tuned_source_ids.add(view.source_id)
        else:
            custom_total += 1
        views.append(view)

    catalogue_error: str | None = None
    missing: list[str] = []
    builtin_total = 0
    try:
        catalogue = builtin_catalogue()
    except BuiltinCatalogueUnavailable as exc:
        catalogue_error = str(exc)
    else:
        missing = list(catalogue.missing)
        installed_at = _installed_at(catalogue.sources)
        builtin_total = len(catalogue.rules)
        for rule in catalogue.rules:
            if rule.source_id in tuned_source_ids:
                # The stored row is this tenant's decision about the rule and
                # already in `views`; adding the compiled projection beside it
                # would list the same rule twice with contradictory statuses.
                continue
            views.append(builtin_view(rule, tenant_id=tenant_id, installed_at=installed_at))

    if not filters.include_builtin:
        views = [v for v in views if not v.is_builtin]
    if not filters.include_custom:
        views = [v for v in views if v.is_builtin]

    matched = [v for v in views if _matches(v, filters)]
    matched.sort(key=lambda v: (v.is_builtin, v.name.lower(), str(v.id)))

    page = matched[offset:] if limit is None else matched[offset : offset + limit]

    return CataloguePage(
        rules=page,
        total=len(matched),
        builtin_total=builtin_total,
        custom_total=custom_total,
        catalogue_error=catalogue_error,
        missing_artefacts=missing,
    )


async def resolve_rule(db: AsyncSession, tenant_id: uuid.UUID, rule_id: uuid.UUID) -> RuleView | None:
    """One rule, stored row first, compiled catalogue second."""
    stmt = select(DetectionRule).where(
        DetectionRule.id == rule_id,
        or_(DetectionRule.tenant_id == tenant_id, DetectionRule.tenant_id.is_(None)),
    )
    row = (await db.execute(stmt)).scalar_one_or_none()
    if row is not None:
        return row_view(row)

    try:
        catalogue = builtin_catalogue()
    except BuiltinCatalogueUnavailable:
        return None
    rule = catalogue.by_uuid(tenant_id).get(rule_id)
    if rule is None:
        return None
    return builtin_view(rule, tenant_id=tenant_id, installed_at=_installed_at(catalogue.sources))


async def materialise_builtin(
    db: AsyncSession,
    rule: BuiltinRule,
    *,
    tenant_id: uuid.UUID,
    actor_id: uuid.UUID | None = None,
    actor_email: str | None = None,
) -> DetectionRule:
    """The tenant's row for a built-in, created on first write.

    Inserted under this tenant's console id for the rule, so the id the page
    already rendered keeps working, and carrying ``provenance.source_id`` so
    fusion's overlay query finds it. ``author`` is written because the overlay
    reports *who* silenced a rule when it explains a match that did not fire —
    "no alert" with no explanation is indistinguishable from a rule that
    simply did not match.

    The id is derived from the tenant as well as the rule. Two tenants tuning
    the same built-in need two rows, and ``detection_rules.id`` is a primary
    key: a shared id would mean the second tenant's insert finds the first
    tenant's row, their change lands on nothing, and their console renders
    somebody else's state.
    """
    rule_id = uuid_for(rule.source_id, tenant_id)
    existing = (
        await db.execute(select(DetectionRule).where(DetectionRule.id == rule_id, DetectionRule.tenant_id == tenant_id))
    ).scalar_one_or_none()
    if existing is not None:
        return existing

    now = datetime.now(UTC)
    row = DetectionRule(
        id=rule_id,
        tenant_id=tenant_id,
        name=rule.name,
        description=rule.description,
        rule_language=RULE_LANGUAGE,
        rule_body=rule.rule_body,
        category=rule.category,
        status="active",
        severity=rule.severity,
        confidence=UNMEASURED_CONFIDENCE,
        mitre_tactics=[],
        mitre_techniques=list(rule.mitre_techniques),
        tags=rule.tags,
        is_builtin=True,
        author=actor_email,
        provenance=_provenance(rule),
        created_by_id=actor_id,
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    await db.flush()
    return row


def _provenance(rule: BuiltinRule) -> dict[str, Any]:
    """What the row records about where the rule came from.

    ``source_id`` is load-bearing — it is the key fusion's overlay joins on —
    so it is written first and never derived from the name.
    """
    provenance: dict[str, Any] = {
        "source_id": rule.source_id,
        "source": "aisoc-builtin",
        "ruleset": rule.ruleset,
        "engine": rule.kind,
    }
    upstream = (rule.spec or {}).get("provenance")
    if isinstance(upstream, dict) and upstream:
        provenance["upstream"] = upstream
    return provenance
