"""Effective-rule resolver for MSSP per-tenant detection scoping.

Given a ``tenant_id``, returns the set of detection rules that should run
for that tenant after layering:

  1. The tenant's own rules            (``detection_rules.tenant_id = T``)
  2. Platform-wide built-in rules      (``tenant_id IS NULL AND is_builtin``)
  3. Rules sourced from packs assigned by an MSSP parent
  4. Per-tenant overrides              (``mssp_rule_overrides``)

Override semantics:
  * ``exclude``   -- drop the rule from the effective set
  * ``customize`` -- keep the rule but apply ``severity_override`` /
                     ``parameter_overrides`` on top of the base rule

The output is a list of :class:`ResolvedRule` instances - the same shape
the rule engine consumes (``id``, ``name``, ``rule_language``,
``rule_body``, ``severity``) plus provenance fields (``source``,
``pack_id``, ``parameter_overrides``) so callers can render where each
rule came from.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.detection_rule import DetectionRule
from app.models.mssp import (
    MSSPRuleOverride,
    MSSPRulePackAssignment,
    MSSPRulePackRule,
)


# ---------------------------------------------------------------------------
# Public dataclass
# ---------------------------------------------------------------------------


@dataclass
class ResolvedRule:
    """A detection rule expanded into its tenant-effective form.

    The rule engine only cares about ``id`` / ``name`` /
    ``rule_language`` / ``rule_body`` / ``severity``; everything else is
    provenance returned for UI surfacing and audit.
    """

    id: uuid.UUID
    name: str
    rule_language: str
    rule_body: str
    severity: str
    category: str | None = None
    status: str = "active"
    is_builtin: bool = False
    # Provenance: where did this rule end up in the effective set?
    #   - "tenant"   tenant authored it directly
    #   - "builtin"  platform-wide built-in rule
    #   - "pack"     supplied by an MSSP-assigned pack
    source: str = "tenant"
    pack_ids: list[uuid.UUID] = field(default_factory=list)
    # Final parameter overrides merged from pack-assignment + per-rule override.
    parameter_overrides: dict[str, Any] = field(default_factory=dict)
    # Was severity changed by an override?
    severity_overridden: bool = False
    original_severity: str | None = None
    override_note: str | None = None

    def to_engine_dict(self) -> dict[str, Any]:
        """Reduce to the dict shape ``rule_engine.run_hunt`` expects."""
        return {
            "id": str(self.id),
            "name": self.name,
            "rule_language": self.rule_language,
            "rule_body": self.rule_body,
            "severity": self.severity,
        }


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------


async def resolve_effective_rules(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    *,
    include_builtin: bool = True,
    include_packs: bool = True,
    rule_ids: list[uuid.UUID] | None = None,
    rule_language: str | None = None,
    category: str | None = None,
    only_active: bool = True,
) -> list[ResolvedRule]:
    """Resolve the effective detection ruleset for ``tenant_id``.

    Args:
        db: An async DB session.
        tenant_id: Child tenant we are resolving for.
        include_builtin: Include platform-wide built-in rules.
        include_packs: Layer in pack-sourced rules from the MSSP parent.
            Disable when the caller wants the raw "tenant + builtin" view
            (e.g. the rule editor showing what *this* tenant authored).
        rule_ids: Optional allowlist; if set, restrict the result to
            these rule ids regardless of source.
        rule_language: Optional language filter (sigma, kql, eql, ...).
        category: Optional category filter.
        only_active: If True, drop rules whose ``status != "active"``.

    Returns:
        A list of :class:`ResolvedRule`, deduplicated by rule id, with
        the tenant's own rules taking precedence over pack/builtin sources.
    """

    # 1. Direct rules: tenant-owned + (optionally) platform built-ins.
    direct_filters: list[Any] = []
    direct_filters.append(
        or_(
            DetectionRule.tenant_id == tenant_id,
            and_(DetectionRule.tenant_id.is_(None), DetectionRule.is_builtin.is_(True))
            if include_builtin
            else DetectionRule.tenant_id == tenant_id,
        )
    )
    if only_active:
        direct_filters.append(DetectionRule.status == "active")
    if rule_ids:
        direct_filters.append(DetectionRule.id.in_(rule_ids))
    if rule_language:
        direct_filters.append(DetectionRule.rule_language == rule_language)
    if category:
        direct_filters.append(DetectionRule.category == category)

    direct_q = select(DetectionRule).where(and_(*direct_filters))
    direct_rows = (await db.execute(direct_q)).scalars().all()

    resolved: dict[uuid.UUID, ResolvedRule] = {}
    for r in direct_rows:
        source = "builtin" if r.tenant_id is None and r.is_builtin else "tenant"
        resolved[r.id] = ResolvedRule(
            id=r.id,
            name=r.name,
            rule_language=r.rule_language,
            rule_body=r.rule_body,
            severity=r.severity,
            category=r.category,
            status=r.status,
            is_builtin=r.is_builtin,
            source=source,
            original_severity=r.severity,
        )

    # 2. Pack-sourced rules: walk the assignments → pack contents → rules.
    pack_assignment_by_rule: dict[uuid.UUID, list[tuple[uuid.UUID, dict[str, Any]]]] = {}
    if include_packs:
        assignments_q = select(MSSPRulePackAssignment).where(
            MSSPRulePackAssignment.child_tenant_id == tenant_id,
            MSSPRulePackAssignment.enabled.is_(True),
        )
        assignments = (await db.execute(assignments_q)).scalars().all()

        if assignments:
            pack_id_to_overrides: dict[uuid.UUID, dict[str, Any]] = {
                a.pack_id: dict(a.parameter_overrides or {}) for a in assignments
            }

            pack_rule_filters: list[Any] = [
                MSSPRulePackRule.pack_id.in_(list(pack_id_to_overrides.keys())),
            ]
            pack_rule_join_filters: list[Any] = []
            if only_active:
                pack_rule_join_filters.append(DetectionRule.status == "active")
            if rule_ids:
                pack_rule_join_filters.append(DetectionRule.id.in_(rule_ids))
            if rule_language:
                pack_rule_join_filters.append(DetectionRule.rule_language == rule_language)
            if category:
                pack_rule_join_filters.append(DetectionRule.category == category)

            pack_q = (
                select(MSSPRulePackRule.pack_id, DetectionRule)
                .join(DetectionRule, DetectionRule.id == MSSPRulePackRule.rule_id)
                .where(and_(*pack_rule_filters, *pack_rule_join_filters))
            )
            for pack_id, rule in (await db.execute(pack_q)).all():
                pack_overrides = pack_id_to_overrides.get(pack_id, {})
                pack_assignment_by_rule.setdefault(rule.id, []).append((pack_id, pack_overrides))
                if rule.id in resolved:
                    # Tenant or builtin row already takes the slot; just
                    # note that this rule is also covered by a pack so
                    # the UI can show the dual provenance.
                    resolved[rule.id].pack_ids.append(pack_id)
                    if pack_overrides:
                        merged = dict(resolved[rule.id].parameter_overrides)
                        merged.update(pack_overrides)
                        resolved[rule.id].parameter_overrides = merged
                else:
                    resolved[rule.id] = ResolvedRule(
                        id=rule.id,
                        name=rule.name,
                        rule_language=rule.rule_language,
                        rule_body=rule.rule_body,
                        severity=rule.severity,
                        category=rule.category,
                        status=rule.status,
                        is_builtin=rule.is_builtin,
                        source="pack",
                        pack_ids=[pack_id],
                        parameter_overrides=dict(pack_overrides),
                        original_severity=rule.severity,
                    )

    if not resolved:
        return []

    # 3. Apply per-tenant overrides (exclude / customize).
    overrides_q = select(MSSPRuleOverride).where(
        MSSPRuleOverride.child_tenant_id == tenant_id,
        MSSPRuleOverride.rule_id.in_(list(resolved.keys())),
    )
    overrides = (await db.execute(overrides_q)).scalars().all()

    for ov in overrides:
        rr = resolved.get(ov.rule_id)
        if rr is None:
            continue
        if ov.action == "exclude":
            resolved.pop(ov.rule_id, None)
            continue
        # action == 'customize'
        if ov.severity_override:
            rr.severity_overridden = True
            rr.severity = ov.severity_override
        if ov.parameter_overrides:
            merged = dict(rr.parameter_overrides)
            merged.update(ov.parameter_overrides)
            rr.parameter_overrides = merged
        if ov.note:
            rr.override_note = ov.note

    return list(resolved.values())


async def count_effective_rules(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    *,
    include_builtin: bool = True,
    include_packs: bool = True,
) -> dict[str, int]:
    """Lightweight counter used by dashboards.

    Returns a dict like ``{"total": 412, "tenant": 14, "builtin": 380, "pack": 18, "excluded": 4}``.
    """

    rules = await resolve_effective_rules(
        db,
        tenant_id,
        include_builtin=include_builtin,
        include_packs=include_packs,
        only_active=False,
    )

    excluded_q = select(MSSPRuleOverride).where(
        MSSPRuleOverride.child_tenant_id == tenant_id,
        MSSPRuleOverride.action == "exclude",
    )
    excluded_count = len((await db.execute(excluded_q)).scalars().all())

    counts = {"total": len(rules), "tenant": 0, "builtin": 0, "pack": 0, "excluded": excluded_count}
    for r in rules:
        counts[r.source] = counts.get(r.source, 0) + 1
    return counts
