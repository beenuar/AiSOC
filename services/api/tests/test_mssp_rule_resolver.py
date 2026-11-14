"""Tests for Tier 3.2 — MSSP per-tenant detection scoping.

Validates the rule resolver logic that combines tenant-owned,
built-in, and pack-assigned rules, applies exclude / customize
overrides, and deduplicates.

These tests run against an in-process SQLite/mock AsyncSession
(no live Postgres required) by constructing ORM objects in memory.
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.services.mssp_rule_resolver import (
    ResolvedRule,
    resolve_effective_rules,
)

# ---------------------------------------------------------------------------
# Helpers — tiny fakes for ORM rows
# ---------------------------------------------------------------------------


def _rule(
    *,
    rid: uuid.UUID | None = None,
    tenant_id: uuid.UUID | None = None,
    name: str = "test-rule",
    rule_language: str = "sigma",
    rule_body: str = "detection: ...",
    severity: str = "medium",
    category: str = "endpoint",
    status: str = "active",
    is_builtin: bool = False,
):
    """Return a fake DetectionRule-like row."""
    obj = MagicMock()
    obj.id = rid or uuid.uuid4()
    obj.tenant_id = tenant_id
    obj.name = name
    obj.rule_language = rule_language
    obj.rule_body = rule_body
    obj.severity = severity
    obj.category = category
    obj.status = status
    obj.is_builtin = is_builtin
    return obj


def _assignment(
    pack_id: uuid.UUID,
    child_tenant_id: uuid.UUID,
    enabled: bool = True,
    parameter_overrides: dict | None = None,
):
    obj = MagicMock()
    obj.pack_id = pack_id
    obj.child_tenant_id = child_tenant_id
    obj.enabled = enabled
    obj.parameter_overrides = parameter_overrides or {}
    return obj


def _pack_rule(pack_id: uuid.UUID, rule_id: uuid.UUID):
    obj = MagicMock()
    obj.pack_id = pack_id
    obj.rule_id = rule_id
    return obj


def _override(
    child_tenant_id: uuid.UUID,
    rule_id: uuid.UUID,
    action: str = "exclude",
    severity_override: str | None = None,
    parameter_overrides: dict | None = None,
    note: str | None = None,
):
    obj = MagicMock()
    obj.child_tenant_id = child_tenant_id
    obj.rule_id = rule_id
    obj.action = action
    obj.severity_override = severity_override
    obj.parameter_overrides = parameter_overrides or {}
    obj.note = note
    return obj


# ---------------------------------------------------------------------------
# ResolvedRule unit tests
# ---------------------------------------------------------------------------


class TestResolvedRule:
    def test_to_engine_dict(self):
        rid = uuid.uuid4()
        rr = ResolvedRule(
            id=rid,
            name="test",
            rule_language="sigma",
            rule_body="detection: ...",
            severity="high",
        )
        d = rr.to_engine_dict()
        assert d["id"] == str(rid)
        assert d["name"] == "test"
        assert d["rule_language"] == "sigma"
        assert d["severity"] == "high"

    def test_defaults(self):
        rr = ResolvedRule(
            id=uuid.uuid4(),
            name="x",
            rule_language="sigma",
            rule_body="...",
            severity="low",
        )
        assert rr.source == "tenant"
        assert rr.pack_ids == []
        assert rr.parameter_overrides == {}
        assert rr.severity_overridden is False
        assert rr.override_note is None


# ---------------------------------------------------------------------------
# Integration-style tests (mock db.execute for resolve_effective_rules)
# ---------------------------------------------------------------------------


def _mock_session(execute_results: list):
    """Build a mock AsyncSession that yields *execute_results* in order."""
    db = AsyncMock()
    call_counter = {"n": 0}

    async def _execute(stmt):
        idx = call_counter["n"]
        call_counter["n"] += 1
        result = MagicMock()
        if idx < len(execute_results):
            data = execute_results[idx]
        else:
            data = []
        scalars_mock = MagicMock()
        scalars_mock.all.return_value = data
        result.scalars.return_value = scalars_mock
        result.all.return_value = data
        return result

    db.execute = _execute
    return db


class TestResolveEffectiveRules:
    @pytest.mark.asyncio
    async def test_tenant_rules_only(self):
        tid = uuid.uuid4()
        r1 = _rule(tenant_id=tid, name="r1")
        db = _mock_session(
            [
                [r1],  # direct rules query
            ]
        )
        resolved = await resolve_effective_rules(db, tid, include_packs=False)
        assert len(resolved) == 1
        assert resolved[0].name == "r1"
        assert resolved[0].source == "tenant"

    @pytest.mark.asyncio
    async def test_builtin_rules_included(self):
        tid = uuid.uuid4()
        r1 = _rule(tenant_id=tid, name="tenant-rule")
        b1 = _rule(tenant_id=None, name="builtin-rule", is_builtin=True)
        db = _mock_session(
            [
                [r1, b1],  # direct rules query
            ]
        )
        resolved = await resolve_effective_rules(db, tid, include_packs=False)
        assert len(resolved) == 2
        sources = {r.source for r in resolved}
        assert sources == {"tenant", "builtin"}

    @pytest.mark.asyncio
    async def test_builtin_excluded(self):
        tid = uuid.uuid4()
        r1 = _rule(tenant_id=tid, name="tenant-rule")
        db = _mock_session(
            [
                [r1],  # direct rules query (no builtins)
            ]
        )
        resolved = await resolve_effective_rules(db, tid, include_builtin=False, include_packs=False)
        assert len(resolved) == 1
        assert resolved[0].source == "tenant"

    @pytest.mark.asyncio
    async def test_pack_rules_merged(self):
        tid = uuid.uuid4()
        pack_id = uuid.uuid4()
        r1 = _rule(tenant_id=tid, name="tenant-rule")
        pr1 = _rule(name="pack-rule")

        assignment = _assignment(pack_id, tid)

        db = _mock_session(
            [
                [r1],  # direct rules
                [assignment],  # pack assignments
                [(pack_id, pr1)],  # pack rule join results
                [],  # overrides
            ]
        )
        resolved = await resolve_effective_rules(db, tid)
        assert len(resolved) == 2
        pack_rules = [r for r in resolved if r.source == "pack"]
        assert len(pack_rules) == 1
        assert pack_rules[0].name == "pack-rule"

    @pytest.mark.asyncio
    async def test_exclude_override_drops_rule(self):
        tid = uuid.uuid4()
        r1 = _rule(tenant_id=tid, name="should-stay")
        r2 = _rule(tenant_id=tid, name="should-drop")

        override = _override(tid, r2.id, action="exclude")

        db = _mock_session(
            [
                [r1, r2],  # direct rules
                [],  # overrides
            ]
        )
        # Manually wire override into the third call
        call_counter = {"n": 0}
        original_execute = db.execute

        async def patched_execute(stmt):
            call_counter["n"] += 1
            if call_counter["n"] == 2:
                result = MagicMock()
                scalars_mock = MagicMock()
                scalars_mock.all.return_value = [override]
                result.scalars.return_value = scalars_mock
                return result
            return await original_execute(stmt)

        db.execute = patched_execute
        resolved = await resolve_effective_rules(db, tid, include_packs=False)
        assert len(resolved) == 1
        assert resolved[0].name == "should-stay"

    @pytest.mark.asyncio
    async def test_customize_override_changes_severity(self):
        tid = uuid.uuid4()
        r1 = _rule(tenant_id=tid, name="adjustable", severity="medium")

        override = _override(
            tid,
            r1.id,
            action="customize",
            severity_override="critical",
            note="escalated per SOC policy",
        )

        call_counter = {"n": 0}

        async def _execute(stmt):
            call_counter["n"] += 1
            result = MagicMock()
            scalars_mock = MagicMock()
            if call_counter["n"] == 1:
                scalars_mock.all.return_value = [r1]
            elif call_counter["n"] == 2:
                scalars_mock.all.return_value = [override]
            else:
                scalars_mock.all.return_value = []
            result.scalars.return_value = scalars_mock
            result.all.return_value = scalars_mock.all.return_value
            return result

        db = AsyncMock()
        db.execute = _execute

        resolved = await resolve_effective_rules(db, tid, include_packs=False)
        assert len(resolved) == 1
        assert resolved[0].severity == "critical"
        assert resolved[0].severity_overridden is True
        assert resolved[0].original_severity == "medium"
        assert resolved[0].override_note == "escalated per SOC policy"

    @pytest.mark.asyncio
    async def test_empty_tenant(self):
        tid = uuid.uuid4()
        db = _mock_session(
            [
                [],  # no direct rules
            ]
        )
        resolved = await resolve_effective_rules(db, tid, include_packs=False)
        assert resolved == []
