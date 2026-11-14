"""The worker reads console-authored rules from the real table, per tenant.

`_load_tenant_rules` connects with asyncpg and reads
``aisoc_business_context_rule_sets`` — the row the api's
``POST /v1/business-context/rules`` writes. The table name, the
``(tenant_id)`` lookup and the ``yaml_text``/``enabled`` columns are schema
facts; the per-tenant suites prove the engine against seeded rules, and this
leg proves the read path against the real migration chain, which is the
boundary a seeded-rules double cannot see.

Skips without a database rather than passing without one.
"""

from __future__ import annotations

import os
import uuid

import pytest

try:
    import asyncpg
except ImportError:  # pragma: no cover
    asyncpg = None

from app.workers.business_context import BusinessContextApplier

DSN = (os.environ.get("DATABASE_URL", "") or "").strip().replace("postgresql+asyncpg://", "postgresql://")
REQUIRED = os.environ.get("MSSP_ISOLATION_REQUIRED", "").strip() not in ("", "0", "false")

TENANT = uuid.UUID("0e700000-0000-0000-0000-0000000000ce")
OTHER = uuid.UUID("0e700000-0000-0000-0000-0000000000cf")

RULES_YAML = """
rules:
  - id: live-prod-bump
    priority: 10
    when:
      field: hostname
      op: startswith
      value: prod-
    then:
      set_severity: critical
      tag: prod-asset
"""

# `integration`: drives the real asyncpg client against a real migration
# chain — the conftest's no-ambient-database guard waves this suite through.
pytestmark = [pytest.mark.asyncio, pytest.mark.integration]


@pytest.fixture
async def seeded_db(monkeypatch):
    if asyncpg is None or "postgres" not in DSN:
        if REQUIRED:
            pytest.fail("MSSP_ISOLATION_REQUIRED is set and DATABASE_URL names no Postgres")
        pytest.skip("needs a live Postgres with the migration chain applied (integration.yml)")
    try:
        conn = await asyncpg.connect(DSN, timeout=5.0)
    except Exception as exc:
        if REQUIRED:
            pytest.fail(f"MSSP_ISOLATION_REQUIRED is set and no database answered: {type(exc).__name__}: {exc}")
        pytest.skip(f"no database at DATABASE_URL ({type(exc).__name__}) — runs in integration.yml")

    monkeypatch.setenv("DATABASE_URL", DSN)
    try:
        for tid, slug in ((TENANT, "bc-live-a"), (OTHER, "bc-live-b")):
            await conn.execute(
                "INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING",
                tid,
                f"BC live {slug}",
                slug,
            )
        await conn.execute(
            """
            INSERT INTO aisoc_business_context_rule_sets (tenant_id, yaml_text, enabled)
            VALUES ($1, $2, TRUE)
            ON CONFLICT (tenant_id) DO UPDATE SET yaml_text = EXCLUDED.yaml_text, enabled = TRUE
            """,
            TENANT,
            RULES_YAML,
        )
        yield conn
        await conn.execute("DELETE FROM aisoc_business_context_rule_sets WHERE tenant_id IN ($1, $2)", TENANT, OTHER)
    finally:
        await conn.close()


async def test_a_saved_rule_applies_to_this_tenants_alert(seeded_db) -> None:
    applier = BusinessContextApplier(rules_file="")  # no file rules — Postgres only
    result = await applier.apply_for_tenant(
        str(TENANT),
        {"id": "a1", "severity": "medium", "hostname": "prod-web-01"},
    )
    assert "live-prod-bump" in result.matched_rule_ids
    assert result.alert["severity"] == "critical"
    assert "prod-asset" in result.alert["tags"]


async def test_another_tenant_gets_nothing(seeded_db) -> None:
    """The lookup is per tenant: a tenant with no saved row applies no rules,
    and never another tenant's."""
    applier = BusinessContextApplier(rules_file="")
    result = await applier.apply_for_tenant(
        str(OTHER),
        {"id": "a1", "severity": "medium", "hostname": "prod-web-01"},
    )
    assert result.matched_rule_ids == []
    assert result.alert["severity"] == "medium"


async def test_a_disabled_rule_set_applies_nothing(seeded_db) -> None:
    await seeded_db.execute(
        "UPDATE aisoc_business_context_rule_sets SET enabled = FALSE WHERE tenant_id = $1",
        TENANT,
    )
    applier = BusinessContextApplier(rules_file="")  # fresh instance: no cache
    result = await applier.apply_for_tenant(
        str(TENANT),
        {"id": "a1", "severity": "medium", "hostname": "prod-web-01"},
    )
    assert result.matched_rule_ids == []
    assert result.alert["severity"] == "medium"
