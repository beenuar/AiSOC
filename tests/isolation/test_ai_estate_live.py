"""The AI inventory, written and read against a real PostgreSQL.

Depth plan 6.1's "Done when": *a fixture estate with one coding agent, one
MCP server and one provider key shows all three on the inventory page, linked
to the right person and device.*

Why this needs a live database rather than a double
---------------------------------------------------
Everything load-bearing here is a property of PostgreSQL rather than of the
Python:

* ``UNIQUE NULLS NOT DISTINCT`` is the reason a provider key — which has no
  device — coalesces onto one row instead of inserting one per sighting.
  Under the default NULL semantics every sighting is a new row and the
  inventory grows without bound while ``first_seen_at`` resets each time. A
  fake connection answers neither way.
* ``LEAST``/``GREATEST`` on conflict are what stop a replayed Kafka batch
  moving ``first_seen_at`` forward.
* The RLS policy is what stops one tenant reading another's estate, and it
  only applies when the connection is the DML-only ``aisoc_app`` role: a
  superuser walks past every policy even under ``FORCE ROW LEVEL SECURITY``.

The suite connects as ``aisoc_app`` for exactly that reason.

Run it with ``ISOLATION_AI_ESTATE_DSN`` pointing at a migrated database. It
is a hard failure, never a skip, when the variable is set — a live suite that
skips is a green check over nothing.
"""

from __future__ import annotations

import asyncio
import os
import sys
import uuid
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "services" / "fusion"))

DSN = os.environ.get("ISOLATION_AI_ESTATE_DSN")

pytestmark = [
    pytest.mark.skipif(not DSN, reason="ISOLATION_AI_ESTATE_DSN is not set"),
    pytest.mark.asyncio,
]

TENANT_A = "aaaaaaaa-0000-0000-0000-00000000000a"
TENANT_B = "bbbbbbbb-0000-0000-0000-00000000000b"


def _recorder_module():
    """Import the real recorder, not a reimplementation of it."""
    from app.services import ai_asset_recorder

    return ai_asset_recorder


def coding_agent_event(tenant: str) -> dict[str, Any]:
    """An `ai-runtime` span, placed per `templates/ai-runtime.yaml`."""
    return {
        "tenant_id": tenant,
        "ocsf_event": {
            "class_uid": 6003,
            "source_type": "ai-runtime",
            "activity_name": "search_siem",
            "actor": {
                "process": {"name": "agent-7f2", "path": "/usr/local/bin/claude"},
                "user": {"name": "ada@example.com"},
            },
            "src_endpoint": {"hostname": "ada-mbp"},
            "metadata": {"product": {"name": "AI Runtime", "feature": {"name": "claude-sonnet-4"}}},
            "cloud": {"provider": "anthropic"},
            "resource": {"name": "github-mcp"},
        },
    }


def provider_key_event(tenant: str) -> dict[str, Any]:
    """An OpenAI organization audit record, as `llm_usage` normalizes it."""
    return {
        "tenant_id": tenant,
        "ocsf_event": {
            "class_uid": 3001,
            "source_type": "llm_usage",
            "activity_name": "openai.api_key.created",
            "actor": {"user": {"name": "ada@example.com"}},
            "metadata": {"product": {"vendor_name": "OpenAI", "name": "AI / LLM Usage Audit"}},
            "finding": {"uid": "key_abc123"},
        },
    }


class _Pool:
    """A real asyncpg pool, opened per test and closed after it."""

    def __init__(self, pool: Any) -> None:
        self._pool = pool

    def acquire(self):  # noqa: ANN201
        return self._pool.acquire()


async def _connect(dsn: str) -> Any:
    # Imported here rather than at module scope, deliberately and against the
    # usual rule. `ci.yml`'s offline isolation job installs a minimal
    # dependency set and collects this whole directory; a module-scope
    # `import asyncpg` turns a suite that should skip into a **collection
    # error**, which took all 353 tests in that job down with it. The same
    # reason keeps the heavy imports inside fixtures in
    # `tests/isolation/test_scim_live.py`.
    import asyncpg

    return await asyncpg.create_pool(dsn, min_size=1, max_size=2)


async def _seed_tenants(pool: Any) -> None:
    async with pool.acquire() as conn:
        for tenant, slug in ((TENANT_A, "iso-ai-a"), (TENANT_B, "iso-ai-b")):
            await conn.execute(
                "INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING",
                uuid.UUID(tenant),
                f"AI estate {slug}",
                slug,
            )


async def _clear(pool: Any) -> None:
    async with pool.acquire() as conn:
        await conn.execute("DELETE FROM aisoc_ai_assets WHERE tenant_id = ANY($1::uuid[])", [uuid.UUID(TENANT_A), uuid.UUID(TENANT_B)])


@pytest_asyncio.fixture
async def pool():  # noqa: ANN201
    assert DSN, "ISOLATION_AI_ESTATE_DSN must be set"
    raw = await _connect(DSN)
    await _seed_tenants(raw)
    await _clear(raw)
    try:
        yield raw
    finally:
        await _clear(raw)
        await raw.close()


async def _rows(pool: Any, tenant: str) -> list[dict[str, Any]]:
    """Read the inventory the way the console route reads it."""
    async with pool.acquire() as conn:
        await conn.execute("SELECT set_config('app.current_tenant_id', $1, false)", tenant)
        records = await conn.fetch(
            "SELECT kind, external_id, display_name, vendor, discovery_source, principal, device, "
            "risk_score, first_seen_at, last_seen_at, observation_count "
            "FROM aisoc_ai_assets WHERE tenant_id = $1::uuid ORDER BY kind",
            tenant,
        )
        return [dict(r) for r in records]


async def test_fixture_estate_shows_all_three_kinds_linked(pool):
    """The plan's own acceptance condition, end to end."""
    mod = _recorder_module()
    recorder = mod.AiAssetRecorder(lambda: _Pool(pool))
    await recorder.observe(coding_agent_event(TENANT_A))
    await recorder.observe(provider_key_event(TENANT_A))
    written = await recorder.flush()
    assert written == 3, "expected a coding agent, an MCP server and a provider key"

    rows = await _rows(pool, TENANT_A)
    by_kind = {r["kind"]: r for r in rows}
    assert set(by_kind) == {"coding_agent", "mcp_server", "provider_key"}

    agent = by_kind["coding_agent"]
    assert agent["principal"] == "ada@example.com"
    assert agent["device"] == "ada-mbp"
    assert agent["vendor"] == "Anthropic"

    server = by_kind["mcp_server"]
    assert server["external_id"] == "github-mcp"
    assert server["device"] == "ada-mbp"

    key = by_kind["provider_key"]
    assert key["external_id"] == "key_abc123"
    assert key["principal"] == "ada@example.com"
    # Not "no device": the provider's audit log carries none, and the row
    # says so through its discovery source rather than through a blank.
    assert key["device"] is None
    assert key["discovery_source"] == "provider_audit"


async def test_a_deviceless_asset_coalesces_instead_of_multiplying(pool):
    """`UNIQUE NULLS NOT DISTINCT`, which is the whole reason it is named.

    Under PostgreSQL's default NULL semantics this asserts the defect: three
    rows for one key, each claiming to be first seen now.
    """
    mod = _recorder_module()
    for _ in range(3):
        recorder = mod.AiAssetRecorder(lambda: _Pool(pool))
        await recorder.observe(provider_key_event(TENANT_A))
        await recorder.flush()

    rows = [r for r in await _rows(pool, TENANT_A) if r["kind"] == "provider_key"]
    assert len(rows) == 1, f"expected one row for one key, got {len(rows)}"
    assert rows[0]["observation_count"] == 3


async def test_a_replayed_batch_cannot_move_first_seen_forward(pool):
    """LEAST/GREATEST on conflict, against a real timestamp comparison."""
    mod = _recorder_module()
    recorder = mod.AiAssetRecorder(lambda: _Pool(pool))
    await recorder.observe(coding_agent_event(TENANT_A))
    await recorder.flush()
    first = [r for r in await _rows(pool, TENANT_A) if r["kind"] == "coding_agent"][0]

    await asyncio.sleep(0.05)
    again = mod.AiAssetRecorder(lambda: _Pool(pool))
    await again.observe(coding_agent_event(TENANT_A))
    await again.flush()
    second = [r for r in await _rows(pool, TENANT_A) if r["kind"] == "coding_agent"][0]

    assert second["first_seen_at"] == first["first_seen_at"], "a replay moved first_seen_at"
    assert second["last_seen_at"] >= first["last_seen_at"]
    assert second["observation_count"] == 2


async def test_a_later_anonymous_sighting_does_not_erase_the_person(pool):
    """COALESCE in the UPDATE, proven against the real statement."""
    mod = _recorder_module()
    recorder = mod.AiAssetRecorder(lambda: _Pool(pool))
    await recorder.observe(coding_agent_event(TENANT_A))
    await recorder.flush()

    anonymous = coding_agent_event(TENANT_A)
    anonymous["ocsf_event"]["actor"].pop("user")
    later = mod.AiAssetRecorder(lambda: _Pool(pool))
    await later.observe(anonymous)
    await later.flush()

    agent = [r for r in await _rows(pool, TENANT_A) if r["kind"] == "coding_agent"][0]
    assert agent["principal"] == "ada@example.com"


async def test_one_tenant_cannot_read_anothers_ai_estate(pool):
    """Row-level security, as the DML-only runtime role sees it."""
    mod = _recorder_module()
    recorder = mod.AiAssetRecorder(lambda: _Pool(pool))
    await recorder.observe(coding_agent_event(TENANT_A))
    await recorder.observe(coding_agent_event(TENANT_B))
    await recorder.flush()

    async with pool.acquire() as conn:
        await conn.execute("SELECT set_config('app.current_tenant_id', $1, false)", TENANT_A)
        visible = await conn.fetch("SELECT tenant_id FROM aisoc_ai_assets")
    assert visible, "tenant A sees nothing at all, so this proves no isolation"
    assert {str(r["tenant_id"]) for r in visible} == {TENANT_A}
