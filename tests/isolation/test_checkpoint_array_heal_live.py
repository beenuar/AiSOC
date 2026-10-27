"""A checkpoint write heals the array a previous release left in the column.

The array shape was produced by the double-encoded ``record_checkpoint`` bind
(and kept alive by every later ``||`` merge, which appends to an array rather
than setting a key). ``_recover_connector_config`` recovers it on *read*, but
the column itself never healed: an upgraded deployment stayed corrupt in
Postgres, each poll appended one more element, and any consumer that
validates ``connector_config`` strictly (``ConnectorResponse``) answered 500
for the whole connectors list.

These tests run ``record_checkpoint`` against real Postgres and assert on the
raw column — a fake engine that records the dict it was handed cannot observe
either the append or the heal.
"""

from __future__ import annotations

import json
import os
import uuid
from typing import Any

import pytest
import pytest_asyncio

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_CONNECTOR_DSN", "").strip(),
        reason="ISOLATION_CONNECTOR_DSN is not set; this suite needs live infrastructure",
    ),
]


def _dsn() -> str:
    value = os.environ.get("ISOLATION_CONNECTOR_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_CONNECTOR_DSN is not set; this suite needs a live Postgres")
    return value


@pytest_asyncio.fixture(scope="module")
async def engine():  # noqa: ANN201
    from sqlalchemy.ext.asyncio import create_async_engine

    created = create_async_engine(_dsn(), future=True)
    yield created
    await created.dispose()


@pytest_asyncio.fixture()
async def connector_row(engine):  # noqa: ANN001, ANN201
    """A connector row, with teardown. ``config`` seeds connector_config raw."""
    import sqlalchemy

    tenant_id = uuid.uuid4()
    connector_id = uuid.uuid4()
    async with engine.begin() as conn:
        await conn.execute(
            sqlalchemy.text(
                "INSERT INTO tenants (id, name, slug) VALUES (:i, :n, :s) ON CONFLICT DO NOTHING"
            ),
            {"i": tenant_id, "n": f"h-{tenant_id.hex[:8]}", "s": f"h-{tenant_id.hex[:8]}"},
        )
    yield {"tenant_id": tenant_id, "connector_id": connector_id}
    async with engine.begin() as conn:
        await conn.execute(
            sqlalchemy.text("DELETE FROM connectors WHERE tenant_id = :t"),
            {"t": tenant_id},
        )
        await conn.execute(
            sqlalchemy.text("DELETE FROM tenants WHERE id = :i"),
            {"i": tenant_id},
        )


async def _seed_config(engine, row: dict[str, Any], config: Any) -> None:  # noqa: ANN001
    import sqlalchemy

    async with engine.begin() as conn:
        await conn.execute(
            sqlalchemy.text(
                "INSERT INTO connectors "
                "(id, tenant_id, connector_type, name, is_enabled, auth_config, connector_config) "
                "VALUES (:i, :t, 'splunk', 'heal-me', true, :a, :c)"
            ),
            {
                "i": row["connector_id"],
                "t": row["tenant_id"],
                "a": json.dumps({"token": "***"}),
                "c": json.dumps(config),
            },
        )


async def _raw_config(engine, row: dict[str, Any]) -> Any:  # noqa: ANN001
    import sqlalchemy

    async with engine.begin() as conn:
        result = await conn.execute(
            sqlalchemy.text(
                "SELECT connector_config::text FROM connectors WHERE id = :i"
            ),
            {"i": row["connector_id"]},
        )
        return json.loads(result.scalar_one())


async def test_checkpoint_heals_legacy_array_column(engine, connector_row) -> None:  # noqa: ANN001
    """The exact shape the old binder produced is rewritten to an object."""
    from app.db.connector_repo import record_checkpoint

    legacy = [
        {"poll_interval_seconds": 120, "filter_rules": ["a"]},
        json.dumps({"checkpoint": {"time": "2026-10-27T17:45:00Z", "id": "old"}}),
        {"checkpoint": {"time": "2026-10-27T17:58:00Z", "id": "newer"}},
    ]
    await _seed_config(engine, connector_row, legacy)

    new_checkpoint = {"time": "2026-10-27T20:00:00Z", "id": "healed"}
    async with engine.begin() as conn:
        await record_checkpoint(conn, connector_row["connector_id"], new_checkpoint)

    config = await _raw_config(engine, connector_row)
    assert isinstance(config, dict), f"column must be an object after the write, got {type(config)}"
    # Everything from every object element survives the fold, and the fresh
    # checkpoint wins over the recovered ones.
    assert config["poll_interval_seconds"] == 120
    assert config["filter_rules"] == ["a"]
    assert config["checkpoint"] == new_checkpoint


async def test_checkpoint_on_clean_object_is_unchanged_shape(engine, connector_row) -> None:  # noqa: ANN001
    """The heal must not disturb the healthy path: object in, object out."""
    from app.db.connector_repo import record_checkpoint

    await _seed_config(engine, connector_row, {"poll_interval_seconds": 300})

    checkpoint = {"seen": ["m1", "m2"]}
    async with engine.begin() as conn:
        await record_checkpoint(conn, connector_row["connector_id"], checkpoint)

    config = await _raw_config(engine, connector_row)
    assert config == {"poll_interval_seconds": 300, "checkpoint": checkpoint}


async def test_heal_is_stable_across_repeated_polls(engine, connector_row) -> None:  # noqa: ANN001
    """Two polls after a heal must not grow the column — the appending stops."""
    from app.db.connector_repo import record_checkpoint

    await _seed_config(engine, connector_row, {"poll_interval_seconds": 60})
    for cursor in ("c1", "c2"):
        async with engine.begin() as conn:
            await record_checkpoint(conn, connector_row["connector_id"], {"id": cursor})

    config = await _raw_config(engine, connector_row)
    assert isinstance(config, dict)
    assert config["checkpoint"] == {"id": "c2"}
    assert sorted(config.keys()) == ["checkpoint", "poll_interval_seconds"]
