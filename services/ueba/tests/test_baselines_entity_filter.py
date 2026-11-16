"""`GET /baselines` server-side entity filter + peer_group_id exposure (#1929).

The list endpoint used to offer only ``entity_type`` + ``limit`` (cap 200),
so a caller interested in *one* entity had to fetch the newest page and
filter client-side — any entity outside the most recently updated rows was
unreachable. The agents context bundle hit exactly that truncation once a
deployment accumulated more baselines than one page.

``peer_group_id`` has been on the ORM model all along; ``BaselineOut`` now
exposes it so the bundle can carry peer-group context into triage.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.routes import BaselineOut, list_baselines
from app.security.tenant_scope import TenantPrincipal

TENANT = uuid.UUID("aaaaaaaa-0000-0000-0000-00000000000a")


def _principal() -> TenantPrincipal:
    return TenantPrincipal(tenant_ids=frozenset({TENANT}), subject="svc", delegated=True)


def _db(captured: list[Any]) -> MagicMock:
    db = MagicMock()

    async def _execute(stmt: Any) -> MagicMock:
        captured.append(stmt)
        result = MagicMock()
        result.scalars.return_value.all.return_value = []
        return result

    db.execute = AsyncMock(side_effect=_execute)
    return db


@pytest.mark.asyncio
async def test_entity_id_filters_server_side() -> None:
    captured: list[Any] = []
    await list_baselines(
        db=_db(captured),
        principal=_principal(),
        tenant_id=None,
        entity_type="device",
        entity_id="web-01",
        limit=1,
    )
    assert len(captured) == 1
    sql = str(captured[0]).lower()
    assert "entity_id" in sql, "entity_id predicate missing from the SELECT"
    params = captured[0].compile().params
    assert params.get("entity_id_1") == "web-01"
    assert params.get("entity_type_1") == "device"


@pytest.mark.asyncio
async def test_omitted_entity_id_keeps_list_semantics() -> None:
    captured: list[Any] = []
    await list_baselines(
        db=_db(captured),
        principal=_principal(),
        tenant_id=None,
        entity_type=None,
        entity_id=None,
        limit=50,
    )
    sql = str(captured[0]).lower()
    assert "entity_id" not in sql.split("where", 1)[1], "no entity_id predicate expected when the filter is omitted"


def test_baseline_out_exposes_peer_group_id() -> None:
    now = datetime.now(UTC)
    row = SimpleNamespace(
        id=uuid.uuid4(),
        tenant_id=TENANT,
        entity_type="device",
        entity_id="web-01",
        feature_stats={"logon_count": {"mean": 4.2, "std": 1.1, "count": 30}},
        peer_group_id="pg-webservers",
        window_start=now,
        window_end=now,
    )
    assert BaselineOut.model_validate(row).peer_group_id == "pg-webservers"


def test_baseline_out_defaults_peer_group_to_none() -> None:
    """Rows written before peer grouping stay serialisable."""
    now = datetime.now(UTC)
    row = SimpleNamespace(
        id=uuid.uuid4(),
        tenant_id=TENANT,
        entity_type="user",
        entity_id="svc-deploy",
        feature_stats={},
        peer_group_id=None,
        window_start=now,
        window_end=now,
    )
    assert BaselineOut.model_validate(row).peer_group_id is None
