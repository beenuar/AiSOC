"""Two Postgres truths on the SIEM content governance arm.

Both are regressions in the shipped migration-180 surface:

* **Refresh selection** filtered connectors on a non-existent
  ``Connector.enabled`` (the model's flag is ``is_enabled``), so every
  "Refresh inventory" raised AttributeError and 500'd before it could even
  report "no connector connected".
* **Tuning proposals** were inserted without ``proposed_by_id``. The
  detection-proposal promote path bars the author from approving their own
  proposal, but that check is guarded by ``proposed_by_id IS NOT NULL`` — so
  these proposals skipped it and a reviewer could approve their own change to
  the customer's SIEM.

Why live: the connector filter is the ORM against real columns, and the
author must land in a real ``detection_rule_proposals`` row for the promote
path's separation-of-duties rule to have anything to compare.

Environment: ISOLATION_SIEM_CONTENT_DSN (aisoc_app) +
ISOLATION_SIEM_CONTENT_ADMIN_DSN (owner, fixtures).
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

import pytest
import pytest_asyncio

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_SIEM_CONTENT_DSN", "").strip(),
        reason="ISOLATION_SIEM_CONTENT_DSN is not set; this suite needs a live Postgres",
    ),
]

_API = Path(__file__).resolve().parents[2] / "services" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

TENANT = uuid.uuid4()
ACTOR = uuid.uuid4()
ACTOR_EMAIL = "l2-analyst@example.test"


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def pools():
    import asyncpg

    admin = await asyncpg.connect(os.environ["ISOLATION_SIEM_CONTENT_ADMIN_DSN"].strip())
    suffix = uuid.uuid4().hex[:8]
    await admin.execute(
        "INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2) ON CONFLICT DO NOTHING",
        TENANT,
        f"sc-gov-{suffix}",
    )
    await admin.execute(
        """
        INSERT INTO users (id, tenant_id, email, username, hashed_password)
        VALUES ($1, $2, $3, $4, 'x') ON CONFLICT DO NOTHING
        """,
        ACTOR,
        TENANT,
        ACTOR_EMAIL,
        f"l2-{suffix}",
    )
    yield admin
    await admin.execute("DELETE FROM detection_rule_proposals WHERE tenant_id = $1", TENANT)
    await admin.execute("DELETE FROM connectors WHERE tenant_id = $1", TENANT)
    await admin.execute("DELETE FROM users WHERE id = $1", ACTOR)
    await admin.execute("DELETE FROM tenants WHERE id = $1", TENANT)
    await admin.close()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def session_factory():
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    dsn = os.environ["ISOLATION_SIEM_CONTENT_ADMIN_DSN"].strip().replace("postgresql://", "postgresql+asyncpg://")
    engine = create_async_engine(dsn, poolclass=None)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


async def test_refresh_selects_only_enabled_content_connectors(pools, session_factory):
    """The refresh selection returns enabled Splunk/Elastic connectors for the
    tenant and skips disabled ones and non-content types — it no longer touches
    a non-existent ``Connector.enabled``."""
    from app.services import siem_content as svc

    splunk_on = uuid.uuid4()
    elastic_off = uuid.uuid4()
    okta_on = uuid.uuid4()
    await pools.execute(
        """
        INSERT INTO connectors (id, tenant_id, name, connector_type, is_enabled)
        VALUES ($1, $2, 'splunk-on', 'splunk', true),
               ($3, $2, 'elastic-off', 'elastic', false),
               ($4, $2, 'okta-on', 'okta', true)
        """,
        splunk_on,
        TENANT,
        elastic_off,
        okta_on,
    )
    async with session_factory() as db:
        conns = await svc.content_capable_connectors(db, tenant_id=TENANT)
    assert {(str(c.id), c.connector_type) for c in conns} == {(str(splunk_on), "splunk")}


async def test_tuning_proposal_records_its_author_for_separation_of_duties(pools, session_factory):
    """A SIEM-tuning proposal must record ``proposed_by_id`` so the promote
    path's author-is-not-approver rule applies — without it that rule (guarded
    by ``proposed_by_id IS NOT NULL``) is silently skipped."""
    from app.services import siem_content as svc

    async with session_factory() as db:
        pid = await svc.record_tuning_proposal(
            db,
            tenant_id=TENANT,
            author_id=ACTOR,
            connector_type="splunk",
            vendor_rule_id="Threat - Brute Force - Rule",
            change="threshold",
            rationale="too noisy on service accounts",
            target_name="Brute Force",
            proposed_content="",
        )
        await db.commit()
    row = await pools.fetchrow("SELECT proposed_by_id, status, source FROM detection_rule_proposals WHERE id = $1", pid)
    assert str(row["proposed_by_id"]) == str(ACTOR), "the author must be recorded or SoD is skipped"
    assert row["status"] == "draft" and row["source"] == "siem-tuning"
