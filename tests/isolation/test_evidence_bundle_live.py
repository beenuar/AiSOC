"""An evidence bundle exported from the real route, against real Postgres.

Parity 3.7. `services/api/tests/test_evidence_bundle.py` proves the
format: deterministic, tamper-evident, prompts hashed. It builds its
bundles from dicts, so it cannot show that the *route* assembles one
correctly from ledger rows, that the export is tenant-scoped, or that a
bundle survives the trip through SQLAlchemy's type coercion.

The ones that only a live run can answer
------------------------------------------
A ledger row is not a dict. `raw_alert` is JSONB, `started_at` is a
timezone-aware datetime, `total_cost_usd` is Numeric, and ids are UUID
objects. Every one of those has a repr that JSON cannot serialise, so a
bundle built from live rows either round-trips or raises — and a unit
test handing in strings would never find out which.

And the export is a **read of another tenant's investigation** if the
scoping is wrong, which is the single worst thing this route could do.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime

import pytest
import pytest_asyncio

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_BUNDLE_DSN", "").strip(),
        reason="ISOLATION_BUNDLE_DSN is not set; this suite needs a live Postgres",
    ),
]

TENANT_A = uuid.UUID("11111111-1111-1111-1111-111111111111")
TENANT_B = uuid.UUID("22222222-2222-2222-2222-222222222222")
WHEN = datetime(2026, 10, 2, 12, 0, 0, tzinfo=UTC)


def _dsn() -> str:
    return os.environ["ISOLATION_BUNDLE_DSN"]


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def seeded():
    """One investigation per tenant, written as the ledger writes them."""
    asyncpg = pytest.importorskip("asyncpg")
    conn = await asyncpg.connect(_dsn().replace("postgresql+asyncpg://", "postgresql://"))
    runs: dict[uuid.UUID, uuid.UUID] = {}
    try:
        for tenant, summary in ((TENANT_A, "tenant A: encoded PowerShell"), (TENANT_B, "tenant B: brute force")):
            slug = f"bundle-{tenant.hex[:8]}"
            await conn.execute(
                "INSERT INTO tenants (id, name, slug) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING",
                tenant,
                slug,
                slug,
            )
            run_id = uuid.uuid4()
            await conn.execute(
                "INSERT INTO investigation_runs "
                "(id, tenant_id, case_id, alert_summary, raw_alert, model_used, status, "
                " total_tokens, total_cost_usd, iterations, started_at, completed_at) "
                "VALUES ($1,$2,$3,$4,$5::jsonb,$6,'completed',4096,0.0012,3,$7,$7)",
                run_id,
                tenant,
                f"CASE-{tenant.hex[:4]}",
                summary,
                json.dumps({"host": "WIN-FIN-02", "user": "j.doe"}),
                "llama3.2:3b-instruct-q4_K_M",
                WHEN,
            )
            await conn.execute(
                "INSERT INTO investigation_events "
                "(id, run_id, tenant_id, seq, ts, kind, agent, summary, payload, duration_ms) "
                "VALUES ($1,$2,$3,1,$4,'llm_response','aisoc-investigation','verdict',$5::jsonb,900)",
                uuid.uuid4(),
                run_id,
                tenant,
                WHEN,
                json.dumps({"verdict": "true_positive", "prompt": f"SYSTEM: secret-for-{slug}"}),
            )
            runs[tenant] = run_id
    finally:
        await conn.close()
    yield runs


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def client(seeded):  # noqa: ANN001
    pytest.importorskip("httpx")
    os.environ["DATABASE_URL"] = _dsn()
    os.environ.setdefault("ENVIRONMENT", "development")

    import httpx
    from app.main import create_application

    transport = httpx.ASGITransport(app=create_application())
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def users(seeded):  # noqa: ANN001
    """A real user per tenant: `get_current_user` resolves `sub` against
    the users table and 401s on "User not found"."""
    asyncpg = pytest.importorskip("asyncpg")
    conn = await asyncpg.connect(_dsn().replace("postgresql+asyncpg://", "postgresql://"))
    made: dict[uuid.UUID, uuid.UUID] = {}
    try:
        for tenant in (TENANT_A, TENANT_B):
            user_id = uuid.uuid4()
            await conn.execute(
                "INSERT INTO users (id, tenant_id, email, username, hashed_password, role, is_active) "
                "VALUES ($1,$2,$3,$4,'x','admin',true) ON CONFLICT DO NOTHING",
                user_id,
                tenant,
                f"bundle-{user_id.hex[:8]}@example.com",
                f"bundle-{user_id.hex[:8]}",
            )
            made[tenant] = user_id
    finally:
        await conn.close()
    yield made


def _auth(users, tenant: uuid.UUID) -> dict[str, str]:  # noqa: ANN001
    from app.core.security import create_access_token

    return {"Authorization": f"Bearer {create_access_token({'sub': str(users[tenant]), 'type': 'access'})}"}


class TestTheRouteExportsAVerifiableBundle:
    async def test_it_returns_a_bundle(self, client, users, seeded) -> None:  # noqa: ANN001
        response = await client.get(f"/api/v1/investigations/{seeded[TENANT_A]}/bundle", headers=_auth(users, TENANT_A))
        assert response.status_code == 200, f"{response.status_code}: {response.text[:300]}"
        assert "attachment" in response.headers.get("content-disposition", "")

    async def test_live_rows_survive_serialisation(self, client, users, seeded) -> None:  # noqa: ANN001
        """UUIDs, tz-aware datetimes, Numeric and JSONB all have reprs
        JSON cannot serialise. A unit test handing in strings would never
        find out which way this goes."""
        response = await client.get(f"/api/v1/investigations/{seeded[TENANT_A]}/bundle", headers=_auth(users, TENANT_A))
        bundle = json.loads(response.content)
        assert bundle["payload"]["run"]["id"] == str(seeded[TENANT_A])
        assert bundle["payload"]["alert"]["raw"]["host"] == "WIN-FIN-02"
        assert bundle["payload"]["model"]["total_cost_usd"] == pytest.approx(0.0012)

    async def test_the_exported_bytes_verify(self, client, users, seeded) -> None:  # noqa: ANN001
        """Verified against the bytes the route sent, not a re-serialised
        parse — which is the whole reason it is served as a download."""
        from app.core.config import settings
        from app.services.evidence_bundle import verify_bundle

        response = await client.get(f"/api/v1/investigations/{seeded[TENANT_A]}/bundle", headers=_auth(users, TENANT_A))
        payload = verify_bundle(json.loads(response.content), signing_key=settings.SECRET_KEY)
        assert payload["run"]["case_id"].startswith("CASE-")

    async def test_two_exports_are_byte_identical(self, client, users, seeded) -> None:  # noqa: ANN001
        """The done-when clause, measured on the real route rather than
        on a dict."""
        first = await client.get(f"/api/v1/investigations/{seeded[TENANT_A]}/bundle", headers=_auth(users, TENANT_A))
        second = await client.get(f"/api/v1/investigations/{seeded[TENANT_A]}/bundle", headers=_auth(users, TENANT_A))
        assert first.content == second.content


class TestItIsTenantScoped:
    async def test_another_tenant_cannot_export_this_investigation(self, client, users, seeded) -> None:  # noqa: ANN001
        """The worst thing this route could do. A bundle is a complete
        investigation: the alert, the evidence, the hostnames.

        Two independent mechanisms hold it, and that was measured rather
        than assumed. Removing the explicit ``tenant_id`` predicate from
        ``_fetch_run`` leaves this test **passing**, because the session
        runs as the DML-only role and RLS refuses the row anyway;
        removing the predicate *and* connecting as the schema owner, so
        RLS does not apply, makes it fail.

        Worth knowing in both directions. The belt and braces are real,
        and a reader should not conclude from a green run that the
        predicate alone is doing the work — or that this test would have
        caught the predicate going missing on its own.
        """
        response = await client.get(f"/api/v1/investigations/{seeded[TENANT_A]}/bundle", headers=_auth(users, TENANT_B))
        assert response.status_code == 404, (
            f"tenant B got {response.status_code} for tenant A's bundle; the body would carry tenant A's whole investigation"
        )

    async def test_each_tenant_can_export_its_own(self, client, users, seeded) -> None:  # noqa: ANN001
        """So the refusal above is isolation rather than a broken route."""
        response = await client.get(f"/api/v1/investigations/{seeded[TENANT_B]}/bundle", headers=_auth(users, TENANT_B))
        assert response.status_code == 200

    async def test_an_uncredentialed_caller_is_refused(self, client, seeded) -> None:  # noqa: ANN001
        response = await client.get(f"/api/v1/investigations/{seeded[TENANT_A]}/bundle")
        assert response.status_code in (401, 403)


class TestPromptsDoNotLeave:
    async def test_the_prompt_text_is_not_in_the_exported_bytes(self, client, users, seeded) -> None:  # noqa: ANN001
        """Measured on what the route actually sent."""
        response = await client.get(f"/api/v1/investigations/{seeded[TENANT_A]}/bundle", headers=_auth(users, TENANT_A))
        assert b"SYSTEM: secret-for-" not in response.content
        assert b"prompt_sha256" in response.content
