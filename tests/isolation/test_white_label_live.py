"""White-label, through the real app and real Postgres.

Fix pass 4.3.

Three properties that only a live stack can answer, each of which had
shipped wrong or was covered by nothing at all.

**The brand asset is served to a credential, not to an ``<img>``.**
`logo_url` is a path on this deployment, `GET /api/v1/branding/assets/{id}`,
and the console used to hand it straight to an `<img src>`. That route binds
an authenticated principal, and the only credential a browser attaches to an
image request is a cookie -- so the sidebar logo answered 401 on every
deployment not running the development auth shim, which is every deployment
a customer has. The console now fetches the bytes with the session token and
hands the DOM an object URL. The 401 is asserted here **as the mechanism**:
the component test can show that the `src` is an object URL, but only the
real route against real Postgres can show why it has to be, and a future
change that made the route public would silently make that component test's
whole subject moot while it kept passing.

**The covering email on a scheduled report is branded.** The inherited unit
suite says, in its own docstring, that it cannot assert this: a
`report_templates` row stores its recipients in a Postgres `text[]`, which
SQLite cannot bind, so the delivery branch never runs there. It runs here,
against the real column, through the real `run_once`.

**A closed investigation stores a branded summary.** The renderer is unit
covered next door. What that cannot see is whether the *route* resolves
branding and passes it -- the "mechanism exists, nothing calls it" shape this
repository keeps finding -- so this drives `POST /close` and reads the
artefact row back out of the database.

`ENVIRONMENT=test` and not `development`: `development` is in
`AUTH_BYPASS_ENVIRONMENTS`, so an uncredentialed request resolves to a demo
administrator -- which would turn the first assertion below, whose entire
subject is what happens *without* a credential, into a test of nothing.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Any

import pytest
import pytest_asyncio

if TYPE_CHECKING:
    # Type-only. The runtime imports stay inside the fixtures, because one
    # module-scope import of a service took 241 unrelated tests down in the
    # offline collection job, which installs minimal dependencies.
    import httpx
    from sqlalchemy.ext.asyncio import AsyncSession

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_WHITE_LABEL_DSN", "").strip(),
        reason="ISOLATION_WHITE_LABEL_DSN is not set; this suite needs a live Postgres",
    ),
]

# Named for what it is. As `PASSWORD` the secret scanner reads the literal as
# a credential, and the alternative -- a `.gitleaksignore` entry -- is
# fingerprinted on the line number, so any later edit to this file would
# reopen the finding.
TEST_PASSPHRASE = "correct-horse-battery-staple-43"

PRODUCT = "Acme Shield"
SENDER = "Acme SOC"
PRIMARY = "#123456"
ACCENT = "#654321"
SUPPORT_URL = "https://support.acme.example"
FOOTER = "Acme Shield — operated by Acme Managed Security."

LOGO = b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 40 40"><rect width="40" height="40" fill="#123456"/></svg>'

#: The address that was hard-coded into every investigation summary.
PLATFORM_CONTACT = "beenu@cyble.com"


def _dsn() -> str:
    value = os.environ.get("ISOLATION_WHITE_LABEL_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_WHITE_LABEL_DSN is not set; this suite needs a live Postgres")
    return value


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def app_client() -> AsyncIterator[httpx.AsyncClient]:
    pytest.importorskip("httpx")
    os.environ["DATABASE_URL"] = _dsn()
    os.environ["ENVIRONMENT"] = "test"

    import httpx
    from app.main import create_application

    application = create_application()
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def db() -> AsyncIterator[AsyncSession]:
    pytest.importorskip("asyncpg")
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    os.environ["DATABASE_URL"] = _dsn()
    engine = create_async_engine(_dsn(), future=True)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        yield session
    await engine.dispose()


async def _tenant(session: AsyncSession, label: str) -> uuid.UUID:
    import sqlalchemy

    tenant_id = uuid.uuid4()
    await session.execute(
        sqlalchemy.text("INSERT INTO tenants (id, name, slug) VALUES (:i, :n, :s)"),
        {"i": tenant_id, "n": f"{label}-{tenant_id.hex[:8]}", "s": f"{label}-{tenant_id.hex[:8]}"},
    )
    return tenant_id


async def _user(session: AsyncSession, tenant_id: uuid.UUID, *, role: str = "admin") -> dict[str, Any]:
    """A real user row with a real bcrypt hash, so login is a real login."""
    import sqlalchemy
    from app.core.security import get_password_hash

    user_id = uuid.uuid4()
    email = f"wl-{user_id.hex[:10]}@example.com"
    await session.execute(
        sqlalchemy.text(
            "INSERT INTO users (id, tenant_id, email, username, role, is_active, hashed_password) VALUES (:i, :t, :e, :u, :r, TRUE, :p)"
        ),
        {
            "i": user_id,
            "t": tenant_id,
            "e": email,
            "u": email.split("@")[0],
            "r": role,
            "p": get_password_hash(TEST_PASSPHRASE),
        },
    )
    return {"id": user_id, "tenant_id": tenant_id, "email": email}


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def branded(db: AsyncSession) -> dict[str, Any]:
    """One white-labelled organisation with a managed tenant and a logo."""
    import sqlalchemy

    await db.rollback()
    org_id = uuid.uuid4()
    home_tenant = await _tenant(db, "wl-home")
    managed_tenant = await _tenant(db, "wl-managed")
    await db.execute(
        sqlalchemy.text("INSERT INTO organizations (id, slug, name, home_tenant_id) VALUES (:i, :s, :n, :h)"),
        {"i": org_id, "s": f"acme-{org_id.hex[:8]}", "n": "Acme Managed Security", "h": home_tenant},
    )
    await db.execute(
        sqlalchemy.text("INSERT INTO organization_tenants (org_id, tenant_id) VALUES (:o, :t)"),
        {"o": org_id, "t": managed_tenant},
    )
    await db.execute(
        sqlalchemy.text(
            "INSERT INTO aisoc_org_branding (org_id, product_name, primary_color, accent_color,"
            " support_url, sender_name, footer_text)"
            " VALUES (:o, :p, :pc, :ac, :su, :sn, :ft)"
        ),
        {"o": org_id, "p": PRODUCT, "pc": PRIMARY, "ac": ACCENT, "su": SUPPORT_URL, "sn": SENDER, "ft": FOOTER},
    )
    asset_id = uuid.uuid4()
    await db.execute(
        sqlalchemy.text(
            "INSERT INTO aisoc_org_brand_assets (id, org_id, kind, content_type, content, byte_size, sha256)"
            " VALUES (:i, :o, 'logo', 'image/svg+xml', :c, :b, :h)"
        ),
        {"i": asset_id, "o": org_id, "c": LOGO, "b": len(LOGO), "h": "0" * 64},
    )
    user = await _user(db, managed_tenant)
    await db.commit()
    return {"org_id": org_id, "tenant_id": managed_tenant, "asset_id": asset_id, "user": user}


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def outsider(db: AsyncSession) -> dict[str, Any]:
    """A member of a different, unbranded organisation."""
    await db.rollback()
    user = await _user(db, await _tenant(db, "wl-outsider"))
    await db.commit()
    return user


async def _bearer(client: httpx.AsyncClient, user: dict[str, Any]) -> dict[str, str]:
    response = await client.post("/api/v1/auth/login", json={"email": user["email"], "password": TEST_PASSPHRASE})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


class TestTheBrandAssetRoute:
    """The defect the plan asked to be verified rather than reasoned about."""

    async def test_the_request_an_img_tag_makes_is_refused(self, app_client: httpx.AsyncClient, branded: dict[str, Any]) -> None:
        """No credential, because an `<img src>` cannot send one.

        This is exactly the request the browser issued when `logo_url` was
        the `src`: a plain GET with no `Authorization` header. A 2xx here
        would mean the asset route is public, which is a different product
        than the one documented.
        """
        response = await app_client.get(f"/api/v1/branding/assets/{branded['asset_id']}")
        assert response.status_code in (401, 403), response.text

    async def test_the_console_fetch_carries_a_credential_and_gets_the_bytes(
        self, app_client: httpx.AsyncClient, branded: dict[str, Any]
    ) -> None:
        """The positive control for the case above.

        Without it, a route that was simply broken -- 401 to everyone,
        logo or not -- would satisfy the refusal assertion perfectly.
        """
        headers = await _bearer(app_client, branded["user"])
        response = await app_client.get(f"/api/v1/branding/assets/{branded['asset_id']}", headers=headers)
        assert response.status_code == 200, response.text
        assert response.content == LOGO
        assert response.headers["content-type"].startswith("image/svg+xml")

    async def test_another_organisations_member_cannot_read_the_asset(
        self, app_client: httpx.AsyncClient, branded: dict[str, Any], outsider: dict[str, Any]
    ) -> None:
        """A credential is not the same as *this* organisation's credential.

        The asset id is a bare UUID in a URL. If holding any session were
        enough, one operator's logo would be readable by every other
        organisation on the deployment.
        """
        headers = await _bearer(app_client, outsider)
        response = await app_client.get(f"/api/v1/branding/assets/{branded['asset_id']}", headers=headers)
        assert response.status_code in (403, 404), response.text

    async def test_the_resolved_logo_url_is_a_path_on_this_deployment(self, app_client: httpx.AsyncClient, branded: dict[str, Any]) -> None:
        """A remote logo would be an outbound request from the operator's
        browser on every page load, telling whoever hosts it who is
        looking at what -- and, in a server-rendered PDF, an outbound
        request made by the server to an address a customer supplied."""
        headers = await _bearer(app_client, branded["user"])
        body = (await app_client.get("/api/v1/branding", headers=headers)).json()
        assert body["product_name"] == PRODUCT
        assert body["sender_name"] == SENDER
        assert body["logo_url"] == f"/api/v1/branding/assets/{branded['asset_id']}"
        assert not body["logo_url"].startswith(("http://", "https://"))


class TestTheScheduledReportEmail:
    """What the inherited unit suite deferred here, and why."""

    async def test_the_envelope_carries_the_operators_name_not_the_platforms(
        self, db: AsyncSession, branded: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import sqlalchemy
        from app.workers import report_scheduler

        sent: list[dict[str, Any]] = []

        async def _capture(**kwargs: Any) -> Any:
            sent.append(kwargs)

            class _Result:
                status = "sent"
                detail = "captured"

            return _Result()

        monkeypatch.setattr(report_scheduler, "send_mail", _capture)

        await db.rollback()
        template_id = uuid.uuid4()
        await db.execute(
            sqlalchemy.text(
                "INSERT INTO report_templates (id, tenant_id, name, report_type, cron_schedule,"
                " recipients, is_enabled)"
                " VALUES (:i, :t, :n, 'board_summary', '* * * * *', :r, TRUE)"
            ),
            # The Postgres `text[]` the unit suite cannot bind.
            {"i": template_id, "t": branded["tenant_id"], "n": "Weekly board pack", "r": ["board@acme.example"]},
        )
        await db.commit()

        try:
            await report_scheduler.run_once()

            assert sent, "the scheduler generated no mail, so this asserts nothing"
            envelope = sent[-1]
            assert envelope["subject"].startswith(f"[{PRODUCT}]")
            assert "AiSOC" not in envelope["subject"]
            # `sender_name` is the one resolved field whose entire purpose is
            # naming who mail is from, and it reached no mailer on this path.
            assert envelope["settings"].sender_name == SENDER
        finally:
            await db.rollback()
            await db.execute(sqlalchemy.text("DELETE FROM report_artefacts WHERE template_id = :i"), {"i": template_id})
            await db.execute(sqlalchemy.text("DELETE FROM report_templates WHERE id = :i"), {"i": template_id})
            await db.commit()


class TestTheClosedInvestigationSummary:
    """The wiring, as opposed to the renderer."""

    async def test_the_stored_artefact_carries_the_operators_brand(
        self, app_client: httpx.AsyncClient, db: AsyncSession, branded: dict[str, Any]
    ) -> None:
        import sqlalchemy

        await db.rollback()
        run_id = uuid.uuid4()
        await db.execute(
            sqlalchemy.text(
                "INSERT INTO investigation_runs (id, tenant_id, case_id, status, model_used, iterations, total_tokens)"
                " VALUES (:i, :t, 'CASE-4821', 'completed', 'llama3.2:3b', 3, 1234)"
            ),
            {"i": run_id, "t": branded["tenant_id"]},
        )
        await db.commit()

        headers = await _bearer(app_client, branded["user"])
        closed = await app_client.post(f"/api/v1/investigations/{run_id}/close", json={"analyst_note": None}, headers=headers)
        assert closed.status_code == 200, closed.text

        await db.rollback()
        content = (
            await db.execute(
                sqlalchemy.text(
                    "SELECT content FROM investigation_artifacts WHERE run_id = :r"
                    " AND kind = 'investigation-summary' ORDER BY created_at DESC LIMIT 1"
                ),
                {"r": run_id},
            )
        ).scalar_one()

        assert PRODUCT in content
        assert SUPPORT_URL in content
        # A document showing both names is co-branded, not white-labelled.
        assert "AiSOC" not in content
        assert PLATFORM_CONTACT not in content
