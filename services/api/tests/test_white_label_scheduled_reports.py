"""The reports that go out on a schedule carry the operator's brand too.

``apps/docs/docs/operations/white-label.md`` lists "Executive digest (HTML
and PDF)" as branded, and on the interactive path it is:
``GET /api/v1/reports/digest`` resolves branding and hands it to the
renderer. The weekly digest that an operator actually receives is not
produced there. It is produced by ``app.workers.weekly_digest_task``, every
Monday, for every active tenant — and that worker called
``render_digest_pdf(digest)`` with no branding at all, so the stored
artefact rendered in the platform palette under the platform name while the
documentation said otherwise.

This is the document the resolver's own docstring singles out: "the one a
customer notices is whichever renders in the document they forward to their
board". A managed customer forwarding their provider's weekly digest would
have forwarded somebody else's product name.

Why no test caught it
---------------------
``test_digest_pdf.py`` covers the worker's fallback by patching
``_generate_for_tenant`` with, in its own words, a "thin inline
re-implementation" and then asserting on that copy. A test that substitutes
a reimplementation for the function under test can never notice what the
real one does not do. These cases call the real ``_generate_for_tenant`` and
the real ``run_once``, and read the bytes that were actually stored.

The covering email that ``report_scheduler`` sends carries the same defect
and is proved next door, in
``tests/isolation/test_white_label_live.py``: its template
row stores recipients in a Postgres ``text[]``, which SQLite cannot bind, so
asserting on it here would mean asserting against a reshaped schema.
"""

from __future__ import annotations

import base64
import sys
import types
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from app.db.database import Base
from app.models.branding import OrgBrandAsset, OrgBranding
from app.models.organization import Organization, OrganizationTenant
from app.models.report import ReportArtefact
from app.services.executive_digest import AlertRow, DigestInputs, build_digest_from_rows
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.ext.compiler import compiles

pytestmark = pytest.mark.asyncio

TENANT = uuid.UUID("eeeeeeee-0000-0000-0000-0000000000e1")
UNBRANDED_TENANT = uuid.UUID("ffffffff-0000-0000-0000-0000000000f1")
ORG = uuid.UUID("0a0a0a0a-0000-0000-0000-00000000000a")

PERIOD_START = datetime(2026, 5, 4, tzinfo=UTC)
PERIOD_END = datetime(2026, 5, 10, 23, 59, 59, tzinfo=UTC)

PRODUCT = "Acme Shield"
PRIMARY = "#123456"
ACCENT = "#654321"
SUPPORT_URL = "https://support.acme.example"
FOOTER = "Acme Shield — operated by Acme Managed Security."

LOGO = b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 40 40"><rect width="40" height="40" fill="#123456"/></svg>'


@compiles(JSONB, "sqlite")
def _jsonb_sqlite(_type_, _compiler_, **_kw_):
    return "TEXT"


@compiles(PgUUID, "sqlite")
def _uuid_sqlite(_type_, _compiler_, **_kw_):
    return "CHAR(36)"


@compiles(ARRAY, "sqlite")
def _array_sqlite(_type_, _compiler_, **_kw_):
    return "TEXT"


def _digest():
    """A small but valid digest. Its *content* is not what is under test."""
    return build_digest_from_rows(
        DigestInputs(
            tenant_id=TENANT,
            period_start=PERIOD_START,
            period_end=PERIOD_END,
            current_alerts=[
                AlertRow(
                    severity="high",
                    status="closed",
                    created_at=PERIOD_START + timedelta(hours=1),
                    resolved_at=PERIOD_START + timedelta(hours=5),
                    first_seen_at=PERIOD_START + timedelta(hours=1, minutes=10),
                    disposition="true_positive",
                    mitre_tactics=["execution"],
                    connector_type="edr-crowdstrike",
                    ai_score=0.9,
                    title="Suspicious PowerShell",
                    alert_id=str(uuid.uuid4()),
                    event_time=PERIOD_START + timedelta(hours=1),
                )
            ],
        )
    )


class _CapturingWeasyPrint:
    """A WeasyPrint stand-in that keeps the HTML it was handed.

    The branding reaches the PDF through that HTML, so capturing it is how
    this asserts on a PDF without the native stack. It records rather than
    accepting anything: a double that swallowed ``string=`` would keep
    passing if the worker stopped rendering altogether.
    """

    captured: list[str] = []

    def __init__(self, *, string: str) -> None:
        type(self).captured.append(string)

    def write_pdf(self) -> bytes:
        return b"%PDF-1.4 captured"


def _install_weasyprint(available: bool) -> None:
    if not available:
        sys.modules["weasyprint"] = None  # type: ignore[assignment]
        return
    module = types.ModuleType("weasyprint")
    module.HTML = _CapturingWeasyPrint  # type: ignore[attr-defined]
    sys.modules["weasyprint"] = module


@pytest_asyncio.fixture
async def session_factory():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(
            Base.metadata.create_all,
            tables=[
                Organization.__table__,
                OrganizationTenant.__table__,
                OrgBranding.__table__,
                OrgBrandAsset.__table__,
                ReportArtefact.__table__,
            ],
        )
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


async def _brand(session_factory) -> None:
    """One white-labelled organisation holding ``TENANT`` in its portfolio."""
    async with session_factory() as db:
        db.add(Organization(id=ORG, name="Acme Managed Security", slug="acme"))
        db.add(OrganizationTenant(org_id=ORG, tenant_id=TENANT))
        db.add(
            OrgBranding(
                org_id=ORG,
                product_name=PRODUCT,
                primary_color=PRIMARY,
                accent_color=ACCENT,
                support_url=SUPPORT_URL,
                footer_text=FOOTER,
            )
        )
        db.add(
            OrgBrandAsset(
                id=uuid.uuid4(),
                org_id=ORG,
                kind="logo",
                content_type="image/svg+xml",
                content=LOGO,
                byte_size=len(LOGO),
                sha256="0" * 64,
            )
        )
        await db.commit()


@pytest.fixture(autouse=True)
def _restore_weasyprint():
    yield
    sys.modules.pop("weasyprint", None)
    _CapturingWeasyPrint.captured.clear()


class TestTheScheduledDigest:
    """``weekly_digest_task`` is the only producer of the weekly digest."""

    async def _run(self, monkeypatch, session_factory, tenant: uuid.UUID) -> ReportArtefact:
        from app.workers import weekly_digest_task as worker

        async def _build(_db, tenant_id, *, period_start, period_end):
            return _digest()

        monkeypatch.setattr(worker, "AsyncSessionLocal", session_factory)
        monkeypatch.setattr(worker, "build_weekly_digest", _build)
        await worker._generate_for_tenant(tenant, PERIOD_START, PERIOD_END)

        async with session_factory() as db:
            return (await db.execute(select(ReportArtefact).where(ReportArtefact.tenant_id == tenant))).scalar_one()

    async def test_the_pdf_carries_the_operators_brand(self, monkeypatch, session_factory) -> None:
        """The worker rendered with no branding, so this was the platform PDF."""
        _install_weasyprint(available=True)
        await _brand(session_factory)
        artefact = await self._run(monkeypatch, session_factory, TENANT)

        assert artefact.output_format == "pdf"
        html = _CapturingWeasyPrint.captured[-1]
        assert PRODUCT in html
        assert PRIMARY in html
        assert ACCENT in html
        assert SUPPORT_URL in html
        assert FOOTER in html

    async def test_the_pdf_does_not_also_carry_the_platform_wordmark(self, monkeypatch, session_factory) -> None:
        """A report showing both names is co-branded by accident."""
        _install_weasyprint(available=True)
        await _brand(session_factory)
        await self._run(monkeypatch, session_factory, TENANT)

        assert "AiSOC" not in _CapturingWeasyPrint.captured[-1]

    async def test_the_pdf_embeds_the_logo_rather_than_linking_it(self, monkeypatch, session_factory) -> None:
        """WeasyPrint runs server-side, so a remote `<img src>` would be an
        outbound request the server makes to an operator-supplied address."""
        _install_weasyprint(available=True)
        await _brand(session_factory)
        await self._run(monkeypatch, session_factory, TENANT)

        assert "data:image/svg+xml;base64," in _CapturingWeasyPrint.captured[-1]

    async def test_the_html_fallback_carries_the_operators_brand(self, monkeypatch, session_factory) -> None:
        """The fallback is what runs wherever the native stack is absent."""
        _install_weasyprint(available=False)
        await _brand(session_factory)
        artefact = await self._run(monkeypatch, session_factory, TENANT)

        assert artefact.output_format == "html"
        body = base64.b64decode(artefact.body_b64 or "").decode("utf-8")
        assert PRODUCT in body
        assert PRIMARY in body
        assert FOOTER in body
        assert "AiSOC" not in body

    async def test_the_artefact_title_carries_the_operators_brand(self, monkeypatch, session_factory) -> None:
        """The title is the row the console lists and the subject mail uses."""
        _install_weasyprint(available=True)
        await _brand(session_factory)
        artefact = await self._run(monkeypatch, session_factory, TENANT)

        assert artefact.title.startswith(PRODUCT)
        assert "AiSOC" not in artefact.title

    async def test_an_unbranded_tenant_still_gets_the_platform_appearance(self, monkeypatch, session_factory) -> None:
        """The positive control.

        A fix that resolved branding and then dropped it, or that blanked
        the name when no organisation owns the tenant, would pass every
        assertion above. This is the case that fails if it does.
        """
        _install_weasyprint(available=True)
        artefact = await self._run(monkeypatch, session_factory, UNBRANDED_TENANT)

        html = _CapturingWeasyPrint.captured[-1]
        assert "AiSOC" in html
        assert "#2563EB" in html
        assert artefact.title.startswith("AiSOC")
