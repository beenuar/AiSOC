"""A white-labelled organisation's console and PDF report carry its branding.

Gap-closure Phase 13.2 gate, and the acceptance is literal: the two surfaces
named in the plan are exercised here against a configured organisation.

Two properties beyond "the name appears"
-----------------------------------------
* **Nothing is fetched from a third party.** The plan says assets are stored
  locally and never fetched from a remote URL, and the reason is that a
  remote logo is an outbound request made by whatever renders it. For a PDF
  that renderer is the server, which makes a customer-supplied address a
  server-side request forgery primitive. So the report is asserted to embed
  the bytes and to contain no external scheme at all.
* **Falling back is field by field.** An organisation that has set a name and
  no colours renders its name against the platform palette. Falling back to
  the whole default row would silently discard the one field the operator
  bothered to set.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from app.db.database import Base
from app.models.branding import OrgBrandAsset, OrgBranding
from app.models.organization import Organization, OrganizationTenant
from app.services.branding import resolver
from app.services.branding.svg_sanitizer import sanitize_svg
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.ext.compiler import compiles

MANAGED_TENANT = uuid.UUID("eeeeeeee-0000-0000-0000-0000000000e1")
HOME_TENANT = uuid.UUID("eeeeeeee-0000-0000-0000-0000000000e2")
UNMANAGED_TENANT = uuid.UUID("ffffffff-0000-0000-0000-0000000000f1")
ORG = uuid.UUID("0a0a0a0a-0000-0000-0000-00000000000a")

LOGO = b"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 40 40">
  <rect width="40" height="40" fill="#123456"/>
</svg>"""


@compiles(JSONB, "sqlite")
def _jsonb_sqlite(_type_, _compiler_, **_kw_):
    return "TEXT"


@compiles(PgUUID, "sqlite")
def _uuid_sqlite(_type_, _compiler_, **_kw_):
    return "CHAR(36)"


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
            ],
        )
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


async def _brand(db, **overrides):
    db.add(Organization(id=ORG, slug="acme", name="Acme MSSP", home_tenant_id=HOME_TENANT))
    db.add(OrganizationTenant(org_id=ORG, tenant_id=MANAGED_TENANT, onboarded_at=datetime.now(UTC)))
    db.add(OrgBranding(org_id=ORG, **overrides))
    await db.commit()


class TestResolution:
    async def test_an_unmanaged_tenant_gets_the_platform_default(self, session_factory):
        async with session_factory() as db:
            branding = await resolver.resolve_branding(db, UNMANAGED_TENANT)
        assert branding.product_name == resolver.DEFAULT_BRANDING.product_name
        # The flag distinguishes "the default because that was chosen" from
        # "the default because nobody has been here yet".
        assert branding.is_white_labelled is False

    async def test_a_managed_tenant_gets_its_operators_branding(self, session_factory):
        async with session_factory() as db:
            await _brand(db, product_name="Acme Shield", primary_color="#123456")
            branding = await resolver.resolve_branding(db, MANAGED_TENANT)
        assert branding.product_name == "Acme Shield"
        assert branding.primary_color == "#123456"
        assert branding.is_white_labelled is True

    async def test_the_operators_own_staff_see_it_too(self, session_factory):
        """Resolution has to follow ``home_tenant_id`` as well as the portfolio.

        Checking only the portfolio leaves the operator's own console
        unbranded, which is the one console they look at every day.
        """
        async with session_factory() as db:
            await _brand(db, product_name="Acme Shield")
            branding = await resolver.resolve_branding(db, HOME_TENANT)
        assert branding.product_name == "Acme Shield"

    async def test_unset_fields_fall_back_individually(self, session_factory):
        """A name and no colours renders the name against the platette."""
        async with session_factory() as db:
            await _brand(db, product_name="Acme Shield")
            branding = await resolver.resolve_branding(db, MANAGED_TENANT)
        assert branding.product_name == "Acme Shield"
        assert branding.primary_color == resolver.DEFAULT_BRANDING.primary_color

    async def test_the_sender_name_defaults_to_the_product_name(self, session_factory):
        """Not to the platform name.

        An operator who renames the product and forgets this field would
        otherwise send mail from a brand their customer has never heard of,
        which reads as a phishing attempt.
        """
        async with session_factory() as db:
            await _brand(db, product_name="Acme Shield")
            branding = await resolver.resolve_branding(db, MANAGED_TENANT)
        assert branding.sender_name == "Acme Shield"

    async def test_an_explicit_sender_name_still_wins(self, session_factory):
        async with session_factory() as db:
            await _brand(db, product_name="Acme Shield", sender_name="Acme SOC")
            branding = await resolver.resolve_branding(db, MANAGED_TENANT)
        assert branding.sender_name == "Acme SOC"

    async def test_a_broken_lookup_returns_the_default_rather_than_raising(self, session_factory):
        """Appearance must never take down content.

        A report that renders in the platform palette is better than a report
        that does not render.
        """

        class Exploding:
            async def execute(self, *_args, **_kwargs):
                raise RuntimeError("database is unavailable")

        branding = await resolver.resolve_branding(Exploding(), MANAGED_TENANT)  # type: ignore[arg-type]
        assert branding == resolver.DEFAULT_BRANDING


class TestAssets:
    async def test_the_logo_is_served_from_this_deployment_not_a_remote_url(self, session_factory):
        async with session_factory() as db:
            await _brand(db, product_name="Acme Shield")
            cleaned = sanitize_svg(LOGO)
            db.add(
                OrgBrandAsset(
                    org_id=ORG,
                    kind="logo",
                    content_type="image/svg+xml",
                    content=cleaned.svg.encode(),
                    byte_size=len(cleaned.svg),
                    sha256="x" * 64,
                )
            )
            await db.commit()
            branding = await resolver.resolve_branding(db, MANAGED_TENANT)

        assert branding.logo_url is not None
        assert branding.logo_url.startswith("/api/v1/branding/assets/")
        assert "http://" not in branding.logo_url
        assert "https://" not in branding.logo_url

    async def test_inlining_produces_a_data_uri_with_no_outbound_reference(self, session_factory):
        async with session_factory() as db:
            await _brand(db, product_name="Acme Shield")
            cleaned = sanitize_svg(LOGO)
            db.add(
                OrgBrandAsset(
                    org_id=ORG,
                    kind="logo",
                    content_type="image/svg+xml",
                    content=cleaned.svg.encode(),
                    byte_size=len(cleaned.svg),
                    sha256="x" * 64,
                )
            )
            await db.commit()
            branding = await resolver.resolve_branding(db, MANAGED_TENANT, inline_logo=True)

        assert branding.logo_data_uri is not None
        assert branding.logo_data_uri.startswith("data:image/svg+xml;base64,")

    async def test_the_bytes_are_not_loaded_unless_asked_for(self, session_factory):
        """The console does not need them and every page load would carry one."""
        async with session_factory() as db:
            await _brand(db, product_name="Acme Shield")
            cleaned = sanitize_svg(LOGO)
            db.add(
                OrgBrandAsset(
                    org_id=ORG,
                    kind="logo",
                    content_type="image/svg+xml",
                    content=cleaned.svg.encode(),
                    byte_size=len(cleaned.svg),
                    sha256="x" * 64,
                )
            )
            await db.commit()
            branding = await resolver.resolve_branding(db, MANAGED_TENANT)
        assert branding.logo_data_uri is None


class TestTheReport:
    """The PDF half of the acceptance.

    A PDF is this HTML run through WeasyPrint, so asserting on the HTML is
    asserting on what the PDF contains, without requiring the native
    rendering stack to be installed in CI.
    """

    @staticmethod
    def _digest():
        from app.services.executive_digest import (
            AlertSummary,
            AutomationSummary,
            CaseSummary,
            DigestPeriod,
            ExecutiveDigest,
            MttSummary,
            SeveritySplit,
        )

        return ExecutiveDigest(
            tenant_id=MANAGED_TENANT,
            period=DigestPeriod(
                label="10-16 March 2026",
                start=datetime(2026, 3, 10, tzinfo=UTC),
                end=datetime(2026, 3, 16, tzinfo=UTC),
            ),
            headline="Two incidents, both contained.",
            alerts=AlertSummary(total=10, new=4, resolved=6, open_at_period_end=4, severity=SeveritySplit()),
            cases=CaseSummary(opened=2, closed=2, open_at_period_end=0, sla_breached=0),
            mtt=MttSummary(mttd_hours=1.0, mttr_hours=2.0, mttc_hours=3.0),
            automation=AutomationSummary(total_decisions=0, auto_executed=0, escalated=0, review_pending=0),
            top_tactics=[],
            top_sources=[],
            high_risk_alerts=[],
            recommendations=[],
        )

    def test_an_unbranded_deployment_renders_exactly_as_before(self):
        from app.services.digest_html import render_digest_html

        html = render_digest_html(self._digest())
        assert "AiSOC" in html

    async def test_a_white_labelled_report_carries_the_name_palette_and_logo(self, session_factory):
        from app.services.digest_html import render_digest_html

        async with session_factory() as db:
            await _brand(db, product_name="Acme Shield", primary_color="#123456", support_url="https://support.acme.example")
            cleaned = sanitize_svg(LOGO)
            db.add(
                OrgBrandAsset(
                    org_id=ORG,
                    kind="logo",
                    content_type="image/svg+xml",
                    content=cleaned.svg.encode(),
                    byte_size=len(cleaned.svg),
                    sha256="x" * 64,
                )
            )
            await db.commit()
            branding = await resolver.resolve_branding(db, MANAGED_TENANT, inline_logo=True)

        html = render_digest_html(self._digest(), branding)

        assert "Acme Shield" in html
        assert "#123456" in html
        assert "data:image/svg+xml;base64," in html
        assert "support.acme.example" in html

        # And the platform name is gone from the chrome. A report that says
        # both is not white-labelled, it is co-branded by accident.
        assert "AiSOC weekly executive digest" not in html
        assert "AiSOC — open-source" not in html

    async def test_the_report_makes_no_outbound_request_when_rendered(self, session_factory):
        """WeasyPrint renders this server-side.

        A remote `<img src>` here is an outbound request made by the server,
        to an address a customer administrator supplied.
        """
        from app.services.digest_html import render_digest_html

        async with session_factory() as db:
            await _brand(db, product_name="Acme Shield")
            cleaned = sanitize_svg(LOGO)
            db.add(
                OrgBrandAsset(
                    org_id=ORG,
                    kind="logo",
                    content_type="image/svg+xml",
                    content=cleaned.svg.encode(),
                    byte_size=len(cleaned.svg),
                    sha256="x" * 64,
                )
            )
            await db.commit()
            branding = await resolver.resolve_branding(db, MANAGED_TENANT, inline_logo=True)

        html = render_digest_html(self._digest(), branding)
        for scheme in ("http://", "https://"):
            offenders = [fragment for fragment in html.split('"') if fragment.startswith(scheme) and "w3.org" not in fragment]
            assert not offenders, f"report references {offenders}"


class TestSupportUrlIsNotAScriptVector:
    """``support_url`` is rendered as a link in email and in a PDF."""

    @pytest.mark.parametrize(
        "hostile",
        ["javascript:alert(1)", "http://insecure.example", "data:text/html,<script>alert(1)</script>", "vbscript:x"],
    )
    def test_a_non_https_support_url_is_refused_at_the_boundary(self, hostile):
        from app.api.v1.endpoints.branding import BrandingIn
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            BrandingIn(support_url=hostile)

    def test_an_https_url_is_accepted(self):
        from app.api.v1.endpoints.branding import BrandingIn

        assert BrandingIn(support_url="https://support.acme.example").support_url == "https://support.acme.example"
