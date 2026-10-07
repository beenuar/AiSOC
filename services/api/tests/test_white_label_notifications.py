"""The signed email approval is wired, and it carries the operator's brand.

Two defects, one path.

``send_approval_email`` had **no caller anywhere in the tree**. The
documentation names it as the fallback for "Slack and Teams are unreachable",
and the function, its signer, its verifier and its consuming endpoint were all
tested — none of which says anything about whether an approval ever produces
one. So these cases drive ``POST /api/v1/approvals`` through the real router
and read what left the mailer, rather than calling the function and asserting
it returns what it was given.

The second is why that matters here: the subject line read ``[AiSOC]`` for
every organisation, and ``sender_name`` — the one resolved field whose entire
purpose is naming who mail comes from — was read by nothing. A managed
customer's on-call analyst is the person this lands on, and they have never
heard of the platform their provider runs.

The link is verified rather than eyeballed. A branded email whose approve
button does not authenticate is worse than an unbranded one, and the
consuming endpoint refuses a token that names no approver — which is exactly
what this function minted while nothing called it.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
import pytest_asyncio
from app.api.v1.deps import CurrentUser, get_current_user
from app.api.v1.endpoints import approvals as endpoint
from app.db.database import Base
from app.db.rls import get_tenant_db
from app.models.branding import OrgBrandAsset, OrgBranding
from app.models.organization import Organization, OrganizationTenant
from app.models.responder import AgentApproval
from app.services.email_approval import EmailApprovalError, _quoted_display_name, verify_token
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.ext.compiler import compiles

TENANT = uuid.UUID("eeeeeeee-0000-0000-0000-0000000000e1")
ORG = uuid.UUID("0a0a0a0a-0000-0000-0000-00000000000a")
USER = uuid.UUID("0b0b0b0b-0000-0000-0000-00000000000b")
SECRET = "test-approval-signing-secret"
ONCALL = ["oncall@acme.example", "duty@acme.example"]


@compiles(JSONB, "sqlite")
def _jsonb_sqlite(_type_, _compiler_, **_kw_):
    return "TEXT"


@compiles(PgUUID, "sqlite")
def _uuid_sqlite(_type_, _compiler_, **_kw_):
    return "CHAR(36)"


class _RecordingMailer:
    """Stands in for Mailgun and records the message, not the call.

    Deliberately declares the same keyword-only signature as
    ``MailgunClient.send``. A double that accepts ``**kwargs`` would keep
    passing if the caller stopped sending ``from_name``, which is the field
    this file exists to prove reaches the wire.
    """

    def __init__(self) -> None:
        self.messages: list[dict[str, Any]] = []

    async def send(
        self,
        *,
        to: list[str],
        subject: str,
        html: str,
        text: str,
        from_addr: str | None = None,
        from_name: str | None = None,
    ) -> dict[str, Any]:
        self.messages.append({"to": to, "subject": subject, "html": html, "text": text, "from_addr": from_addr, "from_name": from_name})
        return {"id": f"<{len(self.messages)}@mailgun.test>"}


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
                # The resolver looks for a logo even when only text fields are
                # set, and it swallows every exception by design. Omitting this
                # table does not fail — it silently resolves the platform
                # default, which is the answer this file is here to disprove.
                OrgBrandAsset.__table__,
                AgentApproval.__table__,
            ],
        )
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


@pytest.fixture
def mailer(monkeypatch: pytest.MonkeyPatch) -> _RecordingMailer:
    recorder = _RecordingMailer()
    monkeypatch.setattr(endpoint, "_build_mailer", lambda: recorder)
    monkeypatch.setenv("AISOC_APPROVAL_EMAIL_RECIPIENTS", ", ".join(ONCALL))
    monkeypatch.setenv("AISOC_EMAIL_APPROVAL_SECRET", SECRET)
    # The realtime fan-out is a different notification path with its own
    # tests; leaving it pointed at nothing keeps this one offline.
    monkeypatch.setattr(endpoint.settings, "REALTIME_BASE_URL", "", raising=False)
    return recorder


@pytest.fixture
def client(session_factory) -> TestClient:
    app = FastAPI()
    app.include_router(endpoint.router, prefix="/api/v1")

    async def _db():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_tenant_db] = _db
    app.dependency_overrides[get_current_user] = lambda: CurrentUser(
        user_id=USER,
        tenant_id=TENANT,
        role="admin",
        email="analyst@acme.example",
        resolved_permissions=frozenset({"cases:write"}),
    )
    return TestClient(app, raise_server_exceptions=False)


async def _brand(session_factory, **overrides) -> None:
    async with session_factory() as db:
        db.add(Organization(id=ORG, slug="acme", name="Acme MSSP", home_tenant_id=uuid.uuid4()))
        db.add(OrganizationTenant(org_id=ORG, tenant_id=TENANT, onboarded_at=datetime.now(UTC)))
        db.add(OrgBranding(org_id=ORG, **overrides))
        await db.commit()


def _request_approval(client: TestClient) -> dict[str, Any]:
    response = client.post(
        "/api/v1/approvals",
        json={
            "title": "Isolate WKSTN-01",
            "summary": "Falcon detection with a confirmed C2 beacon.",
            "risk_level": "high",
            "case_id": "CASE-4471",
            "action": {"action_type": "isolate_host", "target": "WKSTN-01"},
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _links(text_body: str) -> list[str]:
    """The approve and deny URLs, read out of the rendered plain-text body."""
    return [line.split(":", 1)[1].strip() for line in text_body.splitlines() if line.startswith(("Approve:", "Deny:"))]


class TestTheFallbackHasAProducer:
    def test_creating_an_approval_sends_the_signed_email(self, client, mailer) -> None:
        """The defect, stated as a test.

        Nothing in the repository called ``send_approval_email``. Deleting the
        ``_notify_email`` call from ``create_approval`` turns this red, which
        is the only assertion here that could not be satisfied by the function
        existing and being correct.
        """
        _request_approval(client)

        assert mailer.messages, "creating an approval sent no email; the signed fallback has no producer"
        assert [message["to"][0] for message in mailer.messages] == ONCALL

    def test_nothing_is_sent_when_no_recipients_are_configured(self, client, mailer, monkeypatch) -> None:
        """The other direction. Mail to nobody is not a fallback."""
        monkeypatch.delenv("AISOC_APPROVAL_EMAIL_RECIPIENTS", raising=False)
        _request_approval(client)
        assert mailer.messages == []

    def test_a_missing_signing_secret_is_reported_rather_than_silently_skipped(self, client, mailer, monkeypatch, caplog) -> None:
        """An operator who set recipients is expecting mail.

        Returning quietly here is how a wired fallback looks wired and does
        nothing, which is the shape of the defect this file closes.
        """
        monkeypatch.setenv("AISOC_EMAIL_APPROVAL_SECRET", "")
        with caplog.at_level("WARNING"):
            _request_approval(client)

        assert mailer.messages == []
        assert any("AISOC_EMAIL_APPROVAL_SECRET" in record.getMessage() for record in caplog.records)

    def test_an_unreachable_mailer_does_not_fail_the_approval(self, client, mailer, monkeypatch) -> None:
        """The approval is already persisted; notification is best effort."""

        class _Broken:
            async def send(self, **_kwargs: Any) -> dict[str, Any]:
                raise EmailApprovalError("Mailgun is not configured")

        monkeypatch.setattr(endpoint, "_build_mailer", _Broken)
        assert _request_approval(client)["status"] == "pending"


class TestTheMailCarriesTheOperatorsBrand:
    @pytest.mark.asyncio
    async def test_the_subject_and_bodies_name_the_organisations_product(self, client, mailer, session_factory) -> None:
        await _brand(session_factory, product_name="Acme Shield")
        _request_approval(client)

        message = mailer.messages[0]
        assert message["subject"].startswith("[Acme Shield]")
        assert "Acme Shield approval request" in message["text"]
        assert "Acme Shield approval request" in message["html"]

    @pytest.mark.asyncio
    async def test_the_platform_name_is_gone_rather_than_sitting_beside_it(self, client, mailer, session_factory) -> None:
        """Mail showing both is not white-labelled, it is co-branded by accident."""
        await _brand(session_factory, product_name="Acme Shield")
        _request_approval(client)

        message = mailer.messages[0]
        assert "AiSOC" not in message["subject"]
        assert "AiSOC" not in message["text"]
        assert "AiSOC" not in message["html"]

    @pytest.mark.asyncio
    async def test_the_sender_name_reaches_the_mailer(self, client, mailer, session_factory) -> None:
        """``sender_name`` had no reader outside the resolver and its own test."""
        await _brand(session_factory, product_name="Acme Shield", sender_name="Acme SOC")
        _request_approval(client)

        assert mailer.messages[0]["from_name"] == "Acme SOC"

    @pytest.mark.asyncio
    async def test_the_sender_name_defaults_to_the_product_name_on_the_wire(self, client, mailer, session_factory) -> None:
        await _brand(session_factory, product_name="Acme Shield")
        _request_approval(client)

        assert mailer.messages[0]["from_name"] == "Acme Shield"

    @pytest.mark.asyncio
    async def test_the_support_contact_and_footer_are_rendered(self, client, mailer, session_factory) -> None:
        await _brand(
            session_factory,
            product_name="Acme Shield",
            support_url="https://support.acme.example",
            footer_text="Acme Shield, operated by Acme MSSP.",
        )
        _request_approval(client)

        message = mailer.messages[0]
        assert "https://support.acme.example" in message["html"]
        assert "https://support.acme.example" in message["text"]
        assert "Acme Shield, operated by Acme MSSP." in message["html"]

    @pytest.mark.asyncio
    async def test_the_palette_is_applied(self, client, mailer, session_factory) -> None:
        await _brand(session_factory, product_name="Acme Shield", primary_color="#123456", accent_color="#654321")
        _request_approval(client)

        html = mailer.messages[0]["html"]
        assert "#123456" in html
        assert "#654321" in html

    @pytest.mark.asyncio
    async def test_the_approve_and_deny_colours_are_not_brandable(self, client, mailer, session_factory) -> None:
        """Green means contains and red means does not.

        An organisation's palette must not be able to swap the two, which is
        why those two are literals while everything else resolves.
        """
        await _brand(session_factory, product_name="Acme Shield", primary_color="#123456", accent_color="#654321")
        _request_approval(client)

        html = mailer.messages[0]["html"]
        assert "#16a34a" in html
        assert "#dc2626" in html

    def test_an_unbranded_deployment_is_unchanged(self, client, mailer) -> None:
        """The negative control for every case above.

        No organisation, so the platform appearance is what renders — and that
        is the default a self-hosted install should keep seeing.
        """
        _request_approval(client)

        message = mailer.messages[0]
        assert message["subject"].startswith("[AiSOC]")
        assert message["from_name"] == "AiSOC"


class TestTheLinkStillWorks:
    def test_each_recipient_gets_a_token_naming_them_as_the_approver(self, client, mailer) -> None:
        """A shared token records every click as the same identity.

        And a token with *no* approver — which is what this function minted for
        as long as nothing called it — is refused outright by
        ``/actions/email-decide``, so the branded mail would have shipped a
        pair of buttons that do not work.
        """
        _request_approval(client)

        for message in mailer.messages:
            recipient = message["to"][0]
            links = _links(message["text"])
            assert len(links) == 2
            for url in links:
                token = parse_qs(urlparse(url).query)["token"][0]
                assert verify_token(token, secret=SECRET).approver == recipient

    def test_the_two_buttons_carry_opposite_decisions(self, client, mailer) -> None:
        _request_approval(client)

        decisions = {
            verify_token(parse_qs(urlparse(url).query)["token"][0], secret=SECRET).decision for url in _links(mailer.messages[0]["text"])
        }
        assert decisions == {"approved", "rejected"}

    def test_the_link_points_at_the_route_that_serves_it(self, client, mailer) -> None:
        """The console origin, not the API's internal address.

        A recipient clicks from a mail client; the console is the host their
        browser can reach, and it proxies ``/api/v1/*`` through.
        """
        _request_approval(client)

        for url in _links(mailer.messages[0]["text"]):
            assert urlparse(url).path == "/api/v1/actions/email-decide"


class TestTheSenderNameCannotForgeAHeader:
    """``sender_name`` is operator-supplied and lands in a mail header."""

    @pytest.mark.parametrize("hostile", ["Acme\r\nBcc: attacker@evil.example", "Acme\nX-Priority: 1"])
    def test_a_newline_in_the_display_name_is_removed(self, hostile: str) -> None:
        quoted = _quoted_display_name(hostile)
        assert "\r" not in quoted
        assert "\n" not in quoted

    def test_a_quote_is_escaped_rather_than_closing_the_string(self) -> None:
        assert _quoted_display_name('Acme" <evil@example.com> "') == '"Acme\\" <evil@example.com> \\""'


class TestTheMailBodyIsEscaped:
    """Two of the values rendered into this HTML are not ours.

    The brand fields are operator-supplied free text, and the rationale is
    the agent's summary of evidence an attacker influenced — model output
    written into a document an on-call analyst opens in a mail client.
    """

    @pytest.mark.asyncio
    async def test_a_script_tag_in_the_product_name_does_not_survive(self, client, mailer, session_factory) -> None:
        await _brand(session_factory, product_name="<script>alert(1)</script>")
        _request_approval(client)

        html = mailer.messages[0]["html"]
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_a_script_tag_in_the_agent_rationale_does_not_survive(self, client, mailer) -> None:
        response = client.post(
            "/api/v1/approvals",
            json={
                "title": "Isolate WKSTN-01",
                "summary": "<img src=x onerror=alert(1)>",
                "risk_level": "high",
                "action": {"action_type": "isolate_host", "target": "WKSTN-01"},
            },
        )
        assert response.status_code == 201, response.text

        html = mailer.messages[0]["html"]
        assert "<img src=x" not in html
        assert "&lt;img src=x" in html
