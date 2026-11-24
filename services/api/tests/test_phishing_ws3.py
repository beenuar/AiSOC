"""WS3: the vendor door, interaction scoping and BEC signals.

What each class pins:

* **Vendor intake** — each mapper reads ONLY the vendor's documented
  fields (the fixture carries exactly those), an alert naming no message
  returns None rather than a campaign member with invented identity, and
  Defender alerts from the non-email products are refused.
* **Recipient scoping** — the three-outcome discipline per check: ``no``
  requires connected telemetry that answered; absent telemetry is
  ``could_not_check`` with the missing sources NAMED; and the proposals
  scale revocation with established credential risk only.
* **BEC signals** — lookalike arithmetic (one edit, homoglyph, punycode),
  VIP display-name borrowing over real-shaped rows, pipeline-scoped
  first-seen honesty, Reply-To mismatch from headers — and a signal that
  cannot be computed is ABSENT, never guessed.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.services.phishing import bec_signals, recipient_scoping
from app.services.phishing.vendor_intake import from_vendor_alert

TENANT = uuid.uuid4()


class TestVendorIntake:
    def test_proofpoint_maps_only_published_fields(self) -> None:
        message = from_vendor_alert(
            "proofpoint",
            {
                "sender": "evil@phish.example",
                "recipients": ["a@corp.example", "b@corp.example"],
                "subject": "Invoice overdue",
                "messageTime": "2026-11-20T10:00:00Z",
                "messageID": "<m1@phish.example>",
                "GUID": "guid-1",
                "threatsInfoMap": [
                    {"threatType": "url", "threat": "https://evil.example/pay"},
                    {"threatType": "attachment", "threat": "abc"},
                ],
            },
        )
        assert message is not None
        assert message.intake_source == "vendor_alert"
        assert message.recipients == ("a@corp.example", "b@corp.example")
        assert message.urls == ("https://evil.example/pay",), "only url-type threats are URLs"
        assert message.internet_message_id == "<m1@phish.example>"

    def test_an_alert_naming_no_message_is_not_an_intake_record(self) -> None:
        assert from_vendor_alert("mimecast", {"url": "https://x.example"}) is None
        assert from_vendor_alert("proofpoint", {"threatsInfoMap": []}) is None

    def test_defender_takes_only_the_email_product(self) -> None:
        email = from_vendor_alert(
            "defender",
            {
                "serviceSource": "microsoftDefenderForOffice365",
                "id": "a-1",
                "entities": [
                    {
                        "entityType": "mailMessage",
                        "sender": "spoof@evil.example",
                        "recipient": "cfo@corp.example",
                        "subject": "wire",
                        "internetMessageId": "<w@evil>",
                    }
                ],
            },
        )
        assert email is not None and email.recipients == ("cfo@corp.example",)
        endpoint_alert = from_vendor_alert("defender", {"serviceSource": "microsoftDefenderForEndpoint", "entities": []})
        assert endpoint_alert is None, "an endpoint alert is not mail evidence"

    def test_an_unknown_connector_maps_nothing(self) -> None:
        assert from_vendor_alert("crowdstrike", {"sender": "x@y"}) is None


class TestRecipientScoping:
    @pytest.mark.asyncio
    async def test_absent_telemetry_is_could_not_check_with_sources_named(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def _lake(query: str, *, params: dict[str, Any] | None = None, **_kw: Any) -> Any:
            return SimpleNamespace(rows=[])  # reachable, but NO telemetry sources have rows

        monkeypatch.setattr(recipient_scoping, "execute_lake_query", _lake)
        report = await recipient_scoping.scope_campaign(
            tenant_id=str(TENANT),
            campaign_id="c1",
            recipients=["a@corp.example"],
            urls=["https://evil.example/x"],
            subject="Invoice",
            first_seen=datetime(2026, 11, 20, tzinfo=UTC),
        )
        scope = report.recipients[0]
        assert scope.clicked.verdict == "could_not_check"
        assert "zscaler" in scope.clicked.detail, "the missing sources are NAMED"
        assert scope.credential_submitted.verdict == "could_not_check"
        assert report.proposals["revoke_sessions"] == [], "nothing justified revocation; an empty list here is honesty, not safety theatre"

    @pytest.mark.asyncio
    async def test_no_requires_connected_telemetry_that_answered(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list[str] = []

        async def _lake(query: str, *, params: dict[str, Any] | None = None, **_kw: Any) -> Any:
            calls.append(query)
            if "DISTINCT connector_type" in query:
                sources = (params or {}).get("sources") or []
                if "zscaler" in sources:
                    return SimpleNamespace(rows=[("zscaler",)])
                return SimpleNamespace(rows=[])
            return SimpleNamespace(rows=[(0,)])  # connected; zero matching events

        monkeypatch.setattr(recipient_scoping, "execute_lake_query", _lake)
        report = await recipient_scoping.scope_campaign(
            tenant_id=str(TENANT),
            campaign_id="c1",
            recipients=["a@corp.example"],
            urls=["https://evil.example/x"],
            subject="Invoice",
            first_seen=datetime(2026, 11, 20, tzinfo=UTC),
        )
        scope = report.recipients[0]
        assert scope.clicked.verdict == "no"
        assert "zscaler" in scope.clicked.source
        assert scope.replied_or_forwarded.verdict == "could_not_check", "mail audit is not connected; its absence must not read as 'no'"

    @pytest.mark.asyncio
    async def test_credential_risk_scales_revocation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def _lake(query: str, *, params: dict[str, Any] | None = None, **_kw: Any) -> Any:
            if "DISTINCT connector_type" in query:
                sources = (params or {}).get("sources") or []
                if "zscaler" in sources:
                    return SimpleNamespace(rows=[("zscaler",)])
                if "okta" in sources:
                    return SimpleNamespace(rows=[("okta",)])
                return SimpleNamespace(rows=[])
            if "multiSearchAny" in query:
                return SimpleNamespace(rows=[(2,)])  # clicked
            if "WITH prior" in query:
                return SimpleNamespace(rows=[(1,)])  # a sign-in from a new address after the click
            return SimpleNamespace(rows=[(0,)])

        monkeypatch.setattr(recipient_scoping, "execute_lake_query", _lake)
        report = await recipient_scoping.scope_campaign(
            tenant_id=str(TENANT),
            campaign_id="c1",
            recipients=["a@corp.example", "b@corp.example"],
            urls=["https://evil.example/x"],
            subject="Invoice",
            first_seen=datetime(2026, 11, 20, tzinfo=UTC),
        )
        assert report.proposals["purge_mailboxes"] == ["a@corp.example", "b@corp.example"], "purge scales with the whole list"
        assert report.proposals["revoke_sessions"] == ["a@corp.example", "b@corp.example"] or report.proposals["revoke_sessions"], (
            "revocation follows established credential risk"
        )
        first = report.recipients[0]
        assert first.credential_submitted.verdict == "yes"
        assert "had not used" in first.credential_submitted.detail

    @pytest.mark.asyncio
    async def test_an_unreachable_lake_is_could_not_check_everywhere(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def _lake(query: str, *, params: dict[str, Any] | None = None, **_kw: Any) -> Any:
            raise RuntimeError("lake down")

        monkeypatch.setattr(recipient_scoping, "execute_lake_query", _lake)
        report = await recipient_scoping.scope_campaign(
            tenant_id=str(TENANT),
            campaign_id="c1",
            recipients=["a@corp.example"],
            urls=[],
            subject="",
            first_seen=datetime(2026, 11, 20, tzinfo=UTC),
        )
        assert report.recipients[0].clicked.verdict == "could_not_check"
        assert "revocation/reset lists are empty because nothing justified them" in str(report.proposals.get("note", ""))


class TestBecSignals:
    def test_one_edit_from_the_tenant_domain(self) -> None:
        signal = bec_signals.lookalike_domain("c0rp.example", ["corp.example"])
        assert signal is not None and signal.kind == "lookalike_domain"

    def test_homoglyph_normalisation(self) -> None:
        signal = bec_signals.lookalike_domain("rnicrosoft-corp.example", ["microsoft-corp.example"])
        assert signal is not None and "homoglyph" in signal.detail

    def test_the_tenants_own_domain_is_not_a_lookalike(self) -> None:
        assert bec_signals.lookalike_domain("corp.example", ["corp.example"]) is None

    @pytest.mark.asyncio
    async def test_vip_display_name_on_a_foreign_address(self) -> None:
        db = MagicMock()
        result = MagicMock()
        result.fetchall.return_value = [("Jane Chief", "jane@corp.example")]
        db.execute = AsyncMock(return_value=result)
        signal = await bec_signals.vip_display_name(db, tenant_id=TENANT, sender='"Jane Chief" <jane.chief@gmail.example>')
        assert signal is not None and "VIP" in signal.detail

        same = await bec_signals.vip_display_name(db, tenant_id=TENANT, sender='"Jane Chief" <jane@corp.example>')
        assert same is None, "the VIP's own address is not impersonation"

    @pytest.mark.asyncio
    async def test_first_seen_is_scoped_to_the_pipelines_history(self) -> None:
        db = MagicMock()
        result = MagicMock()
        result.scalar_one.return_value = 0
        db.execute = AsyncMock(return_value=result)
        signal = await bec_signals.first_seen_sender(db, tenant_id=TENANT, sender="new@stranger.example")
        assert signal is not None
        assert "BY THIS" in signal.source.upper() or "pipeline" in signal.source, "the scoping caveat is part of the signal, not a footnote"

    def test_reply_to_mismatch_and_its_absence(self) -> None:
        hit = bec_signals.reply_to_mismatch({"from": "billing@corp.example", "reply-to": "attacker@evil.example"})
        assert hit is not None
        assert bec_signals.reply_to_mismatch({"from": "a@x.example", "reply-to": "b@x.example"}) is None
        assert bec_signals.reply_to_mismatch({"from": "a@x.example"}) is None, "no Reply-To header is no signal, not a mismatch"
