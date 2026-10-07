"""Depth 5.2 — the five delivery claims, each of which was false.

Reproduce, measured on the tree this started from:

1. `report_templates.cron_schedule` is a storable, editable field and
   **nothing in `services/api` reads it**, so a tenant could set a schedule
   in the console, see it saved, and never receive a report. Separately,
   `POST /reports/generate` wrote `status="pending"` and nothing ever moved
   it off pending.
2. **No SMTP anywhere in `services/api`** — `grep -rl smtplib` returned
   nothing — while `destinations.dispatch("email", ...)` answered
   `detail="formatted"` and sent nothing.
3. `send_approval_email` had **one reference in the whole tree, its own
   definition**. The verifier, the renderer, the signed URLs and the
   `/approvals/email/decide` route had all shipped, waiting for a link
   nothing ever sent.
4. `services/teams-bot` appeared in **no compose file**, had no Dockerfile,
   and had no route that could post a card.
5. `grep -rln outbound_webhook services/ apps/` returned nothing: AiSOC
   could be told things and could tell nobody anything.

What is asserted below is mostly the honest no-op. Every one of these
channels can be unconfigured, and the thing that matters is that an
unconfigured channel says so instead of reporting a delivery.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from app.services import approval_delivery, outbound_webhooks, smtp_delivery
from app.workers import report_scheduler

pytestmark = pytest.mark.asyncio


class _Recorder:
    """A stand-in transport that records requests and replays answers.

    ``httpx.MockTransport`` rather than ``respx``: the actions and
    connectors services lock respx and this one does not, and adding a test
    dependency to the service with the largest dependency set to avoid
    twenty lines is the wrong trade. The transport sits *under* the real
    ``AsyncClient``, so request building, header assembly and the body the
    signature covers all run exactly as they do in production.
    """

    def __init__(self, *responses: httpx.Response | Exception) -> None:
        self._responses = list(responses)
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        answer = self._responses[min(len(self.requests) - 1, len(self._responses) - 1)]
        if isinstance(answer, Exception):
            raise answer
        return httpx.Response(answer.status_code, content=answer.content, headers=answer.headers)

    @property
    def called(self) -> bool:
        return bool(self.requests)

    def install(self, monkeypatch: pytest.MonkeyPatch, module: Any) -> _Recorder:
        """Make every ``AsyncClient`` built by ``module`` use this transport."""
        real = httpx.AsyncClient

        def _factory(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
            kwargs["transport"] = httpx.MockTransport(self)
            return real(*args, **kwargs)

        monkeypatch.setattr(module.httpx, "AsyncClient", _factory)
        return self


def _ok(status_code: int = 200, payload: dict[str, Any] | None = None, text: str = "") -> httpx.Response:
    if payload is not None:
        return httpx.Response(status_code, json=payload)
    return httpx.Response(status_code, text=text)


# ---------------------------------------------------------------------------
# 2. SMTP
# ---------------------------------------------------------------------------


class TestSmtpDelivery:
    async def test_no_relay_is_skipped_and_says_which_setting(self) -> None:
        result = await smtp_delivery.send_mail(
            recipients=["soc@example.com"],
            subject="x",
            text_body="y",
            settings=smtp_delivery.SmtpSettings(),
        )
        assert result.delivered is False
        assert result.status == "skipped"
        assert "SMTP_HOST" in result.detail

    async def test_no_recipients_is_skipped_not_sent(self) -> None:
        result = await smtp_delivery.send_mail(
            recipients=[],
            subject="x",
            text_body="y",
            settings=smtp_delivery.SmtpSettings(host="relay.example.com", sender="aisoc@example.com"),
        )
        assert (result.delivered, result.status) == (False, "skipped")

    async def test_a_relay_failure_is_reported_not_swallowed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _boom(*args: Any, **kwargs: Any) -> None:
            raise OSError("connection refused")

        monkeypatch.setattr(smtp_delivery, "_send_blocking", _boom)
        result = await smtp_delivery.send_mail(
            recipients=["soc@example.com"],
            subject="x",
            text_body="y",
            settings=smtp_delivery.SmtpSettings(host="relay.example.com", sender="aisoc@example.com"),
        )
        assert (result.delivered, result.status) == (False, "failed")
        assert "connection refused" in result.detail

    async def test_a_send_builds_a_message_with_both_parts_and_the_attachment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: list[Any] = []
        monkeypatch.setattr(smtp_delivery, "_send_blocking", lambda settings, message: captured.append(message))

        result = await smtp_delivery.send_mail(
            recipients="a@example.com, b@example.com",
            subject="Weekly report",
            text_body="plain",
            html_body="<p>rich</p>",
            attachment=("report.html", b"<html></html>", "text/html"),
            settings=smtp_delivery.SmtpSettings(host="relay.example.com", sender="aisoc@example.com"),
        )
        assert result.delivered is True
        message = captured[0]
        assert message["To"] == "a@example.com, b@example.com"
        # A plain-text alternative is always present: an analyst on a
        # locked-down gateway still needs the decision link.
        assert {part.get_content_type() for part in message.walk()} >= {"text/plain", "text/html"}

    def test_the_smtp_mailer_matches_the_mail_delivery_protocol(self) -> None:
        """`email_approval.send_approval_email` calls it by that Protocol.

        A signature mismatch would be invisible until the first real
        approval, because nothing else constructs this class.
        """
        import inspect

        from app.services.email_approval import MailDeliveryClient

        expected = inspect.signature(MailDeliveryClient.send).parameters
        actual = inspect.signature(smtp_delivery.SmtpApprovalMailer.send).parameters
        assert set(expected) == set(actual)


# ---------------------------------------------------------------------------
# 3 and 4. Approval delivery: email, Slack, Teams
# ---------------------------------------------------------------------------


def _approval(**overrides: Any) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid.uuid4(),
        case_id=uuid.uuid4(),
        title="Isolate web-prod-04",
        summary="Credential access observed",
        risk_level="high",
        action={"action_type": "isolate_host", "target": "web-prod-04", **overrides.pop("action", {})},
        **overrides,
    )


class TestApprovalDelivery:
    async def test_every_channel_is_skipped_with_its_setting_when_unconfigured(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for name in (
            "AISOC_APPROVAL_TOKEN_SECRET",
            "SMTP_HOST",
            "SMTP_SENDER",
            "AISOC_SLACK_BOT_URL",
            "AISOC_TEAMS_BOT_URL",
            "AISOC_INTERNAL_TOKEN",
        ):
            monkeypatch.delenv(name, raising=False)

        report = await approval_delivery.deliver_approval(_approval())
        assert set(report.channels) == {"email", "slack", "teams"}
        assert report.delivered_to == []
        assert all(result["status"] == "skipped" for result in report.channels.values())
        assert "AISOC_SLACK_BOT_URL" in report.channels["slack"]["detail"]
        assert "AISOC_TEAMS_BOT_URL" in report.channels["teams"]["detail"]

    async def test_email_refuses_to_send_an_unsigned_decision_link(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A one-click approve anybody could forge is worse than no email."""
        monkeypatch.delenv("AISOC_APPROVAL_TOKEN_SECRET", raising=False)
        monkeypatch.setenv("SMTP_HOST", "relay.example.com")
        monkeypatch.setenv("SMTP_SENDER", "aisoc@example.com")

        report = await approval_delivery.deliver_approval(_approval(action={"approver_emails": ["soc@example.com"]}))
        assert report.channels["email"]["delivered"] is False
        assert "AISOC_APPROVAL_TOKEN_SECRET" in report.channels["email"]["detail"]

    async def test_a_card_the_bot_did_not_post_is_not_a_delivery(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The bots answer 202 with `posted: false` when no channel is set.

        Reading the status code alone — which is the obvious
        implementation — would record that as delivered.
        """
        monkeypatch.setenv("AISOC_SLACK_BOT_URL", "http://slack-bot:8089")
        monkeypatch.setenv("AISOC_INTERNAL_TOKEN", "tok")
        monkeypatch.delenv("AISOC_TEAMS_BOT_URL", raising=False)
        _Recorder(_ok(202, {"posted": False, "reason": "no approvals channel configured"})).install(monkeypatch, approval_delivery)

        report = await approval_delivery.deliver_approval(_approval())
        assert report.channels["slack"]["delivered"] is False
        assert "no approvals channel" in report.channels["slack"]["detail"]

    async def test_a_posted_card_is_a_delivery_and_carries_the_internal_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AISOC_TEAMS_BOT_URL", "http://teams-bot:8090")
        monkeypatch.setenv("AISOC_INTERNAL_TOKEN", "tok")
        monkeypatch.delenv("AISOC_SLACK_BOT_URL", raising=False)
        recorder = _Recorder(_ok(202, {"posted": True})).install(monkeypatch, approval_delivery)

        report = await approval_delivery.deliver_approval(_approval())
        assert report.channels["teams"]["delivered"] is True
        assert report.delivered_to == ["teams"]
        assert recorder.requests[0].headers["X-AiSOC-Internal-Token"] == "tok"

    async def test_a_bot_that_is_down_does_not_take_the_approval_with_it(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The row is already durable; a channel outage must leave a record."""
        monkeypatch.setenv("AISOC_SLACK_BOT_URL", "http://slack-bot:8089")
        monkeypatch.setenv("AISOC_INTERNAL_TOKEN", "tok")
        _Recorder(httpx.ConnectError("refused")).install(monkeypatch, approval_delivery)

        report = await approval_delivery.deliver_approval(_approval())
        assert report.channels["slack"]["status"] == "failed"

    async def test_a_missing_internal_token_is_named_rather_than_round_tripped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Both bots refuse an unset token, so posting is a guaranteed 401."""
        monkeypatch.setenv("AISOC_SLACK_BOT_URL", "http://slack-bot:8089")
        monkeypatch.delenv("AISOC_INTERNAL_TOKEN", raising=False)
        report = await approval_delivery.deliver_approval(_approval())
        assert "AISOC_INTERNAL_TOKEN" in report.channels["slack"]["detail"]


# ---------------------------------------------------------------------------
# 5. Outbound event webhooks
# ---------------------------------------------------------------------------


class TestWebhookSignature:
    def test_a_signature_round_trips(self) -> None:
        body = b'{"a":1}'
        header = outbound_webhooks.sign(body, secret="s3cret", timestamp=1_700_000_000)
        assert outbound_webhooks.verify(body, header, secret="s3cret", now=1_700_000_000)

    def test_a_modified_body_fails(self) -> None:
        header = outbound_webhooks.sign(b'{"a":1}', secret="s3cret", timestamp=1_700_000_000)
        assert not outbound_webhooks.verify(b'{"a":2}', header, secret="s3cret", now=1_700_000_000)

    def test_a_different_secret_fails(self) -> None:
        header = outbound_webhooks.sign(b"x", secret="s3cret", timestamp=1_700_000_000)
        assert not outbound_webhooks.verify(b"x", header, secret="other", now=1_700_000_000)

    def test_a_replayed_body_outside_the_window_fails(self) -> None:
        """The timestamp is inside the signed material, so an attacker
        cannot re-stamp a captured body."""
        header = outbound_webhooks.sign(b"x", secret="s3cret", timestamp=1_700_000_000)
        assert not outbound_webhooks.verify(b"x", header, secret="s3cret", now=1_700_000_000 + 3600)
        forged = header.replace("t=1700000000", "t=1700003600")
        assert not outbound_webhooks.verify(b"x", forged, secret="s3cret", now=1_700_000_000 + 3600)

    @pytest.mark.parametrize("header", ["", "garbage", "t=abc,v1=xx", "v1=xx", "t=1700000000"])
    def test_a_malformed_header_fails_rather_than_raising(self, header: str) -> None:
        assert not outbound_webhooks.verify(b"x", header, secret="s", now=1_700_000_000)


def _delivery(**overrides: Any) -> Any:
    from app.models.outbound_webhook import OutboundDelivery

    defaults = {
        "id": uuid.uuid4(),
        "tenant_id": uuid.uuid4(),
        "webhook_id": uuid.uuid4(),
        "event_type": "alert.created",
        "payload": {"alert_id": "a-1"},
        "status": "pending",
        "attempts": 0,
        "created_at": datetime.now(UTC),
        "last_error": "",
    }
    return OutboundDelivery(**{**defaults, **overrides})


def _webhook(url: str = "https://receiver.example.com/hook") -> Any:
    from app.models.outbound_webhook import OutboundWebhook

    return OutboundWebhook(id=uuid.uuid4(), tenant_id=uuid.uuid4(), name="dest", url=url, event_types=[], secret="", enabled=True)


class TestWebhookDelivery:
    async def test_a_2xx_is_delivered_and_stops_retrying(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _Recorder(_ok(200)).install(monkeypatch, outbound_webhooks)
        delivery = await outbound_webhooks.attempt_delivery(_delivery(), _webhook())
        assert delivery.status == "delivered"
        assert delivery.next_attempt_at is None
        assert delivery.delivered_at is not None

    async def test_a_5xx_is_retried_with_a_backoff(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _Recorder(_ok(503)).install(monkeypatch, outbound_webhooks)
        delivery = await outbound_webhooks.attempt_delivery(_delivery(), _webhook())
        assert delivery.status == "pending"
        assert delivery.next_attempt_at is not None
        assert delivery.next_attempt_at > datetime.now(UTC)

    async def test_a_4xx_is_dead_immediately(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The receiver understood and refused. Six identical refusals
        would be six identical answers, and the operator needs the first."""
        _Recorder(_ok(410, text="gone")).install(monkeypatch, outbound_webhooks)
        delivery = await outbound_webhooks.attempt_delivery(_delivery(), _webhook())
        assert delivery.status == "dead"
        assert delivery.attempts == 1
        assert "410" in delivery.last_error

    @pytest.mark.parametrize("code", [408, 425, 429])
    async def test_the_three_retryable_client_statuses_are_retried(self, code: int, monkeypatch: pytest.MonkeyPatch) -> None:
        _Recorder(_ok(code)).install(monkeypatch, outbound_webhooks)
        delivery = await outbound_webhooks.attempt_delivery(_delivery(), _webhook())
        assert delivery.status == "pending"

    async def test_the_ladder_ends_in_the_dead_letter_view(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _Recorder(_ok(503)).install(monkeypatch, outbound_webhooks)
        delivery = _delivery(attempts=outbound_webhooks.MAX_ATTEMPTS - 1)
        await outbound_webhooks.attempt_delivery(delivery, _webhook())
        assert delivery.attempts == outbound_webhooks.MAX_ATTEMPTS
        assert delivery.status == "dead"
        assert delivery.next_attempt_at is None

    async def test_a_connection_failure_is_retried_not_dead(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _Recorder(httpx.ConnectError("refused")).install(monkeypatch, outbound_webhooks)
        delivery = await outbound_webhooks.attempt_delivery(_delivery(), _webhook())
        assert delivery.status == "pending"
        assert "could not be reached" in delivery.last_error

    async def test_the_body_is_byte_identical_across_attempts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The signature covers the body. A dict that serialised in a
        different order would be a differently-signed message claiming to
        be the same event."""
        recorder = _Recorder(_ok(503)).install(monkeypatch, outbound_webhooks)
        delivery = _delivery(payload={"b": 2, "a": 1, "c": {"z": 1, "y": 2}})
        webhook = _webhook()
        await outbound_webhooks.attempt_delivery(delivery, webhook)
        await outbound_webhooks.attempt_delivery(delivery, webhook)
        assert recorder.requests[0].read() == recorder.requests[1].read()
        envelope = json.loads(recorder.requests[0].read())
        assert envelope["id"] == str(delivery.id)
        assert envelope["type"] == "alert.created"

    async def test_a_signed_delivery_verifies_at_the_receiver(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """End to end over the wire: sign here, verify as a receiver would."""
        monkeypatch.setattr(outbound_webhooks, "_secret_for", lambda webhook: "shared")
        recorder = _Recorder(_ok(200)).install(monkeypatch, outbound_webhooks)
        await outbound_webhooks.attempt_delivery(_delivery(), _webhook())
        request = recorder.requests[0]
        assert outbound_webhooks.verify(request.read(), request.headers["X-AiSOC-Signature"], secret="shared")

    async def test_an_undecryptable_secret_is_dead_not_sent_unsigned(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Sending unsigned because a key would not decrypt is how a
        receiver that checks signatures starts rejecting everything."""

        def _boom(webhook: Any) -> str:
            raise ValueError("key rotated out")

        monkeypatch.setattr(outbound_webhooks, "_secret_for", _boom)
        recorder = _Recorder(_ok(200)).install(monkeypatch, outbound_webhooks)
        delivery = await outbound_webhooks.attempt_delivery(_delivery(), _webhook())
        assert delivery.status == "dead"
        assert not recorder.called


# ---------------------------------------------------------------------------
# 1. The report scheduler
# ---------------------------------------------------------------------------


class TestCronMatching:
    @pytest.mark.parametrize(
        ("expression", "moment", "expected"),
        [
            ("* * * * *", datetime(2026, 10, 7, 9, 0, tzinfo=UTC), True),
            ("0 9 * * *", datetime(2026, 10, 7, 9, 0, tzinfo=UTC), True),
            ("0 9 * * *", datetime(2026, 10, 7, 9, 1, tzinfo=UTC), False),
            ("*/15 * * * *", datetime(2026, 10, 7, 9, 30, tzinfo=UTC), True),
            ("*/15 * * * *", datetime(2026, 10, 7, 9, 31, tzinfo=UTC), False),
            # 2026-10-07 is a Wednesday; cron Sunday=0, so Wednesday is 3.
            ("0 9 * * 3", datetime(2026, 10, 7, 9, 0, tzinfo=UTC), True),
            ("0 9 * * 1", datetime(2026, 10, 7, 9, 0, tzinfo=UTC), False),
            ("0 9 * * 1-5", datetime(2026, 10, 7, 9, 0, tzinfo=UTC), True),
            ("0 9,17 * * *", datetime(2026, 10, 7, 17, 0, tzinfo=UTC), True),
        ],
    )
    def test_matches(self, expression: str, moment: datetime, expected: bool) -> None:
        assert report_scheduler.cron_is_due(expression, moment) is expected

    @pytest.mark.parametrize("expression", ["", "* * * *", "@weekly", "x * * * *", "0 99 * * *", "*/0 * * * *"])
    def test_an_unparseable_expression_raises_rather_than_matching_everything(self, expression: str) -> None:
        """Treating what it cannot parse as "every minute" is how one bad
        field becomes 168 emails."""
        with pytest.raises(ValueError):
            report_scheduler.cron_is_due(expression, datetime(2026, 10, 7, 9, 0, tzinfo=UTC))

    def test_a_schedule_between_polls_is_not_missed(self) -> None:
        """The poll is five minutes and cron granularity is one.

        Asking "does the current minute match" — the obvious
        implementation — would check 08:57 and 09:02 and never 09:00, so a
        weekly report would simply never go out and nothing would say so.
        """
        now = datetime(2026, 10, 7, 9, 2, tzinfo=UTC)
        assert report_scheduler.cron_is_due("0 9 * * *", now) is False
        assert report_scheduler.due_since("0 9 * * *", since=now - timedelta(minutes=5), now=now) is True

    def test_an_already_run_schedule_does_not_run_twice(self) -> None:
        now = datetime(2026, 10, 7, 9, 2, tzinfo=UTC)
        assert report_scheduler.due_since("0 9 * * *", since=datetime(2026, 10, 7, 9, 1, tzinfo=UTC), now=now) is False

    def test_a_long_outage_collapses_into_one_report(self) -> None:
        """Seven daily emails on restart is its own incident."""
        now = datetime(2026, 10, 7, 9, 2, tzinfo=UTC)
        assert report_scheduler.due_since("0 9 * * *", since=now - timedelta(days=7), now=now) is True
        # The catch-up window is bounded, so the pass that follows this one
        # cannot find six more occurrences to fire.
        assert report_scheduler._MAX_CATCHUP == timedelta(hours=24)
