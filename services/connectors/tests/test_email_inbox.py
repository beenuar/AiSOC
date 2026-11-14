"""
Unit tests for ``EmailInboxConnector``.

We don't spin up a real IMAP server — we monkeypatch the ``imaplib``
client construction to a stand-in that behaves like ``imaplib.IMAP4_SSL``
for the surface area we exercise (``login``, ``select``, ``search``,
``fetch``, ``store``, ``close``, ``logout``).

The point of the tests is:

1. Schema declares the fields the wizard needs.
2. ``test_connection`` round-trips a successful select.
3. ``fetch_alerts`` parses RFC822 bytes into the JSON shape that the
   ``email-forwarded`` ingest template downstream expects.
4. Multipart messages get their plaintext extracted.
5. Subject decoding handles RFC 2047 encoded-words.
6. Oversized bodies get truncated rather than blowing up the pipeline.
"""

from __future__ import annotations

import asyncio
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import pytest
from app.connectors import email_inbox as email_inbox_mod
from app.connectors.email_inbox import EmailInboxConnector


class _FakeIMAP:
    """Minimal in-memory IMAP server good enough for the connector.

    Tests register messages by UID (``bytes``) before constructing the
    fake. We track which UIDs were marked seen so tests can assert the
    connector advances the cursor on success.
    """

    def __init__(
        self,
        messages: dict[bytes, bytes] | None = None,
        select_ok: bool = True,
        fail_login: bool = False,
    ):
        self._messages = dict(messages or {})
        self._select_ok = select_ok
        self._fail_login = fail_login
        self.seen: set[bytes] = set()
        self.logged_in = False
        self.logged_out = False
        self.selected: str | None = None

    # imaplib protocol surface
    def login(self, user, pw):  # noqa: ARG002 — match imaplib signature
        if self._fail_login:
            raise OSError("bad credentials")
        self.logged_in = True
        return ("OK", [b"LOGIN OK"])

    def select(self, mailbox, readonly=False):  # noqa: ARG002
        self.selected = mailbox
        if not self._select_ok:
            return ("NO", [b"select failed"])
        return ("OK", [str(len(self._messages)).encode()])

    def search(self, charset, criterion):  # noqa: ARG002
        # All registered messages are "UNSEEN" until ``store`` flags them.
        unseen = [uid for uid in self._messages if uid not in self.seen]
        return ("OK", [b" ".join(unseen)])

    def fetch(self, uid, parts):  # noqa: ARG002
        raw = self._messages.get(uid)
        if raw is None:
            return ("NO", [None])
        return ("OK", [(b"%s (RFC822 {%d}" % (uid, len(raw)), raw)])

    def store(self, uid, op, flags):  # noqa: ARG002
        if op == "+FLAGS" and "\\Seen" in flags:
            self.seen.add(uid)
        return ("OK", [b"STORE OK"])

    def close(self):
        self.selected = None
        return ("OK", [b"CLOSE OK"])

    def logout(self):
        self.logged_out = True
        return ("BYE", [b"LOGOUT OK"])


def _patch_imap(monkeypatch: pytest.MonkeyPatch, fake: _FakeIMAP) -> None:
    """Make ``EmailInboxConnector._open`` return our fake."""

    def _open(self):  # noqa: ARG001
        # Mirror the real ``_open`` contract: returns a "logged in" client.
        fake.login(self._username, self._password)
        return fake

    monkeypatch.setattr(EmailInboxConnector, "_open", _open)


def _run(coro):
    # ``asyncio.run`` is the supported entry point in Python 3.12+; the older
    # ``get_event_loop().run_until_complete`` pattern emits a DeprecationWarning
    # under PEP 678 and is slated for removal.
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


def test_email_inbox_schema_has_required_fields():
    schema = EmailInboxConnector.schema()
    names = {f.name for f in schema.fields}
    assert {"host", "port", "username", "password", "mailbox"} <= names
    assert schema.category == "saas"
    pwd = next(f for f in schema.fields if f.name == "password")
    assert pwd.type == "secret"


def test_email_inbox_capabilities_are_pull_only():
    caps = EmailInboxConnector.capabilities()
    # The connector strictly reads — no write/contain/etc. capabilities.
    assert len(caps) == 1
    assert caps[0].value == "pull_alerts"


# ---------------------------------------------------------------------------
# test_connection
# ---------------------------------------------------------------------------


def test_test_connection_succeeds_on_select_ok(monkeypatch: pytest.MonkeyPatch):
    fake = _FakeIMAP(select_ok=True)
    _patch_imap(monkeypatch, fake)
    c = EmailInboxConnector(host="imap.test", username="u", password="p")
    res = _run(c.test_connection())
    assert res["success"] is True
    assert res["connector"] == "email_inbox"
    assert fake.logged_out is True


def test_test_connection_reports_select_failure(monkeypatch: pytest.MonkeyPatch):
    fake = _FakeIMAP(select_ok=False)
    _patch_imap(monkeypatch, fake)
    c = EmailInboxConnector(host="imap.test", username="u", password="p")
    res = _run(c.test_connection())
    assert res["success"] is False
    assert "INBOX" in res["error"] or "mailbox" in res["error"]


def test_test_connection_reports_login_failure(monkeypatch: pytest.MonkeyPatch):
    fake = _FakeIMAP(fail_login=True)
    _patch_imap(monkeypatch, fake)
    c = EmailInboxConnector(host="imap.test", username="u", password="p")
    res = _run(c.test_connection())
    assert res["success"] is False
    assert "bad credentials" in res["error"]


# ---------------------------------------------------------------------------
# fetch_alerts
# ---------------------------------------------------------------------------


def _build_plaintext_message(
    subject: str = "PagerDuty Alert: prod-db-1 high CPU",
    sender: str = "noreply@pagerduty.com",
    to: str = "aisoc-alerts@example.com",
    body: str = "Service prod-db-1 is at 95% CPU. Please investigate.",
    date: str = "Tue, 05 May 2026 11:30:00 -0700",
    msg_id: str = "<incident-12345@pagerduty.com>",
) -> bytes:
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = to
    msg["Date"] = date
    msg["Message-ID"] = msg_id
    return msg.as_bytes()


def test_fetch_alerts_returns_normalized_event_for_plaintext(
    monkeypatch: pytest.MonkeyPatch,
):
    raw = _build_plaintext_message()
    fake = _FakeIMAP(messages={b"42": raw})
    _patch_imap(monkeypatch, fake)

    c = EmailInboxConnector(host="imap.test", username="u", password="p")
    events = _run(c.fetch_alerts())

    assert len(events) == 1
    e = events[0]
    assert e["subject"] == "PagerDuty Alert: prod-db-1 high CPU"
    assert e["from"] == "noreply@pagerduty.com"
    assert e["to"] == "aisoc-alerts@example.com"
    assert e["message_id"] == "<incident-12345@pagerduty.com>"
    # Body is preserved verbatim — the ingest-side template handles parsing.
    assert "prod-db-1 is at 95% CPU" in e["body"]
    # received_at parses to ISO 8601 — useful for the OCSF time field downstream.
    assert e["received_at"] is not None
    assert "2026-05-05T11:30:00" in e["received_at"]
    # And the connector must have advanced the read cursor.
    assert fake.seen == {b"42"}


def test_fetch_alerts_extracts_text_from_multipart(
    monkeypatch: pytest.MonkeyPatch,
):
    """Most alert emails ship as multipart/alternative — make sure we
    grab the text/plain part rather than the HTML soup."""
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Weekly Vulnerability Digest"
    msg["From"] = "security@example.com"
    msg["To"] = "aisoc-alerts@example.com"
    msg["Date"] = "Wed, 06 May 2026 09:00:00 +0000"
    msg.attach(MIMEText("12 new CVEs this week. CVE-2026-12345 is critical.", "plain"))
    msg.attach(
        MIMEText(
            "<html><body><h1>Digest</h1><p>HTML soup here</p></body></html>",
            "html",
        )
    )
    fake = _FakeIMAP(messages={b"7": msg.as_bytes()})
    _patch_imap(monkeypatch, fake)

    c = EmailInboxConnector(host="imap.test", username="u", password="p")
    events = _run(c.fetch_alerts())

    assert len(events) == 1
    assert "CVE-2026-12345" in events[0]["body"]
    # We should NOT have surfaced HTML tags — text/plain wins.
    assert "<h1>" not in events[0]["body"]


def test_fetch_alerts_decodes_rfc2047_subjects(monkeypatch: pytest.MonkeyPatch):
    """Subjects with non-ASCII characters arrive as RFC 2047 encoded-words.
    Anything dropping that decode would surface gibberish in alerts."""
    raw = _build_plaintext_message(
        subject="=?UTF-8?B?VHJpYWdlZDog4pyFIENyaXRpY2FsIEFsZXJ0?=",
    )
    fake = _FakeIMAP(messages={b"99": raw})
    _patch_imap(monkeypatch, fake)

    c = EmailInboxConnector(host="imap.test", username="u", password="p")
    events = _run(c.fetch_alerts())

    assert events[0]["subject"] == "Triaged: ✅ Critical Alert"


def test_fetch_alerts_truncates_oversized_body(monkeypatch: pytest.MonkeyPatch):
    """A 5 MB attachment-laden alert email shouldn't blow up the
    pipeline — the body cap kicks in."""
    huge = "x" * (email_inbox_mod._MAX_BODY_BYTES + 5_000)
    raw = _build_plaintext_message(body=huge)
    fake = _FakeIMAP(messages={b"1": raw})
    _patch_imap(monkeypatch, fake)

    c = EmailInboxConnector(host="imap.test", username="u", password="p")
    events = _run(c.fetch_alerts())

    assert len(events[0]["body"]) == email_inbox_mod._MAX_BODY_BYTES


def test_fetch_alerts_respects_max_messages_cap(monkeypatch: pytest.MonkeyPatch):
    """If the mailbox has more unread than ``max_messages``, we only
    pull the cap and leave the rest for the next poll."""
    msgs = {f"{i}".encode(): _build_plaintext_message(subject=f"Alert {i}") for i in range(10)}
    fake = _FakeIMAP(messages=msgs)
    _patch_imap(monkeypatch, fake)

    c = EmailInboxConnector(host="imap.test", username="u", password="p", max_messages=3)
    events = _run(c.fetch_alerts())

    assert len(events) == 3
    # Three flagged seen, seven still untouched for the next poll.
    assert len(fake.seen) == 3


def test_fetch_alerts_returns_empty_on_imap_failure(
    monkeypatch: pytest.MonkeyPatch,
):
    """A flaky IMAP server should not crash the scheduler — empty list,
    log a warning, retry on next poll."""

    def _broken_open(self):  # noqa: ARG001
        raise OSError("connection reset")

    monkeypatch.setattr(EmailInboxConnector, "_open", _broken_open)
    c = EmailInboxConnector(host="imap.test", username="u", password="p")
    events = _run(c.fetch_alerts())
    assert events == []


def test_use_ssl_string_form_is_truthy(monkeypatch: pytest.MonkeyPatch):
    """The wizard form may serialize booleans as strings — make sure
    "true"/"false" round-trip correctly."""
    c1 = EmailInboxConnector(host="imap.test", username="u", password="p", use_ssl="true")
    assert c1._use_ssl is True
    c2 = EmailInboxConnector(host="imap.test", username="u", password="p", use_ssl="false")
    assert c2._use_ssl is False
