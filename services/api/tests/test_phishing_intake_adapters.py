"""Three vendor shapes become one reported message, and the grading that follows.

The payloads below are the documented vendor shapes — a Microsoft Graph
``message`` resource with ``internetMessageHeaders``, a Gmail ``Message`` with
``payload.headers[].name/value``, and the flat dict
``EmailInboxConnector._to_event`` emits — rather than a tidied shape the
adapters happen to parse. Accepting a convenient shape and testing against it
is how an intake path passes every test and fails on the first real message.

The hardest case here is the forwarded report, and it is the common one: a
user who reports phish by forwarding it becomes the *sender* of the outer
message. An adapter that reads the envelope names the victim as the attacker
and puts the report mailbox in the recipient list, which would then be the
mailbox the purge proposes to clean.
"""

from __future__ import annotations

import pytest
from app.services.phishing.campaigns import (
    FACTUAL_BASES,
    GROUPING_ORDER,
    grouping_decision,
    normalise_subject,
)
from app.services.phishing.intake import (
    INTAKE_SOURCES,
    ReportedMessage,
    from_email_inbox_event,
    from_gmail_message,
    from_graph_message,
    normalise,
    normalise_message_id,
)

PHISH_SENDER = "billing@phish.example.net"
VICTIM = "alice@example.com"
SECOND_VICTIM = "bob@example.com"
REPORT_MAILBOX = "phishing@example.com"
MESSAGE_ID = "<CAF.20261011.0001@mail.example.net>"


#: A Graph `message` resource as a report mailbox holds it after a user
#: forwarded the phish: the envelope is from the victim, to the report
#: mailbox, and the original is preserved in the internet headers.
GRAPH_FORWARDED = {
    "id": "AAMkAGI2THVSAAA=",
    "internetMessageId": "<fwd.20261011.9001@example.com>",
    "subject": "FW: Action required: your invoice is overdue",
    "from": {"emailAddress": {"name": "Alice Example", "address": VICTIM}},
    "sender": {"emailAddress": {"address": VICTIM}},
    "toRecipients": [{"emailAddress": {"address": REPORT_MAILBOX}}],
    "ccRecipients": [],
    "receivedDateTime": "2026-10-11T06:04:00Z",
    "parentFolderId": "AQMkADAwATM0MDAAMS0wAGZmYy1",
    "hasAttachments": True,
    "internetMessageHeaders": [
        {"name": "Message-ID", "value": MESSAGE_ID},
        {"name": "From", "value": f'"Billing Dept" <{PHISH_SENDER}>'},
        {"name": "To", "value": f"{VICTIM}, {SECOND_VICTIM}"},
        {"name": "Subject", "value": "Action required: your invoice is overdue"},
        {"name": "Received", "value": "from mx1.phish.example.net by example.com"},
        {"name": "Received", "value": "from relay.phish.example.net by mx1.phish.example.net"},
        {"name": "Authentication-Results", "value": "spf=fail smtp.mailfrom=phish.example.net; dkim=none; dmarc=fail"},
    ],
    "body": {
        "contentType": "text",
        "content": "Your invoice is overdue. Pay now at https://pay.phish.example.net/invoice/10452 or your account is suspended.",
    },
    "attachments": [{"name": "invoice.html", "contentType": "text/html", "size": 2048}],
}

GMAIL_REPORT = {
    "id": "19a2f4c1d0e5b7a3",
    "threadId": "19a2f4c1d0e5b7a3",
    "labelIds": ["INBOX", "UNREAD"],
    "snippet": "Your invoice is overdue. Pay now at https://pay.phish.example.net/invoice/98113",
    "payload": {
        "mimeType": "multipart/mixed",
        "headers": [
            {"name": "Delivered-To", "value": REPORT_MAILBOX},
            {"name": "Message-ID", "value": MESSAGE_ID},
            {"name": "From", "value": f"Billing Dept <{PHISH_SENDER}>"},
            {"name": "To", "value": VICTIM},
            {"name": "Cc", "value": SECOND_VICTIM},
            {"name": "Subject", "value": "Action required: your invoice is overdue"},
            {"name": "Date", "value": "Sun, 11 Oct 2026 06:04:00 +0000"},
            {"name": "Authentication-Results", "value": "mx.google.com; spf=fail; dkim=none; dmarc=fail"},
        ],
        "parts": [
            {"partId": "0", "mimeType": "text/plain", "filename": "", "body": {"size": 120}},
            {"partId": "1", "mimeType": "text/html", "filename": "invoice.html", "body": {"size": 2048}},
        ],
    },
}

EMAIL_INBOX_EVENT = {
    "subject": "Action required: your invoice is overdue",
    "from": f'"Billing Dept" <{PHISH_SENDER}>',
    "to": f"{VICTIM}, {SECOND_VICTIM}",
    "received_at": "2026-10-11T06:04:00+00:00",
    "message_id": MESSAGE_ID,
    "body": "Your invoice is overdue. Pay now at https://pay.phish.example.net/invoice/10452",
}


class TestTheGraphAdapterReadsThroughTheForward:
    def test_the_reported_sender_is_the_attacker_not_the_reporter(self) -> None:
        message = from_graph_message(GRAPH_FORWARDED)
        assert message.sender == PHISH_SENDER
        assert message.reported_by == VICTIM

    def test_the_recipients_are_the_original_ones_not_the_report_mailbox(self) -> None:
        """The report mailbox is not a victim, and proposing to purge it would be absurd."""
        message = from_graph_message(GRAPH_FORWARDED)
        assert set(message.recipients) == {VICTIM, SECOND_VICTIM}
        assert REPORT_MAILBOX not in message.recipients

    def test_the_message_id_is_the_originals_not_the_forwards(self) -> None:
        """The forward's own id finds the forward. The purge needs the phish."""
        message = from_graph_message(GRAPH_FORWARDED)
        assert message.internet_message_id == MESSAGE_ID

    def test_repeated_headers_keep_every_hop(self) -> None:
        """Received appears once per hop and the chain is the whole of its value."""
        message = from_graph_message(GRAPH_FORWARDED)
        # Compared as whole hop lines rather than by substring. A
        # substring test on a hostname is the `py/incomplete-url-substring-
        # sanitization` shape, and it is a weaker assertion here anyway:
        # "relay.phish.example.net" is in the joined value whether the hop
        # survived as its own line or was folded into the other one.
        assert message.headers["received"].split("\n") == [
            "from mx1.phish.example.net by example.com",
            "from relay.phish.example.net by mx1.phish.example.net",
        ]

    def test_attachment_metadata_without_a_digest_yields_no_hash(self) -> None:
        """Graph computes no digest, and inventing one would be a fabricated indicator."""
        message = from_graph_message(GRAPH_FORWARDED)
        assert message.attachments[0]["name"] == "invoice.html"
        assert message.attachment_hashes == ()

    def test_a_forward_that_dropped_the_headers_leaves_the_sender_empty(self) -> None:
        """Empty, never the reporter: naming the victim as the attacker is worse than saying nothing."""
        stripped = {**GRAPH_FORWARDED, "internetMessageHeaders": []}
        message = from_graph_message(stripped)
        assert message.sender == ""
        assert message.reported_by == VICTIM


class TestTheGmailAdapter:
    def test_headers_come_off_the_name_value_list(self) -> None:
        message = from_gmail_message(GMAIL_REPORT)
        assert message.sender == PHISH_SENDER
        assert set(message.recipients) == {VICTIM, SECOND_VICTIM}
        assert message.internet_message_id == MESSAGE_ID

    def test_the_snippet_is_the_body_when_metadata_format_was_used(self) -> None:
        message = from_gmail_message(GMAIL_REPORT)
        assert message.body_text == GMAIL_REPORT["snippet"]
        # The exact URL, not a prefix. A prefix match on a URL is the
        # `py/incomplete-url-substring-sanitization` shape, and
        # `https://pay.phish.example.net.attacker.example/` satisfies it.
        assert message.urls == ("https://pay.phish.example.net/invoice/98113",)

    def test_a_part_with_a_filename_is_an_attachment_and_one_without_is_not(self) -> None:
        message = from_gmail_message(GMAIL_REPORT)
        assert [a["name"] for a in message.attachments] == ["invoice.html"]


class TestTheEmailInboxAdapter:
    def test_the_connectors_own_six_keys_are_what_is_parsed(self) -> None:
        message = from_email_inbox_event(EMAIL_INBOX_EVENT, reported_by=VICTIM)
        assert message.intake_source == "email_inbox"
        assert message.sender == PHISH_SENDER
        assert set(message.recipients) == {VICTIM, SECOND_VICTIM}
        assert message.reported_by == VICTIM
        assert message.received_at is not None


class TestTheCanonicalRecord:
    def test_an_unknown_source_is_refused_rather_than_parsed_leniently(self) -> None:
        """A lenient fallback is how the ingest normaliser stamped 'Splunk' on 26 connectors."""
        with pytest.raises(ValueError, match="unknown intake source"):
            normalise("sublime_security", GRAPH_FORWARDED)

    def test_the_source_vocabulary_is_closed(self) -> None:
        with pytest.raises(ValueError, match="unknown intake source"):
            ReportedMessage(intake_source="whatever")
        assert "manual" in INTAKE_SOURCES

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [("abc@example.net", "<abc@example.net>"), ("<abc@example.net>", "<abc@example.net>"), ("", ""), ("  ", "")],
    )
    def test_the_message_id_is_canonically_bracketed(self, raw: str, expected: str) -> None:
        """Graph stores it bracketed; Gmail's operator wants it bare. Pick one, convert at the edges."""
        assert normalise_message_id(raw) == expected

    def test_all_three_adapters_agree_on_the_same_message(self) -> None:
        """The whole point of a canonical record: the same phish, three doors, one identity."""
        graph = from_graph_message(GRAPH_FORWARDED)
        gmail = from_gmail_message(GMAIL_REPORT)
        inbox = from_email_inbox_event(EMAIL_INBOX_EVENT)
        assert graph.internet_message_id == gmail.internet_message_id == inbox.internet_message_id
        assert graph.sender == gmail.sender == inbox.sender
        assert set(graph.recipients) == set(gmail.recipients) == set(inbox.recipients)


class TestGroupingIsStrongestFirst:
    def test_the_message_id_wins_when_present(self) -> None:
        decision = grouping_decision(from_graph_message(GRAPH_FORWARDED))
        assert decision is not None
        assert decision.basis == "internet_message_id"
        assert decision.is_factual

    def test_the_ladder_descends_as_attributes_are_removed(self) -> None:
        base = from_graph_message(GRAPH_FORWARDED)
        no_id = ReportedMessage(
            intake_source="m365_graph", sender=base.sender, subject=base.subject, urls=base.urls, attachment_hashes=("a" * 64,)
        )
        assert grouping_decision(no_id).basis == "attachment_hash"  # type: ignore[union-attr]
        no_hash = ReportedMessage(intake_source="m365_graph", sender=base.sender, subject=base.subject, urls=base.urls)
        assert grouping_decision(no_hash).basis == "url"  # type: ignore[union-attr]
        no_url = ReportedMessage(intake_source="m365_graph", sender=base.sender, subject=base.subject)
        assert grouping_decision(no_url).basis == "sender"  # type: ignore[union-attr]
        subject_only = ReportedMessage(intake_source="m365_graph", subject=base.subject)
        assert grouping_decision(subject_only).basis == "subject"  # type: ignore[union-attr]

    def test_a_message_with_nothing_to_group_on_is_refused(self) -> None:
        """Inventing a group would put an unrelated message in somebody's purge list."""
        assert grouping_decision(ReportedMessage(intake_source="manual")) is None

    def test_subject_is_the_only_basis_that_is_a_judgement(self) -> None:
        assert set(GROUPING_ORDER) - FACTUAL_BASES == {"subject"}

    @pytest.mark.parametrize(
        ("a", "b"),
        [
            ("Invoice 10452 overdue", "RE: Invoice 98113 overdue"),
            ("Action required", "FW: Action  required"),
            ("Payment 7d4f91ab2c", "Payment 0a1b2c3d4e"),
        ],
    )
    def test_subject_normalisation_joins_one_campaigns_variants(self, a: str, b: str) -> None:
        assert normalise_subject(a) == normalise_subject(b)

    def test_subject_normalisation_does_not_join_unrelated_messages(self) -> None:
        """The negative control. A normaliser that collapses everything groups everything."""
        assert normalise_subject("Invoice 10452 overdue") != normalise_subject("Your package has shipped")

    def test_two_bases_with_the_same_string_do_not_collide(self) -> None:
        """A sender address and a URL are not interchangeable even when equal."""
        same = "https://pay.phish.example.net/x"
        by_url = grouping_decision(ReportedMessage(intake_source="manual", urls=(same,)))
        by_sender = grouping_decision(ReportedMessage(intake_source="manual", sender=same))
        assert by_url is not None and by_sender is not None
        assert by_url.key != by_sender.key

    def test_two_reports_of_one_message_produce_one_key(self) -> None:
        graph = grouping_decision(from_graph_message(GRAPH_FORWARDED))
        gmail = grouping_decision(from_gmail_message(GMAIL_REPORT))
        assert graph is not None and gmail is not None
        assert graph.key == gmail.key
