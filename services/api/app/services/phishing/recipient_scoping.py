"""Who interacted with a campaign, per recipient, source named.

A campaign's blast radius is not its recipient list — it is who CLICKED,
who submitted credentials, who replied. The intake pipeline stopped at the
recipient list, so a 200-recipient campaign proposed 200 mailbox purges
and nothing else, with no way to say "these three clicked; start there".

Scoping discipline (the program's three-outcome rule, per CHECK):
every verdict is ``yes`` / ``no`` / ``could_not_check``, and each carries
the SOURCE that answered it — because "no" from a tenant with no web
proxy connected is not a no, it is nobody-looked, and the two must never
render the same. A check answers ``no`` only when its telemetry source is
actually connected and returned nothing for this recipient.

Checks and their sources:

* **clicked** — SWG/DNS events in the lake (zscaler, netskope,
  cisco_umbrella, cloudflare_zt) where the recipient's traffic touched a
  campaign URL's domain inside the window.
* **replied_or_forwarded** — mailbox audit events in the lake
  (m365_audit, google_workspace) where the recipient performed a send
  action whose subject references the campaign subject.
* **credential_submitted** — IdP sign-ins (okta, azure_ad, duo) for the
  recipient from a *new* source address shortly after a click. Strong
  evidence, honestly labelled: ``yes`` here means "a sign-in followed the
  click from an address this account had not used in the window before
  it", not a captured password.

Response proposals scale with the verdicts: purge for every recipient,
session revocation and credential reset ONLY where interaction reached
``credential_submitted`` — proposals, on the governed path, never
auto-dispatched.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from app.db.clickhouse import execute_lake_query

logger = logging.getLogger("aisoc.phishing.recipient_scoping")

SWG_SOURCES = ("zscaler", "netskope", "cisco_umbrella", "cloudflare_zt")
MAIL_AUDIT_SOURCES = ("m365_audit", "google_workspace")
IDP_SOURCES = ("okta", "azure_ad", "duo")

#: How long after the campaign window interactions still count.
WINDOW_HOURS = 72


@dataclass
class CheckResult:
    verdict: str  # yes | no | could_not_check
    source: str
    detail: str = ""

    def as_dict(self) -> dict[str, str]:
        return {"verdict": self.verdict, "source": self.source, "detail": self.detail}


@dataclass
class RecipientScope:
    recipient: str
    clicked: CheckResult
    replied_or_forwarded: CheckResult
    credential_submitted: CheckResult

    def as_dict(self) -> dict[str, Any]:
        return {
            "recipient": self.recipient,
            "clicked": self.clicked.as_dict(),
            "replied_or_forwarded": self.replied_or_forwarded.as_dict(),
            "credential_submitted": self.credential_submitted.as_dict(),
        }


@dataclass
class ScopingReport:
    campaign_id: str
    recipients: list[RecipientScope] = field(default_factory=list)
    #: The response proposals the verdicts justify — drafts for the governed
    #: path, never dispatched from here.
    proposals: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "recipients": [r.as_dict() for r in self.recipients],
            "proposals": self.proposals,
        }


def _domains(urls: list[str]) -> list[str]:
    out: list[str] = []
    for url in urls:
        try:
            host = urlparse(url).hostname or ""
        except ValueError:
            host = ""
        if host:
            out.append(host.lower())
    return sorted(set(out))


async def _connected_sources(tenant_id: str, sources: tuple[str, ...], since: datetime) -> list[str]:
    """Which of these telemetry sources have ANY rows for this tenant in the
    window — the difference between 'no' and 'nobody looked'."""
    result = await execute_lake_query(
        """
        SELECT DISTINCT connector_type FROM aisoc.raw_events
        WHERE tenant_id = toUUID(%(tenant_id)s)
          AND connector_type IN %(sources)s
          AND event_time >= %(since)s
        """,
        params={"tenant_id": tenant_id, "sources": list(sources), "since": since},
    )
    return [str(r[0]) for r in result.rows]


async def _clicked(tenant_id: str, recipient: str, domains: list[str], since: datetime, connected: list[str]) -> CheckResult:
    if not domains:
        return CheckResult("could_not_check", "campaign", "the campaign carries no URLs to match")
    if not connected:
        return CheckResult(
            "could_not_check",
            "none",
            f"no web-proxy/DNS telemetry connected ({', '.join(SWG_SOURCES)})",
        )
    result = await execute_lake_query(
        """
        SELECT count() FROM aisoc.raw_events
        WHERE tenant_id = toUUID(%(tenant_id)s)
          AND connector_type IN %(sources)s
          AND event_time >= %(since)s
          AND user_name = %(recipient)s
          AND multiSearchAny(lower(raw_payload), %(domains)s)
        """,
        params={
            "tenant_id": tenant_id,
            "sources": connected,
            "since": since,
            "recipient": recipient,
            "domains": domains,
        },
    )
    rows = result.rows
    count = int(rows[0][0]) if rows else 0
    source = f"lake events from {', '.join(connected)}"
    if count:
        return CheckResult("yes", source, f"{count} event(s) touching campaign domain(s)")
    return CheckResult("no", source, "telemetry connected; no matching traffic for this recipient")


async def _replied(tenant_id: str, recipient: str, subject: str, since: datetime, connected: list[str]) -> CheckResult:
    if not connected:
        return CheckResult(
            "could_not_check",
            "none",
            f"no mailbox-audit telemetry connected ({', '.join(MAIL_AUDIT_SOURCES)})",
        )
    if not subject.strip():
        return CheckResult("could_not_check", "campaign", "the campaign carries no subject to match")
    result = await execute_lake_query(
        """
        SELECT count() FROM aisoc.raw_events
        WHERE tenant_id = toUUID(%(tenant_id)s)
          AND connector_type IN %(sources)s
          AND event_time >= %(since)s
          AND user_name = %(recipient)s
          AND (positionCaseInsensitive(action, 'send') > 0 OR positionCaseInsensitive(action, 'forward') > 0)
          AND positionCaseInsensitive(raw_payload, %(subject)s) > 0
        """,
        params={
            "tenant_id": tenant_id,
            "sources": connected,
            "since": since,
            "recipient": recipient,
            "subject": subject[:120],
        },
    )
    rows = result.rows
    count = int(rows[0][0]) if rows else 0
    source = f"mailbox audit from {', '.join(connected)}"
    if count:
        return CheckResult("yes", source, f"{count} send/forward event(s) referencing the subject")
    return CheckResult("no", source, "audit connected; no reply/forward referencing the subject")


async def _credential_submitted(tenant_id: str, recipient: str, since: datetime, connected: list[str], clicked: CheckResult) -> CheckResult:
    if clicked.verdict != "yes":
        return CheckResult(
            "could_not_check",
            "derived",
            "credential submission is judged relative to a click, and no click was established",
        )
    if not connected:
        return CheckResult("could_not_check", "none", f"no IdP telemetry connected ({', '.join(IDP_SOURCES)})")
    result = await execute_lake_query(
        """
        WITH prior AS (
          SELECT DISTINCT toString(source_ip) AS src_ip FROM aisoc.raw_events
          WHERE tenant_id = toUUID(%(tenant_id)s)
            AND connector_type IN %(sources)s
            AND user_name = %(recipient)s
            AND event_time < %(since)s
            AND event_time >= %(since)s - INTERVAL 14 DAY
        )
        SELECT count() FROM aisoc.raw_events
        WHERE tenant_id = toUUID(%(tenant_id)s)
          AND connector_type IN %(sources)s
          AND user_name = %(recipient)s
          AND event_time >= %(since)s
          AND toString(source_ip) NOT IN ('', '::')
          AND toString(source_ip) NOT IN (SELECT src_ip FROM prior)
        """,
        params={"tenant_id": tenant_id, "sources": connected, "since": since, "recipient": recipient},
    )
    rows = result.rows
    count = int(rows[0][0]) if rows else 0
    source = f"IdP sign-ins from {', '.join(connected)} relative to the click"
    if count:
        return CheckResult(
            "yes",
            source,
            f"{count} sign-in(s) from address(es) this account had not used in the prior 14 days",
        )
    return CheckResult("no", source, "IdP connected; no new-address sign-in after the click")


async def scope_campaign(
    *,
    tenant_id: str,
    campaign_id: str,
    recipients: list[str],
    urls: list[str],
    subject: str,
    first_seen: datetime,
) -> ScopingReport:
    """Per-recipient interaction verdicts plus the proposals they justify."""
    report = ScopingReport(campaign_id=campaign_id)
    try:
        swg = await _connected_sources(tenant_id, SWG_SOURCES, first_seen)
        lake_reachable = True
    except Exception as exc:  # noqa: BLE001 — unreachable is a scoping outcome, not a crash
        logger.warning("recipient_scoping.lake_unreachable err=%s", type(exc).__name__)
        lake_reachable = False
    if not lake_reachable:
        for recipient in recipients:
            unavailable = CheckResult("could_not_check", "none", "the event lake is unreachable")
            report.recipients.append(
                RecipientScope(
                    recipient=recipient,
                    clicked=unavailable,
                    replied_or_forwarded=unavailable,
                    credential_submitted=unavailable,
                )
            )
        report.proposals = {
            "purge_mailboxes": recipients,
            "revoke_sessions": [],
            "reset_credentials": [],
            "note": (
                "interaction could not be checked; revocation/reset lists are "
                "empty because nothing justified them, not because nobody interacted"
            ),
        }
        return report

    domains = _domains(urls)
    mail = await _connected_sources(tenant_id, MAIL_AUDIT_SOURCES, first_seen)
    idp = await _connected_sources(tenant_id, IDP_SOURCES, first_seen)

    credentialed: list[str] = []
    for recipient in recipients:
        clicked = await _clicked(tenant_id, recipient, domains, first_seen, swg)
        replied = await _replied(tenant_id, recipient, subject, first_seen, mail)
        cred = await _credential_submitted(tenant_id, recipient, first_seen, idp, clicked)
        if cred.verdict == "yes":
            credentialed.append(recipient)
        report.recipients.append(
            RecipientScope(
                recipient=recipient,
                clicked=clicked,
                replied_or_forwarded=replied,
                credential_submitted=cred,
            )
        )

    report.proposals = {
        # Purge scales with the whole list: the message is unwanted in every
        # mailbox regardless of interaction.
        "purge_mailboxes": recipients,
        # Revocation and reset scale ONLY with established credential risk —
        # resetting 200 passwords because 200 people received an email is how
        # response automation loses the room.
        "revoke_sessions": credentialed,
        "reset_credentials": credentialed,
    }
    return report
