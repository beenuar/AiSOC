"""BEC pre-compromise signals: evidence, never a verdict.

BEC's tell is not a payload — it is a RELATIONSHIP anomaly: a lookalike of
your own domain, a display name borrowed from your CFO on a foreign
address, a sender this organisation has never heard from, a Reply-To
pointing somewhere the From does not. Each signal here is computed from
something the platform actually has, carries its source, and is attached
to the campaign as EVIDENCE for triage — a signal never closes or
escalates anything alone.

What each signal is computed FROM:

* **lookalike_domain** — pure string analysis of the sender domain against
  the tenant's own domains: one-character edits, common homoglyph swaps,
  and punycode. No network lookups.
* **vip_display_name** — the tenant's VIP list (migration 177,
  ``tenant_vips``): a sender whose display half matches a VIP's name while
  the address is not the VIP's recorded address.
* **first_seen_sender** — the phishing intake's OWN history: this sender
  appears in no prior campaign or report for this tenant. Scoped honestly:
  "first seen by this pipeline", not "first email ever" (the mail graph
  baseline over the full mail flow is a recorded follow-up — the lake does
  not currently carry per-message sender→recipient mail rows to baseline
  from).
* **reply_to_mismatch** — the intake record's own headers, judged by the
  existing header analysis (:mod:`app.services.phishing.headers`).

**Refused with its reason**: domain-age ("domain registered days ago") —
there is no WHOIS/RDAP source configured in the platform, and inventing a
registration date is worse than not stating one. The signal lands when a
tenant configures a source.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("aisoc.phishing.bec")

#: Homoglyph swaps actually used in lookalike registrations. Small and
#: reviewable; the point is rn→m and 0→o, not Unicode completeness.
_HOMOGLYPHS = (
    ("rn", "m"),
    ("vv", "w"),
    ("0", "o"),
    ("1", "l"),
    ("3", "e"),
    ("5", "s"),
    ("cl", "d"),
)


@dataclass(frozen=True)
class BecSignal:
    kind: str
    detail: str
    source: str

    def as_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "detail": self.detail, "source": self.source}


def _edit_distance_one(a: str, b: str) -> bool:
    """Exactly one insertion, deletion or substitution apart."""
    if a == b:
        return False
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        return sum(1 for x, y in zip(a, b, strict=True) if x != y) == 1
    shorter, longer = (a, b) if len(a) < len(b) else (b, a)
    for i in range(len(longer)):
        if shorter == longer[:i] + longer[i + 1 :]:
            return True
    return False


def _canonical(domain: str) -> str:
    out = domain.lower().strip().rstrip(".")
    for fake, real in _HOMOGLYPHS:
        out = out.replace(fake, real)
    return out


def lookalike_domain(sender_domain: str, tenant_domains: list[str]) -> BecSignal | None:
    d = (sender_domain or "").lower().strip().rstrip(".")
    if not d:
        return None
    for own in tenant_domains:
        own_l = own.lower().strip().rstrip(".")
        if not own_l or d == own_l:
            continue
        if d.startswith("xn--") and _canonical(d) != d:
            return BecSignal(
                "lookalike_domain",
                f"{d!r} is punycode shadowing {own_l!r}",
                "string analysis against the tenant's own domains",
            )
        if _edit_distance_one(d, own_l):
            return BecSignal(
                "lookalike_domain",
                f"{d!r} is one edit from the tenant domain {own_l!r}",
                "string analysis against the tenant's own domains",
            )
        if d != own_l and _canonical(d) == own_l:
            return BecSignal(
                "lookalike_domain",
                f"{d!r} homoglyph-normalises to the tenant domain {own_l!r}",
                "string analysis against the tenant's own domains",
            )
    return None


_VIPS_SQL = text("SELECT display_name, email FROM tenant_vips WHERE tenant_id = :tenant_id")

_PRIOR_SENDER_SQL = text(
    """
    SELECT count(*) FROM aisoc_phishing_campaigns
    WHERE tenant_id = :tenant_id AND lower(sender) = lower(:sender)
      AND created_at < NOW() - INTERVAL '1 hour'
    """
)


def _display_half(sender: str) -> str:
    """`"Jane Smith" <j@x.io>` -> `jane smith`; a bare address -> its local part."""
    s = sender.strip()
    if "<" in s:
        return s.split("<", 1)[0].strip().strip('"').lower()
    return s.split("@", 1)[0].replace(".", " ").lower()


async def vip_display_name(db: AsyncSession, *, tenant_id: uuid.UUID, sender: str) -> BecSignal | None:
    try:
        rows = (await db.execute(_VIPS_SQL, {"tenant_id": str(tenant_id)})).fetchall()
    except Exception as exc:  # noqa: BLE001 — no VIP table/rows means no signal, not an error
        logger.debug("bec.vips_unreadable err=%s", type(exc).__name__)
        return None
    display = _display_half(sender)
    if not display:
        return None
    address = sender.split("<")[-1].rstrip(">").strip().lower()
    for vip_name, vip_email in rows:
        name = str(vip_name or "").lower()
        if name and name == display and address != str(vip_email or "").lower():
            return BecSignal(
                "vip_display_name",
                f"display name matches VIP {vip_name!r} while the address is {address!r}, not the recorded {vip_email!r}",
                "the tenant's VIP list (Settings → Phishing)",
            )
    return None


async def first_seen_sender(db: AsyncSession, *, tenant_id: uuid.UUID, sender: str) -> BecSignal | None:
    address = sender.split("<")[-1].rstrip(">").strip().lower()
    if not address or "@" not in address:
        return None
    try:
        prior = (await db.execute(_PRIOR_SENDER_SQL, {"tenant_id": str(tenant_id), "sender": address})).scalar_one()
    except Exception as exc:  # noqa: BLE001
        logger.debug("bec.history_unreadable err=%s", type(exc).__name__)
        return None
    if int(prior) == 0:
        return BecSignal(
            "first_seen_sender",
            f"{address!r} appears in no prior report or campaign for this tenant",
            "the phishing pipeline's own intake history (scoped: first seen BY THIS "
            "PIPELINE, not first email ever — the full mail-flow baseline is a recorded follow-up)",
        )
    return None


def reply_to_mismatch(headers: dict[str, str]) -> BecSignal | None:
    reply_to = (headers.get("reply-to") or "").strip().lower()
    from_header = (headers.get("from") or "").strip().lower()
    if not reply_to or not from_header:
        return None
    reply_domain = reply_to.split("@")[-1].rstrip(">").strip()
    from_domain = from_header.split("@")[-1].rstrip(">").strip()
    if reply_domain and from_domain and reply_domain != from_domain:
        return BecSignal(
            "reply_to_mismatch",
            f"Reply-To domain {reply_domain!r} differs from From domain {from_domain!r}",
            "the reported message's own headers",
        )
    return None


async def compute_signals(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    sender: str,
    headers: dict[str, str],
    tenant_domains: list[str],
) -> list[dict[str, str]]:
    """All computable signals for one message. Evidence for triage; a signal
    never closes or escalates anything alone, and an uncomputable signal is
    absent rather than guessed."""
    signals: list[BecSignal] = []
    domain = sender.split("@")[-1].rstrip(">").strip() if "@" in sender else ""
    lookalike = lookalike_domain(domain, tenant_domains)
    if lookalike:
        signals.append(lookalike)
    vip = await vip_display_name(db, tenant_id=tenant_id, sender=sender)
    if vip:
        signals.append(vip)
    first = await first_seen_sender(db, tenant_id=tenant_id, sender=sender)
    if first:
        signals.append(first)
    mismatch = reply_to_mismatch(headers)
    if mismatch:
        signals.append(mismatch)
    return [s.as_dict() for s in signals]
