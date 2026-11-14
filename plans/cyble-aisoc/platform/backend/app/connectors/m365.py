"""Microsoft 365 (Email) connector — Microsoft Graph backend.

Implements ``BaseEmailConnector`` against the Microsoft Graph v1.0 API
for Exchange Online mailboxes. Three operations:

  * ``analyze_message`` — fetch a message from a mailbox, extract
    authentication results (SPF/DKIM/DMARC) from the
    ``internetMessageHeaders`` collection, list URLs found in the body,
    and enumerate attachments with SHA-256 of bytes and macro
    heuristics.
  * ``clawback_message`` — soft-clawback via
    ``POST /v1.0/users/{mailbox}/messages/{id}/move`` to
    ``deleteditems``. True ZAP (Zero-hour Auto-Purge) across all
    recipients requires Defender for Office 365 + the Submissions API,
    which is on the roadmap. The single-mailbox move is what most
    tenants want for analyst-initiated clawback today; the response
    structure stays compatible with the eventual ZAP rollout.
  * ``block_sender`` — append the sender SMTP to the tenant
    Defender Tenant Allow/Block List (TABL) via
    ``POST /v1.0/security/tenantAllowBlockListEntries``. Requires the
    ``ThreatHunting.Read.All`` + ``ThreatIndicators.ReadWrite.OwnedBy``
    Graph application permissions, plus a Defender for Office 365 P2 /
    Microsoft 365 E5 license on the tenant. When the API surface is
    not enabled, the call falls back to creating an inbox-rule that
    moves mail from the sender to ``deleteditems`` for the configured
    default mailbox — degraded but auditable.

Config (``params``)
-------------------
* ``azure_tenant_id``      — Azure AD directory tenant ID (GUID).
                             Required. The OAuth token endpoint is
                             keyed on this. Distinct from our own
                             per-customer ``tenant_id``.
* ``default_mailbox``      — User principal name (e.g. ``soc@corp.com``)
                             whose mailbox is targeted when
                             ``message_id`` is not prefixed with a
                             mailbox. Required.
* ``message_id_separator`` — Delimiter that lets callers override the
                             default mailbox by passing
                             ``"user@domain::AAMk…"`` as the
                             ``message_id``. Default ``"::"``.
* ``api_base_url``         — Override for sovereign clouds. Default
                             ``"https://graph.microsoft.com/v1.0"``.
                             Azure Gov: ``"https://graph.microsoft.us/v1.0"``.
                             Azure China: ``"https://microsoftgraph.chinacloudapi.cn/v1.0"``.
* ``token_url``            — Override for sovereign / national OAuth
                             endpoints. Default builds
                             ``https://login.microsoftonline.com/{azure_tenant_id}/oauth2/v2.0/token``.
* ``oauth_scope``          — Override OAuth scope. Default
                             ``"https://graph.microsoft.com/.default"``.
* ``read_timeout_s``       — Per-call read timeout. Default ``30``.
* ``verify_tls``           — Verify TLS certs. Default ``True``.
* ``max_attachments``      — Cap attachments hashed per message.
                             Default ``20``. Each attachment requires
                             a follow-up Graph call.
* ``max_url_chars``        — Cap on body length scanned for URLs.
                             Default ``200_000``. Larger bodies are
                             truncated to keep latency bounded.
* ``block_method``         — ``"tabl"`` (default) or ``"inbox_rule"``.
                             Forces the fallback path even when TABL
                             could be tried.

Config (``secrets``)
--------------------
* ``client_id``     — Azure app registration's Application (client) ID.
* ``client_secret`` — Azure app registration client secret.

The service principal must hold (at minimum):

  * ``Mail.ReadWrite`` (Application) — read/move messages across
    mailboxes for analyze + clawback.
  * ``MailboxSettings.ReadWrite`` (Application) — create inbox-rule
    fallback for ``block_sender``.
  * ``ThreatIndicators.ReadWrite.OwnedBy`` (Application) — Defender
    Tenant Allow/Block List management. Optional but recommended.

Defender / TABL note
--------------------
The ``tenantAllowBlockListEntries`` resource is part of the Defender
threat-management surface. Where Graph routes the call depends on
licensing and the active Defender plan. We POST to the v1.0 path and
let Graph translate; on tenants where the resource is not enabled,
Graph returns 400/403 and we drop to the inbox-rule fallback. The
exact response shape is intentionally documented in the integration
tests; vendors evolve this endpoint and the connector tolerates both
the documented schema and the small variations seen in the wild.

URL extraction
--------------
Graph returns message body either as plaintext (``contentType=text``)
or HTML (``contentType=html``). We extract ``http(s)://...`` URLs with
a conservative regex that stops at whitespace, quotes, angle brackets,
and the standard URL-ending punctuation. We do *not* parse HTML — the
LLM cares about the literal links present, not the link text. URL risk
classification is best-effort: it flags shorteners and look-alike
brands but does NOT make an authoritative call. The Phishing Triage
agent (t2f) layers on top of this.

Attachment hashing
------------------
Attachments come back from ``/messages/{id}/attachments`` with the
file bytes base64-encoded in the ``contentBytes`` field for
``#microsoft.graph.fileAttachment``. We SHA-256 the *decoded* bytes
so the hash matches what a downstream sandbox/VT lookup would see.
For ``#microsoft.graph.itemAttachment`` (a nested message) we return
the item's subject without a hash — there are no canonical bytes.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import re
from typing import Any, Iterable

import httpx

from app.connectors.sdk.base import (
    ConnectorAuthError,
    ConnectorConfig,
    ConnectorError,
)
from app.connectors.sdk.http import AsyncHttpClient, OAuthClientCredentials
from app.connectors.sdk.protocols import BaseEmailConnector

log = logging.getLogger(__name__)


# ─── defaults ────────────────────────────────────────────────────────────

_DEFAULT_API_BASE_URL = "https://graph.microsoft.com/v1.0"
_DEFAULT_OAUTH_SCOPE = "https://graph.microsoft.com/.default"
_DEFAULT_AAD_AUTHORITY = "https://login.microsoftonline.com"

# Same canonical 8-4-4-4-12 hex format as Sentinel.
_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

# RFC 5322-ish SMTP address shape. Permissive on local-part because
# real-world senders include dots, plus tags, hyphens, etc.; strict on
# the domain so we never let a CR/LF or quote slip into a Graph URL
# path segment.
_SMTP_RE = re.compile(
    r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+$"
)

# URL extractor. Matches http/https URLs greedily, stopping at any
# whitespace, quote, angle bracket, or terminating ASCII punctuation
# that almost always sits *outside* the URL. We intentionally accept
# trailing slashes and query strings.
_URL_RE = re.compile(
    r"https?://[^\s<>\"'`{}|\\^]+",
    re.IGNORECASE,
)

# URL shorteners and well-known abused redirector domains. Flagged as
# medium risk: the actual destination is opaque without expansion.
_SHORTENER_DOMAINS = frozenset({
    "bit.ly",
    "t.co",
    "tinyurl.com",
    "ow.ly",
    "buff.ly",
    "is.gd",
    "goo.gl",
    "rebrand.ly",
    "cutt.ly",
    "s.id",
    "rb.gy",
    "shorturl.at",
    "lnkd.in",
})

# Dynamic DNS / free-hosting providers commonly used by phishing
# infrastructure. High risk: legitimate corporate mail almost never
# routes through these.
_DYNDNS_DOMAINS = frozenset({
    "duckdns.org",
    "no-ip.org",
    "no-ip.biz",
    "no-ip.info",
    "freedns.afraid.org",
    "hopto.org",
    "zapto.org",
    "ddns.net",
    "myftp.org",
    "myftp.biz",
})

# Brand strings whose appearance in URL hostnames frequently indicates
# impersonation. Matched case-insensitively as substrings of the
# hostname; if the URL hostname is *equal* to the canonical brand
# domain we don't flag it.
_IMPERSONATED_BRANDS = (
    ("microsoft", "microsoft.com"),
    ("office", "office.com"),
    ("outlook", "outlook.com"),
    ("apple", "apple.com"),
    ("google", "google.com"),
    ("amazon", "amazon.com"),
    ("paypal", "paypal.com"),
    ("dropbox", "dropbox.com"),
    ("docusign", "docusign.com"),
)

# Office macro-bearing extensions. We don't open the file — we trust
# the extension and the Graph ``isInline=false`` flag. A real macro
# scanner (oletools/olevba) is the sandbox layer's job; this is a
# coarse triage signal for the LLM.
_MACRO_EXTENSIONS = frozenset({
    ".docm",
    ".dotm",
    ".xlsm",
    ".xltm",
    ".xlam",
    ".pptm",
    ".potm",
    ".ppam",
    ".sldm",
})


# ─── helpers ─────────────────────────────────────────────────────────────


def _validate_guid(value: Any, *, name: str) -> str:
    """Require `value` to look like an Azure GUID (8-4-4-4-12 hex)."""
    if not isinstance(value, str) or not value:
        raise ConnectorError(
            f"m365: {name} must be a non-empty string",
            vendor="m365",
        )
    if not _GUID_RE.match(value):
        raise ConnectorError(
            f"m365: {name}={value!r} is not a valid Azure GUID",
            vendor="m365",
        )
    return value


def _validate_mailbox(value: Any, *, name: str) -> str:
    """Validate a mailbox UPN — rides into the Graph URL path."""
    if not isinstance(value, str) or not value:
        raise ConnectorError(
            f"m365: {name} must be a non-empty string",
            vendor="m365",
        )
    if not _SMTP_RE.match(value):
        raise ConnectorError(
            f"m365: {name}={value!r} is not a valid SMTP / UPN address",
            vendor="m365",
        )
    return value


def _validate_message_id(value: Any) -> str:
    """Reject control chars or empty Graph message identifiers.

    Graph IDs are long opaque base64-ish strings with ``-`` and ``_``;
    we don't try to validate the alphabet (Graph evolves), but we do
    refuse anything that would let an attacker break out of the URL
    path segment.
    """
    if not isinstance(value, str) or not value:
        raise ConnectorError(
            "m365: message_id must be a non-empty string",
            vendor="m365",
        )
    if any(c < "\x20" or c == "\x7f" for c in value):
        raise ConnectorError(
            "m365: message_id contains control characters",
            vendor="m365",
        )
    if "/" in value or " " in value:
        raise ConnectorError(
            f"m365: message_id={value!r} contains forbidden characters",
            vendor="m365",
        )
    return value


def _parse_auth_results(headers: Iterable[dict[str, Any]]) -> dict[str, str]:
    """Distill SPF/DKIM/DMARC verdicts from ``internetMessageHeaders``.

    Graph returns headers as a list of ``{"name": ..., "value": ...}``
    dicts. The relevant headers are ``Authentication-Results`` (RFC
    8601) and ``Received-SPF``. We extract the first ``spf=``, ``dkim=``,
    and ``dmarc=`` tokens we see; missing headers map to ``"none"`` so
    the LLM gets a stable shape.
    """
    auth = {"spf": "none", "dkim": "none", "dmarc": "none"}
    if not headers:
        return auth
    spf_re = re.compile(r"\bspf=(\w+)", re.IGNORECASE)
    dkim_re = re.compile(r"\bdkim=(\w+)", re.IGNORECASE)
    dmarc_re = re.compile(r"\bdmarc=(\w+)", re.IGNORECASE)
    for h in headers:
        if not isinstance(h, dict):
            continue
        name = str(h.get("name") or "").lower()
        value = str(h.get("value") or "")
        if not value:
            continue
        if name == "authentication-results":
            if m := spf_re.search(value):
                auth["spf"] = m.group(1).lower()
            if m := dkim_re.search(value):
                auth["dkim"] = m.group(1).lower()
            if m := dmarc_re.search(value):
                auth["dmarc"] = m.group(1).lower()
        elif name == "received-spf" and auth["spf"] == "none":
            # Format: ``Pass (...)`` / ``Fail (...)`` / ``Neutral`` / etc.
            first_word = value.strip().split()[0:1]
            if first_word:
                auth["spf"] = first_word[0].lower()
    return auth


def _extract_body_text(body: Any) -> str:
    """Pull a string out of Graph's ``message.body``.

    Body comes back as ``{"contentType": "html|text", "content": "..."}``.
    We return the raw content as-is. The URL regex already excludes
    HTML metacharacters (``<>"'``), so URLs inside ``<a href="...">``
    attributes get extracted correctly — which is critical because
    phishing emails routinely put the real URL only in the href and
    show innocuous "click here" text.
    """
    if not isinstance(body, dict):
        return ""
    raw = body.get("content")
    if not isinstance(raw, str):
        return ""
    return raw


def _hostname_of(url: str) -> str:
    """Return the lowercased hostname from a URL, or ``""``."""
    # Minimal parser to avoid an `urlparse` dependency surprise on
    # exotic characters. We strip scheme, then split on the first
    # ``/``, ``?``, ``#``, or ``:`` (port).
    if "://" not in url:
        return ""
    host = url.split("://", 1)[1]
    for sep in ("/", "?", "#"):
        if sep in host:
            host = host.split(sep, 1)[0]
            break
    if "@" in host:  # userinfo
        host = host.split("@", 1)[1]
    if ":" in host:  # port
        host = host.split(":", 1)[0]
    return host.lower()


def _classify_url(url: str) -> str:
    """Coarse high/medium/low risk classifier.

    Best-effort, never authoritative. The Phishing Triage agent (t2f)
    will layer detonation + brand-reputation on top.
    """
    host = _hostname_of(url)
    if not host:
        return "low"
    # Dynamic DNS / free hosting → high.
    for dyn in _DYNDNS_DOMAINS:
        if host == dyn or host.endswith("." + dyn):
            return "high"
    # Brand impersonation in hostname → high.
    for brand_token, canonical in _IMPERSONATED_BRANDS:
        if brand_token in host and not (
            host == canonical or host.endswith("." + canonical)
        ):
            return "high"
    # IP-literal URLs → high.
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host):
        return "high"
    # Shorteners → medium (destination opaque).
    if host in _SHORTENER_DOMAINS:
        return "medium"
    return "low"


def _extract_urls(body_text: str, *, limit_chars: int) -> list[dict[str, str]]:
    """Pull URLs out of body text, deduplicated and classified.

    Truncates the input to ``limit_chars`` so a 50MB pasted log
    doesn't blow regex evaluation time. Dedupes by URL string while
    preserving first-seen order.
    """
    if not body_text:
        return []
    sample = body_text[:limit_chars]
    seen: set[str] = set()
    out: list[dict[str, str]] = []
    for match in _URL_RE.finditer(sample):
        url = match.group(0).rstrip(").,;:!?\"'")
        if url in seen:
            continue
        seen.add(url)
        out.append({"url": url, "risk": _classify_url(url)})
    return out


def _suspicion_score(
    *,
    auth: dict[str, str],
    urls: list[dict[str, str]],
    attachments: list[dict[str, Any]],
) -> float:
    """Heuristic suspicion score in ``[0.0, 1.0]``.

    Coarse — the LLM is the real classifier. We bias *up* on auth
    failures and *up* on macros / high-risk URLs because those are the
    signals analysts cite when escalating.
    """
    score = 0.0
    if auth.get("spf") in {"fail", "softfail", "permerror"}:
        score += 0.30
    if auth.get("dkim") == "fail":
        score += 0.20
    if auth.get("dmarc") == "fail":
        score += 0.25
    for u in urls:
        if u.get("risk") == "high":
            score += 0.20
            break
    for u in urls:
        if u.get("risk") == "medium":
            score += 0.05
            break
    if any(a.get("macros") for a in attachments):
        score += 0.20
    return min(round(score, 2), 1.0)


def _process_attachments(
    payloads: Iterable[dict[str, Any]],
    *,
    max_attachments: int,
) -> list[dict[str, Any]]:
    """Convert Graph attachment objects into our envelope shape.

    Honours ``max_attachments`` so a huge attachment list can't blow
    LLM context. Skips inline attachments (``isInline=true``) because
    those are typically signature images, not analyst payload.
    """
    out: list[dict[str, Any]] = []
    for payload in payloads:
        if len(out) >= max_attachments:
            break
        if not isinstance(payload, dict):
            continue
        if payload.get("isInline"):
            continue
        otype = str(payload.get("@odata.type") or "")
        name = str(payload.get("name") or "unknown")
        size = payload.get("size")
        record: dict[str, Any] = {
            "filename": name,
            "size_bytes": int(size) if isinstance(size, (int, float)) else None,
            "content_type": payload.get("contentType"),
        }
        if otype == "#microsoft.graph.fileAttachment":
            blob = payload.get("contentBytes")
            if isinstance(blob, str) and blob:
                try:
                    raw = base64.b64decode(blob, validate=False)
                    record["sha256"] = hashlib.sha256(raw).hexdigest()
                except (ValueError, TypeError):
                    record["sha256"] = None
            else:
                record["sha256"] = None
        else:
            # itemAttachment / referenceAttachment / unknown
            record["sha256"] = None
            record["item_type"] = otype or None
        lowered = name.lower()
        record["macros"] = any(lowered.endswith(ext) for ext in _MACRO_EXTENSIONS)
        out.append(record)
    return out


# ─── connector ───────────────────────────────────────────────────────────


class M365EmailConnector(BaseEmailConnector):
    """Microsoft 365 Email via Microsoft Graph v1.0.

    One ``AsyncHttpClient`` against ``graph.microsoft.com``. The
    OAuth client_credentials token is cached in the auth strategy and
    refreshed lazily before expiry — repeated tool calls reuse one
    HTTP pool and one access token per tenant.
    """

    vendor = "m365"

    def __init__(self, config: ConnectorConfig) -> None:
        super().__init__(config)

        azure_tenant_id = config.param("azure_tenant_id")
        default_mailbox = config.param("default_mailbox")
        if not azure_tenant_id:
            raise ConnectorError(
                "m365: missing required param 'azure_tenant_id' "
                "(Azure AD directory tenant GUID)",
                vendor="m365",
            )
        if not default_mailbox:
            raise ConnectorError(
                "m365: missing required param 'default_mailbox' "
                "(target UPN, e.g. 'soc@corp.com')",
                vendor="m365",
            )
        self._azure_tenant_id = _validate_guid(
            azure_tenant_id, name="azure_tenant_id"
        )
        self._default_mailbox = _validate_mailbox(
            default_mailbox, name="default_mailbox"
        )
        sep = config.param("message_id_separator") or "::"
        if not isinstance(sep, str) or not sep:
            raise ConnectorError(
                f"m365: message_id_separator must be a non-empty string "
                f"(got {sep!r})",
                vendor="m365",
            )
        self._mid_separator = sep

        self._max_attachments = int(config.param("max_attachments") or 20)
        if self._max_attachments < 0:
            raise ConnectorError(
                "m365: max_attachments must be >= 0",
                vendor="m365",
            )
        self._max_url_chars = int(config.param("max_url_chars") or 200_000)
        if self._max_url_chars < 0:
            raise ConnectorError(
                "m365: max_url_chars must be >= 0",
                vendor="m365",
            )

        block_method = str(config.param("block_method") or "tabl").lower()
        if block_method not in {"tabl", "inbox_rule"}:
            raise ConnectorError(
                f"m365: block_method={block_method!r} must be "
                f"'tabl' or 'inbox_rule'",
                vendor="m365",
            )
        self._block_method = block_method

        read_timeout = float(config.param("read_timeout_s") or 30.0)
        verify_tls = bool(config.param("verify_tls", True))

        api_base_url = str(
            config.param("api_base_url") or _DEFAULT_API_BASE_URL
        ).rstrip("/")
        self._api_base_url = api_base_url

        # OAuth client_credentials. Azure AD v2.0 endpoint expects
        # ``scope`` (resource/.default form); the Graph default works
        # across commercial + sovereign clouds when paired with the
        # matching ``api_base_url``.
        client_id = config.secret("client_id")
        client_secret = config.secret("client_secret")
        token_url = config.param("token_url") or (
            f"{_DEFAULT_AAD_AUTHORITY}/{self._azure_tenant_id}/oauth2/v2.0/token"
        )
        oauth_scope = str(config.param("oauth_scope") or _DEFAULT_OAUTH_SCOPE)

        auth = OAuthClientCredentials(
            token_url=str(token_url),
            client_id=client_id,
            client_secret=client_secret,
            scope=oauth_scope,
        )

        self._http = AsyncHttpClient(
            base_url=api_base_url,
            auth=auth,
            timeout=httpx.Timeout(
                connect=10.0, read=read_timeout, write=10.0, pool=5.0
            ),
            vendor="m365",
            verify=verify_tls,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )

    # ------------------------------------------------------------------ #
    # Lifecycle                                                          #
    # ------------------------------------------------------------------ #

    async def aclose(self) -> None:
        await self._http.aclose()

    # ------------------------------------------------------------------ #
    # Public protocol surface                                            #
    # ------------------------------------------------------------------ #

    async def health_check(self) -> dict[str, Any]:
        """Verify OAuth + Graph reachability via the configured mailbox.

        ``GET /v1.0/users/{mailbox}?$select=id,userPrincipalName`` is
        the cheapest call that exercises both the OAuth token and the
        Graph permission set. A 401 indicates a token problem; a 403
        indicates missing app permissions; a 404 indicates the mailbox
        does not exist.
        """
        path = f"/users/{self._default_mailbox}"
        payload = await self._http.get(
            path,
            params={"$select": "id,userPrincipalName"},
        )
        return {
            "ok": True,
            "vendor": self.vendor,
            "kind": self.kind.value,
            "mailbox": self._default_mailbox,
            "mailbox_id": (payload or {}).get("id"),
        }

    async def analyze_message(self, *, message_id: str) -> dict[str, Any]:
        """Fetch a message + headers + attachments and produce a verdict.

        Two Graph calls:
          1. ``GET /users/{mailbox}/messages/{id}?$select=...`` for the
             message body, sender, and ``internetMessageHeaders``.
          2. ``GET /users/{mailbox}/messages/{id}/attachments`` for
             attachment metadata + bytes.
        """
        mailbox, mid = self._resolve_target(message_id)

        msg = await self._http.get(
            f"/users/{mailbox}/messages/{mid}",
            params={
                "$select": (
                    "id,subject,from,sender,toRecipients,ccRecipients,"
                    "internetMessageId,internetMessageHeaders,body,"
                    "hasAttachments,receivedDateTime"
                )
            },
        )
        if not isinstance(msg, dict):
            raise ConnectorError(
                f"m365: unexpected Graph response for message {mid!r}",
                vendor="m365",
            )

        from_field = msg.get("from") or msg.get("sender") or {}
        if isinstance(from_field, dict):
            email_address = from_field.get("emailAddress") or {}
            sender_addr = email_address.get("address") if isinstance(email_address, dict) else None
        else:
            sender_addr = None

        headers = msg.get("internetMessageHeaders") or []
        if not isinstance(headers, list):
            headers = []
        auth = _parse_auth_results(headers)

        body_text = _extract_body_text(msg.get("body"))
        urls = _extract_urls(body_text, limit_chars=self._max_url_chars)

        attachments: list[dict[str, Any]] = []
        if msg.get("hasAttachments") and self._max_attachments > 0:
            attach_payload = await self._http.get(
                f"/users/{mailbox}/messages/{mid}/attachments",
                params={"$top": self._max_attachments},
            )
            raw_atts = (
                attach_payload.get("value")
                if isinstance(attach_payload, dict)
                else None
            )
            if isinstance(raw_atts, list):
                attachments = _process_attachments(
                    raw_atts, max_attachments=self._max_attachments
                )

        return {
            "message_id": mid,
            "mailbox": mailbox,
            "internet_message_id": msg.get("internetMessageId"),
            "subject": msg.get("subject"),
            "from": sender_addr or "",
            "received_at": msg.get("receivedDateTime"),
            "auth": auth,
            "links": urls,
            "attachments": attachments,
            "suspicion_score": _suspicion_score(
                auth=auth, urls=urls, attachments=attachments
            ),
        }

    async def clawback_message(self, *, message_id: str) -> dict[str, Any]:
        """Soft-clawback: move the message to Deleted Items.

        Single-mailbox move via Graph's ``/messages/{id}/move``. The
        response shape mirrors the mock so the LLM tool contract stays
        stable, with ``recipients_affected=1`` for the v1 path. A
        future ZAP-based implementation can return a higher count.
        """
        mailbox, mid = self._resolve_target(message_id)

        result = await self._http.post(
            f"/users/{mailbox}/messages/{mid}/move",
            json={"destinationId": "deleteditems"},
        )
        new_id = (result or {}).get("id") if isinstance(result, dict) else None

        return {
            "message_id": mid,
            "mailbox": mailbox,
            "recipients_affected": 1,
            "status": "quarantined",
            "moved_to": "deleteditems",
            "new_message_id": new_id,
        }

    async def block_sender(self, *, sender: str) -> dict[str, Any]:
        """Block a sender at the tenant (TABL) or via inbox-rule fallback.

        Strategy:
          * If ``block_method == "tabl"`` (default), POST to
            ``/security/tenantAllowBlockListEntries`` with action=Block,
            expiration 90 days out. Graph 403/404 → fall back.
          * Inbox-rule fallback: create a server-side rule on the
            configured default mailbox that moves mail from this sender
            to ``deleteditems``. Auditable, but scoped to one mailbox.
        """
        if not isinstance(sender, str) or not _SMTP_RE.match(sender or ""):
            raise ConnectorError(
                f"m365: sender={sender!r} is not a valid SMTP address",
                vendor="m365",
            )

        if self._block_method == "tabl":
            try:
                result = await self._http.post(
                    "/security/tenantAllowBlockListEntries",
                    json={
                        "indicator": sender,
                        "indicatorType": "Sender",
                        "action": "Block",
                        "notes": "Cyble AiSOC analyst block",
                    },
                )
                entry_id = (
                    result.get("id") if isinstance(result, dict) else None
                )
                return {
                    "sender": sender,
                    "blocked": True,
                    "method": "tenant_allow_block_list",
                    "entry_id": entry_id,
                }
            except ConnectorError as exc:
                # 400/403/404 → TABL unavailable on this tenant. Drop
                # to the inbox-rule fallback so the tool still returns
                # a positive disposition the LLM can reason about.
                if exc.status not in {400, 403, 404}:
                    raise
                log.warning(
                    "m365: TABL block_sender failed (status=%s); "
                    "falling back to inbox rule",
                    exc.status,
                )

        # Inbox-rule fallback (also the path when block_method == "inbox_rule").
        rule = await self._http.post(
            f"/users/{self._default_mailbox}/mailFolders/inbox/messageRules",
            json={
                "displayName": f"Cyble AiSOC block {sender}",
                "sequence": 1,
                "isEnabled": True,
                "conditions": {"senderContains": [sender]},
                "actions": {
                    "moveToFolder": "deleteditems",
                    "stopProcessingRules": True,
                },
            },
        )
        rule_id = rule.get("id") if isinstance(rule, dict) else None
        return {
            "sender": sender,
            "blocked": True,
            "method": "inbox_rule",
            "mailbox": self._default_mailbox,
            "rule_id": rule_id,
        }

    # ------------------------------------------------------------------ #
    # Internals                                                          #
    # ------------------------------------------------------------------ #

    def _resolve_target(self, message_id: str) -> tuple[str, str]:
        """Split a possibly-namespaced message_id into (mailbox, id).

        ``"user@corp.com::AAMk…"`` overrides the default mailbox.
        Plain message_ids use ``default_mailbox``. The split is on
        the configured separator (default ``"::"``); both halves are
        validated.
        """
        if not isinstance(message_id, str) or not message_id:
            raise ConnectorError(
                "m365: message_id must be a non-empty string",
                vendor="m365",
            )
        sep = self._mid_separator
        if sep in message_id:
            mbox_raw, _, mid_raw = message_id.partition(sep)
            mailbox = _validate_mailbox(mbox_raw, name="mailbox prefix")
            mid = _validate_message_id(mid_raw)
        else:
            mailbox = self._default_mailbox
            mid = _validate_message_id(message_id)
        return mailbox, mid


# ─── factory ─────────────────────────────────────────────────────────────


def make_m365_email(config: ConnectorConfig) -> M365EmailConnector:
    """Factory registered under ``ConnectorKind.EMAIL`` / vendor ``"m365"``."""
    return M365EmailConnector(config)


# Re-exported so callers can do ``from app.connectors.m365 import …``.
__all__ = [
    "M365EmailConnector",
    "make_m365_email",
]
