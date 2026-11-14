"""Okta IdP connector.

Implements ``BaseIdpConnector`` against the Okta Identity Cloud REST API
(``/api/v1``). Tenants supply their org URL as ``base_url`` — Okta
single-tenants under a per-customer subdomain:

  * Standard:    ``https://example.okta.com``
  * Preview:     ``https://example.oktapreview.com``
  * Custom URL:  ``https://id.example.com``  (BYO domain)

Auth
----
Okta supports two service-to-service auth flows:

  1. **SSWS API tokens** — long-lived bearer tokens issued in the
     admin console under *Security → API → Tokens*. Sent on every
     request as ``Authorization: SSWS <token>``. Simple, well-supported,
     and what the vast majority of integrations use. *Default for this
     connector.*
  2. **OAuth 2.0 with private-key JWT** — scoped, short-lived
     access tokens via the ``/oauth2/v1/token`` endpoint. Recommended
     by Okta for new high-trust integrations but requires customer
     PKI and Org-level "API Service" app config. Out of scope for v1;
     the SDK supports ``OAuthClientCredentials`` if a tenant needs it
     in a later release.

The token is scoped to the issuing admin user; the tenant operator
should provision a service-account with at minimum:

  * Read-only Admin           → ``get_user`` (profile, factors, groups, logs)
  * Group Membership Admin    → group lookup if scoping factors
  * Help Desk Admin (or above)→ ``revoke_sessions``, ``reset_password``
  * Org Admin / Super Admin   → ``disable_user`` (suspend lifecycle)

API mapping
-----------
Each operation routes to the Okta endpoint that most closely matches
what an analyst expects from the action verb.

``get_user``
    GET ``/api/v1/users/{user_id_or_login}`` for the profile +
    ``status`` + ``lastLogin``. Optional fan-out (configurable, on by
    default) to:
      * GET ``/api/v1/users/{id}/groups``  for ``groups[].profile.name``
      * GET ``/api/v1/users/{id}/factors`` for enrolled MFA factors
      * GET ``/api/v1/logs``               for the most recent
        ``user.session.start`` event — used to enrich ``last_signin``
        with src_ip, country and ASN (Okta GeoIP).
    Every fan-out is best-effort: a failure on enrichment downgrades
    to a "the user exists" response rather than failing the whole
    call, because operators need the user record even when the
    System Log API is throttled.

``revoke_sessions``
    DELETE ``/api/v1/users/{id}/sessions?oauthTokens=true``. Clears
    all active Okta SSO and OIDC sessions for the user. Okta returns
    ``204 No Content`` without a session count, so we report the
    pre-DELETE count via a GET-then-DELETE pair when
    ``count_sessions=True`` (the default) and ``-1`` (unknown) when
    sessions aren't enumerable for the token.

``disable_user``
    POST ``/api/v1/users/{id}/lifecycle/suspend``. ``SUSPENDED`` is
    the reversible counterpart to ``DEACTIVATED`` — an admin can
    unsuspend via ``/lifecycle/unsuspend``. We deliberately do NOT
    call ``/lifecycle/deactivate`` since deactivation is destructive
    (drops group assignments, sessions, app links) and a containment
    action should be reversible by default. Operators wanting the
    nuclear option can set ``params.disable_lifecycle="deactivate"``.

``reset_password``
    POST ``/api/v1/users/{id}/lifecycle/reset_password?sendEmail=true``.
    Okta emails the user a one-time link; the connector reports
    ``reset_email_sent=True`` on the successful 200/204.

Identifier hygiene
------------------
Okta accepts both the Okta user ID (e.g. ``00u1abcdef...``) and the
login (typically the user's email) at every ``/users/{id}`` endpoint.
We pass the caller-supplied string through after rejecting control
characters and percent-encoding it for the URL path — Okta's API does
the lookup either way. We do NOT pre-resolve login → id on every call
because that doubles round-trips for what is usually a single GET.

Config (``params``)
-------------------
* ``base_url``                 — Okta org URL (HTTPS). Required.
* ``read_timeout_s``           — Per-request read timeout. Default ``30``.
* ``verify_tls``               — Verify TLS certs. Default ``True``.
* ``include_groups``           — Fetch group memberships during
                                 ``get_user``. Default ``True``.
* ``include_factors``          — Fetch enrolled MFA factors during
                                 ``get_user``. Default ``True``.
* ``include_signin_log``       — Enrich ``last_signin`` from the
                                 System Log API. Default ``True``.
* ``signin_log_window_hours``  — Lookback for System Log enrichment.
                                 Default ``168`` (7d). Capped at
                                 ``720`` (30d).
* ``count_sessions``           — GET sessions before DELETE to
                                 populate ``sessions_revoked``.
                                 Adds one round-trip. Default ``True``.
* ``disable_lifecycle``        — ``"suspend"`` (reversible, default)
                                 or ``"deactivate"`` (destructive).

Config (``secrets``)
--------------------
* ``api_token``                — Okta SSWS API token.

Errors
------
Okta returns ``E0000007`` (not found) and ``E0000016`` (already
suspended / unsuspended) inside the response body as a ``200`` or
``404``. We treat:

  * ``E0000007`` → ``ConnectorError`` with the user id echoed.
  * ``E0000016`` on suspend/unsuspend → success (idempotent).
  * Anything else → ``ConnectorError`` with the Okta error code
    surfaced verbatim for operator triage.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote

import httpx

from app.connectors.sdk.base import (
    ConnectorConfig,
    ConnectorError,
)
from app.connectors.sdk.http import ApiKeyAuth, AsyncHttpClient
from app.connectors.sdk.protocols import BaseIdpConnector

log = logging.getLogger(__name__)


# ─── constants ───────────────────────────────────────────────────────────

# Okta user IDs are 20 char ``oid``-style strings starting with ``00u``.
# We don't gate on this — callers may legitimately pass logins/emails —
# but we use the pattern to decide when to skip path-encoding for an
# obviously-safe identifier.
_OKTA_ID_RE = re.compile(r"^[A-Za-z0-9]{12,32}$")

# Control characters in identifiers are rejected outright. Same posture
# as SentinelOne / CrowdStrike — keeps log lines and audit trails legible.
_FORBIDDEN_CHARS = re.compile(r"[\x00-\x1f\x7f]")

# Okta lifecycle values we accept for ``disable_user``.
_VALID_DISABLE_LIFECYCLES = frozenset({"suspend", "deactivate"})

# Okta error codes we treat as benign idempotent successes on
# suspend/unsuspend. ``E0000016`` is "Activation failed because the
# user is already activated/suspended/etc."
_IDEMPOTENT_SUSPEND_CODES = frozenset({"E0000016"})


# ─── helpers ─────────────────────────────────────────────────────────────


def _check_identifier(value: str, *, field: str) -> str:
    """Reject empty / non-str / control-char user identifiers."""
    if not isinstance(value, str):
        raise ConnectorError(
            f"okta: {field} must be a string (got {type(value).__name__})",
            vendor="okta",
        )
    stripped = value.strip()
    if not stripped:
        raise ConnectorError(
            f"okta: empty {field} rejected",
            vendor="okta",
        )
    if _FORBIDDEN_CHARS.search(stripped):
        raise ConnectorError(
            f"okta: {field} {value!r} contains control characters",
            vendor="okta",
        )
    return stripped


def _encode_path_id(identifier: str) -> str:
    """Percent-encode a user id for use in ``/users/{id}`` paths.

    Okta accepts both the 20-char ID and a login (often an email).
    Logins routinely contain ``@``, ``+``, ``.`` — all of which need
    to round-trip cleanly through ``httpx``. We avoid encoding obvious
    Okta IDs to keep log lines readable.
    """
    if _OKTA_ID_RE.match(identifier):
        return identifier
    # ``quote`` defaults to leaving ``/`` alone; user logins must not
    # contain ``/``, so we pass safe="" to encode everything outside
    # the URL-safe charset.
    return quote(identifier, safe="")


def _coerce_int(value: Any, *, name: str, lo: int, hi: int) -> int:
    """Bound check + cast for integers ingested from external callers."""
    try:
        as_int = int(value)
    except (TypeError, ValueError) as exc:
        raise ConnectorError(
            f"okta: {name} must be an integer (got {value!r})",
            vendor="okta",
        ) from exc
    if as_int < lo or as_int > hi:
        raise ConnectorError(
            f"okta: {name}={as_int} out of range [{lo}, {hi}]",
            vendor="okta",
        )
    return as_int


def _okta_error_code(exc: ConnectorError) -> str | None:
    """Best-effort extraction of an ``errorCode`` from a ConnectorError.

    ``AsyncHttpClient`` puts a truncated body in the message; Okta
    payloads look like ``{"errorCode":"E0000007","errorSummary":"..."}``.
    Pulling the code out lets call-sites decide whether to treat a 4xx
    as idempotent success vs. genuine failure.
    """
    match = re.search(r"E000\d{4}", str(exc))
    return match.group(0) if match else None


def _make_ticket(prefix: str, identifier: str) -> str:
    """Build a stable audit ticket id.

    Operators correlate this back to Okta's System Log entries via the
    identifier. Use the last 8 chars of the (encoded) identifier to
    keep tickets short and printable.
    """
    suffix = _encode_path_id(identifier)[-8:].lstrip("-_") or "0"
    return f"{prefix}-{suffix.upper()}"


# ─── connector ───────────────────────────────────────────────────────────


class OktaIdpConnector(BaseIdpConnector):
    """Okta IdP via the management REST API.

    Each instance owns one ``AsyncHttpClient`` against the configured
    Okta org. The SSWS token is sent as a static
    ``Authorization: SSWS <token>`` header — no refresh required.
    Repeated tool calls for the same tenant reuse one HTTP pool.
    """

    vendor = "okta"

    def __init__(self, config: ConnectorConfig) -> None:
        super().__init__(config)

        base_url = config.param("base_url")
        if not base_url or not isinstance(base_url, str):
            raise ConnectorError(
                "okta: missing required param 'base_url' "
                "(e.g. https://example.okta.com)",
                vendor="okta",
            )
        if not base_url.startswith("https://"):
            raise ConnectorError(
                f"okta: base_url must be https (got {base_url!r})",
                vendor="okta",
            )
        self._base_url = base_url.rstrip("/")

        self._include_groups = bool(
            config.param("include_groups", True)
        )
        self._include_factors = bool(
            config.param("include_factors", True)
        )
        self._include_signin_log = bool(
            config.param("include_signin_log", True)
        )
        self._signin_window_hours = _coerce_int(
            config.param("signin_log_window_hours") or 168,
            name="signin_log_window_hours",
            lo=1,
            hi=720,
        )
        self._count_sessions = bool(
            config.param("count_sessions", True)
        )

        lifecycle = str(
            config.param("disable_lifecycle") or "suspend"
        ).lower()
        if lifecycle not in _VALID_DISABLE_LIFECYCLES:
            raise ConnectorError(
                f"okta: disable_lifecycle must be one of "
                f"{sorted(_VALID_DISABLE_LIFECYCLES)} "
                f"(got {lifecycle!r})",
                vendor="okta",
            )
        self._disable_lifecycle = lifecycle

        read_timeout = float(config.param("read_timeout_s") or 30.0)
        verify_tls = bool(config.param("verify_tls", True))

        api_token = config.secret("api_token")

        # Okta API tokens use the ``SSWS`` scheme — distinct from the
        # OAuth-style ``Bearer ...`` flow. ``ApiKeyAuth`` matches.
        auth = ApiKeyAuth(
            header="Authorization",
            value=f"SSWS {api_token}",
        )

        self._http = AsyncHttpClient(
            base_url=self._base_url,
            auth=auth,
            timeout=httpx.Timeout(
                connect=10.0, read=read_timeout, write=10.0, pool=5.0
            ),
            vendor="okta",
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
    # Health                                                             #
    # ------------------------------------------------------------------ #

    async def health_check(self) -> dict[str, Any]:
        """Probe ``/api/v1/users/me``.

        ``/users/me`` resolves to the SSWS token's owning user — it
        succeeds for any valid token regardless of admin role, which
        makes it the canonical "is the token alive" endpoint. Failure
        here means the token is wrong, expired, or the org URL is
        mis-configured.
        """
        payload = await self._http.get("/api/v1/users/me")
        if isinstance(payload, dict):
            user_id = payload.get("id")
            profile = payload.get("profile") or {}
            return {
                "ok": True,
                "vendor": self.vendor,
                "kind": self.kind.value,
                "service_account_id": user_id,
                "service_account_login": profile.get("login"),
            }
        return {"ok": True, "vendor": self.vendor, "kind": self.kind.value}

    # ------------------------------------------------------------------ #
    # Public protocol surface                                            #
    # ------------------------------------------------------------------ #

    async def get_user(self, *, user: str) -> dict[str, Any]:
        """Fetch user profile + groups + factors + last sign-in event.

        The shape matches ``MockIdpConnector.get_user`` so the LLM
        tools see the same envelope whether real Okta or the mock
        responds. Enrichment fan-outs are best-effort — they degrade
        to ``None`` / empty list rather than failing the whole call,
        because operators still need the core profile during incident
        triage even when the System Log API is throttled.
        """
        identifier = _check_identifier(user, field="user")
        encoded = _encode_path_id(identifier)

        try:
            okta_user = await self._http.get(
                f"/api/v1/users/{encoded}"
            )
        except ConnectorError as exc:
            code = _okta_error_code(exc)
            if code == "E0000007":
                raise ConnectorError(
                    f"okta: user {user!r} not found",
                    vendor="okta",
                    status=404,
                ) from exc
            raise

        if not isinstance(okta_user, dict):
            raise ConnectorError(
                f"okta: unexpected user payload type "
                f"{type(okta_user).__name__}",
                vendor="okta",
            )

        user_id = str(okta_user.get("id") or "")
        profile = okta_user.get("profile") or {}
        if not isinstance(profile, dict):
            profile = {}

        # Default the response to the input ``user`` so downstream
        # logs stay consistent even if we lose the profile. Email
        # falls back to the login (the most common Okta convention).
        email = (
            profile.get("email")
            or profile.get("login")
            or f"{identifier}@unknown"
        )

        result: dict[str, Any] = {
            "user": user,
            "email": email,
            "department": profile.get("department") or "",
            "manager": profile.get("manager") or
            profile.get("managerId") or "",
            "groups": [],
            "last_signin": {},
            "mfa_factors": [],
            # Status is non-mock metadata that operators frequently
            # ask for — we surface it as an additive field so we
            # don't break the schema contract.
            "status": okta_user.get("status") or "UNKNOWN",
        }

        last_login = okta_user.get("lastLogin")
        if isinstance(last_login, str) and last_login:
            result["last_signin"]["ts"] = last_login

        # ── enrichment: groups ────────────────────────────────────
        if self._include_groups and user_id:
            try:
                groups_payload = await self._http.get(
                    f"/api/v1/users/{user_id}/groups",
                    params={"limit": 200},
                )
                if isinstance(groups_payload, list):
                    result["groups"] = [
                        g.get("profile", {}).get("name", "")
                        for g in groups_payload
                        if isinstance(g, dict)
                        and g.get("profile", {}).get("name")
                    ]
            except ConnectorError as exc:
                log.warning(
                    "okta.get_user.groups failed for %s: %s",
                    user,
                    exc,
                )

        # ── enrichment: factors ───────────────────────────────────
        if self._include_factors and user_id:
            try:
                factors_payload = await self._http.get(
                    f"/api/v1/users/{user_id}/factors"
                )
                if isinstance(factors_payload, list):
                    result["mfa_factors"] = [
                        f.get("factorType", "")
                        for f in factors_payload
                        if isinstance(f, dict) and f.get("factorType")
                    ]
            except ConnectorError as exc:
                log.warning(
                    "okta.get_user.factors failed for %s: %s",
                    user,
                    exc,
                )

        # ── enrichment: most recent sign-in ───────────────────────
        if self._include_signin_log and user_id:
            try:
                since = datetime.now(timezone.utc) - timedelta(
                    hours=self._signin_window_hours
                )
                since_iso = since.strftime("%Y-%m-%dT%H:%M:%S.000Z")
                # ``filter`` uses Okta's SCIM-ish filter DSL. The
                # field expression is quoted by Okta server-side; we
                # just need to keep the literal user_id verbatim
                # (Okta IDs are alphanumeric so no escaping needed).
                logs_payload = await self._http.get(
                    "/api/v1/logs",
                    params={
                        "filter": (
                            f'actor.id eq "{user_id}" and '
                            'eventType eq "user.session.start"'
                        ),
                        "since": since_iso,
                        "sortOrder": "DESCENDING",
                        "limit": 1,
                    },
                )
                signin = _extract_signin_event(logs_payload)
                if signin:
                    # Merge over the ``ts`` we already populated from
                    # ``lastLogin``. The log event carries a richer
                    # timestamp + geo.
                    result["last_signin"] = signin
            except ConnectorError as exc:
                log.warning(
                    "okta.get_user.logs failed for %s: %s",
                    user,
                    exc,
                )

        return result

    async def revoke_sessions(self, *, user: str) -> dict[str, Any]:
        """Terminate every Okta SSO + OIDC session for the user.

        Okta's DELETE endpoint returns 204 with no body and no count;
        if ``count_sessions=True`` we GET the session list first to
        report a meaningful number. The DELETE is still issued either
        way so an enumeration failure can't block the containment.
        """
        identifier = _check_identifier(user, field="user")
        encoded = _encode_path_id(identifier)

        pre_count = -1
        if self._count_sessions:
            try:
                sessions = await self._http.get(
                    f"/api/v1/users/{encoded}/sessions"
                )
                if isinstance(sessions, list):
                    pre_count = len(sessions)
            except ConnectorError as exc:
                # Older Okta tokens lack ``users.sessions:read`` —
                # log and continue. The DELETE is the operationally
                # important call.
                log.warning(
                    "okta.revoke_sessions.list failed for %s: %s",
                    user,
                    exc,
                )

        try:
            await self._http.request_json(
                "DELETE",
                f"/api/v1/users/{encoded}/sessions",
                params={"oauthTokens": "true"},
            )
        except ConnectorError as exc:
            code = _okta_error_code(exc)
            if code == "E0000007":
                raise ConnectorError(
                    f"okta: user {user!r} not found",
                    vendor="okta",
                    status=404,
                ) from exc
            raise

        revoked = pre_count if pre_count >= 0 else 0
        return {
            "user": user,
            "sessions_revoked": revoked,
            "ticket": _make_ticket("REVOKE", identifier),
        }

    async def disable_user(
        self, *, user: str, reason: str
    ) -> dict[str, Any]:
        """Suspend (default) or deactivate the user.

        ``suspend`` is the recommended containment verb: reversible
        via ``/lifecycle/unsuspend`` and preserves group + app
        assignments. Operators who want the destructive option can
        set ``params.disable_lifecycle="deactivate"`` at connector
        registration time.
        """
        if not isinstance(reason, str) or not reason.strip():
            raise ConnectorError(
                "okta: disable_user requires a non-empty reason",
                vendor="okta",
            )
        identifier = _check_identifier(user, field="user")
        encoded = _encode_path_id(identifier)
        action = self._disable_lifecycle  # "suspend" | "deactivate"

        try:
            await self._http.post(
                f"/api/v1/users/{encoded}/lifecycle/{action}",
                # Okta's lifecycle endpoints take an empty body;
                # ``data=None`` keeps Content-Length: 0.
                data=None,
            )
        except ConnectorError as exc:
            code = _okta_error_code(exc)
            if code == "E0000007":
                raise ConnectorError(
                    f"okta: user {user!r} not found",
                    vendor="okta",
                    status=404,
                ) from exc
            if code in _IDEMPOTENT_SUSPEND_CODES:
                # Already suspended (or already deactivated for the
                # deactivate variant) — return success and trust the
                # operator they wanted the user in that state.
                log.info(
                    "okta.disable_user: user %s already in target "
                    "lifecycle (%s); treating as idempotent success",
                    user,
                    action,
                )
            else:
                raise

        return {
            "user": user,
            "disabled": True,
            "reason": reason,
            # Additive — operator can audit which lifecycle was used.
            "lifecycle": action,
        }

    async def reset_password(self, *, user: str) -> dict[str, Any]:
        """Send the user a password-reset email via Okta lifecycle.

        Okta returns ``{ "resetPasswordUrl": "..." }`` on success
        when ``sendEmail=false``, or 200 with no useful body when
        ``sendEmail=true``. We always pass ``sendEmail=true`` because
        the SOC playbook explicitly wants the user (not the analyst)
        to drive the recovery — embedding the reset URL in a tool
        response would surface a credential-equivalent secret to the
        LLM.
        """
        identifier = _check_identifier(user, field="user")
        encoded = _encode_path_id(identifier)

        try:
            await self._http.post(
                f"/api/v1/users/{encoded}/lifecycle/reset_password",
                params={"sendEmail": "true"},
                data=None,
            )
        except ConnectorError as exc:
            code = _okta_error_code(exc)
            if code == "E0000007":
                raise ConnectorError(
                    f"okta: user {user!r} not found",
                    vendor="okta",
                    status=404,
                ) from exc
            raise

        return {
            "user": user,
            "reset_email_sent": True,
            "ticket": _make_ticket("RESET", identifier),
        }

    # ------------------------------------------------------------------ #
    # ITDR surface (t2c-itdr)                                            #
    # ------------------------------------------------------------------ #

    async def list_user_sessions(self, *, user: str) -> dict[str, Any]:
        """Enumerate active Okta SSO sessions for ``user``.

        GET ``/api/v1/users/{id}/sessions`` returns the live SSO
        sessions Okta is tracking for the principal — *not* the
        downstream OAuth/OIDC access tokens (those live on the
        ``/oauth2/v1/tokens`` surface and are tied to a client_id).
        For the ITDR sub-agent the SSO sessions are the
        higher-signal artefact: each one represents an active
        browser/device authenticated to Okta itself.

        We enrich every row with the matching System-Log
        ``user.session.start`` event when available so the agent
        gets src_ip / country / ASN / risk together with the
        session id. Each enrichment is per-session and best-effort —
        failure to enrich one row never blocks the others.
        """
        identifier = _check_identifier(user, field="user")
        encoded = _encode_path_id(identifier)

        try:
            sessions_payload = await self._http.get(
                f"/api/v1/users/{encoded}/sessions"
            )
        except ConnectorError as exc:
            code = _okta_error_code(exc)
            if code == "E0000007":
                raise ConnectorError(
                    f"okta: user {user!r} not found",
                    vendor="okta",
                    status=404,
                ) from exc
            raise

        if not isinstance(sessions_payload, list):
            return {"user": user, "sessions": [], "count": 0}

        sessions: list[dict[str, Any]] = []
        for raw in sessions_payload:
            if not isinstance(raw, dict):
                continue
            sessions.append(_normalize_okta_session(raw))

        # Enrich each session with a sign-in log lookup when ITP is
        # available. The filter targets the exact ``authenticationContext.externalSessionId``
        # → ``session.id`` mapping Okta emits on ``user.session.start``.
        if self._include_signin_log and sessions:
            for sess in sessions:
                sid = sess.get("session_id")
                if not sid:
                    continue
                try:
                    enrichment = await self._fetch_session_signin(
                        external_session_id=sid
                    )
                except ConnectorError as exc:
                    log.warning(
                        "okta.list_user_sessions.enrich failed for %s: %s",
                        sid,
                        exc,
                    )
                    continue
                # Don't clobber connector-extracted fields if Okta
                # didn't return a richer value — merge with care.
                for key, value in enrichment.items():
                    if value and not sess.get(key):
                        sess[key] = value

        return {
            "user": user,
            "sessions": sessions,
            "count": len(sessions),
        }

    async def revoke_session(
        self, *, user: str, session_id: str, reason: str | None = None
    ) -> dict[str, Any]:
        """Targeted revoke of a single Okta SSO session.

        DELETE ``/api/v1/sessions/{sessionId}`` kills one session
        and leaves every other session on the principal intact.
        This is the ITDR primitive — the fleet-wide ``revoke_sessions``
        is too blunt when an analyst wants to surgically eject the
        AitM-controlled browser without booting the corp laptop.

        Returns ``revoked=True`` for 204 and for E0000007 (already
        gone — idempotent success).
        """
        _check_identifier(user, field="user")
        sid = _check_identifier(session_id, field="session_id")

        revoked = True
        try:
            await self._http.request_json(
                "DELETE",
                f"/api/v1/sessions/{quote(sid, safe='')}",
            )
        except ConnectorError as exc:
            code = _okta_error_code(exc)
            if code == "E0000007":
                # Already gone — that's the desired end state.
                log.info(
                    "okta.revoke_session: session %s already revoked; "
                    "treating as idempotent success",
                    sid,
                )
            else:
                raise

        return {
            "user": user,
            "session_id": sid,
            "revoked": revoked,
            "ticket": _make_ticket("SESSREV", sid),
        }

    async def list_oauth_grants(self, *, user: str) -> dict[str, Any]:
        """Enumerate OAuth/OIDC consent grants made by ``user``.

        GET ``/api/v1/users/{id}/grants`` returns every active
        consent the user has issued to OAuth applications in the
        org. Each grant is one (user, client_id, scope) triple.
        Okta returns them flat, so we fan out by ``client_id`` to
        the ``/oauth2/v1/clients/{clientId}`` admin endpoint to
        resolve the app name + publisher verification status —
        the two facts the ITDR risk model needs to flag illicit
        consent grants.

        Risk score is a heuristic on top of (unverified publisher,
        broad scopes, recently granted). The sub-agent fuses this
        with cross-source signals before the final verdict; the
        score here is a sort key, not a verdict.
        """
        identifier = _check_identifier(user, field="user")
        encoded = _encode_path_id(identifier)

        try:
            grants_payload = await self._http.get(
                f"/api/v1/users/{encoded}/grants",
                params={"limit": 200},
            )
        except ConnectorError as exc:
            code = _okta_error_code(exc)
            if code == "E0000007":
                raise ConnectorError(
                    f"okta: user {user!r} not found",
                    vendor="okta",
                    status=404,
                ) from exc
            raise

        if not isinstance(grants_payload, list):
            return {"user": user, "grants": []}

        # Cache client metadata across the fan-out — most users
        # consent to the same handful of apps, so we avoid hammering
        # ``/oauth2/v1/clients`` with duplicate GETs.
        client_cache: dict[str, dict[str, Any]] = {}
        grants: list[dict[str, Any]] = []

        for raw in grants_payload:
            if not isinstance(raw, dict):
                continue
            grant = _normalize_okta_grant(raw)
            client_id = grant.get("client_id") or ""
            if client_id and client_id not in client_cache:
                try:
                    client_cache[client_id] = await self._fetch_oauth_client(
                        client_id
                    )
                except ConnectorError as exc:
                    log.warning(
                        "okta.list_oauth_grants.client failed for %s: %s",
                        client_id,
                        exc,
                    )
                    client_cache[client_id] = {}
            client_meta = client_cache.get(client_id, {})
            if client_meta.get("app_name"):
                grant["app_name"] = client_meta["app_name"]
            if "publisher_verified" in client_meta:
                grant["publisher_verified"] = client_meta[
                    "publisher_verified"
                ]
            grant["risk_score"] = _score_grant_risk(grant)
            grants.append(grant)

        return {"user": user, "grants": grants}

    async def revoke_oauth_grant(
        self, *, user: str, grant_id: str, reason: str | None = None
    ) -> dict[str, Any]:
        """Targeted revoke of a single OAuth consent grant.

        DELETE ``/api/v1/users/{id}/grants/{grantId}``. Forward-only
        — the user (or admin) must re-consent to restore access,
        which is the desired property for "kill the illicit-consent
        app without nuking Slack and GitHub".
        """
        identifier = _check_identifier(user, field="user")
        gid = _check_identifier(grant_id, field="grant_id")
        encoded_user = _encode_path_id(identifier)
        encoded_grant = quote(gid, safe="")

        revoked = True
        try:
            await self._http.request_json(
                "DELETE",
                f"/api/v1/users/{encoded_user}/grants/{encoded_grant}",
            )
        except ConnectorError as exc:
            code = _okta_error_code(exc)
            if code == "E0000007":
                log.info(
                    "okta.revoke_oauth_grant: grant %s already revoked; "
                    "treating as idempotent success",
                    gid,
                )
            else:
                raise

        return {
            "user": user,
            "grant_id": gid,
            "revoked": revoked,
            "ticket": _make_ticket("GRANTREV", gid),
        }

    async def list_oauth_apps(self) -> dict[str, Any]:
        """List OAuth applications registered in the tenant.

        GET ``/api/v1/apps?filter=status eq "ACTIVE"&q=&limit=200``
        with ``signOnMode`` filtered client-side to OAuth flavours
        (``OPENID_CONNECT``, ``OAUTH2``, ``SAML_2_0`` is excluded
        because the ITDR risk model is consent-focused, not SAML-IdP-
        focused).

        ``total_users_granted`` is best-effort — Okta doesn't expose
        a direct counter on the apps endpoint, so we omit it rather
        than fan out one extra call per app. The sub-agent can
        compute it from ``list_oauth_grants`` if needed.
        """
        try:
            apps_payload = await self._http.get(
                "/api/v1/apps",
                params={
                    "filter": 'status eq "ACTIVE"',
                    "limit": 200,
                },
            )
        except ConnectorError:
            raise

        if not isinstance(apps_payload, list):
            return {"apps": []}

        apps: list[dict[str, Any]] = []
        for raw in apps_payload:
            if not isinstance(raw, dict):
                continue
            sign_on = (raw.get("signOnMode") or "").upper()
            if sign_on not in {"OPENID_CONNECT", "OAUTH2"}:
                continue
            apps.append(_normalize_okta_app(raw))

        return {"apps": apps}

    # ------------------------------------------------------------------ #
    # ITDR helpers                                                       #
    # ------------------------------------------------------------------ #

    async def _fetch_session_signin(
        self, *, external_session_id: str
    ) -> dict[str, Any]:
        """Fetch the ``user.session.start`` log row for one session.

        Okta indexes sessions in the System Log by
        ``authenticationContext.externalSessionId``. The lookback
        window is the same as the user-level enrichment window.
        """
        since = datetime.now(timezone.utc) - timedelta(
            hours=self._signin_window_hours
        )
        since_iso = since.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        payload = await self._http.get(
            "/api/v1/logs",
            params={
                "filter": (
                    'eventType eq "user.session.start" and '
                    f'authenticationContext.externalSessionId eq '
                    f'"{external_session_id}"'
                ),
                "since": since_iso,
                "sortOrder": "DESCENDING",
                "limit": 1,
            },
        )
        return _extract_signin_event(payload)

    async def _fetch_oauth_client(self, client_id: str) -> dict[str, Any]:
        """Resolve the human-readable app name + publisher metadata.

        The ``/oauth2/v1/clients/{clientId}`` endpoint requires
        ``okta.apps.read``; tenants that don't grant that to the
        service account get a 403 here and we silently fall back
        to the bare client_id. Failure of metadata enrichment must
        never block the grant-listing — incident response is the
        priority.
        """
        encoded = quote(client_id, safe="")
        payload = await self._http.get(
            f"/oauth2/v1/clients/{encoded}"
        )
        if not isinstance(payload, dict):
            return {}
        out: dict[str, Any] = {}
        name = payload.get("client_name") or payload.get("label")
        if isinstance(name, str) and name:
            out["app_name"] = name
        # Okta doesn't expose a binary "publisher verified" flag on
        # OAuth clients — we approximate by checking
        # ``application_type=="web"`` AND a non-empty
        # ``policy_uri`` / ``tos_uri``. Customers that need a
        # stricter signal can override via custom app metadata.
        app_type = payload.get("application_type") or ""
        policy = payload.get("policy_uri") or ""
        tos = payload.get("tos_uri") or ""
        out["publisher_verified"] = bool(
            app_type == "web" and (policy or tos)
        )
        return out


# ─── sign-in log extraction ──────────────────────────────────────────────


def _extract_signin_event(payload: Any) -> dict[str, Any]:
    """Pull the analyst-relevant fields out of an Okta System Log row.

    Okta's ``/api/v1/logs`` returns a list of LogEvent objects with
    deeply nested ``client``, ``securityContext`` and ``debugContext``
    blocks. We surface the same shape the mock IdP emits:
    ``ts``, ``src_ip``, ``country``, ``asn``, ``anomaly_score``.

    Anomaly score is heuristic — Okta exposes ``riskLevel``
    (LOW/MEDIUM/HIGH) in the security context for ITP-enabled orgs.
    We map that to a float so downstream alerting can keep its
    threshold logic numeric.
    """
    if not isinstance(payload, list) or not payload:
        return {}
    event = payload[0]
    if not isinstance(event, dict):
        return {}

    out: dict[str, Any] = {}

    ts = event.get("published")
    if isinstance(ts, str) and ts:
        out["ts"] = ts

    client = event.get("client") or {}
    if isinstance(client, dict):
        ip = client.get("ipAddress")
        if isinstance(ip, str) and ip:
            out["src_ip"] = ip
        geo = client.get("geographicalContext") or {}
        if isinstance(geo, dict):
            country = geo.get("country") or geo.get("countryCode")
            if isinstance(country, str) and country:
                out["country"] = country

    sec_ctx = event.get("securityContext") or {}
    if isinstance(sec_ctx, dict):
        as_num = sec_ctx.get("asNumber")
        as_org = sec_ctx.get("asOrg")
        if as_num and as_org:
            out["asn"] = f"AS{as_num} {as_org}"
        elif as_num:
            out["asn"] = f"AS{as_num}"
        elif as_org:
            out["asn"] = str(as_org)
        risk = sec_ctx.get("riskLevel")
        if isinstance(risk, str):
            out["anomaly_score"] = _risk_to_score(risk)

    # ``debugContext.debugData.threat_suspected`` is another signal
    # Okta surfaces for ITP — promote it into the anomaly score if
    # the security context didn't already.
    debug = event.get("debugContext") or {}
    if (
        "anomaly_score" not in out
        and isinstance(debug, dict)
    ):
        debug_data = debug.get("debugData") or {}
        if isinstance(debug_data, dict):
            threat = debug_data.get("threat_suspected")
            if isinstance(threat, str) and threat.lower() == "true":
                out["anomaly_score"] = 0.75

    return out


def _risk_to_score(risk: str) -> float:
    """Map Okta riskLevel enum to the numeric anomaly_score band."""
    band = risk.strip().upper()
    return {
        "LOW": 0.15,
        "MEDIUM": 0.55,
        "HIGH": 0.85,
        "UNKNOWN": 0.0,
    }.get(band, 0.0)


# ─── ITDR normalization ──────────────────────────────────────────────────


def _normalize_okta_session(raw: dict[str, Any]) -> dict[str, Any]:
    """Map an Okta ``/sessions`` row onto the ITDR session shape.

    Okta returns ``{id, login, userId, createdAt, expiresAt,
    lastPasswordVerification, lastFactorVerification, status,
    amr, idp, mfaActive, ...}``. We translate it into the shape
    the ITDR agent's mocks emit so downstream code is connector-
    agnostic.
    """
    out: dict[str, Any] = {
        "session_id": raw.get("id") or "",
        "ts_created": raw.get("createdAt") or "",
        "last_seen": raw.get("lastPasswordVerification")
        or raw.get("lastFactorVerification")
        or raw.get("createdAt")
        or "",
        "mfa_method": _derive_mfa_method(raw),
        "suspected_aitm": False,
        "device_managed": False,
        "anomaly_score": 0.0,
    }
    # Okta exposes neither src_ip nor country on the bare session
    # row — those come from the System Log enrichment pass that
    # ``list_user_sessions`` performs.
    return out


def _derive_mfa_method(raw: dict[str, Any]) -> str:
    """Translate Okta ``amr`` into a single user-facing label.

    AMR is a list per RFC 8176 (e.g. ``["pwd", "mfa", "fpt"]``).
    We surface the strongest factor present, falling back to
    ``unknown`` when the session was assertion-only.
    """
    amr = raw.get("amr")
    if not isinstance(amr, list):
        return "unknown"
    methods = {str(m).lower() for m in amr if isinstance(m, str)}
    if "hwk" in methods or "swk" in methods:
        return "webauthn"
    if "fpt" in methods or "face" in methods:
        return "biometric"
    if "sms" in methods:
        return "sms"
    if "tel" in methods:
        return "voice"
    if "mfa" in methods:
        return "okta_verify"
    if "pwd" in methods:
        return "password_only"
    return "unknown"


def _normalize_okta_grant(raw: dict[str, Any]) -> dict[str, Any]:
    """Map an Okta ``/grants`` row onto the ITDR grant shape."""
    return {
        "grant_id": raw.get("id") or "",
        "client_id": raw.get("clientId") or "",
        "app_name": raw.get("clientId") or "",  # placeholder; resolved later
        "scopes": list(raw.get("scopes") or []),
        "granted_at": raw.get("created") or "",
        "last_used": raw.get("lastUpdated") or None,
        "publisher_verified": False,
        "risk_score": 0.0,
    }


def _normalize_okta_app(raw: dict[str, Any]) -> dict[str, Any]:
    """Map an Okta ``/apps`` row onto the ITDR app shape."""
    settings = raw.get("settings") or {}
    oauth_client = (
        settings.get("oauthClient") if isinstance(settings, dict) else None
    )
    if not isinstance(oauth_client, dict):
        oauth_client = {}
    scopes = list(oauth_client.get("consent_method") and [] or [])
    # Okta returns OAuth scopes on a separate endpoint
    # (``/api/v1/apps/{id}/grants``). For the listing surface we
    # return the empty list — the sub-agent can fan out per-app
    # when it needs scope detail. Total user count is similarly
    # left absent; see docstring of ``list_oauth_apps``.
    return {
        "client_id": oauth_client.get("client_id") or raw.get("id") or "",
        "app_name": raw.get("label") or raw.get("name") or "",
        "publisher": (
            raw.get("accessibility", {}).get("selfService") and "Self-Service"
        )
        or raw.get("vendor")
        or "",
        "publisher_verified": False,
        "scopes_requested": scopes,
        "first_seen": raw.get("created") or "",
    }


# Catastrophic-scope keywords — granting these to an unverified
# OAuth publisher is the textbook illicit-consent-grant pattern.
_ITDR_HIGH_RISK_SCOPES = frozenset(
    {
        "mail.readwrite",
        "mail.send",
        "mail.read",
        "mailboxsettings.readwrite",
        "files.readwrite.all",
        "sites.readwrite.all",
        "user.readwrite.all",
        "directory.readwrite.all",
        "offline_access",
        "full_access_as_user",
    }
)


def _score_grant_risk(grant: dict[str, Any]) -> float:
    """Heuristic 0..1 risk score for an OAuth consent grant.

    The score blends three signals — publisher trust, scope
    blast-radius, and "is the app actually being used after the
    grant". Verdict still belongs to the ITDR sub-agent; this
    score is a sort key on the grant listing page.
    """
    score = 0.0

    if not grant.get("publisher_verified", False):
        score += 0.4

    scopes = grant.get("scopes") or []
    if isinstance(scopes, list):
        normalized = {str(s).lower() for s in scopes}
        if normalized & _ITDR_HIGH_RISK_SCOPES:
            score += 0.4
        if len(normalized) >= 5:
            # Even individually-benign scopes get suspicious in
            # large clusters — broad consent surface is the worry.
            score += 0.1

    # Grant exists but was never exercised → classic dormant-app
    # red flag (illicit-consent typically grants and then waits
    # for the cron-driven mailbox sweep).
    if not grant.get("last_used"):
        score += 0.1

    return min(1.0, round(score, 2))


# ─── factory ─────────────────────────────────────────────────────────────


def make_okta_idp(config: ConnectorConfig) -> OktaIdpConnector:
    """Factory used by ``app.connectors.sdk.builtin``."""
    return OktaIdpConnector(config)


__all__ = ["OktaIdpConnector", "make_okta_idp"]
