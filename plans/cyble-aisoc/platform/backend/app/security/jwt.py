"""Lightweight HMAC-SHA256 JWT for tenant identification.

We implement the JWT spec (RFC 7519) ourselves rather than pulling in
`PyJWT`/`jose` because:

  1. The token surface for AiSOC tenancy is narrow — we need HS256 sign +
     verify, claim validation (exp/nbf/iat/iss/aud), and tenant routing.
  2. Zero external dependency means the auth path is auditable in one file.
  3. CI ships with a deterministic secret; production rotates via
     `AISOC_JWT_SECRET_KEY`. This module never reaches for the network.

What we deliberately do not do
------------------------------
- No RS256/ES256 (HS256 only — symmetric secret).
- No JWK rotation / kid lookup (would happen in a SaaS deployment via a
  small adapter that wraps `decode_token`).
- No nested JWE / encryption (claims are public to the bearer).

If/when you move to PostgreSQL + RLS this module stays — RLS keys off
`SET LOCAL "tenant.id"` which we derive from the decoded JWT.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Any

from app.config import settings


class JwtError(Exception):
    """Base class for JWT decode / validation failures."""


class JwtDecodeError(JwtError):
    """Token is malformed, signature is invalid, or unsupported algorithm."""


class JwtExpiredError(JwtError):
    """Token's `exp` is in the past."""


class JwtNotYetValidError(JwtError):
    """Token's `nbf` is in the future."""


class JwtMissingClaimError(JwtError):
    """A required claim (e.g. `tid`) is missing."""


_ALG = "HS256"


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    # base64 expects padding to length % 4 == 0
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _sign(message: bytes, secret: str) -> bytes:
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).digest()


def encode_token(
    claims: dict[str, Any],
    *,
    secret: str | None = None,
    expires_in_seconds: int | None = None,
) -> str:
    """Sign `claims` into a JWT (compact serialization).

    `expires_in_seconds` sets `exp = iat + N`. If `claims` already carries
    an `exp`, it wins.
    """
    secret = secret or settings.jwt_secret_key
    if not secret:
        raise JwtError("AISOC_JWT_SECRET_KEY is not configured")

    header = {"alg": _ALG, "typ": "JWT"}
    now = int(time.time())
    payload: dict[str, Any] = {"iat": now, **claims}
    if expires_in_seconds is not None and "exp" not in payload:
        payload["exp"] = now + int(expires_in_seconds)

    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode("ascii")
    sig = _b64url_encode(_sign(signing_input, secret))
    return f"{h}.{p}.{sig}"


def decode_token(
    token: str,
    *,
    secret: str | None = None,
    leeway_seconds: int = 30,
    audience: str | None = None,
    issuer: str | None = None,
) -> dict[str, Any]:
    """Verify signature + temporal claims and return payload.

    Raises:
        JwtDecodeError on malformed / bad-signature / wrong-alg tokens.
        JwtExpiredError if `exp` has passed (with leeway).
        JwtNotYetValidError if `nbf` is still in the future.
    """
    secret = secret or settings.jwt_secret_key
    if not secret:
        raise JwtError("AISOC_JWT_SECRET_KEY is not configured")

    parts = token.split(".")
    if len(parts) != 3:
        raise JwtDecodeError("malformed token: expected 3 segments")
    h_b64, p_b64, s_b64 = parts

    try:
        header = json.loads(_b64url_decode(h_b64))
        payload = json.loads(_b64url_decode(p_b64))
        sig = _b64url_decode(s_b64)
    except (ValueError, json.JSONDecodeError) as exc:
        raise JwtDecodeError(f"malformed token: {exc}") from exc

    if header.get("alg") != _ALG:
        raise JwtDecodeError(f"unsupported alg: {header.get('alg')}")
    if header.get("typ") and header.get("typ") != "JWT":
        raise JwtDecodeError(f"unsupported typ: {header.get('typ')}")

    expected = _sign(f"{h_b64}.{p_b64}".encode("ascii"), secret)
    if not hmac.compare_digest(expected, sig):
        raise JwtDecodeError("bad signature")

    now = int(time.time())
    exp = payload.get("exp")
    if exp is not None and now > int(exp) + leeway_seconds:
        raise JwtExpiredError(f"token expired at {exp}")
    nbf = payload.get("nbf")
    if nbf is not None and now + leeway_seconds < int(nbf):
        raise JwtNotYetValidError(f"token not valid before {nbf}")

    if audience is not None:
        aud = payload.get("aud")
        if isinstance(aud, list):
            if audience not in aud:
                raise JwtDecodeError(f"audience {audience!r} not in {aud!r}")
        elif aud != audience:
            raise JwtDecodeError(f"audience mismatch: {aud!r} != {audience!r}")

    if issuer is not None and payload.get("iss") != issuer:
        raise JwtDecodeError(f"issuer mismatch: {payload.get('iss')!r}")

    return payload


@dataclass(frozen=True)
class TenantClaims:
    """Decoded tenant identity carried in a JWT.

    Fields map to JWT claims:
      - `tid`  → tenant_id (required)
      - `sub`  → analyst principal (email / sub)
      - `roles`→ RBAC roles for this token
      - `mssp_parent_tid` → if set, this token belongs to an MSSP analyst
        operating on behalf of `tid`; mssp_parent_tid is the MSSP's own tenant.
      - `allowed_tenants` → for MSSP tokens, the explicit list of child
        tenants the analyst may view. Empty list = all children.
    """

    tenant_id: str
    subject: str = "anonymous"
    roles: tuple[str, ...] = ()
    mssp_parent_tenant_id: str | None = None
    allowed_tenants: tuple[str, ...] = ()
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_mssp(self) -> bool:
        return self.mssp_parent_tenant_id is not None

    @property
    def is_admin(self) -> bool:
        return "admin" in self.roles or "platform_admin" in self.roles

    def can_view_tenant(self, tenant_id: str) -> bool:
        """Whether this token can read data for the given tenant.

        - Direct match wins.
        - MSSP parents can view their explicit allowed_tenants (or all
          children if `allowed_tenants` is empty).
        - Platform admins can view any tenant.
        """
        if self.is_admin:
            return True
        if tenant_id == self.tenant_id:
            return True
        if self.is_mssp:
            if not self.allowed_tenants:
                return True
            return tenant_id in self.allowed_tenants
        return False


def claims_from_payload(payload: dict[str, Any]) -> TenantClaims:
    """Build a TenantClaims from a decoded JWT payload."""
    tid = payload.get("tid") or payload.get("tenant_id")
    if not tid:
        raise JwtMissingClaimError("missing required claim: tid")

    roles_raw = payload.get("roles") or []
    if isinstance(roles_raw, str):
        roles_raw = [r.strip() for r in roles_raw.split(",") if r.strip()]

    allowed_raw = payload.get("allowed_tenants") or []
    if isinstance(allowed_raw, str):
        allowed_raw = [t.strip() for t in allowed_raw.split(",") if t.strip()]

    return TenantClaims(
        tenant_id=str(tid),
        subject=str(payload.get("sub") or "anonymous"),
        roles=tuple(str(r) for r in roles_raw),
        mssp_parent_tenant_id=(
            str(payload["mssp_parent_tid"])
            if payload.get("mssp_parent_tid")
            else None
        ),
        allowed_tenants=tuple(str(t) for t in allowed_raw),
        raw=payload,
    )


def issue_tenant_token(
    *,
    tenant_id: str,
    subject: str = "demo-analyst",
    roles: list[str] | None = None,
    mssp_parent_tenant_id: str | None = None,
    allowed_tenants: list[str] | None = None,
    expires_in_seconds: int = 8 * 3600,
) -> str:
    """Helper used by tests and the demo bootstrap to mint a tenant token."""
    payload: dict[str, Any] = {
        "tid": tenant_id,
        "sub": subject,
        "roles": list(roles or []),
    }
    if mssp_parent_tenant_id:
        payload["mssp_parent_tid"] = mssp_parent_tenant_id
    if allowed_tenants:
        payload["allowed_tenants"] = list(allowed_tenants)
    return encode_token(payload, expires_in_seconds=expires_in_seconds)
