"""The service-account token exchange, written once.

``gcp_cloud_audit`` and ``gcp_scc`` each already carried a byte-for-byte
copy of the same forty lines: parse the key blob, build an RS256 JWT
assertion, POST it to Google's token endpoint, cache the result. Depth plan
4.1 adds a third Google connector, and a third copy of a credential path is
how one of them silently stops refreshing, or keeps a token past its expiry,
or stops validating a field, in a way the other two do not — so no test
anywhere disagrees with itself.

Only the new connector reads this today. Moving the two older ones onto it
is a change to a working credential path on a connector this plan item does
not otherwise touch, so it is recorded as a follow-up in `DEPTH_PROGRESS.md`
rather than folded in here. The important half is already true: the number
of copies stopped growing.

The JWT is built by hand rather than with ``google-auth`` because
``cryptography`` is already a dependency (the credential vault needs it) and
``google-auth`` is not, so hand-building costs nothing and avoids a
dependency whose resolution would have to be pinned across fourteen
declaration sites.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

DEFAULT_TOKEN_URL = "https://oauth2.googleapis.com/token"

#: Google rejects an assertion whose lifetime exceeds an hour.
_ASSERTION_LIFETIME_SECONDS = 3600

#: Refresh this far before expiry. Clock skew between here and Google plus a
#: slow poll is enough to spend a token that looked valid when the request
#: was built.
_REFRESH_MARGIN_SECONDS = 60


def b64url(data: bytes) -> str:
    """Standard JWT base64url with no padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def parse_service_account(blob: str) -> dict[str, Any]:
    """Validate a pasted service-account key file.

    Raises rather than returning a partial dict: a key missing
    ``private_key`` fails at signing time with a ``cryptography`` error that
    says nothing about which field the operator forgot to paste.
    """
    try:
        info = json.loads(blob)
    except json.JSONDecodeError as exc:
        raise ValueError("service_account_json is not valid JSON. Paste the entire key file contents.") from exc
    if not isinstance(info, dict):
        raise ValueError("service_account_json must be the key file object, not a list or string.")
    for required in ("client_email", "private_key", "token_uri"):
        if required not in info:
            raise ValueError(f"service_account_json missing required field: {required}")
    return info


class ServiceAccountToken:
    """A cached OAuth access token minted from a service-account key."""

    def __init__(self, sa_info: dict[str, Any], scope: str, *, timeout: float = 15.0):
        self._sa_info = sa_info
        self._scope = scope
        self._timeout = timeout
        self._access_token: str | None = None
        self._expiry: float = 0.0

    @property
    def client_email(self) -> str:
        return str(self._sa_info.get("client_email", ""))

    def build_assertion(self) -> str:
        now = int(time.time())
        header = {"alg": "RS256", "typ": "JWT"}
        claims = {
            "iss": self._sa_info["client_email"],
            "scope": self._scope,
            "aud": self._sa_info.get("token_uri", DEFAULT_TOKEN_URL),
            "iat": now,
            "exp": now + _ASSERTION_LIFETIME_SECONDS,
        }
        signing_input = (
            b64url(json.dumps(header, separators=(",", ":")).encode()) + "." + b64url(json.dumps(claims, separators=(",", ":")).encode())
        ).encode("ascii")
        private_key = serialization.load_pem_private_key(self._sa_info["private_key"].encode("utf-8"), password=None)
        signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())  # type: ignore[union-attr]
        return signing_input.decode("ascii") + "." + b64url(signature)

    async def token(self) -> str:
        if self._access_token and time.time() < self._expiry - _REFRESH_MARGIN_SECONDS:
            return self._access_token
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                self._sa_info.get("token_uri", DEFAULT_TOKEN_URL),
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "assertion": self.build_assertion(),
                },
            )
            resp.raise_for_status()
            payload = resp.json()
        self._access_token = str(payload["access_token"])
        self._expiry = time.time() + int(payload.get("expires_in", _ASSERTION_LIFETIME_SECONDS))
        return self._access_token

    def invalidate(self) -> None:
        """Drop the cached token so the next call re-mints.

        Called on a 401: a token can be revoked, and a connector that keeps
        presenting the revoked one reports an auth failure every poll until
        someone restarts the service.
        """
        self._access_token = None
        self._expiry = 0.0

    def headers(self, token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
