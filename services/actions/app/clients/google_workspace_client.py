"""
Google Workspace (Admin SDK Directory + Identity) client.

Wraps the Admin SDK Directory API and Identity Toolkit for the
identity-response actions AiSOC supports:

* ``suspend_user``    — Directory.users.update suspended=True
* ``unsuspend_user``  — Directory.users.update suspended=False
* ``revoke_sessions`` — Directory.users.signOut on Workspace,
                        which invalidates every active OAuth/SAML
                        session and forces a fresh sign-in.
* ``reset_password``  — Directory.users.update password=<temp>
                        with changePasswordAtNextLogin=True. We
                        never persist the temp password in the
                        action response payload.
* ``enforce_2sv``     — Directory.users.update with the legacy
                        ``enforced2Sv`` flag (Workspace's standard
                        verb for "make this user re-enrol MFA on
                        next sign-in").

Authentication
--------------

Google Workspace requires *delegated* service-account auth:
1. Create a service account in GCP IAM.
2. Enable domain-wide delegation in Workspace Admin.
3. Grant the scopes ``admin.directory.user``,
   ``admin.directory.user.security``.

The runtime credential is a JSON key file we sign a JWT with, then
trade for a bearer token. The signed JWT carries ``sub`` = the
super-admin email to impersonate (because the Admin SDK refuses
to act on behalf of a service account; it must impersonate a real
admin).

Credentials expected in :class:`ActionRequest.parameters`:

* ``gws_service_account_key``  — JSON key content as a string.
* ``gws_subject_email``        — admin email to impersonate.

The class uses ``google-auth`` + ``httpx`` rather than the
Google API Python client because the latter is sync-only and would
need a thread pool.
"""

from __future__ import annotations

import json
import secrets
import string
import time
from typing import Any

import httpx
import structlog

logger = structlog.get_logger()

_TOKEN_URI = "https://oauth2.googleapis.com/token"
_DIRECTORY = "https://admin.googleapis.com/admin/directory/v1"
_SCOPES = " ".join(
    [
        "https://www.googleapis.com/auth/admin.directory.user",
        "https://www.googleapis.com/auth/admin.directory.user.security",
    ]
)


def _gen_temp_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%&*"
    while True:
        candidate = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in candidate)
            and any(c.isupper() for c in candidate)
            and any(c.isdigit() for c in candidate)
            and any(c in "!@#$%&*" for c in candidate)
        ):
            return candidate


class GoogleWorkspaceClient:
    """Async client over Admin SDK Directory + Identity Toolkit."""

    def __init__(self, service_account_key: str | dict, subject_email: str) -> None:
        if isinstance(service_account_key, str):
            try:
                service_account_key = json.loads(service_account_key)
            except json.JSONDecodeError as exc:
                raise ValueError(f"gws_service_account_key is not valid JSON: {exc}") from exc
        self._key = service_account_key
        self._subject = subject_email
        self._token: str | None = None
        self._token_expiry: float = 0.0

    async def _mint_token(self, client: httpx.AsyncClient) -> str:
        """Sign a JWT and exchange for an access token.

        We do the signing inline to avoid pulling in `google-auth`
        for one operation — the JWT shape is fixed and the underlying
        crypto is a single RSA-SHA256 sign over a stable claim set.
        """
        # Imports are local because we don't want to pay the
        # cryptography import cost on every client construction; the
        # JWT path only runs once per token.
        import base64

        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding

        now = int(time.time())
        header = {"alg": "RS256", "typ": "JWT"}
        claims = {
            "iss": self._key["client_email"],
            "sub": self._subject,
            "scope": _SCOPES,
            "aud": _TOKEN_URI,
            "iat": now,
            "exp": now + 3600,
        }

        def _b64(blob: dict) -> str:
            return base64.urlsafe_b64encode(json.dumps(blob, separators=(",", ":")).encode()).rstrip(b"=").decode()

        signing_input = f"{_b64(header)}.{_b64(claims)}".encode()
        private_key = serialization.load_pem_private_key(self._key["private_key"].encode(), password=None)
        signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        encoded_sig = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
        jwt_str = f"{signing_input.decode()}.{encoded_sig}"

        resp = await client.post(
            _TOKEN_URI,
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": jwt_str,
            },
        )
        resp.raise_for_status()
        body = resp.json()
        self._token = body["access_token"]
        self._token_expiry = time.time() + int(body.get("expires_in", 3600)) - 60  # 1m safety margin
        return self._token

    async def _ensure_token(self, client: httpx.AsyncClient) -> None:
        if not self._token or time.time() >= self._token_expiry:
            await self._mint_token(client)

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"}

    async def suspend_user(self, user_email: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=20.0) as client:
            await self._ensure_token(client)
            resp = await client.patch(
                f"{_DIRECTORY}/users/{user_email}",
                headers=self._headers(),
                json={"suspended": True},
            )
            resp.raise_for_status()
            logger.info("gws.suspend_user.success", user=user_email)
            return {"success": True, "action": "suspend_user", "user": user_email}

    async def unsuspend_user(self, user_email: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=20.0) as client:
            await self._ensure_token(client)
            resp = await client.patch(
                f"{_DIRECTORY}/users/{user_email}",
                headers=self._headers(),
                json={"suspended": False},
            )
            resp.raise_for_status()
            logger.info("gws.unsuspend_user.success", user=user_email)
            return {"success": True, "action": "unsuspend_user", "user": user_email}

    async def revoke_sessions(self, user_email: str) -> dict[str, Any]:
        """Sign the user out of every Workspace session.

        Workspace's signOut verb terminates OAuth grants too; the
        user has to re-authenticate at the IdP. Equivalent to
        Entra's ``revokeSignInSessions`` plus the OAuth-grant
        reset.
        """
        async with httpx.AsyncClient(timeout=20.0) as client:
            await self._ensure_token(client)
            resp = await client.post(
                f"{_DIRECTORY}/users/{user_email}/signOut",
                headers=self._headers(),
            )
            resp.raise_for_status()
            logger.info("gws.revoke_sessions.success", user=user_email)
            return {"success": True, "action": "revoke_sessions", "user": user_email}

    async def reset_password(self, user_email: str) -> dict[str, Any]:
        temp_password = _gen_temp_password()
        async with httpx.AsyncClient(timeout=20.0) as client:
            await self._ensure_token(client)
            resp = await client.patch(
                f"{_DIRECTORY}/users/{user_email}",
                headers=self._headers(),
                json={
                    "password": temp_password,
                    "changePasswordAtNextLogin": True,
                },
            )
            resp.raise_for_status()
            logger.info("gws.reset_password.success", user=user_email)
            return {
                "success": True,
                "action": "reset_password",
                "user": user_email,
                # Same reasoning as the Entra client — we never
                # surface the temp password into the action
                # timeline.
            }

    async def enforce_2sv(self, user_email: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=20.0) as client:
            await self._ensure_token(client)
            resp = await client.patch(
                f"{_DIRECTORY}/users/{user_email}",
                headers=self._headers(),
                json={"enforced2Sv": True},
            )
            resp.raise_for_status()
            logger.info("gws.enforce_2sv.success", user=user_email)
            return {"success": True, "action": "enforce_2sv", "user": user_email}
