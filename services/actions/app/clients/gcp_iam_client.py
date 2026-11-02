"""GCP IAM client for service-identity containment.

Depth 5.5 names "GCP and Azure: disable a service account or its key". The
tree reaches GCP for Workspace administration only; nothing could touch a
project's service identities, which is where a compromised CI credential or
a leaked key actually lives.

API references, each fetched before this module was written:

* ``serviceAccounts.disable`` — https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts/disable
* ``serviceAccounts.keys.disable`` — https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts.keys/disable

Two containment levels, deliberately separate
---------------------------------------------
Disabling the *account* stops everything it can do and is the blunt answer.
Disabling one *key* stops the credential that leaked and leaves the workload
running on its other keys, which is usually what an operator wants at 3am
and is a different blast radius. Collapsing them into one verb would force
the wider action every time, so they are two verbs with two contracts.

Both are reversible by the matching ``:enable`` call, and both are checkable
by reading the resource back — ``disabled`` is a field on the service account
and on the key. That is why neither carries a verification gap.

Token revocation
----------------
GCP issues short-lived access tokens derived from a key; there is no
"revoke this access token" API. Disabling the key that minted it is the
documented containment, which is what ``revoke_token`` does here, and the
contract says so rather than implying a token-level revocation exists.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)

_TOKEN_URI = "https://oauth2.googleapis.com/token"
_IAM_BASE = "https://iam.googleapis.com/v1"
#: The IAM API needs the broad platform scope; there is no narrower
#: published scope that covers serviceAccounts.disable.
_SCOPE = "https://www.googleapis.com/auth/cloud-platform"


class GCPAPIError(RuntimeError):
    """Google answered and declined. Distinct from "could not reach Google"."""


class GCPIAMClient:
    """Async client over the IAM v1 REST API, authenticated by a key JWT."""

    def __init__(self, service_account_key: str | dict, *, timeout: float = 30.0, base_url: str | None = None) -> None:
        if isinstance(service_account_key, str):
            try:
                service_account_key = json.loads(service_account_key)
            except json.JSONDecodeError as exc:
                raise ValueError(f"gcp_service_account_key is not valid JSON: {exc}") from exc
        # Same reasoning as GoogleWorkspaceClient: a document that is valid
        # JSON but not an object passes construction and fails inside the
        # signing path, during a live containment, with a TypeError about
        # string indices. The configuration is wrong when it is saved.
        if not isinstance(service_account_key, dict):
            raise ValueError(f"gcp_service_account_key must be a JSON object, got {type(service_account_key).__name__}")
        self._key: dict[str, Any] = service_account_key
        self._timeout = timeout
        self._base = (base_url or _IAM_BASE).rstrip("/")
        self._token: str | None = None
        self._token_expiry: float = 0.0

    async def _mint_token(self, client: httpx.AsyncClient) -> str:
        from cryptography.hazmat.primitives import hashes, serialization  # noqa: PLC0415 - deferred: only the token path pays the import
        from cryptography.hazmat.primitives.asymmetric import padding  # noqa: PLC0415

        now = int(time.time())
        header = {"alg": "RS256", "typ": "JWT"}
        claims = {
            "iss": self._key["client_email"],
            "scope": _SCOPE,
            "aud": _TOKEN_URI,
            "iat": now,
            "exp": now + 3600,
        }

        def _b64(blob: dict) -> str:
            return base64.urlsafe_b64encode(json.dumps(blob, separators=(",", ":")).encode()).rstrip(b"=").decode()

        signing_input = f"{_b64(header)}.{_b64(claims)}".encode()
        private_key = serialization.load_pem_private_key(self._key["private_key"].encode(), password=None)
        signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        assertion = f"{signing_input.decode()}.{base64.urlsafe_b64encode(signature).rstrip(b'=').decode()}"

        response = await client.post(
            _TOKEN_URI,
            data={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": assertion},
        )
        response.raise_for_status()
        body = response.json()
        self._token = body["access_token"]
        self._token_expiry = time.time() + int(body.get("expires_in", 3600)) - 60
        return self._token

    async def _request(self, method: str, path: str, *, json_body: dict | None = None) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            if not self._token or time.time() >= self._token_expiry:
                await self._mint_token(client)
            response = await client.request(
                method,
                f"{self._base}{path}",
                headers={"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"},
                json=json_body if json_body is not None else ({} if method == "POST" else None),
            )
        if response.status_code >= 400:
            raise GCPAPIError(f"GCP IAM {method} {path} failed with HTTP {response.status_code}: {_message(response)}")
        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError:
            return {"raw": response.text}

    # ------------------------------------------------------------------
    # Service accounts
    # ------------------------------------------------------------------

    @staticmethod
    def _account_path(service_account: str, project_id: str | None = None) -> str:
        """Accept either a bare email or a full resource name.

        ``projects/-/serviceAccounts/{email}`` with the literal ``-`` is the
        documented wildcard: the API resolves the project from the account
        itself, so an operator who has only the email never has to go and
        find the project id first.
        """
        if service_account.startswith("projects/"):
            return f"/{service_account}"
        return f"/projects/{project_id or '-'}/serviceAccounts/{service_account}"

    async def disable_service_account(self, service_account: str, *, project_id: str | None = None) -> dict[str, Any]:
        path = f"{self._account_path(service_account, project_id)}:disable"
        await self._request("POST", path)
        return {"service_account": service_account, "disabled": True}

    async def enable_service_account(self, service_account: str, *, project_id: str | None = None) -> dict[str, Any]:
        path = f"{self._account_path(service_account, project_id)}:enable"
        await self._request("POST", path)
        return {"service_account": service_account, "disabled": False}

    async def get_service_account(self, service_account: str, *, project_id: str | None = None) -> dict[str, Any]:
        """The read behind the probe. ``disabled`` is absent when false."""
        body = await self._request("GET", self._account_path(service_account, project_id))
        return {
            "service_account": service_account,
            "email": body.get("email"),
            "unique_id": body.get("uniqueId"),
            "disabled": bool(body.get("disabled", False)),
        }

    # ------------------------------------------------------------------
    # Service account keys
    # ------------------------------------------------------------------

    @staticmethod
    def _key_path(key_name: str, service_account: str | None, project_id: str | None) -> str:
        if key_name.startswith("projects/"):
            return f"/{key_name}"
        if not service_account:
            raise ValueError("a bare key id needs the service account it belongs to; pass service_account= or a full resource name")
        return f"/projects/{project_id or '-'}/serviceAccounts/{service_account}/keys/{key_name}"

    async def disable_service_account_key(
        self,
        key_name: str,
        *,
        service_account: str | None = None,
        project_id: str | None = None,
    ) -> dict[str, Any]:
        await self._request("POST", f"{self._key_path(key_name, service_account, project_id)}:disable")
        return {"key": key_name, "service_account": service_account, "disabled": True}

    async def enable_service_account_key(
        self,
        key_name: str,
        *,
        service_account: str | None = None,
        project_id: str | None = None,
    ) -> dict[str, Any]:
        await self._request("POST", f"{self._key_path(key_name, service_account, project_id)}:enable")
        return {"key": key_name, "service_account": service_account, "disabled": False}

    async def list_service_account_keys(self, service_account: str, *, project_id: str | None = None) -> list[dict[str, Any]]:
        body = await self._request("GET", f"{self._account_path(service_account, project_id)}/keys")
        return [
            {
                "name": entry.get("name"),
                "key_type": entry.get("keyType"),
                "disabled": bool(entry.get("disabled", False)),
                "valid_after_time": entry.get("validAfterTime"),
            }
            for entry in body.get("keys", [])
        ]


def _message(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return response.text[:300]
    error = body.get("error")
    if isinstance(error, dict):
        return str(error.get("message") or error)
    return str(error or body)[:300]
