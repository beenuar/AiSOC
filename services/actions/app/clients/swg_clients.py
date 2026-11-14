"""Secure web gateway clients: Zscaler Internet Access and Netskope.

Depth 5.5's last named gap is "connected secure web gateways: block a URL
or domain". The tree could block an IP at a firewall and sinkhole a domain
at Cloudflare Gateway, and had no gateway arm for a *URL* at all — so a
phishing page on a shared host could only be contained by blocking the
whole host, which takes everything else on it down with it.

References, each fetched before this module was written:

* Zscaler URL categories — https://help.zscaler.com/zia/url-categories
* Zscaler API developer reference — https://help.zscaler.com/zia/api-developer-reference-guide
* Netskope REST API v2 — https://docs.netskope.com/en/netskope-help/data-security/netskope-api/rest-api-v2-overview/

Both vendors share one shape and one trap
-----------------------------------------
Neither offers "block this URL". Both offer a *list* that a policy the
customer already owns points at, and the action is adding to or removing
from that list. That is deliberate on their side and right on ours: AiSOC
feeds an existing policy rather than authoring enforcement, so the blast
radius is whatever the customer's own rule already does.

The trap is that both list edits are read-modify-write on a shared object.
Two concurrent containments that each read, append and write will lose one
of the two entries, and the losing action still reports success. Both
clients here send the vendor's *incremental* form — Zscaler's
``?action=ADD_TO_LIST`` and Netskope's patch endpoint — rather than
replacing the list, so a concurrent edit cannot be silently dropped.
"""

from __future__ import annotations

import re
from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)

#: A hostname, optionally with a path. Both vendors take this shape and
#: neither takes a scheme, so a caller passing `https://...` would get a
#: list entry that never matches. Stripped rather than refused because the
#: scheme is noise an analyst reasonably pastes.
_SCHEME = re.compile(r"\Ahttps?://", re.IGNORECASE)


def normalise_target(value: str) -> str:
    """Strip the scheme and any trailing slash from a URL or domain."""
    cleaned = _SCHEME.sub("", (value or "").strip()).rstrip("/")
    if not cleaned:
        raise ValueError("a URL or domain is required")
    return cleaned


class SWGAPIError(RuntimeError):
    """The gateway answered and declined."""


class ZscalerClient:
    """Async client over the Zscaler Internet Access admin API.

    Authentication is the session cookie ZIA mints from an obfuscated
    API key; deployments that already run the Zscaler connector hold that
    session value, so this client takes it rather than re-implementing the
    obfuscation, which is undocumented and version-dependent.
    """

    def __init__(self, base_url: str, session_cookie: str, *, timeout: float = 30.0) -> None:
        self._base = base_url.rstrip("/")
        self._cookie = session_cookie
        self._timeout = timeout

    async def _request(self, method: str, path: str, *, json_body: Any = None, params: dict | None = None) -> Any:
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            response = await client.request(
                method,
                f"{self._base}{path}",
                headers={"Content-Type": "application/json", "Cookie": self._cookie},
                json=json_body,
                params=params,
            )
        if response.status_code >= 400:
            raise SWGAPIError(f"Zscaler {method} {path} failed with HTTP {response.status_code}: {response.text[:300]}")
        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError:
            return {"raw": response.text}

    async def _edit_category(self, category_id: str, values: list[str], *, add: bool) -> dict[str, Any]:
        action = "ADD_TO_LIST" if add else "REMOVE_FROM_LIST"
        body = await self._request(
            "PUT",
            f"/api/v1/urlCategories/{category_id}",
            params={"action": action},
            json_body={"configuredName": category_id, "urls": values},
        )
        logger.info("zscaler.category.edited", category_id=category_id, action=action, count=len(values))
        return {"category_id": category_id, "action": action, "values": values, "result": body}

    async def block_url(self, url: str, *, category_id: str) -> dict[str, Any]:
        return await self._edit_category(category_id, [normalise_target(url)], add=True)

    async def allow_url(self, url: str, *, category_id: str) -> dict[str, Any]:
        return await self._edit_category(category_id, [normalise_target(url)], add=False)

    async def block_domain(self, domain: str, *, category_id: str) -> dict[str, Any]:
        return await self._edit_category(category_id, [normalise_target(domain)], add=True)

    async def allow_domain(self, domain: str, *, category_id: str) -> dict[str, Any]:
        return await self._edit_category(category_id, [normalise_target(domain)], add=False)

    async def get_category(self, category_id: str) -> dict[str, Any]:
        """Read the category back. The probe for every arm above."""
        body = await self._request("GET", f"/api/v1/urlCategories/{category_id}")
        return {
            "id": body.get("id"),
            "configured_name": body.get("configuredName"),
            "urls": body.get("urls") or [],
            "db_categorized_urls": body.get("dbCategorizedUrls") or [],
        }


class NetskopeClient:
    """Async client over the Netskope REST API v2 URL-list endpoints."""

    def __init__(self, base_url: str, api_token: str, *, timeout: float = 30.0) -> None:
        self._base = base_url.rstrip("/")
        self._token = api_token
        self._timeout = timeout

    async def _request(self, method: str, path: str, *, json_body: Any = None, params: dict | None = None) -> Any:
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            response = await client.request(
                method,
                f"{self._base}{path}",
                headers={"Netskope-Api-Token": self._token, "Content-Type": "application/json", "Accept": "application/json"},
                json=json_body,
                params=params,
            )
        if response.status_code >= 400:
            raise SWGAPIError(f"Netskope {method} {path} failed with HTTP {response.status_code}: {response.text[:300]}")
        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError:
            return {"raw": response.text}

    async def _patch_list(self, list_id: str, values: list[str], *, add: bool) -> dict[str, Any]:
        action = "append" if add else "remove"
        body = await self._request(
            "PATCH",
            f"/api/v2/policy/urllist/{list_id}/{action}",
            json_body={"data": {"urls": values}},
        )
        logger.info("netskope.urllist.patched", list_id=list_id, action=action, count=len(values))
        return {"list_id": list_id, "action": action, "values": values, "result": body}

    async def block_url(self, url: str, *, list_id: str) -> dict[str, Any]:
        return await self._patch_list(list_id, [normalise_target(url)], add=True)

    async def allow_url(self, url: str, *, list_id: str) -> dict[str, Any]:
        return await self._patch_list(list_id, [normalise_target(url)], add=False)

    async def block_domain(self, domain: str, *, list_id: str) -> dict[str, Any]:
        return await self._patch_list(list_id, [normalise_target(domain)], add=True)

    async def allow_domain(self, domain: str, *, list_id: str) -> dict[str, Any]:
        return await self._patch_list(list_id, [normalise_target(domain)], add=False)

    async def get_list(self, list_id: str) -> dict[str, Any]:
        """Read the list back. The probe for every arm above.

        Netskope keeps a pending and an applied copy of a list; this
        reports both rather than only the pending one, because a list that
        has been edited and not applied is not yet blocking anything and an
        operator who reads "blocked" needs to know which it is.
        """
        body = await self._request("GET", f"/api/v2/policy/urllist/{list_id}")
        data = body.get("data") or body
        return {
            "id": data.get("id") or list_id,
            "name": data.get("name"),
            "urls": (data.get("data") or {}).get("urls") or data.get("urls") or [],
            "pending": data.get("pending"),
        }
