"""
MISP push service.

Stage 3 #20 (AiSOC v1.0 buyer-value plan).

This module mirrors STIX 2.1 indicators and bundles created via
``/threatintel/stix/...`` into a downstream MISP instance. It is split
into two layers so the mappers can be unit-tested without touching the
network:

* **Pure mappers** (``parse_stix_pattern``, ``stix_indicator_to_misp_attribute``,
  ``stix_bundle_to_misp_event``, ``confidence_to_threat_level``) — no I/O.
* **``MispPushClient``** — thin async wrapper around the MISP REST API
  that calls ``enforce_airgap_for_url`` before every outbound request,
  matching the convention used in
  ``services/api/app/api/v1/endpoints/translation.py``.

The client deliberately does NOT live inside ``services/threatintel`` —
that microservice's ``MispClient`` is read-only (pulls events). The
push path runs from the API service so it shares the same air-gap
chokepoint, the same credential vault loader pattern, and the same
HTTP timeout budget.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

import httpx

from app.core.airgap import enforce_airgap_for_url
from app.core.config import settings

logger = logging.getLogger("aisoc.misp_push")

# ── STIX → MISP type mapping ────────────────────────────────────────────────

# Maps the STIX 2.1 observable type prefix used in indicator patterns to the
# MISP attribute ``type`` + ``category``. Order matters for hash variants —
# we check the longest pattern first.
_STIX_TO_MISP: tuple[tuple[re.Pattern[str], str, str], ...] = (
    # File hashes — STIX uses ``[file:hashes.'SHA-256' = '...']`` etc.
    (
        re.compile(r"\[file:hashes\.['\"]?MD5['\"]?\s*=\s*['\"]([^'\"]+)['\"]\]", re.IGNORECASE),
        "md5",
        "Payload delivery",
    ),
    (
        re.compile(r"\[file:hashes\.['\"]?SHA-?1['\"]?\s*=\s*['\"]([^'\"]+)['\"]\]", re.IGNORECASE),
        "sha1",
        "Payload delivery",
    ),
    (
        re.compile(r"\[file:hashes\.['\"]?SHA-?256['\"]?\s*=\s*['\"]([^'\"]+)['\"]\]", re.IGNORECASE),
        "sha256",
        "Payload delivery",
    ),
    (
        re.compile(r"\[file:hashes\.['\"]?SHA-?512['\"]?\s*=\s*['\"]([^'\"]+)['\"]\]", re.IGNORECASE),
        "sha512",
        "Payload delivery",
    ),
    # Network indicators
    (
        re.compile(r"\[ipv4-addr:value\s*=\s*['\"]([^'\"]+)['\"]\]", re.IGNORECASE),
        "ip-dst",
        "Network activity",
    ),
    (
        re.compile(r"\[ipv6-addr:value\s*=\s*['\"]([^'\"]+)['\"]\]", re.IGNORECASE),
        "ip-dst",
        "Network activity",
    ),
    (
        re.compile(r"\[domain-name:value\s*=\s*['\"]([^'\"]+)['\"]\]", re.IGNORECASE),
        "domain",
        "Network activity",
    ),
    (
        re.compile(r"\[url:value\s*=\s*['\"]([^'\"]+)['\"]\]", re.IGNORECASE),
        "url",
        "Network activity",
    ),
    # Email
    (
        re.compile(r"\[email-addr:value\s*=\s*['\"]([^'\"]+)['\"]\]", re.IGNORECASE),
        "email-src",
        "Payload delivery",
    ),
    # File name
    (
        re.compile(r"\[file:name\s*=\s*['\"]([^'\"]+)['\"]\]", re.IGNORECASE),
        "filename",
        "Payload delivery",
    ),
)


@dataclass(frozen=True)
class ParsedPattern:
    """A STIX pattern parsed into a MISP-compatible attribute."""

    misp_type: str
    misp_category: str
    value: str


def parse_stix_pattern(pattern: str) -> ParsedPattern | None:
    """Parse a STIX 2.1 pattern into a MISP attribute.

    Returns ``None`` for patterns we don't yet know how to translate;
    callers should treat that as "skip but don't fail" so a bundle
    containing one unknown observable still gets pushed for the
    observables we do understand.
    """
    if not pattern:
        return None
    for regex, misp_type, misp_category in _STIX_TO_MISP:
        match = regex.search(pattern)
        if match:
            return ParsedPattern(misp_type=misp_type, misp_category=misp_category, value=match.group(1))
    return None


def confidence_to_threat_level(confidence: int | None) -> int:
    """Map STIX confidence (0-100) to a MISP ``threat_level_id`` (1-4).

    MISP scale: 1=high, 2=medium, 3=low, 4=undefined.
    """
    if confidence is None:
        return settings.MISP_PUSH_DEFAULT_THREAT_LEVEL
    if confidence >= 80:
        return 1  # high
    if confidence >= 50:
        return 2  # medium
    if confidence >= 20:
        return 3  # low
    return 4  # undefined


def stix_indicator_to_misp_attribute(
    indicator: dict[str, Any],
    *,
    distribution: int | None = None,
) -> dict[str, Any] | None:
    """Convert a STIX 2.1 indicator dict to a single MISP attribute dict.

    Returns ``None`` when the pattern isn't translatable. The caller
    can choose to surface that as a 422 (single push) or skip-and-log
    (bundle push).
    """
    parsed = parse_stix_pattern(indicator.get("pattern", ""))
    if parsed is None:
        return None
    distribution_level = distribution if distribution is not None else settings.MISP_PUSH_DEFAULT_DISTRIBUTION
    attribute: dict[str, Any] = {
        "type": parsed.misp_type,
        "category": parsed.misp_category,
        "value": parsed.value,
        "to_ids": True,
        "distribution": distribution_level,
        "comment": indicator.get("description") or indicator.get("name") or "",
    }
    # MISP supports tagging on attributes — surface STIX labels so an
    # operator filtering MISP for ``aisoc:apt-42`` finds it.
    labels = indicator.get("labels") or []
    if labels:
        attribute["Tag"] = [{"name": f"aisoc:{label}"} for label in labels]
    return attribute


def stix_bundle_to_misp_event(
    bundle: dict[str, Any],
    *,
    info: str | None = None,
    distribution: int | None = None,
    threat_level: int | None = None,
    analysis: int | None = None,
) -> dict[str, Any]:
    """Convert a STIX 2.1 bundle dict to a MISP event payload.

    The bundle's ``objects`` list is filtered to STIX indicators; each
    one is mapped via :func:`stix_indicator_to_misp_attribute`. Unknown
    patterns are silently skipped (and counted in the returned
    ``_skipped`` field for the dry-run endpoint to surface).
    """
    distribution_level = distribution if distribution is not None else settings.MISP_PUSH_DEFAULT_DISTRIBUTION
    threat_level_id = threat_level if threat_level is not None else settings.MISP_PUSH_DEFAULT_THREAT_LEVEL
    analysis_id = analysis if analysis is not None else settings.MISP_PUSH_DEFAULT_ANALYSIS

    attributes: list[dict[str, Any]] = []
    skipped = 0
    indicator_names: list[str] = []
    for obj in bundle.get("objects", []) or []:
        if not isinstance(obj, dict) or obj.get("type") != "indicator":
            continue
        attr = stix_indicator_to_misp_attribute(obj, distribution=distribution_level)
        if attr is None:
            skipped += 1
            continue
        attributes.append(attr)
        if obj.get("name"):
            indicator_names.append(str(obj["name"]))

    event_info = (
        info or ("AiSOC bundle " + bundle.get("id", "") + (" — " + "; ".join(indicator_names[:3]) if indicator_names else "")).strip()
    )

    return {
        "Event": {
            "info": event_info,
            "distribution": distribution_level,
            "threat_level_id": threat_level_id,
            "analysis": analysis_id,
            "Attribute": attributes,
            "Tag": [{"name": "aisoc:source=stix"}, {"name": f"aisoc:bundle={bundle.get('id', '')}"}],
        },
        # Non-MISP bookkeeping fields, stripped before POST. Used by the
        # dry-run endpoint to surface visibility.
        "_skipped": skipped,
        "_attribute_count": len(attributes),
    }


def stix_indicator_to_misp_event(
    indicator: dict[str, Any],
    *,
    distribution: int | None = None,
    threat_level: int | None = None,
    analysis: int | None = None,
) -> dict[str, Any] | None:
    """Wrap a single STIX indicator as a one-attribute MISP event."""
    distribution_level = distribution if distribution is not None else settings.MISP_PUSH_DEFAULT_DISTRIBUTION
    threat_level_id = threat_level if threat_level is not None else confidence_to_threat_level(indicator.get("confidence"))
    analysis_id = analysis if analysis is not None else settings.MISP_PUSH_DEFAULT_ANALYSIS

    attr = stix_indicator_to_misp_attribute(indicator, distribution=distribution_level)
    if attr is None:
        return None
    return {
        "Event": {
            "info": indicator.get("name") or f"AiSOC indicator {indicator.get('id', '')}",
            "distribution": distribution_level,
            "threat_level_id": threat_level_id,
            "analysis": analysis_id,
            "Attribute": [attr],
            "Tag": [
                {"name": "aisoc:source=stix"},
                {"name": f"aisoc:indicator={indicator.get('id', '')}"},
            ],
        }
    }


# ── Async push client ───────────────────────────────────────────────────────


class MispPushError(RuntimeError):
    """Raised when the MISP push fails for any reason except air-gap."""


class MispNotConfigured(RuntimeError):
    """Raised when MISP_URL or MISP_API_KEY are not set."""


def _strip_internal_fields(event: dict[str, Any]) -> dict[str, Any]:
    """Remove ``_skipped`` / ``_attribute_count`` bookkeeping before POST."""
    return {k: v for k, v in event.items() if not k.startswith("_")}


class MispPushClient:
    """Async client for pushing STIX → MISP events.

    Always honors :func:`enforce_airgap_for_url` so an air-gapped
    deployment refuses to leak indicators to a public MISP instance.
    """

    def __init__(
        self,
        url: str | None = None,
        api_key: str | None = None,
        verify_ssl: bool | None = None,
        timeout: float | None = None,
    ) -> None:
        self._url = (url or settings.MISP_URL or "").rstrip("/")
        self._api_key = api_key or settings.MISP_API_KEY
        self._verify_ssl = settings.MISP_VERIFY_SSL if verify_ssl is None else verify_ssl
        self._timeout = settings.MISP_PUSH_TIMEOUT_SECONDS if timeout is None else timeout

    @property
    def configured(self) -> bool:
        return bool(self._url and self._api_key)

    def _require_config(self) -> None:
        if not self.configured:
            raise MispNotConfigured("MISP push is not configured. Set MISP_URL and MISP_API_KEY.")

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": self._api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    async def health_check(self) -> dict[str, Any]:
        """Hit ``/users/view/me`` to verify reachability + auth."""
        self._require_config()
        target = f"{self._url}/users/view/me"
        enforce_airgap_for_url(target)
        async with httpx.AsyncClient(verify=self._verify_ssl, timeout=self._timeout, headers=self._headers()) as client:
            try:
                resp = await client.get(target)
            except httpx.RequestError as exc:
                raise MispPushError(f"MISP unreachable: {exc}") from exc
            if resp.status_code == 401:
                raise MispPushError("MISP auth failed (401). Check MISP_API_KEY.")
            if resp.status_code >= 400:
                raise MispPushError(f"MISP health check returned {resp.status_code}")
            try:
                body = resp.json()
            except Exception:
                body = {}
            return {
                "ok": True,
                "url": self._url,
                "user": (body.get("User") or {}).get("email", ""),
                "role": (body.get("Role") or {}).get("name", ""),
            }

    async def push_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """POST a MISP event payload to ``/events/add`` and return the response."""
        self._require_config()
        target = f"{self._url}/events/add"
        enforce_airgap_for_url(target)
        clean_event = _strip_internal_fields(event)
        async with httpx.AsyncClient(verify=self._verify_ssl, timeout=self._timeout, headers=self._headers()) as client:
            try:
                resp = await client.post(target, json=clean_event)
            except httpx.RequestError as exc:
                raise MispPushError(f"MISP push failed: {exc}") from exc
            if resp.status_code == 401:
                raise MispPushError("MISP auth failed (401). Check MISP_API_KEY.")
            if resp.status_code >= 400:
                raise MispPushError(f"MISP push returned {resp.status_code}: {resp.text[:300]}")
            try:
                body = resp.json()
            except Exception as exc:
                raise MispPushError(f"MISP returned non-JSON: {exc}") from exc
            event_id = (body.get("Event") or {}).get("id") or body.get("id") or ""
            uuid_ = (body.get("Event") or {}).get("uuid") or body.get("uuid") or ""
            return {
                "ok": True,
                "misp_event_id": event_id,
                "misp_event_uuid": uuid_,
                "url": f"{self._url}/events/view/{event_id}" if event_id else self._url,
                "raw": body,
            }

    async def push_indicator(
        self,
        indicator: dict[str, Any],
        *,
        distribution: int | None = None,
        threat_level: int | None = None,
        analysis: int | None = None,
    ) -> dict[str, Any]:
        event = stix_indicator_to_misp_event(
            indicator,
            distribution=distribution,
            threat_level=threat_level,
            analysis=analysis,
        )
        if event is None:
            raise MispPushError(f"Indicator pattern {indicator.get('pattern', '')!r} cannot be mapped to a MISP attribute.")
        return await self.push_event(event)

    async def push_bundle(
        self,
        bundle: dict[str, Any],
        *,
        info: str | None = None,
        distribution: int | None = None,
        threat_level: int | None = None,
        analysis: int | None = None,
    ) -> dict[str, Any]:
        event = stix_bundle_to_misp_event(
            bundle,
            info=info,
            distribution=distribution,
            threat_level=threat_level,
            analysis=analysis,
        )
        skipped = event.pop("_skipped", 0)
        attribute_count = event.pop("_attribute_count", 0)
        if attribute_count == 0:
            logger.warning(
                "misp_push.bundle_empty bundle_id=%s skipped=%d",
                bundle.get("id", ""),
                skipped,
            )
            raise MispPushError(f"Bundle {bundle.get('id', '')!r} contained no MISP-translatable indicators.")
        if skipped:
            logger.info(
                "misp_push.bundle_partial bundle_id=%s pushed=%d skipped=%d",
                bundle.get("id", ""),
                attribute_count,
                skipped,
            )
        result = await self.push_event(event)
        result["pushed_attributes"] = attribute_count
        result["skipped_attributes"] = skipped
        return result


def get_push_client() -> MispPushClient:
    """Factory — kept tiny so endpoints can patch it in tests."""
    return MispPushClient()


__all__ = [
    "MispNotConfigured",
    "MispPushClient",
    "MispPushError",
    "ParsedPattern",
    "confidence_to_threat_level",
    "get_push_client",
    "parse_stix_pattern",
    "stix_bundle_to_misp_event",
    "stix_indicator_to_misp_attribute",
    "stix_indicator_to_misp_event",
]
