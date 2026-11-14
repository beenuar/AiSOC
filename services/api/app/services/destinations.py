"""Notification / SOAR handoff destinations (Wave 6, W6.3).

Fan an alert out to Opsgenie, email, or a generic external-SOAR webhook. The
payload builders are pure + deterministic (unit-tested); ``dispatch`` performs
the side-effecting send with a scheme/host guard on outbound webhooks.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

_OPSGENIE_PRIORITY = {"info": "P5", "low": "P4", "medium": "P3", "high": "P2", "critical": "P1"}


class DestinationError(Exception):
    """A destination is misconfigured or its target is disallowed."""


@dataclass
class DispatchResult:
    kind: str
    ok: bool
    detail: str
    payload: dict[str, Any]


def build_opsgenie_payload(alert: dict[str, Any]) -> dict[str, Any]:
    sev = str(alert.get("severity", "medium")).lower()
    return {
        "message": alert.get("title", "AiSOC alert"),
        "alias": f"aisoc-{alert.get('id', '')}",
        "description": alert.get("description", ""),
        "priority": _OPSGENIE_PRIORITY.get(sev, "P3"),
        "source": "AiSOC",
        "tags": ["aisoc", sev, str(alert.get("source", "unknown"))],
        "details": {"alert_id": str(alert.get("id", "")), "severity": sev},
    }


def build_email_payload(alert: dict[str, Any], recipients: list[str]) -> dict[str, Any]:
    sev = str(alert.get("severity", "medium")).upper()
    title = alert.get("title", "AiSOC alert")
    return {
        "to": list(recipients),
        "subject": f"[AiSOC][{sev}] {title}",
        "body": (
            f"Severity: {sev}\n"
            f"Source: {alert.get('source', 'unknown')}\n"
            f"Alert ID: {alert.get('id', '')}\n\n"
            f"{alert.get('description', '')}\n"
        ),
    }


def build_soar_handoff_payload(alert: dict[str, Any]) -> dict[str, Any]:
    """Normalised handoff envelope for an external SOAR (Tines/Torq/XSOAR/…)."""
    return {
        "schema": "aisoc.handoff.v1",
        "alert": {
            "id": str(alert.get("id", "")),
            "title": alert.get("title", ""),
            "severity": str(alert.get("severity", "medium")).lower(),
            "source": alert.get("source", "unknown"),
            "description": alert.get("description", ""),
            "entities": alert.get("entities", []),
            "recommended_actions": alert.get("recommended_actions", []),
        },
    }


def _guard_url(url: str) -> None:
    """Block non-http(s) schemes and resolution to private/loopback/link-local
    ranges (SSRF). Applied to every outbound webhook target."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise DestinationError(f"disallowed scheme: {parsed.scheme or '(none)'}")
    host = parsed.hostname
    if not host:
        raise DestinationError("missing host")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise DestinationError(f"cannot resolve host: {host}") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise DestinationError(f"target resolves to a disallowed address: {ip}")


async def dispatch(kind: str, config: dict[str, Any], alert: dict[str, Any]) -> DispatchResult:
    """Send an alert to a destination. Email returns the formatted payload
    (SMTP delivery is a deployment-specific wrapper); Opsgenie + webhook POST."""
    if kind == "email":
        payload = build_email_payload(alert, config.get("recipients", []))
        if not payload["to"]:
            raise DestinationError("email destination has no recipients")
        return DispatchResult("email", True, "formatted", payload)

    if kind == "opsgenie":
        payload = build_opsgenie_payload(alert)
        url = config.get("url", "https://api.opsgenie.com/v2/alerts")
        headers = {"Authorization": f"GenieKey {config.get('api_key', '')}"}
    elif kind == "webhook":
        payload = build_soar_handoff_payload(alert)
        url = config.get("url", "")
        headers = config.get("headers", {})
        if not url:
            raise DestinationError("webhook destination has no url")
    else:
        raise DestinationError(f"unknown destination kind: {kind}")

    _guard_url(url)
    import httpx  # noqa: PLC0415 — optional/lazy so unit tests can monkeypatch

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(url, json=payload, headers=headers)
    ok = 200 <= resp.status_code < 300
    return DispatchResult(kind, ok, f"http {resp.status_code}", payload)
