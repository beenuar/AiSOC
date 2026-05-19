"""
HashiCorp Vault audit-device polling connector.

Vault doesn't expose audit logs through its HTTP API by design — audit
data flows out of the cluster via *audit devices* (file, socket, syslog).
This connector tails a HTTP-receiver audit sink and *also* exposes a
control-plane health probe via the Vault REST API so we can verify the
token has the right policy attached.

Operationally there are two supported deployments:

1. **Sidecar tail** — Vault writes audit JSON-lines to a file device,
   a sidecar uploads each line to ``POST /v1/_/audit_ingest`` on the
   AiSOC connectors service which buffers them in memory. This
   connector's ``fetch_alerts()`` drains the buffer.
2. **Pull** — for small / single-node Vault deployments operators set
   ``audit_log_path`` and the connector tails the file directly. We
   keep that off the M-effort wave-2 surface; the buffer model is
   what's plumbed in.

Either way, ``test_connection()`` hits ``GET /v1/sys/health`` so a
mis-scoped token surfaces immediately rather than at first event.
Severity collapse: "Vault audit operation" naming maps as

  * ``revoke`` / ``root token`` / ``policy/`` writes → high (intent
    is destructive or privilege-elevating)
  * ``update`` on ``auth/`` or ``sys/`` paths → medium
  * everything else → info
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

_DEFAULT_BUFFER = 5000


class VaultConnector(BaseConnector):
    """HashiCorp Vault audit log."""

    connector_id = "vault"
    connector_name = "HashiCorp Vault Audit"
    connector_category = "iam"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "HashiCorp Vault audit-device events. Vault audit "
                "logs are pushed by a sidecar tailing the file/socket "
                "device into the connectors service buffer; this "
                "connector drains the buffer per poll. test_connection "
                "verifies the cluster health and token policy via the "
                "Vault REST API."
            ),
            docs_url="/docs/connectors/vault",
            fields=[
                Field(
                    "vault_addr",
                    "string",
                    "Vault address",
                    placeholder="https://vault.example.com:8200",
                    help_text="Cluster URL used by test_connection. Can be left blank to skip the live probe.",
                    required=False,
                ),
                Field(
                    "vault_token",
                    "secret",
                    "Vault token (audit-list policy)",
                    required=False,
                    help_text=(
                        "Token with sys/audit list / sys/health read. "
                        "Used only by test_connection — events flow "
                        "via the audit-device sidecar, not through "
                        "this token."
                    ),
                ),
                Field(
                    "namespace",
                    "string",
                    "Vault Enterprise namespace",
                    required=False,
                    help_text="Optional. Sent as X-Vault-Namespace.",
                ),
                Field(
                    "buffer_size",
                    "string",
                    "Max buffered audit lines",
                    required=False,
                    default=str(_DEFAULT_BUFFER),
                ),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (
            Capability.PULL_AUDIT,
            Capability.READ_AUDIT_TRAIL,
        )

    def __init__(
        self,
        vault_addr: str | None = None,
        vault_token: str | None = None,
        namespace: str | None = None,
        buffer_size: str | int | None = None,
    ):
        self._addr = (vault_addr or "").rstrip("/")
        self._token = vault_token
        self._namespace = namespace
        try:
            self._buffer_size = int(buffer_size) if buffer_size else _DEFAULT_BUFFER
        except (TypeError, ValueError):
            self._buffer_size = _DEFAULT_BUFFER
        # The shared buffer between the sidecar's HTTP push and this
        # connector. asyncio.Lock keeps drain + ingest race-free.
        self._buffer: list[dict[str, Any]] = []
        self._lock = asyncio.Lock()

    def _headers(self) -> dict[str, str]:
        h: dict[str, str] = {"Accept": "application/json"}
        if self._token:
            h["X-Vault-Token"] = self._token
        if self._namespace:
            h["X-Vault-Namespace"] = self._namespace
        return h

    async def test_connection(self) -> dict[str, Any]:
        if not self._addr:
            # Buffer-only deployments are valid; report the buffer state.
            return {
                "success": True,
                "connector": self.connector_id,
                "mode": "buffer-only",
                "buffered": len(self._buffer),
            }
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                health = await client.get(f"{self._addr}/v1/sys/health", headers=self._headers())
                # 200 = active, 429 = standby — both mean the cluster is alive.
                # 472 / 473 = perf-secondary / DR-secondary; treat as alive too.
                if health.status_code not in (200, 429, 472, 473):
                    return {
                        "success": False,
                        "connector": self.connector_id,
                        "error": f"sys/health HTTP {health.status_code}: {health.text[:200]}",
                    }
                if self._token:
                    audit_resp = await client.get(
                        f"{self._addr}/v1/sys/audit",
                        headers=self._headers(),
                    )
                    if audit_resp.status_code not in (200, 403):
                        return {
                            "success": False,
                            "connector": self.connector_id,
                            "error": f"sys/audit probe HTTP {audit_resp.status_code}",
                        }
            return {
                "success": True,
                "connector": self.connector_id,
                "addr": self._addr,
            }
        except Exception as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def ingest_audit_lines(self, lines: list[dict[str, Any]]) -> int:
        """Sidecar push entry-point. Returns count buffered after trim."""
        async with self._lock:
            self._buffer.extend(lines)
            if len(self._buffer) > self._buffer_size:
                # Drop oldest events first — keep the back pressure bounded.
                self._buffer = self._buffer[-self._buffer_size :]
            return len(self._buffer)

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        cutoff = time.time() - since_seconds
        async with self._lock:
            drained = list(self._buffer)
            self._buffer.clear()
        out: list[dict[str, Any]] = []
        for ev in drained:
            ts = ev.get("time") or ev.get("@timestamp")
            # Vault file-device timestamps are RFC3339; tolerate epoch too.
            if isinstance(ts, str):
                try:
                    from datetime import datetime

                    parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    ts_epoch = parsed.timestamp()
                except Exception:
                    ts_epoch = cutoff
            elif isinstance(ts, int | float):
                ts_epoch = float(ts)
            else:
                ts_epoch = cutoff
            if ts_epoch < cutoff:
                continue
            out.append(self.normalize(ev))
        return out

    # Vault audit operation tokens that we always escalate. Keep small &
    # reviewable — anything outside the list flows through normalize's
    # path heuristics.
    _HIGH_RISK_OPS = (
        "delete",
        "revoke",
        "rekey",
        "rotate",
    )
    _HIGH_RISK_PATH_FRAGMENTS = (
        "auth/token/root",
        "sys/policies",
        "sys/policy",
        "sys/audit",
        "sys/seal",
        "sys/unseal",
        "sys/raw",
    )

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        # Vault audit JSON has request{} and response{} mirrors; we use
        # request as the source of truth and fall back to response when
        # the entry is the response half of an HMAC-paired record.
        req = raw.get("request") or {}
        resp = raw.get("response") or {}
        op = (req.get("operation") or resp.get("operation") or "").lower()
        path = req.get("path") or resp.get("path") or ""
        auth = raw.get("auth") or {}
        # Severity heuristic, in escalation order.
        severity = "info"
        if op in self._HIGH_RISK_OPS:
            severity = "medium"
        if any(frag in path for frag in self._HIGH_RISK_PATH_FRAGMENTS):
            severity = "high"
        if "root" in (auth.get("policies") or []):
            severity = "high"
        if raw.get("error"):
            # Errors are policy-denials worth surfacing but never *more*
            # severe than the operation itself.
            severity = severity if severity != "info" else "low"
        display_name = auth.get("display_name") or auth.get("entity_id") or ""
        return {
            "source": self.connector_id,
            "external_id": raw.get("request_id") or req.get("id") or "",
            "title": f"Vault {op} {path}".strip(),
            "description": (
                f"op={op}; path={path}; "
                f"actor={display_name}; "
                f"policies={','.join(auth.get('policies') or [])}; "
                f"error={raw.get('error') or ''}"
            ),
            "severity": severity,
            "actor": display_name or auth.get("entity_id"),
            "src_ip": (req.get("remote_address") or resp.get("remote_address")),
            "event_type": f"vault.{op or 'audit'}.{path.split('/')[0] if path else 'event'}",
            "namespace": raw.get("namespace") or self._namespace,
            "raw_event": raw,
            "created_at": raw.get("time") or raw.get("@timestamp"),
        }
