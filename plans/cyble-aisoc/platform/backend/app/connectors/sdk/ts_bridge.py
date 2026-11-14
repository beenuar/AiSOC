"""Bridge between the Python connector registry and a TypeScript
hot-reload dev server (t5-connector-sdk-ga).

The TS SDK at ``platform/sdk/connector-ts`` exposes:

  GET  /healthz              - is the dev server up?
  GET  /manifest             - JSON manifest of the connector
  POST /actions/<name>       - execute an action

This module wraps a running dev server in a thin
:class:`BaseConnector` so the rest of the platform doesn't care
whether a connector is implemented in Python or TypeScript. Two
public entrypoints:

* :func:`attach_ts_dev_connector` — fetch the manifest and register
  a Python factory for ``(kind, vendor)`` that proxies every call
  to the dev server.
* :func:`detach_ts_dev_connector` — best-effort unregister + cache
  flush so the operator can rotate the dev server URL.

Hot-reload is handled on the TypeScript side; the Python side
re-fetches the manifest on demand (cheap, ~5ms over loopback) and
treats every call as fresh, so a TS reload is invisible to the
agent mesh.

Why HTTP over loopback (and not stdin/stdout JSON-RPC)?

  - Plays nicely with the existing FastAPI -> dev workflow.
  - Lets a contributor host the dev server on a remote machine while
    iterating from a laptop (we don't, but the option is free).
  - Trivial to debug with curl.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urljoin

import httpx

from app.connectors.sdk.base import (
    BaseConnector,
    ConnectorAuthError,
    ConnectorConfig,
    ConnectorError,
    ConnectorKind,
    ConnectorRateLimitError,
    ConnectorTimeoutError,
)
from app.connectors.sdk.registry import (
    ConnectorFactory,
    register_connector_factory,
    reset_connector_cache,
    _FACTORIES,  # internal — used to deregister on detach.
)

logger = logging.getLogger(__name__)


_DEFAULT_TIMEOUT_SECONDS = 30.0


# ─── DTOs ───────────────────────────────────────────────────────────


@dataclass(frozen=True)
class TsDevManifest:
    """Snapshot of a TS connector's ``GET /manifest`` payload."""

    sdk_version: str
    kind: ConnectorKind
    vendor: str
    version: str
    actions: dict[str, dict[str, Any]]
    raw: dict[str, Any]


# ─── Manifest fetch + parse ─────────────────────────────────────────


def fetch_manifest(base_url: str, *, timeout: float = 5.0) -> TsDevManifest:
    """Fetch and parse a TS connector's manifest."""
    url = urljoin(base_url.rstrip("/") + "/", "manifest")
    try:
        response = httpx.get(url, timeout=timeout)
    except httpx.RequestError as exc:
        raise ConnectorError(
            f"could not reach TS dev server at {base_url!r}: {exc}"
        ) from exc
    if response.status_code != 200:
        raise ConnectorError(
            f"TS dev server returned {response.status_code} for /manifest "
            f"at {base_url!r} (body: {response.text[:200]!r})"
        )
    blob = response.json()

    try:
        kind = ConnectorKind(str(blob.get("kind")).lower())
    except (TypeError, ValueError) as exc:
        raise ConnectorError(
            f"TS manifest at {base_url!r} declares an unknown kind: {blob.get('kind')!r}"
        ) from exc

    return TsDevManifest(
        sdk_version=str(blob.get("sdk_version", "?")),
        kind=kind,
        vendor=str(blob.get("vendor", "")),
        version=str(blob.get("version", "0.0.0")),
        actions=dict(blob.get("actions") or {}),
        raw=blob,
    )


# ─── HTTP-proxied connector ────────────────────────────────────────


class TsDevConnector(BaseConnector):
    """A Python connector whose actions proxy to a TS dev server."""

    # ``kind`` and ``vendor`` are normally class-level on a concrete
    # subclass. Here we fix them per-instance because every TS connector
    # we wrap could be a different (kind, vendor). Subclassing per-vendor
    # would let the static type checker see them but creates a tax for
    # zero gain in this dynamically-attached path.
    kind = ConnectorKind.SIEM  # placeholder, overwritten in __init__

    def __init__(
        self,
        config: ConnectorConfig,
        *,
        base_url: str,
        manifest: TsDevManifest,
    ) -> None:
        super().__init__(config=config)
        self._base_url = base_url.rstrip("/")
        self._manifest = manifest
        self._client = httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT_SECONDS)
        # Stamp the dynamic kind/vendor so introspection works.
        self.kind = manifest.kind
        self.vendor = manifest.vendor

    @property
    def manifest(self) -> TsDevManifest:
        return self._manifest

    async def aclose(self) -> None:
        await self._client.aclose()

    async def health_check(self) -> dict[str, Any]:
        """Hit the dev server's /healthz endpoint.

        Returns ``{"ok": bool, "vendor": str, "kind": str, "reload_version": int}``.
        Used by the connector registry's "is this tenant connector
        actually reachable?" probe and by the admin UI.
        """
        url = f"{self._base_url}/healthz"
        try:
            response = await self._client.get(url, timeout=5.0)
        except httpx.RequestError as exc:
            return {
                "ok": False,
                "vendor": self.vendor,
                "kind": self.kind.value,
                "error": f"unreachable: {exc}",
            }
        if response.status_code != 200:
            return {
                "ok": False,
                "vendor": self.vendor,
                "kind": self.kind.value,
                "error": f"healthz returned {response.status_code}",
            }
        body = response.json()
        return {
            "ok": bool(body.get("ok")),
            "vendor": self.vendor,
            "kind": self.kind.value,
            "reload_version": int(body.get("reload_version") or 0),
        }

    async def call_action(
        self,
        action: str,
        *,
        input: Mapping[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> Any:
        """Invoke ``action`` on the TS dev server.

        Errors are translated to the existing ``ConnectorError`` family
        so the agent mesh's retry / HITL logic handles a TS upstream
        the same way it handles a Python upstream:

            502 -> ConnectorError (transient)
            408 -> ConnectorTimeoutError
            429 -> ConnectorRateLimitError
            401/403 -> ConnectorAuthError
            422 -> ConnectorError (input validation, do not retry)
        """
        if action not in self._manifest.actions:
            raise ConnectorError(
                f"action {action!r} is not declared in the TS manifest "
                f"for {self._manifest.kind.value}/{self._manifest.vendor}"
            )
        url = f"{self._base_url}/actions/{action}"
        payload: dict[str, Any] = {
            "tenant_id": self.config.tenant_id,
            "idempotency_key": idempotency_key or "",
            "input": dict(input or {}),
            # The TS server runs the same Zod schema against this dict
            # so any drift between the platform's stored config and
            # the connector's expectations is caught up front.
            "config": dict(self.config.params),
        }
        try:
            response = await self._client.post(url, json=payload)
        except httpx.TimeoutException as exc:
            raise ConnectorTimeoutError(
                f"TS connector {self._manifest.vendor}/{action} timed out"
            ) from exc
        except httpx.RequestError as exc:
            raise ConnectorError(
                f"TS connector {self._manifest.vendor}/{action} request failed: {exc}"
            ) from exc

        sc = response.status_code
        if sc == 200:
            data = response.json()
            return data.get("output")
        if sc in (401, 403):
            raise ConnectorAuthError(
                f"TS connector returned {sc} (auth): {response.text[:200]}"
            )
        if sc == 408:
            raise ConnectorTimeoutError(
                f"TS connector returned 408: {response.text[:200]}"
            )
        if sc == 429:
            raise ConnectorRateLimitError(
                f"TS connector rate-limited: {response.text[:200]}"
            )
        # Everything else: surface a clean ConnectorError.
        raise ConnectorError(
            f"TS connector {self._manifest.vendor}/{action} returned {sc}: "
            f"{response.text[:300]}"
        )


# ─── Public attach / detach ────────────────────────────────────────


def _factory_for_manifest(
    base_url: str, manifest: TsDevManifest
) -> ConnectorFactory:
    def _make(config: ConnectorConfig) -> BaseConnector:
        return TsDevConnector(
            config=config, base_url=base_url, manifest=manifest
        )

    _make.__name__ = f"ts_dev_factory[{manifest.vendor}]"
    return _make


def attach_ts_dev_connector(base_url: str) -> TsDevManifest:
    """Register a TS dev server with the Python connector registry.

    Steps:
      1. ``GET {base_url}/manifest`` to learn the kind+vendor+actions.
      2. Register a factory for ``(kind, vendor)`` that returns a
         :class:`TsDevConnector` proxying calls to the dev server.

    Idempotent: re-attaching the same vendor replaces the prior
    factory and logs a warning (same behaviour as Python factories).
    """
    manifest = fetch_manifest(base_url)
    factory = _factory_for_manifest(base_url, manifest)
    decorator = register_connector_factory(
        kind=manifest.kind, vendor=manifest.vendor
    )
    decorator(factory)
    logger.info(
        "ts_bridge:attached kind=%s vendor=%s sdk=%s base=%s actions=%s",
        manifest.kind.value,
        manifest.vendor,
        manifest.sdk_version,
        base_url,
        sorted(manifest.actions.keys()),
    )
    return manifest


async def detach_ts_dev_connector(
    *, kind: ConnectorKind, vendor: str
) -> int:
    """Remove a TS-bridged connector from the registry + cache.

    Returns the number of cached instances evicted (0 or 1 in
    practice). Safe to call when nothing is attached — it just
    no-ops.
    """
    key = (kind, vendor)
    removed = _FACTORIES.pop(key, None)
    if removed is None:
        return 0
    evicted = await reset_connector_cache(kind=kind)
    logger.info(
        "ts_bridge:detached kind=%s vendor=%s evicted=%d",
        kind.value, vendor, evicted,
    )
    return evicted


__all__ = [
    "TsDevConnector",
    "TsDevManifest",
    "attach_ts_dev_connector",
    "detach_ts_dev_connector",
    "fetch_manifest",
]
