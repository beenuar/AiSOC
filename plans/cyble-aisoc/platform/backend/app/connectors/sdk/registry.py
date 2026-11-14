"""Per-tenant connector registry.

This module is the *only* place the rest of the platform asks
"give me a connector for tenant X of kind Y". It owns:

  1. A factory registry  — `(kind, vendor) -> callable(config) -> BaseConnector`
     populated at import time by vendor modules (decorator) or programmatically
     by tests.
  2. A tenant resolver   — load the `TenantConnector` row for `(tenant_id, kind)`
     and build a runtime `ConnectorConfig` from it. If no row exists or the row
     is disabled, fall back to the mock vendor for that kind.
  3. A live-instance cache — keep one connector instance per
     `(tenant_id, kind)` so HTTP keepalive and OAuth tokens survive across tool
     calls. `aclose()` is awaited on eviction so resources don't leak.

The cache is intentionally process-local. In multi-process deployments
(uvicorn workers) each worker maintains its own cache; that's fine because
connector state (tokens, sessions) is not safe to share across processes
anyway.

Public surface
--------------

    from app.connectors import ConnectorKind, get_connector

    siem = await get_connector(tenant_id, ConnectorKind.SIEM)
    events = await siem.search_events(entity="HR-42", entity_type="host")

    # After an admin updates credentials for tenant X:
    await reset_connector_cache(tenant_id="acme-corp")
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from typing import Any

from sqlmodel import Session, select

from app.connectors.sdk.base import (
    BaseConnector,
    ConnectorConfig,
    ConnectorError,
    ConnectorKind,
)

log = logging.getLogger(__name__)


ConnectorFactory = Callable[[ConnectorConfig], BaseConnector]

# (kind, vendor) -> factory. Vendor strings match `TenantConnector.vendor`
# and are case-sensitive on purpose so typos in admin config don't
# silently fall through.
_FACTORIES: dict[tuple[ConnectorKind, str], ConnectorFactory] = {}

# Per-process cache of live connector instances. We keep at most one
# entry per (tenant_id, kind) because the SQLModel enforces the same
# uniqueness at the DB level.
_CACHE: dict[tuple[str, ConnectorKind], BaseConnector] = {}
_CACHE_LOCK = asyncio.Lock()

# We import the vendor pack lazily on first `get_connector` call so the
# package is usable in places that don't need a live connector (tests,
# admin tooling).
_BUILTINS_LOADED = False


# ─── factory registration ────────────────────────────────────────────────


def register_connector_factory(
    *, kind: ConnectorKind, vendor: str
) -> Callable[[ConnectorFactory], ConnectorFactory]:
    """Decorator: register a factory for `(kind, vendor)`.

    Vendor modules use this at import time::

        from app.connectors.sdk.protocols import BaseSiemConnector
        from app.connectors.sdk.registry import register_connector_factory

        @register_connector_factory(kind=ConnectorKind.SIEM, vendor="splunk")
        def make_splunk(config: ConnectorConfig) -> BaseSiemConnector:
            return SplunkSiemConnector(config)

    Re-registering an existing key replaces the previous factory and
    logs a warning — useful in tests, but a smell in production.
    """

    def _decorator(factory: ConnectorFactory) -> ConnectorFactory:
        key = (kind, vendor)
        if key in _FACTORIES:
            log.warning(
                "connector factory %s already registered; overwriting", key
            )
        _FACTORIES[key] = factory
        return factory

    return _decorator


def list_registered_factories() -> list[tuple[ConnectorKind, str]]:
    """Snapshot of currently registered `(kind, vendor)` pairs (sorted).

    Intended for debug / admin endpoints only.
    """
    return sorted(_FACTORIES.keys(), key=lambda kv: (kv[0].value, kv[1]))


def _ensure_builtins_loaded() -> None:
    """Import the bundled vendor pack so the decorators run.

    Idempotent. Safe to call multiple times.
    """
    global _BUILTINS_LOADED
    if _BUILTINS_LOADED:
        return
    try:
        # Importing this module triggers the @register_connector_factory
        # decorators on every shipped vendor (mocks today, real connectors
        # as t1c-splunk / t1c-crowdstrike / … land).
        import app.connectors.sdk.builtin  # noqa: F401
    except ModuleNotFoundError:
        # During SDK bootstrap the builtin pack may not exist yet. Don't
        # crash — tests can still register factories explicitly.
        log.debug("app.connectors.sdk.builtin not present yet; skipping")
    _BUILTINS_LOADED = True


# ─── tenant resolution ───────────────────────────────────────────────────


def _load_tenant_row(tenant_id: str, kind: ConnectorKind):
    """Fetch the single `TenantConnector` for `(tenant_id, kind)` or None.

    Imported lazily to keep this module importable when models aren't yet
    on the path (e.g. unit tests for the SDK only).
    """
    from app.db import engine
    from app.models.tenant_connector import TenantConnector

    with Session(engine) as session:
        return session.exec(
            select(TenantConnector)
            .where(TenantConnector.tenant_id == tenant_id)
            .where(TenantConnector.kind == kind.value)
        ).one_or_none()


def _build_mock_config(tenant_id: str, kind: ConnectorKind) -> ConnectorConfig:
    """Synthetic config used when no real connector is registered for tenant."""
    return ConnectorConfig(
        tenant_id=tenant_id,
        kind=kind,
        vendor="mock",
        params={},
        secrets={},
        enabled=True,
    )


def _resolve_factory(kind: ConnectorKind, vendor: str) -> ConnectorFactory:
    """Look up the factory, falling back to the mock vendor for the kind."""
    key = (kind, vendor)
    factory = _FACTORIES.get(key)
    if factory is not None:
        return factory

    mock_key = (kind, "mock")
    mock_factory = _FACTORIES.get(mock_key)
    if mock_factory is not None:
        log.warning(
            "connector vendor %r for kind %s not registered; "
            "falling back to mock",
            vendor,
            kind.value,
        )
        return mock_factory

    raise ConnectorError(
        f"no factory registered for kind={kind.value} vendor={vendor!r}, "
        "and no mock fallback is available — register the vendor in "
        "app/connectors/sdk/builtin.py"
    )


# ─── public API ──────────────────────────────────────────────────────────


async def get_connector(tenant_id: str, kind: ConnectorKind) -> BaseConnector:
    """Resolve, instantiate, and cache a connector for `(tenant_id, kind)`.

    Resolution order:

      1. If the tenant has an *enabled* `TenantConnector` row, build the
         vendor connector registered for that `(kind, vendor)` pair.
      2. If the row is *disabled* or missing, build the mock connector
         registered as `(kind, "mock")`.
      3. If no factory is registered for the configured vendor, fall back
         to the mock for the kind and log a warning.
      4. If no mock is registered either, raise `ConnectorError` —
         that's a misconfiguration the operator must fix.

    The same instance is returned on subsequent calls within the process
    until `reset_connector_cache` is called or the process restarts.
    """
    if not tenant_id:
        raise ConnectorError("get_connector requires a tenant_id")

    _ensure_builtins_loaded()

    cache_key = (tenant_id, kind)
    cached = _CACHE.get(cache_key)
    if cached is not None:
        return cached

    async with _CACHE_LOCK:
        # Another coroutine may have built it while we waited.
        cached = _CACHE.get(cache_key)
        if cached is not None:
            return cached

        row = _load_tenant_row(tenant_id, kind)
        if row is not None and row.enabled:
            config = row.to_runtime_config()
        else:
            if row is not None and not row.enabled:
                log.info(
                    "tenant %s has disabled %s connector; using mock",
                    tenant_id,
                    kind.value,
                )
            config = _build_mock_config(tenant_id, kind)

        factory = _resolve_factory(config.kind, config.vendor)
        instance = factory(config)
        _CACHE[cache_key] = instance
        log.info(
            "instantiated connector tenant=%s kind=%s vendor=%s",
            tenant_id,
            kind.value,
            config.vendor,
        )
        return instance


async def reset_connector_cache(
    *,
    tenant_id: str | None = None,
    kind: ConnectorKind | None = None,
) -> int:
    """Evict cached connectors and `await aclose()` on each.

    Calling forms:

      - ``reset_connector_cache()``                     flush everything (tests, restart)
      - ``reset_connector_cache(tenant_id=X)``          flush one tenant (creds rotated)
      - ``reset_connector_cache(tenant_id=X, kind=Y)``  flush one entry exactly

    Returns the number of entries evicted.
    """
    async with _CACHE_LOCK:
        keys_to_drop: list[tuple[str, ConnectorKind]] = []
        for (tid, k) in _CACHE.keys():
            if tenant_id is not None and tid != tenant_id:
                continue
            if kind is not None and k != kind:
                continue
            keys_to_drop.append((tid, k))
        evicted = [_CACHE.pop(key) for key in keys_to_drop]

    # Close outside the lock so a slow aclose() doesn't block new resolutions.
    for inst in evicted:
        try:
            await inst.aclose()
        except Exception:  # pragma: no cover - defensive
            log.warning(
                "connector %r raised during aclose()", inst, exc_info=True
            )
    return len(evicted)


def _reset_for_tests() -> None:
    """Synchronous teardown helper for unit tests.

    Drops the cache without awaiting `aclose()`. Use this only when you're
    sure no real I/O is open (e.g. mock connectors in unit tests).
    """
    _CACHE.clear()


__all__ = [
    "ConnectorFactory",
    "get_connector",
    "list_registered_factories",
    "register_connector_factory",
    "reset_connector_cache",
]
