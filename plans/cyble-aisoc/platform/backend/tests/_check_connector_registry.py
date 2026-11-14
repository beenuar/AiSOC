"""Smoke test for the per-tenant ConnectorRegistry.

Verifies:
  1. Factory registration via decorator stores a callable.
  2. Tenant with no row gets the mock connector.
  3. Tenant with an enabled row gets the vendor connector.
  4. Tenant with a disabled row falls back to the mock connector.
  5. Calling get_connector twice returns the same cached instance.
  6. reset_connector_cache evicts entries and awaits aclose().
  7. An unknown vendor on a configured row falls back to the mock.
  8. Missing tenant_id raises ConnectorError.

Run with:

    cd platform/backend
    python -m tests._check_connector_registry
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path

# Force ephemeral DB before app imports so we don't touch the real one.
TMP_DIR = Path(tempfile.mkdtemp(prefix="aisoc-registry-"))
os.environ["AISOC_DB_PATH"] = str(TMP_DIR / "registry-test.db")
os.environ.setdefault("AISOC_ENV", "development")

# Repo root on path so `app.*` imports resolve when run as a script.
HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parent.parent))

from sqlmodel import Session

from app.connectors import (
    BaseConnector,
    ConnectorConfig,
    ConnectorError,
    ConnectorKind,
    get_connector,
    register_connector_factory,
    reset_connector_cache,
)
from app.connectors.sdk import registry as registry_module
from app.db import engine, init_db
from app.models.tenant_connector import TenantConnector


# ─── stub connectors ─────────────────────────────────────────────────────


class _StubConnector(BaseConnector):
    """Tracks construction args and aclose() invocations for assertions."""

    closed_instances: list["_StubConnector"] = []

    def __init__(self, config: ConnectorConfig, *, label: str) -> None:
        super().__init__(config)
        self.label = label
        self.aclose_called = False

    async def health_check(self) -> dict[str, object]:
        return {"ok": True, "label": self.label}

    async def aclose(self) -> None:
        self.aclose_called = True
        _StubConnector.closed_instances.append(self)


def _make_stub_factory(label: str):
    def factory(config: ConnectorConfig) -> _StubConnector:
        return _StubConnector(config, label=label)

    return factory


# Register before any get_connector calls.
register_connector_factory(kind=ConnectorKind.SIEM, vendor="mock")(
    _make_stub_factory("mock")
)
register_connector_factory(kind=ConnectorKind.SIEM, vendor="splunk")(
    _make_stub_factory("splunk")
)


async def _main() -> None:
    init_db()

    # Pretend the bundled vendor pack is already loaded so the registry
    # doesn't try to import a builtin module that doesn't exist yet.
    registry_module._BUILTINS_LOADED = True

    tenant_unconfigured = "tenant-unconfigured"
    tenant_enabled = "tenant-enabled"
    tenant_disabled = "tenant-disabled"
    tenant_unknown_vendor = "tenant-unknown-vendor"

    # Seed three TenantConnector rows.
    with Session(engine) as s:
        enabled_row = TenantConnector(
            tenant_id=tenant_enabled,
            kind=ConnectorKind.SIEM.value,
            vendor="splunk",
            params={"host": "splunk.example.com"},
            enabled=True,
        )
        enabled_row.set_secrets({"token": "abc"})

        disabled_row = TenantConnector(
            tenant_id=tenant_disabled,
            kind=ConnectorKind.SIEM.value,
            vendor="splunk",
            params={"host": "splunk.example.com"},
            enabled=False,
        )
        disabled_row.set_secrets({"token": "xyz"})

        unknown_row = TenantConnector(
            tenant_id=tenant_unknown_vendor,
            kind=ConnectorKind.SIEM.value,
            vendor="bogus-vendor-xxx",
            params={},
            enabled=True,
        )
        unknown_row.set_secrets({"token": "irrelevant"})

        s.add(enabled_row)
        s.add(disabled_row)
        s.add(unknown_row)
        s.commit()

    # (1) tenant with no row -> mock
    c_mock = await get_connector(tenant_unconfigured, ConnectorKind.SIEM)
    assert isinstance(c_mock, _StubConnector)
    assert c_mock.label == "mock", f"expected mock, got {c_mock.label}"
    assert c_mock.config.tenant_id == tenant_unconfigured
    assert c_mock.config.vendor == "mock"
    print("OK  unconfigured tenant -> mock vendor")

    # (2) tenant with enabled row -> real vendor
    c_real = await get_connector(tenant_enabled, ConnectorKind.SIEM)
    assert isinstance(c_real, _StubConnector)
    assert c_real.label == "splunk", f"expected splunk, got {c_real.label}"
    assert c_real.config.secret("token") == "abc"
    assert c_real.config.param("host") == "splunk.example.com"
    print("OK  enabled tenant -> real vendor with decrypted secrets")

    # (3) tenant with disabled row -> mock fallback
    c_disabled = await get_connector(tenant_disabled, ConnectorKind.SIEM)
    assert isinstance(c_disabled, _StubConnector)
    assert c_disabled.label == "mock", (
        f"disabled row should fall back to mock, got {c_disabled.label}"
    )
    print("OK  disabled tenant -> mock fallback")

    # (4) caching: identity is preserved
    c_real_again = await get_connector(tenant_enabled, ConnectorKind.SIEM)
    assert c_real_again is c_real, "cache should return identical instance"
    print("OK  cached instance returned on repeated lookup")

    # (5) unknown vendor falls back to mock
    c_unknown = await get_connector(tenant_unknown_vendor, ConnectorKind.SIEM)
    assert isinstance(c_unknown, _StubConnector)
    assert c_unknown.label == "mock", (
        f"unknown vendor should fall back to mock, got {c_unknown.label}"
    )
    print("OK  unknown vendor -> mock fallback")

    # (6) targeted eviction
    _StubConnector.closed_instances.clear()
    evicted = await reset_connector_cache(
        tenant_id=tenant_enabled, kind=ConnectorKind.SIEM
    )
    assert evicted == 1, f"expected to evict 1, evicted {evicted}"
    assert c_real.aclose_called, "evicted connector should have aclose() awaited"
    print("OK  targeted reset evicts one entry and calls aclose()")

    # After eviction the next lookup builds a new instance.
    c_real_v2 = await get_connector(tenant_enabled, ConnectorKind.SIEM)
    assert c_real_v2 is not c_real, "post-eviction lookup should build a new instance"
    print("OK  post-eviction lookup builds a new instance")

    # (7) global eviction
    _StubConnector.closed_instances.clear()
    evicted = await reset_connector_cache()
    assert evicted >= 3, f"expected to evict at least 3 entries, got {evicted}"
    assert len(_StubConnector.closed_instances) == evicted
    print(f"OK  global reset evicts everything ({evicted} entries)")

    # (8) missing tenant_id
    try:
        await get_connector("", ConnectorKind.SIEM)
    except ConnectorError as e:
        assert "tenant_id" in str(e)
        print("OK  empty tenant_id raises ConnectorError")
    else:
        raise AssertionError("expected ConnectorError for empty tenant_id")

    print("\nALL REGISTRY CHECKS PASSED")


if __name__ == "__main__":
    asyncio.run(_main())
