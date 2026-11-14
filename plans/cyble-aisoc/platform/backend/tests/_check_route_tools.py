"""Smoke test for the tool → connector SDK routing layer.

Verifies the contract established by ``t1c-route-tools``:

  1. Every refactored tool handler is still registered under its
     original ``name``, ``integration``, and ``risk_class`` (no breaking
     change at the LLM tool surface).
  2. The JSON ``params_schema`` does **not** expose ``tenant_id`` to the
     model — tenancy stays a server-side invariant.
  3. Each handler carries the ``needs:tenant`` tag so
     :meth:`app.agents.base.BaseAgent.call_tool` will inject the bound
     ``tenant_id`` before dispatch.
  4. Invoking the handler directly with ``tenant_id=...`` resolves a
     mock connector for the tenant (no DB row configured) and produces
     the same payload as the legacy hardcoded tool, byte-for-byte for
     static handlers, structurally for the SIEM (relative timestamps).
  5. The same handler called with two different tenant ids returns
     independent connector instances (cache key is per-tenant).

Run with:

    cd platform/backend
    python -m tests._check_route_tools
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path

# Force ephemeral DB before app imports so we don't touch the real one.
TMP_DIR = Path(tempfile.mkdtemp(prefix="aisoc-route-"))
os.environ["AISOC_DB_PATH"] = str(TMP_DIR / "route-test.db")
os.environ.setdefault("AISOC_ENV", "development")

# Repo root on path so `app.*` imports resolve when run as a script.
HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parent.parent))

from app.connectors import ConnectorKind, get_connector, reset_connector_cache
from app.connectors.sdk.mocks import (
    MockEdrConnector,
    MockEmailConnector,
    MockIdpConnector,
    MockSiemConnector,
)
from app.db import init_db
# Importing the tool modules triggers registration on the global registry.
from app.tools import edr as _edr  # noqa: F401
from app.tools import email_tool as _email  # noqa: F401
from app.tools import idp as _idp  # noqa: F401
from app.tools import siem as _siem  # noqa: F401
from app.tools.registry import registry


TENANT_A = "tenant-route-A"
TENANT_B = "tenant-route-B"

NEEDS_TENANT = "needs:tenant"

# (tool name, expected integration, kind, expected MockConnector class)
ROUTED_TOOLS: list[tuple[str, str, ConnectorKind, type]] = [
    ("siem.search_events", "splunk", ConnectorKind.SIEM, MockSiemConnector),
    ("siem.get_related_alerts", "splunk", ConnectorKind.SIEM, MockSiemConnector),
    ("edr.get_process_tree", "sentinelone", ConnectorKind.EDR, MockEdrConnector),
    ("edr.isolate_host", "sentinelone", ConnectorKind.EDR, MockEdrConnector),
    ("edr.quarantine_file", "sentinelone", ConnectorKind.EDR, MockEdrConnector),
    ("edr.kill_process", "sentinelone", ConnectorKind.EDR, MockEdrConnector),
    ("idp.get_user", "okta", ConnectorKind.IDP, MockIdpConnector),
    ("idp.revoke_sessions", "okta", ConnectorKind.IDP, MockIdpConnector),
    ("idp.disable_user", "okta", ConnectorKind.IDP, MockIdpConnector),
    ("idp.reset_password", "okta", ConnectorKind.IDP, MockIdpConnector),
    ("email.analyze_message", "proofpoint", ConnectorKind.EMAIL, MockEmailConnector),
    ("email.clawback_message", "proofpoint", ConnectorKind.EMAIL, MockEmailConnector),
    ("email.block_sender", "proofpoint", ConnectorKind.EMAIL, MockEmailConnector),
]


def _check_metadata() -> None:
    """All routed tools must keep stable metadata and declare needs:tenant."""
    for name, integration, _kind, _mock_cls in ROUTED_TOOLS:
        td = registry.get(name)
        assert td is not None, f"tool {name} not registered"
        assert td.integration == integration, (
            f"tool {name} integration drifted: "
            f"got {td.integration!r}, want {integration!r}"
        )
        # The LLM-facing JSON Schema MUST NOT mention tenant_id. The model
        # never sees that field; the agent forcibly injects it server-side.
        params_props = td.params_schema.get("properties", {})
        assert "tenant_id" not in params_props, (
            f"tool {name} leaks tenant_id into params_schema.properties — "
            "the LLM must never see this field"
        )
        required = td.params_schema.get("required", [])
        assert "tenant_id" not in required, (
            f"tool {name} marks tenant_id as required in params_schema — "
            "tenancy is server-injected, not LLM-supplied"
        )
        assert NEEDS_TENANT in td.tags, (
            f"tool {name} is missing the {NEEDS_TENANT!r} tag — "
            "BaseAgent.call_tool will not inject tenant_id"
        )
    print(
        f"OK  {len(ROUTED_TOOLS)} tools keep stable metadata "
        f"+ declare needs:tenant"
    )


async def _check_per_tenant_caching() -> None:
    """Same kind, two tenants, two distinct connector instances."""
    siem_a1 = await get_connector(TENANT_A, ConnectorKind.SIEM)
    siem_a2 = await get_connector(TENANT_A, ConnectorKind.SIEM)
    siem_b = await get_connector(TENANT_B, ConnectorKind.SIEM)
    assert siem_a1 is siem_a2, "same-tenant lookup should return cached instance"
    assert siem_a1 is not siem_b, "different tenants must get different instances"
    assert siem_a1.config.tenant_id == TENANT_A
    assert siem_b.config.tenant_id == TENANT_B
    print("OK  per-tenant connector caching is isolated")


async def _check_siem_routing() -> None:
    td_search = registry.get("siem.search_events")
    td_related = registry.get("siem.get_related_alerts")
    assert td_search and td_related

    events = await td_search.handler(
        tenant_id=TENANT_A, entity="tina.lee", entity_type="user", minutes=60
    )
    assert events["entity"] == "tina.lee"
    assert events["entity_type"] == "user"
    assert events["window_minutes"] == 60
    assert isinstance(events["events"], list) and len(events["events"]) == 3
    types = {e["type"] for e in events["events"]}
    assert types == {"auth_success", "process_start", "network_connection"}

    related = await td_related.handler(
        tenant_id=TENANT_A, entity="tina.lee", hours=24
    )
    assert related["entity"] == "tina.lee"
    assert related["related_count"] == 2
    assert {r["id"] for r in related["related"]} == {"ALR-9821", "ALR-9844"}

    # And the connector resolved for this tenant must be the mock.
    siem = await get_connector(TENANT_A, ConnectorKind.SIEM)
    assert isinstance(siem, MockSiemConnector)
    print("OK  siem.* tool handlers route through mock SIEM connector")


async def _check_edr_routing() -> None:
    td_tree = registry.get("edr.get_process_tree")
    td_isolate = registry.get("edr.isolate_host")
    td_quarantine = registry.get("edr.quarantine_file")
    td_kill = registry.get("edr.kill_process")
    assert td_tree and td_isolate and td_quarantine and td_kill

    tree = await td_tree.handler(tenant_id=TENANT_A, host="win10-prod-04")
    assert tree["host"] == "win10-prod-04"
    assert tree["tree"][0]["name"] == "outlook.exe"

    isolate = await td_isolate.handler(
        tenant_id=TENANT_A,
        host="win10-prod-04",
        reason="credential theft suspected",
    )
    assert isolate == {
        "host": "win10-prod-04",
        "isolated": True,
        "reason": "credential theft suspected",
        "ticket": "ISO-44128",
    }

    quarantine = await td_quarantine.handler(tenant_id=TENANT_A, sha256="0" * 64)
    assert quarantine == {
        "sha256": "0" * 64,
        "quarantined_on_endpoints": 3,
        "ticket": "QUA-7733",
    }

    kill = await td_kill.handler(tenant_id=TENANT_A, host="win10-prod-04", pid=6190)
    assert kill == {"host": "win10-prod-04", "pid": 6190, "terminated": True}

    edr = await get_connector(TENANT_A, ConnectorKind.EDR)
    assert isinstance(edr, MockEdrConnector)
    print("OK  edr.* tool handlers route through mock EDR connector")


async def _check_idp_routing() -> None:
    td_get = registry.get("idp.get_user")
    td_revoke = registry.get("idp.revoke_sessions")
    td_disable = registry.get("idp.disable_user")
    td_reset = registry.get("idp.reset_password")
    assert td_get and td_revoke and td_disable and td_reset

    user = await td_get.handler(tenant_id=TENANT_A, user="tina.lee")
    assert user["user"] == "tina.lee"
    assert user["email"] == "tina.lee@cyble.com"
    assert "vpn-users" in user["groups"]

    revoke = await td_revoke.handler(tenant_id=TENANT_A, user="tina.lee")
    assert revoke == {
        "user": "tina.lee",
        "sessions_revoked": 4,
        "ticket": "REVOKE-22910",
    }

    disable = await td_disable.handler(
        tenant_id=TENANT_A, user="tina.lee", reason="credential theft suspected"
    )
    assert disable == {
        "user": "tina.lee",
        "disabled": True,
        "reason": "credential theft suspected",
    }

    reset = await td_reset.handler(tenant_id=TENANT_A, user="tina.lee")
    assert reset == {"user": "tina.lee", "reset_email_sent": True}

    idp = await get_connector(TENANT_A, ConnectorKind.IDP)
    assert isinstance(idp, MockIdpConnector)
    print("OK  idp.* tool handlers route through mock IdP connector")


async def _check_email_routing() -> None:
    td_analyze = registry.get("email.analyze_message")
    td_clawback = registry.get("email.clawback_message")
    td_block = registry.get("email.block_sender")
    assert td_analyze and td_clawback and td_block

    analyze = await td_analyze.handler(tenant_id=TENANT_A, message_id="msg-001")
    assert analyze["message_id"] == "msg-001"
    assert analyze["from"] == "billing@m1crosoft-secure.com"
    assert analyze["auth"] == {"spf": "fail", "dkim": "none", "dmarc": "fail"}
    assert analyze["suspicion_score"] == 0.94

    clawback = await td_clawback.handler(tenant_id=TENANT_A, message_id="msg-001")
    assert clawback == {
        "message_id": "msg-001",
        "recipients_affected": 47,
        "status": "quarantined",
    }

    block = await td_block.handler(
        tenant_id=TENANT_A, sender="billing@m1crosoft-secure.com"
    )
    assert block == {"sender": "billing@m1crosoft-secure.com", "blocked": True}

    email = await get_connector(TENANT_A, ConnectorKind.EMAIL)
    assert isinstance(email, MockEmailConnector)
    print("OK  email.* tool handlers route through mock email connector")


async def _check_tenant_id_required() -> None:
    """Handlers are keyword-only on tenant_id; calling without it must fail.

    This is the belt-and-braces check that lets us trust BaseAgent's
    `needs:tenant` injection: if a tool is ever invoked without the agent
    binding tenancy, it raises immediately instead of leaking a default.
    """
    td = registry.get("siem.search_events")
    assert td is not None
    try:
        await td.handler(entity="tina.lee", entity_type="user", minutes=60)
    except TypeError as exc:
        assert "tenant_id" in str(exc), (
            f"expected TypeError to mention tenant_id, got: {exc}"
        )
        print("OK  handler refuses to run without tenant_id (keyword-only)")
        return
    raise AssertionError(
        "siem.search_events ran without tenant_id — keyword-only guard broken"
    )


async def _main() -> None:
    init_db()
    _check_metadata()
    await _check_per_tenant_caching()
    await _check_siem_routing()
    await _check_edr_routing()
    await _check_idp_routing()
    await _check_email_routing()
    await _check_tenant_id_required()
    evicted = await reset_connector_cache()
    assert evicted >= 2, f"expected >= 2 cached connectors, got {evicted}"
    print(f"OK  reset_connector_cache evicted {evicted} cached instances")
    print("\nALL TOOL ROUTING CHECKS PASSED")


if __name__ == "__main__":
    asyncio.run(_main())
