"""Smoke test for the built-in mock connectors.

Verifies:
  1. ``app.connectors.sdk.builtin`` registers a mock factory for every
     supported ConnectorKind (SIEM, EDR, IDP, EMAIL).
  2. An unconfigured tenant resolves to a ``Mock*Connector`` of the
     correct concrete class.
  3. Each mock connector reports ``vendor == "mock"``.
  4. Each mock operation returns the *exact* shape the legacy
     ``app/tools/*`` handler returned — byte-for-byte for static
     payloads, and structurally for the SIEM (which has relative
     timestamps).
  5. ``health_check`` returns a small status dict on every kind.
  6. ``aclose()`` is a no-op (does not raise).

Run with:

    cd platform/backend
    python -m tests._check_connector_mocks
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path

# Force ephemeral DB before app imports so we don't touch the real one.
TMP_DIR = Path(tempfile.mkdtemp(prefix="aisoc-mocks-"))
os.environ["AISOC_DB_PATH"] = str(TMP_DIR / "mocks-test.db")
os.environ.setdefault("AISOC_ENV", "development")

# Repo root on path so `app.*` imports resolve when run as a script.
HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parent.parent))

from app.connectors import (
    ConnectorKind,
    get_connector,
    reset_connector_cache,
)
from app.connectors.sdk.mocks import (
    MockEdrConnector,
    MockEmailConnector,
    MockIdpConnector,
    MockSiemConnector,
)
from app.db import init_db


TENANT = "tenant-mock-smoke"


# ─── expected payloads (legacy tool handler outputs) ─────────────────────


EXPECTED_EDR_TREE = {
    "host": "win10-prod-04",
    "tree": [
        {
            "pid": 4112,
            "name": "outlook.exe",
            "user": "tina.lee",
            "children": [
                {
                    "pid": 5240,
                    "name": "winword.exe",
                    "cmdline": "WINWORD.EXE /n /dde",
                    "children": [
                        {
                            "pid": 6014,
                            "name": "powershell.exe",
                            "cmdline": "powershell -EncodedCommand <REDACTED>",
                            "signed": True,
                            "suspicious": True,
                            "children": [
                                {
                                    "pid": 6190,
                                    "name": "rundll32.exe",
                                    "cmdline": (
                                        "rundll32 "
                                        "C:\\Users\\tina.lee\\AppData\\"
                                        "Local\\Temp\\a.dll,Run"
                                    ),
                                    "signed": False,
                                    "suspicious": True,
                                }
                            ],
                        }
                    ],
                }
            ],
        }
    ],
}

EXPECTED_EDR_ISOLATE = {
    "host": "win10-prod-04",
    "isolated": True,
    "reason": "credential theft suspected",
    "ticket": "ISO-44128",
}

EXPECTED_EDR_QUARANTINE = {
    "sha256": "0" * 64,
    "quarantined_on_endpoints": 3,
    "ticket": "QUA-7733",
}

EXPECTED_EDR_KILL = {"host": "win10-prod-04", "pid": 6190, "terminated": True}

EXPECTED_IDP_USER = {
    "user": "tina.lee",
    "email": "tina.lee@cyble.com",
    "department": "Finance",
    "manager": "marc.aldred",
    "groups": ["finance-prod", "okta-admins-no", "vpn-users"],
    "last_signin": {
        "ts": "2026-04-28T17:14:00Z",
        "src_ip": "203.0.113.55",
        "country": "VN",
        "asn": "AS45899 VNPT",
        "anomaly_score": 0.81,
    },
    "mfa_factors": ["webauthn", "okta_verify"],
}

EXPECTED_IDP_REVOKE = {
    "user": "tina.lee",
    "sessions_revoked": 4,
    "ticket": "REVOKE-22910",
}

EXPECTED_IDP_DISABLE = {
    "user": "tina.lee",
    "disabled": True,
    "reason": "credential theft suspected",
}

EXPECTED_IDP_RESET = {"user": "tina.lee", "reset_email_sent": True}

EXPECTED_EMAIL_ANALYZE = {
    "message_id": "msg-001",
    "from": "billing@m1crosoft-secure.com",
    "auth": {"spf": "fail", "dkim": "none", "dmarc": "fail"},
    "links": [
        {"url": "https://evil-update.duckdns.org/login", "risk": "high"},
    ],
    "attachments": [
        {
            "filename": "Invoice_April.docm",
            "sha256": (
                "9c2a4e1a7b8d3f6e0c1b5a9d8e7f6c5b"
                "4a3d2e1f0c9b8a7d6e5f4c3b2a1d0e9f"
            ),
            "macros": True,
        },
    ],
    "suspicion_score": 0.94,
}

EXPECTED_EMAIL_CLAWBACK = {
    "message_id": "msg-001",
    "recipients_affected": 47,
    "status": "quarantined",
}

EXPECTED_EMAIL_BLOCK = {
    "sender": "billing@m1crosoft-secure.com",
    "blocked": True,
}


async def _check_siem() -> None:
    siem = await get_connector(TENANT, ConnectorKind.SIEM)
    assert isinstance(siem, MockSiemConnector), (
        f"expected MockSiemConnector, got {type(siem).__name__}"
    )
    assert siem.vendor == "mock"
    assert siem.config.tenant_id == TENANT

    health = await siem.health_check()
    assert health.get("ok") is True
    assert health.get("vendor") == "mock"

    events = await siem.search_events(
        entity="tina.lee", entity_type="user", minutes=60
    )
    assert events["entity"] == "tina.lee"
    assert events["entity_type"] == "user"
    assert events["window_minutes"] == 60
    assert isinstance(events["events"], list)
    assert len(events["events"]) == 3
    event_types = {e["type"] for e in events["events"]}
    assert event_types == {"auth_success", "process_start", "network_connection"}
    # Every event has a ts and a type — the rest is event-type specific.
    for ev in events["events"]:
        assert "ts" in ev
        assert "type" in ev

    related = await siem.get_related_alerts(entity="tina.lee", hours=24)
    assert related == {
        "entity": "tina.lee",
        "related_count": 2,
        "related": [
            {
                "id": "ALR-9821",
                "title": "Suspicious PowerShell encoded command",
                "severity": "high",
            },
            {
                "id": "ALR-9844",
                "title": "Outbound to known TOR exit node",
                "severity": "high",
            },
        ],
    }
    print("OK  SIEM mock: health_check, search_events, get_related_alerts")


async def _check_edr() -> None:
    edr = await get_connector(TENANT, ConnectorKind.EDR)
    assert isinstance(edr, MockEdrConnector), (
        f"expected MockEdrConnector, got {type(edr).__name__}"
    )
    assert edr.vendor == "mock"

    health = await edr.health_check()
    assert health.get("ok") is True

    tree = await edr.get_process_tree(host="win10-prod-04")
    assert tree == EXPECTED_EDR_TREE, "process_tree shape drifted from legacy"

    isolate = await edr.isolate_host(
        host="win10-prod-04", reason="credential theft suspected"
    )
    assert isolate == EXPECTED_EDR_ISOLATE

    # release_host is SDK-only (no legacy handler); just validate shape.
    release = await edr.release_host(host="win10-prod-04")
    assert release["host"] == "win10-prod-04"
    assert release["isolated"] is False
    assert release["ticket"].startswith("REL-")

    quarantine = await edr.quarantine_file(sha256="0" * 64)
    assert quarantine == EXPECTED_EDR_QUARANTINE

    kill = await edr.kill_process(host="win10-prod-04", pid=6190)
    assert kill == EXPECTED_EDR_KILL

    print(
        "OK  EDR mock: health_check, get_process_tree, isolate_host, "
        "release_host, quarantine_file, kill_process"
    )


async def _check_idp() -> None:
    idp = await get_connector(TENANT, ConnectorKind.IDP)
    assert isinstance(idp, MockIdpConnector), (
        f"expected MockIdpConnector, got {type(idp).__name__}"
    )
    assert idp.vendor == "mock"

    health = await idp.health_check()
    assert health.get("ok") is True

    user = await idp.get_user(user="tina.lee")
    assert user == EXPECTED_IDP_USER, "idp.get_user shape drifted from legacy"

    revoke = await idp.revoke_sessions(user="tina.lee")
    assert revoke == EXPECTED_IDP_REVOKE

    disable = await idp.disable_user(
        user="tina.lee", reason="credential theft suspected"
    )
    assert disable == EXPECTED_IDP_DISABLE

    reset = await idp.reset_password(user="tina.lee")
    assert reset == EXPECTED_IDP_RESET

    print(
        "OK  IDP mock: health_check, get_user, revoke_sessions, "
        "disable_user, reset_password"
    )


async def _check_email() -> None:
    email = await get_connector(TENANT, ConnectorKind.EMAIL)
    assert isinstance(email, MockEmailConnector), (
        f"expected MockEmailConnector, got {type(email).__name__}"
    )
    assert email.vendor == "mock"

    health = await email.health_check()
    assert health.get("ok") is True

    analyze = await email.analyze_message(message_id="msg-001")
    assert analyze == EXPECTED_EMAIL_ANALYZE, (
        "email.analyze_message shape drifted from legacy"
    )

    clawback = await email.clawback_message(message_id="msg-001")
    assert clawback == EXPECTED_EMAIL_CLAWBACK

    block = await email.block_sender(sender="billing@m1crosoft-secure.com")
    assert block == EXPECTED_EMAIL_BLOCK

    print(
        "OK  EMAIL mock: health_check, analyze_message, clawback_message, "
        "block_sender"
    )


async def _check_aclose_noop() -> None:
    # Default aclose() is a no-op; the cache resets call it on every
    # evicted instance, so it must at minimum not raise.
    evicted = await reset_connector_cache()
    assert evicted >= 4, f"expected >=4 cached mock connectors, got {evicted}"
    print(f"OK  aclose() is a safe no-op across {evicted} evictions")


async def _main() -> None:
    init_db()
    await _check_siem()
    await _check_edr()
    await _check_idp()
    await _check_email()
    await _check_aclose_noop()
    print("\nALL MOCK CONNECTOR CHECKS PASSED")


if __name__ == "__main__":
    asyncio.run(_main())
