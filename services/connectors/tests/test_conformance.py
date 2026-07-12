"""Phase 10 — connector runtime-contract conformance suite.

`test_schemas.py` already gates schema well-formedness. This suite gates the
*runtime contract* the reality audit found ungated — most importantly the
"live Test connection" click-and-connect claim, which had NO gate at all.

Every registered connector must:
  * implement `test_connection` as an async coroutine (the contract behind the
    "live Test connection" button),
  * implement `fetch_alerts` as an async coroutine,
  * declare only valid `Capability` verbs,
  * mark every secret field `type="secret"` so it is vault-encrypted.

And the published conformance matrix must be current (drift gate). Live-vendor
sandbox smoke (actually hitting each API) is a separate future wave; this gates
the contract every connector must satisfy to ship.
"""

from __future__ import annotations

import inspect
import sys
from pathlib import Path

from app.connectors import CONNECTOR_REGISTRY
from app.connectors.base import Capability

# Import the conformance generator by path so the drift assertion uses the same
# code the CLI does.
_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
sys.path.insert(0, str(_SCRIPTS))
import connector_conformance as cc  # noqa: E402

# Secret-shaped field names that MUST be marked type="secret" so the vault
# encrypts them. A field called "api_key" rendered as a plain "string" would
# be stored in the clear — the exact leak this check prevents.
_SECRET_NAME_HINTS = ("secret", "password", "token", "api_key", "apikey", "private_key", "client_secret")


def test_registry_not_empty():
    assert CONNECTOR_REGISTRY, "connector registry is empty"


def test_every_connector_implements_async_test_connection():
    """The 'live Test connection' contract — the capability that had NO gate."""
    offenders = [cid for cid, cls in CONNECTOR_REGISTRY.items() if not inspect.iscoroutinefunction(cls.test_connection)]
    assert offenders == [], f"connectors missing an async test_connection: {offenders}"


def test_every_connector_implements_async_fetch_alerts():
    offenders = [cid for cid, cls in CONNECTOR_REGISTRY.items() if not inspect.iscoroutinefunction(cls.fetch_alerts)]
    assert offenders == [], f"connectors missing an async fetch_alerts: {offenders}"


def test_every_declared_capability_is_a_valid_verb():
    for cid, cls in CONNECTOR_REGISTRY.items():
        for cap in cls.capabilities():
            assert isinstance(cap, Capability), f"{cid} declares a non-Capability verb: {cap!r}"


def test_secret_shaped_fields_are_marked_secret():
    """A credential field stored as plain 'string' bypasses the vault. Any
    field whose name looks like a secret must be type='secret'."""
    offenders: list[str] = []
    for cid, cls in CONNECTOR_REGISTRY.items():
        for f in cls.schema().fields:
            name = f.name.lower()
            if any(hint in name for hint in _SECRET_NAME_HINTS) and f.type != "secret":
                offenders.append(f"{cid}.{f.name} (type={f.type})")
    assert offenders == [], f"secret-shaped fields not marked type='secret': {offenders}"


def test_connector_identity_matches_registry_key():
    for cid, cls in CONNECTOR_REGISTRY.items():
        assert cls.connector_id == cid, f"{cls.__name__}.connector_id {cls.connector_id!r} != registry key {cid!r}"
        assert cls.connector_name, f"{cid}: connector_name is empty"


def test_published_conformance_matrix_is_current():
    """Drift gate: the committed matrix must match the registry."""
    data = cc.compute()
    rendered = cc.render_markdown(data)
    committed = cc.DOC.read_text(encoding="utf-8")
    assert committed.strip() == rendered.strip(), "docs/connectors/conformance-matrix.md is stale — run scripts/connector_conformance.py"


def test_all_connectors_conform():
    data = cc.compute()
    assert data["conforming"] == data["total"], f"only {data['conforming']}/{data['total']} connectors conform to the runtime contract"
