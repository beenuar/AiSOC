"""Smoke test for the TenantConnector SQLModel + secrets sealing."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

# Run in a throwaway directory so the dev secrets key + sqlite DB don't
# pollute the workspace.
_tmp = tempfile.mkdtemp(prefix="aisoc_tc_")
os.chdir(_tmp)
Path("data").mkdir(exist_ok=True)
# Force a clean settings load before app modules import config.
os.environ.pop("AISOC_CONNECTOR_SECRETS_KEY", None)
os.environ["AISOC_DB_PATH"] = str(Path(_tmp) / "data" / "aisoc_test.db")

# Ensure the backend package is importable when this file is run directly.
HERE = Path(__file__).resolve()
BACKEND_ROOT = HERE.parent.parent
sys.path.insert(0, str(BACKEND_ROOT))

from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from app.connectors.sdk.base import ConnectorConfig, ConnectorKind
from app.db import engine, init_db
from app.models.tenant_connector import TenantConnector


def main() -> None:
    init_db()

    # 1. Insert a connector with sealed secrets.
    with Session(engine) as s:
        row = TenantConnector(
            tenant_id="demo-tenant",
            kind=ConnectorKind.SIEM.value,
            vendor="splunk",
            params={"host": "https://splunk.example.com", "index": "main"},
        )
        row.set_secrets({"api_key": "s3cret-token-xyz", "ssh_key": "-----BEGIN..."})
        s.add(row)
        s.commit()
        s.refresh(row)
        inserted_id = row.id

    print(f"[ok] inserted TenantConnector id={inserted_id}")

    # 2. Read back, prove ciphertext is opaque and round-trip works.
    with Session(engine) as s:
        row = s.exec(select(TenantConnector).where(TenantConnector.id == inserted_id)).one()
        sealed_api = row.secrets_encrypted["api_key"]
        assert sealed_api != "s3cret-token-xyz", "secrets stored as plaintext!"
        assert sealed_api.startswith("gAAAAA"), f"not a Fernet token: {sealed_api[:20]}"
        decrypted = row.decrypted_secrets()
        assert decrypted == {
            "api_key": "s3cret-token-xyz",
            "ssh_key": "-----BEGIN...",
        }, f"round-trip mismatch: {decrypted}"
        assert row.secret_names() == ["api_key", "ssh_key"]
    print("[ok] secrets sealed at rest, round-trip decrypts cleanly")

    # 3. to_runtime_config() produces the dataclass with plaintext.
    with Session(engine) as s:
        row = s.exec(select(TenantConnector).where(TenantConnector.id == inserted_id)).one()
        rt = row.to_runtime_config()
        assert isinstance(rt, ConnectorConfig)
        assert rt.tenant_id == "demo-tenant"
        assert rt.kind is ConnectorKind.SIEM
        assert rt.vendor == "splunk"
        assert rt.param("host") == "https://splunk.example.com"
        assert rt.secret("api_key") == "s3cret-token-xyz"
        assert rt.enabled is True
    print("[ok] to_runtime_config() yields ConnectorConfig with plaintext secrets")

    # 4. merge_secrets only overwrites listed keys, leaves others intact.
    with Session(engine) as s:
        row = s.exec(select(TenantConnector).where(TenantConnector.id == inserted_id)).one()
        row.merge_secrets({"api_key": "rotated-token-99"})
        s.add(row)
        s.commit()
        s.refresh(row)
        after = row.decrypted_secrets()
        assert after == {
            "api_key": "rotated-token-99",
            "ssh_key": "-----BEGIN...",
        }, f"merge clobbered other keys: {after}"
    print("[ok] merge_secrets rotates one key, preserves the rest")

    # 5. Unique (tenant_id, kind) — second SIEM for same tenant must fail.
    with Session(engine) as s:
        dup = TenantConnector(
            tenant_id="demo-tenant",
            kind=ConnectorKind.SIEM.value,
            vendor="sentinel",
        )
        dup.set_secrets({"client_secret": "second-siem"})
        s.add(dup)
        try:
            s.commit()
        except IntegrityError as e:
            print(f"[ok] unique (tenant_id, kind) constraint fired: {type(e).__name__}")
            s.rollback()
        else:
            raise AssertionError("expected IntegrityError on duplicate (tenant_id, kind)")

    # 6. Same kind under a different tenant is allowed.
    with Session(engine) as s:
        other = TenantConnector(
            tenant_id="other-tenant",
            kind=ConnectorKind.SIEM.value,
            vendor="splunk",
        )
        other.set_secrets({"api_key": "other-tenant-token"})
        s.add(other)
        s.commit()
        s.refresh(other)
        assert other.id is not None
    print("[ok] different tenants can both have a SIEM connector")

    # 7. Different kinds under the same tenant are allowed.
    with Session(engine) as s:
        edr = TenantConnector(
            tenant_id="demo-tenant",
            kind=ConnectorKind.EDR.value,
            vendor="crowdstrike",
            params={"region": "us-1"},
        )
        edr.set_secrets({"client_id": "cs-id", "client_secret": "cs-secret"})
        s.add(edr)
        s.commit()
        s.refresh(edr)
        assert edr.connector_kind is ConnectorKind.EDR
    print("[ok] same tenant can have multiple connectors of different kinds")

    # 8. __repr__ never leaks secret material.
    with Session(engine) as s:
        row = s.exec(select(TenantConnector).where(TenantConnector.id == inserted_id)).one()
        r = repr(row)
        assert "rotated-token-99" not in r, f"plaintext leaked in repr: {r}"
        assert "gAAAAA" not in r, f"ciphertext leaked in repr: {r}"
        print(f"[ok] repr is safe: {r}")

    print("\nall TenantConnector checks passed")


if __name__ == "__main__":
    main()
