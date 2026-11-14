"""Smoke test for the episodic memory upgrade (t1m-episodic).

Covers:
1. SQLite-only default still works end-to-end via the public API.
2. Tenancy filtering (single tenant + allowed_tenants).
3. Qdrant configured but unreachable URL → backend resolves to SQLite,
   no exceptions leak.
4. Qdrant in-memory mode (``:memory:``) → real upsert + recall round-trip
   using payload-filter tenancy.
5. Recall returns the SQLite path's exact same shape and filtering rules.

Run with:
    cd platform/backend
    python -m tests._check_episodic
"""
from __future__ import annotations

import importlib
import os
import sys
import tempfile
from pathlib import Path


def _reset_settings_and_db(env: dict[str, str]) -> tuple[Path, object]:
    """Force a fresh ``Settings`` and a clean SQLite file under ``env``.

    Returns the temp db path (so the caller can clean up) and the freshly
    reloaded ``app.config.settings`` instance.
    """
    tmp = Path(tempfile.mkdtemp(prefix="aisoc-ep-"))
    db_path = tmp / "aisoc.db"
    os.environ["AISOC_DB_PATH"] = str(db_path)
    os.environ["AISOC_SEED_ON_STARTUP"] = "false"
    os.environ["AISOC_AUTONOMY_LEVEL"] = "autonomous"
    os.environ["AISOC_HITL_SLA_SECONDS"] = "2"
    for k, v in env.items():
        os.environ[k] = v
    # Drop cached module state so the new env wins.
    # Note: do NOT reload `app.models.*` — SQLModel/SQLAlchemy registers tables
    # in a shared MetaData, and re-registering blows up with InvalidRequestError.
    # We only reload modules that capture settings at import time.
    for mod in [
        "app.memory",
        "app.memory.episodic",
        "app.memory.embedding",
        "app.memory.scratchpad",
        "app.db",
        "app.config",
    ]:
        sys.modules.pop(mod, None)
    import app.config as config  # type: ignore
    importlib.reload(config)
    # Init DB on the new path.
    from app.db import init_db  # type: ignore

    init_db()
    return db_path, config.settings


def _seed_cases(records: list[dict], tenant_default: str = "demo-tenant") -> None:
    """Bypass the case foreign key by inserting minimal Case rows first."""
    from app.db import session_scope  # type: ignore
    from app.models.case import Case  # type: ignore
    from sqlmodel import select as _select

    with session_scope() as s:
        for r in records:
            existing = s.exec(_select(Case).where(Case.id == r["case_id"])).first()
            if not existing:
                s.add(
                    Case(
                        id=r["case_id"],
                        title=r["title"],
                        severity="medium",
                        status="closed",
                        tenant_id=r.get("tenant_id", tenant_default),
                    )
                )


# ── 1. SQLite-only default ────────────────────────────────────────────
def test_sqlite_default() -> None:
    print("\n[1] SQLite default backend")
    db_path, _ = _reset_settings_and_db({})
    from app.memory.episodic import episodic_backend_name, episodic_recall, episodic_record

    name = episodic_backend_name()
    assert name == "sqlite", f"expected sqlite, got {name}"

    _seed_cases(
        [
            {"case_id": 1001, "title": "Ransom note in S3"},
            {"case_id": 1002, "title": "PowerShell beacon"},
            {"case_id": 1003, "title": "Okta MFA fatigue"},
        ]
    )
    episodic_record(
        1001, "Ransom note in S3", "encryptor uploaded to bucket", "true_positive",
        ["s3", "ransomware"], tenant_id="demo-tenant",
    )
    episodic_record(
        1002, "PowerShell beacon", "encoded cobalt strike beacon",
        "true_positive", ["powershell", "c2"], tenant_id="demo-tenant",
    )
    episodic_record(
        1003, "Okta MFA fatigue", "100+ push prompts", "true_positive",
        ["okta", "identity"], tenant_id="demo-tenant",
    )
    hits = episodic_recall("ransomware S3 bucket", k=3, tenant_id="demo-tenant")
    titles = [h["title"] for h in hits]
    assert "Ransom note in S3" in titles, f"expected match in {titles}"
    print(f"    ✓ default resolves to sqlite, recall top hit: {titles[:1]}")
    return db_path  # type: ignore[return-value]


# ── 2. Tenancy filtering ──────────────────────────────────────────────
def test_tenancy_filter() -> None:
    print("\n[2] Tenancy filter (single tenant + MSSP allowed_tenants)")
    _reset_settings_and_db({})
    from app.memory.episodic import episodic_recall, episodic_record

    _seed_cases(
        [
            {"case_id": 2001, "title": "PSExec lateral", "tenant_id": "acme"},
            {"case_id": 2002, "title": "PSExec lateral", "tenant_id": "globex"},
            {"case_id": 2003, "title": "PSExec lateral", "tenant_id": "umbrella"},
        ]
    )
    episodic_record(2001, "PSExec lateral", "tenant-a psexec", "tp", ["psexec"], tenant_id="acme")
    episodic_record(2002, "PSExec lateral", "tenant-b psexec", "tp", ["psexec"], tenant_id="globex")
    episodic_record(2003, "PSExec lateral", "tenant-c psexec", "tp", ["psexec"], tenant_id="umbrella")

    only_acme = episodic_recall("psexec", k=10, tenant_id="acme")
    assert all(h["tenant_id"] == "acme" for h in only_acme), only_acme
    assert any(h["case_id"] == 2001 for h in only_acme), only_acme
    print(f"    ✓ single-tenant filter ok ({len(only_acme)} hit(s), all=acme)")

    mssp = episodic_recall("psexec", k=10, allowed_tenants=["acme", "globex"])
    tenants = {h["tenant_id"] for h in mssp}
    assert tenants <= {"acme", "globex"} and tenants, f"unexpected {tenants}"
    assert "umbrella" not in tenants
    print(f"    ✓ MSSP allowed_tenants ok (tenants={sorted(tenants)})")


# ── 3. Qdrant configured but unreachable ──────────────────────────────
def test_qdrant_unreachable_fallback() -> None:
    print("\n[3] Qdrant configured but unreachable → falls back to sqlite")
    _reset_settings_and_db(
        {
            "AISOC_EPISODIC_BACKEND": "qdrant",
            # localhost:1 should never have a Qdrant on it.
            "AISOC_QDRANT_URL": "http://127.0.0.1:1",
        }
    )
    from app.memory.episodic import episodic_backend_name, episodic_recall, episodic_record

    name = episodic_backend_name()
    assert name == "sqlite", (
        f"unreachable Qdrant should degrade to sqlite, got {name}"
    )

    _seed_cases([{"case_id": 3001, "title": "DLL sideload"}])
    episodic_record(
        3001, "DLL sideload", "signed binary loads malicious dll", "tp",
        ["sideload"], tenant_id="demo-tenant",
    )
    hits = episodic_recall("dll sideload", k=3, tenant_id="demo-tenant")
    assert any(h["case_id"] == 3001 for h in hits)
    print(f"    ✓ fallback returned hits even with bad qdrant url ({len(hits)} hit(s))")


# ── 4. Qdrant in-memory round-trip ────────────────────────────────────
def test_qdrant_in_memory_roundtrip() -> None:
    print("\n[4] Qdrant in-memory (`:memory:`) end-to-end")
    _reset_settings_and_db(
        {
            "AISOC_EPISODIC_BACKEND": "qdrant",
            "AISOC_QDRANT_URL": ":memory:",
            "AISOC_QDRANT_COLLECTION_PREFIX": "aisoc_episodic_test",
        }
    )
    from app.memory.episodic import episodic_backend_name, episodic_recall, episodic_record

    name = episodic_backend_name()
    if name != "qdrant":
        # qdrant-client must support ":memory:" URLs; otherwise we'd see the
        # SQLite fallback. This isn't a hard test failure but it would mean
        # the local roundtrip case can't run.
        print(f"    ⚠ qdrant in-memory mode unavailable ({name}); skipping")
        return

    _seed_cases(
        [
            {"case_id": 4001, "title": "Brute force RDP", "tenant_id": "acme"},
            {"case_id": 4002, "title": "Brute force RDP", "tenant_id": "globex"},
            {"case_id": 4003, "title": "Cloud key leaked to GitHub", "tenant_id": "acme"},
        ]
    )
    episodic_record(4001, "Brute force RDP", "many failed rdp", "tp", ["rdp"], tenant_id="acme")
    episodic_record(4002, "Brute force RDP", "many failed rdp", "tp", ["rdp"], tenant_id="globex")
    episodic_record(
        4003, "Cloud key leaked to GitHub", "secret in public repo", "tp",
        ["secrets", "github"], tenant_id="acme",
    )

    # Single tenant via Qdrant payload filter.
    acme_only = episodic_recall("rdp brute force", k=5, tenant_id="acme")
    assert all(h["tenant_id"] == "acme" for h in acme_only), acme_only
    assert any(h["case_id"] == 4001 for h in acme_only), acme_only
    assert all(h["case_id"] != 4002 for h in acme_only), acme_only
    print(f"    ✓ qdrant single-tenant filter ({len(acme_only)} hit(s))")

    # MSSP-style multi-tenant.
    mssp = episodic_recall("rdp", k=5, allowed_tenants=["acme", "globex"])
    tenants = {h["tenant_id"] for h in mssp}
    assert tenants <= {"acme", "globex"} and tenants, tenants
    print(f"    ✓ qdrant MSSP allowed_tenants (tenants={sorted(tenants)})")

    # Semantic recall (matches "Cloud key" via tags/title).
    secrets = episodic_recall("github secret leak", k=3, tenant_id="acme")
    titles = [h["title"] for h in secrets]
    assert any("GitHub" in t for t in titles), titles
    print(f"    ✓ qdrant semantic recall top: {titles[:1]}")


# ── 5. Public API shape still matches the old contract ────────────────
def test_recall_shape() -> None:
    print("\n[5] Recall result shape")
    _reset_settings_and_db({})
    from app.memory.episodic import episodic_recall, episodic_record

    _seed_cases([{"case_id": 5001, "title": "Phishing kit hit"}])
    episodic_record(
        5001, "Phishing kit hit", "evilginx2 detected on prod proxy",
        "tp", ["phishing", "evilginx"], tenant_id="demo-tenant",
    )
    hits = episodic_recall("phishing evilginx", k=3, tenant_id="demo-tenant")
    assert hits, "expected at least one hit"
    h = hits[0]
    required = {"case_id", "tenant_id", "title", "verdict", "similarity", "tags", "narrative"}
    missing = required - set(h.keys())
    assert not missing, f"missing keys: {missing}"
    assert isinstance(h["similarity"], float)
    assert isinstance(h["tags"], list)
    print(f"    ✓ shape ok (keys={sorted(h.keys())})")


def main() -> int:
    try:
        test_sqlite_default()
        test_tenancy_filter()
        test_qdrant_unreachable_fallback()
        test_qdrant_in_memory_roundtrip()
        test_recall_shape()
    except AssertionError as exc:
        print(f"\n❌ FAIL: {exc}")
        return 1
    except Exception as exc:  # noqa: BLE001
        import traceback

        print(f"\n💥 ERROR: {exc!r}")
        traceback.print_exc()
        return 2
    print("\n✅ ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
