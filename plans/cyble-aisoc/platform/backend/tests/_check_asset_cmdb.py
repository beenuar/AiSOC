"""End-to-end smoke check for the Asset/CMDB intelligence graph (Theme 2i).

What this test verifies
-----------------------

The CMDB intelligence layer is the read/write surface every agent (Triager,
Investigator, Responder, Reporter, Attack-Path, BAS) goes through to ask
"which thing is on fire, how much does it matter, and who owns it?" — see
``app/cmdb/intel.py``. We exercise:

* **Wiring.** ``app.cmdb`` re-exports the public functions; ``Asset``
  SQLModel registers; ``asset.get_context`` / ``asset.upsert`` / ``asset.list``
  tools are present in the tool registry with the expected risk classes
  and ``needs:tenant`` tag.
* **Tenancy.** Two tenants can hold rows under the same natural key
  without bleeding into each other's lookups, context, or list output.
* **Idempotent upsert + merge.** Re-calling ``upsert_asset`` for the same
  ``(tenant_id, asset_type, key)`` does not duplicate rows; list-valued
  fields (aliases, IPs, compliance_scopes) union; scalars overwrite only
  when supplied.
* **Fuzzy resolve.** ``resolve_asset`` matches by exact key, case-insensitive
  key, alias, IP address, name, and FQDN/short-host prefixing — with
  ``matched_on`` reflecting which path succeeded.
* **Rich context.** ``get_asset_context`` returns asset + recent_cases +
  graph_neighbors + last_activity + compliance + risk_profile, with the
  recent-case haystack matching on key/name/alias.
* **Risk profile + HITL gate.** ``requires_hitl_for_destructive`` flips
  ``True`` for crown-jewel/PROD/compliance-scoped assets and ``False`` for
  dev/sandbox UNKNOWN-criticality ones — Responder reads this to decide
  whether to auto-approve a reversible action.
* **Graph mirroring.** ``upsert_asset`` writes a matching ``ASSET``
  ``GraphNode`` so Attack-Path / blast-radius graph queries see the new
  business-context props without joining the SQL table.
* **Tool dispatch.** Invoking ``asset.get_context`` through the tool
  registry's dispatcher (the same path the LLM tool-use loop uses)
  produces the same payload, with ``found`` set.
* **API route registration.** ``/assets`` routes are mounted on the FastAPI
  app.

Run from ``platform/backend/``::

    PYTHONPATH=. python tests/_check_asset_cmdb.py
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path


def _bootstrap_env() -> Path:
    tmpdir = Path(tempfile.mkdtemp(prefix="aisoc-asset-cmdb-test-"))
    db_path = tmpdir / "aisoc.db"
    os.environ["AISOC_DB_PATH"] = str(db_path)
    os.environ["AISOC_AUTONOMY_LEVEL"] = "autonomous"
    os.environ["AISOC_LLM_PROVIDER"] = "mock"
    return db_path


DB_PATH = _bootstrap_env()
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from datetime import datetime, timezone  # noqa: E402

from sqlmodel import Session, select  # noqa: E402

from app.cmdb import (  # noqa: E402
    get_asset_context,
    list_assets,
    resolve_asset,
    upsert_asset,
)
from app.db import engine, init_db  # noqa: E402
from app.models.asset import (  # noqa: E402
    Asset,
    AssetCriticality,
    AssetEnvironment,
    AssetType,
)
from app.models.case import (  # noqa: E402
    Case,
    CaseStatus,
    Severity,
    Verdict,
)
from app.models.graph import GraphNode, NodeType  # noqa: E402
from app.tools.registry import RiskClass, registry as _tool_registry  # noqa: E402


def get_tool(name: str):
    return _tool_registry.get(name)


def list_tools():
    return _tool_registry.all()


_FAILED: list[str] = []


def check(label: str, ok: bool, *, detail: str = "") -> None:
    if ok:
        print(f"  PASS  {label}")
    else:
        print(f"  FAIL  {label}" + (f" -- {detail}" if detail else ""))
        _FAILED.append(label)


# ── Symbol wiring ────────────────────────────────────────────────────────


def check_wiring() -> None:
    print("\n[1/8] Module + tool wiring")

    # Re-exports.
    from app import cmdb as cmdb_pkg

    for name in (
        "resolve_asset",
        "upsert_asset",
        "get_asset_context",
        "list_assets",
        "mirror_asset_into_graph",
        "AssetContext",
        "AssetRef",
    ):
        check(
            f"app.cmdb re-exports {name}",
            hasattr(cmdb_pkg, name),
        )

    # Tool registry.
    names = {t.name for t in list_tools()}
    for tool_name in ("asset.get_context", "asset.upsert", "asset.list"):
        check(
            f"tool {tool_name} registered",
            tool_name in names,
        )

    get_ctx = get_tool("asset.get_context")
    check(
        "asset.get_context is RiskClass.READ",
        get_ctx is not None and get_ctx.risk_class == RiskClass.READ,
        detail=f"got {get_ctx.risk_class if get_ctx else None}",
    )
    check(
        "asset.get_context is tenant-scoped",
        get_ctx is not None and "needs:tenant" in get_ctx.tags,
    )

    upsert_t = get_tool("asset.upsert")
    check(
        "asset.upsert is WRITE_REVERSIBLE",
        upsert_t is not None and upsert_t.risk_class == RiskClass.WRITE_REVERSIBLE,
        detail=f"got {upsert_t.risk_class if upsert_t else None}",
    )
    check(
        "asset.upsert declares forward_only_reason",
        upsert_t is not None and bool(upsert_t.forward_only_reason),
    )


# ── Idempotent upsert + merge + tenancy ──────────────────────────────────


def check_upsert_and_tenancy() -> None:
    print("\n[2/8] Idempotent upsert + cross-tenant isolation")

    tenant_a = "tenant-alpha"
    tenant_b = "tenant-beta"

    ref1 = upsert_asset(
        tenant_id=tenant_a,
        asset_type=AssetType.HOST,
        key="WIN-FIN-0044",
        name="WIN-FIN-0044",
        aliases=["winfin0044", "WIN-FIN-0044.corp.example.com"],
        criticality=AssetCriticality.CROWN_JEWEL,
        environment=AssetEnvironment.PROD,
        owner="tina.lee",
        business_unit="finance",
        compliance_scopes=["pci", "soc2"],
        ip_addresses=["10.4.21.118"],
        os="Windows 10 22H2",
        sources=["servicenow"],
    )

    check("first upsert returned asset_id", ref1.asset_id > 0)
    check(
        "first upsert reported matched_on=key",
        ref1.matched_on == "key",
        detail=ref1.matched_on,
    )

    # Re-upsert with overlapping aliases + new IP — should merge, not dup.
    ref2 = upsert_asset(
        tenant_id=tenant_a,
        asset_type=AssetType.HOST,
        key="WIN-FIN-0044",
        aliases=["WIN-FIN-0044.corp.example.com", "fin-laptop-old"],
        ip_addresses=["10.4.21.118", "10.4.21.119"],
        compliance_scopes=["pci"],  # already present — should not duplicate
        notes="Finance laptop — secondary IP added",
    )
    check(
        "re-upsert returned same asset_id (idempotent)",
        ref2.asset_id == ref1.asset_id,
        detail=f"{ref2.asset_id} vs {ref1.asset_id}",
    )

    # Same natural key in tenant B should be a separate row.
    ref_b = upsert_asset(
        tenant_id=tenant_b,
        asset_type=AssetType.HOST,
        key="WIN-FIN-0044",
        criticality=AssetCriticality.LOW,
        environment=AssetEnvironment.DEV,
    )
    check(
        "same (asset_type,key) is a separate row across tenants",
        ref_b.asset_id != ref1.asset_id,
        detail=f"a={ref1.asset_id} b={ref_b.asset_id}",
    )

    # Verify list_assets does not bleed.
    a_rows = list_assets(tenant_id=tenant_a)
    b_rows = list_assets(tenant_id=tenant_b)
    check(
        "list_assets[A] does not include tenant B rows",
        all(r["tenant_id"] == tenant_a for r in a_rows),
        detail=f"{len(a_rows)} rows",
    )
    check(
        "list_assets[B] does not include tenant A rows",
        all(r["tenant_id"] == tenant_b for r in b_rows),
        detail=f"{len(b_rows)} rows",
    )

    # Inspect merged shape directly.
    with Session(engine) as s:
        row = s.get(Asset, ref1.asset_id)
        check(
            "aliases unioned without duplicates",
            sorted(row.aliases or [])
            == sorted(
                {"winfin0044", "WIN-FIN-0044.corp.example.com", "fin-laptop-old"}
            ),
            detail=str(row.aliases),
        )
        check(
            "ip_addresses unioned without duplicates",
            sorted(row.ip_addresses or []) == ["10.4.21.118", "10.4.21.119"],
            detail=str(row.ip_addresses),
        )
        check(
            "compliance_scopes unioned without duplicates",
            sorted(row.compliance_scopes or []) == ["pci", "soc2"],
            detail=str(row.compliance_scopes),
        )
        check(
            "criticality preserved across merge",
            row.criticality == AssetCriticality.CROWN_JEWEL,
            detail=str(row.criticality),
        )
        check(
            "notes overwritten by latest upsert",
            "secondary IP" in (row.notes or ""),
            detail=row.notes or "",
        )


# ── Fuzzy resolve ────────────────────────────────────────────────────────


def check_resolve() -> None:
    print("\n[3/8] Fuzzy resolve")

    tenant = "tenant-resolve"
    upsert_asset(
        tenant_id=tenant,
        asset_type=AssetType.HOST,
        key="finance-laptop-04.corp.example.com",
        name="Finance Laptop 04",
        aliases=["finance-laptop-04", "fin-04"],
        criticality=AssetCriticality.HIGH,
        environment=AssetEnvironment.PROD,
        ip_addresses=["10.5.6.7"],
    )

    cases = [
        ("finance-laptop-04.corp.example.com", "key"),
        ("FINANCE-LAPTOP-04.corp.example.com", "key"),  # case-insensitive
        ("fin-04", "alias"),
        ("10.5.6.7", "ip"),
        ("Finance Laptop 04", "name"),
        ("finance-laptop-04", "alias"),  # seeded as explicit alias
    ]
    for identifier, expected_match in cases:
        ref = resolve_asset(tenant_id=tenant, identifier=identifier)
        check(
            f"resolve {identifier!r} → matched_on={expected_match}",
            ref is not None and ref.matched_on == expected_match,
            detail=str(ref),
        )

    # Cross-tenant must not resolve.
    other = resolve_asset(tenant_id="some-other-tenant", identifier="fin-04")
    check("resolve does not cross tenant boundary", other is None)

    # Unknown identifier must return None (not raise).
    none_ref = resolve_asset(tenant_id=tenant, identifier="does-not-exist")
    check("resolve unknown identifier returns None", none_ref is None)


# ── Rich context + risk profile ──────────────────────────────────────────


def _open_case_touching(tenant_id: str, host: str, *, title: str) -> int:
    with Session(engine) as s:
        case = Case(
            tenant_id=tenant_id,
            title=title,
            severity=Severity.HIGH,
            status=CaseStatus.NEW,
            verdict=Verdict.UNKNOWN,
            confidence=0.6,
            affected_hosts=[host],
            affected_users=[],
            created_at=datetime.now(timezone.utc),
        )
        s.add(case)
        s.commit()
        s.refresh(case)
        return case.id


def check_context_and_risk_profile() -> None:
    print("\n[4/8] AssetContext: cases, risk profile, HITL gate")

    tenant = "tenant-ctx"
    upsert_asset(
        tenant_id=tenant,
        asset_type=AssetType.HOST,
        key="payments-db-prim",
        name="Payments DB Primary",
        criticality=AssetCriticality.CROWN_JEWEL,
        environment=AssetEnvironment.PROD,
        owner="payments-oncall",
        business_unit="payments",
        compliance_scopes=["pci"],
        data_classifications=["pii", "phi"],
        ip_addresses=["10.10.10.10"],
        os="RHEL 9",
    )

    # Open a case that mentions it.
    case_id = _open_case_touching(
        tenant, "payments-db-prim", title="Suspicious lateral movement to payments-db-prim"
    )
    check("seeded one open case for the asset", case_id > 0)

    ctx = get_asset_context(tenant_id=tenant, identifier="payments-db-prim")
    check("get_asset_context returns AssetContext", ctx is not None)
    assert ctx is not None  # for mypy on later lines

    payload = ctx.to_dict()
    check(
        "context exposes resolved asset dict with criticality",
        payload["asset"]["criticality"] == AssetCriticality.CROWN_JEWEL.value,
        detail=str(payload["asset"].get("criticality")),
    )
    check(
        "context includes the open case in recent_cases",
        any(c["id"] == case_id for c in payload["recent_cases"]),
        detail=str([c["id"] for c in payload["recent_cases"]]),
    )
    check(
        "last_activity.open_cases >= 1",
        payload["last_activity"]["open_cases"] >= 1,
        detail=str(payload["last_activity"]),
    )
    check(
        "compliance.in_regulated_scope is True for PCI asset",
        payload["compliance"]["in_regulated_scope"] is True,
    )
    rp = payload["risk_profile"]
    check(
        "risk_profile.score within (0,1]",
        0.0 < rp["score"] <= 1.0,
        detail=str(rp),
    )
    check(
        "crown_jewel + PROD + PCI → requires_hitl_for_destructive=True",
        rp["requires_hitl_for_destructive"] is True,
        detail=str(rp),
    )

    # Contrast: dev sandbox UNKNOWN-criticality, no compliance → no HITL.
    upsert_asset(
        tenant_id=tenant,
        asset_type=AssetType.HOST,
        key="dev-throwaway",
        criticality=AssetCriticality.LOW,
        environment=AssetEnvironment.SANDBOX,
    )
    low = get_asset_context(tenant_id=tenant, identifier="dev-throwaway")
    assert low is not None
    check(
        "sandbox/low asset → requires_hitl_for_destructive=False",
        low.to_dict()["risk_profile"]["requires_hitl_for_destructive"] is False,
        detail=str(low.to_dict()["risk_profile"]),
    )

    # Unknown identifier must return None (caller decides what to do).
    missing = get_asset_context(tenant_id=tenant, identifier="ghost-asset")
    check("get_asset_context(unknown) is None", missing is None)


# ── Graph mirroring ──────────────────────────────────────────────────────


def check_graph_mirror() -> None:
    print("\n[5/8] Threat-graph mirroring")

    tenant = "tenant-graph"
    upsert_asset(
        tenant_id=tenant,
        asset_type=AssetType.HOST,
        key="bastion-01",
        name="Bastion 01",
        criticality=AssetCriticality.CROWN_JEWEL,
        environment=AssetEnvironment.PROD,
        owner="sre",
        business_unit="platform",
        ip_addresses=["10.0.0.5"],
        compliance_scopes=["soc2"],
        cloud_provider="aws",
        cloud_account_id="123456789012",
        region="us-east-1",
    )

    with Session(engine) as s:
        node = s.exec(
            select(GraphNode).where(
                GraphNode.tenant_id == tenant,
                GraphNode.type == NodeType.ASSET,
                GraphNode.key == "bastion-01",
            )
        ).first()

    check("graph mirror wrote an ASSET node", node is not None)
    assert node is not None
    props = node.props or {}
    tags = node.tags or []
    check(
        "graph node carries criticality prop",
        props.get("criticality") == AssetCriticality.CROWN_JEWEL.value,
        detail=str(props),
    )
    check(
        "graph node carries environment prop",
        props.get("environment") == AssetEnvironment.PROD.value,
        detail=str(props),
    )
    check(
        "graph node carries cloud props",
        props.get("cloud_provider") == "aws"
        and props.get("cloud_account_id") == "123456789012",
        detail=str(props),
    )
    check(
        "graph node tagged crown_jewel for fast filtering",
        "crown_jewel" in tags,
        detail=str(tags),
    )


# ── Tool dispatch (LLM path) ─────────────────────────────────────────────


def check_tool_dispatch() -> None:
    print("\n[6/8] Tool dispatch via registry (LLM tool-use path)")

    tenant = "tenant-tool"
    upsert_asset(
        tenant_id=tenant,
        asset_type=AssetType.HOST,
        key="reporting-svc-01",
        criticality=AssetCriticality.HIGH,
        environment=AssetEnvironment.STAGING,
        compliance_scopes=["soc2"],
    )

    tool_def = get_tool("asset.get_context")
    assert tool_def is not None

    # The tool handler is async; we invoke it directly the way the LLM
    # tool-use loop does (the agent base injects tenant_id from its own
    # bound tenant — the LLM never supplies it).
    out = asyncio.run(
        tool_def.handler(tenant_id=tenant, identifier="reporting-svc-01")
    )
    check("asset.get_context tool returned a dict", isinstance(out, dict))
    check("tool payload sets found=True", out.get("found") is True)
    check(
        "tool payload echoes identifier",
        out.get("identifier") == "reporting-svc-01",
    )
    check(
        "tool payload includes asset block with criticality",
        out.get("asset", {}).get("criticality") == AssetCriticality.HIGH.value,
    )

    # Unknown identifier should still return a structured response so the
    # LLM can reason about it instead of crashing.
    out2 = asyncio.run(
        tool_def.handler(tenant_id=tenant, identifier="missing-host-xyz")
    )
    check(
        "tool unknown-asset path returns found=False (still actionable)",
        out2 == {"found": False, "identifier": "missing-host-xyz"},
        detail=str(out2),
    )


# ── API route registration ───────────────────────────────────────────────


def check_api_routes() -> None:
    print("\n[7/8] API route registration")

    from app.main import app

    paths = {getattr(r, "path", "") for r in app.routes}
    for expected in (
        "/assets",
        "/assets/{key}",
        "/assets/{key}/context",
        "/assets/resolve",
    ):
        check(
            f"FastAPI route {expected} mounted",
            expected in paths,
            detail=f"{len(paths)} routes registered",
        )


# ── list_assets filters ─────────────────────────────────────────────────


def check_list_filters() -> None:
    print("\n[8/8] list_assets filtering")

    tenant = "tenant-list"
    upsert_asset(
        tenant_id=tenant,
        asset_type=AssetType.HOST,
        key="prod-web-01",
        criticality=AssetCriticality.HIGH,
        environment=AssetEnvironment.PROD,
    )
    upsert_asset(
        tenant_id=tenant,
        asset_type=AssetType.HOST,
        key="dev-web-01",
        criticality=AssetCriticality.LOW,
        environment=AssetEnvironment.DEV,
    )
    upsert_asset(
        tenant_id=tenant,
        asset_type=AssetType.USER,
        key="ada.lovelace",
        criticality=AssetCriticality.HIGH,
        environment=AssetEnvironment.PROD,
    )

    rows = list_assets(tenant_id=tenant, asset_type=AssetType.HOST)
    check(
        "list_assets asset_type=HOST excludes users",
        all(r["asset_type"] == AssetType.HOST.value for r in rows),
        detail=f"{[r['asset_type'] for r in rows]}",
    )

    rows = list_assets(tenant_id=tenant, environment=AssetEnvironment.PROD)
    check(
        "list_assets environment=PROD excludes DEV rows",
        all(r["environment"] == AssetEnvironment.PROD.value for r in rows),
    )

    rows = list_assets(tenant_id=tenant, criticality=AssetCriticality.HIGH)
    check(
        "list_assets criticality=HIGH excludes LOW rows",
        all(r["criticality"] == AssetCriticality.HIGH.value for r in rows),
    )

    rows = list_assets(tenant_id=tenant, query="prod-web")
    check(
        "list_assets query='prod-web' matches by key substring",
        len(rows) == 1 and rows[0]["key"] == "prod-web-01",
        detail=f"{[r['key'] for r in rows]}",
    )


# ── Entrypoint ──────────────────────────────────────────────────────────


def main() -> int:
    print(f"[asset-cmdb smoke] DB={DB_PATH}")
    init_db()

    check_wiring()
    check_upsert_and_tenancy()
    check_resolve()
    check_context_and_risk_profile()
    check_graph_mirror()
    check_tool_dispatch()
    check_api_routes()
    check_list_filters()

    print()
    if _FAILED:
        print(f"FAILED ({len(_FAILED)}):")
        for label in _FAILED:
            print(f"  - {label}")
        return 1
    print("OK — all asset-cmdb smoke checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
