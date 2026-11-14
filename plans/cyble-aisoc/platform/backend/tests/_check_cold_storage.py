"""Smoke test: tiered cold storage + query-on-cold tool (t6-cold-storage).

Covers:

* Classification — events older than ``cold_threshold_days`` land
  in cold; events older than ``warm_threshold_days`` land in warm;
  fresh events stay hot (no roll-off write happens).
* Persistence — warm/cold rows show up on disk in JSON Lines and
  are visible via :meth:`TieredArchive.list_batches`.
* Query parser — supported grammar parses; unsupported clauses
  raise :class:`ValueError`.
* Query engine — predicates filter correctly; LIMIT truncates
  responses and surfaces ``truncated=True``.
* Tool registry — the ``cold_archive.query`` tool is registered
  with risk class READ.
* HTTP surface — stats / batches / query / archive ingest all
  work, archive ingest is admin-gated.
"""
from __future__ import annotations

import os
import tempfile
from datetime import datetime, timedelta, timezone

os.environ["AISOC_AUTH_DISABLED"] = "1"
os.environ["AISOC_LLM_PROVIDER"] = "mock"
TMP_ROOT = tempfile.mkdtemp(prefix="aisoc-cold-")
os.environ["AISOC_COLD_STORAGE_ROOT"] = TMP_ROOT
DB_FILE = tempfile.NamedTemporaryFile(prefix="aisoc-cold-", suffix=".db", delete=False)
DB_FILE.close()
os.environ["AISOC_DB_PATH"] = DB_FILE.name

from pathlib import Path  # noqa: E402

from fastapi.testclient import TestClient  # noqa: E402

from app.cold_storage import (  # noqa: E402
    StorageTier,
    TieredArchive,
    parse_query,
    query_cold_archive,
    write_demo_archive,
)
from app.cold_storage.archive import cold_archive  # noqa: E402
from app.cold_storage.query import LocalQueryEngine, set_query_engine  # noqa: E402
from app.config import settings  # noqa: E402
from app.main import app  # noqa: E402
from app.models.tool_call import RiskClass  # noqa: E402
from app.security.jwt import issue_tenant_token  # noqa: E402
from app.tools.registry import registry as tool_registry  # noqa: E402


def _expect(condition: bool, msg: str) -> None:
    if not condition:
        raise AssertionError(msg)


def _classification_smoke() -> None:
    archive = TieredArchive(
        root=Path(TMP_ROOT) / "classify",
        warm_threshold_days=7,
        cold_threshold_days=30,
    )

    now = datetime.now(timezone.utc)
    fresh_tier = archive.archive(
        {
            "tenant_id": "t-cold",
            "event_time": now.isoformat(),
            "event_class": "auth",
            "outcome": "failure",
        }
    )
    _expect(fresh_tier == StorageTier.HOT, f"fresh should be hot, got {fresh_tier}")

    warm_tier = archive.archive(
        {
            "tenant_id": "t-cold",
            "event_time": (now - timedelta(days=10)).isoformat(),
            "event_class": "auth",
            "outcome": "failure",
            "src_user": "alice",
        }
    )
    _expect(warm_tier == StorageTier.WARM, f"10d should be warm, got {warm_tier}")

    cold_tier = archive.archive(
        {
            "tenant_id": "t-cold",
            "event_time": (now - timedelta(days=60)).isoformat(),
            "event_class": "process_spawn",
            "rare_process": True,
            "src_host": "host-1",
        }
    )
    _expect(cold_tier == StorageTier.COLD, f"60d should be cold, got {cold_tier}")

    warm_batches = archive.list_batches("t-cold", tier=StorageTier.WARM)
    cold_batches = archive.list_batches("t-cold", tier=StorageTier.COLD)
    _expect(len(warm_batches) == 1 and warm_batches[0].rows == 1, "warm batch shape")
    _expect(len(cold_batches) == 1 and cold_batches[0].rows == 1, "cold batch shape")


def _query_parser_smoke() -> None:
    parsed = parse_query("SELECT * FROM tenant.t-1 WHERE outcome = 'failure' LIMIT 5")
    _expect(parsed.tenant_id == "t-1", f"tenant_id parse: {parsed}")
    _expect(len(parsed.predicates) == 1, f"predicate parse: {parsed}")
    _expect(parsed.predicates[0].field == "outcome", "field name parse")
    _expect(parsed.predicates[0].value == "failure", "literal parse")
    _expect(parsed.limit == 5, "limit parse")

    parsed = parse_query("SELECT * FROM tenant.t-1 WHERE __tier = 'warm'")
    _expect(parsed.tier == StorageTier.WARM, f"__tier parse: {parsed}")
    _expect(parsed.limit == 100, "default limit")
    _expect(parsed.predicates == (), "no predicate after stripping __tier")

    try:
        parse_query("SELECT count(*) FROM tenant.t-1")
    except ValueError:
        pass
    else:
        raise AssertionError("count(*) should not parse")

    try:
        parse_query("SELECT * FROM tenant.t-1 WHERE x > 5")
    except ValueError:
        pass
    else:
        raise AssertionError("inequality predicates should not parse")


def _query_smoke() -> None:
    cold_archive.clear_tenant("demo-t6")
    write_demo_archive(tenant_id="demo-t6")
    set_query_engine(LocalQueryEngine(archive=cold_archive))

    # Cold tier — 3 rows seeded.
    result = query_cold_archive(
        query="SELECT * FROM tenant.demo-t6 WHERE __tier = 'cold' LIMIT 10"
    )
    _expect(result["row_count"] == 3, f"cold rows: {result}")
    _expect(result["tier"] == StorageTier.COLD, f"tier mismatch: {result}")

    # Predicate filtering.
    filtered = query_cold_archive(
        query=(
            "SELECT * FROM tenant.demo-t6 "
            "WHERE __tier = 'cold' AND src_host = 'host-1' LIMIT 10"
        )
    )
    _expect(filtered["row_count"] == 3, f"predicate match: {filtered}")

    no_match = query_cold_archive(
        query=(
            "SELECT * FROM tenant.demo-t6 "
            "WHERE __tier = 'cold' AND src_host = 'never' LIMIT 10"
        )
    )
    _expect(no_match["row_count"] == 0, f"no-match query: {no_match}")

    # Limit truncates.
    truncated = query_cold_archive(
        query="SELECT * FROM tenant.demo-t6 WHERE __tier = 'cold' LIMIT 1"
    )
    _expect(truncated["row_count"] == 1, "limit should reduce rows")
    _expect(truncated["truncated"], "truncated should be True at limit")

    # Tenant cross-check on the tool wrapper.
    try:
        query_cold_archive(
            query="SELECT * FROM tenant.other-tenant LIMIT 1",
            tenant_id="demo-t6",
        )
    except ValueError:
        pass
    else:
        raise AssertionError("cross-tenant query should be rejected by tool")


def _tool_registry_smoke() -> None:
    tool_def = tool_registry.get("cold_archive.query")
    _expect(tool_def is not None, "cold_archive.query not registered")
    _expect(
        tool_def.risk_class == RiskClass.READ,
        f"wrong risk class: {tool_def.risk_class}",
    )
    _expect(
        tool_def.integration == "cold_archive",
        f"wrong integration: {tool_def.integration}",
    )


def _api_smoke() -> None:
    cold_archive.clear_tenant(settings.default_tenant)
    write_demo_archive(tenant_id=settings.default_tenant)
    set_query_engine(LocalQueryEngine(archive=cold_archive))

    admin_token = issue_tenant_token(
        tenant_id=settings.default_tenant,
        subject="cold-admin",
        roles=["admin"],
    )
    headers = {"Authorization": f"Bearer {admin_token}"}

    with TestClient(app) as client:
        r = client.get("/cold-storage/stats", headers=headers)
        _expect(r.status_code == 200, f"stats 200 expected, got {r.status_code}")

        r = client.get("/cold-storage/batches?tier=cold", headers=headers)
        _expect(r.status_code == 200, "batches 200 expected")
        body = r.json()
        _expect(body["count"] >= 1, f"expected at least one cold batch: {body}")

        r = client.post(
            "/cold-storage/query",
            json={
                "query": (
                    f"SELECT * FROM tenant.{settings.default_tenant} "
                    "WHERE __tier = 'cold' LIMIT 5"
                )
            },
            headers=headers,
        )
        _expect(r.status_code == 200, f"query 200 expected, got {r.status_code} {r.text}")
        body = r.json()
        _expect(body["row_count"] >= 1, f"expected rows in query result: {body}")

        # Reject malformed queries with 400.
        r = client.post(
            "/cold-storage/query",
            json={"query": "DROP TABLE events"},
            headers=headers,
        )
        _expect(r.status_code == 400, "malformed query should 400")

        # Admin-gated archive ingest.
        analyst_token = issue_tenant_token(
            tenant_id=settings.default_tenant,
            subject="analyst-1",
            roles=["analyst"],
        )
        old_event_time = (datetime.now(timezone.utc) - timedelta(days=45)).isoformat()
        r = client.post(
            "/cold-storage/archive",
            json={
                "event_time": old_event_time,
                "event_class": "auth",
                "extra": {"outcome": "success"},
            },
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        _expect(r.status_code == 403, f"non-admin archive should 403, got {r.status_code}")

        r = client.post(
            "/cold-storage/archive",
            json={
                "event_time": old_event_time,
                "event_class": "auth",
                "extra": {"outcome": "success"},
            },
            headers=headers,
        )
        _expect(r.status_code == 200, f"admin archive 200 expected, got {r.status_code} {r.text}")
        body = r.json()
        _expect(body["tier"] == StorageTier.COLD, f"tier wrong on backfill: {body}")


def main() -> None:
    _classification_smoke()
    _query_parser_smoke()
    _query_smoke()
    _tool_registry_smoke()
    _api_smoke()
    print("ok: cold-storage smoke")


if __name__ == "__main__":
    main()
