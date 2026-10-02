"""Scheduled hunts read the tenant's own events, not a fixture.

Maturity: parity 6.1, and part of what takes the **68-hunt YAML
library** off Alpha.

Lives in its own file rather than beside the lake suite because both
services call their package `app`: running from `services/api` resolves
`app.hunt` to nothing. Two services, one module name, so one suite each.

What was wrong
--------------
The only implemented telemetry provider was `synthetic`, so every
scheduled hunt on every deployment ran against
`services/agents/tests/eval_data/synthetic_telemetry.jsonl`. The hunts
produced findings about events no customer had, and found nothing about
the events they did. `ingest` existed as a name and returned an empty
list.

The rule the replacement is built on
--------------------------------------
An unreachable lake returns nothing and says so. There is no fallback to
the fixture. A scheduled hunt that quietly reports findings from
synthetic telemetry is worse than one that reports nothing, because an
operator cannot tell the two apart and one of them is fabricated data
presented as their own estate.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

TENANT_A = uuid.UUID("11111111-1111-1111-1111-111111111111")
TENANT_B = uuid.UUID("22222222-2222-2222-2222-222222222222")

# `app.hunt.lake_source` reads CLICKHOUSE_* the way the fusion writer and
# the API do. This suite is configured with ISOLATION_CLICKHOUSE_*, so
# bridge them at import rather than teaching the production module a
# second spelling it would only use in tests.
if os.environ.get("ISOLATION_CLICKHOUSE_HOST"):
    os.environ.setdefault("CLICKHOUSE_HOST", os.environ["ISOLATION_CLICKHOUSE_HOST"])
    os.environ.setdefault("CLICKHOUSE_PORT", os.environ.get("ISOLATION_CLICKHOUSE_PORT", "9000"))
    os.environ.setdefault("CLICKHOUSE_USER", os.environ.get("ISOLATION_CLICKHOUSE_USER", "default"))
    os.environ.setdefault("CLICKHOUSE_PASSWORD", os.environ.get("ISOLATION_CLICKHOUSE_PASSWORD", ""))
    os.environ.setdefault("CLICKHOUSE_DATABASE", "aisoc")


def _client():  # noqa: ANN202
    host = os.environ.get("ISOLATION_CLICKHOUSE_HOST", "").strip()
    if not host:
        pytest.skip("ISOLATION_CLICKHOUSE_HOST is not set; this suite needs a live ClickHouse")
    driver = pytest.importorskip("clickhouse_driver")
    return driver.Client(
        host=host,
        port=int(os.environ.get("ISOLATION_CLICKHOUSE_PORT", "9000")),
        user=os.environ.get("ISOLATION_CLICKHOUSE_USER", "default"),
        password=os.environ.get("ISOLATION_CLICKHOUSE_PASSWORD", ""),
    )


@pytest.fixture(scope="module")
def lake():
    """The product's own schema, seeded for two tenants.

    `001_init.sql` verbatim, for the reason the lake suite records: a
    test that writes its own CREATE TABLE cannot notice the real one has
    drifted.
    """
    client = _client()
    root = Path(os.environ.get("ISOLATION_REPO_ROOT", "."))
    ddl = (root / "services" / "api" / "clickhouse" / "001_init.sql").read_text(encoding="utf-8")
    lines = [ln for ln in ddl.splitlines() if not ln.strip().startswith("--")]
    for statement in (s.strip() for s in "\n".join(lines).split(";")):
        if statement:
            client.execute(statement)

    client.execute("TRUNCATE TABLE IF EXISTS aisoc.raw_events")
    now = datetime.now(UTC).replace(tzinfo=None)
    client.execute(
        "INSERT INTO aisoc.raw_events "
        "(tenant_id, event_time, class_uid, category_uid, severity_id, severity, "
        "src_hostname, user_name, process_name, raw_payload) VALUES",
        [
            (
                TENANT_A,
                now,
                2001,
                2,
                4,
                "high",
                "tenant-a-host-1",
                "j.doe",
                "powershell.exe",
                '{"cmdline": "-enc AAA"}',
            ),
            (TENANT_A, now, 2001, 2, 4, "high", "tenant-a-host-2", "j.doe", "cmd.exe", "{}"),
            (TENANT_B, now, 2001, 2, 4, "high", "tenant-b-host-1", "other", "cmd.exe", "{}"),
        ],
    )
    yield client
    client.execute("TRUNCATE TABLE IF EXISTS aisoc.raw_events")


class TestItReadsTenantData:
    def test_a_tenants_hunt_reads_its_own_events(self, lake) -> None:  # noqa: ANN001
        from app.hunt.lake_source import fetch_recent_events

        hosts = {e.get("host") for e in fetch_recent_events(str(TENANT_A))}
        assert hosts == {"tenant-a-host-1", "tenant-a-host-2"}, hosts

    def test_it_does_not_read_another_tenants(self, lake) -> None:  # noqa: ANN001
        from app.hunt.lake_source import fetch_recent_events

        hosts = {e.get("host") for e in fetch_recent_events(str(TENANT_A))}
        assert "tenant-b-host-1" not in hosts

    def test_the_other_tenant_has_data_so_the_above_is_a_real_negative(self, lake) -> None:  # noqa: ANN001
        """Without this, tenant A's exclusion could mean B has nothing."""
        from app.hunt.lake_source import fetch_recent_events

        assert fetch_recent_events(str(TENANT_B)), "tenant B has no rows, so excluding them from A's read proves nothing"


class TestTheMatchNamespace:
    def test_a_nested_vendor_payload_is_flattened(self, lake) -> None:  # noqa: ANN001
        """Connectors nest their payload under the envelope, and a
        matcher doing a flat lookup reads `None` — which is how 663 of
        825 loaded rules once matched on fields that were never
        visible."""
        from app.hunt.lake_source import fetch_recent_events

        cmdlines = {e.get("cmdline") for e in fetch_recent_events(str(TENANT_A)) if e.get("cmdline")}
        assert "-enc AAA" in cmdlines, f"the nested vendor payload did not reach the match namespace: {cmdlines!r}"

    def test_a_row_with_no_ip_does_not_crash_the_read(self, lake) -> None:  # noqa: ANN001
        """`source_ip` and `dest_ip` are IPv6 columns, and the driver
        raises `AddressValueError` decoding the zero-length packed
        address an unset column yields. A row with no IP is the common
        case for identity and SaaS events, so the natural read crashed on
        ordinary data — the query casts with `IPv6NumToString`."""
        from app.hunt.lake_source import fetch_recent_events

        events = fetch_recent_events(str(TENANT_A))
        assert events, "the read returned nothing for rows that have no IP set"
        assert all(e.get("src_ip") == "" for e in events)


class TestItRefusesToFabricate:
    def test_an_unreachable_lake_raises_rather_than_returning_the_fixture(self) -> None:
        """The honesty rule this module is built on.

        The scheduler catches this, logs it, and records an empty run —
        so "the lake is down" and "this tenant had no events" stay
        distinguishable instead of both looking like a quiet success.
        """
        from app.hunt.lake_source import fetch_recent_events

        previous = os.environ.get("CLICKHOUSE_PORT")
        os.environ["CLICKHOUSE_PORT"] = "1"
        try:
            with pytest.raises(Exception):  # noqa: B017, PT011
                fetch_recent_events(str(TENANT_A))
        finally:
            if previous is None:
                os.environ.pop("CLICKHOUSE_PORT", None)
            else:
                os.environ["CLICKHOUSE_PORT"] = previous

    def test_the_scheduler_turns_that_into_an_empty_run_not_the_fixture(self) -> None:
        """The other half, at the call site.

        `_load_telemetry` must not quietly substitute the synthetic
        corpus when the lake is unreachable.
        """
        from app.hunt.scheduler import _load_telemetry

        previous = os.environ.get("CLICKHOUSE_PORT")
        os.environ["CLICKHOUSE_PORT"] = "1"
        try:
            events = _load_telemetry(str(TENANT_A))
        finally:
            if previous is None:
                os.environ.pop("CLICKHOUSE_PORT", None)
            else:
                os.environ["CLICKHOUSE_PORT"] = previous

        assert events == [], (
            f"an unreachable lake produced {len(events)} events. If those came from the "
            "synthetic corpus, the scheduler is reporting fixture findings as the "
            "tenant's own."
        )
