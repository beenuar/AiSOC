"""The retro-hunt's done-when clause, proven against a live warehouse.

Gap-closure Phase 8.1.

The clause is: *a new IOC injected into the pipeline produces a retro-hunt
alert for a tenant whose recorded lake data contains it, and none for a tenant
whose data does not.* Everything below exists to make that provable rather
than asserted.

Why this test is shaped the way it is
-------------------------------------

The thing that could be wrong is the mapping from an indicator to a lake
column, and that is exactly the kind of wrong a self-authored fixture cannot
find. Roughly 600 of this repository's 825 detection fixtures are synthesised
from the rule they test, which makes replay circular, and the two largest
field-reachability defects in its history both passed their own tests
throughout. So no part of the chain below is re-implemented here:

* the OCSF event is shaped the way ``services/ingest`` emits one, with the
  endpoint blocks and fingerprint list the normaliser produces;
* the lake row comes from ``lake_writer.event_to_row``, the only function in
  production that writes to ``aisoc.raw_events``, loaded from its own file;
* the table is created from ``services/api/clickhouse/001_init.sql``, the DDL
  a deployment actually runs;
* the sweep SQL comes from ``retro_hunt.sql.build_sweep_sql``, the generator
  the service calls.

If the mapping is wrong, this test fails. That is the difference between
proving a sweep matches recorded data and asserting that it does.

Both modules are loaded by path because ``services/api`` and
``services/fusion`` both package their code as a top-level ``app``, so only
one of them can be imported normally in one interpreter. The loader registers
each module in ``sys.modules`` for the duration of its execution, because
``@dataclass`` resolves annotations through it, and removes it afterwards,
because a synthetic name left behind has previously broken 21 unrelated tests
in this repository while every test in its own file passed.

Skips when no ClickHouse is reachable, the same way the rest of this directory
does. It runs for real in ``isolation-live.yml``.
"""

from __future__ import annotations

import importlib.util
import ipaddress
import os
import re
import sys
import uuid
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

# Two tenants. A has the indicator in its recorded data; B does not. The
# done-when clause is a statement about the pair, so neither is meaningful
# alone.
TENANT_A = uuid.UUID("aaaaaaaa-0000-4000-8000-000000000001")
TENANT_B = uuid.UUID("bbbbbbbb-0000-4000-8000-000000000002")

# The indicator a feed publishes. Documentation-range addresses and an
# obviously-synthetic hash, so nothing here resembles a real IOC.
IOC_IP = "203.0.113.77"
IOC_SHA256 = "a" * 64
IOC_DOMAIN = "malicious.example.invalid"
BENIGN_IP = "198.51.100.5"


def _load_by_path(rel: str, alias: str) -> Any:
    """Import one module by file path, leaving ``sys.modules`` as it found it."""
    spec = importlib.util.spec_from_file_location(alias, REPO_ROOT / rel)
    if spec is None or spec.loader is None:  # pragma: no cover - path is fixed
        raise RuntimeError(f"cannot load {rel}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[alias] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(alias, None)
    return module


def _load_sweep_sql() -> Any:
    """Load ``retro_hunt.sql``, which imports ``ioc_fields`` by package path.

    ``sql.py`` does ``from app.services.retro_hunt.ioc_fields import ...``, so
    the package name has to resolve. Registering the two parents as namespace
    modules is enough, and is cheaper and far less fragile than putting the
    whole API service on ``sys.path`` beside the fusion service, which is the
    collision this loader exists to avoid.
    """
    import types  # noqa: PLC0415 - only needed on this path

    created: list[str] = []
    for name in ("app", "app.services", "app.services.retro_hunt"):
        if name not in sys.modules:
            sys.modules[name] = types.ModuleType(name)
            created.append(name)
    try:
        ioc_fields = _load_by_path(
            "services/api/app/services/retro_hunt/ioc_fields.py",
            "app.services.retro_hunt.ioc_fields",
        )
        sys.modules["app.services.retro_hunt.ioc_fields"] = ioc_fields
        sql_module = _load_by_path("services/api/app/services/retro_hunt/sql.py", "app.services.retro_hunt.sql")
        return ioc_fields, sql_module
    finally:
        sys.modules.pop("app.services.retro_hunt.ioc_fields", None)
        for name in created:
            sys.modules.pop(name, None)


def _raw_events_ddl() -> str:
    """The production DDL for ``aisoc.raw_events``, read from the file.

    Trimmed of the ``INDEX`` clauses only: bloom-filter indexes change the
    plan, never the result, and a single-node test container does not need
    them. Everything that decides whether a value matches, above all the
    ``IPv6`` and ``Array(String)`` column types, is used verbatim.
    """
    sql = (REPO_ROOT / "services/api/clickhouse/001_init.sql").read_text(encoding="utf-8")
    match = re.search(r"(CREATE TABLE IF NOT EXISTS aisoc\.raw_events.*?ORDER BY \([^)]*\))", sql, re.DOTALL)
    assert match, "could not find the raw_events DDL; this test must not invent one"
    body = match.group(1)
    return "\n".join(line for line in body.splitlines() if not line.strip().startswith(("INDEX ", "--")))


def _ocsf_event(*, tenant: uuid.UUID, src_ip: str, sha256: str | None = None, dst_hostname: str = "") -> dict[str, Any]:
    """One normalized OCSF event, shaped the way ingest emits them.

    The nesting is the point. ``src_endpoint.ip``, ``file.fingerprints[0].value``
    and ``dst_endpoint.hostname`` are where the writer reads from, and a
    flattened fixture would silently pass while production silently failed.
    """
    event: dict[str, Any] = {
        "class_uid": 4001,
        "category_uid": 4,
        "severity_id": 3,
        "severity": "medium",
        "time": "2026-09-20T12:00:00Z",
        "src_endpoint": {"ip": src_ip, "port": 44321},
        "dst_endpoint": {"ip": "198.51.100.200", "port": 443, "hostname": dst_hostname},
        "device": {"name": "web-01"},
        "actor": {"user": {"name": "alice"}},
        "process": {"name": "curl"},
        "metadata": {"product": {"name": "aws_cloudtrail"}},
    }
    if sha256:
        event["file"] = {"path": "/tmp/payload.bin", "fingerprints": [{"algorithm": "SHA-256", "value": sha256}]}
    return {
        "id": str(uuid.uuid4()),
        "tenant_id": str(tenant),
        "connector_type": "aws_cloudtrail",
        "ocsf_event": event,
    }


@pytest.fixture(scope="module")
def clickhouse_client() -> Any:
    driver = pytest.importorskip("clickhouse_driver", reason="clickhouse-driver not installed")
    # `ISOLATION_*` is what `isolation-live.yml` sets, and is preferred so this
    # file behaves identically to the rest of the directory in CI. The
    # unprefixed names are the fallback so a developer can point it at a local
    # container without inventing a second set of variables.
    host = os.getenv("ISOLATION_CLICKHOUSE_HOST") or os.getenv("CLICKHOUSE_HOST", "localhost")
    # Chained `or` with the default last, so an env var set to the empty string
    # falls through to the default rather than reaching `int("")`.
    port = int(os.getenv("ISOLATION_CLICKHOUSE_PORT") or os.getenv("CLICKHOUSE_PORT") or "9000")
    try:
        client = driver.Client(
            host=host,
            port=port,
            user=os.getenv("CLICKHOUSE_USER", "default"),
            password=os.getenv("CLICKHOUSE_PASSWORD", ""),
            connect_timeout=5,
        )
        client.execute("SELECT 1")
    except Exception as exc:  # noqa: BLE001 - absence is a skip, not a failure
        pytest.skip(f"no ClickHouse at {host}:{port} ({type(exc).__name__})")
    return client


@pytest.fixture(scope="module")
def seeded_lake(clickhouse_client: Any) -> Any:
    """A real lake holding rows the real writer produced.

    Tenant A's events contain the published indicators. Tenant B's contain
    ordinary traffic and a different hash, so a sweep that matched for B would
    be matching something other than what it was asked about.
    """
    lake_writer = _load_by_path("services/fusion/app/services/lake_writer.py", "_aisoc_live_lake_writer")

    client = clickhouse_client
    client.execute("CREATE DATABASE IF NOT EXISTS aisoc")
    client.execute("DROP TABLE IF EXISTS aisoc.raw_events")
    client.execute(_raw_events_ddl())

    messages = [
        _ocsf_event(tenant=TENANT_A, src_ip=IOC_IP, sha256=IOC_SHA256, dst_hostname=IOC_DOMAIN),
        _ocsf_event(tenant=TENANT_A, src_ip=BENIGN_IP),
        _ocsf_event(tenant=TENANT_B, src_ip=BENIGN_IP, sha256="b" * 64, dst_hostname="ordinary.example.invalid"),
        _ocsf_event(tenant=TENANT_B, src_ip="198.51.100.6"),
    ]

    rows = []
    for message in messages:
        row = lake_writer.event_to_row(message)
        assert row is not None, "the production writer refused an event this test must be able to record"
        out = {k: v for k, v in row.items() if not (k == "event_id" and v is None)}
        out["source_ip"] = lake_writer._to_ip_obj(row["source_ip"])
        out["dest_ip"] = lake_writer._to_ip_obj(row["dest_ip"])
        rows.append(out)

    client.execute(lake_writer._INSERT_SQL, rows, types_check=True)
    yield client
    client.execute("DROP TABLE IF EXISTS aisoc.raw_events")


# --------------------------------------------------------------------------
# What the writer actually recorded
# --------------------------------------------------------------------------


def test_the_writer_stores_an_ipv4_address_as_its_ipv4_mapped_form() -> None:
    """The reason the sweep needs ``toIPv6``, established before it is used.

    Asserted against the production writer rather than stated in a comment,
    because if this ever stops being true the sweep's normalisation becomes
    wrong in the other direction and would again match nothing.
    """
    lake_writer = _load_by_path("services/fusion/app/services/lake_writer.py", "_aisoc_ip_shape_writer")
    stored = lake_writer._to_ip_obj(IOC_IP)
    assert isinstance(stored, ipaddress.IPv6Address)
    assert stored == ipaddress.IPv6Address(f"::ffff:{IOC_IP}")
    assert stored.ipv4_mapped == ipaddress.IPv4Address(IOC_IP)
    # Compared as addresses rather than as text on purpose. Python renders a
    # mapped address in hex (`::ffff:cb00:714d`), so a string comparison here
    # would be asserting a rendering rather than the value, and the value is
    # what the column holds and what the predicate has to match.
    assert str(stored) != IOC_IP


def test_the_writer_puts_a_fingerprint_in_the_hash_sha256_column() -> None:
    """The reason md5 and sha1 map to ``hash_sha256``."""
    lake_writer = _load_by_path("services/fusion/app/services/lake_writer.py", "_aisoc_hash_shape_writer")
    row = lake_writer.event_to_row(_ocsf_event(tenant=TENANT_A, src_ip=IOC_IP, sha256=IOC_SHA256))
    assert row is not None
    assert row["hash_sha256"] == IOC_SHA256


# --------------------------------------------------------------------------
# The done-when clause
# --------------------------------------------------------------------------


def _sweep(client: Any, *, tenant: uuid.UUID, indicator_type: str, value: str) -> int:
    ioc_fields, sql_module = _load_sweep_sql()
    mapping = ioc_fields.SWEEPABLE_TYPES[indicator_type]
    sql, _columns = sql_module.build_sweep_sql(mapping)
    rows = client.execute(
        sql,
        {"tenant_id": str(tenant), "lookback_days": 3650, "needle": value},
    )
    assert len(rows) == 1, "the sweep must be an aggregate returning exactly one row"
    return int(rows[0][0])


@pytest.mark.parametrize(
    ("indicator_type", "value"),
    [("ip", IOC_IP), ("sha256", IOC_SHA256), ("domain", IOC_DOMAIN)],
)
def test_a_published_indicator_is_found_for_the_tenant_whose_data_holds_it(
    seeded_lake: Any,
    indicator_type: str,
    value: str,
) -> None:
    """Half one of the done-when clause, for three indicator types.

    This is the assertion that the mapping is right. It runs the real
    generator against a real warehouse holding a row the real writer produced,
    so a wrong column, a missing ``toIPv6`` or a scalar comparison against an
    array all fail here.
    """
    assert _sweep(seeded_lake, tenant=TENANT_A, indicator_type=indicator_type, value=value) >= 1


@pytest.mark.parametrize(
    ("indicator_type", "value"),
    [("ip", IOC_IP), ("sha256", IOC_SHA256), ("domain", IOC_DOMAIN)],
)
def test_the_same_indicator_is_not_found_for_a_tenant_whose_data_lacks_it(
    seeded_lake: Any,
    indicator_type: str,
    value: str,
) -> None:
    """Half two. Tenant B has rows, just not these, so a zero here is real.

    A tenant with no rows at all would return zero whether or not the sweep
    were tenant-scoped, which would make this half vacuous. B's rows are
    asserted separately below.
    """
    assert _sweep(seeded_lake, tenant=TENANT_B, indicator_type=indicator_type, value=value) == 0


@pytest.mark.parametrize(
    ("indicator_type", "value", "expected_columns"),
    [
        ("ip", IOC_IP, {"source_ip", "iocs"}),
        ("sha256", IOC_SHA256, {"hash_sha256", "iocs"}),
        ("domain", IOC_DOMAIN, {"dst_hostname"}),
        ("hostname", "web-01", {"src_hostname"}),
        ("username", "alice", {"user_name"}),
        ("process_name", "curl", {"process_name"}),
    ],
)
def test_each_mapped_column_is_exercised_on_its_own(
    seeded_lake: Any,
    indicator_type: str,
    value: str,
    expected_columns: set[str],
) -> None:
    """Which columns actually match, one predicate at a time.

    The test above this one runs the assembled statement, and an OR hides a
    broken branch behind a working one. ``iocs`` carries IP addresses and
    hashes as plain strings, so it matches for most indicator types whether or
    not the typed column beside it was mapped correctly: pointing ``source_ip``
    at a column that does not exist would still have passed. Dropping
    ``is_ip`` from both IP columns was tried against this file and the
    assembled-statement tests all passed, which is what this exists to close.

    So each column is probed alone, and the set that matches is compared
    against the set that should. A column that stops matching is named rather
    than absorbed.
    """
    ioc_fields, sql_module = _load_sweep_sql()
    mapping = ioc_fields.SWEEPABLE_TYPES[indicator_type]

    matched: set[str] = set()
    for column in mapping.columns:
        predicate = sql_module.column_predicate(column)
        count = seeded_lake.execute(
            f"SELECT count() FROM aisoc.raw_events WHERE tenant_id = %(tenant_id)s AND ({predicate})",
            {"tenant_id": str(TENANT_A), "needle": value},
        )[0][0]
        if count:
            matched.add(column.name)

    assert matched == expected_columns, (
        f"{indicator_type}: columns that matched recorded lake data were {sorted(matched)}, expected {sorted(expected_columns)}. "
        f"A column in the expected set that did not match is a mapping that reads something the writer never fills."
    )


def test_the_iocs_array_alone_does_not_carry_the_ip_mapping(seeded_lake: Any) -> None:
    """The typed IP column must match on its own merit.

    Stated separately because it is the specific masking that was found: with
    ``iocs`` in the same OR, an ``ip`` sweep matches even when nothing about
    ``source_ip`` is right.
    """
    ioc_fields, sql_module = _load_sweep_sql()
    source_ip = next(c for c in ioc_fields.SWEEPABLE_TYPES["ip"].columns if c.name == "source_ip")
    count = seeded_lake.execute(
        f"SELECT count() FROM aisoc.raw_events WHERE tenant_id = %(tenant_id)s AND ({sql_module.column_predicate(source_ip)})",
        {"tenant_id": str(TENANT_A), "needle": IOC_IP},
    )[0][0]
    assert count >= 1


def test_an_array_flag_that_disagrees_with_the_column_is_a_hard_error(seeded_lake: Any) -> None:
    """Why the mapping gate checks the flags, measured rather than asserted.

    Three of the four flag disagreements make ClickHouse reject the query, so
    they cannot ship silently. The fourth, a missing ``is_ip``, is tolerated
    because the server coerces the literal, which is recorded here so the
    mapping module's comments describe the server's real behaviour instead of
    a plausible one.
    """
    with pytest.raises(Exception):  # noqa: B017 - driver raises a ServerException subclass
        seeded_lake.execute(
            "SELECT count() FROM aisoc.raw_events WHERE has(hash_sha256, %(needle)s)",
            {"needle": IOC_SHA256},
        )
    with pytest.raises(Exception):  # noqa: B017
        seeded_lake.execute(
            "SELECT count() FROM aisoc.raw_events WHERE iocs = %(needle)s",
            {"needle": IOC_SHA256},
        )
    # And the tolerated one, recorded as tolerated.
    coerced = seeded_lake.execute(
        "SELECT count() FROM aisoc.raw_events WHERE tenant_id = %(t)s AND source_ip = %(needle)s",
        {"t": str(TENANT_A), "needle": IOC_IP},
    )[0][0]
    assert coerced >= 1, "ClickHouse coerces a string literal to IPv6; if this ever stops, toIPv6 becomes load-bearing"


def test_tenant_b_has_recorded_data_so_its_zero_is_a_real_negative(seeded_lake: Any) -> None:
    """Without this the negative half proves only that B's partition is empty."""
    rows = seeded_lake.execute(
        "SELECT count() FROM aisoc.raw_events WHERE tenant_id = %(t)s",
        {"t": str(TENANT_B)},
    )
    assert rows[0][0] >= 2
    # And B really does hold a benign address the sweep can find, which shows
    # the query works against B's partition rather than being scoped to
    # nothing.
    assert _sweep(seeded_lake, tenant=TENANT_B, indicator_type="ip", value=BENIGN_IP) >= 1


def test_a_thousand_matching_events_still_produce_one_aggregate_row(seeded_lake: Any) -> None:
    """The structural answer to "one IOC must not open a thousand alerts".

    Written with real rows rather than reasoned about: a thousand events
    carrying the indicator are inserted and the sweep is asserted to return a
    single row whose count reflects all of them. The service opens one alert
    per (tenant, indicator), so this is the layer that decides how much work
    reaches it.
    """
    lake_writer = _load_by_path("services/fusion/app/services/lake_writer.py", "_aisoc_bulk_writer")
    flood_tenant = uuid.UUID("cccccccc-0000-4000-8000-000000000003")
    rows = []
    for _ in range(1000):
        row = lake_writer.event_to_row(_ocsf_event(tenant=flood_tenant, src_ip=IOC_IP))
        assert row is not None
        out = {k: v for k, v in row.items() if not (k == "event_id" and v is None)}
        out["source_ip"] = lake_writer._to_ip_obj(row["source_ip"])
        out["dest_ip"] = lake_writer._to_ip_obj(row["dest_ip"])
        rows.append(out)
    seeded_lake.execute(lake_writer._INSERT_SQL, rows, types_check=True)

    ioc_fields, sql_module = _load_sweep_sql()
    sql, _ = sql_module.build_sweep_sql(ioc_fields.SWEEPABLE_TYPES["ip"])
    result = seeded_lake.execute(sql, {"tenant_id": str(flood_tenant), "lookback_days": 3650, "needle": IOC_IP})

    assert len(result) == 1, "a thousand matches must still be one row"
    assert result[0][0] == 1000, "the aggregate must count every match, not a page of them"
    # Bounded evidence regardless of match count: the distinct sets are
    # capped, so alert evidence cannot grow with the size of the match.
    assert len(result[0][3]) <= 20
    assert len(result[0][4]) <= 20


def test_the_sweep_is_scoped_even_when_the_indicator_exists_for_another_tenant(seeded_lake: Any) -> None:
    """The isolation half, stated as its own assertion.

    The indicator is present in the table for tenant A. A sweep run as B must
    not see it, and the reason must be the tenant predicate rather than the
    indicator's absence from the warehouse.
    """
    total = seeded_lake.execute(
        "SELECT count() FROM aisoc.raw_events WHERE source_ip = toIPv6(%(v)s)",
        {"v": IOC_IP},
    )[0][0]
    assert total >= 1, "the indicator must be present in the table for this to mean anything"
    assert _sweep(seeded_lake, tenant=TENANT_B, indicator_type="ip", value=IOC_IP) == 0
