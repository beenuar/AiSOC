"""Hunting AiSOC's own event lake.

Every connector's events are archived to ClickHouse `aisoc.raw_events`, and
nothing could query them. `/nl-query/execute` only ever executed against
Elasticsearch, so a tenant whose data lives in the platform's own lake got
"ES_URL or ES_API_KEY not configured" and could not query anything they had
ingested. `POST /saved-hunts/{id}/run` was worse: it re-translated the
question, stamped `last_run_at` and returned, so the console showed "last run
just now" for a hunt that had queried nothing — indistinguishable from a hunt
that ran and found no matches.

The compiler turns the translator's structured IR into ClickHouse SQL. The two
properties it must not get wrong are that no analyst text ever reaches the SQL
string, and that tenant scoping is generated rather than rewritten in
afterwards.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

import pytest
from app.services.lake_hunt import (
    LAKE_TABLE,
    MAX_LIMIT,
    HuntCompileError,
    compile_hunt,
)

TENANT = "aaaaaaaa-0000-0000-0000-000000000001"


@dataclass
class _Intents:
    """Stands in for the translator's QueryIntents."""

    filters: list[tuple[str, str, str]] = field(default_factory=list)
    group_by: list[str] = field(default_factory=list)
    aggregations: list[tuple[str, str | None, str]] = field(default_factory=list)
    sort_by: tuple[str, str] | None = None
    limit: int = 500
    distinct: str | None = None
    time_field: str = "@timestamp"


# ── tenant scoping ────────────────────────────────────────────────────────


def test_the_tenant_predicate_is_generated_and_bound():
    """Not rewritten in afterwards, and bound rather than interpolated.

    `rewrite_for_tenant` exists to constrain untrusted operator SQL and cannot
    help a caller who forgets to use it, so scoping is structural here.
    """
    compiled = compile_hunt(_Intents(), tenant_id=TENANT)
    assert "tenant_id = %(tenant_id)s" in compiled.sql
    assert compiled.params["tenant_id"] == TENANT
    assert TENANT not in compiled.sql


def test_the_query_targets_the_lake_table():
    assert LAKE_TABLE in compile_hunt(_Intents(), tenant_id=TENANT).sql


def test_a_time_window_is_always_applied():
    """An unbounded scan over the lake is a denial of service on itself."""
    compiled = compile_hunt(_Intents(), tenant_id=TENANT, hours=6)
    assert "event_time >= now() - INTERVAL %(hours)s HOUR" in compiled.sql
    assert compiled.params["hours"] == 6


# ── no user text in the SQL ───────────────────────────────────────────────


def test_filter_values_are_bound_never_interpolated():
    compiled = compile_hunt(
        _Intents(filters=[("user.name", "==", "alice")]),
        tenant_id=TENANT,
    )
    assert "alice" not in compiled.sql
    assert "alice" in compiled.params.values()


def test_a_sql_injection_attempt_in_the_question_stays_data():
    """The question is untrusted input and the lake holds every tenant's events."""
    payload = "alice'; DROP TABLE aisoc.raw_events; --"
    compiled = compile_hunt(
        _Intents(filters=[("user.name", "==", payload)]),
        tenant_id=TENANT,
    )
    assert "DROP TABLE" not in compiled.sql
    assert payload in compiled.params.values()


def test_an_unknown_field_cannot_become_a_column_name():
    """Otherwise a crafted field name is an injection point in the projection."""
    compiled = compile_hunt(
        _Intents(filters=[("evil) OR 1=1 --", "==", "x")]),
        tenant_id=TENANT,
    )
    assert "OR 1=1" not in compiled.sql
    assert "evil) OR 1=1 --" in compiled.unsupported_fields


def test_an_unknown_operator_is_rejected():
    with pytest.raises(HuntCompileError):
        compile_hunt(_Intents(filters=[("user.name", "REGEXP", ".*")]), tenant_id=TENANT)


def test_an_aggregation_alias_cannot_inject():
    compiled = compile_hunt(
        _Intents(aggregations=[("count", None, "x AS y, (SELECT 1)")]),
        tenant_id=TENANT,
    )
    assert "SELECT 1" not in compiled.sql


# ── honesty about what was dropped ────────────────────────────────────────


def test_fields_the_lake_does_not_store_are_reported():
    """A hunt that silently drops filters returns more rows than was asked for.

    Which reads to an analyst as "nothing was filtered out" when the truth is
    "your filter was discarded".
    """
    compiled = compile_hunt(
        _Intents(filters=[("source.geo.country_iso_code", "==", "IR")]),
        tenant_id=TENANT,
    )
    assert compiled.unsupported_fields == ["source.geo.country_iso_code"]
    assert compiled.is_partial


def test_a_fully_supported_hunt_is_not_marked_partial():
    compiled = compile_hunt(
        _Intents(filters=[("host.name", "==", "WIN-DC01")]),
        tenant_id=TENANT,
    )
    assert compiled.unsupported_fields == []
    assert not compiled.is_partial


# ── operators ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("op", "expected"),
    [("==", "="), ("!=", "!="), (">", ">"), ("<", "<"), (">=", ">="), ("<=", "<=")],
)
def test_scalar_operators_render(op: str, expected: str):
    compiled = compile_hunt(
        _Intents(filters=[("destination.port", op, "445")]),
        tenant_id=TENANT,
    )
    assert f"dst_port {expected} %(f0)s" in compiled.sql
    assert compiled.params["f0"] == 445


def test_numeric_columns_are_coerced_to_numbers():
    """ClickHouse rejects a string against a UInt column."""
    compiled = compile_hunt(
        _Intents(filters=[("event.severity", ">=", "4")]),
        tenant_id=TENANT,
    )
    assert compiled.params["f0"] == 4


def test_a_non_numeric_value_on_a_numeric_column_is_refused():
    with pytest.raises(HuntCompileError):
        compile_hunt(_Intents(filters=[("destination.port", "==", "http")]), tenant_id=TENANT)


def test_in_lists_are_decoded_from_the_ir_encoding():
    """The IR JSON-encodes IN lists so its dedup set stays hashable."""
    compiled = compile_hunt(
        _Intents(filters=[("user.name", "IN", json.dumps(["alice", "bob"]))]),
        tenant_id=TENANT,
    )
    assert "user_name IN %(f0)s" in compiled.sql
    assert compiled.params["f0"] == ["alice", "bob"]


def test_like_becomes_a_bound_pattern():
    compiled = compile_hunt(
        _Intents(filters=[("process.name", "LIKE", "powershell")]),
        tenant_id=TENANT,
    )
    assert "ILIKE %(f0)s" in compiled.sql
    assert compiled.params["f0"] == "%powershell%"


def test_array_columns_use_membership_not_equality():
    """`mitre_techniques` is an Array(String); `=` would never match."""
    compiled = compile_hunt(
        _Intents(filters=[("threat.technique.id", "==", json.dumps(["T1059"]))]),
        tenant_id=TENANT,
    )
    assert "hasAny(mitre_techniques, %(f0)s)" in compiled.sql


def test_a_range_operator_on_an_array_column_is_refused():
    with pytest.raises(HuntCompileError):
        compile_hunt(
            _Intents(filters=[("threat.technique.id", ">", "T1059")]),
            tenant_id=TENANT,
        )


# ── shape of the query ────────────────────────────────────────────────────


def test_group_by_projects_the_grouping_and_a_count():
    compiled = compile_hunt(_Intents(group_by=["source.ip"]), tenant_id=TENANT)
    assert "GROUP BY source_ip" in compiled.sql
    assert "count() AS event_count" in compiled.sql


def test_an_aggregate_query_is_not_ordered_by_an_ungrouped_column():
    """ClickHouse errors on ORDER BY event_time when it is not in GROUP BY.

    The unmappable-sort fallback used to emit exactly that, turning a
    reasonable question into a failed query.
    """
    compiled = compile_hunt(
        _Intents(group_by=["source.ip"], sort_by=("nonexistent.field", "desc")),
        tenant_id=TENANT,
    )
    assert "ORDER BY count() DESC" in compiled.sql
    assert "ORDER BY event_time" not in compiled.sql


def test_a_flat_query_orders_by_time_descending():
    assert "ORDER BY event_time DESC" in compile_hunt(_Intents(), tenant_id=TENANT).sql


def test_distinct_projects_a_single_column():
    compiled = compile_hunt(_Intents(distinct="user.name"), tenant_id=TENANT)
    assert "DISTINCT user_name" in compiled.sql


def test_the_limit_is_capped():
    """An analyst asking for a million rows must not get a million rows."""
    compiled = compile_hunt(_Intents(limit=10_000_000), tenant_id=TENANT)
    assert f"LIMIT {MAX_LIMIT}" in compiled.sql


def test_an_explicit_limit_is_honoured():
    assert "LIMIT 25" in compile_hunt(_Intents(limit=25), tenant_id=TENANT).sql


# ── against the real translator ───────────────────────────────────────────


def test_real_translator_output_compiles():
    """End to end from an analyst's sentence to bound SQL."""
    translator = pytest.importorskip("app._vendor.nl_query.translator")
    translated = translator.translate("processes named powershell.exe on host WIN-DC01")
    compiled = compile_hunt(translated.intents, tenant_id=TENANT)
    assert LAKE_TABLE in compiled.sql
    assert compiled.params["tenant_id"] == TENANT
    # Entity values arrived as parameters, not as SQL text.
    assert "win-dc01" in [str(v).lower() for v in compiled.params.values()]
