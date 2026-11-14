"""The sweep query, generated from the field mapping and nothing else.

Gap-closure Phase 8.1.

Separated from :mod:`app.services.retro_hunt.sweep` on purpose. That module
does I/O: it holds a ClickHouse client, a database session and the federated
search, so importing it pulls in SQLAlchemy and the settings object. This one
imports the standard library and the field mapping, which means the two places
that most need to check the generated SQL can load it directly:

* ``scripts/check_ioc_lake_mapping.py``, which has no service dependencies
  installed;
* ``tests/isolation/test_retro_hunt_live.py``, which runs the *real* generator
  against a *live* ClickHouse holding a row produced by the *real* lake
  writer, and would be proving nothing if it re-implemented the query.

That second one is the whole reason for the split. This repository's recurring
defect is a test that compares a producer against a copy of itself, and a live
test that built its own SQL would be exactly that.
"""

from __future__ import annotations

from app.services.retro_hunt.ioc_fields import LAKE_TABLE, LakeColumn, LakeFieldMapping

__all__ = ["DISTINCT_CAP", "build_sweep_sql", "column_predicate"]

#: How many distinct values of each grouping column a sweep returns. Bounded
#: because this lands in alert evidence and, through it, in a prompt.
DISTINCT_CAP = 20


def column_predicate(column: LakeColumn) -> str:
    """The one predicate that tests ``column`` against the bound needle.

    Public so the live test can exercise each column on its own. A sweep ORs
    several columns together, and an OR hides a broken one behind a working
    one: ``iocs`` carries IP addresses and hashes as plain strings, so it
    matches for most indicator types regardless of whether the typed column
    beside it was mapped correctly. Testing the assembled statement would
    therefore pass with ``source_ip`` pointed at nothing.
    """
    if column.is_array:
        return f"has({column.name}, %(needle)s)"
    if column.is_ip:
        # Explicit normalisation rather than a load-bearing conversion.
        # ClickHouse 24.3 does coerce a string literal to IPv6 when comparing
        # against an IPv6 column, so `source_ip = '203.0.113.77'` matches the
        # `::ffff:203.0.113.77` the writer stored. Measured, not assumed; see
        # `tests/isolation/test_retro_hunt_live.py`. `toIPv6` says what is
        # meant instead of relying on an implicit cast staying implicit, and
        # it keeps the predicate honest about the fact that the stored value
        # is not the string the feed published.
        return f"{column.name} = toIPv6(%(needle)s)"
    return f"{column.name} = %(needle)s"


def build_sweep_sql(mapping: LakeFieldMapping) -> tuple[str, tuple[str, ...]]:
    """Build the aggregate sweep for one indicator type.

    Returns the SQL and the column names it searched. The statement carries
    three bound parameters (``tenant_id``, ``lookback_days``, ``needle``) and
    no interpolated value of any kind: column names come from
    :mod:`app.services.retro_hunt.ioc_fields`, which is a closed table in this
    repository, and the indicator itself is always a parameter. An indicator
    is third-party text from a public feed, so it is untrusted in exactly the
    way an operator's SQL is.

    The result is an aggregate rather than a selection, and that is the
    structural answer to "an IOC that matches a thousand rows should not open
    a thousand alerts": there is no code path here that can return a row per
    match.
    """
    predicates = [column_predicate(column) for column in mapping.columns]

    sql = (
        "SELECT count() AS sightings, "
        "min(event_time) AS first_sighting, "
        "max(event_time) AS last_sighting, "
        f"groupUniqArray({DISTINCT_CAP})(connector_type) AS connector_types, "
        f"groupUniqArray({DISTINCT_CAP})(src_hostname) AS hosts, "
        f"groupUniqArray({DISTINCT_CAP})(user_name) AS users "
        f"FROM {LAKE_TABLE} "
        "WHERE tenant_id = %(tenant_id)s "
        "AND event_time >= now() - INTERVAL %(lookback_days)s DAY "
        f"AND ({' OR '.join(predicates)})"
    )

    # Fail closed on the property this module's correctness rests on. The
    # statement is generated a few lines above, so this can only fire on a
    # future edit, which is exactly when it is worth having: the equivalent
    # check in `lake_sql` exists because a dependency upgrade silently turned
    # the tenant predicate into a no-op and the rewriter reported success.
    if "tenant_id = %(tenant_id)s" not in sql:
        raise AssertionError("refusing to return a sweep query with no tenant predicate")

    return sql, mapping.column_names
