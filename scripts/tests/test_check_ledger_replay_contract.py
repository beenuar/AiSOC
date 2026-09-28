"""The ledger replay-contract gate detects what it claims, and only that.

Proven against each of the three properties it holds, in both directions,
against the parser shapes that would make it lie, and against the corpora it
has to refuse rather than call clean.

The near misses matter as much as the hits: a cases route that happens to
contain the word "investigations", a ``COALESCE`` that names its own target,
a field documented in a comment, and a handler that reads exactly one event
by sequence number. A gate that fires on any of those is a nuisance somebody
will switch off.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
GATE = REPO_ROOT / "scripts" / "check_ledger_replay_contract.py"


def _load():
    spec = importlib.util.spec_from_file_location("check_ledger_replay_contract", GATE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MODULE = _load()


def _codes(mutate) -> set[str]:
    """Finding codes the gate reports for the probe corpus after ``mutate``.

    Callers bind the result before asserting on it. ``mutate`` changes the
    corpus, and a call with a side effect inside an ``assert`` disappears
    under ``python -O`` along with the assertion — which would leave every
    injection test here passing without injecting anything.
    """
    corpus = MODULE._probe_corpus()
    mutate(corpus)
    return {finding.code for finding in MODULE.evaluate(corpus)}


# ---------------------------------------------------------------------------
# The baseline the injections are measured against
# ---------------------------------------------------------------------------


def test_the_probe_corpus_is_clean() -> None:
    """Every case below asserts a *change*, so the baseline has to be silent."""
    assert MODULE.evaluate(MODULE._probe_corpus()) == []


def test_the_probe_corpus_is_built_from_the_recorded_lists() -> None:
    """A probe kept beside the lists would drift from them.

    Every recorded server-only route has to appear as a declared route in the
    probe, or the probe reports its own exemptions as stale and the pressure
    is to weaken the check instead of the fixture.
    """
    corpus = MODULE._probe_corpus()
    assert set(MODULE.SERVER_ONLY_ROUTES) <= set(corpus.routes)
    assert corpus.delegate_reads_writer
    for table, column in MODULE.UNWRITTEN_COLUMNS:
        assert column in corpus.schema_columns[table]
        assert column not in corpus.written_columns[table]


# ---------------------------------------------------------------------------
# Property 1 — field parity
# ---------------------------------------------------------------------------


def test_a_field_added_to_the_response_model_alone_is_caught() -> None:
    """The direction that drifts: the model grows, TypeScript does not hear."""
    reported = _codes(lambda c: c.model_fields.add("groundedness"))
    assert "FIELD-PY-NOT-IN-TS" in reported


def test_a_field_added_to_typescript_alone_is_caught() -> None:
    reported = _codes(lambda c: c.ts_fields.add("pivot_path"))
    assert "FIELD-TS-NOT-IN-PY" in reported


def test_a_rename_on_one_side_is_reported_in_both_directions() -> None:
    """``input_hash`` becoming ``inputHash`` is a loss *and* an absence."""

    def rename(corpus) -> None:
        corpus.model_fields.discard("input_hash")
        corpus.model_fields.add("inputHash")

    assert _codes(rename) >= {"FIELD-PY-NOT-IN-TS", "FIELD-TS-NOT-IN-PY"}


# ---------------------------------------------------------------------------
# Property 2 — route parity
# ---------------------------------------------------------------------------


def test_a_client_request_with_no_matching_route_is_caught() -> None:
    """The shape this repository shipped: six pivots against ``/attack-graph``."""
    reported = _codes(lambda c: c.client_paths.add("/investigations/{}/attack-graph"))
    assert "ROUTE-CLIENT-ORPHAN" in reported


def test_deleting_a_route_the_client_still_calls_is_caught() -> None:
    reported = _codes(lambda c: c.routes.pop("GET /investigations/{}/replay"))
    assert "ROUTE-CLIENT-ORPHAN" in reported


def test_a_declared_route_nothing_calls_and_nothing_records_is_caught() -> None:
    def add_orphan(corpus) -> None:
        corpus.routes["GET /investigations/{}/orphan"] = MODULE.RouteDecl("GET", "/investigations/{}/orphan", "orphan_handler")

    assert "ROUTE-UNCONSUMED" in _codes(add_orphan)


def test_a_route_consumed_outside_the_typed_client_still_counts() -> None:
    """``/timeline`` is called through a bare ``fetch``, and that is a caller.

    A consumed-or-recorded check that only read ``ledgerApi`` would demand a
    written reason for a route that has one.
    """

    def add_fetch_only(corpus) -> None:
        corpus.routes["GET /investigations/{}/timeline"] = MODULE.RouteDecl("GET", "/investigations/{}/timeline", "get_timeline")
        corpus.consumer_paths.add("/investigations/{}/timeline")

    assert "ROUTE-UNCONSUMED" not in _codes(add_fetch_only)


def test_a_recorded_exemption_the_router_dropped_is_caught() -> None:
    key = next(iter(MODULE.SERVER_ONLY_ROUTES))
    reported = _codes(lambda c: c.routes.pop(key))
    assert "ROUTE-STALE-EXEMPTION" in reported


def test_a_recorded_exemption_the_console_started_calling_is_caught() -> None:
    def start_calling(corpus) -> None:
        for key in MODULE.SERVER_ONLY_ROUTES:
            corpus.consumer_paths.add(corpus.routes[key].path)

    assert "ROUTE-STALE-EXEMPTION" in _codes(start_calling)


# ---------------------------------------------------------------------------
# Property 3 — writer / schema parity and sequencing
# ---------------------------------------------------------------------------


def test_a_schema_column_the_writer_never_writes_is_caught() -> None:
    """The direction no generic raw-SQL gate makes, because it cannot know
    which writer a table belongs to."""
    reported = _codes(lambda c: c.schema_columns[MODULE.EVENTS_TABLE].add("signed_by"))
    assert "COLUMN-UNWRITTEN" in reported


def test_the_other_column_direction_is_delegated_to_a_gate_that_exists() -> None:
    """A column the writer writes and no migration creates is held elsewhere.

    ``check_raw_sql_columns.py`` makes that comparison generically over every
    raw statement under ``services/*/app``, this writer's included, so
    duplicating it here would be two places to keep in step rather than two
    checks. Measured on this tree: dropping ``investigation_events.input_hash``
    from migration 008 exits 1 there.
    """
    delegate = REPO_ROOT / MODULE.DELEGATE_REL
    assert delegate.is_file(), f"{MODULE.DELEGATE_REL} is gone and this gate is delegating to nothing"
    assert MODULE.DELEGATE_SCOPE_MARKER in delegate.read_text(encoding="utf-8")


def test_losing_the_delegate_is_a_finding_rather_than_a_silence() -> None:
    """A direction nobody covers must not go quiet because two files each
    believed the other had it."""
    reported = _codes(lambda c: setattr(c, "delegate_reads_writer", False))
    assert "COLUMN-DELEGATION-MISSING" in reported


def test_a_recorded_unwritten_column_the_writer_started_writing_is_caught() -> None:
    def start_writing(corpus) -> None:
        for table, column in MODULE.UNWRITTEN_COLUMNS:
            corpus.written_columns[table].add(column)

    assert "COLUMN-STALE-EXEMPTION" in _codes(start_writing)


def test_an_event_appended_without_a_sequence_number_is_caught() -> None:
    reported = _codes(lambda c: c.written_columns[MODULE.EVENTS_TABLE].discard("seq"))
    assert "SEQ-UNSTAMPED" in reported


def test_dropping_the_run_and_sequence_uniqueness_is_caught() -> None:
    """Without it a replayed write appends a second copy instead of conflicting."""
    reported = _codes(lambda c: c.unique_constraints[MODULE.EVENTS_TABLE].clear())
    assert "SEQ-NOT-UNIQUE" in reported


def test_moving_the_creating_migration_is_caught_rather_than_followed() -> None:
    def move(corpus) -> None:
        corpus.created_in_migration[MODULE.EVENTS_TABLE] = "services/api/migrations/999_elsewhere.sql"

    assert "SEQ-SCHEMA-MOVED" in _codes(move)


def test_a_collection_read_with_no_ordering_is_caught() -> None:
    def unorder(corpus) -> None:
        corpus.event_queries[0] = MODULE.EventQuery("replay_run", orders_by_sequence=False)

    assert "SEQ-UNORDERED-READ" in _codes(unorder)


def test_ordering_a_replay_by_the_clock_is_caught() -> None:
    """``ts`` ties at write resolution and moves under a clock correction."""

    def by_clock(corpus) -> None:
        corpus.event_queries[0] = MODULE.EventQuery("replay_run", orders_by_sequence=False, other_order_columns=("ts",))

    assert _codes(by_clock) >= {"SEQ-UNORDERED-READ", "SEQ-ORDERED-BY-CLOCK"}


# ---------------------------------------------------------------------------
# Non-vacuity
# ---------------------------------------------------------------------------


def test_every_empty_corpus_is_refused_rather_than_called_clean() -> None:
    """Found nothing and scanned nothing must not print the same word."""
    table = MODULE.EVENTS_TABLE
    for mutate, code in (
        (lambda c: c.model_fields.clear(), "EMPTY-MODEL"),
        (lambda c: c.ts_fields.clear(), "EMPTY-TS"),
        (lambda c: c.routes.clear(), "EMPTY-ROUTES"),
        (lambda c: c.client_paths.clear(), "EMPTY-CLIENT"),
        (lambda c: c.schema_columns[table].clear(), "EMPTY-SCHEMA"),
        (lambda c: c.written_columns[table].clear(), "EMPTY-WRITER"),
        (lambda c: c.event_queries.clear(), "EMPTY-HANDLERS"),
    ):
        assert code in _codes(mutate), code


def test_a_vacuous_corpus_exits_two_rather_than_one() -> None:
    """Nothing was compared, so there is no disagreement to report as one."""
    corpus = MODULE._probe_corpus()
    corpus.model_fields.clear()
    assert MODULE.exit_status(MODULE.evaluate(corpus)) == 2

    drifted = MODULE._probe_corpus()
    drifted.model_fields.add("groundedness")
    assert MODULE.exit_status(MODULE.evaluate(drifted)) == 1
    assert MODULE.exit_status([]) == 0


def test_a_vacuous_corpus_reports_only_the_refusal() -> None:
    """A drift verdict over an empty set would be indistinguishable from a clean one."""
    corpus = MODULE._probe_corpus()
    corpus.model_fields.clear()
    assert {finding.code for finding in MODULE.evaluate(corpus)} == {"EMPTY-MODEL"}


# ---------------------------------------------------------------------------
# The parsers, on the shapes that would make them lie
# ---------------------------------------------------------------------------


def test_a_table_named_only_in_a_docstring_is_not_a_write() -> None:
    source = '"""Appends to investigation_events (id, run_id, seq)."""\n'
    parsed = MODULE.parse_written_columns(source, "probe.py", MODULE.LEDGER_TABLES)
    assert parsed[MODULE.EVENTS_TABLE] == set()


def test_an_insert_column_list_is_read_and_the_values_are_not() -> None:
    source = (
        "async def go(conn):\n"
        '    await conn.execute("""\n'
        "        INSERT INTO investigation_events (id, run_id, seq, payload)\n"
        "        VALUES ($1, $2, $3, $4::jsonb)\n"
        '    """)\n'
    )
    parsed = MODULE.parse_written_columns(source, "probe.py", MODULE.LEDGER_TABLES)
    assert parsed[MODULE.EVENTS_TABLE] == {"id", "run_id", "seq", "payload"}


def test_an_update_credits_the_assignment_target_and_not_the_expression() -> None:
    """``COALESCE($6, total_cost_usd)`` must not credit anything it reads."""
    source = (
        "async def go(conn):\n"
        '    await conn.execute("""\n'
        "        UPDATE investigation_runs\n"
        "           SET total_cost_usd = COALESCE($2, total_cost_usd),\n"
        "               status = CASE WHEN $3 THEN 'closed' ELSE status END\n"
        "         WHERE id = $1 AND tenant_id = $4\n"
        '    """)\n'
    )
    parsed = MODULE.parse_written_columns(source, "probe.py", MODULE.LEDGER_TABLES)
    assert parsed["investigation_runs"] == {"total_cost_usd", "status"}


def test_a_write_to_a_table_outside_the_ledger_is_ignored() -> None:
    """The writer also updates ``alerts``; that belongs to another gate."""
    source = 'async def go(conn):\n    await conn.execute("UPDATE alerts SET disposition = $1 WHERE id = $2")\n'
    parsed = MODULE.parse_written_columns(source, "probe.py", MODULE.LEDGER_TABLES)
    assert all(columns == set() for columns in parsed.values())


def test_a_later_add_column_counts_as_created() -> None:
    """Four of the columns the writer writes arrived in migration 063.

    A gate reading only the creating migration would report four findings
    against a tree that works.
    """
    files = {
        "008.sql": "CREATE TABLE IF NOT EXISTS investigation_runs (\n  id UUID PRIMARY KEY,\n  status VARCHAR(20) NOT NULL\n);\n",
        "063.sql": "ALTER TABLE investigation_runs\n    ADD COLUMN IF NOT EXISTS measured_call_count INTEGER NOT NULL DEFAULT 0;\n",
    }
    columns, created_in, _uniques = MODULE.parse_schema(files, MODULE.LEDGER_TABLES)
    assert columns["investigation_runs"] == {"id", "status", "measured_call_count"}
    assert created_in["investigation_runs"] == "008.sql"


def test_a_table_constraint_is_not_read_as_a_column() -> None:
    files = {
        "008.sql": (
            "CREATE TABLE IF NOT EXISTS investigation_events (\n"
            "  id UUID PRIMARY KEY,\n"
            "  run_id UUID NOT NULL REFERENCES investigation_runs(id) ON DELETE CASCADE,\n"
            "  seq INTEGER NOT NULL,\n"
            "  UNIQUE (run_id, seq)\n"
            ");\n"
        ),
    }
    columns, _created_in, uniques = MODULE.parse_schema(files, MODULE.LEDGER_TABLES)
    assert columns[MODULE.EVENTS_TABLE] == {"id", "run_id", "seq"}
    assert uniques[MODULE.EVENTS_TABLE] == {("run_id", "seq")}


def test_a_comment_on_column_statement_does_not_create_a_column() -> None:
    """``063`` repeats every column name in prose, and that is the point of it."""
    files = {
        "063.sql": (
            "-- ALTER TABLE investigation_runs ADD COLUMN IF NOT EXISTS ghost INTEGER;\n"
            "COMMENT ON COLUMN investigation_runs.total_cost_usd IS 'Measured cost only.';\n"
        ),
    }
    columns, _created_in, _uniques = MODULE.parse_schema(files, MODULE.LEDGER_TABLES)
    assert columns["investigation_runs"] == set()


def test_a_cases_route_containing_the_word_investigations_is_not_a_ledger_path() -> None:
    """``/cases/${caseId}/investigations/${runId}/report.md`` is a cases route.

    Crediting it would invent a client path the router does not declare *and*
    mark a genuinely unconsumed route as consumed — a finding in one direction
    and a missed finding in the other, from one mistake.
    """
    assert MODULE.ledger_path_from_literal("/api/v1/cases/${caseId}/investigations/${runId}/report.md") is None


def test_a_base_url_variable_and_a_version_prefix_are_both_accepted() -> None:
    assert MODULE.ledger_path_from_literal("${apiBase}/investigations/${runId}/timeline") == "/investigations/{}/timeline"
    assert MODULE.ledger_path_from_literal("/api/v1/investigations/${runId}/replay") == "/investigations/{}/replay"
    assert MODULE.ledger_path_from_literal("/api/v1/investigations") == "/investigations"


def test_a_query_string_is_not_part_of_the_path() -> None:
    assert MODULE.ledger_path_from_literal("/api/v1/investigations/${runId}/explain?step=3") == "/investigations/{}/explain"


def test_a_documented_or_commented_out_typescript_field_is_not_a_field() -> None:
    source = "export interface Probe {\n  /** documented */\n  real: number;\n  // ghost: string;\n}\n"
    assert MODULE.parse_ts_interface_fields(source, "Probe") == {"real"}


def test_a_nested_inline_object_does_not_contribute_its_keys() -> None:
    source = "export interface Probe {\n  outer: {\n    inner: string;\n  };\n  flat: number;\n}\n"
    assert MODULE.parse_ts_interface_fields(source, "Probe") == {"outer", "flat"}


def test_an_optional_typescript_field_is_still_a_field() -> None:
    assert MODULE.parse_ts_interface_fields("export interface Probe {\n  maybe?: string;\n}\n", "Probe") == {"maybe"}


def test_the_router_prefix_is_read_from_the_constructor() -> None:
    source = (
        'router = APIRouter(prefix="/investigations", tags=["investigations"])\n'
        "\n\n"
        '@router.get("/{run_id}/replay")\n'
        "async def replay_run(run_id):\n"
        "    return []\n"
    )
    assert set(MODULE.parse_routes(source, "probe.py")) == {"GET /investigations/{}/replay"}


def test_a_decorator_from_another_object_is_not_a_route() -> None:
    """``@app.get`` and ``@other_router.get`` are not this router's surface."""
    source = 'router = APIRouter(prefix="/investigations")\n\n\n@app.get("/elsewhere")\nasync def elsewhere():\n    return []\n'
    assert MODULE.parse_routes(source, "probe.py") == {}


def test_a_single_event_read_is_not_asked_for_an_ordering() -> None:
    """``explain_step``'s focal lookup is by exact ``seq`` and needs no order."""
    source = (
        "async def focus(db):\n"
        "    q = select(InvestigationEvent).where(InvestigationEvent.seq == step)\n"
        "    return (await db.execute(q)).scalar_one_or_none()\n"
    )
    assert MODULE.parse_event_queries(source, "probe.py") == []


def test_an_ordering_appended_in_a_later_statement_is_still_found() -> None:
    """These are chained builders; ``list_events`` orders three statements on."""
    source = (
        "async def stream(db):\n"
        "    q = select(InvestigationEvent).where(InvestigationEvent.run_id == run_id)\n"
        "    q = q.where(InvestigationEvent.seq > since)\n"
        "    q = q.order_by(InvestigationEvent.seq.asc()).limit(limit)\n"
        "    return (await db.execute(q)).scalars().all()\n"
    )
    assert MODULE.parse_event_queries(source, "probe.py") == [MODULE.EventQuery("stream", orders_by_sequence=True)]


def test_ordering_by_a_non_sequence_column_is_read_off_the_source() -> None:
    source = (
        "async def replay(db):\n"
        "    q = select(InvestigationEvent).order_by(InvestigationEvent.ts.asc())\n"
        "    return (await db.execute(q)).scalars().all()\n"
    )
    parsed = MODULE.parse_event_queries(source, "probe.py")
    assert parsed == [MODULE.EventQuery("replay", orders_by_sequence=False, other_order_columns=("ts",))]


def test_an_ordering_on_another_model_is_not_attributed_to_events() -> None:
    """``list_artifacts`` orders by ``InvestigationArtifact.created_at``."""
    source = (
        "async def artifacts(db):\n"
        "    q = select(InvestigationEvent).order_by(InvestigationEvent.seq.asc())\n"
        "    a = select(InvestigationArtifact).order_by(InvestigationArtifact.created_at.asc())\n"
        "    return (await db.execute(q)).scalars().all(), (await db.execute(a)).scalars().all()\n"
    )
    parsed = MODULE.parse_event_queries(source, "probe.py")
    assert parsed == [MODULE.EventQuery("artifacts", orders_by_sequence=True, other_order_columns=())]


def test_the_client_object_is_read_and_its_neighbours_are_not() -> None:
    """``api.ts`` holds every client in the console; only one owns this contract."""
    source = (
        "export const ledgerApi = {\n"
        "  replay: (runId: string) => request(`/api/v1/investigations/${runId}/replay`),\n"
        "};\n"
        "\n"
        "export const otherApi = {\n"
        "  nope: (runId: string) => request(`/api/v1/investigations/${runId}/invented`),\n"
        "};\n"
    )
    assert MODULE.parse_client_paths(source, "ledgerApi") == {"/investigations/{}/replay"}


# ---------------------------------------------------------------------------
# Reading a tree
# ---------------------------------------------------------------------------


def test_a_missing_subject_is_a_refusal_and_not_a_verdict() -> None:
    """Every content directory absent is the scratch-tree shape."""
    try:
        MODULE.collect(REPO_ROOT / "scripts")
    except MODULE.GateError as exc:
        assert "missing" in str(exc)
    else:  # pragma: no cover - the point of the test
        raise AssertionError("collect() rendered a verdict about a tree with no subject")


def test_the_gate_answers_the_self_test_flag() -> None:
    result = subprocess.run([sys.executable, str(GATE), "--self-test"], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_live_repository_is_clean() -> None:
    """The contract this gate exists for, asserted against the real tree."""
    result = subprocess.run([sys.executable, str(GATE)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_json_verdict_carries_the_counts_it_was_based_on() -> None:
    """A verdict with no counts cannot be audited for having scanned anything."""
    import json

    result = subprocess.run([sys.executable, str(GATE), "--json"], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["findings"] == []
    assert all(value > 0 for value in payload["counts"].values()), payload["counts"]
