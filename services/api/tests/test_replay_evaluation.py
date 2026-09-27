"""Replay evaluation: the credential translation, the chain, the export, the routes.

Gap-closure Phase 1.4 gate.

Four properties, each asserted by name below:

* a connector's stored field names reach the readers as the credential keys
  the client factory actually reads, in both directions
* a failure anywhere in the chain is terminal with a reason, never a partial
  report over whichever findings arrived
* the export serves the artefact that was stored, and the latency exclusion is
  the only thing it changes
* the tenant comes from the credential, and a run belonging to another tenant
  is not reachable

Nothing here needs a database or a network. The store is a recorded stub and
the two service calls are a mock transport, so the orchestration can be driven
through every branch.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from app._vendor.aisoc_benchmark.replay import LATENCY_LINE_PREFIX, format_replay_report, score_replay
from app.api.v1.deps import CurrentUser, get_current_user
from app.api.v1.endpoints.evaluations import router as evaluations_router
from app.services.replay_evaluation import job as job_module
from app.services.replay_evaluation import report as report_export
from app.services.replay_evaluation import store as store_module
from app.services.replay_evaluation.vendors import (
    REPLAYABLE_CONNECTORS,
    UnsupportedConnector,
    credentials_for,
    replayable_connector_ids,
    vendor_for,
)
from fastapi import FastAPI
from fastapi.testclient import TestClient

TENANT = uuid.UUID("aaaaaaaa-0000-0000-0000-00000000000a")
OTHER_TENANT = uuid.UUID("bbbbbbbb-0000-0000-0000-00000000000b")
USER = uuid.UUID("11111111-1111-1111-1111-111111111111")


# ---------------------------------------------------------------------------
# The credential translation
# ---------------------------------------------------------------------------


class TestCredentialTranslation:
    """Two vocabularies meet, and a key under the wrong name fails silently.

    The factory returns ``None`` rather than raising, so the symptom is "no
    usable credentials", which reads to an operator as a problem on their
    side. That makes this the mapping most worth pinning.
    """

    def test_splunk_fields_reach_the_keys_the_factory_reads(self) -> None:
        credentials = credentials_for(
            "splunk",
            {"base_url": "https://splunk:8089", "token": "t"},
            {"ssl_verify": False, "saved_search": "`my_notables`"},
        )

        assert credentials["splunk_url"] == "https://splunk:8089"
        assert credentials["splunk_token"] == "t"
        assert credentials["search_override"] == "`my_notables`"
        # False is copied, not dropped. Disabling verification is a deliberate
        # choice for an internal CA, and dropping it would silently re-enable
        # verification against a certificate that will not validate.
        assert credentials["splunk_verify_ssl"] is False

    def test_every_mapped_target_is_a_key_some_factory_actually_reads(self) -> None:
        """The direction that drifts.

        ``services/actions`` declares the key names its client factory reads.
        This asserts every target this table produces is in one of those sets,
        so a factory that renames a key fails here rather than at a customer's
        first evaluation.
        """
        # Mirrored rather than imported: this service cannot import
        # ``services/actions``. The lists are the ``*_CLIENT_PARAM_KEYS``
        # tuples in ``app/executors/siem.py`` plus the two reader-only knobs.
        known = {
            "splunk_url",
            "splunk_host",
            "splunk_token",
            "splunk_username",
            "splunk_password",
            "splunk_verify_ssl",
            "elastic_url",
            "elastic_api_key",
            "elastic_username",
            "elastic_password",
            "kibana_url",
            "sentinel_tenant_id",
            "sentinel_client_id",
            "sentinel_client_secret",
            "sentinel_subscription_id",
            "sentinel_resource_group",
            "sentinel_workspace_name",
            "qradar_url",
            "qradar_token",
            "qradar_verify_ssl",
            "mde_tenant_id",
            "mde_client_id",
            "mde_client_secret",
            # Reader arguments rather than client-constructor keys.
            "search_override",
            "index",
        }
        for entry in REPLAYABLE_CONNECTORS.values():
            for target in (*entry.auth_map.values(), *entry.config_map.values()):
                assert target in known, f"{entry.connector_type} maps to unknown credential key {target}"

    def test_a_field_the_tenant_did_not_store_is_omitted_not_nulled(self) -> None:
        credentials = credentials_for("splunk", {"base_url": "https://splunk:8089"}, {})

        assert "splunk_token" not in credentials
        assert "splunk_username" not in credentials

    def test_every_replayable_connector_names_a_reader_arm(self) -> None:
        for connector_type in replayable_connector_ids():
            assert vendor_for(connector_type) in {"splunk", "sentinel", "elastic", "qradar", "defender"}

    def test_all_five_reader_arms_are_reachable_from_some_connector(self) -> None:
        """The reverse direction: a reader nothing can reach is a reader nobody runs."""
        reached = {entry.vendor for entry in REPLAYABLE_CONNECTORS.values()}
        assert reached == {"splunk", "sentinel", "elastic", "qradar", "defender"}

    def test_a_connector_with_no_reader_is_refused_by_name(self) -> None:
        with pytest.raises(UnsupportedConnector) as excinfo:
            credentials_for("crowdstrike", {"client_id": "x"}, {})

        message = str(excinfo.value)
        assert "crowdstrike" in message
        # The refusal lists what *is* supported, so an operator has the next
        # step rather than only the rejection.
        assert "splunk" in message


# ---------------------------------------------------------------------------
# The export
# ---------------------------------------------------------------------------


def _decision(index: int, expected: str, verdict: str) -> dict[str, Any]:
    return {
        "finding_id": f"ES-{index:03d}",
        "vendor": "splunk",
        "rule_id": "rule-42",
        "closed_at": "2026-03-01T00:00:00+00:00",
        "expected_disposition": expected,
        "vendor_disposition": "disposition:1",
        "labelled": True,
        "verdict": verdict,
        "verdict_raw": verdict,
        "confidence": 0.8,
        "tier": "deterministic",
        "findings": ["Observed 198.51.100.7 beaconing"],
        "confidence_basis": [],
        "evidence": {"src_ip": "198.51.100.7"},
        "tool_calls": 0,
        "resolved_models": [],
        "tokens": 0,
        "measured_usd": None,
        "estimated_usd": None,
        "unpriced_calls": 0,
        "latency_ms": index,
        "error": None,
    }


def _corpus() -> list[dict[str, Any]]:
    rows = [_decision(i, "true_positive", "true_positive") for i in range(35)]
    rows += [_decision(100 + i, "false_positive", "false_positive") for i in range(60)]
    return rows


class TestExport:
    def test_the_markdown_export_is_the_stored_bytes_untouched(self) -> None:
        stored = "# Replay evaluation\n\n- Decisions replayed: 3\n"

        assert report_export.report_markdown(stored) == stored

    def test_excluding_latency_changes_that_line_and_nothing_else(self) -> None:
        """The precise form of the reproducibility claim.

        Everything else in the report is a property of the input and the code.
        The two latency figures measure the host, and they will differ between
        two runs on the same machine.
        """
        report = format_replay_report(score_replay(_corpus()))
        stripped = report_export.report_markdown(report, exclude_latency=True)

        original = report.split("\n")
        after = stripped.split("\n")
        assert len(original) == len(after)
        differing = [(a, b) for a, b in zip(original, after, strict=True) if a != b]
        assert len(differing) == 1
        assert differing[0][0].startswith(LATENCY_LINE_PREFIX)
        assert differing[0][1].startswith(LATENCY_LINE_PREFIX)
        assert "not reproducible" in differing[0][1]

    def test_the_json_export_nulls_latency_rather_than_dropping_the_keys(self) -> None:
        score = score_replay(_corpus()).as_dict()
        assert score["mean_latency_ms"] is not None

        payload = json.loads(report_export.report_json(evaluation_id="e", score=score, method={}, exclude_latency=True))

        # Present and None, not absent. A reader should not have to tell "this
        # run measured no latency" from "this key is missing on some exports".
        assert payload["score"]["mean_latency_ms"] is None
        assert payload["score"]["p95_latency_ms"] is None
        assert payload["latency_excluded"] is True

    def test_the_json_export_is_stable_across_two_renders(self) -> None:
        score = score_replay(_corpus()).as_dict()

        first = report_export.report_json(evaluation_id="e", score=score, method={"a": 1})
        second = report_export.report_json(evaluation_id="e", score=score, method={"a": 1})

        assert first == second

    def test_model_output_in_the_report_is_escaped_before_it_becomes_html(self) -> None:
        """The report embeds strings a model produced from attacker-influenced evidence.

        Hallucinated indicator examples are model output by definition, and
        they reach the PDF. Writing them into HTML unescaped would put that
        output into a document an operator opens.
        """
        markdown = "## Hallucination\n\n- Examples: <script>alert(1)</script>, a&b\n"

        html = report_export.markdown_to_html(markdown)

        assert "<script>" not in html
        assert "&lt;script&gt;" in html
        assert "a&amp;b" in html

    def test_the_html_has_no_generation_timestamp(self) -> None:
        """A report that prints "generated at" cannot reproduce byte for byte."""
        html = report_export.markdown_to_html("# Replay evaluation\n\n- Decisions replayed: 3\n")

        assert "generated" not in html.lower()

    def test_tables_survive_the_conversion_with_their_header(self) -> None:
        markdown = "| Disposition | Support |\n|---|---|\n| true_positive | 31 |\n"

        html = report_export.markdown_to_html(markdown)

        assert "<th>Disposition</th>" in html
        assert "<td>true_positive</td>" in html
        # The divider row carries no data and must not become a row.
        assert html.count("<tr>") == 2


# ---------------------------------------------------------------------------
# The chain
# ---------------------------------------------------------------------------


class _RecordingStore:
    """Stands in for the two tables, recording what the job would have written."""

    def __init__(self) -> None:
        self.status: list[str] = []
        self.failure: str | None = None
        self.result: dict[str, Any] | None = None

    async def mark_running(self, db: Any, *, tenant_id: uuid.UUID, evaluation_id: uuid.UUID) -> None:
        self.status.append("running")

    async def fail_evaluation(self, db: Any, *, tenant_id: uuid.UUID, evaluation_id: uuid.UUID, error: str) -> None:
        self.status.append("failed")
        self.failure = error

    async def store_result(self, db: Any, **fields: Any) -> None:
        self.status.append("completed")
        self.result = fields


class _StubSession:
    """Just enough AsyncSession for the job's own calls."""

    def __init__(self, connector: Any = None) -> None:
        self._connector = connector

    async def execute(self, *args: Any, **kwargs: Any) -> Any:
        connector = self._connector

        class _Result:
            def scalar_one_or_none(self) -> Any:
                return connector

        return _Result()

    async def rollback(self) -> None:
        return None


class _Connector:
    def __init__(self) -> None:
        self.connector_type = "splunk"
        self.auth_config = {"base_url": "https://splunk:8089", "token": "t"}
        self.connector_config = {"ssl_verify": True}


def _request(**overrides: Any) -> job_module.ReplayRequest:
    defaults: dict[str, Any] = {
        "tenant_id": TENANT,
        "evaluation_id": uuid.uuid4(),
        "connector_row_id": uuid.uuid4(),
        "connector_type": "splunk",
        "vendor": "splunk",
        "window_start": datetime(2026, 3, 1, tzinfo=UTC),
        "window_end": datetime(2026, 6, 1, tzinfo=UTC),
        "train_fraction": 0.7,
        "limit": 1000,
        "bootstrap_seed": 20260926,
        "bootstrap_resamples": 50,
    }
    return job_module.ReplayRequest(**{**defaults, **overrides})


@pytest.fixture
def recording_store(monkeypatch: pytest.MonkeyPatch) -> _RecordingStore:
    stub = _RecordingStore()
    monkeypatch.setattr(job_module.store, "mark_running", stub.mark_running)
    monkeypatch.setattr(job_module.store, "fail_evaluation", stub.fail_evaluation)
    monkeypatch.setattr(job_module.store, "store_result", stub.store_result)
    return stub


@pytest.fixture
def no_vault(monkeypatch: pytest.MonkeyPatch) -> None:
    """The vault is exercised by its own suite; here it passes the dict through."""

    class _Vault:
        def decrypt_dict(self, value: dict[str, Any]) -> dict[str, Any]:
            return dict(value)

    monkeypatch.setattr(job_module, "get_vault", lambda: _Vault())


def _transport(monkeypatch: pytest.MonkeyPatch, handler: Any) -> None:
    real_client = httpx.AsyncClient
    monkeypatch.setattr(
        job_module.httpx,
        "AsyncClient",
        lambda *a, **kw: real_client(*a, **{**kw, "transport": httpx.MockTransport(handler)}),
    )


@pytest.mark.asyncio
class TestChain:
    async def test_a_complete_run_scores_and_stores_the_report(
        self,
        monkeypatch: pytest.MonkeyPatch,
        recording_store: _RecordingStore,
        no_vault: None,
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/replay/history"):
                return httpx.Response(
                    200,
                    json={"vendor": "splunk", "count": 95, "labelled": 95, "unlabeled": 0, "findings": [{"x": 1}]},
                )
            return httpx.Response(200, json={"decisions": _corpus(), "method": {"split": {"train_findings": 66}}})

        _transport(monkeypatch, handler)

        await job_module.run_evaluation(_StubSession(_Connector()), _request())

        assert recording_store.status == ["running", "completed"]
        result = recording_store.result
        assert result is not None
        assert result["report_markdown"].startswith("# Replay evaluation")
        # The sample sizes the console shows beside the headline come from the
        # history read, not from the decision count, so the two surfaces
        # cannot disagree about what was read.
        assert result["method"]["history"]["findings_read"] == 95
        assert result["method"]["history"]["findings_labelled"] == 95
        assert result["findings_read"] == 95

    async def test_an_empty_window_is_a_failure_not_a_report_over_nothing(
        self,
        monkeypatch: pytest.MonkeyPatch,
        recording_store: _RecordingStore,
        no_vault: None,
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"vendor": "splunk", "count": 0, "labelled": 0, "findings": []})

        _transport(monkeypatch, handler)

        await job_module.run_evaluation(_StubSession(_Connector()), _request())

        assert recording_store.status == ["running", "failed"]
        assert "no closed findings" in (recording_store.failure or "")
        assert recording_store.result is None

    async def test_a_history_read_that_fails_is_terminal_with_the_reason(
        self,
        monkeypatch: pytest.MonkeyPatch,
        recording_store: _RecordingStore,
        no_vault: None,
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/replay/history"):
                return httpx.Response(502, json={"detail": "reading splunk history failed: ConnectError"})
            raise AssertionError("the replay must not run when the history could not be read")

        _transport(monkeypatch, handler)

        await job_module.run_evaluation(_StubSession(_Connector()), _request())

        assert recording_store.status == ["running", "failed"]
        assert "502" in (recording_store.failure or "")

    async def test_a_connector_in_another_tenant_is_not_reachable(
        self,
        monkeypatch: pytest.MonkeyPatch,
        recording_store: _RecordingStore,
        no_vault: None,
    ) -> None:
        """The row is loaded with a tenant predicate, so it resolves to nothing."""
        _transport(monkeypatch, lambda request: httpx.Response(200, json={}))

        await job_module.run_evaluation(_StubSession(connector=None), _request(tenant_id=OTHER_TENANT))

        assert recording_store.status == ["running", "failed"]
        assert "not found" in (recording_store.failure or "")

    async def test_an_unexpected_exception_still_terminates_the_row(
        self,
        monkeypatch: pytest.MonkeyPatch,
        recording_store: _RecordingStore,
        no_vault: None,
    ) -> None:
        """A detached job that raises would otherwise leave the row running forever.

        A job that never terminates is indistinguishable from a slow one, and
        a poller would wait on it until it gave up.
        """

        def handler(request: httpx.Request) -> httpx.Response:
            raise RuntimeError("something nobody predicted")

        _transport(monkeypatch, handler)

        await job_module.run_evaluation(_StubSession(_Connector()), _request())

        assert recording_store.status == ["running", "failed"]
        assert recording_store.failure

    async def test_the_agents_call_declares_the_tenant_it_acts_for(
        self,
        monkeypatch: pytest.MonkeyPatch,
        recording_store: _RecordingStore,
        no_vault: None,
    ) -> None:
        """A service token with no tenant header resolves to an empty scope.

        So the header is always sent, and it always carries the tenant the
        route took from the caller's credential.
        """
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            if request.url.path.endswith("/replay/history"):
                return httpx.Response(200, json={"vendor": "splunk", "count": 1, "labelled": 1, "findings": [{"x": 1}]})
            return httpx.Response(200, json={"decisions": _corpus(), "method": {}})

        _transport(monkeypatch, handler)

        await job_module.run_evaluation(_StubSession(_Connector()), _request())

        replay_calls = [r for r in seen if r.url.path.endswith("/replay/run")]
        assert replay_calls
        assert replay_calls[0].headers["X-AiSOC-Tenant-ID"] == str(TENANT)

    async def test_the_credentials_forwarded_are_the_translated_ones(
        self,
        monkeypatch: pytest.MonkeyPatch,
        recording_store: _RecordingStore,
        no_vault: None,
    ) -> None:
        seen: list[dict[str, Any]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/replay/history"):
                seen.append(json.loads(request.content))
                return httpx.Response(200, json={"vendor": "splunk", "count": 1, "labelled": 1, "findings": [{"x": 1}]})
            return httpx.Response(200, json={"decisions": _corpus(), "method": {}})

        _transport(monkeypatch, handler)

        await job_module.run_evaluation(_StubSession(_Connector()), _request())

        assert seen
        assert seen[0]["credentials"]["splunk_url"] == "https://splunk:8089"
        assert "base_url" not in seen[0]["credentials"]


# ---------------------------------------------------------------------------
# The routes
# ---------------------------------------------------------------------------


@pytest.fixture
def stub_app(monkeypatch: pytest.MonkeyPatch) -> FastAPI:
    """Only the evaluations router, with a resolved user.

    Same pattern as ``test_misp_push.py``: the production composition is
    covered elsewhere, and that these routes refuse an anonymous caller is
    asserted by ``scripts/check_route_auth.py``.
    """
    app = FastAPI()
    app.include_router(evaluations_router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: CurrentUser(
        user_id=USER,
        tenant_id=TENANT,
        email="stub@example.test",
        role="admin",
        scopes=["*"],
    )
    return app


def test_capabilities_names_only_connectors_with_a_reader(stub_app: FastAPI) -> None:
    """The console must not offer a source this deployment cannot replay."""
    from app.db.database import get_db

    stub_app.dependency_overrides[get_db] = lambda: None
    body = TestClient(stub_app).get("/api/v1/evaluations/replay/capabilities").json()

    assert {c["connector_type"] for c in body["connectors"]} == set(replayable_connector_ids())
    # The floor travels to the client so the page can say why a headline would
    # be withheld before a run is started, not only after.
    assert body["min_malicious_for_headline"] == 30


def test_an_evaluation_in_another_tenant_is_a_404(stub_app: FastAPI, monkeypatch: pytest.MonkeyPatch) -> None:
    """Not a 403: telling the two apart would confirm the id exists."""
    from app.db.database import get_db

    stub_app.dependency_overrides[get_db] = lambda: _StubSession()

    async def _none(db: Any, **kwargs: Any) -> None:
        return None

    monkeypatch.setattr(store_module, "get_evaluation", _none)

    response = TestClient(stub_app).get(f"/api/v1/evaluations/replay/{uuid.uuid4()}")

    assert response.status_code == 404


def test_exporting_a_run_that_has_no_report_is_a_409_with_the_reason(stub_app: FastAPI, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.db.database import get_db

    stub_app.dependency_overrides[get_db] = lambda: _StubSession()
    evaluation_id = uuid.uuid4()

    async def _failed(db: Any, **kwargs: Any) -> store_module.EvaluationRow:
        return store_module.EvaluationRow(
            id=evaluation_id,
            tenant_id=TENANT,
            status="failed",
            error="the actions service is unreachable",
            connector_id="c",
            vendor="splunk",
            window_start=datetime(2026, 3, 1, tzinfo=UTC),
            window_end=datetime(2026, 6, 1, tzinfo=UTC),
            train_fraction=0.7,
            bootstrap_seed=1,
            bootstrap_resamples=1,
            findings_read=0,
            findings_labelled=0,
            decisions_recorded=0,
            graded=0,
            malicious_support=0,
            headline_accuracy=None,
            headline_withheld_reason=None,
            malicious_recall=None,
            requested_by=USER,
            created_at=datetime(2026, 6, 1, tzinfo=UTC),
            started_at=None,
            completed_at=None,
        )

    monkeypatch.setattr(store_module, "get_evaluation", _failed)

    response = TestClient(stub_app).get(f"/api/v1/evaluations/replay/{evaluation_id}/export")

    assert response.status_code == 409
    assert "unreachable" in response.json()["detail"]


def test_no_route_on_this_surface_takes_a_tenant_from_the_caller() -> None:
    """The tenant is never a request field, a query parameter or a path segment."""
    for route in evaluations_router.routes:
        assert "tenant" not in route.path
        for name in getattr(route, "dependant", None).query_params if hasattr(route, "dependant") else []:
            assert "tenant" not in name.name


def test_the_withheld_headline_is_null_rather_than_zero() -> None:
    """A zero in an accuracy column says the agent got every answer wrong.

    "The window held too few malicious cases to print one" is a different
    fact with a different remedy, and the two must not render the same.
    """
    thin = [_decision(i, "true_positive", "true_positive") for i in range(5)]
    score = score_replay(thin)

    assert score.headline_accuracy is None
    assert score.headline_withheld_reason
    assert "below the 30" in score.headline_withheld_reason
