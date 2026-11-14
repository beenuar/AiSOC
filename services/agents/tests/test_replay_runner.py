"""The replay runner: splitting, envelope construction, and reproducibility.

Gap-closure Phase 1.2.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from app.replay.connector_normalizer import (
    _API_PREFIX,
    PrenormalizedRows,
    fetch_normalized,
    row_key,
)
from app.replay.findings import HistoricalFinding
from app.replay.normalize import NormalizerUnavailable, to_fused_envelope
from app.replay.runner import DEFAULT_TRAIN_FRACTION, ReplayRunner, split_by_time

from tests.replay_recording import (
    SplunkNotableNormalizer,
    assert_non_degenerate,
    comparable,
    historical_findings,
    load_recording,
    recorded_gateway,
    verdict_classes,
)

_BASE = datetime(2026, 3, 1, tzinfo=UTC)

#: The real Splunk ES notable shape, as ``list_closed_notables`` returns it.
#: Recorded rather than invented: the field names are the ones the SPL in
#: ``SplunkClient.list_closed_notables`` selects.
_NOTABLE = {
    "event_id": "ES-1",
    "rule_id": "rule-42",
    "rule_name": "Suspicious PowerShell",
    "search_name": "Suspicious PowerShell",
    "urgency": "high",
    "disposition": "disposition:1",
    "src": "192.0.2.10",
    "host": "WS-01",
    "_time": "1772323200",
}


class _SplunkLikeNormalizer:
    """The mapping ``services/connectors`` applies to a Splunk row.

    A stand-in, and the docstring says so rather than letting a reader assume
    the real connector is under test here. The real one is reached over HTTP
    in production (``app.replay.connector_normalizer``) and is exercised
    against the registry in the connectors service's own suite.
    """

    connector_id = "splunk"

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        return {
            "source": "splunk",
            "external_id": raw.get("event_id", ""),
            "title": raw.get("search_name") or "Splunk Notable Event",
            "severity": "high",
            "src_ip": raw.get("src"),
            "hostname": raw.get("host"),
            "raw_event": raw,
            "created_at": raw.get("_time"),
        }


def _finding(index: int, *, disposition: str = "false_positive") -> HistoricalFinding:
    return HistoricalFinding(
        vendor="splunk",
        finding_id=f"ES-{index:03d}",
        title="Suspicious PowerShell",
        disposition=disposition,
        vendor_disposition="disposition:1",
        closed_at=_BASE + timedelta(hours=index),
        rule_id="rule-42",
        raw={**_NOTABLE, "event_id": f"ES-{index:03d}"},
    )


# --------------------------------------------------------------------------
# Splitting
# --------------------------------------------------------------------------


def test_the_split_is_by_time_and_the_test_window_is_the_later_period() -> None:
    findings = [_finding(i) for i in range(10)]

    split = split_by_time(findings)

    assert split.train_fraction == DEFAULT_TRAIN_FRACTION
    assert len(split.train) == 7
    assert len(split.test) == 3
    assert max(f.closed_at for f in split.train) <= split.split_at
    assert min(f.closed_at for f in split.test) > split.split_at


def test_a_finding_closed_exactly_at_the_split_stays_in_the_train_window() -> None:
    """A tie must not become a test case the frozen context already knows about."""
    findings = [_finding(i) for i in range(10)]
    # Give three findings the same close time as the boundary row.
    tied = [
        HistoricalFinding(
            vendor="splunk",
            finding_id=f"TIE-{i}",
            title="Tied",
            disposition="false_positive",
            vendor_disposition="disposition:3",
            closed_at=findings[6].closed_at,
            raw=dict(_NOTABLE),
        )
        for i in range(3)
    ]

    split = split_by_time([*findings, *tied])

    assert all(f.closed_at <= split.split_at for f in split.train)
    assert not any(f.finding_id.startswith("TIE") for f in split.test)


def test_splitting_is_stable_when_close_times_collide() -> None:
    """A bulk close gives many findings one timestamp; the order must still be total."""
    same_time = [
        HistoricalFinding(
            vendor="splunk",
            finding_id=f"BULK-{i:02d}",
            title="Bulk closed",
            disposition="false_positive",
            vendor_disposition="disposition:3",
            closed_at=_BASE,
            raw=dict(_NOTABLE),
        )
        for i in range(10)
    ]
    later = [_finding(i + 50) for i in range(10)]

    first = split_by_time([*same_time, *later])
    shuffled = split_by_time([*later[::-1], *same_time[::-1]])

    assert [f.finding_id for f in first.test] == [f.finding_id for f in shuffled.test]


def test_an_empty_history_is_refused_rather_than_split() -> None:
    with pytest.raises(ValueError, match="empty history"):
        split_by_time([])


@pytest.mark.parametrize("fraction", [0.0, 1.0, -0.1, 1.5])
def test_a_fraction_that_would_empty_a_window_is_refused(fraction: float) -> None:
    with pytest.raises(ValueError, match="strictly between"):
        split_by_time([_finding(0), _finding(1)], train_fraction=fraction)


# --------------------------------------------------------------------------
# Envelope
# --------------------------------------------------------------------------


def test_the_envelope_carries_the_fields_build_state_reads() -> None:
    finding = _finding(1)
    normalized = _SplunkLikeNormalizer().normalize(dict(finding.raw))

    envelope = to_fused_envelope(finding, normalized, tenant_id="t-1", connector_id="splunk")

    alert = envelope["alert"]
    assert envelope["alert_row_id"] == finding.finding_id
    assert alert["title"] == "Suspicious PowerShell"
    assert alert["severity"] == "high"
    # Lifted by the connector.
    assert alert["src_ip"] == "192.0.2.10"
    assert alert["hostname"] == "WS-01"
    # Present only in the untouched vendor row; read from there rather than
    # dropped, because a connector lifts only what it has a canonical home for.
    assert alert["rule_id"] == "rule-42"
    assert alert["connector_type"] == "splunk"
    assert alert["raw_event"] == dict(finding.raw)


def test_the_envelope_does_not_invent_a_fusion_confidence() -> None:
    """Fusion computes it from correlated evidence a single finding does not have."""
    finding = _finding(1)
    envelope = to_fused_envelope(finding, _SplunkLikeNormalizer().normalize(dict(finding.raw)), tenant_id="t-1")

    assert "confidence_score" not in envelope
    assert envelope["alert"]["risk_score"] == 0.0


# --------------------------------------------------------------------------
# Running
# --------------------------------------------------------------------------


#: Fixed rather than generated, so the two runs below differ in nothing at all.
_REPLAY_TENANT = "6f1b2a84-0c3e-4f5a-9d27-8c1a0b3e4f55"


@pytest.mark.asyncio
async def test_two_runs_over_one_history_produce_identical_decisions(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reproducible, and over verdicts that are not all the same verdict.

    Fix pass 3.5. This asserted reproducibility with ``AISOC_DETERMINISTIC=1``
    set, which pins triage to the heuristic tier — and that tier answers
    ``likely_benign`` at 0.10 for every alert it is given. So the acceptance
    bar for Phase 1 was one constant list compared against itself: a runner
    that had stopped reading its input entirely would have passed it.

    What drives it now is a recording of a real model answering the real
    triage prompt (``tests/eval_data/replay_triage_recording.json``), served
    over a loopback socket to the gateway client the worker actually builds.
    Recordings give both halves at once — a live model varies its verdicts and
    cannot repeat them, a constant repeats and does not vary.

    Latency is excluded from the comparison and nothing else is. It is a wall
    clock measurement and will never repeat; every other field is a property
    of the input and the code. Driving a real reply through the path found a
    second place it leaks — ``run_auto_triage`` writes the elapsed time into a
    finding string — which a constant-output run could never have shown.
    """
    recording = load_recording()
    findings = historical_findings(recording)

    async def _run() -> list[dict[str, Any]]:
        with recorded_gateway(recording["responses"], monkeypatch) as gateway:
            runner = ReplayRunner(normalizer=SplunkNotableNormalizer(), tenant_id=_REPLAY_TENANT)
            run = await runner.run(findings)
            # A replay that quietly took the deterministic path would be
            # reproducible for the old reason, so the gateway is asked whether
            # it was called rather than the tier being trusted to say so.
            assert not gateway.refused, f"the run asked for alerts the recording does not cover: {gateway.refused}"
            assert len(gateway.served) == len(run.decisions), f"served {len(gateway.served)} replies for {len(run.decisions)} decisions"
        return [comparable(decision.as_dict()) for decision in run.decisions]

    first = await _run()
    second = await _run()

    assert first == second
    assert_non_degenerate(first)


def test_the_acceptance_bar_rejects_a_constant_verdict_stream() -> None:
    """The guard above, proven against the output it exists to refuse.

    Without this, ``assert_non_degenerate`` is itself unfalsified: the only
    evidence it works would be that it passes on a recording chosen because it
    passes. The rows here are what the deterministic tier really produced on
    the pre-fix test — six alerts, one verdict, one confidence.
    """
    constant = [{"verdict": "benign", "confidence": 0.1, "error": None} for _ in range(6)]

    with pytest.raises(AssertionError, match="one class"):
        assert_non_degenerate(constant)

    assert verdict_classes(constant) == {"benign"}


@pytest.mark.asyncio
async def test_a_row_the_normalizer_cannot_map_is_recorded_not_guessed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_DETERMINISTIC", "1")

    class _Refuses:
        connector_id = "splunk"

        def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
            if raw.get("event_id") == "ES-009":
                raise NormalizerUnavailable("no envelope for this row")
            return _SplunkLikeNormalizer().normalize(raw)

    runner = ReplayRunner(normalizer=_Refuses(), tenant_id=str(uuid.uuid4()))
    run = await runner.run([_finding(i) for i in range(10)])

    refused = [d for d in run.decisions if d.finding_id == "ES-009"]
    assert len(refused) == 1
    assert refused[0].verdict is None
    assert "no envelope for this row" in (refused[0].error or "")


# --------------------------------------------------------------------------
# Reaching the production normalizer over HTTP
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_connectors_service_supplies_the_normalized_envelopes() -> None:
    rows = [dict(_NOTABLE), {**_NOTABLE, "event_id": "ES-2"}]
    seen: dict[str, Any] = {}

    def _handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["token"] = request.headers.get("Authorization")
        seen["tenant"] = request.headers.get("X-AiSOC-Tenant-ID")
        return httpx.Response(
            200,
            json={
                "connector_id": "splunk",
                "row_count": 2,
                "rows": [_SplunkLikeNormalizer().normalize(dict(row)) for row in rows],
            },
        )

    transport = httpx.MockTransport(_handler)
    original = httpx.AsyncClient

    def _client(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = transport
        return original(*args, **kwargs)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(httpx, "AsyncClient", _client)
        lookup = await fetch_normalized("splunk", rows, tenant_id="t-1", service_url="http://connectors:8003", service_token="secret")

    # The connectors service mounts its router under /api/v1. This asserted
    # the bare path when the route shipped, which codified the defect rather
    # than catching it: nothing called `fetch_normalized` until Phase 1.4, so
    # a 404 on every request was invisible.
    # `test_the_normalize_url_matches_where_the_route_is_mounted` below reads
    # the mount out of the connectors service instead of restating it here.
    assert seen["url"] == "http://connectors:8003/api/v1/connectors/splunk/normalize"
    assert seen["token"] == "Bearer secret"
    assert seen["tenant"] == "t-1"
    assert isinstance(lookup, PrenormalizedRows)
    assert lookup.normalize(dict(rows[1]))["external_id"] == "ES-2"


@pytest.mark.asyncio
async def test_a_short_batch_is_refused_rather_than_partially_graded() -> None:
    """Fewer envelopes than rows would silently drop findings from the window."""
    rows = [dict(_NOTABLE), {**_NOTABLE, "event_id": "ES-2"}]

    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"connector_id": "splunk", "row_count": 1, "rows": [{"source": "splunk"}]})

    transport = httpx.MockTransport(_handler)
    original = httpx.AsyncClient

    def _client(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = transport
        return original(*args, **kwargs)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(httpx, "AsyncClient", _client)
        with pytest.raises(NormalizerUnavailable, match="silently drop findings"):
            await fetch_normalized("splunk", rows, tenant_id="t-1", service_token="secret")


@pytest.mark.asyncio
async def test_a_missing_service_token_is_named_rather_than_retried() -> None:
    with pytest.raises(NormalizerUnavailable, match="AISOC_SERVICE_TOKEN"):
        await fetch_normalized("splunk", [dict(_NOTABLE)], tenant_id="t-1", service_token="")


def test_a_row_outside_the_batch_is_refused_never_substituted() -> None:
    lookup = PrenormalizedRows({row_key(_NOTABLE): {"source": "splunk"}}, connector_id="splunk")

    with pytest.raises(NormalizerUnavailable, match="will not substitute"):
        lookup.normalize({"event_id": "never-sent"})


def test_the_normalize_url_matches_where_the_route_is_mounted() -> None:
    """Both directions, against the connectors service's own source.

    Gap-closure Phase 1.4. This service cannot import ``services/connectors``
    (both package their code as top-level ``app``), so the mount prefix and
    the route path are read out of that tree with ``ast`` rather than
    restated here. A test that restates them is a test that agrees with
    itself: the previous one asserted a URL missing the ``/api/v1`` segment
    and passed for as long as nothing called the function.
    """
    import ast

    connectors = Path(__file__).resolve().parents[3] / "services" / "connectors" / "app"

    main = ast.parse((connectors / "main.py").read_text())
    prefixes: set[str] = {
        str(keyword.value.value)
        for node in ast.walk(main)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "include_router"
        for keyword in node.keywords
        if keyword.arg == "prefix" and isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str)
    }
    assert prefixes, "could not read any router prefix out of the connectors service"

    router = ast.parse((connectors / "api" / "router.py").read_text())
    routes: set[str] = {
        str(decorator.args[0].value)
        for node in ast.walk(router)
        if isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef)
        for decorator in node.decorator_list
        if isinstance(decorator, ast.Call)
        and isinstance(decorator.func, ast.Attribute)
        and decorator.func.attr in {"post", "get"}
        and decorator.args
        and isinstance(decorator.args[0], ast.Constant)
        and isinstance(decorator.args[0].value, str)
    }
    normalize_route = next(r for r in routes if r.endswith("/normalize"))

    # What `fetch_normalized` would actually request, built the same way it
    # builds it, against what the service actually serves.
    served = {f"{prefix}{normalize_route}".replace("{connector_id}", "splunk") for prefix in prefixes}
    requested = f"{_API_PREFIX}/connectors/splunk/normalize"
    assert requested in served, f"{requested} is not served; the service mounts {sorted(served)}"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "connector_id",
    [
        "../../admin",
        "splunk/../../v1/shutdown",
        "http://169.254.169.254/latest/meta-data",
        "splunk?x=1",
        "SPLUNK",
        "",
    ],
)
async def test_a_connector_id_that_is_not_one_never_reaches_a_url(connector_id: str) -> None:
    """The id arrives in a request body and is interpolated into a URL path.

    Refused against the registry's own shape rather than escaped: encoding
    would turn `../../admin` into a literal segment that 404s, which reads as
    a missing connector, while refusing names the value that was wrong. A
    string outside this shape could not name a real connector anyway.
    """
    with pytest.raises(NormalizerUnavailable, match="not a connector id"):
        await fetch_normalized(
            connector_id,
            [dict(_NOTABLE)],
            tenant_id="t-1",
            service_url="http://connectors:8003",
            service_token="secret",
        )
