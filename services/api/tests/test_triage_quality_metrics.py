"""Abstention and groundedness are published, not just computed.

v8.0 wired `app.confidence.groundedness` into the triage path so an
auto-closing verdict whose reasoning cites indicators the evidence never
contained is demoted to `needs_review` instead of closing. The score itself
survived only inside a findings string, which meant it could not be
aggregated, trended, or used to answer the question a buyer evaluating an
AI-SOC actually asks: how often is your agent's reasoning supported by what it
was shown, and how often does it decline to decide?

A system that never abstains is not calibrated — it is guessing with
confidence. Publishing the rate inverts the usual vendor incentive to report
only automation percentage.

Two things these tests pin down because both are easy to get wrong in the
flattering direction:

* `mean_groundedness` averages only *scored* verdicts. The deterministic
  triage path never assesses groundedness, so counting its verdicts as 0.0
  would report a platform-wide collapse in reasoning quality every time the
  LLM path was unavailable.
* NULL means "not scored", which is a different fact from "scored zero".
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

metrics = pytest.importorskip(
    "app.api.v1.endpoints.metrics",
    reason="API dependencies not installed",
)


class _Row:
    """Positional row shaped like the aggregate query's SELECT list."""

    def __init__(self, triaged, abstentions, ungrounded, scored, mean):
        self._v = (triaged, abstentions, ungrounded, scored, mean)

    def __getitem__(self, i):
        return self._v[i]


class _DB:
    def __init__(self, row=None, raises=False):
        self._row = row
        self._raises = raises

    async def execute(self, *_a, **_k):
        if self._raises:
            raise RuntimeError("column does not exist")
        row = self._row

        class _Result:
            @staticmethod
            def first():
                return row

        return _Result()


@pytest.mark.asyncio
async def test_abstention_rate_is_needs_review_over_triaged():
    out = await metrics._triage_quality(
        _DB(_Row(triaged=100, abstentions=25, ungrounded=4, scored=80, mean=0.91)),
        "t",
        None,
        None,
    )
    assert out["triaged_alerts"] == 100
    assert out["abstentions"] == 25
    assert out["abstention_rate"] == 0.25


@pytest.mark.asyncio
async def test_ungrounded_demotions_are_counted_separately():
    """Distinct from the abstention count.

    `needs_review` is also reached by low confidence and by genuine
    escalation. This is the subset where the agent had a confident
    auto-closing answer that its own evidence did not support, which is a
    different and more alarming signal.
    """
    out = await metrics._triage_quality(
        _DB(_Row(triaged=100, abstentions=25, ungrounded=4, scored=80, mean=0.91)),
        "t",
        None,
        None,
    )
    assert out["ungrounded_demotions"] == 4
    assert out["ungrounded_demotions"] < out["abstentions"]


@pytest.mark.asyncio
async def test_mean_groundedness_averages_only_scored_verdicts():
    """Unscored verdicts must not be counted as zero.

    80 of 100 verdicts were scored; the mean describes those 80.
    """
    out = await metrics._triage_quality(
        _DB(_Row(triaged=100, abstentions=25, ungrounded=4, scored=80, mean=0.91)),
        "t",
        None,
        None,
    )
    assert out["scored_verdicts"] == 80
    assert out["mean_groundedness"] == 0.91


@pytest.mark.asyncio
async def test_no_scored_verdicts_reports_none_not_zero():
    """NULL is "not scored", which is not the same fact as "scored zero"."""
    out = await metrics._triage_quality(
        _DB(_Row(triaged=10, abstentions=1, ungrounded=0, scored=0, mean=None)),
        "t",
        None,
        None,
    )
    assert out["mean_groundedness"] is None
    assert out["scored_verdicts"] == 0


@pytest.mark.asyncio
async def test_nothing_triaged_does_not_divide_by_zero():
    out = await metrics._triage_quality(
        _DB(_Row(triaged=0, abstentions=0, ungrounded=0, scored=0, mean=None)),
        "t",
        None,
        None,
    )
    assert out["abstention_rate"] == 0.0


@pytest.mark.asyncio
async def test_a_missing_column_degrades_instead_of_breaking_the_funnel():
    """Pre-migration deployments must still get a funnel.

    Same contract as `_repeat_alerts_suppressed`: an optional analytics column
    is never allowed to take down the whole dashboard.
    """
    out = await metrics._triage_quality(_DB(raises=True), "t", None, None)
    assert out["triaged_alerts"] == 0
    assert out["mean_groundedness"] is None


@pytest.mark.asyncio
async def test_no_rows_returns_the_empty_shape():
    out = await metrics._triage_quality(_DB(None), "t", None, None)
    assert out["abstention_rate"] == 0.0
    assert out["scored_verdicts"] == 0


def test_the_funnel_model_exposes_every_field():
    """The endpoint's response model must actually carry these.

    Computing a metric and not publishing it is the shape of defect this whole
    line of work exists to remove.
    """
    fields = metrics.FunnelMetrics.model_fields
    for name in (
        "triaged_alerts",
        "abstentions",
        "abstention_rate",
        "ungrounded_demotions",
        "mean_groundedness",
        "scored_verdicts",
    ):
        assert name in fields, f"{name} is computed but not exposed on FunnelMetrics"


@pytest.mark.asyncio
async def test_every_computed_window_field_reaches_the_response(monkeypatch):
    """Declaring a field is not the same as forwarding it.

    ``_funnel_window`` merges ``_triage_quality``'s output into the dict it
    returns, but every field has to be named again in the ``FunnelMetrics(...)``
    call to reach the client. Six were not, so the endpoint answered 0 for all
    of them whatever the database held — and a published zero reads as "this
    tenant never abstained, and nothing was ever demoted for being ungrounded",
    which is a stronger claim than saying nothing at all.

    The loop is deliberately generic rather than a list of the six: any field
    the window computes and the model declares must survive the trip, including
    ones added after this test was written.
    """
    window = {
        "events_of_interest": 1_000,
        "correlation_instances": 100,
        "alerts_generated": 40,
        "signal_to_noise": 0.6,
        "mttd_seconds": 12.5,
        "analyst_queue_depth": 7,
        "correlation_efficiency": 0.1,
        "alert_yield": 0.04,
        "mitre_coverage": metrics.MitreCoverage(covered=3, total=10, ratio=0.3),
        "repeat_alerts_suppressed": 5,
        "repeat_suppression_rate": 0.1111,
        "triaged_alerts": 100,
        "abstentions": 25,
        "abstention_rate": 0.25,
        "ungrounded_demotions": 4,
        "mean_groundedness": 0.91,
        "scored_verdicts": 80,
    }

    async def _window(*_a, **_k):
        return dict(window)

    monkeypatch.setattr(metrics, "_funnel_window", _window)

    out = await metrics.get_funnel_metrics(
        user=SimpleNamespace(tenant_id="t-1"),
        db=object(),
        period="24h",
    )

    declared = metrics.FunnelMetrics.model_fields
    unforwarded = [name for name, expected in window.items() if name in declared and getattr(out, name) != expected]
    assert not unforwarded, f"computed but not forwarded to the response: {unforwarded}"

    # Serialisation is what a client actually sees; a field can be set on the
    # model and still be dropped by an alias or exclude rule.
    payload = out.model_dump()
    assert payload["abstention_rate"] == 0.25
    assert payload["mean_groundedness"] == 0.91
    assert payload["scored_verdicts"] == 80
