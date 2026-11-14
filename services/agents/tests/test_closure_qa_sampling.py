"""A sample of auto-closures reaches an analyst, and produces a real number.

Parity plan 3.5.

The property worth testing hardest is the sampling itself. `random() < rate`
would sample at the configured rate **per replica**, so three replicas at
5 percent sample 15 percent, and a redelivered Kafka message would get a
second independent roll and weight one closure twice in the accuracy
figure. Neither shows up as an error; both quietly make the published
number wrong.
"""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager

import pytest
from app.closure.qa_sampling import (
    DEFAULT_SAMPLE_RATE,
    RUBRIC,
    ClosureQaSampler,
    accuracy_from_reviews,
    should_sample,
)


class TestTheSampleIsDeterministic:
    def test_the_same_alert_always_gets_the_same_answer(self) -> None:
        """Across replicas and across a redelivery."""
        alert = str(uuid.uuid4())
        answers = {should_sample(alert, rate=0.5) for _ in range(50)}
        assert len(answers) == 1, "sampling the same alert twice gave two answers"

    def test_a_rate_of_zero_samples_nothing(self) -> None:
        assert not any(should_sample(str(uuid.uuid4()), rate=0.0) for _ in range(50))

    def test_a_rate_of_one_samples_everything(self) -> None:
        assert all(should_sample(str(uuid.uuid4()), rate=1.0) for _ in range(50))

    def test_the_rate_is_approximately_honoured(self) -> None:
        """Uniform enough that the published rate means something.

        Tolerance is wide on purpose: this asserts the hash is not skewed,
        not that 2,000 draws hit 5 percent exactly.
        """
        alerts = [str(uuid.uuid4()) for _ in range(2000)]
        sampled = sum(should_sample(a, rate=0.05) for a in alerts)
        assert 40 <= sampled <= 160, f"5% of 2000 sampled {sampled}, which is not uniform"

    def test_a_higher_rate_is_a_superset_of_a_lower_one(self) -> None:
        """A consequence of bucketing rather than rolling, and a useful
        one: raising the rate reviews more of the same closures rather
        than an unrelated set, so a tenant's accuracy figure stays
        comparable across a rate change.
        """
        alerts = [str(uuid.uuid4()) for _ in range(500)]
        low = {a for a in alerts if should_sample(a, rate=0.1)}
        high = {a for a in alerts if should_sample(a, rate=0.3)}
        assert low <= high


class _Conn:
    def __init__(self, *, rate=None, fail=False, fail_write=False) -> None:  # noqa: ANN001
        self.rate = rate
        # Separate flags, because the two failures are different: a rate
        # that cannot be read falls back to the default, while a write that
        # fails means the sample was chosen and then lost.
        self.fail = fail
        self.fail_write = fail_write
        self.inserts: list[tuple] = []

    async def fetchrow(self, sql, *args):  # noqa: ANN001, ARG002
        if self.fail:
            raise RuntimeError("down")
        return None if self.rate is None else {"qa_sample_rate": self.rate}

    async def execute(self, sql, *args):  # noqa: ANN001, ARG002
        if self.fail or self.fail_write:
            raise RuntimeError("down")
        self.inserts.append(args)


class _Pool:
    def __init__(self, conn: _Conn) -> None:
        self._conn = conn

    @asynccontextmanager
    async def acquire(self):
        yield self._conn


@pytest.mark.asyncio
class TestTheSampler:
    async def test_it_writes_a_review_row_for_a_sampled_closure(self) -> None:
        conn = _Conn(rate=1.0)
        sampler = ClosureQaSampler(_Pool(conn))
        decision = await sampler.record(
            tenant_id=str(uuid.uuid4()),
            alert_id=str(uuid.uuid4()),
            alert_class="identity",
            disposition="benign",
            confidence=0.91,
        )
        assert decision.sampled is True
        assert conn.inserts, "no review row was written"

    async def test_it_writes_nothing_when_not_sampled(self) -> None:
        conn = _Conn(rate=0.0)
        sampler = ClosureQaSampler(_Pool(conn))
        decision = await sampler.record(
            tenant_id=str(uuid.uuid4()),
            alert_id=str(uuid.uuid4()),
            alert_class="identity",
            disposition="benign",
            confidence=0.91,
        )
        assert decision.sampled is False
        assert not conn.inserts

    async def test_a_tenant_with_no_policy_gets_the_default_rate(self) -> None:
        sampler = ClosureQaSampler(_Pool(_Conn(rate=None)))
        assert await sampler.rate_for(tenant_id=str(uuid.uuid4()), alert_class=None) == DEFAULT_SAMPLE_RATE

    async def test_an_unreadable_rate_falls_back_rather_than_raising(self) -> None:
        """A sampling failure must not stop a closure the policy allowed."""
        sampler = ClosureQaSampler(_Pool(_Conn(fail=True)))
        assert await sampler.rate_for(tenant_id=str(uuid.uuid4()), alert_class=None) == DEFAULT_SAMPLE_RATE

    async def test_a_write_failure_is_reported_rather_than_swallowed(self) -> None:
        """A sampler that silently stops produces an accuracy figure over a
        shrinking denominator, which looks like a stable measurement."""
        sampler = ClosureQaSampler(_Pool(_Conn(rate=1.0, fail_write=True)))
        decision = await sampler.record(
            tenant_id=str(uuid.uuid4()),
            alert_id=str(uuid.uuid4()),
            alert_class=None,
            disposition="benign",
            confidence=0.9,
        )
        assert decision.sampled is False
        assert "failed" in decision.reason


class TestTheAccuracyFigure:
    def test_no_reviews_means_not_measured_rather_than_zero(self) -> None:
        """A closure accuracy of 0.0 and "nobody has reviewed one yet" are
        completely different claims."""
        out = accuracy_from_reviews([{"status": "pending"}])
        assert out["measured"] is False
        assert "closure_accuracy" not in out
        assert out["pending"] == 1

    def test_every_mean_travels_with_its_denominator(self) -> None:
        """An accuracy of 1.0 over three reviews and over three hundred are
        different claims, and a figure without the count invites the
        reader to assume the second."""
        reviews = [
            {
                "status": "reviewed",
                "agent_disposition": "benign",
                "reviewer_disposition": "benign",
                "score_evidence": 4,
                "score_verdict": 5,
            }
        ]
        out = accuracy_from_reviews(reviews)
        assert out["reviewed"] == 1
        assert out["closure_accuracy"] == 1.0
        assert out["scored_evidence"] == 1

    def test_a_disagreement_lowers_it(self) -> None:
        reviews = [
            {"status": "reviewed", "agent_disposition": "benign", "reviewer_disposition": "benign"},
            {
                "status": "reviewed",
                "agent_disposition": "benign",
                "reviewer_disposition": "true_positive",
            },
        ]
        out = accuracy_from_reviews(reviews)
        assert out["closure_accuracy"] == 0.5
        assert out["disagreed"] == 1

    def test_an_axis_nobody_scored_reports_none_rather_than_zero(self) -> None:
        reviews = [{"status": "reviewed", "agent_disposition": "b", "reviewer_disposition": "b"}]
        out = accuracy_from_reviews(reviews)
        for axis in RUBRIC:
            assert out[f"mean_{axis}"] is None
            assert out[f"scored_{axis}"] == 0

    def test_the_rubric_has_the_five_axes_the_plan_names(self) -> None:
        assert set(RUBRIC) == {"evidence", "reasoning", "verdict", "response", "report"}


class TestTheWiring:
    def test_the_closure_path_calls_the_sampler(self) -> None:
        """Otherwise this is another mechanism with a passing test and no
        caller, which is the shape the whole parity plan exists to find."""
        import inspect

        from app.agents import auto_triage_agent

        source = inspect.getsource(auto_triage_agent.run_auto_triage)
        assert "_sample_for_qa(" in source, (
            "run_auto_triage does not sample its closures, so no closure accuracy can ever be measured on real data"
        )

    def test_it_samples_only_actual_closures(self) -> None:
        """Sampling an alert that was escalated would measure something
        else entirely."""
        import inspect

        from app.agents import auto_triage_agent

        source = inspect.getsource(auto_triage_agent.run_auto_triage)
        closure_block = source[source.index("if should_auto_close:") :]
        assert "_sample_for_qa(" in closure_block.split("\n\n")[0] + closure_block[:600]
