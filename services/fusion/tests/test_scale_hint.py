"""The autoscaling hint, and the two ways a hint lies (parity 6.9).

A hint is only useful if the number relates to something. The two
failures this pins are both ones this repository has shipped before: a
threshold that relates to no published figure, and an unmeasurable value
reported as zero.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from app.services import scale_hint

REPO_ROOT = Path(__file__).resolve().parents[3]
PUBLISHED_RUN = REPO_ROOT / "docs/perf/results/2026-10-11-compose-realistic-mix.json"


def test_the_per_replica_budget_is_the_published_figure():
    """The constant has to be derivable from a run someone can check.

    A per-replica budget picked out of the air makes the hint a number
    that relates to nothing — the defect this repository measured on a
    performance gate whose floor sat orders of magnitude below the
    figures it was supposed to protect. If the published run changes,
    this fails until the constant moves with it.
    """
    assert PUBLISHED_RUN.is_file(), f"{PUBLISHED_RUN} is missing; the constant has no source"
    report = json.loads(PUBLISHED_RUN.read_text(encoding="utf-8"))
    published = report["metrics"]["ingest_accepted_eps"]
    assert published["measured"] is True
    assert scale_hint.PUBLISHED_REPLICA_EPS == pytest.approx(published["value"], abs=0.01), (
        "PUBLISHED_REPLICA_EPS has drifted from the run it names"
    )


def test_an_unreadable_lag_is_not_reported_as_no_backlog(monkeypatch):
    # The difference between "no backlog" and "we could not measure the
    # backlog" is the whole of lag_measured. Reporting the second as the
    # first is how a stalled consumer looks healthy.
    hint = scale_hint.compute(None)
    assert hint.lag_measured is False
    assert hint.suggested_replicas == scale_hint.MIN_REPLICAS
    assert "could not be read" in hint.as_dict()["basis"]


def test_no_backlog_suggests_the_floor_and_says_it_was_measured():
    hint = scale_hint.compute(0)
    assert hint.lag_measured is True
    assert hint.suggested_replicas == scale_hint.MIN_REPLICAS


def test_a_backlog_one_replica_clears_in_the_window_needs_one_replica():
    # 122.56 events/s for 120s is roughly 14,707 messages.
    within = int(scale_hint.PUBLISHED_REPLICA_EPS * scale_hint.DEFAULT_DRAIN_TARGET_SECONDS) - 1
    assert scale_hint.compute(within).suggested_replicas == 1


def test_a_backlog_of_three_windows_asks_for_three_replicas():
    per_replica = scale_hint.PUBLISHED_REPLICA_EPS * scale_hint.DEFAULT_DRAIN_TARGET_SECONDS
    assert scale_hint.compute(int(per_replica * 2.5)).suggested_replicas == 3


def test_the_hint_is_clamped_so_a_stuck_consumer_cannot_ask_for_the_cluster():
    # Lag that is not falling because nothing is consuming would otherwise
    # turn into an unbounded scale-out that cannot help.
    enormous = int(scale_hint.PUBLISHED_REPLICA_EPS * scale_hint.DEFAULT_DRAIN_TARGET_SECONDS * 10_000)
    assert scale_hint.compute(enormous).suggested_replicas == scale_hint.MAX_REPLICAS


def test_the_hint_never_suggests_removing_the_last_replica():
    assert scale_hint.compute(0).suggested_replicas >= 1
    assert scale_hint.MIN_REPLICAS >= 1


def test_a_negative_lag_is_floored_rather_than_inverting_the_hint():
    assert scale_hint.compute(-500).lag_messages == 0


@pytest.mark.parametrize("bad", ["not-a-number", "0", "-5"])
def test_a_bad_override_falls_back_to_the_published_figure(monkeypatch, bad):
    monkeypatch.setenv("AISOC_FUSION_REPLICA_EPS", bad)
    assert scale_hint.compute(0).replica_eps == pytest.approx(scale_hint.PUBLISHED_REPLICA_EPS)


def test_a_valid_override_is_honoured(monkeypatch):
    # The published figure is a laptop's; an operator's hardware is not.
    monkeypatch.setenv("AISOC_FUSION_REPLICA_EPS", "1000")
    hint = scale_hint.compute(int(1000 * scale_hint.DEFAULT_DRAIN_TARGET_SECONDS * 1.5))
    assert hint.replica_eps == pytest.approx(1000.0)
    assert hint.suggested_replicas == 2


def test_the_basis_string_states_what_the_number_came_from():
    basis = scale_hint.compute(30_000).as_dict()["basis"]
    assert "backlog" in basis
    assert "per replica" in basis
