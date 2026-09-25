"""A failing tick has to say what failed, and whether waiting will help.

Both scheduler loops in ``app/workers`` logged ``err=<ExceptionTypeName>``
and nothing else. ``err=ProgrammingError`` every thirty seconds is a line
that repeats forever without ever telling an operator whether their next
move is to wait or to go and fix something — the same shape as a consumer
that retries a permanent failure in silence, one level quieter.
"""

from __future__ import annotations

import logging

import pytest

from app.workers._tick_failures import TickFailures


@pytest.fixture()
def logger() -> logging.Logger:
    return logging.getLogger("aisoc.test.tick_failures")


def test_the_first_failure_is_a_warning_that_carries_the_message(caplog, logger):
    tracker = TickFailures("demo", logger)
    with caplog.at_level(logging.WARNING, logger=logger.name):
        tracker.record_failure(RuntimeError('column "peer_group_id" does not exist'))

    record = caplog.records[-1]
    assert record.levelno == logging.WARNING
    assert "peer_group_id" in record.getMessage(), "the message is what makes the line actionable"
    assert "RuntimeError" in record.getMessage()


def test_a_run_that_outlives_a_transient_explanation_escalates(caplog, logger):
    tracker = TickFailures("demo", logger, stuck_after_seconds=0.0)
    with caplog.at_level(logging.WARNING, logger=logger.name):
        tracker.record_failure(RuntimeError("boom"))

    record = caplog.records[-1]
    assert record.levelno == logging.ERROR
    assert "misconfiguration rather than churn" in record.getMessage()


def test_a_short_run_is_not_called_not_resolving(logger):
    tracker = TickFailures("demo", logger, stuck_after_seconds=3600.0)
    tracker.record_failure(RuntimeError("boom"))
    assert not tracker.not_resolving, "a single failure is exactly what a retry is for"
    assert tracker.consecutive == 1


def test_recovery_is_logged_so_the_last_line_is_not_a_stale_fault(caplog, logger):
    tracker = TickFailures("demo", logger, stuck_after_seconds=0.0)
    tracker.record_failure(RuntimeError("boom"))
    with caplog.at_level(logging.INFO, logger=logger.name):
        tracker.record_success()

    assert "recovered after 1 consecutive failure" in caplog.records[-1].getMessage()
    assert tracker.consecutive == 0
    assert not tracker.not_resolving


def test_a_success_with_no_prior_failure_says_nothing(caplog, logger):
    tracker = TickFailures("demo", logger)
    with caplog.at_level(logging.INFO, logger=logger.name):
        tracker.record_success()
    assert caplog.records == [], "a healthy loop must not narrate every tick"


def test_newlines_in_the_message_cannot_forge_a_log_line(caplog, logger):
    tracker = TickFailures("demo", logger)
    with caplog.at_level(logging.WARNING, logger=logger.name):
        tracker.record_failure(RuntimeError("real failure\nWARNING fake line injected"))

    rendered = caplog.records[-1].getMessage()
    assert "\n" not in rendered
    assert "\r" not in rendered
    assert "fake line injected" in rendered, "the text is kept, only the line break is removed"


def test_a_long_message_is_truncated(caplog, logger):
    tracker = TickFailures("demo", logger)
    with caplog.at_level(logging.WARNING, logger=logger.name):
        tracker.record_failure(RuntimeError("x" * 5000))
    assert len(caplog.records[-1].getMessage()) < 600
