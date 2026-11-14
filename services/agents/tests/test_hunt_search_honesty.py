"""`POST /api/v1/hunt/search` must not describe work it did not do.

The handler had exactly one path — `_synthetic_hits()` — and three separate
claims about it were false at once, all of them visible to an operator on
the page:

* its docstring said "Execute a hunt query and return matching telemetry
  events", and it executed nothing;
* `source: Literal["sample", "live"]` declared a `live` value **no code path
  could produce**, so a caller branching on it was branching on a dead value;
* `took_ms` timed the generation of the fake hits, so a query that never ran
  published a measured latency — `0ms` beside a real-looking hit count, which
  is the same defect as the `took: 42` removed before it with a humbler
  number;
* the notice told the reader to "run the hunt from /hunt against a configured
  data source" while they were standing on `/hunt`.

These tests pin the handler's three honest states. They are written against
the response the route returns rather than by reading its source, because a
test that reads source cannot notice that the code does not run.
"""

from __future__ import annotations

import uuid

import pytest
from app.api import hunt_search as mod
from app.security.tenant_scope import TenantPrincipal

TENANT = uuid.UUID("00000000-0000-0000-0000-000000000001")


@pytest.fixture
def principal():
    """The real principal, not a stand-in.

    A hand-rolled double here would be the "test double more capable than
    the real thing" trap pointing the other way: it would not have
    `is_empty`, and the scope resolution the handler depends on would never
    be exercised.
    """
    return TenantPrincipal(tenant_ids=frozenset({TENANT}), subject="analyst@example.com")


def _run(coro):
    import asyncio

    return asyncio.run(coro)


class TestNoLatencyForAQueryThatDidNotRun:
    def test_unavailable_lake_publishes_no_latency(self, principal, monkeypatch):
        """`took_ms` is None when nothing was queried — never 0.

        Fails on the pre-fix tree: the handler always returned
        `took_ms=int(...)`, which is 0 for synthetic generation.
        """
        monkeypatch.setattr(mod, "_search_lake", _unavailable)
        res = _run(mod.hunt_search(mod.HuntQuery(query="cmd.exe"), principal))
        assert res.took_ms is None, f"published a latency of {res.took_ms} for a query that never ran"
        assert res.source == "unavailable"
        assert res.total == 0
        assert res.hits == []

    def test_live_lake_publishes_a_real_latency(self, principal, monkeypatch):
        """A query that ran reports the time it took, measured around the read."""
        monkeypatch.setattr(mod, "_search_lake", _one_hit)
        res = _run(mod.hunt_search(mod.HuntQuery(query="cmd.exe"), principal))
        assert res.took_ms is not None
        assert res.took_ms >= 0


class TestTheLiveLiteralIsReachable:
    def test_a_lake_answer_reports_live(self, principal, monkeypatch):
        """Fails on the pre-fix tree: no code path could produce `live`."""
        monkeypatch.setattr(mod, "_search_lake", _one_hit)
        res = _run(mod.hunt_search(mod.HuntQuery(query="cmd.exe"), principal))
        assert res.source == "live"
        assert res.total == 1
        assert res.hits[0].raw["process_name"] == "cmd.exe"

    def test_the_declared_vocabulary_has_no_dead_value(self):
        """Every value `source` declares is one some branch can return.

        A `Literal` member nothing produces is a contract a caller writes
        dead code against.
        """
        import typing

        declared = set(typing.get_args(mod.HuntResponse.model_fields["source"].annotation))
        assert declared == set(mod.HUNT_SOURCES), f"declared {sorted(declared)} but the handler can only produce {sorted(mod.HUNT_SOURCES)}"


class TestTheNoticeDoesNotRedirectToThisPage:
    def test_notice_does_not_send_the_reader_to_hunt(self, principal, monkeypatch):
        """Fails on the pre-fix tree: the notice said "run the hunt from /hunt"."""
        monkeypatch.setattr(mod, "_search_lake", _unavailable)
        res = _run(mod.hunt_search(mod.HuntQuery(query="cmd.exe"), principal))
        assert res.notice
        assert "/hunt" not in res.notice, f"the notice points at the page the reader is on: {res.notice!r}"

    def test_unavailable_notice_names_the_reason(self, principal, monkeypatch):
        monkeypatch.setattr(mod, "_search_lake", _unavailable)
        res = _run(mod.hunt_search(mod.HuntQuery(query="cmd.exe"), principal))
        assert "no query ran" in res.notice.lower()


class TestNothingIsFabricated:
    def test_the_handler_has_no_synthetic_hit_generator(self):
        """The fabricating path is deleted, not reworded.

        A fallback that invents telemetry is the defect this repository
        removes rather than rewrites; leaving the generator in place means
        the next caller finds it.
        """
        assert not hasattr(mod, "_synthetic_hits"), "the synthetic-hit generator is still importable"

    def test_an_empty_result_is_not_an_unavailable_result(self, principal, monkeypatch):
        """A lake that answered with no rows is `live`, not `unavailable`.

        Collapsing the two is how "your telemetry has nothing matching" and
        "we could not look" become the same screen.
        """
        monkeypatch.setattr(mod, "_search_lake", _no_hits)
        res = _run(mod.hunt_search(mod.HuntQuery(query="nothing-matches-this"), principal))
        assert res.source == "live"
        assert res.total == 0
        assert res.took_ms is not None


# ── stand-ins for the lake read ──────────────────────────────────────────────
# Each returns the shape `_search_lake` returns, so the handler under test is
# the real one and only the ClickHouse round trip is replaced.


async def _unavailable(*_a, **_kw):
    return mod.LakeAnswer(available=False, reason="ClickHouse is not reachable from this service", hits=[])


async def _one_hit(*_a, **_kw):
    return mod.LakeAnswer(
        available=True,
        reason=None,
        hits=[
            {
                "id": "e1",
                "timestamp": "2026-11-02T00:00:00+00:00",
                "source": "crowdstrike",
                "event_type": "4688",
                "raw": {"process_name": "cmd.exe", "src_hostname": "WS-1"},
                "highlights": ["cmd.exe"],
            }
        ],
    )


async def _no_hits(*_a, **_kw):
    return mod.LakeAnswer(available=True, reason=None, hits=[])
