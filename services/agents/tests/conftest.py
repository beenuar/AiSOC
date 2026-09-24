"""Shared agents-test fixtures.

Wave 1 introduced two process-wide singletons that carry state across calls:
the CostGovernor (verdict dedup cache + per-tenant spend) and the LLM
ResponseCache. Reset both before every test so a verdict/response recorded by
one test can't leak into the next (e.g. a reused alert hitting DEDUPLICATED, or
a cached LLM response shadowing a test's mocked one).

The other piece of leaked state is the *environment*. The agents unit suite
runs with no database — but it only ran that way because GitHub's runners
happen to have nothing listening on 5432 and nothing exports ``DATABASE_URL``
for the agents step. On a developer's machine, where both are usually true,
``FusedAlertTriageWorker.triage()`` opened real asyncpg connections through
``business_context._load_tenant_rules`` and ``ledger.persist_auto_triage``,
and two tests in ``test_business_context_hotpath.py`` failed with
``InterfaceError: cannot perform operation: another operation is in progress``
— pytest-asyncio gives each test its own event loop, so the module-level pool
one test opens is unusable by the next.

Two ad-hoc workarounds for this already existed and neither worked:
``os.environ.setdefault("DATABASE_URL", "")`` at the top of two test modules
(a no-op precisely when the variable is set, which is the only case that
matters) and a per-module fixture stubbing three ledger functions, which left
every other database caller reachable. ``_no_ambient_database`` below replaces
both with one rule for the whole suite.
"""

from __future__ import annotations

import asyncpg
import pytest


class AmbientDatabaseUse(BaseException):
    """Raised when a unit test opens a real database connection.

    Deliberately a ``BaseException`` rather than an ``Exception``. Every call
    site this guard covers is wrapped in a fail-soft ``except Exception`` that
    logs a warning and carries on — that is the correct production behaviour
    and the reason the original bug was invisible. A guard raising
    ``Exception`` would be swallowed by the very handlers it exists to police
    and would report nothing, which is the shape of gate this repository keeps
    finding: one that cannot fail on the path that matters.
    """


@pytest.fixture(autouse=True)
def _reset_agent_singletons():
    from app.core.cost_governor import reset_governor
    from app.llm.contract import _RESPONSE_CACHE

    reset_governor()
    _RESPONSE_CACHE.clear()
    yield
    reset_governor()
    _RESPONSE_CACHE.clear()


@pytest.fixture(autouse=True)
def _no_ambient_database(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch):
    """Run the unit suite with no database, and fail loudly if one is reached.

    Removing the inherited DSN makes the suite deterministic. Refusing the
    connection as well is what keeps it that way: without it, a future change
    that adds a database call to a unit-tested path stays green on CI (no
    Postgres on the runner) while failing on contributors' machines, which is
    the failure this fixture exists to end. A test that needs the real thing
    says so with a marker instead of relying on what the host happens to run.
    """
    if request.node.get_closest_marker("integration"):
        yield
        return

    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_DSN", raising=False)

    if request.node.get_closest_marker("touches_database"):
        yield
        return

    def _refuse(*args: object, **kwargs: object):
        raise AmbientDatabaseUse(
            f"{request.node.nodeid} opened a real database connection. Agents unit "
            "tests run with no database. Stub the call, or mark the test "
            "`integration` (needs real infrastructure) or `touches_database` "
            "(drives the real client against a DSN the test sets itself)."
        )

    monkeypatch.setattr(asyncpg, "connect", _refuse)
    monkeypatch.setattr(asyncpg, "create_pool", _refuse)
    yield
