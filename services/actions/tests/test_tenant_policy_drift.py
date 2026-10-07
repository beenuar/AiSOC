"""Dispatch re-checks the evidence behind a grant, using the shared evaluator.

Fix pass item 3.7. See ``plans/aisoc_fix_pass_plan.plan.md``.

``state = 'granted'`` is a cached verdict, and the only thing that moved a
grant out of it was ``reconcile_grants`` in ``services/api`` — whose single
production caller was the handler behind ``GET /autonomy-policy/grants``. So a
tenant whose agreement had collapsed kept auto-executing containment until
somebody opened a page, which on an unattended deployment is never.

The behaviour lives in ``tests/isolation/test_autonomy_drift_at_dispatch_live.py``,
against a real Postgres, because the thing worth proving is that the aggregate
and the evaluator agree about real rows. What is here is what does not need a
database: that the parameters match the statements, and that the decision is
the shared evaluator's rather than a second opinion written locally.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from app.services.autonomy_evidence_rules import (
    AGREEMENT_COUNTS_SQL,
    RECENT_COUNTS_SQL,
)
from app.services.tenant_policy import _bound

_MODULE = Path(__file__).resolve().parents[1] / "app" / "services" / "tenant_policy.py"


def _placeholders(statement: str) -> int:
    return max((int(index) for index in re.findall(r"\$(\d+)", statement)), default=0)


class TestTheParametersMatchTheStatements:
    """The defect this class exists for failed closed, which is why it hid.

    The two aggregates bind different numbers of parameters — the trailing
    slice takes ``$7`` for its ``LIMIT`` and the window aggregate stops at
    ``$6``. Passing seven to both made asyncpg refuse, the refusal was caught,
    and an unreadable record is treated as no record: every grant on every
    deployment was withheld while the log said the evidence could not be read.
    A safety control stuck on reads like working caution, so nothing about the
    symptom says "broken".
    """

    def test_the_window_aggregate_gets_exactly_what_it_binds(self) -> None:
        params = tuple(range(1, 20))
        statement, *bound = _bound(AGREEMENT_COUNTS_SQL, params)

        assert statement.strip().startswith("SELECT")
        assert len(bound) == _placeholders(AGREEMENT_COUNTS_SQL)

    def test_the_trailing_slice_gets_its_limit(self) -> None:
        params = tuple(range(1, 20))
        _statement, *bound = _bound(RECENT_COUNTS_SQL, params)

        assert len(bound) == _placeholders(RECENT_COUNTS_SQL)

    def test_the_two_statements_really_do_differ(self) -> None:
        """Otherwise the derivation above is untested by construction."""
        assert _placeholders(RECENT_COUNTS_SQL) > _placeholders(AGREEMENT_COUNTS_SQL)


class TestTheDecisionIsTheSharedEvaluators:
    def test_the_dispatch_path_calls_evaluate_demotion(self) -> None:
        """Not a locally written threshold comparison.

        A safety control two services define differently is off in whichever
        one is more generous, which is the whole reason
        ``autonomy_evidence_rules`` is vendored byte-identical into both. A
        dispatch-side re-check that compared its own numbers would reintroduce
        exactly the divergence the vendoring exists to prevent.
        """
        tree = ast.parse(_MODULE.read_text(encoding="utf-8"))

        imported = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module == "app.services.autonomy_evidence_rules"
            for alias in node.names
        }
        assert "evaluate_demotion" in imported, "tenant_policy no longer imports the shared demotion evaluator"

        called = {node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
        assert "evaluate_demotion" in called, "the evaluator is imported but never called, which is the shape this item exists to remove"

    def test_dispatch_writes_no_grant_transition(self) -> None:
        """Enforcing is this service's job; issuing and revoking are not.

        ``services/api`` owns the tenant session and the hash-chained audit
        log, so a demotion written from here would be a state change with
        nobody's name on it and no entry explaining it. Withholding is the
        whole of the dispatch-side remedy.
        """
        source = _MODULE.read_text(encoding="utf-8")

        assert "UPDATE aisoc_autonomy_grants" not in source
        assert "INSERT INTO aisoc_autonomy_grants" not in source
