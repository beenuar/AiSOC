"""Every status a worker writes to ``report_artefacts`` is one the column allows.

Found while proving the white-label property of the scheduled report: the
covering email could not be asserted against a real Postgres because the
sweep never got as far as sending one. ``report_scheduler`` wrote
``status="generated"`` and ``weekly_digest_task`` wrote ``status="ready"``,
and ``migrations/019_board_reports.sql`` constrains that column to
``pending | generating | completed | failed``. Neither value is a member, so
both workers raised ``CheckViolationError`` on commit and **no scheduled
report and no Monday digest had ever been stored on a real deployment**.

Why no test caught it, and why this one is shaped the way it is
---------------------------------------------------------------
The CHECK lives in the migration. The ORM model declares no constraint at
all, so a suite that builds its tables with ``Base.metadata.create_all`` --
which is every offline suite in this service -- gets a column that accepts
any string. The database and the model disagreed about what a status is, and
only the database's opinion matters in production.

So this reads the vocabulary out of the **migration**, which is the authority,
and the literals out of the **workers**, which are what drift. Asserting the
two agree in that direction is the direction that changes: a new status is
invented in Python far more often than a CHECK is rewritten.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

API_ROOT = Path(__file__).resolve().parents[1]
MIGRATION = API_ROOT / "migrations" / "019_board_reports.sql"
DELIVERY_MIGRATION = API_ROOT / "migrations" / "098_report_delivery.sql"

#: Every module that constructs or mutates a ``ReportArtefact``.
WRITERS = (
    API_ROOT / "app" / "workers" / "report_scheduler.py",
    API_ROOT / "app" / "workers" / "weekly_digest_task.py",
    API_ROOT / "app" / "api" / "v1" / "endpoints" / "reports.py",
)


def _vocabulary(sql: str, column: str) -> frozenset[str]:
    """The values a ``CHECK (<column> IN (...))`` permits."""
    match = re.search(rf"CHECK\s*\(\s*{column}\s+IN\s*\(([^)]*)\)", sql, re.IGNORECASE)
    assert match, f"no CHECK found for {column}; the migration has been reshaped"
    return frozenset(re.findall(r"'([^']+)'", match.group(1)))


def _assigned_literals(path: Path, field: str) -> set[str]:
    """Every string literal this module assigns to ``field``.

    Both spellings, because the schedulers use one each: a keyword argument
    in a ``ReportArtefact(...)`` construction, and an attribute assignment
    on an instance afterwards. Looking for only the first is how the
    ``delivery_status`` writes would have been missed.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for keyword in node.keywords:
                if keyword.arg == field and isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                    found.add(keyword.value.value)
        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for target in node.targets:
                if isinstance(target, ast.Attribute) and target.attr == field:
                    found.add(node.value.value)
    return found


STATUSES = _vocabulary(MIGRATION.read_text(encoding="utf-8"), "status")
DELIVERY_STATUSES = _vocabulary(DELIVERY_MIGRATION.read_text(encoding="utf-8"), "delivery_status")


def test_the_migration_vocabulary_parsed() -> None:
    """A parser that silently found nothing would pass every case below."""
    assert STATUSES == {"pending", "generating", "completed", "failed"}
    assert DELIVERY_STATUSES == {"not_attempted", "sent", "skipped", "failed"}


@pytest.mark.parametrize("path", WRITERS, ids=lambda p: p.name)
def test_every_status_written_is_one_the_column_allows(path: Path) -> None:
    written = _assigned_literals(path, "status")
    # `status` is a common attribute name; only the ones that are not in the
    # vocabulary are interesting, and an unrelated `status="ok"` on some other
    # object would be a false positive. The writers here assign it to nothing
    # else, and that is itself worth holding still.
    assert written, f"{path.name} assigns no status literal; has the writer moved?"
    assert written <= STATUSES, f"{path.name} writes {sorted(written - STATUSES)}, which {MIGRATION.name} refuses"


@pytest.mark.parametrize("path", WRITERS, ids=lambda p: p.name)
def test_every_delivery_status_written_is_one_the_column_allows(path: Path) -> None:
    written = _assigned_literals(path, "delivery_status")
    assert written <= DELIVERY_STATUSES, (
        f"{path.name} writes {sorted(written - DELIVERY_STATUSES)}, which {DELIVERY_MIGRATION.name} refuses"
    )


def test_the_check_detects_the_values_that_shipped() -> None:
    """The gate's own self-test, in both directions.

    ``generated`` and ``ready`` are the two literals that were live in the
    tree. A detector that could not see them is a detector that would have
    let this ship, which is exactly what happened.
    """
    assert "generated" not in STATUSES
    assert "ready" not in STATUSES
    assert "completed" in STATUSES
